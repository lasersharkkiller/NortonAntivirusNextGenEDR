// User Account Control (UAC) bypass fingerprints. Covers registry handler
// hijacking (ms-settings, mscfile, exefile), COM object auto-elevation
// abuse (CMSTPLUA, ColorDataProxy), environment variable hijacking,
// auto-elevating binary invocation from scripts, UAC policy tampering,
// DLL hijacking in trusted directories, and token manipulation patterns.
//
// Tier: signal-only — some patterns appear in legitimate admin scripts.
// Chain with: non-admin user context, script/LOLBin parent process,
// temp/Downloads path, or rapid registry-write-then-execute sequence.

// ---------------------------------------------------------------------------
// Registry handler hijack for auto-elevating binaries. Attacker writes to
// HKCU\Software\Classes\{ms-settings,mscfile,exefile}\Shell\Open\command
// then launches the auto-elevating binary (fodhelper, eventvwr, sdclt)
// which reads the hijacked handler and executes the attacker's payload
// at high integrity.
// ---------------------------------------------------------------------------
rule UAC_Registry_Handler_Hijack
{
    meta:
        description = "UAC bypass: HKCU class handler hijack for ms-settings/mscfile/exefile + DelegateExecute (T1548.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Registry paths for handler hijacking
        $rp1 = "ms-settings\\Shell\\Open\\command"                     ascii nocase
        $rp2 = "mscfile\\Shell\\Open\\command"                        ascii nocase
        $rp3 = "exefile\\Shell\\Open\\command"                        ascii nocase
        $rp4 = "Software\\Classes\\ms-settings"                       ascii nocase
        $rp5 = "Software\\Classes\\mscfile"                           ascii nocase
        $rp6 = "Software\\Classes\\exefile"                           ascii nocase

        // DelegateExecute value (set to empty string for bypass)
        $de1 = "DelegateExecute"                                       ascii nocase

        // Registry write methods
        $rw1 = "New-Item"                                              ascii nocase
        $rw2 = "Set-ItemProperty"                                      ascii nocase
        $rw3 = "New-ItemProperty"                                      ascii nocase
        $rw4 = "reg add"                                               ascii nocase
        $rw5 = "REG ADD"                                               ascii
        $rw6 = ".RegWrite("                                            ascii nocase
        $rw7 = "RegSetValueEx"                                         ascii nocase
        $rw8 = "RegCreateKeyEx"                                        ascii nocase

        // Auto-elevating binary triggers
        $ae1 = "fodhelper"                                             ascii nocase
        $ae2 = "eventvwr"                                              ascii nocase
        $ae3 = "sdclt"                                                 ascii nocase
        $ae4 = "computerdefaults"                                      ascii nocase
        $ae5 = "slui"                                                  ascii nocase

        $rp1w = "ms-settings\\Shell\\Open\\command"                    wide nocase
        $rp2w = "mscfile\\Shell\\Open\\command"                       wide nocase

    condition:
        any of ($rp*)
        or ($de1 and any of ($rw*) and any of ($ae*))
}


// ---------------------------------------------------------------------------
// COM object UAC bypass. Certain COM objects auto-elevate when instantiated
// via specific interfaces. Attackers CoCreate CMSTPLUA or ColorDataProxy
// and call ShellExec/LaunchElevatedProcess to run commands at high integrity.
// ---------------------------------------------------------------------------
rule UAC_COM_Object_Bypass
{
    meta:
        description = "UAC bypass: CMSTPLUA / ColorDataProxy / FileOperation COM auto-elevation abuse (T1548.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // CMSTPLUA — Connection Manager Setup TrustLevel Utility Agent
        $cm1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"               ascii nocase
        $cm2 = "CMSTPLUA"                                              ascii nocase
        $cm3 = "ICMLuaUtil"                                            ascii nocase

        // ColorDataProxy
        $cd1 = "{D2E7025F-8B69-4AE6-A3B1-C2BC0F92A3B2}"               ascii nocase
        $cd2 = "ColorDataProxy"                                        ascii nocase

        // FileOperation (IFileOperation auto-elevate)
        $fo1 = "{3AD05575-8857-4850-9277-11B85BDB8E09}"               ascii nocase
        $fo2 = "IFileOperation"                                        ascii nocase

        // COM auto-elevate methods
        $me1 = "ShellExec("                                            ascii nocase
        $me2 = "LaunchElevatedProcess"                                 ascii nocase
        $me3 = "CoGetObject"                                           ascii nocase
        $me4 = "Elevation:Administrator!new:"                          ascii nocase

        $cm1w = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"              wide nocase
        $cd1w = "{D2E7025F-8B69-4AE6-A3B1-C2BC0F92A3B2}"              wide nocase

    condition:
        ($cm1 or $cm1w) or $cm3
        or ($cd1 or $cd1w) or $cd2
        or $fo1 or ($fo2 and any of ($me*))
        or $me4
}


// ---------------------------------------------------------------------------
// Environment variable UAC bypass. Overriding windir or systemroot in
// HKCU\Environment before invoking silentcleanup or other auto-elevating
// tasks that use %windir% in their command — the task expands the hijacked
// variable and executes the attacker's payload.
// ---------------------------------------------------------------------------
rule UAC_EnvVar_Hijack
{
    meta:
        description = "UAC bypass: HKCU\\Environment windir/systemroot override for auto-elevating task hijack (T1548.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Environment registry path
        $env1 = "\\Environment\\windir"                                ascii nocase
        $env2 = "\\Environment\\systemroot"                            ascii nocase
        $env3 = "HKCU\\Environment"                                    ascii nocase

        // Registry write methods
        $rw1 = "Set-ItemProperty"                                      ascii nocase
        $rw2 = "New-ItemProperty"                                      ascii nocase
        $rw3 = "reg add"                                               ascii nocase
        $rw4 = ".RegWrite("                                            ascii nocase
        $rw5 = "RegSetValueEx"                                         ascii nocase

        // Trigger binaries that read %windir%
        $trig1 = "silentcleanup"                                       ascii nocase
        $trig2 = "schtasks /run"                                       ascii nocase
        $trig3 = "Disk Cleanup"                                        ascii nocase

        $env1w = "\\Environment\\windir"                               wide nocase
        $env2w = "\\Environment\\systemroot"                           wide nocase

    condition:
        any of ($env1, $env1w, $env2, $env2w)
        or ($env3 and any of ($rw*))
}


// ---------------------------------------------------------------------------
// Auto-elevating binary invocation from script. Scripts that launch
// fodhelper, wsreset, computerdefaults, changepk, or other auto-elevating
// binaries — the script writes the handler hijack then triggers elevation.
// ---------------------------------------------------------------------------
rule UAC_AutoElevate_Binary_From_Script
{
    meta:
        description = "UAC bypass: auto-elevating binary invoked from script — handler hijack + trigger pattern (T1548.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Auto-elevating binaries
        $ae1 = "fodhelper.exe"                                         ascii nocase
        $ae2 = "fodhelper"                                             ascii nocase
        $ae3 = "wsreset.exe"                                           ascii nocase
        $ae4 = "computerdefaults.exe"                                  ascii nocase
        $ae5 = "changepk.exe"                                         ascii nocase
        $ae6 = "sdclt.exe"                                             ascii nocase
        $ae7 = "slui.exe"                                              ascii nocase
        $ae8 = "dccw.exe"                                              ascii nocase
        $ae9 = "iscsicpl.exe"                                         ascii nocase
        $ae10 = "perfmon.exe"                                          ascii nocase

        // Script/process launch indicators
        $sl1 = "Start-Process"                                         ascii nocase
        $sl2 = "cmd /c"                                                ascii nocase
        $sl3 = "Shell("                                                ascii nocase
        $sl4 = "CreateObject("                                         ascii nocase
        $sl5 = ".Run("                                                 ascii nocase
        $sl6 = "Invoke-Item"                                           ascii nocase
        $sl7 = "& \""                                                  ascii

        // Registry handler setup (confirms UAC bypass intent)
        $reg1 = "ms-settings"                                          ascii nocase
        $reg2 = "Shell\\Open\\command"                                 ascii nocase
        $reg3 = "DelegateExecute"                                      ascii nocase

    condition:
        (any of ($ae*) and any of ($reg*))
        or (any of ($ae*) and any of ($sl*) and any of ($reg*))
}


// ---------------------------------------------------------------------------
// UAC policy tampering. Directly disabling UAC via EnableLUA=0 or setting
// ConsentPromptBehaviorAdmin=0 (never prompt) or PromptOnSecureDesktop=0
// (disable secure desktop) via registry modification.
// ---------------------------------------------------------------------------
rule UAC_Policy_Tampering
{
    meta:
        description = "UAC policy tamper: EnableLUA / ConsentPromptBehaviorAdmin / PromptOnSecureDesktop registry disable (T1548.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Policy registry path
        $pp1 = "\\Policies\\System"                                    ascii nocase
        $pp2 = "CurrentVersion\\Policies\\System"                      ascii nocase

        // Policy values
        $pv1 = "EnableLUA"                                             ascii nocase
        $pv2 = "ConsentPromptBehaviorAdmin"                            ascii nocase
        $pv3 = "PromptOnSecureDesktop"                                 ascii nocase
        $pv4 = "FilterAdministratorToken"                              ascii nocase
        $pv5 = "LocalAccountTokenFilterPolicy"                         ascii nocase

        // Disable values
        $dv1 = "/d 0"                                                  ascii nocase
        $dv2 = "-Value 0"                                              ascii nocase
        $dv3 = "dword:00000000"                                        ascii nocase
        $dv4 = "= 0"                                                   ascii nocase

        // Registry write methods
        $rw1 = "Set-ItemProperty"                                      ascii nocase
        $rw2 = "reg add"                                               ascii nocase
        $rw3 = "REG ADD"                                               ascii
        $rw4 = "RegSetValueEx"                                         ascii nocase

        $pv1w = "EnableLUA"                                            wide nocase
        $pv2w = "ConsentPromptBehaviorAdmin"                           wide nocase

    condition:
        (any of ($pp*) and any of ($pv1, $pv1w, $pv2, $pv2w, $pv3) and any of ($dv*))
        or (any of ($pp*) and any of ($pv*) and any of ($rw*))
        or ($pv5 and any of ($dv*))
}


// ---------------------------------------------------------------------------
// Trusted directory DLL hijack for UAC bypass. Creating a directory
// "C:\Windows \System32\" (note trailing space in "Windows ") that passes
// trusted-directory checks, then placing a malicious DLL for auto-elevating
// binaries to load.
// ---------------------------------------------------------------------------
rule UAC_Trusted_Directory_DLL_Hijack
{
    meta:
        description = "UAC bypass: trusted directory DLL hijack via trailing-space path (C:\\Windows \\System32\\) (T1548.002 + T1574.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Trailing space directory paths
        $td1 = "Windows \\System32"                                    ascii nocase
        $td2 = "Windows \\SysWOW64"                                   ascii nocase
        $td3 = "Windows \\System32\\"                                  ascii nocase

        // Directory creation methods
        $mk1 = "mkdir"                                                 ascii nocase
        $mk2 = "md "                                                   ascii nocase
        $mk3 = "New-Item"                                              ascii nocase
        $mk4 = "CreateDirectory"                                       ascii nocase

        // DLL file operations
        $dl1 = ".dll"                                                  ascii nocase
        $dl2 = "copy"                                                  ascii nocase
        $dl3 = "xcopy"                                                 ascii nocase
        $dl4 = "Move-Item"                                             ascii nocase

        $td1w = "Windows \\System32"                                   wide nocase

    condition:
        ($td1 or $td1w or $td2 or $td3)
        or (any of ($td*) and any of ($mk*))
}


// ---------------------------------------------------------------------------
// Token manipulation for elevation. Direct use of token APIs to duplicate,
// impersonate, or create processes with stolen/manufactured tokens — the
// API-level plumbing behind potato exploits, token theft, and PPID spoofing.
// ---------------------------------------------------------------------------
rule UAC_Token_Manipulation
{
    meta:
        description = "Token manipulation: CreateProcessWithToken / ImpersonateLoggedOnUser / NtSetInformationToken (T1134)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Process creation with token
        $tok1 = "CreateProcessWithTokenW"                              ascii nocase
        $tok2 = "CreateProcessWithLogonW"                              ascii nocase
        $tok3 = "CreateProcessAsUser"                                  ascii nocase

        // Token manipulation
        $tok4 = "DuplicateTokenEx"                                     ascii nocase
        $tok5 = "ImpersonateLoggedOnUser"                              ascii nocase
        $tok6 = "SetThreadToken"                                       ascii nocase
        $tok7 = "AdjustTokenPrivileges"                                ascii nocase
        $tok8 = "NtSetInformationToken"                                ascii nocase

        // Privilege escalation tokens
        $priv1 = "SeDebugPrivilege"                                    ascii nocase
        $priv2 = "SeImpersonatePrivilege"                              ascii nocase
        $priv3 = "SeAssignPrimaryTokenPrivilege"                       ascii nocase
        $priv4 = "SeTcbPrivilege"                                      ascii nocase

        $tok1w = "CreateProcessWithTokenW"                             wide nocase
        $tok4w = "DuplicateTokenEx"                                    wide nocase

    condition:
        (($tok1 or $tok1w) or $tok2) and ($tok4 or $tok4w or $tok5)
        or ($tok3 and ($tok4 or $tok5))
        or $tok8
        or (any of ($tok4, $tok5, $tok6, $tok7) and 2 of ($priv*))
}


// ---------------------------------------------------------------------------
// DLL sideloading for UAC bypass via specific auto-elevating binaries.
// Known DLL hijack targets: sysprep.exe+cryptbase.dll, winsat.exe+winmm.dll,
// dism.exe+dismcore.dll — placing the malicious DLL in the same directory
// as the auto-elevating binary.
// ---------------------------------------------------------------------------
rule UAC_DLL_Sideload_AutoElevate
{
    meta:
        description = "UAC DLL sideload: known DLL hijack pairs for auto-elevating binaries (T1548.002 + T1574.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // sysprep.exe DLL targets
        $sp1 = "sysprep"                                               ascii nocase
        $sp_dll1 = "cryptbase.dll"                                     ascii nocase
        $sp_dll2 = "shcore.dll"                                        ascii nocase
        $sp_dll3 = "dbgcore.dll"                                       ascii nocase

        // winsat.exe DLL targets
        $ws1 = "winsat"                                                ascii nocase
        $ws_dll1 = "winmm.dll"                                        ascii nocase
        $ws_dll2 = "dxgi.dll"                                         ascii nocase

        // dism.exe / pkgmgr.exe DLL targets
        $dm1 = "dism"                                                  ascii nocase
        $dm2 = "pkgmgr"                                                ascii nocase
        $dm_dll1 = "dismcore.dll"                                      ascii nocase

        // File copy/write operations
        $cp1 = "copy"                                                  ascii nocase
        $cp2 = "xcopy"                                                 ascii nocase
        $cp3 = "Move-Item"                                             ascii nocase
        $cp4 = "Copy-Item"                                             ascii nocase

    condition:
        ($sp1 and any of ($sp_dll*) and any of ($cp*))
        or ($ws1 and any of ($ws_dll*) and any of ($cp*))
        or (($dm1 or $dm2) and $dm_dll1 and any of ($cp*))
}
