// Top PowerShell attack patterns. Covers CLM bypass, PS v2 downgrade, Add-Type
// compilation, WMI persistence, profile backdoors, credential access cmdlets,
// registry/scheduled-task persistence via PS, and logging evasion. Complements
// existing empire_stager_patterns.yar, fileless_script_patterns.yar, and
// download_cradle_patterns.yar.
//
// Tier: signal-only — every primitive here has benign uses in admin scripts.

// ---------------------------------------------------------------------------
// Constrained Language Mode (CLM) bypass. CLM restricts Add-Type, COM, .NET
// reflection, and other dangerous primitives. Attackers flip LanguageMode
// back to FullLanguage to restore access.
// ---------------------------------------------------------------------------
rule PS_CLM_Bypass
{
    meta:
        description = "PowerShell Constrained Language Mode bypass: LanguageMode set to FullLanguage / SessionState.LanguageMode probe (T1059.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $clm1 = "$ExecutionContext.SessionState.LanguageMode"          ascii nocase
        $clm2 = "FullLanguage"                                        ascii nocase
        $clm3 = "ConstrainedLanguage"                                 ascii nocase
        $clm4 = "LanguageMode"                                        ascii nocase
        $clm5 = "__PSLockdownPolicy"                                  ascii nocase
        $clm6 = "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds" ascii nocase

        $set1 = "= \"FullLanguage\""                                  ascii nocase
        $set2 = "= 'FullLanguage'"                                    ascii nocase

        $clm1w = "$ExecutionContext.SessionState.LanguageMode"         wide nocase

    condition:
        ($clm1 or $clm1w) or ($clm5)
        or (($clm2 or $clm3) and $clm4)
        or any of ($set*)
}


// ---------------------------------------------------------------------------
// PowerShell v2 downgrade. PS v2 has no AMSI, no ScriptBlock logging, no
// module logging — a complete telemetry bypass. Attacker invokes
// `powershell -Version 2` on a host where .NET 2.0 is still installed.
// ---------------------------------------------------------------------------
rule PS_V2_Downgrade_Attack
{
    meta:
        description = "PowerShell -Version 2 downgrade — bypasses AMSI and ScriptBlock logging (T1059.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $d1 = "powershell -version 2"                                  ascii nocase
        $d2 = "powershell.exe -version 2"                              ascii nocase
        $d3 = "powershell -v 2"                                        ascii nocase
        $d4 = "powershell.exe -v 2"                                    ascii nocase
        $d5 = "-version 2.0"                                           ascii nocase
        $d6 = "powershell -version 2 -"                                ascii nocase

        $d1w = "powershell -version 2"                                 wide nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// Add-Type inline C# compilation. Compiles and loads arbitrary C#/P/Invoke
// at runtime — the bridge from PS to native Win32 API without reflection.
// Paired with [DllImport] this is the canonical P/Invoke exploit shape.
// ---------------------------------------------------------------------------
rule PS_AddType_CSharp_Compilation
{
    meta:
        description = "Add-Type inline C# compilation with P/Invoke or unsafe code — PS-to-native API bridge (T1059.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $at1 = "Add-Type -TypeDefinition"                              ascii nocase
        $at2 = "Add-Type -MemberDefinition"                            ascii nocase
        $at3 = "Add-Type -Path"                                        ascii nocase

        $pi1 = "[DllImport("                                          ascii nocase
        $pi2 = "DllImportAttribute"                                    ascii nocase
        $pi3 = "Marshal.GetDelegateForFunctionPointer"                 ascii nocase
        $pi4 = "Marshal.AllocHGlobal"                                  ascii nocase
        $pi5 = "VirtualAlloc"                                          ascii nocase
        $pi6 = "CreateThread"                                          ascii nocase
        $pi7 = "VirtualProtect"                                        ascii nocase
        $pi8 = "RtlMoveMemory"                                        ascii nocase

    condition:
        any of ($at*) and any of ($pi*)
}


// ---------------------------------------------------------------------------
// WMI event subscription persistence. Creates a permanent WMI event that
// fires a command or script — survives reboot without Run keys or tasks.
// ---------------------------------------------------------------------------
rule PS_WMI_EventSubscription_Persistence
{
    meta:
        description = "WMI event subscription persistence: __EventFilter + __EventConsumer + FilterToConsumerBinding (T1546.003)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $w1 = "__EventFilter"                                          ascii nocase
        $w2 = "__EventConsumer"                                        ascii nocase
        $w3 = "CommandLineEventConsumer"                               ascii nocase
        $w4 = "ActiveScriptEventConsumer"                              ascii nocase
        $w5 = "__FilterToConsumerBinding"                              ascii nocase
        $w6 = "Register-WmiEvent"                                      ascii nocase
        $w7 = "Set-WmiInstance"                                        ascii nocase
        $w8 = "Register-CimIndicationEvent"                            ascii nocase
        $w9 = "New-CimInstance"                                        ascii nocase

    condition:
        ($w1 and $w2)
        or ($w1 and $w5)
        or ($w3 or $w4)
        or $w6 or $w7
        or ($w8 and $w1)
}


// ---------------------------------------------------------------------------
// PowerShell profile persistence. $PROFILE is loaded on every PS session —
// writing to it gives persistent execution in every interactive shell.
// ---------------------------------------------------------------------------
rule PS_Profile_Backdoor
{
    meta:
        description = "PowerShell profile backdoor: write/append to $PROFILE / profile.ps1 (T1546.013)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $p1 = "Set-Content $PROFILE"                                   ascii nocase
        $p2 = "Add-Content $PROFILE"                                   ascii nocase
        $p3 = "Out-File $PROFILE"                                      ascii nocase
        $p4 = "Out-File -FilePath $PROFILE"                            ascii nocase
        $p5 = "Microsoft.PowerShell_profile.ps1"                       ascii nocase
        $p6 = "Microsoft.PowerShellISE_profile.ps1"                    ascii nocase
        $p7 = "profile.ps1"                                            ascii nocase

        $w1 = "Set-Content"                                            ascii nocase
        $w2 = "Add-Content"                                            ascii nocase
        $w3 = "Out-File"                                               ascii nocase
        $w4 = "Invoke-Expression"                                      ascii nocase
        $w5 = "IEX"                                                    ascii nocase

    condition:
        any of ($p1, $p2, $p3, $p4)
        or (any of ($p5, $p6) and any of ($w*))
}


// ---------------------------------------------------------------------------
// Credential access cmdlets. PowerShell primitives that extract, convert,
// or enumerate stored credentials.
// ---------------------------------------------------------------------------
rule PS_Credential_Access
{
    meta:
        description = "PowerShell credential access: ConvertFrom-SecureString / [Net.NetworkCredential] / cmdkey / vaultcmd (T1552 / T1555)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $c1 = "ConvertFrom-SecureString"                               ascii nocase
        $c2 = "[Net.NetworkCredential]"                                ascii nocase
        $c3 = "[System.Net.NetworkCredential]"                         ascii nocase
        $c4 = "cmdkey /add"                                            ascii nocase
        $c5 = "vaultcmd /listcreds"                                    ascii nocase
        $c6 = "vaultcmd /listproperties"                               ascii nocase
        $c7 = "dpapi::masterkey"                                       ascii nocase
        $c8 = "dpapi::cred"                                            ascii nocase
        $c9 = "[System.Security.Cryptography.ProtectedData]"           ascii nocase
        $ca = "Unprotect-CmsMessage"                                   ascii nocase

        // SecureString → plaintext extraction chain
        $chain1 = "ConvertTo-SecureString"                             ascii nocase
        $chain2 = "GetNetworkCredential()"                             ascii nocase

    condition:
        any of ($c*) or ($chain1 and $chain2)
}


// ---------------------------------------------------------------------------
// PowerShell logging evasion. Disabling ScriptBlock logging, module logging,
// or redirecting the module analysis cache makes the PS runtime go silent.
// ---------------------------------------------------------------------------
rule PS_Logging_Evasion
{
    meta:
        description = "PowerShell logging evasion: ScriptBlockLogging disable / PSModuleAnalysisCachePath redirect (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $l1 = "EnableScriptBlockLogging"                               ascii nocase
        $l2 = "EnableScriptBlockInvocationLogging"                     ascii nocase
        $l3 = "PSModuleAnalysisCachePath"                              ascii nocase
        $l4 = "$env:PSModuleAnalysisCachePath"                         ascii nocase
        $l5 = "EnableModuleLogging"                                    ascii nocase
        $l6 = "ScriptBlockLogging"                                     ascii nocase

        // Registry paths for PS logging policy
        $r1 = "\\Policies\\Microsoft\\Windows\\PowerShell\\"          ascii nocase

        // Value set to 0 (disable)
        $v1 = "/d 0"                                                   ascii nocase
        $v2 = "-Value 0"                                               ascii nocase
        $v3 = "dword:00000000"                                         ascii nocase

    condition:
        ($l4 or $l3)
        or (any of ($l1, $l2, $l5, $l6) and $r1 and any of ($v*))
}


// ---------------------------------------------------------------------------
// Scheduled task creation via PowerShell cmdlets or schtasks.
// ---------------------------------------------------------------------------
rule PS_ScheduledTask_Persistence
{
    meta:
        description = "Scheduled task creation: Register-ScheduledTask / schtasks /create with execution payload (T1053.005)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $st1 = "Register-ScheduledTask"                                ascii nocase
        $st2 = "New-ScheduledTaskAction"                               ascii nocase
        $st3 = "New-ScheduledTaskTrigger"                              ascii nocase
        $st4 = "schtasks /create"                                      ascii nocase
        $st5 = "schtasks.exe /create"                                  ascii nocase
        $st6 = "schtasks /change"                                      ascii nocase

        // Payload indicators chained with task creation
        $p1 = "powershell"                                             ascii nocase
        $p2 = "cmd.exe"                                                ascii nocase
        $p3 = "mshta"                                                  ascii nocase
        $p4 = "wscript"                                                ascii nocase
        $p5 = "rundll32"                                               ascii nocase
        $p6 = "-encodedcommand"                                        ascii nocase

    condition:
        ($st1 and $st2)
        or ($st1 and $st3)
        or (any of ($st4, $st5, $st6) and any of ($p*))
}
