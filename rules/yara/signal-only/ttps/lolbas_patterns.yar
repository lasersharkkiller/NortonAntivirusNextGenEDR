// Living-off-the-land binary/script (LOLBAS) fingerprints. Pairs a name+path
// indicator with an abuse-signature primitive so a benign shortcut to
// certutil.exe doesn't fire. Scans scripts, config files, OneNote/HTA/XSL
// documents, PowerShell transcripts, and any other text-ish content where
// attacker recipes get materialised.
//
// Tier: signal-only — every single token below appears in legitimate Windows
// administration, developer tooling, MSDN samples, and pentest training
// material. Chain with process context (parent, user-writable path,
// outbound network, etc.) before quarantine.

// ---------------------------------------------------------------------------
// MSBuild inline-task C# execution (T1127.001). An .xml/.csproj that contains
// a <UsingTask> + Fragment-class + Execute method + <Code Type="Class"> inline
// block is a C#-via-MSBuild payload — the MSBuild binary compiles & runs it.
// ---------------------------------------------------------------------------
rule LOLBAS_MSBuild_InlineTask_CSharp
{
    meta:
        description = "MSBuild inline-task payload: <UsingTask>+<Code Type=\"Class\"> XML executes arbitrary C# via msbuild.exe (T1127.001)"
        author      = "NortonEDR"
        reference   = "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $xml_pi       = "<?xml"                                                    ascii nocase
        $project      = "<Project "                                                ascii nocase
        $using_task   = "<UsingTask"                                               ascii nocase
        $task_factory = "TaskFactory=\"CodeTaskFactory\""                          ascii nocase
        $task_factory2= "TaskFactory=\"RoslynCodeTaskFactory\""                    ascii nocase
        $task_fragment= "<Task>"                                                   ascii nocase
        $code_class   = "<Code Type=\"Class\""                                     ascii nocase
        $code_frag    = "<Code Type=\"Fragment\""                                  ascii nocase
        $using_sys    = "using System"                                             ascii
        $itask        = "ITask"                                                    ascii
        $execute_m    = "public override bool Execute"                             ascii
        $assembly_l   = "Assembly.Load"                                            ascii

    condition:
        $xml_pi and $project and $using_task
        and any of ($task_factory, $task_factory2)
        and any of ($code_class, $code_frag)
        and any of ($using_sys, $itask, $execute_m, $assembly_l)
}


// ---------------------------------------------------------------------------
// Squiblydoo / scrobj.dll — regsvr32 /s /u /i:<url> scriptlet exec (T1218.010)
// The payload is a .sct / .xml with <scriptlet><registration><script> block.
// ---------------------------------------------------------------------------
rule LOLBAS_Scrobj_Scriptlet_Payload
{
    meta:
        description = "COM scriptlet (.sct/.xml) payload for regsvr32 scrobj.dll exec (Squiblydoo / T1218.010)"
        author      = "NortonEDR"
        reference   = "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $s1 = "<scriptlet"                                                         ascii nocase
        $s2 = "<registration"                                                      ascii nocase
        $s3 = "<!CDATA["                                                           ascii nocase
        $s4 = "</script>"                                                          ascii nocase
        $s5 = "scrobj.dll"                                                         ascii nocase
        $s6 = "progid="                                                            ascii nocase
        $s7 = "classid=\"{"                                                        ascii nocase
        $s8 = "<public>"                                                           ascii nocase
        $scriptrun = "new ActiveXObject("                                          ascii nocase

    condition:
        ($s1 and $s2) or
        ($s5 and 2 of ($s3, $s4, $s6, $s7, $s8, $scriptrun))
}


// ---------------------------------------------------------------------------
// XSL script-processor abuse (T1220). Any XSL stylesheet that contains a
// <msxsl:script> or user:CreateObject is script-proxy-exec material —
// wmic /format:evil.xsl, msxsl.exe, powershell Add-Type [Xsl] load all rely
// on this primitive.
// ---------------------------------------------------------------------------
rule LOLBAS_XSL_ScriptProcessor
{
    meta:
        description = "XSL stylesheet with embedded JScript/VBScript <msxsl:script> — T1220 XSL Script Processing"
        author      = "NortonEDR"
        reference   = "https://lolbas-project.github.io/lolbas/Binaries/Wmic/"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $xsl_ns   = "http://www.w3.org/1999/XSL/Transform"                         ascii nocase
        $msxsl    = "<msxsl:script"                                                ascii nocase
        $lang_js  = "language=\"JScript\""                                         ascii nocase
        $lang_vbs = "language=\"VBScript\""                                        ascii nocase
        $lang_cs  = "language=\"C#\""                                              ascii nocase
        $user_obj = "user:"                                                        ascii nocase
        $active_x = "new ActiveXObject"                                            ascii nocase
        $shell    = "WScript.Shell"                                                ascii nocase
        $cmd      = ".Run("                                                        ascii nocase

    condition:
        $xsl_ns and $msxsl and any of ($lang_js, $lang_vbs, $lang_cs)
        and any of ($user_obj, $active_x, $shell, $cmd)
}


// ---------------------------------------------------------------------------
// HTA / Office-macro proxy-exec payload. .hta is plain HTML + <script> with
// ActiveX, served via mshta.exe. Matches HTA files and inline-HTA strings in
// phishing-stage documents.
// ---------------------------------------------------------------------------
rule LOLBAS_HTA_Payload
{
    meta:
        description = "HTML Application (.hta) payload — mshta.exe proxy-exec vehicle (T1218.005)"
        author      = "NortonEDR"
        reference   = "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $hta_app   = "<hta:application"                                            ascii nocase
        $hta_app_w = "<hta:application"                                            wide  nocase
        $active    = "new ActiveXObject("                                          ascii nocase
        $shell_run = ".ShellExecute("                                              ascii nocase
        $wsh_run   = "WScript.Shell"                                               ascii nocase
        $xhr       = "MSXML2.XMLHTTP"                                              ascii nocase
        $stream    = "ADODB.Stream"                                                ascii nocase
        $download  = "DownloadFile("                                               ascii nocase

    condition:
        ($hta_app or $hta_app_w)
        and any of ($active, $shell_run, $wsh_run, $xhr, $stream, $download)
}


// ---------------------------------------------------------------------------
// INF-file LOLBin proxy exec (T1218 advpack/ieadvpack/setupapi variants).
// The RegisterOCXs / RunPreSetupCommands / AddReg sections are the abuse
// primitives — they execute a command or write HKLM\...\Run persistence.
// ---------------------------------------------------------------------------
rule LOLBAS_INF_ProxyExec
{
    meta:
        description = "INF file containing RegisterOCXs / RunPreSetupCommands — advpack/ieadvpack/setupapi LaunchINFSection proxy-exec (T1218)"
        author      = "NortonEDR"
        reference   = "https://lolbas-project.github.io/lolbas/Binaries/Advpack/"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        $version   = "[version]"                                                   ascii nocase
        $sig       = "Signature=\"$"                                               ascii nocase
        $default   = "[DefaultInstall"                                             ascii nocase
        $reg_ocx   = "RegisterOCXs="                                               ascii nocase
        $run_pre   = "RunPreSetupCommands="                                        ascii nocase
        $run_post  = "RunPostSetupCommands="                                       ascii nocase
        $unreg_ocx = "UnregisterOCXs="                                             ascii nocase
        $addreg_run= "HKLM,\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\""  ascii nocase
        $addreg_rl = "HKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\""  ascii nocase
        $cmdexec   = "cmd.exe /c"                                                  ascii nocase
        $psexec    = "powershell"                                                  ascii nocase

    condition:
        ($version and $sig and $default) and
        (any of ($reg_ocx, $run_pre, $run_post, $unreg_ocx) or
         (any of ($addreg_run, $addreg_rl) and any of ($cmdexec, $psexec)))
}


// ---------------------------------------------------------------------------
// PowerShell one-liner ingress-tool-transfer recipe cluster. Catches the
// canonical "download -> execute" shapes in PS1 payloads, scheduled-task
// Actions, WMI __EventConsumer CommandLineTemplate, and anywhere else an
// attacker stashes a bootstrap.
// ---------------------------------------------------------------------------
rule LOLBAS_PowerShell_IngressExec_OneLiner
{
    meta:
        description = "PowerShell download-and-execute one-liner: WebClient/Invoke-WebRequest + IEX / Start-Process / Assembly.Load"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $fetch1 = "(New-Object Net.WebClient).DownloadString("                     ascii nocase
        $fetch2 = "(New-Object System.Net.WebClient).DownloadString("              ascii nocase
        $fetch3 = "(New-Object Net.WebClient).DownloadFile("                       ascii nocase
        $fetch4 = "Invoke-WebRequest -Uri"                                         ascii nocase
        $fetch5 = "iwr -Uri"                                                       ascii nocase
        $fetch6 = "curl.exe -s"                                                    ascii nocase

        $exec1  = "| IEX"                                                          ascii nocase
        $exec2  = "|iex"                                                           ascii nocase
        $exec3  = "Invoke-Expression ("                                            ascii nocase
        $exec4  = "Start-Process"                                                  ascii nocase
        $exec5  = "[System.Reflection.Assembly]::Load("                            ascii nocase
        $exec6  = "::EntryPoint.Invoke("                                           ascii nocase

        // Wide form for PowerShell in-memory buffers
        $fetch1w = "(New-Object Net.WebClient).DownloadString("                    wide  nocase
        $exec1w  = "| IEX"                                                         wide  nocase

    condition:
        (any of ($fetch1, $fetch2, $fetch3, $fetch4, $fetch5, $fetch6)
         and any of ($exec1, $exec2, $exec3, $exec4, $exec5, $exec6))
        or ($fetch1w and $exec1w)
}


// ---------------------------------------------------------------------------
// LOLBin-by-pathless-hash avoidance: catches the "renamed LOLBin" trick where
// certutil.exe / bitsadmin.exe / etc. is copied elsewhere and renamed. We
// match on the internal OriginalFilename / ProductName / FileDescription
// strings embedded in the PE resource, which attackers rarely strip because
// doing so breaks signature validation.
// ---------------------------------------------------------------------------
rule LOLBAS_Renamed_MSBinary_VersionInfo
{
    meta:
        description = "PE file claims Microsoft LOLBin version-info (OriginalFilename certutil/bitsadmin/etc.) — pair with on-disk basename mismatch to catch renamed LOLBin abuse"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "medium"
        scan_target = "file"

    strings:
        $mz   = { 4D 5A }
        $ofn  = "OriginalFilename"                                                 wide
        $c1   = "certutil.exe"                                                     wide  nocase
        $c2   = "bitsadmin.exe"                                                    wide  nocase
        $c3   = "rundll32.exe"                                                     wide  nocase
        $c4   = "regsvr32.exe"                                                     wide  nocase
        $c5   = "mshta.exe"                                                        wide  nocase
        $c6   = "installutil.exe"                                                  wide  nocase
        $c7   = "msbuild.exe"                                                      wide  nocase
        $c8   = "msxsl.exe"                                                        wide  nocase
        $c9   = "wmic.exe"                                                         wide  nocase
        $c10  = "cmstp.exe"                                                        wide  nocase
        $c11  = "atbroker.exe"                                                     wide  nocase
        $c12  = "mavinject.exe"                                                    wide  nocase
        $c13  = "ieexec.exe"                                                       wide  nocase

        // Microsoft vendor strings — confirms the PE is MS-signed LOLBin-class
        $ms1  = "Microsoft Corporation"                                            wide
        $ms2  = "Microsoft(R) Windows(R) Operating System"                         wide

    condition:
        $mz at 0 and $ofn and any of ($c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9, $c10, $c11, $c12, $c13)
        and any of ($ms1, $ms2)
}
