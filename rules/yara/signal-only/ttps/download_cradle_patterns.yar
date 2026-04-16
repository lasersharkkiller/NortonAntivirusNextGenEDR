// Download-cradle fingerprints. A "cradle" is a two-part primitive that
// fetches remote content and feeds it to an in-process executor without
// touching disk — the canonical stage-2 delivery shape across Empire,
// Covenant, Sliver PS profiles, Metasploit web_delivery, commodity stealers,
// and ad-hoc operator one-liners.
//
// Tier: signal-only — every primitive below has legitimate uses (package
// managers, install scripts, RMM tooling, telemetry uploaders). Chain with
// process parentage, signing, path, and outbound-destination context before
// action.

// ---------------------------------------------------------------------------
// PowerShell WebClient / Invoke-WebRequest cradles paired with an executor.
// The ordered pair [remote fetch] + [IEX / Assembly.Load / Start-Process]
// is the cradle shape — either half alone is too noisy to act on.
// ---------------------------------------------------------------------------
rule Cradle_PowerShell_WebClient_Invoke_Chain
{
    meta:
        description = "PowerShell WebClient/IWR cradle chained into IEX / Assembly.Load / Start-Process (T1059.001 / T1105)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Fetch primitives
        $f1  = "(New-Object Net.WebClient).DownloadString("           ascii nocase
        $f2  = "(New-Object System.Net.WebClient).DownloadString("    ascii nocase
        $f3  = "(New-Object Net.WebClient).DownloadData("             ascii nocase
        $f4  = "(New-Object Net.WebClient).DownloadFile("             ascii nocase
        $f5  = "Invoke-WebRequest -Uri"                               ascii nocase
        $f6  = "Invoke-RestMethod -Uri"                               ascii nocase
        $f7  = "iwr -Uri"                                             ascii nocase
        $f8  = "irm -Uri"                                             ascii nocase
        $f9  = "iwr http"                                             ascii nocase
        $f10 = "irm http"                                             ascii nocase
        $f11 = "[Net.WebRequest]::Create("                            ascii nocase
        $f12 = "[System.Net.WebRequest]::Create("                     ascii nocase
        $f13 = "HttpClient).GetStringAsync("                          ascii nocase
        $f14 = "HttpClient).GetByteArrayAsync("                       ascii nocase

        // Executor primitives
        $x1  = "| IEX"                                                ascii nocase
        $x2  = "|IEX"                                                 ascii nocase
        $x3  = "Invoke-Expression"                                    ascii nocase
        $x4  = "iex ("                                                ascii nocase
        $x5  = "iex("                                                 ascii nocase
        $x6  = "[Reflection.Assembly]::Load("                         ascii nocase
        $x7  = "[System.Reflection.Assembly]::Load("                  ascii nocase
        $x8  = "::EntryPoint.Invoke("                                 ascii nocase
        $x9  = "Start-Process"                                        ascii nocase

        // Wide variants for in-memory PowerShell
        $f1w = "(New-Object Net.WebClient).DownloadString("           wide nocase
        $f5w = "Invoke-WebRequest -Uri"                               wide nocase
        $x1w = "| IEX"                                                wide nocase
        $x3w = "Invoke-Expression"                                    wide nocase

    condition:
        (any of ($f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14)
         and any of ($x1, $x2, $x3, $x4, $x5, $x6, $x7, $x8, $x9))
        or ((any of ($f1w, $f5w)) and (any of ($x1w, $x3w)))
}


// ---------------------------------------------------------------------------
// COM XHR cradles — Msxml2.XMLHTTP / WinHttp.WinHttpRequest from JScript,
// VBScript, HTA, and PowerShell New-Object -ComObject. Classic "mshta" and
// "wscript //e:jscript" delivery vehicle, also used by Excel 4.0 macros that
// escape to VBA and by SquiblyTwo variants.
// ---------------------------------------------------------------------------
rule Cradle_COM_XHR_Fetch_Execute
{
    meta:
        description = "COM XHR cradle (Msxml2.XMLHTTP / WinHttp.WinHttpRequest) paired with ShellExecute / Eval / Run / ADODB.Stream write"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $c1 = "Msxml2.XMLHTTP"                                        ascii nocase
        $c2 = "Msxml2.ServerXMLHTTP"                                  ascii nocase
        $c3 = "WinHttp.WinHttpRequest.5.1"                            ascii nocase
        $c4 = "Microsoft.XMLHTTP"                                     ascii nocase
        $c5 = "New-Object -ComObject Msxml2"                          ascii nocase
        $c6 = "New-Object -Com Msxml2"                                ascii nocase
        $c7 = "New-Object -Com WinHttp"                               ascii nocase

        // Follow-on execution primitives that turn a fetch into a cradle
        $e1 = ".ResponseBody"                                         ascii nocase
        $e2 = ".ResponseText"                                         ascii nocase
        $e3 = "ADODB.Stream"                                          ascii nocase
        $e4 = "WScript.Shell"                                         ascii nocase
        $e5 = ".ShellExecute("                                        ascii nocase
        $e6 = ".Run("                                                 ascii nocase
        $e7 = "eval("                                                 ascii nocase
        $e8 = "Execute("                                              ascii nocase
        $e9 = "ExecuteGlobal "                                        ascii nocase

    condition:
        any of ($c*) and 2 of ($e*)
}


// ---------------------------------------------------------------------------
// BITS cradle — Start-BitsTransfer / bitsadmin /transfer used to pull a
// binary and optionally chain SetNotifyCmdLine for execution-on-completion.
// Common in HAFNIUM, Diavol, Conti precursors, and many commodity stealers.
// ---------------------------------------------------------------------------
rule Cradle_BITS_Transfer_Fetch
{
    meta:
        description = "BITS download cradle (Start-BitsTransfer / bitsadmin /transfer, optional SetNotifyCmdLine execution) — T1197 / T1105"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $b1 = "Start-BitsTransfer -Source"                            ascii nocase
        $b2 = "Start-BitsTransfer"                                    ascii nocase
        $b3 = "Import-Module BitsTransfer"                            ascii nocase
        $b4 = "bitsadmin /transfer"                                   ascii nocase
        $b5 = "bitsadmin.exe /transfer"                               ascii nocase
        $b6 = "/SetNotifyCmdLine"                                     ascii nocase
        $b7 = "bitsadmin /create"                                     ascii nocase
        $b8 = "bitsadmin /addfile"                                    ascii nocase
        $b9 = "bitsadmin /resume"                                     ascii nocase

        $b1w = "Start-BitsTransfer"                                   wide  nocase
        $b4w = "bitsadmin /transfer"                                  wide  nocase

    condition:
        any of ($b*)
}


// ---------------------------------------------------------------------------
// LOLBin URL-fetch cradles. certutil -urlcache, mshta http, regsvr32 scrobj
// URL, rundll32 url.dll FileProtocolHandler / OpenURL. The binary name plus
// a URL token on the same line is the signal — benign admin use of these is
// almost never paired with an http(s) argument.
// ---------------------------------------------------------------------------
rule Cradle_LOLBin_URL_Fetch
{
    meta:
        description = "LOLBin URL-fetch cradle: certutil -urlcache / mshta http / regsvr32 /i:http / rundll32 url.dll (T1218)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $c_certutil_a = "certutil -urlcache -split -f"                ascii nocase
        $c_certutil_b = "certutil.exe -urlcache"                      ascii nocase
        $c_certutil_c = "certutil -urlcache -f http"                  ascii nocase
        $c_certutil_d = "certutil -urlcache"                          ascii nocase

        $c_mshta_a    = "mshta http"                                  ascii nocase
        $c_mshta_b    = "mshta vbscript:"                             ascii nocase
        $c_mshta_c    = "mshta javascript:"                           ascii nocase

        $c_regsvr_a   = "regsvr32 /s /n /u /i:http"                   ascii nocase
        $c_regsvr_b   = "regsvr32.exe /s /n /u /i:http"               ascii nocase
        $c_regsvr_c   = "regsvr32 /u /s /i:http"                      ascii nocase

        $c_rundll_a   = "rundll32 javascript:"                        ascii nocase
        $c_rundll_b   = "rundll32.exe javascript:"                    ascii nocase
        $c_rundll_c   = "rundll32 url.dll,OpenURL"                    ascii nocase
        $c_rundll_d   = "rundll32 url.dll,FileProtocolHandler"        ascii nocase
        $c_rundll_e   = "rundll32.exe url.dll,FileProtocolHandler"    ascii nocase

        $c_msiexec    = "msiexec /i http"                             ascii nocase
        $c_msiexec2   = "msiexec /i:http"                             ascii nocase
        $c_msiexec3   = "msiexec /q /i http"                          ascii nocase

        $c_finger     = "finger.exe "                                 ascii nocase
        $c_finger2    = "| finger "                                   ascii nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// Reflective Assembly.Load cradle — the "in-memory .NET loader" pattern
// where DownloadData() bytes are passed directly to Assembly.Load without
// hitting disk. The signature of choice for Covenant Grunt stagers, Posh
// assembly cradles, and many C# tradecraft loaders.
// ---------------------------------------------------------------------------
rule Cradle_Reflective_Assembly_From_URL
{
    meta:
        description = "Reflective .NET Assembly.Load fed from a remote-fetched byte buffer — in-memory stager cradle (T1620)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $a1 = "[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData"         ascii nocase
        $a2 = "[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData"  ascii nocase
        $a3 = "[Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData"  ascii nocase
        $a4 = "[Reflection.Assembly]::Load([Convert]::FromBase64String"                      ascii nocase
        $a5 = "[System.Reflection.Assembly]::Load([Convert]::FromBase64String"               ascii nocase
        $a6 = "Assembly.Load((New-Object Net.WebClient).DownloadData"                        ascii nocase
        $a7 = "::EntryPoint.Invoke($null,"                                                   ascii nocase

        $a1w = "[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData"        wide nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// DNS cradles — payload delivered as TXT-record data, then Resolve-DnsName
// / nslookup output is concatenated and executed. Invoke-DNSExfiltrator and
// Invoke-DNSCat2 follow this shape, as do commodity DNS-tunnel loaders.
// ---------------------------------------------------------------------------
rule Cradle_DNS_TXT_Fetch_Execute
{
    meta:
        description = "DNS TXT-record cradle: Resolve-DnsName -Type TXT piped into IEX / assembled from labels (T1071.004)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $d1 = "Resolve-DnsName -Type TXT"                             ascii nocase
        $d2 = "Resolve-DnsName"                                       ascii nocase
        $d3 = "[System.Net.Dns]::GetHostEntry("                       ascii nocase
        $d4 = "nslookup -type=txt"                                    ascii nocase
        $d5 = "Invoke-DNSExfiltrator"                                 ascii nocase
        $d6 = "Invoke-DNSCat"                                         ascii nocase

        // Executor
        $x1 = "| IEX"                                                 ascii nocase
        $x2 = "Invoke-Expression"                                     ascii nocase
        $x3 = "iex ("                                                 ascii nocase

    condition:
        ($d1 and any of ($x1, $x2, $x3))
        or $d5 or $d6
        or ($d2 and $d1 and any of ($x1, $x2, $x3))
}


// ---------------------------------------------------------------------------
// Char-split / concat obfuscated cradles. Invoke-Obfuscation splits the
// canonical method names across "+" concatenations so naive string matches
// on "DownloadString" miss. We explicitly enumerate the split variants that
// appear in Empire / Invoke-Obfuscation output.
// ---------------------------------------------------------------------------
rule Cradle_CharSplit_Obfuscated
{
    meta:
        description = "Char-split / concat-obfuscated cradle method names (Invoke-Obfuscation / Empire Launcher)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $s1 = "\"Download\"+\"String\""                               ascii nocase
        $s2 = "\"Downloads\"+\"tring\""                               ascii nocase
        $s3 = "\"Down\"+\"loadString\""                               ascii nocase
        $s4 = "\"DownLoad\"+\"String\""                               ascii nocase
        $s5 = "\"Invoke\"+\"-Expression\""                            ascii nocase
        $s6 = "\"I\"+\"EX\""                                          ascii nocase
        $s7 = "\"Net.\"+\"WebClient\""                                ascii nocase
        $s8 = "\"New-\"+\"Object\""                                   ascii nocase
        $s9 = "\"FromBase64\"+\"String\""                             ascii nocase

        // Backtick escape obfuscation: D`own`load`Str`ing
        $bt1 = "D`ownload`String"                                     ascii nocase
        $bt2 = "D`o`w`n`l`o`a`d`S`t`r`i`n`g"                          ascii nocase
        $bt3 = "I`E`X"                                                ascii nocase
        $bt4 = "In`voke-Ex`pression"                                  ascii nocase

        // Format-operator obfuscation: ("{0}{1}" -f 'Download','String')
        $fmt = /\"\{0\}\{1\}\"\s*-f\s*'[A-Za-z]{3,12}'\s*,\s*'[A-Za-z]{3,12}'/ nocase

    condition:
        any of ($s*) or any of ($bt*) or $fmt
}
