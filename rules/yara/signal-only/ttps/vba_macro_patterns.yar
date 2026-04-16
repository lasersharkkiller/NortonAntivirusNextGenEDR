// VBA macro payload fingerprints. Targets the entry-point handlers,
// shell-execution primitives, object-creation chains, and DDE auto-fields
// that appear in phishing macro droppers. Operates on raw file bytes — the
// VBA module source text in legacy OLE (CFB) .doc/.xls/.ppt files is stored
// partially uncompressed, so literal strings frequently match without
// decompression. For OOXML (.docm/.xlsm), YARA scans the outer ZIP; many
// of the patterns also match in `vbaProject.bin` entries that are zip-Stored
// rather than Deflated.
//
// Tier: signal-only — these primitives appear in legitimate VBA macros
// (report generators, data import, UI automation). Chain with parent
// process (explorer/outlook/browser), MOTW, and path context.

// ---------------------------------------------------------------------------
// Macro auto-execute entry points. Every phishing macro needs at least one
// of these to fire without user interaction beyond enabling macros.
// ---------------------------------------------------------------------------
rule VBA_AutoExec_EntryPoint
{
    meta:
        description = "VBA auto-execute entry point: AutoOpen / Document_Open / Workbook_Open / Auto_Close / Document_Close (T1204.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "medium"
        scan_target = "file"

    strings:
        $a1  = "AutoOpen"                                              ascii nocase
        $a2  = "Auto_Open"                                             ascii nocase
        $a3  = "Document_Open"                                         ascii nocase
        $a4  = "Workbook_Open"                                         ascii nocase
        $a5  = "AutoClose"                                             ascii nocase
        $a6  = "Auto_Close"                                            ascii nocase
        $a7  = "Document_Close"                                        ascii nocase
        $a8  = "Workbook_BeforeClose"                                  ascii nocase
        $a9  = "Workbook_Activate"                                     ascii nocase
        $a10 = "AutoExec"                                              ascii nocase
        $a11 = "Document_New"                                          ascii nocase
        $a12 = "Workbook_BeforeSave"                                   ascii nocase
        $a13 = "InkPicture_Painted"                                    ascii nocase
        $a14 = "ContentControlOnExit"                                  ascii nocase
        $a15 = "MultiPage1_Layout"                                     ascii nocase

        // Presence of VBA module source marker (confirms this is a VBA project)
        $vba_attr = "Attribute VB_Name"                                ascii nocase

    condition:
        $vba_attr and any of ($a*)
}


// ---------------------------------------------------------------------------
// VBA shell-execution primitives. These turn a macro into a launcher — the
// macro constructs a cmdline and calls one of these to execute it.
// ---------------------------------------------------------------------------
rule VBA_Shell_Execution_Primitive
{
    meta:
        description = "VBA macro with shell-execution primitive: Shell() / WScript.Shell / CreateObject / ShellExecute (T1059.005)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        // Auto-exec gate
        $gate1  = "AutoOpen"                                           ascii nocase
        $gate2  = "Auto_Open"                                          ascii nocase
        $gate3  = "Document_Open"                                      ascii nocase
        $gate4  = "Workbook_Open"                                      ascii nocase
        $gate5  = "AutoExec"                                           ascii nocase
        $gate6  = "Document_Close"                                     ascii nocase
        $gate7  = "Workbook_BeforeClose"                               ascii nocase

        // Execution primitives
        $s1  = "Shell("                                                ascii nocase
        $s2  = "Shell "                                                ascii nocase
        $s3  = "WScript.Shell"                                         ascii nocase
        $s4  = "CreateObject(\"WScript.Shell\")"                       ascii nocase
        $s5  = "CreateObject(\"Shell.Application\")"                   ascii nocase
        $s6  = ".ShellExecute "                                        ascii nocase
        $s7  = "CreateObject(\"Scripting.FileSystemObject\")"          ascii nocase
        $s8  = "WinExec"                                               ascii nocase
        $s9  = "CallByName"                                            ascii nocase
        $s10 = "MacScript"                                             ascii nocase
        $s11 = "Application.Run"                                       ascii nocase
        $s12 = "VBA.Shell"                                             ascii nocase
        $s13 = "Interaction.Shell"                                     ascii nocase
        $s14 = "CreateObject(\"WScript.Network\")"                     ascii nocase

    condition:
        any of ($gate*) and 2 of ($s*)
}


// ---------------------------------------------------------------------------
// VBA download / network cradle. Macro fetches a second stage over the
// network — XMLHTTP, WinHttp, ADODB.Stream, URLDownloadToFile, or
// PowerShell invocation from VBA.
// ---------------------------------------------------------------------------
rule VBA_Download_Cradle
{
    meta:
        description = "VBA macro with network fetch: XMLHTTP / ADODB.Stream / URLDownloadToFile / PowerShell invocation (T1204.002 + T1105)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        $gate1 = "AutoOpen"                                            ascii nocase
        $gate2 = "Auto_Open"                                           ascii nocase
        $gate3 = "Document_Open"                                       ascii nocase
        $gate4 = "Workbook_Open"                                       ascii nocase
        $gate5 = "AutoExec"                                            ascii nocase

        $n1  = "MSXML2.XMLHTTP"                                       ascii nocase
        $n2  = "Microsoft.XMLHTTP"                                     ascii nocase
        $n3  = "WinHttp.WinHttpRequest"                                ascii nocase
        $n4  = "ADODB.Stream"                                          ascii nocase
        $n5  = "URLDownloadToFile"                                     ascii nocase
        $n6  = "URLDownloadToFileA"                                    ascii nocase
        $n7  = ".Open \"GET\""                                         ascii nocase
        $n8  = ".Open \"POST\""                                        ascii nocase
        $n9  = ".ResponseBody"                                         ascii nocase
        $n10 = ".ResponseText"                                         ascii nocase
        $n11 = "Net.WebClient"                                         ascii nocase
        $n12 = "powershell"                                            ascii nocase
        $n13 = "DownloadFile("                                         ascii nocase
        $n14 = "Lib \"urlmon\""                                        ascii nocase

    condition:
        any of ($gate*) and 2 of ($n*)
}


// ---------------------------------------------------------------------------
// VBA process-injection primitives. Macros that call Win32 API via Declare
// to allocate memory, write shellcode, and CreateThread — the classic
// VBA-macro-to-shellcode bridge.
// ---------------------------------------------------------------------------
rule VBA_Process_Injection_API
{
    meta:
        description = "VBA macro with Win32 injection API: VirtualAlloc / RtlMoveMemory / CreateThread (T1204.002 + T1055)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file"

    strings:
        $d1 = "Declare "                                               ascii nocase
        $d2 = "Private Declare "                                       ascii nocase
        $d3 = "Declare PtrSafe Function"                               ascii nocase

        $a1 = "VirtualAlloc"                                           ascii nocase
        $a2 = "VirtualAllocEx"                                         ascii nocase
        $a3 = "RtlMoveMemory"                                         ascii nocase
        $a4 = "RtlCopyMemory"                                         ascii nocase
        $a5 = "CreateThread"                                           ascii nocase
        $a6 = "CreateRemoteThread"                                     ascii nocase
        $a7 = "NtAllocateVirtualMemory"                                ascii nocase
        $a8 = "NtWriteVirtualMemory"                                   ascii nocase
        $a9 = "WriteProcessMemory"                                     ascii nocase
        $aa = "EnumSystemLocalesA"                                     ascii nocase
        $ab = "EnumChildWindows"                                       ascii nocase
        $ac = "EnumWindows"                                            ascii nocase

    condition:
        any of ($d*) and ($a1 or $a2 or $a7) and ($a3 or $a4 or $a8 or $a9) and ($a5 or $a6 or $aa or $ab or $ac)
}


// ---------------------------------------------------------------------------
// DDE auto-field in Office document. DDE (Dynamic Data Exchange) abuses the
// =DDEAUTO() field / DDEAUTO field-code in Word/Excel to launch commands
// without macros at all.
// ---------------------------------------------------------------------------
rule Office_DDE_AutoField
{
    meta:
        description = "DDE auto-execution field in Office document — DDEAUTO / DDE with cmd/powershell (T1559.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        $dde1 = "DDEAUTO"                                             ascii nocase
        $dde2 = "DDE "                                                ascii nocase
        $dde3 = "dde\""                                               ascii nocase

        $cmd1 = "cmd.exe"                                             ascii nocase
        $cmd2 = "powershell"                                          ascii nocase
        $cmd3 = "cmd /c"                                              ascii nocase
        $cmd4 = "cmd /k"                                              ascii nocase
        $cmd5 = "mshta "                                              ascii nocase
        $cmd6 = "certutil "                                           ascii nocase
        $cmd7 = "bitsadmin "                                          ascii nocase

    condition:
        any of ($dde*) and any of ($cmd*)
}


// ---------------------------------------------------------------------------
// GetObject("new:" / GetObject("winmgmts:") WMI pivot from VBA.
// Creates a live WMI process without CreateObject("WScript.Shell") so it
// evades simple shell-exec pattern matches.
// ---------------------------------------------------------------------------
rule VBA_GetObject_WMI_Pivot
{
    meta:
        description = "VBA GetObject WMI pivot — GetObject(\"new:\" / \"winmgmts:\") process launch (T1059.005 + T1047)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        $g1 = "GetObject(\"new:"                                      ascii nocase
        $g2 = "GetObject(\"winmgmts:"                                 ascii nocase
        $g3 = "GetObject(\"winmgmts:{impersonationLevel=impersonate}" ascii nocase
        $g4 = "Win32_Process"                                         ascii nocase
        $g5 = "Win32_ProcessStartup"                                  ascii nocase
        $g6 = ".Create("                                              ascii nocase
        $g7 = "Win32_ScheduledJob"                                    ascii nocase

    condition:
        (any of ($g1, $g2, $g3)) and any of ($g4, $g5, $g6, $g7)
}


// ---------------------------------------------------------------------------
// Stomped VBA p-code (Evil Clippy / OfficePurge). When the VBA source text
// is stripped but the compiled p-code is left intact, there's a telltale:
// "Attribute VB_Name" is missing while the _VBA_PROJECT stream header with
// its version and MODULEOFFSET entries still exists. We match the CFB dir
// marker + p-code header in the absence of the source-text attribute.
// ---------------------------------------------------------------------------
rule VBA_Stomped_PCode
{
    meta:
        description = "VBA project with compiled p-code but no source text (Attribute VB_Name absent) — Evil Clippy / OfficePurge stomping (T1027)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        // CFB magic
        $cfb     = { D0 CF 11 E0 A1 B1 1A E1 }

        // _VBA_PROJECT stream header: version-independent magic 0xCC 0x61
        $vba_hdr = { CC 61 }

        // Module stream compile-time markers
        $module_offset = "MODULEOFFSET"                                ascii nocase

        // VBA source marker — should be present in healthy projects
        $vba_attr = "Attribute VB_Name"                                ascii nocase

    condition:
        $cfb at 0 and $vba_hdr and $module_offset and not $vba_attr
}


// ---------------------------------------------------------------------------
// VBA callback / delayed execution. Application.OnTime schedules code to
// run at a specific time or after a delay; Application.OnKey fires on
// keystrokes. Both bypass immediate auto-exec monitoring and are used to
// defer payload detonation past sandbox analysis windows.
// ---------------------------------------------------------------------------
rule VBA_Callback_Delayed_Execution
{
    meta:
        description = "VBA callback/delayed execution: Application.OnTime / OnKey / UserForm event handlers (T1137 + T1059.005)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Scheduled / callback triggers
        $cb1 = "Application.OnTime"                                    ascii nocase
        $cb2 = "Application.OnKey"                                     ascii nocase

        // ActiveX control event handlers (auto-exec on interaction/layout)
        $ax1 = "Frame1_Layout"                                         ascii nocase
        $ax2 = "ScrollBar_Change"                                      ascii nocase
        $ax3 = "Spinner_Change"                                        ascii nocase
        $ax4 = "TextBox_Change"                                        ascii nocase
        $ax5 = "ComboBox_Change"                                       ascii nocase
        $ax6 = "WebBrowser_DocumentComplete"                           ascii nocase
        $ax7 = "Timer_Timer"                                           ascii nocase
        $ax8 = "Image_Click"                                           ascii nocase
        $ax9 = "Label_Click"                                           ascii nocase

        // Dangerous content paired with callback
        $d1 = "Shell("                                                 ascii nocase
        $d2 = "CreateObject("                                          ascii nocase
        $d3 = "WScript.Shell"                                          ascii nocase
        $d4 = "CallByName"                                             ascii nocase
        $d5 = "Declare"                                                ascii nocase

    condition:
        any of ($cb*) and any of ($d*)
        or any of ($ax*) and any of ($d*)
}


// ---------------------------------------------------------------------------
// VBA anti-analysis / environment detection. Disabling events, screen
// updating, and alerts hides macro activity; enumerating environment
// variables and hardware detects sandbox environments.
// ---------------------------------------------------------------------------
rule VBA_Anti_Analysis_Evasion
{
    meta:
        description = "VBA anti-analysis: EnableEvents/ScreenUpdating/DisplayAlerts=False + environment/sandbox detection (T1497 + T1564)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // UI suppression
        $ui1 = "Application.EnableEvents = False"                      ascii nocase
        $ui2 = "Application.ScreenUpdating = False"                    ascii nocase
        $ui3 = "Application.DisplayAlerts = False"                     ascii nocase
        $ui4 = "ActiveWindow.Visible = False"                          ascii nocase

        // Environment enumeration (sandbox detection)
        $env1 = "Application.UserName"                                 ascii nocase
        $env2 = "Environ(\"COMPUTERNAME\")"                            ascii nocase
        $env3 = "Environ(\"USERNAME\")"                                ascii nocase
        $env4 = "Environ(\"USERDOMAIN\")"                              ascii nocase
        $env5 = "Environ(\"TEMP\")"                                    ascii nocase
        $env6 = "Environ(\"APPDATA\")"                                 ascii nocase
        $env7 = "Environ(\"NUMBER_OF_PROCESSORS\")"                    ascii nocase

        // VM / sandbox hardware detection via WMI
        $vm1 = "Win32_ComputerSystem"                                  ascii nocase
        $vm2 = "Win32_BIOS"                                            ascii nocase
        $vm3 = "Win32_DiskDrive"                                       ascii nocase

        // Execution after evasion
        $ex1 = "Shell("                                                ascii nocase
        $ex2 = "CreateObject("                                         ascii nocase
        $ex3 = "GetObject("                                            ascii nocase

    condition:
        3 of ($ui*)
        or (any of ($ui*) and any of ($env*) and any of ($ex*))
        or (2 of ($env*) and any of ($vm*))
        or (any of ($vm*) and any of ($ui*) and any of ($ex*))
}


// ---------------------------------------------------------------------------
// VBA Declare with Alias — Win32 API obfuscation. The Alias keyword in
// Declare statements lets VBA call Win32 APIs under arbitrary names,
// defeating keyword-based detection of dangerous functions like
// VirtualAlloc, CreateThread, GetProcAddress.
// ---------------------------------------------------------------------------
rule VBA_Declare_Alias_API_Obfuscation
{
    meta:
        description = "VBA Declare with Alias: Win32 API name obfuscation in Declare statements (T1059.005 + T1027)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Declare variants
        $dec1 = "Declare Function"                                     ascii nocase
        $dec2 = "Declare PtrSafe Function"                             ascii nocase
        $dec3 = "Declare Sub"                                          ascii nocase
        $dec4 = "Declare PtrSafe Sub"                                  ascii nocase

        // Alias keyword — obfuscation indicator
        $alias = "Alias \""                                            ascii nocase

        // Dangerous Win32 libraries
        $lib1 = "Lib \"kernel32\""                                     ascii nocase
        $lib2 = "Lib \"ntdll\""                                       ascii nocase
        $lib3 = "Lib \"user32\""                                      ascii nocase
        $lib4 = "Lib \"advapi32\""                                    ascii nocase
        $lib5 = "Lib \"urlmon\""                                      ascii nocase

        // Dangerous APIs through Declare (with or without Alias)
        $api1 = "GetProcAddress"                                       ascii nocase
        $api2 = "GetModuleHandle"                                      ascii nocase
        $api3 = "LoadLibraryA"                                         ascii nocase
        $api4 = "LoadLibraryW"                                         ascii nocase
        $api5 = "CallWindowProc"                                       ascii nocase
        $api6 = "EnumSystemLocalesA"                                   ascii nocase
        $api7 = "GetTickCount"                                         ascii nocase
        $api8 = "CreateProcessA"                                       ascii nocase
        $api9 = "SetFileTime"                                          ascii nocase
        $api10 = "RegOpenKeyEx"                                        ascii nocase
        $api11 = "RegSetValueEx"                                       ascii nocase

    condition:
        (any of ($dec*) and $alias and any of ($lib*))
        or (any of ($dec*) and any of ($api1, $api2, $api3, $api4))
        or (any of ($dec*) and ($api5 or $api6))
        or (any of ($dec*) and $lib2)
}


// ---------------------------------------------------------------------------
// VBA programmatic DDE execution. DDEInitiate/DDEExecute/DDEPoke called
// from VBA code opens a DDE channel and sends commands — distinct from
// DDE field codes in the document body (which Office_DDE_AutoField covers).
// ---------------------------------------------------------------------------
rule VBA_DDE_Programmatic_Execution
{
    meta:
        description = "VBA programmatic DDE: DDEInitiate + DDEExecute — DDE command execution from VBA code (T1559.002)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $dde1 = "DDEInitiate"                                          ascii nocase
        $dde2 = "DDEExecute"                                           ascii nocase
        $dde3 = "DDEPoke"                                              ascii nocase
        $dde4 = "DDETerminate"                                         ascii nocase

        // DDE targets
        $t1 = "cmd"                                                    ascii nocase
        $t2 = "powershell"                                             ascii nocase
        $t3 = "mshta"                                                  ascii nocase
        $t4 = "wscript"                                                ascii nocase
        $t5 = "cscript"                                                ascii nocase

    condition:
        ($dde1 and $dde2)
        or ($dde1 and $dde3)
        or ($dde2 and any of ($t*))
}


// ---------------------------------------------------------------------------
// VBA self-modifying code. Accessing VBProject.VBComponents at runtime to
// add modules, insert code lines, or modify existing code — used for
// spreading macros to other documents or injecting payloads at runtime.
// ---------------------------------------------------------------------------
rule VBA_Self_Modifying_Code
{
    meta:
        description = "VBA self-modifying code: VBProject.VBComponents access for runtime code injection (T1137.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // VBProject access
        $vp1 = "VBProject"                                            ascii nocase
        $vp2 = "VBComponents"                                         ascii nocase
        $vp3 = "VBComponent"                                          ascii nocase

        // Module manipulation
        $mm1 = ".Add("                                                 ascii nocase
        $mm2 = ".Remove("                                              ascii nocase
        $mm3 = "CodeModule"                                            ascii nocase
        $mm4 = ".InsertLines"                                          ascii nocase
        $mm5 = ".DeleteLines"                                          ascii nocase
        $mm6 = ".AddFromBuffer"                                        ascii nocase
        $mm7 = ".AddFromFile"                                          ascii nocase
        $mm8 = ".ReplaceLine"                                          ascii nocase

        // Export / import (cross-document spreading)
        $ei1 = ".Export("                                              ascii nocase
        $ei2 = ".Import("                                              ascii nocase

    condition:
        ($vp1 and $vp2 and any of ($mm*))
        or ($vp2 and $mm3 and ($mm4 or $mm5 or $mm6 or $mm8))
        or ($vp2 and any of ($ei*))
}


// ---------------------------------------------------------------------------
// VBA keystroke injection. SendKeys injects keystrokes into the active
// application — used to trigger system dialogs, type commands into
// terminals, or bypass UI restrictions.
// ---------------------------------------------------------------------------
rule VBA_SendKeys_Injection
{
    meta:
        description = "VBA SendKeys: keystroke injection for UI automation abuse / command execution (T1059.005)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $sk1 = "SendKeys"                                             ascii nocase
        $sk2 = "Application.SendKeys"                                  ascii nocase

        // Targets paired with SendKeys
        $t1 = "cmd"                                                    ascii nocase
        $t2 = "powershell"                                             ascii nocase
        $t3 = "{ENTER}"                                               ascii nocase
        $t4 = "Shell("                                                 ascii nocase
        $t5 = "Application.OnTime"                                     ascii nocase

    condition:
        ($sk1 or $sk2) and any of ($t*)
}


// ---------------------------------------------------------------------------
// VBA persistence via SaveSetting / file system. SaveSetting writes to
// HKCU\Software\VB and VBA Program Settings — a lightweight persistence
// mechanism built into VBA. Open/Write/Close for binary file drops.
// ---------------------------------------------------------------------------
rule VBA_Persistence_Registry_File
{
    meta:
        description = "VBA persistence: SaveSetting (registry) / Open...For Binary (file drop) / MacroOptions (UI hide) (T1547 + T1137)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Registry-like persistence
        $ss1 = "SaveSetting"                                           ascii nocase
        $ss2 = "GetSetting"                                            ascii nocase

        // Binary file write (VBA native I/O)
        $fw1 = "Open "                                                 ascii nocase
        $fw2 = " For Binary"                                          ascii nocase
        $fw3 = "Put #"                                                 ascii nocase
        $fw4 = "Write #"                                               ascii nocase

        // File operations
        $fo1 = "Dir("                                                  ascii nocase
        $fo2 = "Kill "                                                 ascii nocase
        $fo3 = "FileCopy "                                             ascii nocase

        // UI hiding
        $uh1 = "Application.MacroOptions"                              ascii nocase

        // Dangerous targets
        $dt1 = ".exe"                                                  ascii nocase
        $dt2 = ".dll"                                                  ascii nocase
        $dt3 = ".bat"                                                  ascii nocase
        $dt4 = "\\Startup\\"                                          ascii nocase
        $dt5 = "%APPDATA%"                                             ascii nocase

    condition:
        ($ss1 and any of ($dt*))
        or ($fw1 and $fw2 and ($fw3 or $fw4) and any of ($dt*))
        or ($fo3 and any of ($dt4, $dt5))
        or ($uh1)
}


// ---------------------------------------------------------------------------
// VBA string obfuscation. Chr/Chrw/Mid/StrReverse/StrConv chains inside
// VBA macro code to reconstruct payloads from obfuscated strings. Distinct
// from VBScript detection rules because VBA source is extracted from
// Office documents and scanned separately.
// ---------------------------------------------------------------------------
rule VBA_String_Obfuscation
{
    meta:
        description = "VBA string obfuscation: Chr/StrReverse/StrConv/Mid chains for payload deobfuscation (T1027 + T1059.005)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Character code construction
        $chr1 = "Chr("                                                 ascii nocase
        $chr2 = "Chrw("                                                ascii nocase
        $cat1 = "& Chr("                                               ascii nocase
        $cat2 = "&Chr("                                                ascii nocase

        // String manipulation
        $sm1 = "StrReverse("                                           ascii nocase
        $sm2 = "StrConv("                                              ascii nocase
        $sm3 = "Mid("                                                  ascii nocase
        $sm4 = "Replace("                                              ascii nocase

        // Execution sinks
        $ex1 = "Shell("                                                ascii nocase
        $ex2 = "CreateObject("                                         ascii nocase
        $ex3 = "CallByName"                                            ascii nocase
        $ex4 = ".Run("                                                 ascii nocase

        // VBA source indicator
        $vba = "Attribute VB_Name"                                     ascii nocase

    condition:
        ($vba and (#cat1 + #cat2) > 5 and any of ($ex*))
        or ($vba and $sm1 and any of ($ex*))
        or ($vba and $sm2 and any of ($ex*))
        or ($vba and $sm3 and $chr1 and any of ($ex*))
}


// ---------------------------------------------------------------------------
// Excel 4.0 (XLM) callback functions. XLM macros can register callbacks
// (ON.DOUBLE_CLICK, ON.KEY, ON.ENTRY) that fire on user interaction —
// evading immediate auto-exec scanning. Extends the existing
// Office_Excel4_Macro_Sheet rule in ole_cfb_markers.yar.
// ---------------------------------------------------------------------------
rule XLM_Callback_AutoExec
{
    meta:
        description = "Excel 4.0 XLM callback: ON.DOUBLE_CLICK / ON.KEY / ON.ENTRY — delayed auto-execution in macro sheets"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file"

    strings:
        // XLM callback registration functions
        $xlcb1 = "ON.DOUBLE.CLICK"                                     ascii nocase
        $xlcb2 = "ON.KEY"                                              ascii nocase
        $xlcb3 = "ON.ENTRY"                                            ascii nocase
        $xlcb4 = "ON.DATA"                                             ascii nocase
        $xlcb5 = "ON.RECALC"                                           ascii nocase
        $xlcb6 = "ON.SHEET"                                            ascii nocase
        $xlcb7 = "ON.TIME"                                             ascii nocase
        $xlcb8 = "ON.WINDOW"                                           ascii nocase

        // XLM dangerous functions (payload after callback)
        $xld1 = "=EXEC("                                              ascii nocase
        $xld2 = "=CALL("                                              ascii nocase
        $xld3 = "=REGISTER("                                          ascii nocase
        $xld4 = "=RUN("                                               ascii nocase
        $xld5 = "=FORMULA("                                           ascii nocase
        $xld6 = "=FOPEN("                                             ascii nocase
        $xld7 = "=FWRITE("                                            ascii nocase
        $xld8 = "=URLMON"                                              ascii nocase

    condition:
        any of ($xlcb*) and any of ($xld*)
}
