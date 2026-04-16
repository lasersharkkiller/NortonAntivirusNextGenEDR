// IOfficeAntiVirus (mpoav) tamper fingerprints. The COM provider at CLSID
// {2781761E-28E0-4109-99FE-B9D127C57AFE} (mpoav.dll) is what Office calls
// via IOfficeAntiVirus::Scan on inbound macro / embedded-object content.
// Attackers disable, redirect, or unregister this provider before detonating
// a macro-dropper so the scan path is silent.
//
// Scan targets: file (.reg / .bat / .ps1 / .vbs persistence payloads and
// dropper scripts) + process_memory (to catch in-memory tampering recipes
// from Empire, Cobalt Strike, commodity loaders).
//
// Tier: signal-only — legitimate admin tooling occasionally writes these
// keys during Office repair / policy deployment. Chain with parent process,
// signed status, and script path before escalation.

// ---------------------------------------------------------------------------
// Registry-level IOfficeAntiVirus disable recipes. Catches .reg files,
// cmd.exe reg add/delete, PowerShell Set-ItemProperty, VBS reg.Write, and
// C# RegistryKey.SetValue targeting the OfficeAntiVirus keys or mpoav CLSID.
// ---------------------------------------------------------------------------
rule OfficeAV_Registry_Disable_Or_Redirect
{
    meta:
        description = "IOfficeAntiVirus (mpoav) provider disable or InProcServer32 redirect — Office macro AV tamper (T1562.001)"
        author      = "NortonEDR"
        reference   = "https://learn.microsoft.com/en-us/windows/win32/api/msoav/nn-msoav-iofficeantivirus"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Key paths touched
        $k1 = "SOFTWARE\\Microsoft\\OfficeAntiVirus"                                  ascii nocase
        $k2 = "HKLM\\SOFTWARE\\Microsoft\\OfficeAntiVirus"                            ascii nocase
        $k3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\OfficeAntiVirus"              ascii nocase
        $k4 = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"                                ascii nocase
        $k5 = "CLSID\\{2781761E-28E0-4109-99FE-B9D127C57AFE}\\InProcServer32"         ascii nocase
        $k6 = "Component Categories\\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}"          ascii nocase
        $k7 = "mpoav.dll"                                                             ascii nocase

        // Wide forms (PS in-memory / UTF-16 .reg files)
        $k1w = "SOFTWARE\\Microsoft\\OfficeAntiVirus"                                 wide  nocase
        $k4w = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"                               wide  nocase
        $k7w = "mpoav.dll"                                                            wide  nocase

        // Tamper verbs
        $v1 = "reg delete"                                                            ascii nocase
        $v2 = "reg add"                                                               ascii nocase
        $v3 = "RegDeleteKey"                                                          ascii nocase
        $v4 = "RegDeleteValue"                                                        ascii nocase
        $v5 = "Remove-Item"                                                           ascii nocase
        $v6 = "Remove-ItemProperty"                                                   ascii nocase
        $v7 = "Set-ItemProperty"                                                      ascii nocase
        $v8 = "New-ItemProperty"                                                      ascii nocase
        $v9 = "RegistryKey.SetValue"                                                  ascii nocase
        $va = ".RegWrite "                                                            ascii nocase
        $vb = ".RegDelete "                                                           ascii nocase

        // Disable tokens
        $d1 = "Disabled\"=dword:00000001"                                             ascii nocase
        $d2 = "\"State\"=dword:00000000"                                              ascii nocase
        $d3 = "Disabled dword 1"                                                      ascii nocase
        $d4 = "/v Disabled /t REG_DWORD /d 1"                                         ascii nocase

    condition:
        (any of ($k1, $k2, $k3, $k4, $k5, $k6, $k7) or any of ($k1w, $k4w, $k7w))
        and (any of ($v*) or any of ($d*))
}


// ---------------------------------------------------------------------------
// Office VBA-security tamper — the "let macros run" recipe. VBAWarnings=1
// (Enable all macros, no prompt) + AccessVBOM=1 (VBA project access) are
// the two registry flips that let a phishing macro self-modify and run
// without scan interaction. Paired with the OfficeAV key, this is the full
// macro-AV bypass path.
// ---------------------------------------------------------------------------
rule OfficeAV_VBA_Security_Tamper
{
    meta:
        description = "Office VBA security tamper: VBAWarnings=1 / AccessVBOM=1 / DisableAttachmentScanning (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $a1 = "VBAWarnings"                                                           ascii nocase
        $a2 = "AccessVBOM"                                                            ascii nocase
        $a3 = "DisableAttachmentScanning"                                             ascii nocase
        $a4 = "DisableHyperlinkWarning"                                               ascii nocase
        $a5 = "BlockContentExecutionFromInternet"                                     ascii nocase
        $a6 = "MarkInternalAsUnsafe"                                                  ascii nocase
        $a7 = "MOTWExclusions"                                                        ascii nocase

        $b1 = "\\Office\\" ascii nocase
        $b2 = "\\Security\\" ascii nocase

        // Value setter token (1 = enable all macros / grant VBOM)
        $v1 = "/t REG_DWORD /d 1"                                                     ascii nocase
        $v2 = "dword:00000001"                                                        ascii nocase
        $v3 = "-Value 1"                                                              ascii nocase
        $v4 = "REG_DWORD /d 0"                                                        ascii nocase  // disable-warning variant

        $a1w = "VBAWarnings"                                                          wide nocase
        $a2w = "AccessVBOM"                                                           wide nocase

    condition:
        (any of ($a1, $a2, $a3, $a4, $a5, $a6, $a7) or any of ($a1w, $a2w))
        and $b1 and $b2
        and any of ($v*)
}


// ---------------------------------------------------------------------------
// In-VBA IOfficeAntiVirus-bypass patterns. Some operator macros register a
// fake provider or call into the COM category directly to suppress the scan
// in-process. Rare but distinctive — when it hits, it hits hard.
// ---------------------------------------------------------------------------
rule OfficeAV_VBA_Provider_Bypass
{
    meta:
        description = "VBA/C# code that self-registers or unregisters IOfficeAntiVirus providers (in-memory macro-AV bypass)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $i1 = "IOfficeAntiVirus"                                                      ascii nocase
        $i2 = "OfficeAntiVirus.Scan"                                                  ascii nocase
        $i3 = "CoCreateInstance"                                                      ascii nocase
        $i4 = "CLSIDFromString"                                                       ascii nocase
        $i5 = "{56FFCC30-D398-11D0-B2AE-00A0C908FA49}"                                ascii nocase
        $i6 = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"                                ascii nocase
        $i7 = "DllGetClassObject"                                                     ascii nocase
        $i8 = "DllUnregisterServer"                                                   ascii nocase

        $i1w = "IOfficeAntiVirus"                                                     wide nocase
        $i5w = "{56FFCC30-D398-11D0-B2AE-00A0C908FA49}"                               wide nocase
        $i6w = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"                               wide nocase

    condition:
        ($i1 or $i1w)
        and any of ($i3, $i4, $i5, $i5w, $i6, $i6w, $i7, $i8)
}
