// OLE Compound Binary File (CFB) structural markers. Catches embedded
// objects, template injection references, and Ole10Native payloads inside
// legacy Office documents. Operates on raw file bytes — the CFB directory
// entries and stream names are uncompressed fixed-width UTF-16LE, so YARA
// literal strings (wide) match directly.
//
// Tier: signal-only — every OLE document (legitimate or not) has these
// structures. The rules below add specificity via required combinations.

// ---------------------------------------------------------------------------
// Embedded OLE object with executable payload. A Word/Excel document that
// contains an Ole10Native stream with an .exe/.scr/.bat/.vbs inside — the
// CVE-2017-0199 / RTF embedded-object dropper shape.
// ---------------------------------------------------------------------------
rule OLE_Embedded_Executable_Object
{
    meta:
        description = "OLE Compound File with embedded Ole10Native executable payload — .exe/.scr/.bat/.vbs inside Office doc (T1566.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        // CFB magic
        $cfb = { D0 CF 11 E0 A1 B1 1A E1 }

        // Ole10Native stream name (UTF-16LE directory entry)
        $ole10 = { 01 00 4F 00 6C 00 65 00 31 00 30 00 4E 00 61 00 74 00 69 00 76 00 65 00 }

        // Executable extensions inside the stream (ASCII strings in the
        // native data blob that precede the embedded binary)
        $ext1 = ".exe"                                                 ascii nocase
        $ext2 = ".scr"                                                 ascii nocase
        $ext3 = ".bat"                                                 ascii nocase
        $ext4 = ".cmd"                                                 ascii nocase
        $ext5 = ".vbs"                                                 ascii nocase
        $ext6 = ".js"                                                  ascii nocase
        $ext7 = ".wsf"                                                 ascii nocase
        $ext8 = ".hta"                                                 ascii nocase
        $ext9 = ".pif"                                                 ascii nocase
        $exta = ".com"                                                 ascii nocase

        // MZ header inside file body (the embedded PE)
        $mz = { 4D 5A 90 00 }

    condition:
        $cfb at 0 and $ole10
        and (any of ($ext*) or $mz)
}


// ---------------------------------------------------------------------------
// OLE template injection. An OOXML (.docx/.dotm) or RTF document with an
// external OLE template relationship pointing to a remote URL. The target
// URL loads a macro-enabled template at document-open time — user sees a
// clean .docx, Office silently fetches the armed .dotm.
// ---------------------------------------------------------------------------
rule Office_Remote_Template_Injection
{
    meta:
        description = "Office remote template injection: external relationship or RTF \\*\\template targeting http(s) URL (T1221)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file"

    strings:
        // OOXML relationship pointing to an external .dotm / .dot / .docm
        $rel1 = "Target=\"http"                                        ascii nocase
        $rel2 = "Target=\"https"                                       ascii nocase
        $rel3 = "TargetMode=\"External\""                              ascii nocase
        $rel4 = "attachedTemplate"                                     ascii nocase
        $rel5 = "oleObject"                                            ascii nocase
        $rel6 = ".dotm"                                                ascii nocase
        $rel7 = ".dot\""                                               ascii nocase
        $rel8 = "subDocument"                                          ascii nocase

        // RTF template injection: {\*\template http://...}
        $rtf1 = "\\*\\template"                                        ascii
        $rtf2 = "{\\rtf"                                               ascii

        // URL inside relationship XML
        $url  = /Target="https?:\/\/[^\s"]{10,200}"/ nocase

    condition:
        // OOXML shape: relationship XML with external target + template/oleObject type
        ($rel3 and ($rel4 or $rel5 or $rel8) and ($rel1 or $rel2 or $url))
        // RTF shape: \*\template + RTF header
        or ($rtf1 and $rtf2)
}


// ---------------------------------------------------------------------------
// Embedded Equation Editor OLE object (CVE-2017-11882 / CVE-2018-0802).
// The CLSID for Microsoft Equation 3.0 / Microsoft Equation Editor inside
// an OLE compound or RTF indicates an Equation Editor exploit attempt — the
// most commonly exploited Office vulnerability family in commodity phishing.
// ---------------------------------------------------------------------------
rule OLE_EquationEditor_Exploit
{
    meta:
        description = "Embedded Equation Editor OLE object (CLSID for eqnedt32) — CVE-2017-11882 / CVE-2018-0802 exploit vehicle"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file"

    strings:
        // CLSID {0002CE02-0000-0000-C000-000000000046} — Microsoft Equation 3.0
        $clsid_eq3 = { 02 CE 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        // CLSID {00021700-0000-0000-C000-000000000046} — Math Type (alternate)
        $clsid_mt  = { 00 17 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // RTF object embedding markers for eqnedt32
        $rtf_obj    = "\\object"                                       ascii
        $rtf_class1 = "Equation.3"                                     ascii nocase
        $rtf_class2 = "Equation.DSMT"                                  ascii nocase
        $rtf_class3 = "eqnedt32"                                       ascii nocase

        // CFB magic
        $cfb = { D0 CF 11 E0 A1 B1 1A E1 }

        // ZIP magic (OOXML)
        $zip = { 50 4B 03 04 }

    condition:
        ($cfb at 0 and ($clsid_eq3 or $clsid_mt))
        or ($zip at 0 and ($clsid_eq3 or $clsid_mt))
        or ($rtf_obj and ($rtf_class1 or $rtf_class2 or $rtf_class3))
}


// ---------------------------------------------------------------------------
// Excel 4.0 macro sheet (XLM). Antedates VBA; abuse resurged 2019-present.
// The CFB/BIFF record contains a Boundsheet record (type 0x85) with sheet
// type 0x01 (macro sheet) and the sheet is named with common attacker
// conventions. Also catches OOXML <sheet ... type="macrosheetpart">.
// ---------------------------------------------------------------------------
rule Office_Excel4_Macro_Sheet
{
    meta:
        description = "Excel 4.0 (XLM) macro sheet — BIFF8 Boundsheet type=0x01 or OOXML macrosheetpart (T1059.009)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        // CFB magic
        $cfb = { D0 CF 11 E0 A1 B1 1A E1 }

        // BIFF8 Boundsheet record: type 0x85, length 8+, sheet type byte = 0x01
        $bs_macro = { 85 00 ?? 00 ?? ?? ?? ?? 01 }

        // Excel 4.0 function tokens that appear in the formulas
        $xlm1 = "EXEC("                                               ascii nocase
        $xlm2 = "=EXEC("                                              ascii nocase
        $xlm3 = "CALL("                                               ascii nocase
        $xlm4 = "=CALL("                                              ascii nocase
        $xlm5 = "REGISTER("                                           ascii nocase
        $xlm6 = "=REGISTER("                                          ascii nocase
        $xlm7 = "FORMULA("                                            ascii nocase
        $xlm8 = "=FORMULA("                                           ascii nocase
        $xlm9 = "RUN("                                                ascii nocase
        $xlma = "=RUN("                                               ascii nocase
        $xlmb = "HALT()"                                              ascii nocase
        $xlmc = "ALERT("                                              ascii nocase
        $xlmd = "=CHAR("                                              ascii nocase
        $xlme = "AUTO_OPEN"                                           ascii nocase

        // OOXML: sheet element referencing a macro sheet part
        $ooxml_ms = "macrosheetpart"                                   ascii nocase

    condition:
        ($cfb at 0 and $bs_macro and any of ($xlm*))
        or ($cfb at 0 and 3 of ($xlm*))
        or $ooxml_ms
}
