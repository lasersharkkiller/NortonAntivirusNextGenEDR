rule Mimikatz_CoreStrings_QuarantineSafe
{
    meta:
        description = "Mimikatz — unique credential-dumping strings. High confidence, FP-validated against System32 + Program Files."
        author      = "NortonEDR"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        tier        = "quarantine-safe"
        severity    = "critical"

    strings:
        $a1 = "gentilkiwi (Benjamin DELPY)"          ascii wide
        $a2 = "A La Vie, A L'Amour"                  ascii wide
        $a3 = "sekurlsa::logonpasswords"             ascii wide
        $a4 = "sekurlsa::pth /user:"                 ascii wide
        $a5 = "lsadump::lsa /inject"                 ascii wide
        $a6 = "privilege::debug"                     ascii wide
        $a7 = "KiwiAndRegistryTools"                 ascii wide

    condition:
        2 of them
}
