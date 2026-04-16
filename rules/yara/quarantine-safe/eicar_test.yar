// EICAR Anti-Malware Test File. The 68-byte EICAR string is the universal
// AV test file defined by the European Institute for Computer Antivirus
// Research. Every security product MUST detect it. Zero false-positive risk
// — the string has no legitimate use outside of AV testing.
//
// Tier: quarantine-safe — always flag, no benign usage.

rule EICAR_Test_File
{
    meta:
        description = "EICAR Anti-Malware Test File — standard AV detection test string"
        author      = "NortonEDR"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        tier        = "quarantine-safe"
        severity    = "critical"

    strings:
        // The official 68-byte EICAR test string
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar
}
