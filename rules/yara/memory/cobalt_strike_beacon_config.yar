rule CobaltStrike_Beacon_ConfigBlob_Memory
{
    meta:
        description = "Cobalt Strike beacon in-memory config blob — the XOR-obfuscated settings table that every beacon carries."
        author      = "NortonEDR"
        reference   = "https://www.elastic.co/security-labs/detecting-cobalt-strike-beacon"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // Decoded beacon config header — appears early in the settings table.
        // The sequence 0x00 0x01 0x00 0x01 0x00 0x02 is the option-type/length
        // framing Cobalt Strike uses for config fields (option 1, short, len 2).
        $cfg_header_xored_2e = { 2e 2f 2e 2f 2e 2c }   // XOR 0x2E
        $cfg_header_xored_69 = { 69 68 69 68 69 6b }   // XOR 0x69 (v4.x)
        $cfg_header_plain    = { 00 01 00 01 00 02 }

        // Sleep mask / beacon task strings that survive mask removal
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon.x64.dll"   ascii
        $s3 = "ReflectiveLoader" ascii

        // Common C2 profile metadata-variable names
        $m1 = "User-Agent: " ascii
        $m2 = "%%IMPORT%%"   ascii

    condition:
        any of ($cfg_header_*) or (2 of ($s*)) or (1 of ($s*) and 1 of ($m*))
}
