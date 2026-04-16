// XOR-encoded PE headers in memory. Droppers, reflective loaders, and
// resource-embedded payloads routinely store a child PE single-byte-XOR'd
// against a static key so "MZ...PE" doesn't appear verbatim on disk or in
// memory scanners. When the loader unpacks the buffer, it XORs byte-for-byte
// and jumps in. We match the XOR'd MZ..PE header shape for the 32 most
// common single-byte keys — catching the payload while it's still encoded,
// before the unpacker runs.
//
// The matched shape is the first 64 bytes of IMAGE_DOS_HEADER XOR'd with key K:
//   offset 0x00: 'M' ^ K, 'Z' ^ K
//   offset 0x3C: e_lfanew (low byte ^ K  — varies; wildcarded)
// plus 4 bytes at e_lfanew of "PE\0\0" XOR'd:  'P'^K 'E'^K 0^K 0^K
//
// We can only check the MZ prefix and the e_lfanew pointer shape + PE magic
// relative position via a short jump token, because e_lfanew itself is
// key-dependent and not known a priori. So the rule uses: MZ^K at offset 0,
// within 0-256 bytes find PE\0\0^K. That's the same two-anchor recipe
// classic AV engines use for this technique.
//
// Tier: memory — running this on disk files would match legitimate resources
// in installers, compressed archives, and packed PEs which intentionally hide
// this exact shape. In memory, post-RW allocation, this shape = staged payload.

rule XOREncoded_PE_Header_Memory
{
    meta:
        description = "XOR-encoded PE header in memory — 'MZ...PE\\0\\0' single-byte-XOR'd with a static key (reflective loader payload, encoded resource, dropper blob)"
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // Each pair is the MZ prefix XOR'd with key K, followed within 0-256
        // bytes by the PE\0\0 magic XOR'd with the same K. 32 common keys
        // cover ~every real-world sample without blowing up rule compile size.

        // Key 0x01: 4C 5B ... 51 44 01 01
        $k01 = { 4C 5B [0-256] 51 44 01 01 }
        // Key 0x02: 4F 58 ... 52 47 02 02
        $k02 = { 4F 58 [0-256] 52 47 02 02 }
        // Key 0x03: 4E 59 ... 53 46 03 03
        $k03 = { 4E 59 [0-256] 53 46 03 03 }
        // Key 0x04: 49 5E ... 54 41 04 04
        $k04 = { 49 5E [0-256] 54 41 04 04 }
        // Key 0x05
        $k05 = { 48 5F [0-256] 55 40 05 05 }
        // Key 0x06
        $k06 = { 4B 5C [0-256] 56 43 06 06 }
        // Key 0x07
        $k07 = { 4A 5D [0-256] 57 42 07 07 }
        // Key 0x08
        $k08 = { 45 52 [0-256] 58 4D 08 08 }
        // Key 0x09
        $k09 = { 44 53 [0-256] 59 4C 09 09 }
        // Key 0x0A
        $k0a = { 47 50 [0-256] 5A 4F 0A 0A }
        // Key 0x0B
        $k0b = { 46 51 [0-256] 5B 4E 0B 0B }
        // Key 0x0C
        $k0c = { 41 56 [0-256] 5C 49 0C 0C }
        // Key 0x0D
        $k0d = { 40 57 [0-256] 5D 48 0D 0D }
        // Key 0x0E
        $k0e = { 43 54 [0-256] 5E 4B 0E 0E }
        // Key 0x0F
        $k0f = { 42 55 [0-256] 5F 4A 0F 0F }
        // Key 0x10
        $k10 = { 5D 4A [0-256] 40 55 10 10 }
        // Key 0x20
        $k20 = { 6D 7A [0-256] 70 65 20 20 }
        // Key 0x40
        $k40 = { 0D 1A [0-256] 10 05 40 40 }
        // Key 0x42
        $k42 = { 0F 18 [0-256] 12 07 42 42 }
        // Key 0x55
        $k55 = { 18 0F [0-256] 05 10 55 55 }
        // Key 0x66
        $k66 = { 2B 3C [0-256] 36 23 66 66 }
        // Key 0x77
        $k77 = { 3A 2D [0-256] 27 32 77 77 }
        // Key 0x7F
        $k7f = { 32 25 [0-256] 2F 3A 7F 7F }
        // Key 0x80
        $k80 = { CD DA [0-256] D0 C5 80 80 }
        // Key 0x99
        $k99 = { D4 C3 [0-256] C9 DC 99 99 }
        // Key 0xAA
        $kaa = { E7 F0 [0-256] FA EF AA AA }
        // Key 0xBB
        $kbb = { F6 E1 [0-256] EB FE BB BB }
        // Key 0xCC
        $kcc = { 81 96 [0-256] 9C 89 CC CC }
        // Key 0xDE
        $kde = { 93 84 [0-256] 8E 9B DE DE }
        // Key 0xEE
        $kee = { A3 B4 [0-256] BE AB EE EE }
        // Key 0xFE
        $kfe = { B3 A4 [0-256] AE BB FE FE }
        // Key 0xFF
        $kff = { B2 A5 [0-256] AF BA FF FF }

    condition:
        any of them
}
