// Detect the STRUCTURE of API-hashing resolvers rather than specific hash
// constants. This durably catches Sliver, Havoc, Hell's Gate, Meterpreter,
// Cobalt Strike beacons, and most hand-written loaders regardless of which
// hash algorithm they use (djb2, CRC32, ROR13, FNV-1a, custom).
//
// The common shape: load EXPORT_DIRECTORY, loop over AddressOfNames, compute
// a rolling hash over each name (byte load + rotate/xor + add in a 3-5 insn
// loop), compare to a target constant, branch if equal.
//
// Tier: memory (signal-only — meant to fire on live process memory scans
// during W->X flips, where it's confirming that the region contains a
// resolver loop, not a goodware binary).

rule ApiHashing_Ror13_ResolverLoop_Memory
{
    meta:
        description = "ROR13 / ROR7-style API hash resolver loop (Metasploit block_api, Cobalt Strike, many custom stagers)"
        author      = "NortonEDR"
        reference   = "https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // x86: lodsb ; ror edi, 0Dh ; add edi, eax ; loop or cmp
        //  AC            C1 CF 0D        01 C7        ... E2 ??|75 ??|3B ??
        $x86_ror13_a = { AC C1 CF 0D 01 C7 }
        $x86_ror13_b = { AC C1 CF 07 01 C7 }

        // x64: lodsb ; ror edi, 0Dh ; add edi, eax
        //  AC            C1 CF 0D        01 C7
        // (same raw opcodes, different prefix context — pattern matches both modes)
        $x64_ror13_prefix = { 48 31 ?? AC C1 C? 0D 01 C? }

        // Common export-directory offset pattern:
        // mov  ebx, [ebx + 20h]  (AddressOfNames)  -> 8B 5B 20
        // add  ebx, edx                            -> 01 D3
        // mov  ecx, [ebx + edi*4]                  -> 8B 0C BB
        $exp_names_walk_x86 = { 8B 5B 20 01 D3 }

        // mov  r8d, [r9 + 20h]  (x64 variant)
        $exp_names_walk_x64 = { 41 8B ?? 20 4C 01 ?? }

    condition:
        (any of ($x86_ror13*)) or
        $x64_ror13_prefix or
        (any of ($exp_names_walk*) and filesize < 16MB)
}


rule ApiHashing_GenericRollingHashLoop_Memory
{
    meta:
        description = "Generic rolling-hash API resolver: lodsb + rotate/shift + xor/add in a 3-5 byte loop body — matches djb2, FNV-1a, CRC32, and custom variants"
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "medium"
        scan_target = "process_memory"

    strings:
        // djb2: hash = hash * 33 + c  (shl 5 / add hash / add c)
        //  C1 E? 05  01 ??  00 ??
        $djb2_shape  = { C1 E? 05 01 ?? 00 ?? }

        // FNV-1a: hash = (hash ^ c) * 0x01000193
        //  33 ??  69 ?? 93 01 00 01
        $fnv1a_shape = { 33 ?? 69 ?? 93 01 00 01 }

        // Arbitrary rol/ror + xor/add accumulator inside a 5-byte window
        //  AC  C1 C? ??  31/01 ??
        $rol_xor = { AC C1 C? ?? 31 ?? }
        $rol_add = { AC C1 C? ?? 01 ?? }

        // Table-based CRC32: mov eax, [edx + ecx*4] ; xor accumulator
        //  8B 04 8A  31/33 ??
        $crc32_table = { 8B 04 8A 3? ?? }

    condition:
        2 of them
}


rule ApiHashing_PebWalk_x64_Memory
{
    meta:
        description = "x64 PEB-walk to ntdll!LdrLoadDll/GetProcedureAddress — used as the first step before hashing"
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "medium"
        scan_target = "process_memory"

    strings:
        // mov rax, gs:[60h]           -> 65 48 8B 04 25 60 00 00 00
        // mov rax, [rax + 18h]        -> 48 8B 40 18     (PEB->Ldr)
        // mov rax, [rax + 20h]        -> 48 8B 40 20     (InLoadOrderModuleList)
        $peb_walk_full = {
            65 48 8B 04 25 60 00 00 00
            48 8B 40 18
            48 8B ?? 20
        }

        // Shorter variant some stagers use:
        //   gs:[30h] in WOW64 contexts, or via teb directly
        $peb_via_teb = { 65 48 8B 14 25 30 00 00 00 }

        // Export-directory dereference: e_lfanew + DataDirectory[0]
        // mov eax, [rcx + 3Ch]   -> 8B 41 3C
        // add rax, rcx           -> 48 01 C8
        // mov eax, [rax + 88h]   -> 8B 80 88 00 00 00  (DataDirectory[Export].VirtualAddress)
        $export_dir_deref = { 8B ?? 3C 48 01 ?? 8B ?? 88 00 00 00 }

    condition:
        $peb_walk_full or
        ($peb_via_teb and $export_dir_deref)
}
