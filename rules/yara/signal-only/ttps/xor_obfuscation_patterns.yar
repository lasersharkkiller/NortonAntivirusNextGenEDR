// XOR-obfuscation fingerprints: PowerShell/JScript/VBScript XOR decode loops,
// integer-array shellcode stashes, and the base64+XOR stager shape. Catches
// the decoders even when the ciphertext is obfuscated past string matching —
// the loop structure and array form are themselves the signal.
//
// Tier: signal-only — XOR is a legitimate primitive in checksum routines,
// PRNGs, bitmasks in WMI queries, etc. Chain with process/path context.

// ---------------------------------------------------------------------------
// PowerShell XOR decode loop. The canonical shape is an indexed for/foreach
// over a byte/char buffer assigning `$x[$i] -bxor $key[$i % $key.Length]`.
// Empire, SharpShell, Nishang's Invoke-PoshRatHttp, and many custom stagers
// all emit this exact structure. `-bxor` is also the PS bitwise-XOR operator,
// so its presence in a non-admin script is rare.
// ---------------------------------------------------------------------------
rule XOR_PowerShell_DecodeLoop
{
    meta:
        description = "PowerShell XOR-decode loop: -bxor inside a for/foreach over indexed key material (Empire/Covenant/Nishang stager shape)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Key-schedule patterns
        $k1 = "-bxor $key[$i % $key.Length]"                      ascii nocase
        $k2 = "-bxor $k[$i % $k.Length]"                          ascii nocase
        $k3 = "-bxor($k[$i%$k.length])"                           ascii nocase
        $k4 = "-bxor $key[($i % $key.Length)]"                    ascii nocase
        $k5 = "-bxor $keybytes[$i % $keybytes.length]"            ascii nocase
        $k6 = "-bxor $keybytes[($i % $keybytes.length)]"          ascii nocase
        $k7 = "-bxor $xorkey[$i % $xorkey.length]"                ascii nocase
        $k8 = "-bxor $b[$i%$b.length]"                            ascii nocase

        // Loop scaffolding around -bxor — catches ad-hoc variable names
        $loop_for_bxor     = /for\s*\(\s*\$[a-z]\s*=\s*0[^)]{0,64}\$[a-z]\s*-lt[^)]{0,64}\)\s*{[^}]{0,256}-bxor/ nocase
        $loop_foreach_bxor = /foreach\s*\(\s*\$[a-z]\s+in[^)]{0,96}\)\s*{[^}]{0,256}-bxor/ nocase

        // Wide (UTF-16) forms for in-memory PS buffers
        $k1w = "-bxor $key[$i % $key.Length]"                     wide  nocase
        $k2w = "-bxor $k[$i % $k.Length]"                         wide  nocase

        // JS/VBS XOR loops — same primitive, different syntax
        $js_xor  = /\^\s*key\[\s*i\s*%\s*key\.length\s*\]/        nocase
        $vbs_xor = "xor asc(mid(key"                              ascii nocase

    condition:
        any of ($k*) or any of ($loop_*) or $js_xor or $vbs_xor
}


// ---------------------------------------------------------------------------
// PowerShell / C# byte-array shellcode stash. Attackers store the shellcode
// as a comma-separated byte list in source — 0x4C,0x8B,0xD1,... — which
// evades string-based scanners that look for contiguous opcode bytes.
// We match on a long run of 2-digit hex bytes (200+) in an array literal.
// ---------------------------------------------------------------------------
rule XOR_Shellcode_ByteArrayStash
{
    meta:
        description = "Large byte-array literal in script (@(0xNN,0xNN,...) or new byte[]{0xNN,...}) — embedded shellcode pre-XOR-decode"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // PS array literal: @(0x4C,0x8B,0xD1,...) with 200+ elements
        $ps_hex_array = /@\s*\(\s*0x[0-9A-Fa-f]{1,2}\s*,(\s*0x[0-9A-Fa-f]{1,2}\s*,?\s*){200,}/ nocase

        // C# / C++ byte array literal: new byte[] { 0x4C, 0x8B, ... }
        $cs_hex_array = /new\s+byte\s*\[\s*\]\s*\{\s*0x[0-9A-Fa-f]{1,2}(\s*,\s*0x[0-9A-Fa-f]{1,2}){200,}/

        // PS array of decimal bytes: (76,139,209,184,...) — same payload
        $ps_dec_array = /\(\s*[0-9]{1,3}\s*,(\s*[0-9]{1,3}\s*,?\s*){250,}\)/

        // CS Int[] / Uint[] variants
        $cs_dec_array = /new\s+(byte|int|uint)\s*\[\s*\]\s*\{\s*[0-9]{1,3}(\s*,\s*[0-9]{1,3}){250,}/

        // Pair: array literal AND an -bxor / ^=  pattern nearby
        $xor_op = /\-bxor|\^\=|\^key/ nocase

    condition:
        any of ($ps_hex_array, $cs_hex_array, $ps_dec_array, $cs_dec_array)
}


// ---------------------------------------------------------------------------
// Base64+XOR stager chain. The ordered triple [base64 decode call] +
// [-bxor loop] + [IEX / Invoke / Assembly.Load] is the stager shape used by
// Empire, Covenant Grunt, Posh-SecMod, and most PS-based CS beacon profiles.
// All three primitives in the same script = malicious chain with very high
// precision.
// ---------------------------------------------------------------------------
rule XOR_Base64_Xor_IEX_Chain
{
    meta:
        description = "Script contains Base64 decode + XOR loop + IEX/Assembly.Load chain — Empire/Covenant/CS stager obfuscation shape"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $b64_a = "[System.Convert]::FromBase64String"    ascii nocase
        $b64_b = "[Convert]::FromBase64String"           ascii nocase
        $b64_w = "[System.Convert]::FromBase64String"    wide  nocase

        $xor_a = "-bxor"                                 ascii nocase
        $xor_w = "-bxor"                                 wide  nocase

        $exec_a = "Invoke-Expression"                    ascii nocase
        $exec_b = "| IEX"                                ascii nocase
        $exec_c = "iex ("                                ascii nocase
        $exec_d = "[Reflection.Assembly]::Load"          ascii nocase
        $exec_e = "[System.Reflection.Assembly]::Load"   ascii nocase
        $exec_w = "Invoke-Expression"                    wide  nocase

    condition:
        (any of ($b64_a, $b64_b) and $xor_a and any of ($exec_a, $exec_b, $exec_c, $exec_d, $exec_e))
        or ($b64_w and $xor_w and $exec_w)
}


// ---------------------------------------------------------------------------
// C-style XOR decryptor in compiled binary. A tight inner loop of the shape:
//   xor byte ptr [rsi+rcx], al
//   inc rcx
//   cmp rcx, <len>
//   jb <start>
// appears in almost every packer and crypter stub. We match the opcode
// pattern; tier:signal-only keeps it off on-disk Windows system libraries
// (where benign XOR loops exist in CRT routines) without sacrificing the
// process-memory visibility.
// ---------------------------------------------------------------------------
rule XOR_Native_DecryptorLoop
{
    meta:
        description = "Native-code single-byte XOR decrypt loop — xor byte ptr [mem+idx], AL; inc idx; loop"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "medium"
        scan_target = "file,process_memory"

    strings:
        // xor  byte ptr [rdx+rax], cl ; inc rax ; cmp rax, r?? ; jb -0x?
        //  32 14 02   48 FF C0   49 3B C?   72 F?
        $loop_x64_a = { 32 ?? ?? 48 FF C? ?? 3B C? 72 ?? }

        // xor  byte ptr [rsi+rcx], bl ; inc rcx ; dec r9 ; jnz -0x?
        //  32 1C 0E   48 FF C1   49 FF C9   75 F?
        $loop_x64_b = { 32 ?? ?? 48 FF C? 49 FF C? 75 ?? }

        // x86 variant:
        // xor  byte ptr [esi+ecx], al ; inc ecx ; cmp ecx, edi ; jb -0x?
        //  30 04 0E   41   3B CF   72 F?
        $loop_x86 = { 30 ?? ?? 41 3B ?? 72 ?? }

        // Multi-byte key XOR (4-byte key in register pool):
        // xor [rcx+rax], edx ; add rax, 4 ; cmp rax, r9 ; jb -0x?
        //  31 14 01   48 83 C0 04   49 3B C?   72 F?
        $loop_4byte = { 31 ?? ?? 48 83 C0 04 49 3B C? 72 ?? }

    condition:
        any of them
}
