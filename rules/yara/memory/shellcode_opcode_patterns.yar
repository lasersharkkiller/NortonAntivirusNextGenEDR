// Family-agnostic opcode patterns for shellcode, direct syscall stubs, GetPC
// tricks, and in-process hook patches. These match instruction *shapes* rather
// than family-specific bytes, so they age well as malware authors swap
// payloads but keep reusing the same underlying techniques.
//
// Tier: memory (intentionally — several of these patterns legitimately appear
// inside ntdll/kernelbase on disk, which is fine because they shouldn't match
// MEM_PRIVATE regions of a non-loader process). Running these against
// on-disk files would FP heavily; the FP test harness blocks that path.

// ---------------------------------------------------------------------------
// Direct-syscall stubs (Hell's Gate / Halo's Gate / Tartarus Gate pattern)
// When this shape appears outside of ntdll it means a loader has synthesised
// a syscall stub to bypass user-mode hooks.
// ---------------------------------------------------------------------------
rule Shellcode_DirectSyscall_Stub_Memory
{
    meta:
        description = "Direct syscall stub — mov r10,rcx ; mov eax,SSN ; syscall ; ret (Hell's/Halo's/Tartarus Gate)"
        author      = "NortonEDR"
        reference   = "https://github.com/am0nsec/HellsGate"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // 4C 8B D1         mov r10, rcx
        // B8 ?? ?? 00 00   mov eax, <SSN>     (low 16 bits, high 16 zero)
        // 0F 05            syscall
        // C3               ret
        $hells_gate = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

        // Same prologue but with a test/jne for wow64 check before syscall
        // (Halo's Gate resolver body)
        $halos_gate = { 4C 8B D1 B8 ?? ?? 00 00 [0-24] 0F 05 C3 }

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// Indirect syscall via borrowed "syscall" instruction inside ntdll
// RecycledGate / FreshyCalls / SysWhispers3 all emit this shape.
// ---------------------------------------------------------------------------
rule Shellcode_IndirectSyscall_Jmp_Memory
{
    meta:
        description = "Indirect syscall — mov r10,rcx ; mov eax,SSN ; jmp [ntdll syscall gadget] (RecycledGate / FreshyCalls / SysWhispers3)"
        author      = "NortonEDR"
        reference   = "https://github.com/klezVirus/SysWhispers3"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // 4C 8B D1  B8 ?? ?? 00 00  FF 25 ?? ?? ?? ??     (jmp qword ptr [rip+disp32])
        $indirect_jmp_rip = { 4C 8B D1 B8 ?? ?? 00 00 FF 25 ?? ?? ?? ?? }

        // 4C 8B D1  B8 ?? ?? 00 00  FF E?                 (jmp reg)
        $indirect_jmp_reg = { 4C 8B D1 B8 ?? ?? 00 00 FF E? }

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// GetPC / position-independent setup — present in nearly every stager
// ---------------------------------------------------------------------------
rule Shellcode_GetPC_Patterns_Memory
{
    meta:
        description = "Classic position-independent code self-locating tricks (call $+5 ; pop; fnstenv/fpu GetEIP)"
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "medium"
        scan_target = "process_memory"

    strings:
        // E8 00 00 00 00       call $+5
        // 5?                   pop reg      (any general-purpose register)
        $call_pop = { E8 00 00 00 00 5? }

        // D9 EE                fldz
        // D9 74 24 F4          fnstenv [esp-0Ch]
        // 5?                   pop reg
        $fnstenv_getpc = { D9 EE D9 74 24 F4 5? }

        // 64 A1 30 00 00 00    mov eax, fs:[0x30]          (x86 PEB)
        // 65 48 8B 04 25 60 00 00 00  mov rax, gs:[0x60]   (x64 PEB)
        $peb_x86 = { 64 A1 30 00 00 00 }
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 }

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// Skape egg-hunter (classic 32-byte pattern)
// ---------------------------------------------------------------------------
rule Shellcode_EggHunter_Skape_Memory
{
    meta:
        description = "Skape/Hdm egg-hunter shellcode — scans address space via NtAccessCheckAndAuditAlarm for marker 'w00tw00t'"
        author      = "NortonEDR"
        reference   = "http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf"
        tier        = "memory"
        severity    = "high"
        scan_target = "process_memory"

    strings:
        // 66 81 CA FF 0F   or dx, 0x0FFF
        // 42               inc edx
        // 52               push edx
        // 6A 02            push 2            (NtAccessCheckAndAuditAlarm syscall)
        // 58               pop eax
        // CD 2E            int 0x2E
        // 3C 05            cmp al, 5
        // 74 EA            jz  back
        $skape = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 74 EA }

        // NtDisplayString variant (syscall 0x43)
        $skape_ntdisplay = { 66 81 CA FF 0F 42 52 6A 43 58 CD 2E 3C 05 74 EA }

        // SEH-based egg-hunter (no syscall — uses IsBadReadPtr pattern)
        $seh_egghunter = { EB 21 59 B8 ?? ?? ?? ?? 51 6A FF [0-8] E3 F9 }

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// PAGE_EXECUTE_READWRITE as an immediate argument (shellcode stager signature).
// Benign code usually passes PAGE_READWRITE (0x04) to VirtualAlloc for heaps;
// a literal 0x40 push/mov near an allocator call strongly implies stager intent.
// ---------------------------------------------------------------------------
rule Shellcode_RwxAllocator_Prologue_Memory
{
    meta:
        description = "RWX allocator prologue — literal PAGE_EXECUTE_READWRITE (0x40) passed to VirtualAlloc-shaped call"
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "medium"
        scan_target = "process_memory"

    strings:
        // x64 fastcall:  mov r9d, 0x40         (flProtect arg, 4th param)
        //                41 B9 40 00 00 00
        $x64_r9 = { 41 B9 40 00 00 00 }

        // x64:           mov r8d, 0x3000       (MEM_COMMIT|MEM_RESERVE, 3rd arg)
        //                followed within 16 bytes by  mov r9d, 0x40
        $x64_commit_then_rwx = { 41 B8 00 30 00 00 [0-16] 41 B9 40 00 00 00 }

        // x86 stdcall:   push 0x40             6A 40
        //                push 0x1000/0x3000    68 00 10 00 00 / 68 00 30 00 00
        //                push 0                6A 00
        //                push 0                6A 00
        //                call VirtualAlloc
        $x86_push_rwx = { 6A 40 68 00 ?0 00 00 6A 00 6A 00 E8 }

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// AMSI / ETW in-process patches. Short byte sequences; only match when they
// appear at the *very start* of AmsiScanBuffer / EtwEventWrite — which the
// scanner path achieves by running against process memory where the hook
// writes are visible.
// ---------------------------------------------------------------------------
rule HookPatch_AmsiScanBuffer_Memory
{
    meta:
        description = "AMSI bypass patch — AmsiScanBuffer entry rewritten to return AMSI_RESULT_CLEAN or skipped"
        author      = "NortonEDR"
        reference   = "https://rastamouse.me/memory-patching-amsi-bypass/"
        tier        = "memory"
        severity    = "critical"
        scan_target = "process_memory"

    strings:
        // mov eax, 0x80070057 ; ret   (E_INVALIDARG — common bypass value)
        $patch_einvalid_x64 = { B8 57 00 07 80 C3 }
        // xor eax, eax ; ret          (return S_OK + AMSI_RESULT_CLEAN=0 via out-param left untouched)
        $patch_xor_ret      = { 31 C0 C3 }
        // xor rax, rax ; ret
        $patch_xor_ret64    = { 48 31 C0 C3 }
        // mov eax, 0 ; ret
        $patch_mov0_ret     = { B8 00 00 00 00 C3 }
        // Single-byte RET stub — paired with stack-fixup prologue some bypasses use
        // (only useful combined with AMSI-specific context; low-precision alone)

    condition:
        any of them and filesize < 16MB
}


rule HookPatch_EtwEventWrite_Memory
{
    meta:
        description = "ETW bypass patch — EtwEventWrite / NtTraceEvent prologue replaced with ret stub"
        author      = "NortonEDR"
        reference   = "https://github.com/xpn/EtwStartupPatch"
        tier        = "memory"
        severity    = "critical"
        scan_target = "process_memory"

    strings:
        // xor rax, rax ; ret
        $etw_xor_ret = { 48 31 C0 C3 }
        // ret + nops (tail-call patches)
        $etw_ret_nops = { C3 90 90 90 90 }
        // The specific 5-byte prologue rewrite seen in public bypasses:
        // "mov eax, 0 ; ret"  replacing "4C 8B D1 B8 5C 00 00 00" (NtTraceEvent SSN load)
        $etw_zero_ret_x64 = { 33 C0 C2 14 00 }

    condition:
        any of them and filesize < 16MB
}
