// D/Invoke, manual-interop, and runtime-IL-emission patterns in managed
// assemblies. D/Invoke (TheWover/FuzzySecurity) is the dominant technique
// for bypassing .NET's ILStubGenerated ETW event — it resolves native APIs
// at runtime via manual PEB walking, calls them through delegates bound to
// raw function pointers, and optionally manual-maps DLLs without going
// through the Windows loader.
//
// Since D/Invoke assemblies carry stable type/method names (it's a public
// library most offensive tooling compiles as-is), string matching against
// the CLR metadata produces high-precision detections that our ETW path
// structurally cannot catch.
//
// Tier: signal-only — matches on name strings alone and would FP on any
// red-team training repo or copy of D/Invoke sitting in the user's Downloads.

// ---------------------------------------------------------------------------
// D/Invoke library fingerprint — stable types/methods from DInvoke.dll
// ---------------------------------------------------------------------------
rule DInvoke_Library_Fingerprint
{
    meta:
        description = "Managed assembly contains D/Invoke library internals (DynamicAPIInvoke, GetExportAddress, ManualMap) — manual native-API resolution bypassing ILStubGenerated ETW"
        author      = "NortonEDR"
        reference   = "https://github.com/TheWover/DInvoke"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Managed-PE marker — cheap gate so the rule doesn't scan every file
        $clr_marker = "BSJB"

        // Core D/Invoke resolver methods
        $m_dyn_api         = "DynamicAPIInvoke"          ascii
        $m_dyn_func        = "DynamicFunctionInvoke"     ascii
        $m_get_lib_addr    = "GetLibraryAddress"         ascii
        $m_get_export      = "GetExportAddress"          ascii
        $m_get_peb_ldr     = "GetPebLdrModuleEntry"      ascii
        $m_get_syscall     = "GetSyscallStub"            ascii
        $m_call_syscall    = "CallSyscall"               ascii
        $m_dyn_syscall     = "DynamicSyscallInvoke"      ascii

        // D/Invoke manual-mapping submodule
        $m_manual_map      = "ManualMap"                 ascii
        $m_overload_mod    = "OverloadModule"            ascii
        $m_relocate_img    = "RelocateModule"            ascii
        $m_rewrite_iat     = "RewriteModuleIAT"          ascii
        $m_map_module_dsk  = "MapModuleToMemory"         ascii
        $m_map_module_mem  = "MapModuleFromDisk"         ascii

        // D/Invoke namespace roots
        $ns_dinvoke        = "DInvoke."                  ascii
        $ns_dinvoke_core   = "DInvoke.DynamicInvoke"     ascii
        $ns_dinvoke_mm     = "DInvoke.ManualMap"         ascii
        $ns_dinvoke_data   = "DInvoke.Data"              ascii

    condition:
        $clr_marker and 2 of ($m_*, $ns_*)
}


// ---------------------------------------------------------------------------
// Manual interop signal — Marshal.GetDelegateForFunctionPointer combined with
// multiple native Nt API name strings in the same assembly. This catches
// custom-written D/Invoke-style loaders that don't import the DInvoke
// library wholesale but reimplement the pattern.
// ---------------------------------------------------------------------------
rule ManualInterop_DelegateFunctionPointer_Cluster
{
    meta:
        description = "Managed assembly uses Marshal.GetDelegateForFunctionPointer alongside raw Nt-API name strings — hallmark of manual interop that bypasses DllImport/ILStubGenerated"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $clr_marker = "BSJB"

        // Manual-interop primitives
        $p_get_delegate = "GetDelegateForFunctionPointer"  ascii
        $p_get_funcptr  = "GetFunctionPointerForDelegate"  ascii
        $p_unmanaged_fp = "UnmanagedFunctionPointer"       ascii
        $p_delegate_inv = "Delegate.DynamicInvoke"         ascii
        $p_marshal      = "System.Runtime.InteropServices.Marshal" ascii

        // Native Nt-API name strings that would be looked up via
        // GetProcAddress / PEB walk (D/Invoke resolves these by name).
        $n_nt_alloc     = "NtAllocateVirtualMemory"        ascii
        $n_nt_protect   = "NtProtectVirtualMemory"         ascii
        $n_nt_write     = "NtWriteVirtualMemory"           ascii
        $n_nt_map       = "NtMapViewOfSection"             ascii
        $n_nt_unmap     = "NtUnmapViewOfSection"           ascii
        $n_nt_create_s  = "NtCreateSection"                ascii
        $n_nt_open_pr   = "NtOpenProcess"                  ascii
        $n_nt_create_t  = "NtCreateThreadEx"               ascii
        $n_nt_queue     = "NtQueueApcThread"               ascii
        $n_nt_set_ctx   = "NtSetContextThread"             ascii
        $n_nt_resume    = "NtResumeThread"                 ascii
        $n_rtl_user_th  = "RtlCreateUserThread"            ascii
        $n_ldr_load     = "LdrLoadDll"                     ascii
        $n_ldr_getproc  = "LdrGetProcedureAddress"         ascii

        // Delegate-type suffix convention used by D/Invoke and derivatives
        $t_delegate_t1  = "NtAllocateVirtualMemory_t"      ascii
        $t_delegate_t2  = "NtProtectVirtualMemory_t"       ascii
        $t_delegate_t3  = "NtCreateThreadEx_t"             ascii
        $t_delegate_t4  = "NtWriteVirtualMemory_t"         ascii

    condition:
        $clr_marker and
        (
            (any of ($p_get_delegate, $p_get_funcptr) and 3 of ($n_*))
            or any of ($t_delegate_*)
            or (any of ($p_*) and any of ($t_delegate_*))
        )
}


// ---------------------------------------------------------------------------
// Runtime IL emission — Reflection.Emit / DynamicMethod / Calli. Attackers
// use this to emit native-calling thunks at runtime so nothing static in
// the assembly reveals the native targets. Donut, SharpSploit, and several
// Covenant grunts rely on this.
// ---------------------------------------------------------------------------
rule RuntimeILEmission_DynamicMethod_Calli
{
    meta:
        description = "Managed assembly emits IL at runtime via DynamicMethod + OpCodes.Calli — runtime-generated native-call thunks (Donut, SharpSploit, runtime syscall gadget builders)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $clr_marker = "BSJB"

        $r_emit_ns     = "System.Reflection.Emit"         ascii
        $r_dyn_method  = "DynamicMethod"                  ascii
        $r_il_gen      = "ILGenerator"                    ascii
        $r_method_b    = "MethodBuilder"                  ascii
        $r_type_b      = "TypeBuilder"                    ascii
        $r_asm_b       = "AssemblyBuilder"                ascii
        $r_define_dyn  = "DefineDynamicAssembly"          ascii
        $r_run_collect = "RunAndCollect"                  ascii

        // The specific opcodes that reveal native-call-building intent
        $op_calli      = "OpCodes.Calli"                  ascii
        $op_calli_emit = "EmitCalli"                      ascii
        $op_ldftn      = "OpCodes.Ldftn"                  ascii

        // Unsafe / native-signature indicators paired with the above
        $sig_cdecl     = "CallingConvention.Cdecl"        ascii
        $sig_stdcall   = "CallingConvention.StdCall"      ascii
        $sig_native    = "NativeCallingConvention"        ascii

    condition:
        $clr_marker and
        (
            // Calli emission is high-signal by itself
            any of ($op_calli, $op_calli_emit)
            // Or DynamicMethod + unmanaged calling convention
            or (any of ($r_dyn_method, $r_il_gen) and any of ($sig_*))
            // Or DefineDynamicAssembly + RunAndCollect (in-memory assembly
            // that self-destructs — classic offensive pattern)
            or ($r_define_dyn and $r_run_collect)
        )
}


// ---------------------------------------------------------------------------
// Indirect-syscall-from-C# fingerprint. Tooling like "Inline-ExecuteAssembly"
// and recent SharpSploit forks bundle x64 syscall gadgets as byte arrays
// inside the managed assembly and resolve SSNs at runtime by walking ntdll
// exports. The byte arrays themselves are the fingerprint.
// ---------------------------------------------------------------------------
rule CSharp_Indirect_Syscall_Gadget_Blob
{
    meta:
        description = "Managed assembly embeds the x64 syscall-stub byte sequence 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 — shellcode-grade syscall gadget compiled into a C# binary"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $clr_marker = "BSJB"

        // The stub bytes expressed in the compiled blob format .NET uses
        // when you declare `new byte[] { 0x4C, 0x8B, 0xD1, ... }` — the
        // compiler lays them out contiguously in the #US/#Blob stream.
        $stub_bytes_direct   = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        $stub_bytes_indirect = { 4C 8B D1 B8 ?? ?? 00 00 FF 25 ?? ?? ?? ?? }

        // Companion strings typically used by the loader
        $s_ssn_resolver = "GetSyscallNumber"              ascii
        $s_gadget       = "SyscallGadget"                 ascii
        $s_syscaller    = "Syscaller"                     ascii

    condition:
        $clr_marker and
        (any of ($stub_bytes_*) or (any of ($s_*) and $clr_marker))
}
