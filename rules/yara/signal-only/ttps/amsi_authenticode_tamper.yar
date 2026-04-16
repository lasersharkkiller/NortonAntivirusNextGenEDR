// AMSI, Authenticode, and code-signing trust infrastructure tampering
// fingerprints. Covers AMSI DLL/context manipulation, WLDP bypass,
// SIP/trust provider hijack, certificate store manipulation, catalog
// file tampering, WinVerifyTrust patching, and Code Integrity bypass.
//
// Tier: signal-only — security tools reference these APIs legitimately.
// Chain with: non-security-tool process, script parent, unsigned binary,
// or combination with execution/persistence indicators.

// ---------------------------------------------------------------------------
// AMSI in-memory bypass. Scripts or binaries that reference AMSI internal
// functions (AmsiScanBuffer, AmsiOpenSession) and field names
// (amsiInitFailed, amsiContext) for in-memory patching or reflection
// bypass. Complements the YARA memory rule for prologue byte patches.
// ---------------------------------------------------------------------------
rule AMSI_InMemory_Bypass_Reference
{
    meta:
        description = "AMSI in-memory bypass: AmsiScanBuffer/AmsiOpenSession/amsiInitFailed reference for patching (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // AMSI function targets
        $fn1 = "AmsiScanBuffer"                                        ascii nocase
        $fn2 = "AmsiScanString"                                        ascii nocase
        $fn3 = "AmsiOpenSession"                                       ascii nocase
        $fn4 = "AmsiInitialize"                                        ascii nocase
        $fn5 = "AmsiCloseSession"                                      ascii nocase
        $fn6 = "AmsiUacScan"                                           ascii nocase

        // AMSI bypass fields / context
        $ctx1 = "amsiInitFailed"                                       ascii nocase
        $ctx2 = "amsiContext"                                          ascii nocase
        $ctx3 = "amsiSession"                                          ascii nocase

        // Patch indicators (memory manipulation near AMSI)
        $patch1 = "VirtualProtect"                                     ascii nocase
        $patch2 = "WriteProcessMemory"                                 ascii nocase
        $patch3 = "Marshal.Copy"                                       ascii nocase
        $patch4 = "RtlMoveMemory"                                     ascii nocase
        $patch5 = "[Runtime.InteropServices.Marshal]::Copy"            ascii nocase

        // DLL manipulation
        $dll1 = "amsi.dll"                                             ascii nocase
        $dll2 = "GetModuleHandle"                                      ascii nocase
        $dll3 = "GetProcAddress"                                       ascii nocase
        $dll4 = "LoadLibrary"                                          ascii nocase

        // AMSI result constants / error codes
        $res1 = "AMSI_RESULT_CLEAN"                                    ascii nocase
        $res2 = "0x80070057"                                           ascii nocase   // E_INVALIDARG
        $res3 = "E_INVALIDARG"                                         ascii nocase
        $res4 = "AMSI_RESULT_NOT_DETECTED"                             ascii nocase

        // -----------------------------------------------------------
        // Matt Graeber reflection bypass and variants.
        //
        // Classic one-liner (2016):
        //   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
        //     GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        //
        // Rasta-mouse variation (targeting amsiContext):
        //   $t=[Ref].Assembly.GetType('S.M.A.AmsiUtils')
        //   $f=$t.GetField('amsiContext','NonPublic,Static')
        //   [IntPtr]$ptr=$f.GetValue($null)
        //   [Int32[]]$buf=@(0); [Marshal]::Copy($buf,0,$ptr,1)
        //
        // Other variants target amsiSession, use full type paths,
        // or split the chain across variables.
        // -----------------------------------------------------------
        $refl1 = "System.Management.Automation.AmsiUtils"              ascii nocase
        $refl2 = "NonPublic,Static"                                    ascii nocase
        $refl3 = "NonPublic, Static"                                   ascii nocase  // with space
        $refl4 = /GetField\s*\(\s*['"]amsiInitFailed/                  ascii nocase
        $refl5 = /GetField\s*\(\s*['"]amsiContext/                     ascii nocase
        $refl6 = /GetField\s*\(\s*['"]amsiSession/                     ascii nocase
        $refl7 = /\.SetValue\s*\(\s*\$null\s*,\s*\$true\s*\)/         ascii nocase
        $refl8 = /\.SetValue\s*\(\s*\$null\s*,\s*\$false\s*\)/        ascii nocase
        $refl9 = "[Ref].Assembly.GetType("                             ascii nocase
        $refl10 = /GetType\s*\(\s*['"]System\.Management\.Automation\.Amsi/ ascii nocase
        // Variable-stored reflection chain fragments
        $refl11 = /\$\w+\s*=\s*\[Ref\]\.Assembly/                     ascii nocase
        $refl12 = /\.GetField\s*\(\s*['"]amsi/                         ascii nocase  // any GetField('amsi...')
        // GetValue + Marshal.Copy combo (amsiContext zeroing)
        $refl13 = /\.GetValue\s*\(\s*\$null\s*\)/                     ascii nocase

        $fn1w = "AmsiScanBuffer"                                       wide nocase
        $ctx1w = "amsiInitFailed"                                      wide nocase

    condition:
        // Direct function reference + memory patch
        (any of ($fn*) and any of ($patch*))
        // amsi.dll + resolve API + function target
        or ($dll1 and ($dll2 or $dll3) and any of ($fn*))
        // Bypass field + patch (amsiInitFailed/amsiContext + VirtualProtect etc.)
        or (($ctx1 or $ctx1w) and any of ($patch*))
        // Classic Graeber reflection: AmsiUtils + NonPublic binding
        or ($refl1 and ($refl2 or $refl3))
        // Reflection GetField targeting AMSI fields
        or any of ($refl4, $refl5, $refl6)
        // SetValue($null,$true) — the field flip
        or ($refl7 and ($refl1 or any of ($refl4, $refl5, $refl6)))
        // [Ref].Assembly.GetType targeting AMSI
        or $refl10
        // Variable-stored reflection targeting AMSI fields
        or ($refl11 and $refl12)
        // GetValue + Marshal.Copy combo (amsiContext zeroing)
        or ($refl13 and any of ($patch*) and ($ctx2 or $refl5))
        // AMSI function + result constant (return forcing)
        or (any of ($fn*) and any of ($res*))
}


// ---------------------------------------------------------------------------
// AMSI internal COM method / vtable patching. Advanced bypass that leaves
// exported function prologues intact and instead patches CAmsiAntimalware::Scan
// or manipulates the COM vtable so the internal provider-iteration method
// is redirected. Scripts reference internal class/method names, vtable
// offsets, or amsi.dll+offset patterns to locate and patch these targets.
// ---------------------------------------------------------------------------
rule AMSI_Internal_Method_VTable_Patch
{
    meta:
        description = "AMSI internal COM method/vtable patch: CAmsiAntimalware::Scan bypass (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Internal class / method references
        $cls1 = "CAmsiAntimalware"                                     ascii nocase
        $cls2 = "CAmsiStream"                                         ascii nocase
        $cls3 = "CAmsiBufferStream"                                   ascii nocase
        $cls4 = "CAmsiAntimalware::Scan"                              ascii nocase
        $cls5 = "amsi!CAmsiAntimalware"                               ascii nocase

        // COM vtable manipulation
        $vt1 = "vtable"                                                ascii nocase
        $vt2 = "vftable"                                               ascii nocase
        $vt3 = "virtualmethod"                                         ascii nocase
        $vt4 = "vfptr"                                                 ascii nocase

        // Offset-based patching (amsi.dll base + offset)
        $off1 = "amsi+0x"                                             ascii nocase
        $off2 = "amsi.dll+0x"                                         ascii nocase
        $off3 = /amsi\s*\+\s*0x[0-9a-fA-F]{2,6}/                     ascii nocase

        // Memory write / patch indicators
        $patch1 = "VirtualProtect"                                     ascii nocase
        $patch2 = "WriteProcessMemory"                                 ascii nocase
        $patch3 = "Marshal.Copy"                                       ascii nocase
        $patch4 = "RtlMoveMemory"                                     ascii nocase
        $patch5 = "memcpy"                                             ascii nocase

        // COM interface manipulation
        $com1 = "IAmsiStream"                                          ascii nocase
        $com2 = "IAntimalware"                                         ascii nocase
        $com3 = "QueryInterface"                                       ascii nocase

        // amsi.dll reference
        $dll1 = "amsi.dll"                                             ascii nocase

    condition:
        any of ($cls*)
        or (any of ($vt*) and $dll1 and any of ($patch*))
        or (any of ($off*) and any of ($patch*))
        or (any of ($com1, $com2) and any of ($patch*))
}


// ---------------------------------------------------------------------------
// AMSI attribute tampering. Manipulating IAmsiStream::GetAttribute return
// values or the underlying IAmsiStream vtable to forge CONTENT_SIZE (zero or
// truncate), redirect CONTENT_ADDRESS to a decoy buffer, corrupt SESSION,
// or set AMSI_ATTRIBUTE_QUIET to suppress scanning. Scripts that reference
// AMSI_ATTRIBUTE enum values alongside memory write or COM manipulation
// APIs are likely performing attribute-level bypass.
// ---------------------------------------------------------------------------
rule AMSI_Attribute_Tampering
{
    meta:
        description = "AMSI attribute tampering: IAmsiStream GetAttribute manipulation to blind providers (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // AMSI_ATTRIBUTE enum values / field names
        $attr1 = "AMSI_ATTRIBUTE_CONTENT_SIZE"                             ascii nocase
        $attr2 = "AMSI_ATTRIBUTE_CONTENT_ADDRESS"                          ascii nocase
        $attr3 = "AMSI_ATTRIBUTE_CONTENT_NAME"                             ascii nocase
        $attr4 = "AMSI_ATTRIBUTE_SESSION"                                  ascii nocase
        $attr5 = "AMSI_ATTRIBUTE_APP_NAME"                                 ascii nocase
        $attr6 = "AMSI_ATTRIBUTE_QUIET"                                    ascii nocase
        $attr7 = "AMSI_ATTRIBUTE_ALL_SIZE"                                 ascii nocase
        $attr8 = "AMSI_ATTRIBUTE_ALL_ADDRESS"                              ascii nocase

        // IAmsiStream interface / method references
        $iface1 = "IAmsiStream"                                            ascii nocase
        $iface2 = "GetAttribute"                                           ascii nocase
        $iface3 = "3e47f2e5-81d4-4d3b-897f-545096770373"                  ascii nocase

        // Memory manipulation near AMSI stream
        $mem1 = "VirtualProtect"                                           ascii nocase
        $mem2 = "WriteProcessMemory"                                       ascii nocase
        $mem3 = "Marshal.Copy"                                             ascii nocase
        $mem4 = "RtlMoveMemory"                                            ascii nocase
        $mem5 = "memcpy"                                                   ascii nocase

        // COM vtable manipulation
        $vtbl1 = "vtable"                                                  ascii nocase
        $vtbl2 = "vftable"                                                 ascii nocase
        $vtbl3 = "ComInterfaceDispatch"                                    ascii nocase

        // Specific bypass patterns
        $bp1 = "contentSize"                                               ascii nocase
        $bp2 = "contentAddress"                                            ascii nocase
        $bp3 = "amsiStream"                                                ascii nocase
        $bp4 = "pAmsiStream"                                               ascii nocase

    condition:
        any of ($attr*)
        or ($iface1 and $iface2 and any of ($mem*))
        or ($iface3 and any of ($mem*))
        or (any of ($bp*) and any of ($mem*) and ($iface1 or $iface2))
        or (any of ($vtbl*) and ($iface1 or $iface2))
}


// ---------------------------------------------------------------------------
// AMSI evasion via string obfuscation. Detects scripts that reconstruct
// AMSI-related strings (AmsiScanBuffer, amsiInitFailed, AmsiUtils, etc.)
// through concatenation, format strings, backtick insertion, [char] arrays,
// -join operators, .Replace() calls, or environment variable character
// extraction. These techniques break keyword-based AMSI scanning because
// the final string only exists at runtime, not in the source code.
//
// Tier: signal-only — legitimate scripts rarely construct AMSI API names
// through obfuscation. Chain with: script engine parent, unsigned binary,
// or combination with AMSI bypass indicators.
// ---------------------------------------------------------------------------
rule AMSI_String_Obfuscation_Evasion
{
    meta:
        description = "AMSI string obfuscation evasion: concatenation/format/tick/char-array to reconstruct AMSI bypass strings (T1562.001, T1027)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // --- String concatenation splitting AMSI keywords ---
        // PowerShell double-quote: "Am"+"si", "Amsi"+"Utils", etc.
        $cat1  = /["']am["']\s*\+\s*["']si/                               nocase
        $cat2  = /["']amsi["']\s*\+\s*["']utils/                          nocase
        $cat3  = /["']amsi["']\s*\+\s*["']scanbuffer/                     nocase
        $cat4  = /["']amsi["']\s*\+\s*["']opensession/                    nocase
        $cat5  = /["']amsi["']\s*\+\s*["']initialize/                     nocase
        $cat6  = /["']amsiinit["']\s*\+\s*["']failed/                     nocase
        $cat7  = /["']amsi["']\s*\+\s*["']context/                        nocase

        // --- Format-string operator (-f) ---
        // "{0}{1}"-f'amsi','utils'  or  "{0}{1}"-f"Amsi","ScanBuffer"
        $fmt1  = /\-f\s*["']amsi["']\s*,/                                 nocase
        $fmt2  = /["']\{0\}\{1\}["']\s*\-f.*amsi/                         nocase

        // --- PowerShell backtick (tick) insertion ---
        // A`m`s`i, am`si, A`msiUtils, etc.
        $tick1 = /[Aa]`[Mm]`[Ss]`[Ii]/                                    ascii
        $tick2 = /[Aa][Mm]`[Ss][Ii]/                                      ascii
        $tick3 = /`[Aa]`[Mm]`[Ss]`[Ii]/                                   ascii
        $tick4 = /[Aa]`m`s`i`[UuSsCcIi]/                                  ascii

        // --- [char] array / -join reconstruction ---
        // [char]65 = 'A', [char]109 = 'm', [char]115 = 's', [char]105 = 'i'
        $chr1  = "[char]65" ascii nocase
        $chr2  = /\[char\]\s*0x41/                                         nocase
        $chr3  = /65\s*,\s*109\s*,\s*115\s*,\s*105/                       ascii   // A,m,s,i decimal
        $chr4  = /0x41\s*,\s*0x6d\s*,\s*0x73\s*,\s*0x69/                  nocase  // hex
        $chr5  = /-join\s*\(\s*\[char\[\]\]/                              nocase  // -join([char[]]

        // --- .Replace() constructing AMSI strings ---
        $rep1  = /["']ams[^"']*["']\s*[\.\-]\s*replace\s*\(/              nocase
        $rep2  = /["']am[^"']{1,4}si[^"']*["']\s*[\.\-]\s*replace\s*\(/  nocase

        // --- Environment variable character extraction ---
        // $env:comspec[4,15,25]-join'' extracts chars from known env vars
        $env1  = /\$env:\w+\[\d+/                                         nocase
        $env2  = /\]\s*-join\s*["']["']/                                   nocase

        // --- XOR deobfuscation ---
        $xor1  = "-bxor"                                                   ascii nocase

        // --- Execution primitives (required for compound conditions) ---
        $exec1 = "Invoke-Expression"                                       ascii nocase
        $exec2 = "iex("                                                    ascii nocase
        $exec3 = "iex "                                                    ascii nocase
        $exec4 = ".Invoke("                                                ascii nocase
        $exec5 = "Set-Variable"                                            ascii nocase
        $exec6 = "[scriptblock]::Create"                                   ascii nocase

    condition:
        // Direct AMSI-related obfuscation (high confidence)
        any of ($cat*)
        or any of ($fmt*)
        or any of ($tick*)
        // Char-code array with AMSI char codes
        or ($chr3 or $chr4)
        or ($chr1 and $chr5)
        // Replace-based AMSI string construction
        or any of ($rep*)
        // Env-var extraction + join + execution (compound)
        or ($env1 and $env2 and any of ($exec*))
        // XOR + execution + char construction (compound)
        or ($xor1 and any of ($chr*) and any of ($exec*))
}


// ---------------------------------------------------------------------------
// AMSI hardware breakpoint bypass & parameter corruption.
//
// Instead of patching amsi.dll code, attackers can:
//   1. Set hardware breakpoints (DR0-DR3) on AmsiScanBuffer/AmsiOpenSession
//      entry point, then install a VEH that modifies the return value to
//      E_INVALIDARG or forces AMSI_RESULT_CLEAN before resuming.
//   2. Corrupt parameters: zero out amsiContext before the call so
//      AmsiScanBuffer returns E_INVALIDARG without scanning.
//   3. Patch AmsiOpenSession instead (less monitored), so no valid session
//      is created and subsequent AmsiScanBuffer calls are no-ops.
//   4. Overwrite the AMSI_RESULT output pointer with AMSI_RESULT_CLEAN (0)
//      before the provider writes its real verdict.
//
// References:
//   - @_RastaMouse: AmsiScanBuffer hw breakpoint bypass
//   - @CCob (ethicalchaos): hardware breakpoint AmsiOpenSession bypass
//   - @ZeroMemoryEx: amsiContext zeroing technique
// ---------------------------------------------------------------------------
rule AMSI_HWBreakpoint_ParamCorrupt_Bypass
{
    meta:
        description = "AMSI hardware breakpoint or parameter corruption bypass: DR register abuse, VEH return forcing, amsiContext zeroing (T1562.001)"
        author      = "NortonEDR"
        severity    = "critical"
        mitre_att   = "T1562.001"
        created     = "2026-04-16"

    strings:
        // Hardware breakpoint infrastructure — set/read DR registers
        $hw1 = "SetThreadContext"                                      ascii nocase
        $hw2 = "GetThreadContext"                                      ascii nocase
        $hw3 = "NtSetContextThread"                                    ascii nocase
        $hw4 = "NtGetContextThread"                                    ascii nocase
        $hw5 = "CONTEXT_DEBUG_REGISTERS"                               ascii nocase
        $hw6 = "0x00010"                                               ascii nocase   // CONTEXT_DEBUG_REGISTERS x86
        $hw7 = "0x00100000"                                            ascii nocase   // CONTEXT_DEBUG_REGISTERS x64
        $hw8 = "NtContinue"                                            ascii nocase   // exception→NtContinue path

        // Debug register fields — the actual DR values being set
        $dr1 = "Dr0"                                                   ascii nocase
        $dr2 = "Dr1"                                                   ascii nocase
        $dr3 = "Dr2"                                                   ascii nocase
        $dr4 = "Dr3"                                                   ascii nocase
        $dr5 = "Dr7"                                                   ascii nocase
        $dr6 = ".ContextFlags"                                         ascii nocase
        $dr7 = /context\.(Dr[0-3]|Dr7)\s*=/                           ascii nocase
        $dr8 = /\$ctx\.(Dr[0-3]|Dr7)/                                 ascii nocase   // PowerShell $ctx.Dr0
        // C# and direct struct field access
        $dr9 = /ctx\.Dr[0-3]\s*=\s*(ulong|long|IntPtr)/               ascii nocase
        $dr10 = "CONTEXT64"                                            ascii nocase   // explicit 64-bit context struct

        // VEH / exception handler setup (intercepts the HW BP firing)
        $veh1 = "AddVectoredExceptionHandler"                          ascii nocase
        $veh2 = "EXCEPTION_SINGLE_STEP"                                ascii nocase
        $veh3 = "0x80000004"                                           ascii nocase   // EXCEPTION_SINGLE_STEP value
        $veh4 = "EXCEPTION_CONTINUE_EXECUTION"                         ascii nocase
        $veh5 = "RemoveVectoredExceptionHandler"                       ascii nocase
        // Alternate exception handler mechanisms
        $veh6 = "SetUnhandledExceptionFilter"                          ascii nocase
        $veh7 = "__except"                                             ascii nocase   // SEH handler in C/C++
        $veh8 = "RtlAddVectoredExceptionHandler"                       ascii nocase  // ntdll direct

        // Anti-debug setup (commonly precedes HW BP installation)
        $antdbg1 = "ThreadHideFromDebugger"                            ascii nocase
        $antdbg2 = "NtSetInformationThread"                            ascii nocase
        $antdbg3 = "0x11"                                              ascii nocase   // ThreadHideFromDebugger class
        $antdbg4 = "ZwSetInformationThread"                            ascii nocase

        // AMSI function targets (what the HW BP is set on)
        $amsi1 = "AmsiScanBuffer"                                      ascii nocase
        $amsi2 = "AmsiOpenSession"                                     ascii nocase
        $amsi3 = "AmsiScanString"                                      ascii nocase
        $amsi4 = "amsi.dll"                                            ascii nocase
        $amsi5 = "AmsiCloseSession"                                    ascii nocase
        $amsi6 = "AmsiInitialize"                                      ascii nocase

        // AMSI function resolution chain (force-load + resolve address)
        $resolve1 = /LoadLibrary[AW]?\s*\(\s*["']amsi/                ascii nocase
        $resolve2 = /GetModuleHandle[AW]?\s*\(\s*["']amsi/            ascii nocase
        $resolve3 = /GetProcAddress\s*\([^,]*,\s*["']AmsiScanBuffer/  ascii nocase
        $resolve4 = /GetProcAddress\s*\([^,]*,\s*["']AmsiOpenSession/ ascii nocase

        // Return value / result manipulation (in VEH context)
        $ret1 = "AMSI_RESULT_CLEAN"                                    ascii nocase
        $ret2 = "0x80070057"                                           ascii nocase   // E_INVALIDARG
        $ret3 = "E_INVALIDARG"                                         ascii nocase
        $ret4 = /Rax\s*=\s*0/                                         ascii nocase
        $ret5 = /Rax\s*=\s*0x80070057/                                ascii nocase
        $ret6 = /\$context\.Rax/                                       ascii nocase
        $ret7 = /Rip\s*[+=]/                                          ascii nocase
        $ret8 = /\$context\.Rip/                                       ascii nocase
        $ret9 = /context->Rip\s*[+=]/                                 ascii nocase   // C/C++ variant
        $ret10 = /context->Rax\s*=/                                   ascii nocase   // C/C++ variant
        $ret11 = "ExceptionInformation"                                ascii nocase   // EXCEPTION_RECORD field access

        // Parameter corruption (zeroing amsiContext)
        $param1 = /amsiContext\s*=\s*0/                                ascii nocase
        $param2 = /amsiContext\s*=\s*\[IntPtr\]::Zero/                 ascii nocase
        $param3 = "IntPtr.Zero"                                        ascii nocase
        $param4 = /Marshal::Copy\s*\(\s*\$buf/                        ascii nocase

        // Patch bytes for AmsiOpenSession (less commonly monitored)
        $opsess1 = { B8 57 00 07 80 C3 }                              // MOV EAX, E_INVALIDARG; RET
        $opsess2 = { 31 C0 C3 }                                       // XOR EAX,EAX; RET
        $opsess3 = { 33 C0 C3 }                                       // XOR EAX,EAX; RET (MSVC)

    condition:
        // === Coburn technique core: HW BP + VEH + AMSI target ===
        (any of ($hw*) and any of ($veh*) and any of ($amsi*))
        // HW BP + AMSI function resolution (LoadLibrary/GetProcAddress chain)
        or (any of ($hw*) and any of ($resolve*))
        // Debug registers + AMSI function reference
        or (any of ($dr*) and any of ($amsi*))
        // VEH + return value manipulation + AMSI
        or (any of ($veh*) and any of ($ret*) and any of ($amsi*))
        // AMSI function resolution + VEH (resolve AmsiScanBuffer, set up handler)
        or (any of ($resolve*) and any of ($veh1, $veh6, $veh8))
        // Anti-debug + AMSI reference (ThreadHideFromDebugger setup)
        or (any of ($antdbg*) and any of ($amsi*) and any of ($hw*))
        // Parameter corruption patterns + AMSI context
        or (any of ($param*) and any of ($amsi*))
        // AmsiOpenSession-specific patch bytes
        or (any of ($opsess*) and any of ($amsi*))
        // Context register manipulation in exception handler
        or (any of ($ret4, $ret5, $ret6, $ret7, $ret8, $ret9, $ret10) and ($veh1 or $veh2 or $veh3))
        // NtContinue path + DR registers + AMSI
        or ($hw8 and any of ($dr*) and any of ($amsi*))
}


// ---------------------------------------------------------------------------
// AMSI evasion via alternate execution context. Instead of patching AMSI,
// attackers execute malicious code in contexts where AMSI is not initialized,
// not integrated, or uses a legacy runtime without AMSI support.
//
// Techniques:
//   1. Custom runspace with blank InitialSessionState (skips AMSI init)
//   2. Force CLR v2 hosting (pre-AMSI .NET framework)
//   3. DotNetToJScript / GadgetToJScript (JScript→.NET without AMSI)
//   4. Patch the caller-side in System.Management.Automation.dll
//   5. PowerShell Runspace with modified LanguageMode
//   6. Group Policy / registry FeatureBits disablement
//   7. COR_PROFILER hijack to intercept AMSI JIT calls
// ---------------------------------------------------------------------------
rule AMSI_Alternate_Execution_Context_Bypass
{
    meta:
        description = "AMSI evasion via alternate execution context: custom runspace, CLR downgrade, DotNetToJScript, caller-side patch (T1562.001)"
        author      = "NortonEDR"
        severity    = "high"
        mitre_att   = "T1562.001"
        created     = "2026-04-16"

    strings:
        // Custom runspace without AMSI
        $rs1 = "InitialSessionState.Create()"                         ascii nocase
        $rs2 = "InitialSessionState.CreateDefault2()"                 ascii nocase
        $rs3 = /RunspaceFactory\.CreateRunspace\s*\(/                 ascii nocase
        $rs4 = ".LanguageMode ="                                      ascii nocase
        $rs5 = "RunspaceInvoke"                                       ascii nocase
        $rs6 = "[PowerShell]::Create()"                               ascii nocase

        // CLR v2 / legacy runtime activation (pre-AMSI .NET)
        $clr1 = "useLegacyV2RuntimeActivationPolicy"                  ascii nocase
        $clr2 = /supportedRuntime\s+version="v2\.0/                   ascii nocase
        $clr3 = /clrVersion="?v2\.0/                                  ascii nocase
        $clr4 = "CorBindToRuntimeEx"                                  ascii nocase  // legacy CLR hosting API

        // DotNetToJScript / GadgetToJScript
        $d2j1 = "DotNetToJScript"                                     ascii nocase
        $d2j2 = "GadgetToJScript"                                     ascii nocase
        $d2j3 = "starcommanddispatch"                                 ascii nocase
        $d2j4 = "d2fjscript"                                          ascii nocase
        // BinaryFormatter deserialization (DotNetToJScript core)
        $d2j5 = "BinaryFormatter"                                     ascii nocase
        $d2j6 = "ObjectStateFormatter"                                ascii nocase
        $d2j7 = "LosFormatter"                                        ascii nocase

        // Caller-side patch (System.Management.Automation.dll internals)
        $caller1 = "AmsiUtils"                                        ascii nocase
        $caller2 = "ScanContent"                                      ascii nocase
        $caller3 = "ScanString"                                       ascii nocase
        $caller4 = "amsiInitialized"                                  ascii nocase
        $caller5 = "System.Management.Automation.dll"                 ascii nocase

        // AMSI FeatureBits registry disablement
        $reg1 = /AMSI\\FeatureBits/                                   ascii nocase
        $reg2 = "Set-ItemProperty"                                    ascii nocase
        $reg3 = "New-ItemProperty"                                    ascii nocase

        // AMSI probing (pre-bypass reconnaissance)
        $probe1 = "Test-Path variable:amsiInitFailed"                 ascii nocase
        $probe2 = "Test-Path variable:amsiContext"                    ascii nocase

        // Script execution context markers
        $exec1 = ".AddScript("                                        ascii nocase
        $exec2 = ".AddCommand("                                       ascii nocase
        $exec3 = "Invoke-Command"                                     ascii nocase
        $exec4 = "Invoke-Expression"                                  ascii nocase

    condition:
        // Custom runspace + script execution (blank ISS skips AMSI)
        (($rs1 or $rs2) and any of ($exec*))
        // CLR v2 forcing + .NET execution
        or any of ($clr*)
        // DotNetToJScript patterns
        or any of ($d2j1, $d2j2, $d2j3, $d2j4)
        // BinaryFormatter + JScript context (DotNetToJScript payload)
        or ($d2j5 and any of ($d2j1, $d2j2))
        // Caller-side patch: AmsiUtils internal + memory write
        or ($caller1 and ($caller2 or $caller3 or $caller4) and $caller5)
        // FeatureBits registry manipulation
        or ($reg1 and ($reg2 or $reg3))
        // AMSI probing
        or any of ($probe*)
}


// ---------------------------------------------------------------------------
// AMSI DLL hijack / unhooking. Manipulating the amsi.dll load path via
// SetDllDirectory/AddDllDirectory, or unloading and reloading amsi.dll
// to remove security vendor hooks from the clean copy.
// ---------------------------------------------------------------------------
rule AMSI_DLL_Hijack_Unhook
{
    meta:
        description = "AMSI DLL hijack/unhook: SetDllDirectory redirect or FreeLibrary+reload to remove hooks (T1562.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $dll1 = "amsi.dll"                                             ascii nocase

        // DLL search order manipulation
        $dir1 = "SetDllDirectory"                                      ascii nocase
        $dir2 = "AddDllDirectory"                                      ascii nocase

        // DLL unload + reload (unhooking)
        $ul1 = "FreeLibrary"                                           ascii nocase
        $ul2 = "LoadLibrary"                                           ascii nocase
        $ul3 = "GetModuleHandle"                                       ascii nocase

        // Mapping clean copy from disk
        $map1 = "CreateFileMapping"                                    ascii nocase
        $map2 = "MapViewOfFile"                                        ascii nocase
        $map3 = "NtCreateSection"                                      ascii nocase
        $map4 = "NtMapViewOfSection"                                   ascii nocase

        $dll1w = "amsi.dll"                                            wide nocase

    condition:
        ($dll1 or $dll1w) and any of ($dir*)
        or ($dll1 and $ul1 and $ul2)
        or ($dll1 and any of ($map*))
}


// ---------------------------------------------------------------------------
// WLDP (Windows Lockdown Policy) bypass. Patching WldpQueryDynamicCodeTrust
// or WldpIsClassInApprovedList to allow unsigned/untrusted code execution
// on systems with Device Guard or WDAC enabled.
// ---------------------------------------------------------------------------
rule WLDP_Bypass
{
    meta:
        description = "WLDP bypass: WldpQueryDynamicCodeTrust / WldpIsClassInApprovedList patch (T1553)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $wl1 = "WldpQueryDynamicCodeTrust"                             ascii nocase
        $wl2 = "WldpIsClassInApprovedList"                             ascii nocase
        $wl3 = "wldp.dll"                                              ascii nocase
        $wl4 = "WldpGetLockdownPolicy"                                 ascii nocase

        // Patch indicators
        $p1 = "VirtualProtect"                                         ascii nocase
        $p2 = "WriteProcessMemory"                                     ascii nocase
        $p3 = "GetProcAddress"                                         ascii nocase
        $p4 = "GetModuleHandle"                                        ascii nocase

        // WLDP registry
        $reg1 = "\\Microsoft\\WLDP"                                    ascii nocase
        $reg2 = "DeviceGuard"                                          ascii nocase

        $wl1w = "WldpQueryDynamicCodeTrust"                            wide nocase

    condition:
        ($wl1 or $wl1w) and any of ($p*)
        or ($wl2 and any of ($p*))
        or ($wl3 and ($p3 or $p4) and ($wl1 or $wl2))
        or $wl4
        or $reg1
}


// ---------------------------------------------------------------------------
// SIP (Subject Interface Package) hijack. Redirecting the DLL path in
// Cryptography\OID registry keys so that Windows loads an attacker-
// controlled DLL for signature verification instead of the real one.
// This makes any file appear validly signed.
// ---------------------------------------------------------------------------
rule SIP_Hijack
{
    meta:
        description = "SIP hijack: CryptSIPDll registry redirect — Authenticode verification subversion (T1553.003)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // SIP registry paths
        $sip1 = "CryptSIPDllVerifyIndirectData"                        ascii nocase
        $sip2 = "CryptSIPDllGetSignedDataMsg"                          ascii nocase
        $sip3 = "CryptSIPDllPutSignedDataMsg"                          ascii nocase
        $sip4 = "CryptSIPDllCreateIndirectData"                        ascii nocase
        $sip5 = "CryptSIPDllIsMyFileType"                              ascii nocase

        // Parent registry path
        $oid1 = "\\Cryptography\\OID\\"                                ascii nocase
        $oid2 = "EncodingType 0"                                       ascii nocase

        // Registry write indicators
        $rw1 = "Set-ItemProperty"                                      ascii nocase
        $rw2 = "New-ItemProperty"                                      ascii nocase
        $rw3 = "reg add"                                               ascii nocase
        $rw4 = "RegSetValueEx"                                         ascii nocase
        $rw5 = ".RegWrite("                                            ascii nocase

        // Known SIP GUIDs that are hijack targets
        $guid1 = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"             ascii nocase
        $guid2 = "{603BCC1F-4B59-4E08-B724-D2C6297EF351}"             ascii nocase

    condition:
        any of ($sip*)
        or ($oid1 and $oid2 and any of ($rw*))
        or (any of ($guid*) and any of ($rw*))
}


// ---------------------------------------------------------------------------
// WinVerifyTrust / wintrust.dll tampering. Patching WinVerifyTrust to
// always return S_OK (0x0) makes all signature checks pass, defeating
// Authenticode enforcement system-wide.
// ---------------------------------------------------------------------------
rule WinVerifyTrust_Tamper
{
    meta:
        description = "WinVerifyTrust tampering: wintrust.dll hook/patch for Authenticode bypass (T1553.003)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $wvt1 = "WinVerifyTrust"                                       ascii nocase
        $wvt2 = "wintrust.dll"                                         ascii nocase
        $wvt3 = "WTHelperProvDataFromStateData"                        ascii nocase
        $wvt4 = "WTHelperGetProvSignerFromChain"                       ascii nocase

        // Patch / hook indicators
        $p1 = "VirtualProtect"                                         ascii nocase
        $p2 = "WriteProcessMemory"                                     ascii nocase
        $p3 = "GetProcAddress"                                         ascii nocase
        $p4 = "Detours"                                                ascii nocase
        $p5 = "MinHook"                                                ascii nocase

        // Clean-copy remap (unhooking wintrust.dll)
        $m1 = "CreateFileMapping"                                      ascii nocase
        $m2 = "MapViewOfFile"                                          ascii nocase
        $m3 = "NtCreateSection"                                        ascii nocase

        $wvt1w = "WinVerifyTrust"                                      wide nocase

    condition:
        ($wvt1 or $wvt1w) and any of ($p*)
        or ($wvt2 and ($p3 or $p4 or $p5))
        or ($wvt2 and any of ($m*))
        or ($wvt3 or $wvt4) and any of ($p*)
}


// ---------------------------------------------------------------------------
// Certificate store manipulation. Adding rogue root CAs, removing
// legitimate certs from the Disallowed store, or injecting into the
// TrustedPublisher store via certutil, PowerShell, or direct registry
// writes.
// ---------------------------------------------------------------------------
rule Certificate_Store_Manipulation
{
    meta:
        description = "Certificate store tamper: root CA injection / TrustedPublisher add / Disallowed removal (T1553.004)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // certutil commands
        $cu1 = "certutil -addstore root"                               ascii nocase
        $cu2 = "certutil -addstore trustedpublisher"                   ascii nocase
        $cu3 = "certutil -delstore"                                    ascii nocase
        $cu4 = "certutil -importpfx"                                   ascii nocase
        $cu5 = "certutil.exe -addstore"                                ascii nocase
        $cu6 = "certutil -user -addstore"                              ascii nocase

        // PowerShell certificate cmdlets
        $ps1 = "Import-Certificate"                                    ascii nocase
        $ps2 = "Export-Certificate"                                    ascii nocase
        $ps3 = "Import-PfxCertificate"                                 ascii nocase
        $ps4 = "New-SelfSignedCertificate"                             ascii nocase
        $ps5 = "Set-AuthenticodeSignature"                             ascii nocase

        // Certificate store paths
        $sp1 = "Cert:\\LocalMachine\\Root"                             ascii nocase
        $sp2 = "Cert:\\LocalMachine\\TrustedPublisher"                 ascii nocase
        $sp3 = "Cert:\\LocalMachine\\Disallowed"                       ascii nocase
        $sp4 = "Cert:\\CurrentUser\\Root"                              ascii nocase

        // Registry certificate store paths
        $rp1 = "\\SystemCertificates\\ROOT"                            ascii nocase
        $rp2 = "\\SystemCertificates\\TrustedPublisher"                ascii nocase
        $rp3 = "\\SystemCertificates\\Disallowed"                      ascii nocase
        $rp4 = "\\SystemCertificates\\CA"                              ascii nocase

        // .NET certificate APIs
        $net1 = "X509Store"                                            ascii nocase
        $net2 = "X509Certificate2"                                     ascii nocase
        $net3 = ".Add("                                                ascii nocase
        $net4 = "StoreName.Root"                                       ascii nocase
        $net5 = "StoreName.TrustedPublisher"                           ascii nocase

    condition:
        any of ($cu*)
        or any of ($ps1, $ps3, $ps4)
        or any of ($sp*)
        or any of ($rp*)
        or (($net1 and ($net4 or $net5)) and $net3)
}


// ---------------------------------------------------------------------------
// Catalog file (CatRoot) tampering. Modifying or deleting Windows catalog
// files (.cat) or the catalog database (CatRoot2) to invalidate or forge
// file signatures. Also covers CryptCATAdmin API abuse for direct catalog
// manipulation.
// ---------------------------------------------------------------------------
rule Catalog_File_Tampering
{
    meta:
        description = "Catalog file tamper: CatRoot/CatRoot2 modification or CryptCATAdmin API abuse (T1553.003)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Catalog directory paths
        $cat1 = "\\CatRoot\\"                                          ascii nocase
        $cat2 = "\\CatRoot2\\"                                        ascii nocase

        // Catalog admin APIs
        $api1 = "CryptCATAdminCalcHashFromFileHandle"                  ascii nocase
        $api2 = "CryptCATAdminAcquireContext"                          ascii nocase
        $api3 = "CryptCATAdminAddCatalog"                              ascii nocase
        $api4 = "CryptCATAdminRemoveCatalog"                           ascii nocase
        $api5 = "CryptCATCatalogInfoFromContext"                       ascii nocase

        // File operations on catalog paths
        $fo1 = "del "                                                  ascii nocase
        $fo2 = "Remove-Item"                                           ascii nocase
        $fo3 = "copy "                                                 ascii nocase
        $fo4 = "Move-Item"                                             ascii nocase

    condition:
        ($api3 or $api4)
        or (($cat1 or $cat2) and any of ($fo*))
        or ($api1 and $api2 and $api3)
}


// ---------------------------------------------------------------------------
// Code Integrity / Device Guard / HVCI bypass. Disabling driver signature
// enforcement, Hypervisor Code Integrity, or Virtualization-Based Security
// via bcdedit, registry modification, or ci.dll patching.
// ---------------------------------------------------------------------------
rule Code_Integrity_Bypass
{
    meta:
        description = "Code Integrity bypass: bcdedit testsigning/nointegritychecks, HVCI/VBS disable, ci.dll reference (T1553.006)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // bcdedit commands
        $bc1 = "bcdedit /set testsigning"                              ascii nocase
        $bc2 = "bcdedit /set nointegritychecks"                        ascii nocase
        $bc3 = "bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS"     ascii nocase
        $bc4 = "bcdedit /set hypervisorlaunchtype off"                 ascii nocase
        $bc5 = "bcdedit /set vsmlaunchtype off"                        ascii nocase
        $bc6 = "bcdedit.exe /set"                                      ascii nocase

        // ci.dll manipulation
        $ci1 = "ci.dll"                                                ascii nocase
        $ci2 = "CiValidateImageHeader"                                 ascii nocase
        $ci3 = "CiCheckSignedFile"                                     ascii nocase

        // Patch indicators near ci.dll
        $p1 = "VirtualProtect"                                         ascii nocase
        $p2 = "WriteProcessMemory"                                     ascii nocase
        $p3 = "GetProcAddress"                                         ascii nocase

        // WDAC policy modification
        $wdac1 = "Set-RuleOption"                                      ascii nocase
        $wdac2 = "Merge-CIPolicy"                                     ascii nocase
        $wdac3 = "New-CIPolicy"                                       ascii nocase
        $wdac4 = "ConvertFrom-CIPolicy"                               ascii nocase

        // Device Guard registry
        $dg1 = "\\DeviceGuard"                                        ascii nocase
        $dg2 = "EnableVirtualizationBasedSecurity"                     ascii nocase
        $dg3 = "HypervisorEnforcedCodeIntegrity"                      ascii nocase

    condition:
        any of ($bc1, $bc2, $bc3, $bc4, $bc5)
        or ($ci1 and any of ($p*))
        or ($ci2 or $ci3)
        or any of ($wdac*)
        or ($dg1 and ($dg2 or $dg3))
}

// ---------------------------------------------------------------------------
// AMSI provider in-process patching. Attackers exploit the fact that amsi.dll
// and AMSI providers are mapped into the calling process. They can:
//   1. Patch the provider's Scan() prologue (NOP/RET/JMP)
//   2. Redirect the IAntimalwareProvider COM vtable
//   3. Zero/overwrite the provider's keyword tables
//   4. FreeLibrary the provider DLL
//   5. Hook the provider's IAT entries (GetAttribute, etc.)
//
// This rule detects scripts and tools that reference provider internals,
// COM vtable manipulation patterns, and DLL unloading techniques aimed
// at AMSI providers.
// ---------------------------------------------------------------------------
rule AMSI_Provider_InProcess_Patching
{
    meta:
        description = "AMSI provider in-process patching: Scan() prologue patch, COM vtable redirect, keyword zeroing, provider unload, IAT hook (T1562.001)"
        author      = "NortonEDR"
        severity    = "critical"
        mitre_att   = "T1562.001"
        created     = "2026-04-16"

    strings:
        // Provider COM interface identifiers
        $iface1 = "IAntimalwareProvider"                          ascii nocase
        $iface2 = "b2cabfe3-fe04-42b1-a5df-08d483d4d125"         ascii nocase  // IAntimalwareProvider GUID
        $iface3 = "IAntiMalware"                                 ascii nocase
        $iface4 = "IAntimalware2"                                ascii nocase

        // Provider DLL / class references
        $prov1 = "AmsiProvider"                                   ascii nocase
        $prov2 = "InProcServer32"                                 ascii nocase
        $prov3 = "\\Microsoft\\AMSI\\Providers"                   ascii nocase

        // COM vtable manipulation
        $vtbl1 = "vtable"                                         ascii nocase
        $vtbl2 = "vftable"                                        ascii nocase
        $vtbl3 = "VirtualMethodTable"                             ascii nocase
        $vtbl4 = /\[\s*3\s*\]\s*=/ ascii                         // vtable[3] = Scan slot overwrite
        $vtbl5 = "Marshal.ReadIntPtr"                             ascii nocase  // C# vtable read
        $vtbl6 = "Marshal.WriteIntPtr"                            ascii nocase  // C# vtable write

        // Prologue patching patterns (writing bytes to function entry)
        $patch1 = { C3 }                                          // RET (neuter function)
        $patch2 = { 90 90 90 90 90 }                              // NOP slide
        $patch3 = { 31 C0 C3 }                                   // XOR EAX,EAX; RET (return 0 = CLEAN)
        $patch4 = { 33 C0 C3 }                                   // XOR EAX,EAX; RET (MSVC variant)
        $patch5 = { B8 00 00 00 00 C3 }                          // MOV EAX,0; RET (S_OK)

        // Memory write APIs (needed to patch provider code)
        $mem1 = "VirtualProtect"                                  ascii nocase
        $mem2 = "WriteProcessMemory"                              ascii nocase
        $mem3 = "NtWriteVirtualMemory"                            ascii nocase
        $mem4 = "NtProtectVirtualMemory"                          ascii nocase
        $mem5 = "memcpy"                                          ascii nocase
        $mem6 = "RtlCopyMemory"                                  ascii nocase

        // Provider DLL unloading
        $unload1 = "FreeLibrary"                                  ascii nocase
        $unload2 = "LdrUnloadDll"                                 ascii nocase
        $unload3 = "NtUnmapViewOfSection"                         ascii nocase

        // Provider scan method references
        $scan1 = "::Scan("                                        ascii nocase
        $scan2 = "Scan(IAmsiStream"                               ascii nocase
        $scan3 = "AmsiScan"                                       ascii nocase

        // Script patterns for provider tampering
        $scr1 = "GetModuleHandle"                                 ascii nocase
        $scr2 = "GetProcAddress"                                  ascii nocase
        $scr3 = /\[DllImport\s*\(\s*["']amsi/ ascii nocase
        $scr4 = "amsi!DllGetClassObject"                          ascii nocase
        $scr5 = "CoCreateInstance"                                ascii nocase

    condition:
        // Provider interface + memory write + patch bytes
        (any of ($iface*) and any of ($mem*) and any of ($patch*))
        // Provider references + vtable manipulation
        or (any of ($prov*) and any of ($vtbl*) and any of ($mem*))
        // Provider DLL unloading combined with AMSI references
        or (any of ($unload*) and (any of ($iface*) or any of ($prov*) or any of ($scan*)))
        // COM vtable write + scan method reference
        or (($vtbl5 or $vtbl6) and any of ($scan*))
        // Script loading AMSI + patching + vtable
        or (any of ($scr*) and any of ($vtbl*) and any of ($patch*))
}
