#define INITGUID
#include "AmsiProvider.h"
#include <cstdio>
#include <cctype>
#include <new>

// ---------------------------------------------------------------------------
// Module-level ref-count tracking for DllCanUnloadNow
// ---------------------------------------------------------------------------
static volatile LONG g_objectCount = 0;
static volatile LONG g_lockCount   = 0;
static HINSTANCE     g_hModule     = nullptr;

// ---------------------------------------------------------------------------
// Self-integrity baseline — captured once at DllMain (DLL_PROCESS_ATTACH).
//
// Because amsi.dll and its providers are mapped into the attacker's process,
// the attacker has full read/write access to our code, vtable, keyword
// table, and IAT.  We baseline critical values at load time and verify them
// on every Scan() call.  Any deviation means in-process patching occurred.
// ---------------------------------------------------------------------------

// 1. Scan() prologue bytes — detect NOP/RET/JMP patching of our entry point
static BYTE  g_ScanPrologueBaseline[16] = {};
static void* g_ScanMethodAddress        = nullptr;
static bool  g_IntegrityBaselineValid   = false;

// 2. IAntimalwareProvider vtable pointer — detect COM vtable redirect
static const void* g_ExpectedVtable     = nullptr;

// 3. Keyword canary — detect kMaliciousKeywords[] zeroing/overwrite
static const char* g_KeywordCanaryPtr   = nullptr;  // points to kMaliciousKeywords[0]
static BYTE  g_KeywordCanaryBytes[32]   = {};
static ULONG g_KeywordCanaryLen         = 0;
static bool  g_KeywordCanaryValid       = false;

// 4. IAT cross-validation — detect IAT hooking of our imports
//    We baseline the address of GetProcAddress itself (frequently hooked)
static FARPROC g_BaselineGetProcAddress = nullptr;

// Forward declaration
static void LogDetection(const wchar_t* contentName, const char* keyword);

// Capture self-integrity baseline from the first NortonAmsiProvider instance.
// Called from NortonAmsiProvider::Scan() on the very first invocation, when
// `this` is a valid provider pointer with a live vtable.
static void CaptureIntegrityBaseline(NortonAmsiProvider* firstInstance) {
    if (g_IntegrityBaselineValid) return;

    // 1. Baseline Scan() method prologue.
    //    The vtable entry for Scan() is at index 3 in IAntimalwareProvider
    //    (after QueryInterface, AddRef, Release).
    //    We can get it from the vtable of `this`.
    const void** vtable = *reinterpret_cast<const void***>(firstInstance);
    g_ExpectedVtable    = vtable;

    // vtable[3] = Scan, vtable[4] = CloseSession, vtable[5] = DisplayName
    g_ScanMethodAddress = const_cast<void*>(vtable[3]);
    memcpy(g_ScanPrologueBaseline, g_ScanMethodAddress, sizeof(g_ScanPrologueBaseline));

    // 3. Keyword canary — deferred to CaptureKeywordCanary() which is called
    //    from Scan() after kMaliciousKeywords[] is visible.

    // 4. IAT baseline — GetProcAddress from kernel32
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        g_BaselineGetProcAddress = GetProcAddress(hK32, "GetProcAddress");
    }

    g_IntegrityBaselineValid = true;
}

// Check all integrity baselines.  Returns true if tampered.
static bool CheckSelfIntegrity(NortonAmsiProvider* self) {
    if (!g_IntegrityBaselineValid) return false;

    // Check 1: Scan() prologue — detect NOP/RET/JMP patching
    if (g_ScanMethodAddress &&
        memcmp(g_ScanMethodAddress, g_ScanPrologueBaseline,
               sizeof(g_ScanPrologueBaseline)) != 0)
    {
        LogDetection(nullptr,
            "[TAMPER] AMSI provider Scan() prologue patched — "
            "in-process code modification detected");
        return true;
    }

    // Check 2: vtable pointer — detect COM vtable redirect
    const void** currentVtable = *reinterpret_cast<const void***>(self);
    if (currentVtable != g_ExpectedVtable) {
        LogDetection(nullptr,
            "[TAMPER] AMSI provider vtable pointer changed — "
            "COM vtable hijack detected");
        return true;
    }

    // Also verify the Scan slot in the vtable still points to our method
    if (currentVtable[3] != g_ScanMethodAddress) {
        LogDetection(nullptr,
            "[TAMPER] AMSI provider vtable Scan() slot redirected — "
            "COM vtable entry patched");
        return true;
    }

    // Check 3: keyword canary — detect kMaliciousKeywords[] zeroing
    if (g_KeywordCanaryValid && g_KeywordCanaryPtr && g_KeywordCanaryLen > 0) {
        if (memcmp(g_KeywordCanaryPtr, g_KeywordCanaryBytes,
                   g_KeywordCanaryLen) != 0)
        {
            LogDetection(nullptr,
                "[TAMPER] AMSI keyword table modified — "
                "in-memory keyword zeroing/overwrite detected");
            return true;
        }
    }

    // Check 4: IAT — detect hooking of GetProcAddress
    if (g_BaselineGetProcAddress) {
        HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
        if (hK32) {
            FARPROC current = GetProcAddress(hK32, "GetProcAddress");
            if (current != g_BaselineGetProcAddress) {
                LogDetection(nullptr,
                    "[TAMPER] AMSI provider IAT hook detected — "
                    "GetProcAddress address changed");
                return true;
            }
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Malicious keyword list (lowercase; checked against lowercase content)
// ---------------------------------------------------------------------------
static const char* const kMaliciousKeywords[] = {
    // EICAR Anti-Malware Test File (must always detect)
    "x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*",
    // Mimikatz / credential theft
    "invoke-mimikatz",
    "sekurlsa::logonpasswords",
    "sekurlsa::wdigest",
    "kerberos::ptt",
    "kerberos::golden",
    "kerberos::silver",
    "lsadump::sam",
    "lsadump::dcsync",
    "privilege::debug",
    "token::elevate",
    // PowerShell attack frameworks
    "invoke-shellcode",
    "invoke-reflectivepeinjection",
    "invoke-bloodhound",
    "powersploit",
    "powerup",
    "powerview",
    "sharphound",
    // AMSI bypass reflection patterns (Matt Graeber / rasta-mouse technique)
    //
    // Classic one-liner:
    //   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
    //     GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    //
    // Variants: split across variables, obfuscated type names, targeting
    // amsiContext/amsiSession instead of amsiInitFailed.
    "amsibypass",
    "amsiutils",
    "amsicontext",
    "amsisession",                                     // amsiSession field target
    "[ref].assembly.gettype",
    "system.management.automation.amsi",
    "system.management.automation.amsiutils",          // full qualified class name
    "getfield('amsiinitfailed'",                       // reflection GetField targeting amsiInitFailed (single-quote)
    "getfield(\"amsiinitfailed\"",                     // double-quote variant
    "getfield('amsicontext'",                          // targeting amsiContext instead
    "getfield(\"amsicontext\"",
    "getfield('amsisession'",                          // targeting amsiSession
    "getfield(\"amsisession\"",
    ".setvalue($null,$true)",                          // the actual field flip (no space)
    ".setvalue($null, $true)",                         // with space
    ".setvalue($null,\"true\")",                       // string true variant
    "gettype('system.management.automation.amsiutils'",  // GetType with full path (single)
    "gettype(\"system.management.automation.amsiutils\"", // GetType with full path (double)
    "amsiutils').getfield(",                           // chained: AmsiUtils').GetField(
    "amsiutils\").getfield(",                          // double-quote chained variant

    // ---------------------------------------------------------------
    // AmsiScanBuffer / AmsiOpenSession parameter corruption & return
    // value forcing.  Attackers don't always NOP/RET the whole
    // function — they can:
    //   - Set amsiContext to 0 so AmsiScanBuffer returns E_INVALIDARG
    //   - Patch just the comparison (jump) so the wrong branch executes
    //   - Patch AmsiOpenSession to fail, so no session → no scans
    //   - Use hardware breakpoints (DR0-DR3) on AmsiScanBuffer entry
    //     with a VEH that forces a clean return
    //   - Force the output *result pointer to AMSI_RESULT_CLEAN
    // ---------------------------------------------------------------
    "0x80070057",                                      // E_INVALIDARG hex literal
    "amsi_result_clean",                               // AMSI_RESULT_CLEAN constant
    "amsiclosesession",                                // AmsiCloseSession target
    "amsiuacscan",                                     // undocumented AMSI UAC scan
    "addvectoredexceptionhandler",                     // VEH for hardware breakpoint bypass
    "removevectoredexceptionhandler",                  // VEH cleanup after bypass
    "setunhandledexceptionfilter",                     // alternate exception handler for HW BP
    "setthreadcontext",                                // set DR registers for HW breakpoint
    "getthreadcontext",                                // read DR registers (enumerate existing BPs)
    "ntsetcontextthread",                              // ntdll direct syscall variant
    "ntgetcontextthread",                              // ntdll direct syscall variant
    "ntcontinue",                                      // exception→NtContinue DR register path
    "dr0",                                             // debug register 0 (HW BP on AMSI)
    "dr1",                                             // debug register 1
    "dr2",                                             // debug register 2
    "dr3",                                             // debug register 3
    "dr6",                                             // debug register 6 (status)
    "dr7",                                             // debug register 7 (enable HW BP)
    "context.dr0",                                     // CONTEXT structure DR0 field
    "context.dr7",                                     // CONTEXT structure DR7 field
    "context.rip",                                     // CONTEXT structure RIP (VEH skip)
    "context.rax",                                     // CONTEXT structure RAX (return forge)
    "$ctx.dr0",                                        // PowerShell CONTEXT.DR0
    "$ctx.dr7",                                        // PowerShell CONTEXT.DR7
    "$ctx.rip",                                        // PowerShell CONTEXT.RIP
    "$ctx.rax",                                        // PowerShell CONTEXT.RAX
    "context_debug_registers",                         // CONTEXT_DEBUG_REGISTERS flag
    "0x00100000",                                      // CONTEXT_DEBUG_REGISTERS numeric (x64)
    "0x00010",                                         // CONTEXT_DEBUG_REGISTERS numeric (x86)
    "exception_single_step",                           // HW breakpoint exception code
    "0x80000004",                                      // EXCEPTION_SINGLE_STEP numeric value
    "exception_continue_execution",                    // VEH return to skip function
    "threadhidefromdebugger",                          // anti-debug before HW BP install
    "0x11",                                            // ThreadHideFromDebugger class ID (in NtSetInformationThread context)

    // LoadLibrary + GetProcAddress chain to resolve AMSI function pointers
    "loadlibrary(\"amsi",                              // LoadLibrary("amsi.dll") — force AMSI load
    "loadlibrary('amsi",                               // single-quote variant
    "loadlibrarya(\"amsi",                             // ANSI variant
    "loadlibraryw(\"amsi",                             // wide variant
    "getprocaddress(getmodulehandle(\"amsi",           // GetProcAddress combo targeting amsi.dll
    "getmodulehandle(\"amsi.dll\")",                   // GetModuleHandle for amsi.dll specifically

    // ---------------------------------------------------------------
    // Additional AMSI bypass techniques.
    // ---------------------------------------------------------------

    // 1. PowerShell Runspace with AMSI disabled
    //    Creating a custom runspace and setting its ApartmentState or
    //    LanguageMode to bypass AMSI entirely. The InitialSessionState
    //    can omit AMSI initialization.
    "initialsessionstate.create()",                    // blank session state (no AMSI init)
    "initialsessionstate.createdefault2()",            // default2 may have different AMSI behavior
    "runspacefactory.createrunspace(",                 // creating custom runspace
    "runspace.open()",                                 // opening custom runspace (in keyword context)
    ".languagemode = ",                                // setting LanguageMode on runspace

    // 2. .NET Assembly.Load without AMSI
    //    Before .NET 4.8, Assembly.Load(byte[]) did not submit to AMSI.
    //    Attackers force CLR 2.0/4.0 hosting to avoid AMSI-integrated versions.
    "uselegacyv2runtimeactivationpolicy",              // app.config forcing CLR v2
    "clrversion=v2.0",                                 // forcing legacy CLR
    "startup sku=\".netframework,version=v2.0\"",      // app.config CLR2 activation
    "supportedruntime version=\"v2.0\"",               // supported runtime CLR2

    // 3. Alternate scripting hosts / unmanaged PowerShell (AMSI-unaware)
    //    These hosts don't call AmsiInitialize or don't integrate AMSI,
    //    so content runs without scanning.
    "system.automation.runspaces",                     // custom PS hosting (C#)
    "powershell.create().addscript(",                  // unmanaged PS host pattern
    "runspaceinvoke",                                  // simple runspace invocation
    "minishell",                                       // minimal PowerShell host

    // 4. AMSI bypass via COM hijack of AMSI provider CLSID
    //    Redirect our provider's InProcServer32 to a benign DLL so
    //    amsi.dll loads the wrong provider.
    "coregisterclassobject",                           // COM class registration override
    "corevokeclassobject",                             // COM class revocation

    // 5. AMSI bypass via Group Policy / registry disablement
    //    Already covered: "amsi\\featurebits" and "featurebits" in keyword list below.

    // 6. DotNetToJScript / GadgetToJScript — bypass AMSI by running
    //    .NET code via JScript/VBScript where AMSI coverage is weaker
    //    or absent (older engines).
    "dotnettojscript",                                 // tool name
    "gadgettojscript",                                 // tool name
    "starcommanddispatch",                             // DotNetToJScript helper class
    "d2fjscript",                                      // common abbreviation

    // 7. AMSI bypass via WMI/CIM — execute code via WMI which may not
    //    submit to AMSI (depends on provider and method).
    "invoke-wmimethod -class win32_process -name create",  // WMI process creation
    "invoke-cimmethod -classname win32_process",       // CIM process creation
    "gwmi -query",                                     // WMI query (lateral movement context)

    // 8. AMSI bypass via unregistering/replacing notification callback
    //    The AmsiNotificationCallback in the PEB can be nulled out.
    "amsinotificationcallback",                        // internal callback

    // 9. PowerShell transcription evasion (complementary to AMSI bypass)
    //    Disabling transcription hides activity even if AMSI is bypassed.
    "stop-transcript",                                 // stop active transcript
    "enabletranscripting",                             // GP key to disable transcription
    "invocationheader",                                // transcript header manipulation
    "protectedeventlogging",                           // disable protected event logging

    // 10. .NET profiler hijack to intercept AMSI calls
    //     COR_PROFILER can intercept JIT compilation including AMSI methods.
    //     Already covered: "cor_profiler_path", "cor_enable_profiling" in keyword list below.

    // 11. Patch AmsiScanBuffer caller (inside PowerShell engine)
    //     Instead of patching amsi.dll, patch the call site in
    //     System.Management.Automation.dll that invokes AmsiScanBuffer.
    "system.management.automation.dll",                // target DLL for caller-side patch
    "amsiutils.scanstring",                            // internal .NET method
    "amsiutils.scancontent",                           // internal .NET method
    "amsiutils.init",                                  // internal .NET method
    "amsiutils.amsiinitialized",                       // internal .NET field

    // 12. PSAmsiScanner / Test-Path AMSI probing
    //     Attackers probe whether AMSI is active before choosing bypass.
    "test-path variable:amsiinitfailed",               // probe amsiInitFailed variable
    "test-path variable:amsicontext",                  // probe amsiContext variable

    // ---------------------------------------------------------------
    // AMSI evasion via string obfuscation.
    // AMSI receives the source code, NOT the evaluated result, so
    // string concatenation/format-strings break keyword matching.
    // Detect the obfuscation patterns themselves as high-signal.
    // ---------------------------------------------------------------

    // PowerShell string concatenation splitting AMSI keywords
    "\"am\"+\"si\"",                      // "Am"+"si" (concatenation)
    "'am'+'si'",                          // 'Am'+'si' (single-quote concat)
    "\"amsi\"+\"utils\"",
    "'amsi'+'utils'",
    "\"amsi\"+\"scanbuffer\"",
    "\"amsi\"+\"opensession\"",
    "\"amsi\"+\"initialize\"",
    "\"ams\"+\"iinitialized\"",           // obfuscated amsiInitFailed variant
    "\"amsi\"+\"context\"",
    "\"amsiinit\"+\"failed\"",
    "'amsiinit'+'failed'",

    // PowerShell format-string operator (-f) constructing AMSI strings
    // "{0}{1}" -f "amsi","utils"  or  "{0}{1}" -f 'amsi','scanb'
    "\"-f 'amsi'\"",
    "\"-f \"amsi\"",
    "-f 'amsi','",
    "-f \"amsi\",\"",

    // PowerShell backtick insertion (tick marks break string matching)
    // e.g., A`m`s`i`U`t`i`l`s
    "a`m`s`i",
    "`a`m`s`i",
    "a`ms`i",
    "am`si",

    // [char] array / -join reconstruction
    // -join([char[]](65,109,115,105)) = "Amsi"
    // [char]0x41+[char]0x6d = "Am"
    "[char]65,[char]109,[char]115,[char]105",  // A,m,s,i decimal
    "[char]0x41,[char]0x6d,[char]0x73,[char]0x69",  // A,m,s,i hex
    "65,109,115,105",                          // bare AMSI char codes in array context
    "-join[char[]](65,",                       // -join with A(65) start
    "new-object string([char[]],",             // String([char[]],...) constructor

    // String .Replace() constructing AMSI keywords
    ".replace('",                              // any .Replace() call (broad signal)
    "\"amsi\".replace(",
    "replace('xx','si')",                      // common placeholder pattern
    "replace(\"xx\",\"si\")",

    // PowerShell Set-Variable / GV / SV indirection
    // Attackers store "amsi" in a variable, then reference it:
    //   set-variable -name a -value "amsi"; (gv a).value+"utils"
    "set-variable -name",                      // variable indirection primitive
    "(gv '",                                   // Get-Variable shorthand

    // Environment variable smuggling
    // $env:comspec[4,15,25]-join'' constructs strings from env var chars
    "$env:comspec[",
    "$env:psmodulepath[",
    "]-join''",
    "]-join\"\"",

    // XOR / byte-array deobfuscation near AMSI context
    "-bxor",                                   // PowerShell XOR operator
    "[system.runtime.interopservices.marshal]::ptrtostringauto",

    // AMSI attribute tampering references
    "amsi_attribute_content_size",
    "amsi_attribute_content_address",
    "amsi_attribute_content_name",
    "amsi_attribute_session",
    "amsi_attribute_app_name",
    "amsi_attribute_quiet",
    "getattribute(",                      // IAmsiStream::GetAttribute call
    "iamsistream",                        // IAmsiStream interface manipulation
    // AMSI internal COM method / vtable patching
    "camsiantimalware",
    "camsistream",
    "iamsiscan",                          // IAmsiStream interface
    "amsiscan(",                          // CAmsiAntimalware::Scan method reference
    "amsi!camsi",                         // WinDbg-style qualified method name
    "amsiantimalware::scan",              // class::method reference
    "vtable",                             // virtual method table manipulation
    "vftable",                            // MSVC vtable naming convention
    "amsi+0x",                            // amsi.dll offset reference for patching
    // Shellcode / loader patterns
    "virtualalloc",          // in script context
    "createthread",          // in script context
    "shellcode",
    "meterpreter",
    "cobaltstrike",
    // Network stager patterns
    "downloadstring(",
    "downloaddata(",
    "net.webclient",
    "wscript.shell",
    // ---------------------------------------------------------------
    // Web shell signatures — China Chopper, Godzilla, Behinder/Bingxie,
    // AntSword, and generic ASPX/JSP/PHP web shell patterns.
    // ---------------------------------------------------------------
    // China Chopper (classic one-liner web shell)
    "eval(request",                    // eval(Request.Item["..."])
    "eval(request.item",               // exact China Chopper pattern
    "execute(request(",                // ASP classic variant
    "eval request(",                   // VBScript variant
    "<%eval request",                  // raw ASP China Chopper
    "response.write(eval(",            // response eval variant
    // Godzilla web shell
    "gaborone",                        // Godzilla default session key
    "pass=",                           // Godzilla password parameter
    "javax.crypto.cipher",             // Godzilla Java AES encryption
    "aesencode",                       // Godzilla C# AES encryption helper
    "createaescipher",                 // Godzilla AES cipher creation
    // Behinder (Bingxie) web shell
    "behinder",                        // tool name reference
    "e45e329feb5d925b",                // Behinder default AES key MD5 prefix
    "javax.crypto.spec.secretkeyspec", // Behinder Java AES key spec
    "aes/ecb/pkcs5padding",            // Behinder AES mode (ECB is unusual)
    "classloader.defineclass",         // Behinder runtime class loading
    "assembly.load(convert.frombase64string", // Behinder .NET payload loading
    // AntSword web shell
    "antsword",                        // tool name reference
    "ant_",                            // AntSword default parameter prefix
    "asoutputstream",                  // AntSword Java output stream pattern
    "@eval(base64_decode(",            // AntSword PHP base64 eval
    "assert(base64_decode(",           // AntSword PHP assert variant
    // Generic web shell patterns
    "system.reflection.assembly.load", // .NET reflective assembly load (web shells)
    "processbuilder(",                 // Java command execution
    "runtime.getruntime().exec(",      // Java Runtime.exec
    "unsafe.eval(",                    // unsafe eval wrapper
    "frombase64string",                // base64 decode + assembly load combo
    "thread_start(system.delegate",    // .NET thread-based execution
    "httppostedfile",                  // file upload control (web shell dropper)
    "file_put_contents(",              // PHP file write (web shell dropper)
    "passthru(",                       // PHP command execution
    "system(",                         // PHP/Python command execution (in script context)
    "proc_open(",                      // PHP process execution
    "pcntl_exec(",                     // PHP direct exec
    // ---------------------------------------------------------------
    // Offensive C# tool namespace/class signatures — these appear in
    // the AMSI buffer when .NET assemblies are loaded via
    // Assembly.Load(byte[]) / execute-assembly.
    // ---------------------------------------------------------------
    "rubeus.commands",  "rubeus.lib.interop",
    "seatbelt.commands",  "seatbelt.runtime",
    "sharpup.checks",  "sharpup.utilities",
    "certify.commands",  "certify.domain",
    "sharpdpapi.commands",
    "sharphound.client",  "sharphound.collectors",
    "sharpview.functions",
    "sharpwmi.program",
    "sharpchrome.commands",
    "safetykatz.program",
    "sharpsploit.credentials",  "sharpsploit.execution",
    "sharpsploit.lateralmovement",  "sharpsploit.mimikatz",
    "grunt.gruntlauncher",  "covenant.models",
    "sharppersist.schtaskbackdoor",
    "inveigh.inveigh",  "inveigh.relay",
    "sharproast.program",
    "sharpsecdump.program",
    "sharpkatz.module",
    "whisker.commands",
    "standin.standin",
    "sharpgpoabuse.program",
    // ---------------------------------------------------------------
    // Adam Chester (@_xpn_) "Hiding Your .NET — ETW" techniques.
    // PowerShell/C# reflection patches against managed EventSource /
    // EventProvider private fields, and the EtwEventWrite prologue.
    // ---------------------------------------------------------------
    "m_eventsourceenabled",                  // EventSource private field nulled
    "m_eventpipeprovider",                   // EventPipe provider field
    "m_reghandle",                           // EventSource REGHANDLE nulled
    "etweventprovider",                      // internal framework class
    "eventsource.m_enabled",                 // qualified form
    "eventprovider.m_enabled",               // qualified form
    "getfield(\"m_eventsourceenabled\"",     // reflection lookup (double-quote)
    "getfield('m_eventsourceenabled'",       // reflection lookup (single-quote)
    "getfield(\"m_reghandle\"",
    "getfield('m_reghandle'",
    "getfield(\"etwprovider\"",              // static field lookup on EventPipe
    "getfield('etwprovider'",
    "nonpublic, instance",                   // reflection binding flags (frequent with field patch)
    "nonpublic,instance",                    // no-space variant
    "bindingflags.nonpublic",
    "[system.diagnostics.tracing.eventsource]",  // PS type cast used in PoC
    "system.diagnostics.tracing.eventprovider",  // internal type reference
    "\"etweventwrite\"",                     // GetProcAddress lookup in ntdll (double-quote)
    "'etweventwrite'",                       // single-quote variant
    "getprocaddress(getmodulehandle(\"ntdll",// precursor to EtwEventWrite patch
    "virtualprotect",                        // ntdll prologue patch (context + EtwEventWrite)
    "\\xc2\\x14\\x00",                       // RET 0x14 x64 patch bytes
    "\\xc3",                                 // bare RET patch (often quoted in PoC)
    "0xc3, 0x00",                            // RET sled form used in xpn gist

    // ---------------------------------------------------------------
    // PowerShell Empire / Starkiller agent + module identifiers.
    // Empire's PS agent is heavily obfuscated pre-AMSI but its module
    // output, tasking keywords, and staging-chain helpers are
    // plaintext after deobfuscation — and PowerShell re-submits the
    // deobfuscated buffer to AMSI for scanning.
    // ---------------------------------------------------------------
    // Stager chain (Base64 + XOR decode + IEX)
    "-bxor $key[$i % $key.length]",          // Empire stager XOR inner loop
    "-bxor $k[$i % $k.length]",              // shortened-variable variant
    "[system.text.encoding]::ascii.getstring([system.convert]::frombase64string",
    "[system.convert]::frombase64string($",  // stager entry point (short)
    "iex ([system.text.encoding]::utf8.getstring",
    "iex([system.text.encoding]::ascii.getstring",
    // Agent internals
    "$script:taskresults",                   // Empire agent tasking queue
    "$script:getdelegate",                   // Empire PS delegate resolver
    "$script:cliprecord",                    // Empire clipboard monitor field
    "$script:keystrokes",                    // Empire keylogger buffer
    "encrypt-bytes ",                        // Empire AES helper (narrow+space)
    "decrypt-bytes ",                        // Empire AES helper
    "create-aescipher",                      // Empire AES cipher factory
    // Tasking / module names (Empire 3/4 + Starkiller naming)
    "invoke-empire",
    "invoke-psinject",
    "psinject ",
    "invoke-dllinjection",
    "invoke-reflectivedllinjection",
    "invoke-tokenmanipulation",
    "invoke-credentialinjection",
    "invoke-runas",
    "invoke-ninjacopy",
    "invoke-ninja ",
    "invoke-sharefinder",
    "invoke-userhunter",
    "invoke-kerberoast",
    "invoke-mimikittenz",
    "invoke-wmiexec",
    "invoke-smbexec",
    "invoke-psexec",
    "invoke-dcsync",
    "invoke-inveigh",
    "invoke-portscan",
    "get-keystrokes",
    "get-timedscreenshot",
    "get-gpppassword",
    "get-pachashes",                         // Invoke-Mimikatz verb
    "find-avsignature",                      // PowerSploit persistence helper
    // Empire default HTTP routes / URIs (checkin + tasking)
    "/login/process.php",
    "/admin/get.php",
    "/admin/post.php",
    "/admin/controlpanel.php",
    "/news.php",
    "/news.asp",
    "/news/index.php",
    "/login.php?page=",
    // Starkiller (Empire 5) routes
    "/api/v2/agents/",
    "/api/v2/admin/",
    "/emp_agent",                            // Starkiller URI token
    // Empire default User-Agent (classic IE11 Win7 fingerprint)
    "mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0)",

    // ---------------------------------------------------------------------
    // Download cradles (T1059.001 / T1105). Canonical PS/JS/VBS shapes that
    // fetch a second-stage payload and feed it straight into an executor.
    // Lowercased; the keyword list is matched case-insensitively via the
    // pre-lowered content buffer in OnScanBuffer.
    // ---------------------------------------------------------------------
    // .NET WebClient / HttpClient cradles
    "(new-object net.webclient).downloadstring(",
    "(new-object system.net.webclient).downloadstring(",
    "(new-object net.webclient).downloaddata(",
    "(new-object net.webclient).downloadfile(",
    "(new-object system.net.http.httpclient).getstringasync(",
    "[system.net.webrequest]::create(",
    // PowerShell built-in cradles
    "invoke-webrequest -uri",
    "invoke-restmethod -uri",
    "iwr -uri",
    "irm -uri",
    "iwr http",
    "irm http",
    // COM XHR cradles (PowerShell, JScript, VBScript)
    "msxml2.xmlhttp",
    "msxml2.serverxmlhttp",
    "winhttp.winhttprequest.5.1",
    "new-object -comobject msxml2.xmlhttp",
    "new-object -com msxml2",
    "new-object -com winhttp",
    // BITS cradle
    "start-bitstransfer -source",
    "import-module bitstransfer",
    // LOLBin cradles
    "certutil -urlcache -split -f",
    "certutil.exe -urlcache -split -f",
    "certutil -urlcache -f http",
    "bitsadmin /transfer",
    "mshta http",
    "mshta vbscript:",
    "mshta javascript:",
    "regsvr32 /s /n /u /i:http",
    "rundll32 javascript:",
    "rundll32.exe javascript:",
    "rundll32 url.dll,openurl",
    "rundll32 url.dll,fileprotocolhandler",
    // curl/wget aliases + native
    "curl.exe -o",
    "curl.exe -fsslo",
    "curl -s http",
    "wget http",
    "curl http",
    // IEX chained onto a fetch
    "| iex",
    "|iex",
    "iex (iwr",
    "iex(iwr",
    "iex (new-object",
    "iex(new-object",
    "iex (invoke-webrequest",
    "iex ([system.text.encoding]",
    "iex([system.text.encoding]",
    // Reflective assembly loaded from URL-sourced bytes
    "[reflection.assembly]::load((new-object net.webclient).downloaddata",
    "[system.reflection.assembly]::load((new-object net.webclient).downloaddata",
    "[reflection.assembly]::load([convert]::frombase64string",
    // DNS cradle / exfil frameworks
    "invoke-dnsexfiltrator",
    "resolve-dnsname -type txt",
    // Python / WSL cradles
    "python -c \"import urllib",
    "python -c \"import requests",
    "python3 -c \"import urllib",
    "wsl -e curl",
    "wsl curl http",
    // Char-split obfuscated cradles (very common Empire/Invoke-Obfuscation shape)
    "\"downloads\"+\"tring\"",
    "\"download\"+\"string\"",
    "\"down\"+\"loadstring\"",
    "\"invoke\"+\"-expression\"",
    "\"i\"+\"ex\"",
    "downloadstring.invoke(",

    // ---------------------------------------------------------------------
    // VS Code tunnel / extension abuse (T1219.001 / T1059). Catches scripts
    // that automate tunnel setup, extension sideloading, or use the VS Code
    // Electron node.js escape to exec arbitrary code.
    // ---------------------------------------------------------------------
    "code.exe tunnel",
    "code tunnel --accept-server-license-terms",
    "code-tunnel",
    "devtunnel host",
    "code serve-web",
    "--install-extension",
    "--extensions-dir",
    "tunnel service install",
    "--ms-enable-electron-run-as-node",
    "vscode-remote://",
    ".vscode/tasks.json",
    "\"shellcommand\":",
    "\"prelaunchcommand\":",
    "tunnels.api.visualstudio.com",
    "global-relay.codedev.ms",
    ".devtunnels.ms",

    // AMSI provider enumeration / tampering (WhoAMSI technique)
    "\\microsoft\\amsi\\providers",
    "get-childitem \"hklm:\\software\\microsoft\\amsi",
    "reg query \"hklm\\software\\microsoft\\amsi",
    "remove-item \"hklm:\\software\\microsoft\\amsi",
    "reg delete \"hklm\\software\\microsoft\\amsi",
    "inprocserver32",

    // PowerShell Constrained Language Mode bypass
    "$executioncontext.sessionstate.languagemode",
    "fulllanguage",
    "constrainedlanguage",
    // PowerShell downgrade (v2 lacks AMSI/ScriptBlock logging)
    "powershell -version 2",
    "powershell.exe -version 2",
    "powershell -v 2",
    // Add-Type C# compilation (inline P/Invoke)
    "add-type -typedefinition",
    "add-type -memberdefinition",
    "[dllimport(",
    // Marshal / reflection interop
    "[system.runtime.interopservices.marshal]::",
    "getdelegateforfunctionpointer",
    "allochglobal",
    "structuretoptr",
    // WMI event subscription persistence
    "register-wmievent",
    "set-wmiinstance",
    "__eventfilter",
    "__eventconsumer",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "__filtertoconsumerbinding",
    // PS profile persistence
    "set-content $profile",
    "add-content $profile",
    "microsoft.powershell_profile.ps1",
    // Credential access
    "convertfrom-securestring",
    "[net.networkcredential]",
    "cmdkey /add",
    "vaultcmd /listcreds",
    "dpapi::masterkey",
    "dpapi::cred",
    // Registry persistence paths
    "currentversion\\run",
    "currentversion\\runonce",
    "userinitmprlogonscript",
    // Scheduled task creation
    "register-scheduledtask",
    "new-scheduledtaskaction",
    "schtasks /create",
    // PS logging evasion
    "psmoduleanalysiscachepath",
    "enablescriptblocklogging",
    "enablescriptblockinvocationlogging",

    // ---------------------------------------------------------------------
    // .NET malware techniques: unmanaged CLR hosting, LOLBin abuse,
    // runtime compilation, dynamic IL generation, GAC hijack, Donut
    // loader, AppDomainManager injection, COR_PROFILER, COM hijack.
    // ---------------------------------------------------------------------
    // Unmanaged CLR hosting
    "clrcreateinstance",
    "corbindtoruntimeex",
    "iclrruntimehost",
    "executeindefaultappdomain",
    "icorruntimehost",
    // .NET LOLBin indicators in script content
    "regsvcs.exe",
    "regasm.exe",
    "addinprocess.exe",
    "addinprocess32.exe",
    "installutil /logfile= /logtoconsole=false",
    // Runtime compilation from managed code
    "csharpcodeprovider",
    "compileassemblyfromsource",
    "codedomprovider",
    "generateinmemory",
    "microsoft.csharp.csharpcodeprovider",
    "system.codedom.compiler",
    // Dynamic type / IL generation
    "activator.createinstance(",
    "system.reflection.emit",
    "dynamicmethod(",
    "ilgenerator",
    "opcodes.calli",
    "definemethod(",
    "definetype(",
    // .NET assembly manipulation
    "dnlib.dotnet",
    "mono.cecil",
    // GAC hijack
    "gacutil /i",
    "\\assembly\\gac_msil\\",
    "\\assembly\\gac_64\\",
    // COR_PROFILER hijack
    "cor_enable_profiling",
    "cor_profiler_path",
    "coreclr_enable_profiling",
    "coreclr_profiler",
    // AppDomainManager injection
    "appdomainmanagerassembly",
    "appdomainmanagertype",
    // Donut loader signatures
    "donut_instance",
    "amsi_result_clean",
    // TypeConfuseDelegate
    "typeconfusedelegate",
    // COM hijack shim
    "inprocserver32",
    "mscoree.dll",

    // ---------------------------------------------------------------------
    // Malicious JavaScript / Windows Script Host (T1059.007 / T1059.005)
    // WSH COM objects, JScript obfuscation, Node.js abuse, dropper shapes.
    // ---------------------------------------------------------------------
    // WSH COM objects (classic JScript/VBScript malware primitives)
    "wscript.shell",
    "scripting.filesystemobject",
    "shell.application",
    "adodb.stream",
    ".savetofile",
    ".responsebody",
    ".responsetext",
    "wscript.network",
    "getobject(\"winmgmts:",
    "win32_process",
    "schedule.service",
    // MSScriptControl — COM script engine without spawning WSH
    "msscriptcontrol.scriptcontrol",
    "scriptcontrol.language",
    ".addcode(",
    ".executestatement(",
    // JScript obfuscation primitives
    "charcodeat(",
    "string.fromcharcode(",
    "fromcharcode(",
    "unescape(",
    "decodeuri(",
    "decodeuricomponent(",
    // Windows Script Encoder magic marker
    "#@~^",
    // WSH registry persistence
    ".regwrite(",
    ".regread(",
    ".regdelete(",
    // ShellExecute with "runas" (UAC bypass)
    "shellexecute",
    "\"runas\"",
    // Node.js abuse
    "child_process",
    "require(\"child_process\")",
    "require('child_process')",
    ".exec(",
    ".execsync(",
    ".spawn(",
    "preinstall",
    "postinstall",
    // WSF polyglot markers
    "<script language=\"jscript\"",
    "<script language=\"vbscript\"",
    "<script language=",
    // JScript.Encode / VBScript.Encode
    ".jse",
    ".vbe",
    "jscript.encode",
    "vbscript.encode",
    // WMI remote XSL
    "wmic /format:",
    "wmic process call create",

    // ---------------------------------------------------------------------
    // VBScript-specific malware techniques (T1059.005)
    // Runtime execution, obfuscation, DCOM lateral movement, class abuse.
    // ---------------------------------------------------------------------
    // VBScript runtime code execution (eval-equivalent)
    "executeglobal",
    "executeglobal(",
    "execute(",
    "execute request(",
    "execute(replace(",
    "getref(",
    // VBScript character/string obfuscation
    "chr(",
    "chrw(",
    "chrb(",
    "strreverse(",
    "clng(\"&h\"",
    // VBScript self-reference / self-deletion
    "wscript.scriptfullname",
    "wscript.scriptname",
    "deletefile(wscript.",
    // VBScript sandbox evasion
    "wscript.sleep(",
    "wscript.arguments",
    // InternetExplorer.Application COM (hidden IE for HTTP)
    "internetexplorer.application",
    // DCOM lateral movement objects
    "mmc20.application",
    "shellbrowserwindow",
    "shellwindows",
    // MSXML2.DOMDocument Base64 decode
    "msxml2.domdocument",
    "nodetypedvalue",
    // VBScript class auto-execution
    "class_initialize",
    "class_terminate",

    // ---------------------------------------------------------------------
    // VBA macro malware techniques (T1059.005 / T1137)
    // Callbacks, anti-analysis, DDE, self-modification, persistence.
    // ---------------------------------------------------------------------
    // VBA callback / delayed execution
    "application.ontime",
    "application.onkey",
    // VBA anti-analysis
    "application.enableevents = false",
    "application.screenupdating = false",
    "application.displayalerts = false",
    "application.username",
    // VBA programmatic DDE
    "ddeinitiate",
    "ddeexecute",
    "ddepoke",
    // VBA self-modification
    "vbproject.vbcomponents",
    "vbcomponents.add",
    "codemodule.insertlines",
    "codemodule.addfrombuffer",
    "codemodule.deletelines",
    // VBA keystroke injection
    "sendkeys",
    // VBA persistence
    "savesetting",
    "getsetting",
    "application.macrooptions",
    // VBA Declare aliasing / Win32 API obfuscation
    "declare ptrsafe function",
    "declare function",
    "declare ptrsafe sub",
    "declare sub",
    "alias \"",
    // Additional dangerous Win32 APIs from VBA Declare
    "getprocaddress",
    "getmodulehandle",
    "loadlibrarya",
    "loadlibraryw",
    "gettickcount",
    "createprocessa",
    "createprocessw",
    "setfiletime",
    "regopenkeyex",
    "regsetvalueex",
    "callwindowproc",
    // VBA encoding / decoding
    "strconv(",
    "strreverse(",
    // VBA ActiveX control events (auto-exec)
    "webbrowser_documentcomplete",

    // ---------------------------------------------------------------------
    // UAC bypass techniques (T1548.002)
    // Registry handler hijack, COM CLSID abuse, env var hijack, policy.
    // ---------------------------------------------------------------------
    // AMSI tampering (T1562.001)
    "amsi\\featurebits",
    "\\microsoft\\amsi",
    "featurebits",
    "amsiscanbuffer",
    "amsiscanstring",
    "amsiopensession",
    "amsiinitfailed",
    "amsi.dll",
    "setdlldirectory",
    "adddlldirectory",
    // WLDP bypass (T1553)
    "wldpquerydynamiccodetrust",
    "wldpisclassinapprovedlist",
    "wldp.dll",
    // SIP / Trust provider hijack (T1553.003)
    "cryptsipdll",
    "cryptsipdllverifyindirectdata",
    "cryptsipdllgetsigneddatamsg",
    "\\cryptography\\oid\\",
    "winverifytrust",
    "wintrust.dll",
    // Certificate store manipulation (T1553.004)
    "certutil -addstore root",
    "certutil -addstore trustedpublisher",
    "certutil -delstore",
    "certutil -importpfx",
    "import-certificate",
    "\\systemcertificates\\root",
    "\\systemcertificates\\trustedpublisher",
    "\\systemcertificates\\disallowed",
    // Catalog tampering
    "cryptcatadmin",
    // Code Integrity / Device Guard
    "bcdedit /set nointegritychecks",
    "bcdedit /set testsigning",
    "bcdedit /set hypervisorlaunchtype off",
    "ci.dll",
    "set-ruleoption",
    // HKCU class handler hijack (auto-elevate abuse)
    "ms-settings\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
    "exefile\\shell\\open\\command",
    "shell\\open\\command",
    "delegateexecute",
    // Environment variable UAC bypass
    "\\environment\\windir",
    "\\environment\\systemroot",
    // COM object UAC bypass
    "{3e5fc7f9-9a51-4367-9063-a120244fbec7}",
    "cmstplua",
    "icmluautil",
    "{d2e7025f-8b69-4ae6-a3b1-c2bc0f92a3b2}",
    "colordataproxy",
    // UAC policy tampering
    "enablelua",
    "consentpromptbehavioradmin",
    "promptonsecuredesktop",
    // Auto-elevating binary invocations from script
    "fodhelper.exe",
    "wsreset.exe",
    "computerdefaults.exe",
    "changepk.exe",
    "silentcleanup",
    // Token manipulation
    "createprocesswithtokenw",
    "createprocesswithlogonw",
    "ntsetinformationtoken",
    // Trusted directory DLL hijack
    "windows \\system32",

    // ---------------------------------------------------------------------
    // Windows Script Host infrastructure abuse (T1059.005 / T1059.007)
    // COM scriptlets, monikers, WshController, remote DCOM, policy tamper.
    // ---------------------------------------------------------------------
    // COM scriptlets (.sct / .wsc)
    ".sct",
    ".wsc",
    "scrobj.dll",
    "<scriptlet>",
    "<registration",
    "getobject(\"script:",
    "getobject(\"script:http",
    // WSH remote execution
    "wshcontroller",
    "wshremote",
    "createscript(",
    "wscript.connectobject",
    "wscript.disconnectobject",
    // WSH flag abuse
    "//h:cscript",
    "//h:wscript",
    "//job:",
    "wscript.timeout",
    // Remote DCOM / WMI
    "getobject(\"new:",
    "winmgmts:\\\\",
    "\\root\\cimv2",
    // WSH network
    "wscript.network",
    ".mapnetworkdrive(",
    // WSH policy tampering
    "windows script host\\settings",
    "trustpolicy",

    // ---------------------------------------------------------------------
    // Fileless / in-memory-only script execution primitives. These are the
    // PowerShell Runtime API shapes that let script source live as a string
    // inside the host process and be executed without ever hitting disk,
    // scriptblock cache, or MOTW. Benign uses exist (module authors, DSC,
    // remoting) but combined with AMSI-buffer context these are high-signal.
    // ---------------------------------------------------------------------
    "[scriptblock]::create(",
    "[system.management.automation.scriptblock]::create(",
    "$executioncontext.invokecommand.invokescript(",
    "$executioncontext.invokecommand.newscriptblock(",
    "$executioncontext.sessionstate.invokecommand.invokescript(",
    ".invokecommand.invokescript(",
    ".newscriptblock(",
    "[powershell]::create()",
    "[system.management.automation.powershell]::create()",
    ".addscript(",
    ".addcommand(",
    "[runspacefactory]::createrunspace",
    "[runspacefactory]::createrunspacepool",
    "$runspace.open()",
    "invoke-command -scriptblock",
    "invoke-asbuiltreport",
    "scriptblockast",
    "[parser]::parseinput(",
    "parseinput(",
    // Rebuilt-from-bytes script (common Cobalt Strike PS profile shape)
    "[system.text.encoding]::unicode.getstring([convert]::frombase64string",
    "[system.text.encoding]::utf8.getstring([convert]::frombase64string",
    "[system.text.encoding]::ascii.getstring([convert]::frombase64string",
    // Assembly.Load of current-process-only byte buffer (fileless .NET)
    "[appdomain]::currentdomain.load(",
    "[appdomain]::currentdomain.getassemblies()",
    "getmodulehandle(\"amsi.dll\")",
    "getprocaddress.invoke(",
    // IEX-of-a-variable — payload lives in $s / $a / $x before exec
    "iex $",
    "invoke-expression $",
    "& ([scriptblock]::create(",
    ". ([scriptblock]::create(",

    nullptr
};

// ---------------------------------------------------------------------------
// Log a detection event to a file alongside the EDR binary
// ---------------------------------------------------------------------------
static void LogDetection(const wchar_t* contentName, const char* keyword) {
    FILE* f = nullptr;
    if (fopen_s(&f, "norton_amsi_detections.log", "a") != 0 || !f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f,
        "[%04d-%02d-%02d %02d:%02d:%02d] DETECTED keyword=\"%s\" content=\"%ls\"\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        keyword,
        contentName ? contentName : L"<unknown>");
    fclose(f);
}

// ---------------------------------------------------------------------------
// NortonAmsiProvider — IUnknown
// ---------------------------------------------------------------------------
NortonAmsiProvider::NortonAmsiProvider() : m_refCount(1) {
    InterlockedIncrement(&g_objectCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProvider::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProvider::Release() {
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) {
        InterlockedDecrement(&g_objectCount);
        delete this;
    }
    return ref;
}

STDMETHODIMP NortonAmsiProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// ---------------------------------------------------------------------------
// NortonAmsiProvider::Scan — core detection logic
// ---------------------------------------------------------------------------
STDMETHODIMP NortonAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_CLEAN;

    // -------------------------------------------------------------------
    // Self-integrity verification.
    //
    // Because our provider DLL is mapped into the attacker's process,
    // they can patch our Scan() prologue (NOP/RET), redirect our COM
    // vtable, zero our keyword table, or hook our IAT entries.
    //
    // On first call: capture baselines from the live vtable.
    // On every call: verify nothing has been tampered with.
    // If tampered: report DETECTED (the scan result itself is untrusted
    // but AMSI will still see our verdict before the patched path runs).
    // -------------------------------------------------------------------
    if (!g_IntegrityBaselineValid) {
        CaptureIntegrityBaseline(this);
    }
    // Capture keyword canary on first Scan() call (kMaliciousKeywords is
    // defined in this TU after the integrity functions, so we do it here).
    if (!g_KeywordCanaryValid && kMaliciousKeywords[0] != nullptr) {
        g_KeywordCanaryPtr = kMaliciousKeywords[0];
        g_KeywordCanaryLen = static_cast<ULONG>(
            min(strlen(g_KeywordCanaryPtr), (size_t)sizeof(g_KeywordCanaryBytes)));
        memcpy(g_KeywordCanaryBytes, g_KeywordCanaryPtr, g_KeywordCanaryLen);
        g_KeywordCanaryValid = true;
    }
    if (g_IntegrityBaselineValid) {
        if (CheckSelfIntegrity(this)) {
            *result = AMSI_RESULT_DETECTED;
            return S_OK;
        }
    }

    try {
        // -------------------------------------------------------------------
        // AMSI_ATTRIBUTE validation & cross-checks.
        //
        // Attackers tamper with IAmsiStream attributes to blind providers:
        //   - Zero CONTENT_SIZE so providers skip scanning
        //   - Redirect CONTENT_ADDRESS to a benign decoy buffer
        //   - Truncate CONTENT_SIZE to hide the payload past the first N bytes
        //   - Patch IAmsiStream vtable to return forged attribute values
        //
        // Defense: cross-validate attributes against IAmsiStream::Read(),
        // detect zero-size from live script engines, verify address/read
        // content consistency.
        // -------------------------------------------------------------------

        // Retrieve content size
        ULONGLONG contentSize = 0;
        ULONG returned = 0;
        HRESULT hr = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_SIZE,
            sizeof(contentSize), (BYTE*)&contentSize, &returned);

        // --- Tamper check 1: zero-size from active script engine ---
        // If CONTENT_SIZE is 0 or unavailable, check if APP_NAME is present.
        // A live script engine (powershell.exe, cscript.exe, etc.) should
        // never submit zero-size content — this indicates attribute tampering.
        if (FAILED(hr) || returned < sizeof(contentSize) || contentSize == 0) {
            WCHAR appNameBuf[256] = {};
            ULONG appNameRet = 0;
            HRESULT appHr = stream->GetAttribute(
                AMSI_ATTRIBUTE_APP_NAME,
                sizeof(appNameBuf), (BYTE*)appNameBuf, &appNameRet);

            if (SUCCEEDED(appHr) && appNameRet > 0 && appNameBuf[0] != L'\0') {
                // APP_NAME is present but CONTENT_SIZE is 0 — suspicious.
                // A legitimate empty submission (e.g., blank line) would still
                // have a valid size.  Attribute tampering detected.
                LogDetection(appNameBuf, "[TAMPER] AMSI_ATTRIBUTE_CONTENT_SIZE=0 from active app");
                *result = AMSI_RESULT_DETECTED;
                return S_OK;
            }
            return S_OK;  // genuinely empty or no app context
        }

        // Cap to 8 MB to bound scan time
        if (contentSize > 8ULL * 1024 * 1024)
            contentSize = 8ULL * 1024 * 1024;

        // --- Tamper check 2: suspiciously small CONTENT_SIZE ---
        // Script engines almost never submit 1-3 byte content. If the size
        // is implausibly small, probe via Read() for the real content.
        ULONGLONG reportedSize = contentSize;

        // Try to get a direct pointer to the content
        ULONG_PTR contentAddr = 0;
        hr = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_ADDRESS,
            sizeof(contentAddr), (BYTE*)&contentAddr, &returned);

        std::vector<BYTE> readBuf;
        const BYTE* bytes = nullptr;
        ULONG byteCount = 0;

        if (SUCCEEDED(hr) && contentAddr != 0) {
            // --- Tamper check 3: cross-validate CONTENT_ADDRESS vs Read() ---
            // If both methods are available, compare the first 64 bytes.
            // A mismatch means CONTENT_ADDRESS was redirected to a decoy buffer.
            BYTE readProbe[64] = {};
            ULONG readProbeSize = 0;
            HRESULT readHr = stream->Read(0, sizeof(readProbe), readProbe, &readProbeSize);

            if (SUCCEEDED(readHr) && readProbeSize > 0) {
                const BYTE* addrBytes = reinterpret_cast<const BYTE*>(contentAddr);
                ULONG cmpLen = min(readProbeSize, (ULONG)sizeof(readProbe));
                bool mismatch = false;

                __try {
                    for (ULONG i = 0; i < cmpLen; i++) {
                        if (addrBytes[i] != readProbe[i]) {
                            mismatch = true;
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // CONTENT_ADDRESS points to invalid memory — tampered
                    mismatch = true;
                }

                if (mismatch) {
                    // CONTENT_ADDRESS and Read() return different data.
                    // Attackers patched the address to point to a decoy buffer.
                    LogDetection(nullptr,
                        "[TAMPER] AMSI_ATTRIBUTE_CONTENT_ADDRESS diverges from Read() — decoy buffer");
                    *result = AMSI_RESULT_DETECTED;

                    // Use Read() data as the real content for further scanning
                    readBuf.resize(static_cast<size_t>(contentSize));
                    ULONG readSize = 0;
                    stream->Read(0, static_cast<ULONG>(contentSize), readBuf.data(), &readSize);
                    if (readSize > 0) {
                        bytes     = readBuf.data();
                        byteCount = readSize;
                    } else {
                        return S_OK;
                    }
                } else {
                    bytes     = reinterpret_cast<const BYTE*>(contentAddr);
                    byteCount = static_cast<ULONG>(contentSize);
                }

                // --- Tamper check 4: CONTENT_SIZE truncation ---
                // If Read() returned more data than CONTENT_SIZE claims,
                // the size attribute was truncated to hide the payload.
                if (SUCCEEDED(readHr) && readProbeSize > 0 &&
                    reportedSize < 64 && readProbeSize > reportedSize)
                {
                    LogDetection(nullptr,
                        "[TAMPER] AMSI_ATTRIBUTE_CONTENT_SIZE truncated — "
                        "Read() has more data than reported size");
                    *result = AMSI_RESULT_DETECTED;

                    // Re-read with the full probe size to scan the real content
                    readBuf.resize(static_cast<size_t>(8ULL * 1024 * 1024));
                    ULONG fullRead = 0;
                    stream->Read(0, static_cast<ULONG>(readBuf.size()),
                                 readBuf.data(), &fullRead);
                    if (fullRead > byteCount) {
                        bytes     = readBuf.data();
                        byteCount = fullRead;
                    }
                }
            } else {
                // Read() failed but CONTENT_ADDRESS succeeded — use address
                bytes     = reinterpret_cast<const BYTE*>(contentAddr);
                byteCount = static_cast<ULONG>(contentSize);
            }
        } else {
            // CONTENT_ADDRESS unavailable — fall back to IAmsiStream::Read
            readBuf.resize(static_cast<size_t>(contentSize));
            ULONG readSize = 0;
            hr = stream->Read(0, static_cast<ULONG>(contentSize), readBuf.data(), &readSize);
            if (FAILED(hr) || readSize == 0) return S_OK;
            bytes     = readBuf.data();
            byteCount = readSize;
        }

        // Build a lowercase searchable string.
        // Handle both wide (UTF-16 LE) and narrow (ANSI/UTF-8) content.
        // Heuristic: if the second byte is NUL, treat as wide.
        std::string searchable;
        searchable.reserve(byteCount);

        bool isWide = (byteCount >= 2 && bytes[1] == 0);
        if (isWide) {
            const wchar_t* wptr = reinterpret_cast<const wchar_t*>(bytes);
            ULONG wlen = byteCount / 2;
            for (ULONG i = 0; i < wlen; i++) {
                wchar_t wc = wptr[i];
                searchable += (wc < 0x80)
                    ? static_cast<char>(tolower(static_cast<unsigned char>(wc)))
                    : '?';
            }
        } else {
            for (ULONG i = 0; i < byteCount; i++) {
                searchable += static_cast<char>(tolower(static_cast<unsigned char>(bytes[i])));
            }
        }

        // Scan for malicious keywords
        const char* hitKeyword = nullptr;
        for (int i = 0; kMaliciousKeywords[i]; i++) {
            if (searchable.find(kMaliciousKeywords[i]) != std::string::npos) {
                hitKeyword = kMaliciousKeywords[i];
                break;
            }
        }

        if (hitKeyword) {
            *result = AMSI_RESULT_DETECTED;

            // Get content name for logging
            PWSTR contentName = nullptr;
            ULONG nameRet = 0;
            stream->GetAttribute(
                AMSI_ATTRIBUTE_CONTENT_NAME,
                sizeof(contentName), (BYTE*)&contentName, &nameRet);

            LogDetection(contentName, hitKeyword);
        }
    }
    catch (...) {
        // Never crash the host process
    }

    return S_OK;
}

STDMETHODIMP_(void) NortonAmsiProvider::CloseSession(ULONGLONG /*session*/) {}

STDMETHODIMP NortonAmsiProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_INVALIDARG;
    const wchar_t* name = L"NortonAntivirusNextGenEDR";
    size_t len = wcslen(name) + 1;
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
    if (!*displayName) return E_OUTOFMEMORY;
    wcscpy_s(*displayName, len, name);
    return S_OK;
}

// ---------------------------------------------------------------------------
// NortonAmsiProviderFactory — IClassFactory
// ---------------------------------------------------------------------------
NortonAmsiProviderFactory::NortonAmsiProviderFactory() : m_refCount(1) {}

STDMETHODIMP_(ULONG) NortonAmsiProviderFactory::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProviderFactory::Release() {
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) delete this;
    return ref;
}

STDMETHODIMP NortonAmsiProviderFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

STDMETHODIMP NortonAmsiProviderFactory::CreateInstance(
    IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;

    NortonAmsiProvider* provider = new (std::nothrow) NortonAmsiProvider();
    if (!provider) return E_OUTOFMEMORY;

    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();
    return hr;
}

STDMETHODIMP NortonAmsiProviderFactory::LockServer(BOOL fLock) {
    if (fLock) InterlockedIncrement(&g_lockCount);
    else       InterlockedDecrement(&g_lockCount);
    return S_OK;
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_hModule = hinstDLL;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// COM exports
// ---------------------------------------------------------------------------
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_NortonAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;

    NortonAmsiProviderFactory* factory =
        new (std::nothrow) NortonAmsiProviderFactory();
    if (!factory) return E_OUTOFMEMORY;

    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return (g_lockCount == 0 && g_objectCount == 0) ? S_OK : S_FALSE;
}

// ---------------------------------------------------------------------------
// Self-registration helpers
// ---------------------------------------------------------------------------
static LONG WriteRegSz(HKEY root, const wchar_t* path, const wchar_t* name,
                        const wchar_t* value) {
    HKEY hKey = nullptr;
    LONG r = RegCreateKeyExW(root, path, 0, nullptr, REG_OPTION_NON_VOLATILE,
                             KEY_WRITE, nullptr, &hKey, nullptr);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(hKey, name, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(value),
                       static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return r;
}

STDAPI DllRegisterServer() {
    WCHAR dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    // HKLM\SOFTWARE\Classes\CLSID\{...}\InProcServer32 = <path>
    WCHAR keyPath[300];
    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32", kProviderClsidStr);

    LONG r = WriteRegSz(HKEY_LOCAL_MACHINE, keyPath, nullptr, dllPath);
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);

    r = WriteRegSz(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);

    // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{...}
    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", kProviderClsidStr);

    HKEY hKey = nullptr;
    r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &hKey, nullptr);
    if (r == ERROR_SUCCESS) RegCloseKey(hKey);

    return S_OK;
}

STDAPI DllUnregisterServer() {
    WCHAR keyPath[300];

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    return S_OK;
}
