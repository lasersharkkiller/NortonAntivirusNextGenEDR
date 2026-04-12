#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <winreg.h>
// wincrypt.h types used in CRYPT32 hooks — defined as opaque pointers to avoid
// WIN32_LEAN_AND_MEAN / include-order conflicts with the full wincrypt.h header.
typedef void*       HCERTSTORE_OPAQUE;
typedef const void* PCCERT_CONTEXT_OPAQUE;
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")

#define HOOKDLL_EXPORTS
#include "HookDll.h"

// ---------------------------------------------------------------------------
// Pipe IPC — sends telemetry lines to the NortonEDR pipe server.
// Line format: SEVERITY\tCALLER_PID\tAPI_NAME\tTARGET_PID\tDETAIL\n
// ---------------------------------------------------------------------------

static HANDLE           g_pipe     = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeLock;
static DWORD            g_selfPid  = 0;
static bool             g_lockInit = false;

static void ConnectToPipe() {
    if (!WaitNamedPipeA("\\\\.\\pipe\\NortonEDR_HookDll", 2000)) return;
    g_pipe = CreateFileA("\\\\.\\pipe\\NortonEDR_HookDll",
        GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_pipe == INVALID_HANDLE_VALUE) g_pipe = INVALID_HANDLE_VALUE;
}

static void SendHookEvent(
    const char* severity, const char* apiName,
    DWORD targetPid, const char* detail)
{
    if (g_pipe == INVALID_HANDLE_VALUE || !g_lockInit) return;
    char buf[512];
    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%s\t%lu\t%s\t%lu\t%s\n",
        severity, g_selfPid, apiName, targetPid, detail);
    if (len <= 0) return;
    EnterCriticalSection(&g_pipeLock);
    DWORD written = 0;
    WriteFile(g_pipe, buf, (DWORD)len, &written, nullptr);
    LeaveCriticalSection(&g_pipeLock);
}

// ---------------------------------------------------------------------------
// Hook table
// ---------------------------------------------------------------------------

enum HookIdx : int {
    IDX_VIRTUALALLOC          = 0,
    IDX_VIRTUALALLOCEX        = 1,
    IDX_WRITEPROCESSMEMORY    = 2,
    IDX_CREATEREMOTETHREAD    = 3,
    IDX_CREATEREMOTETHREADEX  = 4,
    IDX_LOADLIBRARYA          = 5,
    IDX_LOADLIBRARYW          = 6,
    IDX_LOADLIBRARYEXA        = 7,
    IDX_LOADLIBRARYEXW        = 8,
    IDX_RESUMETHREAD          = 9,
    IDX_SETTHREADCONTEXT      = 10,
    IDX_REGSETVALUEEX_A       = 11,
    IDX_REGSETVALUEEX_W       = 12,
    IDX_READPROCESSMEMORY     = 13,  // deception: post-read LSASS buffer patching
    IDX_NTQUERYSYSTEMINFO     = 14,  // deception: hide EDR, inject decoy process
    // --- Evasion-path execution triggers ---
    IDX_CREATETHREAD          = 15,  // local thread with non-module start address
    IDX_MAPVIEWOFFILE         = 16,  // file-backed section mapped executable
    IDX_REGISTERCLASSEXA      = 17,  // WndProc shellcode dispatch (window message)
    IDX_REGISTERCLASSEXW      = 18,
    IDX_ENUMSYSTEMLOCALESA    = 19,  // callback abuse
    IDX_ENUMSYSLANGGRPA       = 20,  // callback abuse — rarity score 100 in malware set
    IDX_ENUMWINDOWS           = 21,  // callback abuse
    IDX_ENUMCHILDWINDOWS      = 22,  // callback abuse
    IDX_SETTIMER              = 23,  // timer callback execution
    IDX_SETWAITABLETIMER      = 24,  // timer callback execution
    IDX_CREATETIMERQUEUETIMER  = 25,  // timer callback execution
    // --- Category 1 additions from differential analysis ---
    IDX_OPENPROCESS            = 26,  // injection precursor — log target PID
    IDX_VIRTUALPROTECT         = 27,  // RWX page marking (shellcode staging)
    IDX_CREATEFILEMAPPINGW     = 28,  // section creation for module stomping
    IDX_CREATEFILEMAPPINGA     = 29,
    IDX_ENUMSYSTEMLOCALESW     = 30,  // W variant callback abuse
    IDX_CALLWINDOWPROCA        = 31,  // WndProc dispatch callback abuse
    IDX_CALLWINDOWPROCW        = 32,
    IDX_ENUMTHREADWINDOWS      = 33,  // callback abuse
    IDX_CONVERTTHREADTOFIBER   = 34,  // fiber-based shellcode execution
    IDX_CREATEFIBER            = 35,
    IDX_SWITCHTOFIBER          = 36,
    IDX_RTLCREATEUSERTHREAD    = 37,  // direct user-mode thread (ntdll, bypasses CreateThread)
    IDX_CREATEWAITABLETIMEREXW  = 38,  // timer variant missed in first pass
    // --- Gap closure: window WndProc hijack + CRYPT32 callback abuse ---
    IDX_SETWINDOWLONGPTRA       = 39,  // post-creation WndProc replacement (Path B window msgs)
    IDX_SETWINDOWLONGPTRW       = 40,
    IDX_CERTENUMCERTIFICATES    = 41,  // CRYPT32 callback abuse (score 94, mal 27)
    IDX_CERTFINDCERTIFICATE     = 42,  // CRYPT32 callback abuse (score 94, mal 24)
    // --- VEH hooking bypass: shellcode registered as vectored exception handler ---
    IDX_ADDVECTOREDEXCEPTIONHANDLER   = 43,  // kernel32.dll (thunks to ntdll)
    IDX_ADDVECTOREDCONTINUEHANDLER    = 44,  // kernel32.dll
    IDX_RTLADDVECTOREDEXCEPTIONHANDLER = 45, // ntdll.dll — direct call path
    IDX_RTLADDVECTOREDCONTINUEHANDLER  = 46, // ntdll.dll — direct call path
    // --- Authentication downgrade detection: SSPI hooks ---
    IDX_INITIALIZESECURITYCONTEXTW     = 47, // sspicli.dll — Negotiate→NTLM fallback
    IDX_ACQUIRECREDENTIALSHANDLEW      = 48, // sspicli.dll — explicit NTLM/WDigest credential acquisition
    // --- Sleep obfuscation detection ---
    IDX_SYSTEMFUNCTION032              = 49, // advapi32.dll — RC4 encrypt used by Ekko/Foliage
    // --- DPAPI credential harvesting ---
    IDX_CRYPTUNPROTECTDATA             = 50, // crypt32.dll — DPAPI decryption
    // --- Process Ghosting / Transacted Hollowing ---
    IDX_NTSETINFORMATIONFILE           = 51, // ntdll.dll — FileDispositionInformation (delete-pending)
    IDX_NTCREATETRANSACTION            = 52, // ntdll.dll — TxF for transacted hollowing
    HOOK_COUNT                  = 53
};

struct ApiHook {
    const char* modName;    // lowercase, e.g. "kernel32.dll"
    const char* funcName;
    FARPROC     hookFn;

    // IAT patching
    FARPROC     original;   // original IAT slot value

    // Inline hook + trampoline
    BYTE*       inlineTarget;   // address of the patched function prologue
    BYTE        savedBytes[16]; // copy of overwritten prologue bytes
    FARPROC     trampoline;     // executable stub: savedBytes + JMP back
    bool        inlinePatched;
};

// Forward declarations of hook stubs
static LPVOID  WINAPI Hook_VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
static LPVOID  WINAPI Hook_VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static BOOL    WINAPI Hook_WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
static HANDLE  WINAPI Hook_CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static HANDLE  WINAPI Hook_CreateRemoteThreadEx(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                 LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                                 LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR);
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR);
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR, HANDLE, DWORD);
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
static DWORD   WINAPI Hook_ResumeThread(HANDLE);
static BOOL    WINAPI Hook_SetThreadContext(HANDLE, const CONTEXT*);
static LONG    WINAPI Hook_RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
static LONG    WINAPI Hook_RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static BOOL    WINAPI Hook_ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
static BOOL    WINAPI Hook_NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
static HANDLE  WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static LPVOID  WINAPI Hook_MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static ATOM    WINAPI Hook_RegisterClassExA(const WNDCLASSEXA*);
static ATOM    WINAPI Hook_RegisterClassExW(const WNDCLASSEXW*);
static BOOL    WINAPI Hook_EnumSystemLocalesA(LOCALE_ENUMPROCA, DWORD);
static BOOL    WINAPI Hook_EnumSystemLanguageGroupsA(LANGUAGEGROUP_ENUMPROCA, DWORD, LONG_PTR);
static BOOL    WINAPI Hook_EnumWindows(WNDENUMPROC, LPARAM);
static BOOL    WINAPI Hook_EnumChildWindows(HWND, WNDENUMPROC, LPARAM);
static UINT_PTR WINAPI Hook_SetTimer(HWND, UINT_PTR, UINT, TIMERPROC);
static BOOL    WINAPI Hook_SetWaitableTimer(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, PVOID, BOOL);
static BOOL    WINAPI Hook_CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
static HANDLE  WINAPI Hook_OpenProcess(DWORD, BOOL, DWORD);
static BOOL    WINAPI Hook_VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
static HANDLE  WINAPI Hook_CreateFileMappingW(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
static HANDLE  WINAPI Hook_CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
static BOOL    WINAPI Hook_EnumSystemLocalesW(LOCALE_ENUMPROCW, DWORD);
static LRESULT WINAPI Hook_CallWindowProcA(WNDPROC, HWND, UINT, WPARAM, LPARAM);
static LRESULT WINAPI Hook_CallWindowProcW(WNDPROC, HWND, UINT, WPARAM, LPARAM);
static BOOL    WINAPI Hook_EnumThreadWindows(DWORD, WNDENUMPROC, LPARAM);
static LPVOID  WINAPI Hook_ConvertThreadToFiber(LPVOID);
static LPVOID  WINAPI Hook_CreateFiber(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
static VOID    WINAPI Hook_SwitchToFiber(LPVOID);
static NTSTATUS NTAPI Hook_RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
                                               SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);
static HANDLE  WINAPI Hook_CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
static LONG_PTR WINAPI Hook_SetWindowLongPtrA(HWND, int, LONG_PTR);
static LONG_PTR WINAPI Hook_SetWindowLongPtrW(HWND, int, LONG_PTR);
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertFindCertificateInStore(HCERTSTORE_OPAQUE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT_OPAQUE);
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertEnumCertificatesInStore(HCERTSTORE_OPAQUE, PCCERT_CONTEXT_OPAQUE);
static PVOID   WINAPI Hook_AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   WINAPI Hook_AddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   NTAPI  Hook_RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   NTAPI  Hook_RtlAddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
// SSPI authentication downgrade hooks
typedef void* PCtxtHandle;
typedef void* PCredHandle;
typedef void* PSecBufferDesc;
// DPAPI hook — CryptUnprotectData uses DATA_BLOB structures
typedef struct { DWORD cbData; BYTE* pbData; } HOOK_DATA_BLOB;
// SystemFunction032 — RC4 encryption (sleep obfuscation)
typedef struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } USTRING;
static LONG  WINAPI Hook_InitializeSecurityContextW(
    PCredHandle, PCtxtHandle, wchar_t*, ULONG, ULONG, ULONG,
    PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, ULONG*, PLARGE_INTEGER);
static LONG  WINAPI Hook_AcquireCredentialsHandleW(
    wchar_t*, wchar_t*, ULONG, PVOID, PVOID, PVOID, PVOID, PCredHandle, PLARGE_INTEGER);
// Sleep obfuscation
static NTSTATUS WINAPI Hook_SystemFunction032(USTRING* data, USTRING* key);
// DPAPI credential harvesting
static BOOL WINAPI Hook_CryptUnprotectData(
    HOOK_DATA_BLOB*, wchar_t**, HOOK_DATA_BLOB*, PVOID, PVOID, DWORD, HOOK_DATA_BLOB*);
// Process Ghosting / Transacted Hollowing
static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE, PVOID, PVOID, ULONG, ULONG);
static NTSTATUS NTAPI Hook_NtCreateTransaction(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PVOID);

static ApiHook g_hooks[HOOK_COUNT] = {
    { "kernel32.dll", "VirtualAlloc",         (FARPROC)Hook_VirtualAlloc,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "VirtualAllocEx",       (FARPROC)Hook_VirtualAllocEx,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "WriteProcessMemory",   (FARPROC)Hook_WriteProcessMemory,  nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateRemoteThread",   (FARPROC)Hook_CreateRemoteThread,  nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateRemoteThreadEx", (FARPROC)Hook_CreateRemoteThreadEx,nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryA",         (FARPROC)Hook_LoadLibraryA,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryW",         (FARPROC)Hook_LoadLibraryW,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryExA",       (FARPROC)Hook_LoadLibraryExA,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryExW",       (FARPROC)Hook_LoadLibraryExW,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ResumeThread",         (FARPROC)Hook_ResumeThread,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SetThreadContext",     (FARPROC)Hook_SetThreadContext,     nullptr, nullptr, {}, nullptr, false },
    { "advapi32.dll", "RegSetValueExA",       (FARPROC)Hook_RegSetValueExA,       nullptr, nullptr, {}, nullptr, false },
    { "advapi32.dll", "RegSetValueExW",       (FARPROC)Hook_RegSetValueExW,       nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ReadProcessMemory",    (FARPROC)Hook_ReadProcessMemory,    nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "NtQuerySystemInformation",    (FARPROC)Hook_NtQuerySystemInformation,    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateThread",               (FARPROC)Hook_CreateThread,                nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "MapViewOfFile",              (FARPROC)Hook_MapViewOfFile,               nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "RegisterClassExA",           (FARPROC)Hook_RegisterClassExA,            nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "RegisterClassExW",           (FARPROC)Hook_RegisterClassExW,            nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLocalesA",         (FARPROC)Hook_EnumSystemLocalesA,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLanguageGroupsA",  (FARPROC)Hook_EnumSystemLanguageGroupsA,   nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumWindows",                (FARPROC)Hook_EnumWindows,                 nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumChildWindows",           (FARPROC)Hook_EnumChildWindows,            nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetTimer",                   (FARPROC)Hook_SetTimer,                    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SetWaitableTimer",           (FARPROC)Hook_SetWaitableTimer,            nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateTimerQueueTimer",      (FARPROC)Hook_CreateTimerQueueTimer,       nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "OpenProcess",               (FARPROC)Hook_OpenProcess,                 nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "VirtualProtect",            (FARPROC)Hook_VirtualProtect,              nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFileMappingW",        (FARPROC)Hook_CreateFileMappingW,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFileMappingA",        (FARPROC)Hook_CreateFileMappingA,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLocalesW",        (FARPROC)Hook_EnumSystemLocalesW,          nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "CallWindowProcA",           (FARPROC)Hook_CallWindowProcA,             nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "CallWindowProcW",           (FARPROC)Hook_CallWindowProcW,             nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumThreadWindows",         (FARPROC)Hook_EnumThreadWindows,           nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ConvertThreadToFiber",      (FARPROC)Hook_ConvertThreadToFiber,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFiber",               (FARPROC)Hook_CreateFiber,                 nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SwitchToFiber",             (FARPROC)Hook_SwitchToFiber,               nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlCreateUserThread",       (FARPROC)Hook_RtlCreateUserThread,         nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateWaitableTimerExW",    (FARPROC)Hook_CreateWaitableTimerExW,      nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetWindowLongPtrA",         (FARPROC)Hook_SetWindowLongPtrA,           nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetWindowLongPtrW",         (FARPROC)Hook_SetWindowLongPtrW,           nullptr, nullptr, {}, nullptr, false },
    { "crypt32.dll",  "CertFindCertificateInStore",(FARPROC)Hook_CertFindCertificateInStore,   nullptr, nullptr, {}, nullptr, false },
    { "crypt32.dll",  "CertEnumCertificatesInStore",(FARPROC)Hook_CertEnumCertificatesInStore, nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "AddVectoredExceptionHandler",   (FARPROC)Hook_AddVectoredExceptionHandler,    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "AddVectoredContinueHandler",    (FARPROC)Hook_AddVectoredContinueHandler,     nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlAddVectoredExceptionHandler",(FARPROC)Hook_RtlAddVectoredExceptionHandler, nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlAddVectoredContinueHandler", (FARPROC)Hook_RtlAddVectoredContinueHandler,  nullptr, nullptr, {}, nullptr, false },
    // SSPI authentication downgrade detection
    { "sspicli.dll",  "InitializeSecurityContextW",    (FARPROC)Hook_InitializeSecurityContextW,      nullptr, nullptr, {}, nullptr, false },
    { "sspicli.dll",  "AcquireCredentialsHandleW",     (FARPROC)Hook_AcquireCredentialsHandleW,      nullptr, nullptr, {}, nullptr, false },
    // Sleep obfuscation detection (Ekko/Foliage use SystemFunction032 = RC4)
    { "advapi32.dll", "SystemFunction032",             (FARPROC)Hook_SystemFunction032,               nullptr, nullptr, {}, nullptr, false },
    // DPAPI browser credential harvesting
    { "crypt32.dll",  "CryptUnprotectData",            (FARPROC)Hook_CryptUnprotectData,              nullptr, nullptr, {}, nullptr, false },
    // Process Ghosting (delete-before-map) and Transacted Hollowing
    { "ntdll.dll",    "NtSetInformationFile",          (FARPROC)Hook_NtSetInformationFile,            nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "NtCreateTransaction",           (FARPROC)Hook_NtCreateTransaction,             nullptr, nullptr, {}, nullptr, false },
};

// Returns the correct call-through address.
// When both hook types are active, IAT stubs MUST call the trampoline — calling
// .original directly would re-enter the inline hook (the prologue is now our JMP).
static inline FARPROC GetCallThrough(int idx) {
    return g_hooks[idx].inlinePatched
           ? g_hooks[idx].trampoline
           : g_hooks[idx].original;
}

// ---------------------------------------------------------------------------
// IAT patching engine
// ---------------------------------------------------------------------------

static void ToLower(const char* src, char* dst, int dstLen) {
    int i = 0;
    for (; i < dstLen - 1 && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static void PatchModuleIAT(HMODULE hMod, bool restore) {
    __try {
        auto base = (BYTE*)hMod;
        auto dos  = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto nth  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE) return;

        IMAGE_DATA_DIRECTORY& impDir =
            nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!impDir.VirtualAddress || !impDir.Size) return;

        auto desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);
        for (; desc->Name; desc++) {
            char lowerName[64];
            ToLower((const char*)(base + desc->Name), lowerName, sizeof(lowerName));

            for (int hi = 0; hi < HOOK_COUNT; hi++) {
                if (strcmp(lowerName, g_hooks[hi].modName) != 0) continue;

                auto orig  = desc->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA64*)(base + desc->OriginalFirstThunk) : nullptr;
                auto first = (IMAGE_THUNK_DATA64*)(base + desc->FirstThunk);

                for (DWORD ti = 0; first[ti].u1.Function; ti++) {
                    if (!orig || (orig[ti].u1.Ordinal & IMAGE_ORDINAL_FLAG64)) continue;
                    auto ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig[ti].u1.AddressOfData);
                    if (_stricmp(ibn->Name, g_hooks[hi].funcName) != 0) continue;

                    auto slot = (FARPROC*)&first[ti].u1.Function;
                    if (!restore && g_hooks[hi].original == nullptr)
                        g_hooks[hi].original = *slot;
                    if (g_hooks[hi].original == nullptr) continue;

                    DWORD old = 0;
                    if (VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &old)) {
                        *slot = restore ? g_hooks[hi].original : g_hooks[hi].hookFn;
                        VirtualProtect(slot, sizeof(FARPROC), old, &old);
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void PatchAllModules(bool restore) {
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    for (DWORD i = 0, n = needed / sizeof(HMODULE); i < n; i++)
        if (mods[i]) PatchModuleIAT(mods[i], restore);
}

// ---------------------------------------------------------------------------
// Inline hook + trampoline engine
//
// Patch layout (written at function prologue, kPatchBytes = 14):
//   FF 25 00 00 00 00        JMP QWORD PTR [RIP+0]   — 6 bytes
//   XX XX XX XX XX XX XX XX  absolute address of hook stub — 8 bytes
//
// Trampoline layout (kTrampolineSize = 32 bytes, PAGE_EXECUTE_READWRITE):
//   [ 0 .. 13] original prologue bytes (14 bytes saved before patching)
//   [14 .. 27] FF 25 00 00 00 00 + 8-byte address of (target + 14)
//   [28 .. 31] padding
//
// The hook stub calls GetCallThrough() which returns the trampoline address,
// ensuring the call-through re-executes the displaced bytes then falls through
// to the rest of the original function (target + 14).
//
// Limitation (by design, no disassembler): if a relative branch or RIP-relative
// memory operand falls in the first 14 bytes, IsSafeToCopy() rejects the function
// and the inline hook is silently skipped (IAT hook still applies).
// ---------------------------------------------------------------------------

static constexpr int kPatchBytes    = 14; // 6-byte indirect JMP + 8-byte address
static constexpr int kTrampolineSize = 32;

static BYTE* g_trampolinePool = nullptr;

// Saved before any hooking so VerifyHooks() can VirtualProtect without re-entering
// our own Hook_VirtualProtect stub.
static BOOL (WINAPI *g_vpOriginal)(LPVOID, SIZE_T, DWORD, PDWORD) = nullptr;

// Hook-integrity watch thread handles.
static HANDLE g_watchStop   = nullptr;  // auto-reset event — signals thread to exit
static HANDLE g_watchThread = nullptr;

// Returns false if the first `len` bytes contain instructions that would produce
// wrong results when copied to a different address (RIP-relative operands or
// relative branches).
static bool IsSafeToCopy(const BYTE* fn, int len) {
    __try {
        for (int i = 0; i < len; i++) {
            BYTE b = fn[i];

            // Relative CALL / near JMP / short JMP
            if (b == 0xE8 || b == 0xE9 || b == 0xEB) return false;

            // Conditional near jumps: 0F 80..8F
            if (b == 0x0F && i + 1 < len && (fn[i + 1] & 0xF0) == 0x80) return false;

            // RIP-relative memory operand: ModRM mod=00 rm=101.
            // Cover the most common cases in prologues:
            //   REX.W (48..4F) + MOV r,rm (8B) or LEA r,m (8D) with RIP-rel ModRM
            if ((b >= 0x48 && b <= 0x4F) && i + 2 < len) {
                BYTE opc   = fn[i + 1];
                BYTE modrm = fn[i + 2];
                if ((opc == 0x8B || opc == 0x8D) &&
                    (modrm >> 6) == 0 && (modrm & 7) == 5)
                    return false;
            }

            // Indirect CALL/JMP through RIP-relative pointer: FF 15 / FF 25 disp32
            if (b == 0xFF && i + 1 < len) {
                BYTE modrm = fn[i + 1];
                BYTE reg   = (modrm >> 3) & 7;  // reg field selects CALL(2)/JMP(4)
                if ((reg == 2 || reg == 4) &&
                    (modrm >> 6) == 0 && (modrm & 7) == 5)
                    return false;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}

static void InstallInlineHook(ApiHook& h, BYTE* trampolineSlot) {
    HMODULE hMod = GetModuleHandleA(h.modName);
    if (!hMod) return;

    // GetProcAddress resolves forwarder chains (e.g. kernel32→KernelBase)
    BYTE* target = (BYTE*)GetProcAddress(hMod, h.funcName);
    if (!target) return;

    if (!IsSafeToCopy(target, kPatchBytes)) return;

    // --- Build trampoline ---
    // Bytes 0..13: displaced prologue
    memcpy(trampolineSlot, target, kPatchBytes);
    // Bytes 14..27: absolute JMP back to target+14
    BYTE* jmpBack = trampolineSlot + kPatchBytes;
    ULONG64 returnAddr = (ULONG64)(target + kPatchBytes);
    jmpBack[0] = 0xFF; jmpBack[1] = 0x25;
    jmpBack[2] = jmpBack[3] = jmpBack[4] = jmpBack[5] = 0x00; // [RIP+0]
    memcpy(jmpBack + 6, &returnAddr, sizeof(ULONG64));

    // --- Record for restore ---
    memcpy(h.savedBytes, target, kPatchBytes);
    h.inlineTarget = target;
    h.trampoline   = (FARPROC)trampolineSlot;

    // --- Write the 14-byte prologue patch ---
    BYTE patch[kPatchBytes];
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0x00; // [RIP+0]
    ULONG64 hookAddr = (ULONG64)h.hookFn;
    memcpy(patch + 6, &hookAddr, sizeof(ULONG64));

    DWORD old = 0;
    if (VirtualProtect(target, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(target, patch, kPatchBytes);
        VirtualProtect(target, kPatchBytes, old, &old);
        h.inlinePatched = true;
    }
}

static void RemoveInlineHook(ApiHook& h) {
    if (!h.inlinePatched || !h.inlineTarget) return;
    DWORD old = 0;
    if (VirtualProtect(h.inlineTarget, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(h.inlineTarget, h.savedBytes, kPatchBytes);
        VirtualProtect(h.inlineTarget, kPatchBytes, old, &old);
    }
    h.inlinePatched = false;
    h.inlineTarget  = nullptr;
    h.trampoline    = nullptr;
}

// ---------------------------------------------------------------------------
// Hook self-integrity
//
// VerifyHooks() walks every installed inline hook and checks that the first
// two bytes of the patched prologue are still 0xFF 0x25 (our indirect JMP).
// If another tool (Detours, manual unhooking) has overwritten the patch, we:
//   1. Send a Critical event naming the affected API.
//   2. Re-apply the 14-byte patch using the saved hookFn address.
//
// WatchThreadProc runs in a background thread started at DLL_PROCESS_ATTACH
// and calls VerifyHooks() every 2 seconds until signalled to stop.
// ---------------------------------------------------------------------------

static void VerifyHooks() {
    if (!g_vpOriginal) return;

    for (int i = 0; i < HOOK_COUNT; i++) {
        ApiHook& h = g_hooks[i];
        if (!h.inlinePatched || !h.inlineTarget) continue;

        // Check that our patch signature (FF 25) is still in place.
        bool tampered = false;
        __try {
            tampered = (h.inlineTarget[0] != 0xFF || h.inlineTarget[1] != 0x25);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!tampered) continue;

        // Report the tampering — another hooking layer removed our patch.
        char det[192];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "inline hook removed/overwritten: %s!%s at %p — bytes now %02X %02X",
            h.modName, h.funcName, (void*)h.inlineTarget,
            (unsigned)h.inlineTarget[0], (unsigned)h.inlineTarget[1]);
        SendHookEvent("Critical", "HookIntegrityViolation", 0, det);

        // Re-apply the 14-byte patch via the raw VirtualProtect pointer so we
        // don't re-enter Hook_VirtualProtect and generate a spurious alert.
        BYTE patch[kPatchBytes];
        patch[0] = 0xFF; patch[1] = 0x25;
        patch[2] = patch[3] = patch[4] = patch[5] = 0x00;
        ULONG64 hookAddr = (ULONG64)h.hookFn;
        memcpy(patch + 6, &hookAddr, sizeof(ULONG64));

        DWORD old = 0;
        if (g_vpOriginal(h.inlineTarget, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(h.inlineTarget, patch, kPatchBytes);
            g_vpOriginal(h.inlineTarget, kPatchBytes, old, &old);
        }
    }
}

// ---------------------------------------------------------------------------
// ETW / AMSI critical function integrity monitoring (XPN "Hiding Your .NET")
//
// Attackers patch ntdll!EtwEventWrite or amsi!AmsiScanBuffer prologues with
// a `ret` (0xC3) to blind ETW telemetry or AMSI scanning.  The prerequisite
// VirtualProtect on image memory is caught by the kernel driver, but we add
// a user-mode integrity check here as defense-in-depth.
//
// On first call, we snapshot the first 16 bytes of each function.
// On each subsequent check, we compare and alert + restore if tampered.
// ---------------------------------------------------------------------------
struct CriticalFuncGuard {
    const char* modName;
    const char* funcName;
    BYTE* addr;            // resolved address
    BYTE  baseline[16];    // original prologue bytes
    bool  valid;           // baseline captured
};

static CriticalFuncGuard g_etwGuards[] = {
    { "ntdll.dll",  "EtwEventWrite",     nullptr, {}, false },
    { "ntdll.dll",  "EtwEventWriteFull", nullptr, {}, false },
    { "ntdll.dll",  "NtTraceEvent",      nullptr, {}, false },
    { "amsi.dll",   "AmsiScanBuffer",    nullptr, {}, false },
    { "amsi.dll",   "AmsiOpenSession",   nullptr, {}, false },
    // Mimikatz crypto::capi / crypto::cng patches these to force-export
    // non-exportable private keys (CRYPT_EXPORTABLE flag bypass).
    { "ncrypt.dll", "NCryptOpenStorageProvider", nullptr, {}, false },
    { "ncrypt.dll", "NCryptExportKey",           nullptr, {}, false },
    { "ncrypt.dll", "NCryptFreeObject",          nullptr, {}, false },
    { nullptr, nullptr, nullptr, {}, false }
};

static void InitCriticalFuncGuards() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        HMODULE hMod = GetModuleHandleA(g_etwGuards[i].modName);
        if (!hMod) continue;
        BYTE* fn = (BYTE*)GetProcAddress(hMod, g_etwGuards[i].funcName);
        if (!fn) continue;

        g_etwGuards[i].addr = fn;
        __try {
            memcpy(g_etwGuards[i].baseline, fn, 16);
            g_etwGuards[i].valid = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

static void VerifyCriticalFuncIntegrity() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        CriticalFuncGuard& g = g_etwGuards[i];
        if (!g.valid || !g.addr) continue;

        // amsi.dll may not be loaded yet — re-resolve on each check
        if (!g.valid && !g.addr) {
            HMODULE hMod = GetModuleHandleA(g.modName);
            if (!hMod) continue;
            BYTE* fn = (BYTE*)GetProcAddress(hMod, g.funcName);
            if (!fn) continue;
            g.addr = fn;
            __try {
                memcpy(g.baseline, fn, 16);
                g.valid = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }

        bool tampered = false;
        BYTE current[16] = {};
        __try {
            memcpy(current, g.addr, 16);
            tampered = (memcmp(current, g.baseline, 16) != 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        if (!tampered) continue;

        // Identify the specific patch pattern for better alerting
        const char* pattern = "unknown modification";
        if (current[0] == 0xC3)
            pattern = "ret (0xC3) — XPN ETW/AMSI blind technique";
        else if (current[0] == 0xB8 && current[5] == 0xC3)
            pattern = "mov eax,imm + ret — forced clean return";
        else if (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3)
            pattern = "xor eax,eax + ret — forced S_OK return";
        else if (current[0] == 0x48 && current[1] == 0x31 && current[2] == 0xC0 && current[3] == 0xC3)
            pattern = "xor rax,rax + ret — forced zero return (x64)";

        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "%s!%s prologue patched: %s — "
            "original %02X%02X%02X%02X now %02X%02X%02X%02X",
            g.modName, g.funcName, pattern,
            g.baseline[0], g.baseline[1], g.baseline[2], g.baseline[3],
            current[0], current[1], current[2], current[3]);
        SendHookEvent("Critical", "EtwAmsiIntegrity", 0, det);

        // Restore the original prologue to re-enable ETW/AMSI
        DWORD old = 0;
        if (g_vpOriginal &&
            g_vpOriginal(g.addr, 16, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(g.addr, g.baseline, 16);
            g_vpOriginal(g.addr, 16, old, &old);
        }
    }
}

// Check for amsi.dll loads that happened after our initial scan
static void RefreshAmsiGuards() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        if (g_etwGuards[i].valid) continue;
        HMODULE hMod = GetModuleHandleA(g_etwGuards[i].modName);
        if (!hMod) continue;
        BYTE* fn = (BYTE*)GetProcAddress(hMod, g_etwGuards[i].funcName);
        if (!fn) continue;
        g_etwGuards[i].addr = fn;
        __try {
            memcpy(g_etwGuards[i].baseline, fn, 16);
            g_etwGuards[i].valid = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ---------------------------------------------------------------------------
// Hardware breakpoint hooking detection (DR0-DR3 abuse)
//
// Attackers use SetThreadContext to set hardware breakpoints (DR0-DR3) on
// ETW/AMSI/ntdll functions, then register a VEH handler that intercepts the
// breakpoint exception, modifies registers/return values, and continues.
// This hooks functions WITHOUT modifying code bytes, bypassing prologue
// integrity checks.
//
// Detection: GetThreadContext on the current thread and check if any DR0-DR3
// registers point into security-critical DLLs (ntdll, amsi, sspicli, etc.).
// Legitimate software almost never sets hardware breakpoints; only debuggers
// and offensive tools (TamperingSyscalls, HWSyscalls, AMSI-bypass-via-hwbp).
// ---------------------------------------------------------------------------

static void CheckHardwareBreakpoints()
{
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return;

    // DR7 bit layout: bits 0,2,4,6 = local enable for DR0-DR3
    // If no breakpoints are enabled, skip.
    if ((ctx.Dr7 & 0x55) == 0) return;

    ULONG_PTR breakpoints[4] = { ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 };
    BYTE localEnable[4] = {
        (BYTE)(ctx.Dr7 & 1),
        (BYTE)((ctx.Dr7 >> 2) & 1),
        (BYTE)((ctx.Dr7 >> 4) & 1),
        (BYTE)((ctx.Dr7 >> 6) & 1),
    };

    // Critical modules where hardware breakpoints indicate hooking
    struct { const char* mod; HMODULE hMod; } critMods[] = {
        { "ntdll.dll",    GetModuleHandleA("ntdll.dll") },
        { "amsi.dll",     GetModuleHandleA("amsi.dll") },
        { "sspicli.dll",  GetModuleHandleA("sspicli.dll") },
        { "kernelbase.dll", GetModuleHandleA("kernelbase.dll") },
    };

    for (int i = 0; i < 4; i++) {
        if (!localEnable[i] || breakpoints[i] == 0) continue;

        for (int m = 0; m < _countof(critMods); m++) {
            if (!critMods[m].hMod) continue;

            MODULEINFO mi = {};
            if (!GetModuleInformation(GetCurrentProcess(), critMods[m].hMod,
                    &mi, sizeof(mi)))
                continue;

            ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
            ULONG_PTR end  = base + mi.SizeOfImage;

            if (breakpoints[i] >= base && breakpoints[i] < end) {
                char det[256];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Hardware breakpoint hooking: DR%d=0x%llX points into %s — "
                    "VEH-based function hooking without code modification "
                    "(AMSI/ETW/syscall bypass via hardware breakpoints)",
                    i, (unsigned long long)breakpoints[i], critMods[m].mod);
                SendHookEvent("Critical", "HardwareBreakpointHook", 0, det);

                // Clear the breakpoint to neutralize the hook
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                switch (i) {
                    case 0: ctx.Dr0 = 0; break;
                    case 1: ctx.Dr1 = 0; break;
                    case 2: ctx.Dr2 = 0; break;
                    case 3: ctx.Dr3 = 0; break;
                }
                ctx.Dr7 &= ~(3ULL << (i * 2)); // clear local+global enable
                SetThreadContext(GetCurrentThread(), &ctx);
                break;
            }
        }
    }
}

static DWORD WINAPI WatchThreadProc(LPVOID) {
    // WaitForSingleObject with 2000 ms timeout: fires VerifyHooks on each expiry,
    // exits cleanly when g_watchStop is signalled from RemoveHooks().
    while (WaitForSingleObject(g_watchStop, 2000) == WAIT_TIMEOUT) {
        VerifyHooks();
        RefreshAmsiGuards();
        VerifyCriticalFuncIntegrity();
        CheckHardwareBreakpoints();
    }
    return 0;
}

static void InstallAllInlineHooks() {
    // Capture VirtualProtect before any inline/IAT patching.  Used by
    // VerifyHooks() to re-apply patches without triggering our own hook stub.
    g_vpOriginal = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");

    g_trampolinePool = (BYTE*)VirtualAlloc(
        nullptr, HOOK_COUNT * kTrampolineSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_trampolinePool) {
        // VirtualAlloc(PAGE_EXECUTE_READWRITE) failed in-process.
        // Most likely cause: ProcessDynamicCodePolicy (ProhibitDynamicCode) is active,
        // which the kernel enforces by rejecting RWX allocations.
        // IAT patches will still be applied but inline hooks cannot be installed —
        // coverage is significantly reduced (no GetProcAddress-path interception).
        SendHookEvent("Critical", "DynamicCodePolicy", 0,
            "VirtualAlloc(RWX) failed — ProcessDynamicCodePolicy likely active; "
            "trampoline pool not created, inline hooks will NOT be installed");
        return;
    }

    for (int i = 0; i < HOOK_COUNT; i++)
        InstallInlineHook(g_hooks[i], g_trampolinePool + i * kTrampolineSize);

    // Harden: flip pool RWX → RX.  Any future in-process write to a trampoline
    // now requires VirtualProtect (which we hook), making the attempt visible.
    DWORD old = 0;
    VirtualProtect(g_trampolinePool, (SIZE_T)(HOOK_COUNT * kTrampolineSize),
                   PAGE_EXECUTE_READ, &old);
}

static void RemoveAllInlineHooks() {
    for (int i = 0; i < HOOK_COUNT; i++)
        RemoveInlineHook(g_hooks[i]);

    if (g_trampolinePool) {
        VirtualFree(g_trampolinePool, 0, MEM_RELEASE);
        g_trampolinePool = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Hook stubs
// All stubs call GetCallThrough(idx) for call-through, which is correct
// regardless of which hook types are active.
// ---------------------------------------------------------------------------

static LPVOID WINAPI Hook_VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    typedef LPVOID(WINAPI* Fn)(LPVOID, SIZE_T, DWORD, DWORD);
    if (flProtect == PAGE_EXECUTE_READWRITE || flProtect == PAGE_EXECUTE_WRITECOPY) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "RWX alloc: size=0x%llX prot=0x%lX", (ULONG64)dwSize, flProtect);
        SendHookEvent("Warning", "VirtualAlloc", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_VIRTUALALLOC))(
        lpAddress, dwSize, flAllocationType, flProtect);
}

static LPVOID WINAPI Hook_VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect)
{
    typedef LPVOID(WINAPI* Fn)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        const char* sev = (flProtect == PAGE_EXECUTE_READWRITE ||
                           flProtect == PAGE_EXECUTE_WRITECOPY)
                          ? "Critical" : "High";
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote alloc: targetPid=%lu size=0x%llX prot=0x%lX",
            targetPid, (ULONG64)dwSize, flProtect);
        SendHookEvent(sev, "VirtualAllocEx", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_VIRTUALALLOCEX))(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

// ---------------------------------------------------------------------------
// Checks whether [lpBaseAddress, lpBaseAddress+nSize) overlaps with the
// target process's PEB->ProcessParameters->CommandLine buffer.
//
// Used to detect argument-spoofing: attacker spawns child with CREATE_SUSPENDED
// + benign-looking args, then overwrites the PEB CommandLine before resume so
// the child runs with different args than what NtCreateUserProcess recorded.
// Also catches self-modification (process hiding its own launch args from
// scanners that read user-mode PEB).
//
// Offsets are 64-bit Windows layout:
//   PEB+0x20          → ProcessParameters pointer
//   ProcessParameters+0x72 → CommandLine.MaximumLength (USHORT)
//   ProcessParameters+0x78 → CommandLine.Buffer (PWSTR)
// ---------------------------------------------------------------------------
static BOOL IsWriteTargetingCmdLine(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T nSize)
{
    typedef NTSTATUS (NTAPI *NtQIP_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static NtQIP_t fnNtQIP = nullptr;
    if (!fnNtQIP)
        fnNtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                           "NtQueryInformationProcess");
    if (!fnNtQIP) return FALSE;

    PROCESS_BASIC_INFORMATION pbi = {};
    if (!NT_SUCCESS(fnNtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)))
        return FALSE;

    BYTE* pebBase = (BYTE*)pbi.PebBaseAddress;
    if (!pebBase) return FALSE;

    // Read PEB->ProcessParameters pointer (offset 0x20 in 64-bit PEB)
    ULONG_PTR pParamsAddr = 0;
    if (!ReadProcessMemory(hProcess, pebBase + 0x20, &pParamsAddr, sizeof(pParamsAddr), nullptr) || !pParamsAddr)
        return FALSE;

    // Read CommandLine.MaximumLength (offset 0x72) and .Buffer (offset 0x78)
    USHORT   cmdMaxLen  = 0;
    ULONG_PTR cmdBufPtr = 0;
    if (!ReadProcessMemory(hProcess, (BYTE*)pParamsAddr + 0x72, &cmdMaxLen,  sizeof(cmdMaxLen),  nullptr) || !cmdMaxLen)
        return FALSE;
    if (!ReadProcessMemory(hProcess, (BYTE*)pParamsAddr + 0x78, &cmdBufPtr,  sizeof(cmdBufPtr),  nullptr) || !cmdBufPtr)
        return FALSE;

    BYTE* writeStart = (BYTE*)lpBaseAddress;
    BYTE* writeEnd   = writeStart + nSize;
    BYTE* cmdStart   = (BYTE*)cmdBufPtr;
    BYTE* cmdEnd     = cmdStart + cmdMaxLen;
    return (writeStart < cmdEnd && writeEnd > cmdStart) ? TRUE : FALSE;
}

static BOOL WINAPI Hook_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,
    SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    DWORD targetPid    = GetProcessId(hProcess);
    DWORD effectivePid = targetPid ? targetPid : g_selfPid;  // pseudo-handle (-1) → self

    if (targetPid && targetPid != g_selfPid) {
        // Cross-process write — always suspicious
        const char* tag = "";
        if (nSize >= 2 && lpBuffer) {
            __try { if (*(const WORD*)lpBuffer == 0x5A4D) tag = " [MZ]"; }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote write: targetPid=%lu dst=%p size=0x%llX%s",
            targetPid, lpBaseAddress, (ULONG64)nSize, tag);
        SendHookEvent("Critical", "WriteProcessMemory", targetPid, det);
    }

    // Argument spoofing / self-hiding: does this write land on the target's
    // PEB CommandLine buffer?  Fires for both cross-process and self-writes.
    if (nSize > 0 && IsWriteTargetingCmdLine(hProcess, lpBaseAddress, nSize)) {
        char spoof[192];
        _snprintf_s(spoof, sizeof(spoof), _TRUNCATE,
            "%s: write targets PEB CommandLine of pid=%lu dst=%p size=0x%llX",
            (effectivePid == g_selfPid)
                ? "PEB CommandLine self-modification (scanner evasion)"
                : "Argument spoofing: cross-process PEB CommandLine overwrite",
            effectivePid, lpBaseAddress, (ULONG64)nSize);
        SendHookEvent("Critical", "WriteProcessMemory", effectivePid, spoof);
    }

    return ((Fn)GetCallThrough(IDX_WRITEPROCESSMEMORY))(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

static HANDLE WINAPI Hook_CreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote thread: targetPid=%lu startAddr=%p", targetPid, lpStartAddress);
        SendHookEvent("Critical", "CreateRemoteThread", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEREMOTETHREAD))(
        hProcess, lpSA, dwStackSize, lpStartAddress, lpParam, dwCreationFlags, lpThreadId);
}

static HANDLE WINAPI Hook_CreateRemoteThreadEx(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttrList, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote thread ex: targetPid=%lu startAddr=%p", targetPid, lpStartAddress);
        SendHookEvent("Critical", "CreateRemoteThreadEx", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEREMOTETHREADEX))(
        hProcess, lpSA, dwStackSize, lpStartAddress, lpParam,
        dwCreationFlags, lpAttrList, lpThreadId);
}

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName) {
    typedef HMODULE(WINAPI* Fn)(LPCSTR);
    if (lpLibFileName) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE, "path=%s", lpLibFileName);
        SendHookEvent("Info", "LoadLibraryA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYA))(lpLibFileName);
}

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName) {
    typedef HMODULE(WINAPI* Fn)(LPCWSTR);
    if (lpLibFileName) {
        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, lpLibFileName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE, "path=%s", narrow);
        SendHookEvent("Info", "LoadLibraryW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYW))(lpLibFileName);
}

static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    typedef HMODULE(WINAPI* Fn)(LPCSTR, HANDLE, DWORD);
    if (lpLibFileName && dwFlags == 0) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "path=%s flags=0x%lX", lpLibFileName, dwFlags);
        SendHookEvent("Info", "LoadLibraryExA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYEXA))(lpLibFileName, hFile, dwFlags);
}

static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    typedef HMODULE(WINAPI* Fn)(LPCWSTR, HANDLE, DWORD);
    if (lpLibFileName && dwFlags == 0) {
        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, lpLibFileName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "path=%s flags=0x%lX", narrow, dwFlags);
        SendHookEvent("Info", "LoadLibraryExW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYEXW))(lpLibFileName, hFile, dwFlags);
}

static DWORD WINAPI Hook_ResumeThread(HANDLE hThread) {
    typedef DWORD(WINAPI* Fn)(HANDLE);
    DWORD tid = GetThreadId(hThread);
    DWORD pid = tid ? GetProcessIdOfThread(hThread) : 0;
    if (pid && pid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "cross-process resume: targetPid=%lu tid=%lu", pid, tid);
        SendHookEvent("High", "ResumeThread", pid, det);
    }
    return ((Fn)GetCallThrough(IDX_RESUMETHREAD))(hThread);
}

static BOOL WINAPI Hook_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    typedef BOOL(WINAPI* Fn)(HANDLE, const CONTEXT*);
    DWORD tid = GetThreadId(hThread);
    DWORD pid = tid ? GetProcessIdOfThread(hThread) : 0;

    if (pid && pid != g_selfPid) {
        // Cross-process context manipulation: RIP redirect or inject via debug regs
        DWORD64 rip = 0;
        if (lpContext && (lpContext->ContextFlags & CONTEXT_CONTROL))
            rip = lpContext->Rip;
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "cross-process SetThreadContext: targetPid=%lu tid=%lu RIP=0x%llX",
            pid, tid, rip);
        SendHookEvent("Critical", "SetThreadContext", pid, det);
    }

    // VEH hardware breakpoint bypass: same-process thread arming DR0-DR3.
    // An attacker sets a hardware breakpoint on the inline-hook JMP target so
    // a EXCEPTION_SINGLE_STEP/EXCEPTION_BREAKPOINT fires BEFORE the hook runs,
    // then redirects RIP from inside the VEH — bypassing our inline hook entirely.
    // Detect any same-process call that sets at least one DR with CONTEXT_DEBUG_REGISTERS.
    if (lpContext && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        if (lpContext->Dr0 || lpContext->Dr1 || lpContext->Dr2 || lpContext->Dr3) {
            char det[200];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "SetThreadContext(CONTEXT_DEBUG_REGISTERS) tid=%lu "
                "Dr0=0x%llX Dr1=0x%llX Dr2=0x%llX Dr3=0x%llX — "
                "hardware BP may be used to bypass inline hooks via VEH",
                tid,
                (unsigned long long)lpContext->Dr0,
                (unsigned long long)lpContext->Dr1,
                (unsigned long long)lpContext->Dr2,
                (unsigned long long)lpContext->Dr3);
            SendHookEvent("High", "SetThreadContext", pid ? pid : g_selfPid, det);
        }
    }

    return ((Fn)GetCallThrough(IDX_SETTHREADCONTEXT))(hThread, lpContext);
}

static bool IsPersistenceValue(const char* name) {
    if (!name) return false;
    static const char* kSuspect[] = {
        "Run", "RunOnce", "Load", "Shell", "Userinit",
        "AppInit_DLLs", "BootExecute", nullptr
    };
    for (int i = 0; kSuspect[i]; i++)
        if (_stricmp(name, kSuspect[i]) == 0) return true;
    return false;
}

static LONG WINAPI Hook_RegSetValueExA(
    HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    typedef LONG(WINAPI* Fn)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    const char* sev = IsPersistenceValue(lpValueName) ? "High" : "Info";
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "value=%s type=%lu size=%lu",
        lpValueName ? lpValueName : "(default)", dwType, cbData);
    SendHookEvent(sev, "RegSetValueExA", 0, det);
    return ((Fn)GetCallThrough(IDX_REGSETVALUEEX_A))(
        hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

static LONG WINAPI Hook_RegSetValueExW(
    HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    typedef LONG(WINAPI* Fn)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    char narrow[128] = {};
    if (lpValueName)
        WideCharToMultiByte(CP_UTF8, 0, lpValueName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
    const char* sev = IsPersistenceValue(narrow) ? "High" : "Info";
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "value=%s type=%lu size=%lu",
        narrow[0] ? narrow : "(default)", dwType, cbData);
    SendHookEvent(sev, "RegSetValueExW", 0, det);
    return ((Fn)GetCallThrough(IDX_REGSETVALUEEX_W))(
        hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// ---------------------------------------------------------------------------
// Deception helpers
// ---------------------------------------------------------------------------

// Canary NTLM hash (MD4 of empty string) — universally flagged by SIEMs and
// domain controllers if used in pass-the-hash or Kerberos attacks.
static const BYTE kCanaryNtlmHash[16] = {
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
};

// EDR process names to conceal from NtQuerySystemInformation output.
// The attacker sees an unprotected host — no defenders visible.
static const char* kEdrProcessNames[] = {
    "NortonEDR.exe", "nortonav.exe", "MsMpEng.exe",
    "SentinelAgent.exe", "CSFalconService.exe", nullptr
};

// Name of the injected decoy process — appears as an attractive SYSTEM process
// with no parent, ready for injection (a honeypot for injection attempts).
static const char kDecoyProcessName[] = "svchost_config.exe";

static bool IsLsassHandle(HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    if (!pid) return false;
    // Open a query-only handle to get the image name
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    char name[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    // Use QueryFullProcessImageNameA for reliability
    typedef BOOL(WINAPI* QFn)(HANDLE, DWORD, LPSTR, PDWORD);
    static QFn qfn = (QFn)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                          "QueryFullProcessImageNameA");
    bool result = false;
    if (qfn && qfn(h, 0, name, &sz)) {
        // Match basename "lsass.exe" case-insensitively
        const char* base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        result = (_stricmp(base, "lsass.exe") == 0);
    }
    CloseHandle(h);
    return result;
}

// Scan buffer for 16-byte windows that look like NTLM hashes and replace them.
// Heuristic: >= 8 non-zero bytes AND >= 5 bytes in 0x80-0xFF range AND max
// run of identical bytes <= 4.
static void PatchNtlmHashesInBuffer(LPVOID buffer, SIZE_T size) {
    if (!buffer || size < 16) return;
    BYTE* buf = (BYTE*)buffer;
    DWORD patched = 0;
    for (SIZE_T off = 0; off + 16 <= size; off += 8) {
        BYTE* w = buf + off;
        int nonZero = 0, highByte = 0, maxRun = 0, run = 1;
        for (int i = 0; i < 16; i++) {
            if (w[i]) nonZero++;
            if (w[i] >= 0x80) highByte++;
            if (i > 0) {
                if (w[i] == w[i-1]) run++; else run = 1;
                if (run > maxRun) maxRun = run;
            }
        }
        if (nonZero >= 8 && highByte >= 5 && maxRun <= 4) {
            memcpy(w, kCanaryNtlmHash, 16);
            patched++;
            off += 8; // skip to avoid partial overlap
        }
    }
    if (patched) {
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "Replaced %lu NTLM hash candidate(s) with canary in LSASS read buffer", patched);
        SendHookEvent("Critical", "ReadProcessMemory[Deception]", 0, msg);
    }
}

// ---------------------------------------------------------------------------
// Hook_ReadProcessMemory — post-read LSASS buffer deception
// ---------------------------------------------------------------------------
static BOOL WINAPI Hook_ReadProcessMemory(
    HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    Fn real = (Fn)GetCallThrough(IDX_READPROCESSMEMORY);

    // Execute the real read first
    BOOL result = real(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    if (!result || !lpBuffer || nSize < 16) return result;

    DWORD targetPid = GetProcessId(hProcess);
    if (!IsLsassHandle(hProcess)) return result;

    // Target is LSASS — log the attempt
    char det[128];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "LSASS read: base=0x%p size=%zu — applying credential deception",
        lpBaseAddress, nSize);
    SendHookEvent("Critical", "ReadProcessMemory", targetPid, det);

    // Corrupt NTLM hash candidates in the output buffer
    SIZE_T bytesRead = lpNumberOfBytesRead ? *lpNumberOfBytesRead : nSize;
    PatchNtlmHashesInBuffer(lpBuffer, bytesRead);

    return result;
}

// ---------------------------------------------------------------------------
// Hook_NtQuerySystemInformation — process list deception
//
// SystemProcessInformation (class 5): patch the linked list of
// SYSTEM_PROCESS_INFORMATION entries to:
//   a) Remove entries whose ImageName matches a known EDR process name.
//      The attacker sees no active defenders.
//   b) Inject a single decoy SYSTEM_PROCESS_INFORMATION entry that looks
//      like a lightly protected svchost variant — a honeypot for injection.
// ---------------------------------------------------------------------------

// Minimal SYSTEM_PROCESS_INFORMATION layout (matches Windows internals)
struct SPI_ENTRY {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE  Reserved1[48];
    UNICODE_STRING ImageName;
    LONG  BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    // ... more fields follow but we only need offsets above
};

static bool IsEdrProcess(const wchar_t* name, int nameLen) {
    if (!name || nameLen <= 0) return false;
    char narrow[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, name, nameLen,
                        narrow, sizeof(narrow)-1, nullptr, nullptr);
    for (int i = 0; kEdrProcessNames[i]; i++)
        if (_stricmp(narrow, kEdrProcessNames[i]) == 0) return true;
    return false;
}

static BOOL WINAPI Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    typedef BOOL(WINAPI* Fn)(ULONG, PVOID, ULONG, PULONG);
    Fn real = (Fn)GetCallThrough(IDX_NTQUERYSYSTEMINFO);

    BOOL result = real(SystemInformationClass, SystemInformation,
                       SystemInformationLength, ReturnLength);

    // Only patch SystemProcessInformation (class 5)
    if (!result || SystemInformationClass != 5 ||
        !SystemInformation || !SystemInformationLength) return result;

    // Walk the linked list and unlink any EDR process entries
    BYTE* base  = (BYTE*)SystemInformation;
    SPI_ENTRY* prev = nullptr;
    SPI_ENTRY* cur  = (SPI_ENTRY*)base;
    DWORD removedCount = 0;

    while (true) {
        // Validate entry is within buffer bounds
        if ((BYTE*)cur < base ||
            (BYTE*)cur + sizeof(SPI_ENTRY) > base + SystemInformationLength) break;

        bool remove = false;
        if (cur->ImageName.Buffer && cur->ImageName.Length > 0) {
            remove = IsEdrProcess(cur->ImageName.Buffer,
                                  cur->ImageName.Length / sizeof(wchar_t));
        }

        if (remove) {
            removedCount++;
            if (prev) {
                // Unlink: previous entry skips directly to our successor
                if (cur->NextEntryOffset == 0)
                    prev->NextEntryOffset = 0;  // we were last
                else
                    prev->NextEntryOffset += cur->NextEntryOffset;
            } else if (cur->NextEntryOffset != 0) {
                // We're the first entry — slide the buffer start
                MoveMemory(base, base + cur->NextEntryOffset,
                           SystemInformationLength - cur->NextEntryOffset);
                cur = (SPI_ENTRY*)base;
                continue;
            }
        }

        prev = remove ? prev : cur;
        if (cur->NextEntryOffset == 0) break;
        cur = (SPI_ENTRY*)((BYTE*)cur + cur->NextEntryOffset);
    }

    if (removedCount) {
        char msg[64];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "Removed %lu EDR process(es) from SystemProcessInformation", removedCount);
        SendHookEvent("Info", "NtQuerySystemInformation[Deception]", 0, msg);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Category 1 stubs — injection precursors and missing execution paths
// ---------------------------------------------------------------------------

// OpenProcess: log every cross-process handle acquisition with its desired access.
// This is the universal precursor to every injection technique and credential dump.
static HANDLE WINAPI Hook_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    typedef HANDLE(WINAPI* Fn)(DWORD, BOOL, DWORD);
    if (dwProcessId != g_selfPid) {
        const char* sev = (dwDesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_READ |
                           PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) ? "High" : "Info";
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "targetPid=%lu access=0x%lX", dwProcessId, dwDesiredAccess);
        SendHookEvent(sev, "OpenProcess", dwProcessId, det);
    }
    return ((Fn)GetCallThrough(IDX_OPENPROCESS))(dwDesiredAccess, bInheritHandle, dwProcessId);
}

// VirtualProtect: alert when marking a region PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY.
// Catches in-process shellcode staging that doesn't go through VirtualAlloc.
static BOOL WINAPI Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    typedef BOOL(WINAPI* Fn)(LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL inModule = lpAddress ? IsAddressInKnownModule(lpAddress) : FALSE;

    if (flNewProtect == PAGE_EXECUTE_READWRITE || flNewProtect == PAGE_EXECUTE_WRITECOPY) {
        char det[160];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "addr=%p size=0x%llX prot=0x%lX inModule=%d",
            lpAddress, (ULONG64)dwSize, flNewProtect, (int)inModule);
        // RWX outside a module = shellcode staging (Critical); inside = trampoline noise (Info)
        SendHookEvent(inModule ? "Info" : "Critical", "VirtualProtect", 0, det);
    } else if ((flNewProtect == PAGE_READWRITE || flNewProtect == PAGE_WRITECOPY) && inModule) {
        // Write-only on a loaded module's code section — ntdll/DLL stomp pattern.
        // PAGE_READWRITE is the protection malware uses before memcpy'ing clean ntdll bytes
        // over our inline hooks; it doesn't trigger the RWX check above so needs its own path.
        char det[200];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "addr=%p size=0x%llX prot=0x%lX — write permission on loaded module "
            "(ntdll/DLL stomp pattern)",
            lpAddress, (ULONG64)dwSize, flNewProtect);
        SendHookEvent("Critical", "VirtualProtect", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_VIRTUALPROTECT))(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// CreateFileMapping: flag executable sections (SEC_IMAGE or PAGE_EXECUTE_*)
static HANDLE WINAPI Hook_CreateFileMappingW(
    HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttr, DWORD flProtect,
    DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCWSTR lpName)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    DWORD prot = flProtect & 0xFF; // low byte is page protection
    if (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
        prot == PAGE_EXECUTE_WRITECOPY || (flProtect & SEC_IMAGE)) {
        char name[64] = {};
        if (lpName) WideCharToMultiByte(CP_UTF8, 0, lpName, -1, name, sizeof(name)-1, nullptr, nullptr);
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable section: prot=0x%lX name=%s", flProtect, name[0] ? name : "(anon)");
        SendHookEvent("High", "CreateFileMappingW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFILEMAPPINGW))(
        hFile, lpAttr, flProtect, dwMaxSizeHigh, dwMaxSizeLow, lpName);
}

static HANDLE WINAPI Hook_CreateFileMappingA(
    HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttr, DWORD flProtect,
    DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCSTR lpName)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    DWORD prot = flProtect & 0xFF;
    if (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
        prot == PAGE_EXECUTE_WRITECOPY || (flProtect & SEC_IMAGE)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable section: prot=0x%lX name=%s", flProtect, lpName ? lpName : "(anon)");
        SendHookEvent("High", "CreateFileMappingA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFILEMAPPINGA))(
        hFile, lpAttr, flProtect, dwMaxSizeHigh, dwMaxSizeLow, lpName);
}

// EnumSystemLocalesW — W variant of the callback-abuse technique
static BOOL WINAPI Hook_EnumSystemLocalesW(LOCALE_ENUMPROCW lpLocaleEnumProc, DWORD dwFlags) {
    typedef BOOL(WINAPI* Fn)(LOCALE_ENUMPROCW, DWORD);
    if (lpLocaleEnumProc && !IsAddressInKnownModule((const void*)lpLocaleEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpLocaleEnumProc);
        SendHookEvent("Critical", "EnumSystemLocalesW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSTEMLOCALESW))(lpLocaleEnumProc, dwFlags);
}

// CallWindowProc: used to dispatch shellcode through an existing window procedure slot
static LRESULT WINAPI Hook_CallWindowProcA(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wP, LPARAM lP) {
    typedef LRESULT(WINAPI* Fn)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
    if (lpPrevWndFunc && !IsAddressInKnownModule((const void*)lpPrevWndFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module", (void*)lpPrevWndFunc);
        SendHookEvent("Critical", "CallWindowProcA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CALLWINDOWPROCA))(lpPrevWndFunc, hWnd, Msg, wP, lP);
}

static LRESULT WINAPI Hook_CallWindowProcW(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wP, LPARAM lP) {
    typedef LRESULT(WINAPI* Fn)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
    if (lpPrevWndFunc && !IsAddressInKnownModule((const void*)lpPrevWndFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module", (void*)lpPrevWndFunc);
        SendHookEvent("Critical", "CallWindowProcW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CALLWINDOWPROCW))(lpPrevWndFunc, hWnd, Msg, wP, lP);
}

static BOOL WINAPI Hook_EnumThreadWindows(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(DWORD, WNDENUMPROC, LPARAM);
    if (lpfn && !IsAddressInKnownModule((const void*)lpfn)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpfn);
        SendHookEvent("Critical", "EnumThreadWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMTHREADWINDOWS))(dwThreadId, lpfn, lParam);
}

// Fiber-based shellcode: ConvertThreadToFiber + CreateFiber + SwitchToFiber
// The detection point is SwitchToFiber with a non-module address — that's when
// execution is transferred. ConvertThreadToFiber and CreateFiber are logged for
// context but not blocked (they're legitimately used by runtimes like .NET).
static LPVOID WINAPI Hook_ConvertThreadToFiber(LPVOID lpParameter) {
    typedef LPVOID(WINAPI* Fn)(LPVOID);
    SendHookEvent("Info", "ConvertThreadToFiber", 0, "thread converted to fiber");
    return ((Fn)GetCallThrough(IDX_CONVERTTHREADTOFIBER))(lpParameter);
}

static LPVOID WINAPI Hook_CreateFiber(
    SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    typedef LPVOID(WINAPI* Fn)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
    if (lpStartAddress && !IsAddressInKnownModule((const void*)lpStartAddress)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "fiberStart=%p NOT in any loaded module", (void*)lpStartAddress);
        SendHookEvent("Critical", "CreateFiber", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFIBER))(dwStackSize, lpStartAddress, lpParameter);
}

static VOID WINAPI Hook_SwitchToFiber(LPVOID lpFiber) {
    typedef VOID(WINAPI* Fn)(LPVOID);
    if (lpFiber && !IsAddressInKnownModule(lpFiber)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "fiberAddr=%p NOT in any loaded module — shellcode fiber execution", lpFiber);
        SendHookEvent("Critical", "SwitchToFiber", 0, det);
    }
    ((Fn)GetCallThrough(IDX_SWITCHTOFIBER))(lpFiber);
}

// RtlCreateUserThread: direct ntdll thread creation, bypasses CreateThread hook.
// Used by Metasploit, Cobalt Strike, and Mimikatz for remote thread injection.
typedef NTSTATUS (NTAPI* RtlCreateUserThread_t)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);

static NTSTATUS NTAPI Hook_RtlCreateUserThread(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended, ULONG StackZeroBits,
    SIZE_T StackReserve, SIZE_T StackCommit,
    PVOID StartAddress, PVOID Parameter,
    PHANDLE ThreadHandle, PVOID ClientId)
{
    DWORD targetPid = GetProcessId(ProcessHandle);
    const char* sev = (targetPid && targetPid != g_selfPid) ? "Critical" : "High";
    char det[128];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "targetPid=%lu startAddr=%p inModule=%d",
        targetPid, StartAddress, (int)IsAddressInKnownModule(StartAddress));
    SendHookEvent(sev, "RtlCreateUserThread", targetPid, det);
    return ((RtlCreateUserThread_t)GetCallThrough(IDX_RTLCREATEUSERTHREAD))(
        ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits,
        StackReserve, StackCommit, StartAddress, Parameter, ThreadHandle, ClientId);
}

// CreateWaitableTimerExW — timer variant with APC callback (missed in first pass)
static HANDLE WINAPI Hook_CreateWaitableTimerExW(
    LPSECURITY_ATTRIBUTES lpAttr, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)
{
    typedef HANDLE(WINAPI* Fn)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
    // Log creation; execution trigger is caught by SetWaitableTimer hook
    SendHookEvent("Info", "CreateWaitableTimerExW", 0, "waitable timer created");
    return ((Fn)GetCallThrough(IDX_CREATEWAITABLETIMEREXW))(lpAttr, lpName, dwFlags, dwDesiredAccess);
}

// SetWindowLongPtr(GWLP_WNDPROC): post-creation WndProc replacement.
// This is Path B of the window-message shellcode technique — the attacker
// creates a legitimate window then replaces its WndProc with a shellcode
// address, bypassing our RegisterClassEx hook entirely.
#ifndef GWLP_WNDPROC
#define GWLP_WNDPROC (-4)
#endif

static LONG_PTR WINAPI Hook_SetWindowLongPtrA(HWND hWnd, int nIndex, LONG_PTR dwNewLong) {
    typedef LONG_PTR(WINAPI* Fn)(HWND, int, LONG_PTR);
    if (nIndex == GWLP_WNDPROC && dwNewLong &&
        !IsAddressInKnownModule((const void*)dwNewLong)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "GWLP_WNDPROC replaced with addr=%p NOT in any loaded module "
            "(window-message shellcode dispatch, Path B)",
            (void*)dwNewLong);
        SendHookEvent("Critical", "SetWindowLongPtrA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWINDOWLONGPTRA))(hWnd, nIndex, dwNewLong);
}

static LONG_PTR WINAPI Hook_SetWindowLongPtrW(HWND hWnd, int nIndex, LONG_PTR dwNewLong) {
    typedef LONG_PTR(WINAPI* Fn)(HWND, int, LONG_PTR);
    if (nIndex == GWLP_WNDPROC && dwNewLong &&
        !IsAddressInKnownModule((const void*)dwNewLong)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "GWLP_WNDPROC replaced with addr=%p NOT in any loaded module "
            "(window-message shellcode dispatch, Path B)",
            (void*)dwNewLong);
        SendHookEvent("Critical", "SetWindowLongPtrW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWINDOWLONGPTRW))(hWnd, nIndex, dwNewLong);
}

// CertFindCertificateInStore / CertEnumCertificatesInStore:
// Both accept a pfnFindCallback function pointer (optional, may be NULL).
// When non-NULL and pointing outside loaded modules, this is the CRYPT32
// callback abuse technique — shellcode passed as a certificate enumeration
// callback (score 94, mal 24-27 in differential, zero clean use).
// Note: CertEnumCertificatesInStore has no explicit callback argument —
// we hook it purely as a telemetry signal since it appears in the Mimikatz
// certificate-store enumeration path alongside cryptdll.dll.
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertFindCertificateInStore(
    HCERTSTORE_OPAQUE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags,
    DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT_OPAQUE pPrevCertContext)
{
    typedef PCCERT_CONTEXT_OPAQUE(WINAPI* Fn)(HCERTSTORE_OPAQUE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT_OPAQUE);
    // dwFindType == 6 (CERT_FIND_SUBJECT_FUNC) or 8 (CERT_FIND_ISSUER_FUNC)
    // means pvFindPara is a function pointer — the callback abuse path.
    if (pvFindPara &&
        (dwFindType == 6 || dwFindType == 8) &&
        !IsAddressInKnownModule(pvFindPara)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module findType=%lu (CRYPT32 callback abuse)",
            pvFindPara, dwFindType);
        SendHookEvent("Critical", "CertFindCertificateInStore", 0, det);
    } else {
        SendHookEvent("Info", "CertFindCertificateInStore", 0, "certificate store access");
    }
    return ((Fn)GetCallThrough(IDX_CERTFINDCERTIFICATE))(
        hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);
}

static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertEnumCertificatesInStore(
    HCERTSTORE_OPAQUE hCertStore, PCCERT_CONTEXT_OPAQUE pPrevCertContext)
{
    typedef PCCERT_CONTEXT_OPAQUE(WINAPI* Fn)(HCERTSTORE_OPAQUE, PCCERT_CONTEXT_OPAQUE);
    if (pPrevCertContext == nullptr)
        SendHookEvent("Info", "CertEnumCertificatesInStore", 0, "certificate store enumeration start");
    return ((Fn)GetCallThrough(IDX_CERTENUMCERTIFICATES))(hCertStore, pPrevCertContext);
}

// ---------------------------------------------------------------------------
// IsAddressInKnownModule
//
// Returns true if `addr` falls within the virtual address range of any module
// loaded in the current process. Used by all execution-trigger hooks to detect
// shellcode function pointers that live in heap or anonymous mapped memory.
// ---------------------------------------------------------------------------

static bool IsAddressInKnownModule(const void* addr) {
    if (!addr) return true; // NULL is not shellcode
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return true; // can't tell — don't false-positive
    DWORD n = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < n; i++) {
        if (!mods[i]) continue;
        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        const BYTE* base = (const BYTE*)mi.lpBaseOfDll;
        if ((const BYTE*)addr >= base && (const BYTE*)addr < base + mi.SizeOfImage)
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Evasion-path execution trigger stubs
// ---------------------------------------------------------------------------

// Technique 3: local CreateThread with shellcode start address (heap staging)
static HANDLE WINAPI Hook_CreateThread(
    LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    if (lpStartAddress && !IsAddressInKnownModule((const void*)lpStartAddress)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "local thread: startAddr=%p NOT in any loaded module (heap/anon shellcode)",
            (void*)lpStartAddress);
        SendHookEvent("Critical", "CreateThread", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATETHREAD))(
        lpSA, dwStackSize, lpStartAddress, lpParam, dwCreationFlags, lpThreadId);
}

// Technique 6: MapViewOfFile with FILE_MAP_EXECUTE — file-backed section / module stomping
static LPVOID WINAPI Hook_MapViewOfFile(
    HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    typedef LPVOID(WINAPI* Fn)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    if (dwDesiredAccess & FILE_MAP_EXECUTE) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable file mapping: access=0x%lX size=0x%llX",
            dwDesiredAccess, (ULONG64)dwNumberOfBytesToMap);
        SendHookEvent("High", "MapViewOfFile", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_MAPVIEWOFFILE))(
        hFileMappingObject, dwDesiredAccess,
        dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

// Technique 2: RegisterClassEx with WndProc shellcode address (window message dispatch)
static ATOM WINAPI Hook_RegisterClassExA(const WNDCLASSEXA* lpwcx) {
    typedef ATOM(WINAPI* Fn)(const WNDCLASSEXA*);
    if (lpwcx && lpwcx->lpfnWndProc &&
        !IsAddressInKnownModule((const void*)lpwcx->lpfnWndProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module — window message shellcode dispatch",
            (void*)lpwcx->lpfnWndProc);
        SendHookEvent("Critical", "RegisterClassExA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_REGISTERCLASSEXA))(lpwcx);
}

static ATOM WINAPI Hook_RegisterClassExW(const WNDCLASSEXW* lpwcx) {
    typedef ATOM(WINAPI* Fn)(const WNDCLASSEXW*);
    if (lpwcx && lpwcx->lpfnWndProc &&
        !IsAddressInKnownModule((const void*)lpwcx->lpfnWndProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module — window message shellcode dispatch",
            (void*)lpwcx->lpfnWndProc);
        SendHookEvent("Critical", "RegisterClassExW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_REGISTERCLASSEXW))(lpwcx);
}

// Technique 4: Callback abuse — Enum* functions used to dispatch shellcode
static BOOL WINAPI Hook_EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags) {
    typedef BOOL(WINAPI* Fn)(LOCALE_ENUMPROCA, DWORD);
    if (lpLocaleEnumProc && !IsAddressInKnownModule((const void*)lpLocaleEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpLocaleEnumProc);
        SendHookEvent("Critical", "EnumSystemLocalesA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSTEMLOCALESA))(lpLocaleEnumProc, dwFlags);
}

// EnumSystemLanguageGroupsA — rarity score 100 in malware differential: never in clean,
// seen in 16 malicious samples. Treat as Critical unconditionally when callback is
// outside module space.
static BOOL WINAPI Hook_EnumSystemLanguageGroupsA(
    LANGUAGEGROUP_ENUMPROCA lpLanguageGroupEnumProc, DWORD dwFlags, LONG_PTR lParam)
{
    typedef BOOL(WINAPI* Fn)(LANGUAGEGROUP_ENUMPROCA, DWORD, LONG_PTR);
    if (lpLanguageGroupEnumProc &&
        !IsAddressInKnownModule((const void*)lpLanguageGroupEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module [rarity-100 malware indicator]",
            (void*)lpLanguageGroupEnumProc);
        SendHookEvent("Critical", "EnumSystemLanguageGroupsA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSLANGGRPA))(
        lpLanguageGroupEnumProc, dwFlags, lParam);
}

static BOOL WINAPI Hook_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(WNDENUMPROC, LPARAM);
    if (lpEnumFunc && !IsAddressInKnownModule((const void*)lpEnumFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpEnumFunc);
        SendHookEvent("Critical", "EnumWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMWINDOWS))(lpEnumFunc, lParam);
}

static BOOL WINAPI Hook_EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(HWND, WNDENUMPROC, LPARAM);
    if (lpEnumFunc && !IsAddressInKnownModule((const void*)lpEnumFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpEnumFunc);
        SendHookEvent("Critical", "EnumChildWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMCHILDWINDOWS))(hWndParent, lpEnumFunc, lParam);
}

// Technique 5: Timer callbacks — shellcode registered as timer handler
static UINT_PTR WINAPI Hook_SetTimer(
    HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
{
    typedef UINT_PTR(WINAPI* Fn)(HWND, UINT_PTR, UINT, TIMERPROC);
    if (lpTimerFunc && !IsAddressInKnownModule((const void*)lpTimerFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "TimerProc=%p NOT in any loaded module", (void*)lpTimerFunc);
        SendHookEvent("Critical", "SetTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETTIMER))(hWnd, nIDEvent, uElapse, lpTimerFunc);
}

static BOOL WINAPI Hook_SetWaitableTimer(
    HANDLE hTimer, const LARGE_INTEGER* lpDueTime, LONG lPeriod,
    PTIMERAPCROUTINE pfnCompletionRoutine, PVOID lpArgToCompletionRoutine, BOOL fResume)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, const LARGE_INTEGER*, LONG,
                              PTIMERAPCROUTINE, PVOID, BOOL);
    if (pfnCompletionRoutine &&
        !IsAddressInKnownModule((const void*)pfnCompletionRoutine)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "APC routine=%p NOT in any loaded module", (void*)pfnCompletionRoutine);
        SendHookEvent("Critical", "SetWaitableTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWAITABLETIMER))(
        hTimer, lpDueTime, lPeriod, pfnCompletionRoutine,
        lpArgToCompletionRoutine, fResume);
}

static BOOL WINAPI Hook_CreateTimerQueueTimer(
    PHANDLE phNewTimer, HANDLE TimerQueue,
    WAITORTIMERCALLBACK Callback, PVOID Parameter,
    DWORD DueTime, DWORD Period, ULONG Flags)
{
    typedef BOOL(WINAPI* Fn)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID,
                              DWORD, DWORD, ULONG);
    if (Callback && !IsAddressInKnownModule((const void*)Callback)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)Callback);
        SendHookEvent("Critical", "CreateTimerQueueTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATETIMERQUEUETIMER))(
        phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);
}

// ---------------------------------------------------------------------------
// VEH hooking bypass coverage
//
// Technique: attacker calls AddVectoredExceptionHandler / RtlAddVectoredExceptionHandler
// with a shellcode address, then intentionally triggers an exception (div-by-zero,
// access violation, or a hardware debug breakpoint set via SetThreadContext DR0-DR3).
// The VEH fires BEFORE the inline hook JMP is reached — bypassing our detour
// entirely — and the VEH handler can redirect RIP to any address.
//
// We flag registrations whose handler address does not belong to any loaded PE
// module on disk, which is the signature of heap/stack shellcode.
// ---------------------------------------------------------------------------

// Shared logic for all four VEH registration APIs.
static void CheckVehHandler(const char* apiName, PVECTORED_EXCEPTION_HANDLER handler) {
    if (!handler) return;
    if (!IsAddressInKnownModule((const void*)handler)) {
        char det[160];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "VEH handler=%p NOT in any loaded module — "
            "shellcode may be registered as vectored exception handler to bypass inline hooks",
            (void*)handler);
        SendHookEvent("Critical", apiName, g_selfPid, det);
    }
}

static PVOID WINAPI Hook_AddVectoredExceptionHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(WINAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("AddVectoredExceptionHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_ADDVECTOREDEXCEPTIONHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID WINAPI Hook_AddVectoredContinueHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(WINAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("AddVectoredContinueHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_ADDVECTOREDCONTINUEHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID NTAPI Hook_RtlAddVectoredExceptionHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(NTAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("RtlAddVectoredExceptionHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_RTLADDVECTOREDEXCEPTIONHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID NTAPI Hook_RtlAddVectoredContinueHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(NTAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("RtlAddVectoredContinueHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_RTLADDVECTOREDCONTINUEHANDLER))(FirstHandler, VectoredHandler);
}

// ---------------------------------------------------------------------------
// Sleep obfuscation detection — SystemFunction032 hook (Ekko/Foliage/Cronos)
//
// Sleep obfuscation frameworks (Ekko, Foliage, Cronos, Havoc sleep masks)
// use SystemFunction032 (RC4) to encrypt their implant's memory while sleeping.
// The pattern: VirtualProtect(RX→RW) → SystemFunction032(encrypt) → Sleep →
// SystemFunction032(decrypt) → VirtualProtect(RW→RX).
//
// Detection: when SystemFunction032 is called on a buffer that resides in a
// MEM_PRIVATE region (not a loaded module), this is almost certainly sleep
// obfuscation — legitimate code uses CryptEncrypt or BCrypt, not the
// undocumented SystemFunction032.
// ---------------------------------------------------------------------------

static NTSTATUS WINAPI Hook_SystemFunction032(USTRING* data, USTRING* key)
{
    typedef NTSTATUS(WINAPI* Fn)(USTRING*, USTRING*);

    if (data && data->Buffer && data->Length > 0) {
        // Check if the target buffer is in a private (non-module) region
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(data->Buffer, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // MEM_PRIVATE + large buffer = sleep obfuscation indicator
            // Legitimate RC4 usage is on small data blobs, not entire PE sections.
            if (mbi.Type == MEM_PRIVATE && data->Length > 4096) {
                char det[256];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Sleep obfuscation (Ekko/Foliage/Cronos): SystemFunction032 called on "
                    "MEM_PRIVATE region at %p (size=%lu, protect=0x%lx) — "
                    "RC4 encrypt/decrypt of implant memory during beacon sleep",
                    (void*)data->Buffer, data->Length, mbi.Protect);
                SendHookEvent("Critical", "SystemFunction032", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_SYSTEMFUNCTION032))(data, key);
}

// ---------------------------------------------------------------------------
// DPAPI credential harvesting — CryptUnprotectData hook
//
// Browser credential stealers (SharpChromium, HackBrowserData, Mimikatz
// dpapi::chrome, CookieMonster) call CryptUnprotectData to decrypt the
// browser's AES-GCM master key (stored in Local State, DPAPI-encrypted).
// Legitimate browsers call this themselves; any OTHER process calling it
// is harvesting credentials.
// ---------------------------------------------------------------------------

static BOOL WINAPI Hook_CryptUnprotectData(
    HOOK_DATA_BLOB* pDataIn, wchar_t** ppszDataDescr,
    HOOK_DATA_BLOB* pOptionalEntropy, PVOID pvReserved,
    PVOID pPromptStruct, DWORD dwFlags, HOOK_DATA_BLOB* pDataOut)
{
    typedef BOOL(WINAPI* Fn)(HOOK_DATA_BLOB*, wchar_t**, HOOK_DATA_BLOB*,
                              PVOID, PVOID, DWORD, HOOK_DATA_BLOB*);

    // Only flag non-browser processes calling CryptUnprotectData
    char exeName[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
    const char* base = exeName;
    for (const char* p = exeName; *p; p++)
        if (*p == '\\' || *p == '/') base = p + 1;

    BOOL isBrowser = (_stricmp(base, "chrome.exe")   == 0 ||
                      _stricmp(base, "msedge.exe")   == 0 ||
                      _stricmp(base, "firefox.exe")  == 0 ||
                      _stricmp(base, "opera.exe")    == 0 ||
                      _stricmp(base, "brave.exe")    == 0 ||
                      _stricmp(base, "vivaldi.exe")  == 0 ||
                      _stricmp(base, "iexplore.exe") == 0);

    // Legitimate DPAPI callers: browsers, credential manager, system
    BOOL isSystem = (_stricmp(base, "lsass.exe")     == 0 ||
                     _stricmp(base, "svchost.exe")   == 0 ||
                     _stricmp(base, "services.exe")  == 0 ||
                     _stricmp(base, "NortonEDR.exe") == 0);

    if (!isBrowser && !isSystem && pDataIn && pDataIn->cbData > 0) {
        // CRYPTPROTECT_UI_FORBIDDEN (0x01) = programmatic access without UI prompt
        // — credential stealers always set this flag.
        const char* severity = (dwFlags & 0x01) ? "Critical" : "Warning";
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "DPAPI credential harvesting: %s called CryptUnprotectData "
            "(size=%lu, flags=0x%lx) — possible browser/credential theft "
            "(SharpChromium/HackBrowserData/Mimikatz dpapi)",
            base, pDataIn->cbData, dwFlags);
        SendHookEvent(severity, "CryptUnprotectData", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_CRYPTUNPROTECTDATA))(
        pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved,
        pPromptStruct, dwFlags, pDataOut);
}

// ---------------------------------------------------------------------------
// Process Ghosting detection — NtSetInformationFile hook
//
// Process Ghosting: attacker creates a file, writes malicious PE, marks it
// delete-pending (NtSetInformationFile with FileDispositionInformation),
// creates a section from it, then closes the handle (file is deleted).
// The section survives, and the process is created from a "ghost" file
// that no longer exists on disk.
//
// Detection: NtSetInformationFile with FileDispositionInformation (class 13)
// or FileDispositionInformationEx (class 64) from a non-system process.
// Legitimate software rarely marks files delete-pending while keeping the
// handle open for section creation.
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation,
    ULONG Length, ULONG FileInformationClass)
{
    typedef NTSTATUS(NTAPI* Fn)(HANDLE, PVOID, PVOID, ULONG, ULONG);

    // FileDispositionInformation = 13, FileDispositionInformationEx = 64
    if ((FileInformationClass == 13 || FileInformationClass == 64) &&
        FileInformation && Length >= sizeof(BOOLEAN))
    {
        BOOLEAN deleteFile = *(BOOLEAN*)FileInformation;
        if (deleteFile) {
            // Check if this file handle was recently written to (heuristic for ghosting)
            // For now, flag delete-pending from non-system processes as suspicious
            char exeName[MAX_PATH] = {};
            GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
            const char* base = exeName;
            for (const char* p = exeName; *p; p++)
                if (*p == '\\' || *p == '/') base = p + 1;

            BOOL isTrusted = (_stricmp(base, "explorer.exe") == 0 ||
                              _stricmp(base, "svchost.exe")  == 0 ||
                              _stricmp(base, "msiexec.exe")  == 0 ||
                              _stricmp(base, "TiWorker.exe") == 0 ||
                              _stricmp(base, "setup.exe")    == 0 ||
                              _stricmp(base, "NortonEDR.exe") == 0);

            if (!isTrusted) {
                char det[256];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Process Ghosting indicator: %s set FileDispositionInfo%s "
                    "(delete-pending) — file may be used for ghost process creation "
                    "(T1055.012 variant)",
                    base,
                    FileInformationClass == 64 ? "Ex" : "");
                SendHookEvent("Warning", "NtSetInformationFile", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_NTSETINFORMATIONFILE))(
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

// ---------------------------------------------------------------------------
// Transacted Hollowing — NtCreateTransaction hook (user-mode complement)
//
// The kernel syscall hook already catches NtCreateTransaction; this user-mode
// hook provides redundancy and catches cases where the syscall hook is bypassed
// (e.g., via direct syscall from injected code that was already inside a
// process before HookDll loaded).
//
// Transacted Hollowing combines TxF (NTFS transactions) with process hollowing:
// create a transaction, write malicious PE to a transacted file, create a
// MEM_IMAGE section from it, then rollback (artifact-free on disk).
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI Hook_NtCreateTransaction(
    PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID Uow, HANDLE TmHandle,
    ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags,
    PLARGE_INTEGER Timeout, PVOID Description)
{
    typedef NTSTATUS(NTAPI* Fn)(PHANDLE, ACCESS_MASK, PVOID, PVOID, HANDLE,
                                 ULONG, ULONG, ULONG, PLARGE_INTEGER, PVOID);

    // NtCreateTransaction is almost never called by legitimate user-mode software.
    // TxF is deprecated since Windows 8 and MS discourages its use.
    char exeName[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
    const char* base = exeName;
    for (const char* p = exeName; *p; p++)
        if (*p == '\\' || *p == '/') base = p + 1;

    BOOL isTrusted = (_stricmp(base, "svchost.exe")  == 0 ||
                      _stricmp(base, "msiexec.exe")  == 0 ||
                      _stricmp(base, "TiWorker.exe") == 0 ||
                      _stricmp(base, "NortonEDR.exe") == 0);

    if (!isTrusted) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "Transacted Hollowing: %s called NtCreateTransaction "
            "— TxF is deprecated; likely Process Doppelganging / "
            "Transacted Hollowing evasion technique",
            base);
        SendHookEvent("Warning", "NtCreateTransaction", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_NTCREATETRANSACTION))(
        TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle,
        CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
}

// ---------------------------------------------------------------------------
// Authentication downgrade detection — SSPI hooks (T1556.001)
//
// 1. AcquireCredentialsHandleW — monitors which authentication package is
//    requested.  Explicit "NTLM" or "WDigest" acquisition from a non-system
//    process is suspicious (mimikatz sekurlsa, ntlmrelayx, Inveigh).
//    Legitimate apps use "Negotiate" which prefers Kerberos.
//
// 2. InitializeSecurityContextW — monitors the target SPN.  When pszTargetName
//    is NULL or contains "NTLM" (forced NTLM instead of Kerberos), the
//    Negotiate SSP falls back to NTLM — this is the runtime downgrade.
//    Also detects missing SPN (common in relay attacks where the attacker
//    intentionally omits the SPN to force NTLM).
// ---------------------------------------------------------------------------

// Case-insensitive wide-string comparison for SSP package names.
static bool WideStrEqualI(const wchar_t* a, const wchar_t* b) {
    if (!a || !b) return false;
    for (int i = 0; ; i++) {
        wchar_t ca = (a[i] >= L'A' && a[i] <= L'Z') ? a[i] + 32 : a[i];
        wchar_t cb = (b[i] >= L'A' && b[i] <= L'Z') ? b[i] + 32 : b[i];
        if (ca != cb) return false;
        if (ca == L'\0') return true;
    }
}

// Processes that legitimately acquire NTLM credentials (lsass, svchost, etc.).
static bool IsSspiTrustedProcess() {
    char name[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, name, sizeof(name))) return false;
    // Extract just the filename
    const char* base = name;
    for (const char* p = name; *p; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    return (_stricmp(base, "lsass.exe")    == 0 ||
            _stricmp(base, "svchost.exe")  == 0 ||
            _stricmp(base, "services.exe") == 0 ||
            _stricmp(base, "winlogon.exe") == 0 ||
            _stricmp(base, "System")       == 0 ||
            _stricmp(base, "NortonEDR.exe") == 0);
}

static LONG WINAPI Hook_AcquireCredentialsHandleW(
    wchar_t* pszPrincipal, wchar_t* pszPackage, ULONG fCredentialUse,
    PVOID pvLogonID, PVOID pAuthData, PVOID pGetKeyFn,
    PVOID pvGetKeyArgument, PCredHandle phCredential, PLARGE_INTEGER ptsExpiry)
{
    typedef LONG(WINAPI* Fn)(wchar_t*, wchar_t*, ULONG, PVOID, PVOID,
                              PVOID, PVOID, PCredHandle, PLARGE_INTEGER);

    // Flag explicit NTLM / WDigest / LM package acquisition from non-system processes.
    // Legitimate apps use "Negotiate" (which tries Kerberos first).
    if (pszPackage && !IsSspiTrustedProcess()) {
        bool isNtlm    = WideStrEqualI(pszPackage, L"NTLM");
        bool isWDigest = WideStrEqualI(pszPackage, L"WDigest");

        if (isNtlm || isWDigest) {
            char det[200];
            char pkgA[32] = {};
            for (int i = 0; i < 31 && pszPackage[i]; i++)
                pkgA[i] = (char)(pszPackage[i] & 0x7F);
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "Auth downgrade (T1556.001): explicit %s credential acquisition "
                "— non-Negotiate auth enables relay/downgrade attacks",
                pkgA);
            SendHookEvent(isWDigest ? "Critical" : "Warning",
                "AcquireCredentialsHandleW", 0, det);
        }
    }

    return ((Fn)GetCallThrough(IDX_ACQUIRECREDENTIALSHANDLEW))(
        pszPrincipal, pszPackage, fCredentialUse, pvLogonID, pAuthData,
        pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}

static LONG WINAPI Hook_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, wchar_t* pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, ULONG* pfContextAttr, PLARGE_INTEGER ptsExpiry)
{
    typedef LONG(WINAPI* Fn)(PCredHandle, PCtxtHandle, wchar_t*, ULONG, ULONG,
                              ULONG, PSecBufferDesc, ULONG, PCtxtHandle,
                              PSecBufferDesc, ULONG*, PLARGE_INTEGER);

    if (!IsSspiTrustedProcess()) {
        // Detection 1: NULL target SPN — forces NTLM fallback.
        // Legitimate Kerberos auth always specifies an SPN (e.g., "HTTP/server.domain").
        // Relay tools (ntlmrelayx, Inveigh) omit the SPN to force NTLM.
        if (!pszTargetName && !phContext) {
            // First call (phContext==NULL) with no SPN = forced NTLM
            SendHookEvent("Warning", "InitializeSecurityContextW", 0,
                "Auth downgrade (T1556.001): InitializeSecurityContext called "
                "with NULL target SPN — forces Negotiate→NTLM fallback "
                "(relay attack / credential theft)");
        }

        // Detection 2: Target name containing explicit NTLM force-strings.
        // Some attack tools pass pszTargetName = "NTLM" or empty string
        // to override the Negotiate package's Kerberos preference.
        if (pszTargetName && !phContext) {
            bool forceNtlm = (pszTargetName[0] == L'\0') ||
                              WideStrEqualI(pszTargetName, L"NTLM");
            if (forceNtlm) {
                char det[200];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Auth downgrade (T1556.001): InitializeSecurityContext "
                    "target='%S' — forced NTLM authentication bypass of Kerberos",
                    pszTargetName[0] ? pszTargetName : L"(empty)");
                SendHookEvent("Warning", "InitializeSecurityContextW", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_INITIALIZESECURITYCONTEXTW))(
        phCredential, phContext, pszTargetName, fContextReq, Reserved1,
        TargetDataRep, pInput, Reserved2, phNewContext, pOutput,
        pfContextAttr, ptsExpiry);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void InstallHooks() {
    g_selfPid = GetCurrentProcessId();
    InitializeCriticalSection(&g_pipeLock);
    g_lockInit = true;

    ConnectToPipe();
    InstallAllInlineHooks(); // prologue patches first — catches GetProcAddress callers
    PatchAllModules(false);  // IAT patches catch load-time importers

    // Confirm successful injection to kernel driver — enables injection timeout detection.
    // NORTONAV_HOOKDLL_CONFIRM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
    {
        HANDLE hDev = CreateFileA("\\\\.\\NortonEDR",
            GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDev != INVALID_HANDLE_VALUE) {
            DWORD pid = g_selfPid;
            DWORD returned = 0;
            DeviceIoControl(hDev, 0x00222018,
                &pid, sizeof(pid), nullptr, 0, &returned, nullptr);
            CloseHandle(hDev);
        }
    }

    // Snapshot ETW/AMSI critical function prologues before the watch thread starts.
    // These baselines are checked every 2s to detect XPN-style patching.
    InitCriticalFuncGuards();

    // Start the hook-integrity watch thread.
    // WatchThreadProc is inside HookDll so IsAddressInKnownModule() returns true
    // for its start address — Hook_CreateThread won't fire a false alarm.
    g_watchStop = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (g_watchStop)
        g_watchThread = CreateThread(nullptr, 0, WatchThreadProc, nullptr, 0, nullptr);
}

void RemoveHooks() {
    // Stop the watch thread first — it must not run while we're restoring patches,
    // or it may race on inlinePatched/inlineTarget and re-apply a hook mid-restore.
    if (g_watchStop) {
        SetEvent(g_watchStop);
        if (g_watchThread) {
            WaitForSingleObject(g_watchThread, 3000);
            CloseHandle(g_watchThread);
            g_watchThread = nullptr;
        }
        CloseHandle(g_watchStop);
        g_watchStop = nullptr;
    }

    RemoveAllInlineHooks(); // restore prologues before IAT (avoid re-entry during teardown)
    PatchAllModules(true);

    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    if (g_lockInit) {
        DeleteCriticalSection(&g_pipeLock);
        g_lockInit = false;
    }
}

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstDll);

        // Pin the DLL — bump refcount so FreeLibrary from malware cannot unload us.
        // GetModuleHandleEx with GET_MODULE_HANDLE_EX_FLAG_PIN sets the refcount to
        // MAXULONG, making the module permanently loaded until process exit.
        {
            HMODULE hPin = nullptr;
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                (LPCWSTR)DllMain,
                &hPin);
        }

        InstallHooks();
        break;

    case DLL_PROCESS_DETACH:
        // lpReserved != NULL means the process is terminating — safe to clean up.
        // lpReserved == NULL means someone called FreeLibrary — this should not
        // happen since we pinned the DLL, but if it does, alert and refuse.
        if (lpReserved == NULL) {
            SendHookEvent("Critical", "DLL_PROCESS_DETACH",
                g_selfPid,
                "FreeLibrary called on HookDll — "
                "EDR hook removal attempt (DLL should be pinned)");
            return FALSE;  // reject the unload
        }
        RemoveHooks();
        break;
    }
    return TRUE;
}
