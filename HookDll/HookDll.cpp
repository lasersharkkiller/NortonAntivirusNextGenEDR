#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <winreg.h>
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
    IDX_VIRTUALALLOC         = 0,
    IDX_VIRTUALALLOCEX       = 1,
    IDX_WRITEPROCESSMEMORY   = 2,
    IDX_CREATEREMOTETHREAD   = 3,
    IDX_CREATEREMOTETHREADEX = 4,
    IDX_LOADLIBRARYA         = 5,
    IDX_LOADLIBRARYW         = 6,
    IDX_LOADLIBRARYEXA       = 7,
    IDX_LOADLIBRARYEXW       = 8,
    IDX_RESUMETHREAD         = 9,
    IDX_SETTHREADCONTEXT     = 10,
    IDX_REGSETVALUEEX_A      = 11,
    IDX_REGSETVALUEEX_W      = 12,
    IDX_READPROCESSMEMORY    = 13,   // deception: post-read LSASS buffer patching
    IDX_NTQUERYSYSTEMINFO    = 14,   // deception: hide EDR, inject decoy process
    HOOK_COUNT               = 15
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
    { "ntdll.dll",    "NtQuerySystemInformation", (FARPROC)Hook_NtQuerySystemInformation, nullptr, nullptr, {}, nullptr, false },
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

static void InstallAllInlineHooks() {
    g_trampolinePool = (BYTE*)VirtualAlloc(
        nullptr, HOOK_COUNT * kTrampolineSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_trampolinePool) return;

    for (int i = 0; i < HOOK_COUNT; i++)
        InstallInlineHook(g_hooks[i], g_trampolinePool + i * kTrampolineSize);
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

static BOOL WINAPI Hook_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,
    SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
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
        DWORD64 rip = 0;
        if (lpContext && (lpContext->ContextFlags & CONTEXT_CONTROL))
            rip = lpContext->Rip;
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "cross-process SetThreadContext: targetPid=%lu tid=%lu RIP=0x%llX",
            pid, tid, rip);
        SendHookEvent("Critical", "SetThreadContext", pid, det);
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
// Public API
// ---------------------------------------------------------------------------

void InstallHooks() {
    g_selfPid = GetCurrentProcessId();
    InitializeCriticalSection(&g_pipeLock);
    g_lockInit = true;

    ConnectToPipe();
    InstallAllInlineHooks(); // prologue patches first — catches GetProcAddress callers
    PatchAllModules(false);  // IAT patches catch load-time importers
}

void RemoveHooks() {
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

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstDll);
        InstallHooks();
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        break;
    }
    return TRUE;
}
