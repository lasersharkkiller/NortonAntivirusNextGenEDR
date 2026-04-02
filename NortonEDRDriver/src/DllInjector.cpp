#include "Globals.h"

// Undocumented APC types and functions not always exposed by ntifs.h
typedef VOID (NTAPI* PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID (NTAPI* PKKERNEL_ROUTINE_)(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef VOID (NTAPI* PKRUNDOWN_ROUTINE_)(PRKAPC Apc);
typedef enum _KAPC_ENVIRONMENT_ {
    OriginalApcEnvironment = 0,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT_, *PKAPC_ENVIRONMENT_;

// Must be extern "C" — these are undocumented exports in ntoskrnl.lib;
// C++ mangling would produce a decorated name the linker cannot find.
extern "C" {
NTKERNELAPI VOID KeInitializeApc(PRKAPC Apc, PKTHREAD Thread,
    KAPC_ENVIRONMENT_ Environment, PKKERNEL_ROUTINE_ KernelRoutine,
    PKRUNDOWN_ROUTINE_ RundownRoutine, PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode, PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(PRKAPC Apc, PVOID SystemArgument1,
    PVOID SystemArgument2, KPRIORITY Increment);
}

// ---------------------------------------------------------------------------
// DllInjector — kernel-mode APC injection of HookDll.dll into user processes.
//
// Trigger: ImageLoadNotifyRoutine calls TryInject() on every ntdll.dll load
// (the first DLL mapped into every new process).  At that point the loading
// thread is the correct injection target and the driver is already attached
// to the process, so ZwAllocateVirtualMemory(NtCurrentProcess()) allocates
// in the target's address space.
//
// Mechanism:
//   1. Allocate a READWRITE buffer in the target process and write the DLL path.
//   2. KeInitializeApc / KeInsertQueueApc with LoadLibraryW as the NormalRoutine
//      and the path buffer VA as NormalContext (= RCX on x64 = first argument).
//   3. The APC fires when the thread next enters an alertable wait, which the
//      loader does during early initialisation.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Globals set once from user mode via NORTONAV_SET_INJECT_CONFIG IOCTL
// ---------------------------------------------------------------------------
static volatile PVOID  g_LoadLibraryW  = nullptr;
static WCHAR           g_HookDllPath[260] = {};
static ULONG           g_PathByteLen   = 0;
static ULONG           g_OwnerPid      = 0;
static volatile BOOLEAN g_ConfigSet    = FALSE;

// ---------------------------------------------------------------------------
// Per-process injection dedup
// ---------------------------------------------------------------------------
#define MAX_INJECTED_PIDS 2048
static ULONG      g_InjectedPids[MAX_INJECTED_PIDS] = {};
static LONG       g_InjectedCount = 0;
static KSPIN_LOCK g_PidLock;

// Returns TRUE if pid was already in the set; adds it and returns FALSE otherwise.
static BOOLEAN MarkInjected(ULONG pid) {
    KIRQL irql;
    KeAcquireSpinLock(&g_PidLock, &irql);
    for (LONG i = 0; i < g_InjectedCount; i++) {
        if (g_InjectedPids[i] == pid) {
            KeReleaseSpinLock(&g_PidLock, irql);
            return TRUE;
        }
    }
    if (g_InjectedCount < MAX_INJECTED_PIDS)
        g_InjectedPids[g_InjectedCount++] = pid;
    KeReleaseSpinLock(&g_PidLock, irql);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Process filter — skip injection into sensitive or self processes
// ---------------------------------------------------------------------------
static const char* const kSkipNames[] = {
    "System", "smss.exe", "csrss.exe", "wininit.exe", "lsass.exe", nullptr
};

static BOOLEAN ShouldSkipProcess(PEPROCESS process) {
    if (process == PsInitialSystemProcess) return TRUE;
    if (HandleToUlong(PsGetProcessId(process)) == g_OwnerPid) return TRUE;

    char* name = PsGetProcessImageFileName(process);
    if (!name) return TRUE;
    for (int i = 0; kSkipNames[i]; i++) {
        if (_strnicmp(name, kSkipNames[i], 15) == 0) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// ntdll.dll path check — suffix match, case-insensitive
// ---------------------------------------------------------------------------
static BOOLEAN IsNtdll(PUNICODE_STRING fullImageName) {
    if (!fullImageName || !fullImageName->Buffer) return FALSE;
    // "ntdll.dll" = 9 WCHAR = 18 bytes
    if (fullImageName->Length < 18) return FALSE;

    static const WCHAR kSuffix[] = L"ntdll.dll";
    PWCHAR tail = fullImageName->Buffer +
                  (fullImageName->Length / sizeof(WCHAR)) - 9;

    for (int i = 0; i < 9; i++) {
        WCHAR c = tail[i];
        if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        if (c != kSuffix[i]) return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// APC plumbing
// ---------------------------------------------------------------------------
struct ApcCtx { KAPC Apc; };

// Kernel routine: called in kernel mode when the APC fires.
// Frees our context; the path buffer in the target process is intentionally
// left — it is a tiny RW allocation and freeing it from the kernel routine
// would require a process handle we don't carry here.
static VOID NTAPI ApcKernelRoutine(
    PRKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArg1,
    PVOID* SystemArg2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);
    ExFreePoolWithTag(CONTAINING_RECORD(Apc, ApcCtx, Apc), 'apci');
}

// Rundown routine: called if the thread exits before the APC fires.
static VOID NTAPI ApcRundownRoutine(PRKAPC Apc) {
    ExFreePoolWithTag(CONTAINING_RECORD(Apc, ApcCtx, Apc), 'apci');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

VOID DllInjector::Initialize() {
    KeInitializeSpinLock(&g_PidLock);
}

VOID DllInjector::SetConfig(
    PVOID  loadLibraryW,
    ULONG  ownerPid,
    PCWSTR path,
    ULONG  byteLen)
{
    if (!loadLibraryW || !path || byteLen == 0 || byteLen > sizeof(g_HookDllPath)) return;

    g_LoadLibraryW = loadLibraryW;
    g_OwnerPid     = ownerPid;
    RtlCopyMemory(g_HookDllPath, path, byteLen);
    g_PathByteLen  = byteLen;
    g_ConfigSet    = TRUE;

    DbgPrint("[+] DllInjector: configured LoadLibraryW=%p ownerPid=%lu path bytes=%lu\n",
             loadLibraryW, ownerPid, byteLen);
}

// Called from ImageLoadNotifyRoutine while the driver is attached to `process`.
// Must be called at PASSIVE_LEVEL with the process context attached.
VOID DllInjector::TryInject(PEPROCESS process, PUNICODE_STRING fullImageName) {
    if (!g_ConfigSet) return;
    if (!IsNtdll(fullImageName)) return;
    if (ShouldSkipProcess(process)) return;

    ULONG pid = HandleToUlong(PsGetProcessId(process));
    if (MarkInjected(pid)) return;

    // Allocate a READWRITE buffer in the target process.
    // NtCurrentProcess() resolves to the attached process context.
    PVOID  pathBuf  = nullptr;
    SIZE_T pathSize = g_PathByteLen;
    NTSTATUS status = ZwAllocateVirtualMemory(
        NtCurrentProcess(), &pathBuf, 0, &pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] DllInjector: ZwAllocateVirtualMemory failed 0x%X (pid=%lu)\n",
                 status, pid);
        return;
    }

    __try {
        RtlCopyMemory(pathBuf, g_HookDllPath, g_PathByteLen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ZwFreeVirtualMemory(NtCurrentProcess(), &pathBuf, &pathSize, MEM_RELEASE);
        return;
    }

    // Allocate APC context from non-paged pool
    ApcCtx* ctx = (ApcCtx*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ApcCtx), 'apci');
    if (!ctx) {
        ZwFreeVirtualMemory(NtCurrentProcess(), &pathBuf, &pathSize, MEM_RELEASE);
        return;
    }

    // Target: the current thread — the thread that triggered the image load.
    // NormalContext becomes RCX when the user-mode routine fires, i.e., the
    // first (and only) argument to LoadLibraryW.
    KeInitializeApc(
        &ctx->Apc,
        (PKTHREAD)PsGetCurrentThread(),
        OriginalApcEnvironment,
        ApcKernelRoutine,
        ApcRundownRoutine,
        (PKNORMAL_ROUTINE)g_LoadLibraryW,
        UserMode,
        pathBuf);

    if (!KeInsertQueueApc(&ctx->Apc, nullptr, nullptr, IO_NO_INCREMENT)) {
        DbgPrint("[-] DllInjector: KeInsertQueueApc failed (pid=%lu)\n", pid);
        ZwFreeVirtualMemory(NtCurrentProcess(), &pathBuf, &pathSize, MEM_RELEASE);
        ExFreePoolWithTag(ctx, 'apci');
    } else {
        DbgPrint("[+] DllInjector: APC queued pid=%lu pathBuf=%p\n", pid, pathBuf);
    }
}
