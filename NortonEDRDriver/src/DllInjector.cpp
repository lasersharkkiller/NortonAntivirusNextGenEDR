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
// PsGetProcessMitigationPolicy — local resolver for SignaturePolicy checks.
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnPsGetProcessMitigationPolicy)(
    PEPROCESS, ULONG, PVOID, SIZE_T);

static pfnPsGetProcessMitigationPolicy g_PsGetMitig = nullptr;
static volatile LONG g_MitigResolvedLocal = 0;

static VOID EnsureMitigationResolver() {
    if (InterlockedCompareExchange(&g_MitigResolvedLocal, 1, 0) == 0) {
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"PsGetProcessMitigationPolicy");
        g_PsGetMitig = (pfnPsGetProcessMitigationPolicy)MmGetSystemRoutineAddress(&us);
    }
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

// ---------------------------------------------------------------------------
// Injection confirmation tracking — detects failed/blocked/raced APC injection.
// HookDll must send NORTONAV_HOOKDLL_CONFIRM within 5 seconds of APC queue.
// ---------------------------------------------------------------------------
#define MAX_PENDING_INJECT 512

struct PendingInject {
    ULONG pid;
    LARGE_INTEGER queuedTime;
    BOOLEAN used;
};

static PendingInject g_PendingInjects[MAX_PENDING_INJECT] = {};
static KSPIN_LOCK    g_PendingLock;

// ---------------------------------------------------------------------------
// Signature policy bypass tracking (Adam Chester "blockdlls" / ACG bypass).
//
// When a process has PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES,
// LoadLibraryW(HookDll.dll) silently fails because CI rejects the image.
// We temporarily clear the EPROCESS signature restriction flags before queuing
// our APC, and restore them after HookDll confirms (or on timeout).
//
// Cleared fields:
//   - MitigationFlags bit 23 (SignatureMitigationOptIn) → disables policy enforcement
//   - SectionSignatureLevel → set to 0 (unchecked) so CI allows any signature level
// ---------------------------------------------------------------------------
#define MAX_SIG_RESTORE 256

struct SigRestore {
    ULONG pid;
    ULONG originalMitigFlags;    // full MitigationFlags DWORD
    UCHAR originalSectionSigLvl; // original SectionSignatureLevel byte
    BOOLEAN used;
};

static SigRestore g_SigRestores[MAX_SIG_RESTORE] = {};
// Protected by g_PendingLock (shared with PendingInject — always acquired together)

// Restore original signature policy flags on an EPROCESS.
// Called at PASSIVE_LEVEL (IOCTL handler or work item).
static VOID RestoreSigFlags(ULONG pid) {
    ULONG origFlags = 0;
    UCHAR origSigLvl = 0;
    BOOLEAN found = FALSE;

    // Find and claim the entry under lock
    KIRQL irql;
    KeAcquireSpinLock(&g_PendingLock, &irql);
    for (int i = 0; i < MAX_SIG_RESTORE; i++) {
        if (g_SigRestores[i].used && g_SigRestores[i].pid == pid) {
            origFlags  = g_SigRestores[i].originalMitigFlags;
            origSigLvl = g_SigRestores[i].originalSectionSigLvl;
            g_SigRestores[i].used = FALSE;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PendingLock, irql);

    if (!found) return;

    // Patch EPROCESS outside lock (PsLookupProcessByProcessId needs PASSIVE_LEVEL)
    PEPROCESS proc = nullptr;
    if (NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)pid, &proc))) {
        PUCHAR eproc = (PUCHAR)proc;
        *(ULONG*)(eproc + EPROCESS_MITIGATION_FLAGS_OFFSET) = origFlags;
        *(UCHAR*)(eproc + EPROCESS_SECTION_SIGNATURE_LEVEL) = origSigLvl;
        ObDereferenceObject(proc);
        DbgPrint("[+] DllInjector: restored SignaturePolicy for pid=%lu\n", pid);
    }
}

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
    KeInitializeSpinLock(&g_PendingLock);
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

    // -----------------------------------------------------------------------
    // Bypass ProcessSignaturePolicy (blockdlls / ACG) — Adam Chester technique.
    //
    // If the process was created with BLOCK_NON_MICROSOFT_BINARIES, LoadLibraryW
    // will fail with STATUS_INVALID_IMAGE_HASH because our HookDll isn't
    // Microsoft-signed.  We temporarily clear the signature restriction in
    // EPROCESS so our APC succeeds, then restore it from ConfirmInjection().
    //
    // Timing: we're in ImageLoadNotifyRoutine for ntdll.dll — this is the very
    // first image load.  No user code has run yet, so the security window
    // (policy disabled) only covers system DLL loads which are MS-signed anyway.
    // -----------------------------------------------------------------------
    {
        EnsureMitigationResolver();
        if (g_PsGetMitig) {
            DWORD sigFlags = 0;
            if (NT_SUCCESS(g_PsGetMitig(process, 8 /*ProcessSignaturePolicy*/,
                    &sigFlags, sizeof(sigFlags))) &&
                (sigFlags & 0x1)) // bit 0 = MicrosoftSignedOnly
            {
                PUCHAR eproc = (PUCHAR)process;

                // Save original values for restoration
                ULONG origMitigFlags = *(ULONG*)(eproc + EPROCESS_MITIGATION_FLAGS_OFFSET);
                UCHAR origSigLevel   = *(UCHAR*)(eproc + EPROCESS_SECTION_SIGNATURE_LEVEL);

                // Clear SignatureMitigationOptIn (bit 23) in MitigationFlags
                *(ULONG*)(eproc + EPROCESS_MITIGATION_FLAGS_OFFSET) =
                    origMitigFlags & ~(1UL << MITIGATION_SIGNATURE_OPT_IN_BIT);

                // Zero SectionSignatureLevel — remove minimum signature requirement
                *(UCHAR*)(eproc + EPROCESS_SECTION_SIGNATURE_LEVEL) = 0;

                // Record for later restoration
                KIRQL irql;
                KeAcquireSpinLock(&g_PendingLock, &irql);
                for (int i = 0; i < MAX_SIG_RESTORE; i++) {
                    if (!g_SigRestores[i].used) {
                        g_SigRestores[i].pid                 = pid;
                        g_SigRestores[i].originalMitigFlags  = origMitigFlags;
                        g_SigRestores[i].originalSectionSigLvl = origSigLevel;
                        g_SigRestores[i].used                = TRUE;
                        break;
                    }
                }
                KeReleaseSpinLock(&g_PendingLock, irql);

                DbgPrint("[+] DllInjector: cleared SignaturePolicy for pid=%lu "
                         "(MitigFlags=0x%X→0x%X, SectionSigLvl=%u→0) — will restore on confirm\n",
                         pid, origMitigFlags,
                         origMitigFlags & ~(1UL << MITIGATION_SIGNATURE_OPT_IN_BIT),
                         origSigLevel);
            }
        }
    }

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

        // Record pending injection for confirmation tracking
        KIRQL irql;
        KeAcquireSpinLock(&g_PendingLock, &irql);
        for (int i = 0; i < MAX_PENDING_INJECT; i++) {
            if (!g_PendingInjects[i].used) {
                g_PendingInjects[i].pid  = pid;
                KeQuerySystemTimePrecise(&g_PendingInjects[i].queuedTime);
                g_PendingInjects[i].used = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_PendingLock, irql);
    }
}

// ---------------------------------------------------------------------------
// ConfirmInjection — called from IOCTL handler when HookDll reports success.
// Also restores any temporarily-cleared SignaturePolicy flags.
// ---------------------------------------------------------------------------
VOID DllInjector::ConfirmInjection(ULONG pid) {
    KIRQL irql;
    KeAcquireSpinLock(&g_PendingLock, &irql);
    for (int i = 0; i < MAX_PENDING_INJECT; i++) {
        if (g_PendingInjects[i].used && g_PendingInjects[i].pid == pid) {
            g_PendingInjects[i].used = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PendingLock, irql);

    // Restore SignaturePolicy flags if we cleared them for this PID.
    // HookDll is now loaded and hooked — safe to re-enable the policy so the
    // process's intended blockdlls protection applies to all subsequent loads.
    RestoreSigFlags(pid);

    DbgPrint("[+] DllInjector: HookDll confirmed for pid=%lu\n", pid);
}

// ---------------------------------------------------------------------------
// CheckPendingTimeouts — called periodically from a timer work item.
// Emits WARNING for any injection that hasn't been confirmed within 5 seconds.
// ---------------------------------------------------------------------------
VOID DllInjector::CheckPendingTimeouts() {
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);

    const LONGLONG kTimeoutTicks = 5LL * 10000000LL;  // 5 seconds in 100ns units

    KIRQL irql;
    KeAcquireSpinLock(&g_PendingLock, &irql);
    for (int i = 0; i < MAX_PENDING_INJECT; i++) {
        if (!g_PendingInjects[i].used) continue;
        if ((now.QuadPart - g_PendingInjects[i].queuedTime.QuadPart) < kTimeoutTicks)
            continue;

        ULONG pid = g_PendingInjects[i].pid;
        g_PendingInjects[i].used = FALSE;
        KeReleaseSpinLock(&g_PendingLock, irql);

        char msg[200];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "HookDll injection timeout: pid=%lu did not confirm within 5s "
            "— process may be unmonitored (APC race, mitigation policy block, or injection failure)",
            pid);

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
        if (notif) {
            RtlZeroMemory(notif, sizeof(*notif));
            SET_WARNING(*notif);
            SET_IMAGE_LOAD_PATH_CHECK(*notif);
            notif->pid    = (HANDLE)(ULONG_PTR)pid;
            notif->isPath = FALSE;
            SIZE_T msgLen = strlen(msg) + 1;
            notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
            if (notif->msg) {
                RtlCopyMemory(notif->msg, msg, msgLen);
                notif->bufSize = (ULONG)msgLen;
                if (!CallbackObjects::GetNotifQueue()->Enqueue(notif)) {
                    ExFreePool(notif->msg); ExFreePool(notif);
                }
            } else { ExFreePool(notif); }
        }

        // Restore SignaturePolicy flags if we cleared them — injection failed,
        // no reason to leave the process with weakened signature enforcement.
        RestoreSigFlags(pid);

        // Re-acquire and continue scanning
        KeAcquireSpinLock(&g_PendingLock, &irql);
    }
    KeReleaseSpinLock(&g_PendingLock, irql);
}

// ---------------------------------------------------------------------------
// IsOurApc — used by the periodic APC queue scanner to distinguish our own
// HookDll injection APCs from malicious ones.
// Returns TRUE if normalRoutine matches our configured LoadLibraryW address
// AND the PID is one we previously injected into.
// ---------------------------------------------------------------------------
BOOLEAN DllInjector::IsOurApc(PVOID normalRoutine, ULONG pid) {
    if (!g_ConfigSet) return FALSE;
    if (normalRoutine != g_LoadLibraryW) return FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&g_PidLock, &irql);
    for (LONG i = 0; i < g_InjectedCount; i++) {
        if (g_InjectedPids[i] == pid) {
            KeReleaseSpinLock(&g_PidLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_PidLock, irql);
    return FALSE;
}
