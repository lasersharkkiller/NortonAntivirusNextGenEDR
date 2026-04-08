/*
  AntiTamper.cpp — Periodic integrity re-verification and driver self-protection.

  Two mechanisms:

  1. Driver-object reference bump (Init).
     ObReferenceObject on the driver object keeps the reference count above the
     OS unload threshold.  A kernel-mode attacker calling ZwUnloadDriver / using
     a vulnerable driver to invoke NtUnloadDriver will succeed in issuing the
     unload request but the driver will not actually be freed until our extra
     reference is released in Cleanup().  This forces a two-step bypass (unload +
     patch memory directly) rather than a clean single-call eviction.

  2. Periodic PASSIVE_LEVEL integrity checks (every 30 s).
     A synchronization timer fires a DPC every 30 seconds.  The DPC queues a
     delayed system worker thread at PASSIVE_LEVEL.  The worker re-runs:
       - SSDT baseline comparison        (CheckSsdtIntegrity)
       - Kernel ntoskrnl inline hooks    (ScanKernelInlineHooks)
       - Kernel ntoskrnl EAT hooks       (ScanKernelEatHooks)
       - ETW function prologue hooks     (CheckEtwHooks)
       - AltSyscall handler slot check   (CheckAltSyscallHandlerIntegrity)
       - PsLoadedModuleList delink check (CheckModuleVisibility)

  IRQL contract:
     Timer DPC runs at DISPATCH_LEVEL — only queues the work item (no heavy work).
     Work item runs at PASSIVE_LEVEL   — safe for all the checks above.
*/

#include "Globals.h"

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

static KTIMER          s_IntegrityTimer;
static KDPC            s_IntegrityDpc;
static WORK_QUEUE_ITEM s_IntegrityWork;
static volatile LONG   s_WorkPending  = 0;
static PDRIVER_OBJECT  s_DriverObject = nullptr;
static BufferQueue*    s_Queue        = nullptr;

// ---------------------------------------------------------------------------
// EmitAntitamperAlert — enqueue a Critical notification from this module.
// ---------------------------------------------------------------------------

static VOID EmitAntitamperAlert(const char* msg)
{
    BufferQueue* q = s_Queue; // capture before possible null-out
    if (!q || !msg) return;

    SIZE_T msgLen = 0;
    while (msg[msgLen] && msgLen < 255) msgLen++;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'atkn');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    notif->pid    = PsGetProcessId(PsGetCurrentProcess());
    notif->isPath = FALSE;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen + 1, 'atmg');
    if (notif->msg) {
        RtlCopyMemory(notif->msg, msg, msgLen + 1);
        notif->bufSize = (ULONG)(msgLen + 1);
        if (!q->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// EmitKernelCheckAlert — like EmitAntitamperAlert but sets a method4 bit.
// Used for DKOM, DSE, and unsigned module detections.
// ---------------------------------------------------------------------------

typedef VOID (*PFN_SET_METHOD4)(PKERNEL_STRUCTURED_NOTIFICATION);

static VOID SetDkomBit(PKERNEL_STRUCTURED_NOTIFICATION n) { SET_DKOM_CHECK(*n); }
static VOID SetDseBit (PKERNEL_STRUCTURED_NOTIFICATION n) { SET_DSE_BYPASS_CHECK(*n); }
static VOID SetUmodBit(PKERNEL_STRUCTURED_NOTIFICATION n) { SET_UNSIGNED_MODULE_CHECK(*n); }

static VOID EmitKernelCheckAlert(const char* msg, PFN_SET_METHOD4 m4setter)
{
    BufferQueue* q = s_Queue;
    if (!q || !msg) return;

    SIZE_T msgLen = 0;
    while (msg[msgLen] && msgLen < 511) msgLen++;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'kicn');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    if (m4setter) m4setter(notif);
    notif->pid    = 0;
    notif->isPath = FALSE;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen + 1, 'kimg');
    if (notif->msg) {
        RtlCopyMemory(notif->msg, msg, msgLen + 1);
        notif->bufSize = (ULONG)(msgLen + 1);
        if (!q->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// CheckModuleVisibility — verify NortonEDR is still linked in
// PsLoadedModuleList via the DriverSection LDR_DATA_TABLE_ENTRY.
//
// A rootkit hiding a kernel module will unlink the LDTE by setting
// Flink->Blink = Blink and Blink->Flink = Flink (bypassing our entry).
// We detect this by verifying the back-links point back to us.
// ---------------------------------------------------------------------------

static VOID CheckModuleVisibility()
{
    PDRIVER_OBJECT drvObj = s_DriverObject;
    if (!drvObj || !MmIsAddressValid(drvObj)) return;

    __try {
        PLDR_DATA_TABLE_ENTRY ldte =
            (PLDR_DATA_TABLE_ENTRY)drvObj->DriverSection;

        if (!ldte || !MmIsAddressValid(ldte)) {
            EmitAntitamperAlert(
                "ANTI-TAMPER: DriverSection is NULL/invalid — "
                "possible kernel memory corruption");
            return;
        }

        PLIST_ENTRY flink = ldte->InLoadOrderLinks.Flink;
        PLIST_ENTRY blink = ldte->InLoadOrderLinks.Blink;

        if (!MmIsAddressValid(flink) || !MmIsAddressValid(blink)) {
            EmitAntitamperAlert(
                "ANTI-TAMPER: PsLoadedModuleList links are invalid — "
                "kernel rootkit may be corrupting module list");
            return;
        }

        if (flink->Blink != &ldte->InLoadOrderLinks) {
            EmitAntitamperAlert(
                "ANTI-TAMPER: NortonEDR delisted from PsLoadedModuleList "
                "(Flink->Blink mismatch) — kernel rootkit hiding driver");
            return;
        }

        if (blink->Flink != &ldte->InLoadOrderLinks) {
            EmitAntitamperAlert(
                "ANTI-TAMPER: NortonEDR delisted from PsLoadedModuleList "
                "(Blink->Flink mismatch) — kernel rootkit hiding driver");
            return;
        }

        DbgPrint("[+] AntiTamper: module visibility OK\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EmitAntitamperAlert(
            "ANTI-TAMPER: Exception reading PsLoadedModuleList links — "
            "possible memory corruption or active attack");
    }
}

// ---------------------------------------------------------------------------
// CheckDkomHiding — cross-reference EPROCESS kernel list vs ZwQSI(5) API.
//
// A DKOM rootkit unlinks EPROCESS.ActiveProcessLinks so the process is absent
// from ZwQuerySystemInformation(SystemProcessInformation=5) but still present
// in the kernel doubly-linked list.  We walk both and diff.
//
// EPROCESS.ActiveProcessLinks offset = 0x448 on Win10 19041 through Win11 22632.
// PsInitialSystemProcess is the list head (System process, PID 4).
// ---------------------------------------------------------------------------

#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x448u
#define DKOM_MAX_PROCS 1024u

static VOID CheckDkomHiding()
{
    // --- Build kernel-visible PID set by walking ActiveProcessLinks ---
    ULONG kernelPids[DKOM_MAX_PROCS] = {};
    ULONG kernelCount = 0;

    __try {
        PLIST_ENTRY head = (PLIST_ENTRY)
            ((ULONG_PTR)PsInitialSystemProcess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);
        PLIST_ENTRY entry = head->Flink;

        while (entry != head && kernelCount < DKOM_MAX_PROCS) {
            if (!MmIsAddressValid(entry)) break;
            PEPROCESS proc = (PEPROCESS)
                ((ULONG_PTR)entry - EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);
            HANDLE pid = PsGetProcessId(proc);
            kernelPids[kernelCount++] = HandleToUlong(pid);
            entry = entry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] DKOM check: exception walking ActiveProcessLinks\n");
        return;
    }

    if (kernelCount == 0) return;

    // --- Query API-visible PIDs via ZwQuerySystemInformation(5) ---
    ULONG bufferSize = 256 * 1024;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'dkqb');
    if (!buffer) return;

    ULONG retLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(5, buffer, bufferSize, &retLen);
    if (status == STATUS_INFO_LENGTH_MISMATCH && retLen > bufferSize) {
        ExFreePool(buffer);
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, retLen, 'dkqb');
        if (!buffer) return;
        bufferSize = retLen;
        status = ZwQuerySystemInformation(5, buffer, bufferSize, &retLen);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        DbgPrint("[-] DKOM check: ZwQuerySystemInformation failed 0x%x\n", status);
        return;
    }

    // Build API PID set
    ULONG apiPids[DKOM_MAX_PROCS] = {};
    ULONG apiCount = 0;

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (apiCount < DKOM_MAX_PROCS) {
        apiPids[apiCount++] = HandleToUlong(spi->UniqueProcessId);
        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)spi + spi->NextEntryOffset);
    }

    ExFreePool(buffer);

    // --- Diff: kernel PID not in API list → DKOM hidden ---
    for (ULONG i = 0; i < kernelCount; i++) {
        ULONG kpid = kernelPids[i];
        if (kpid == 0) continue; // idle

        BOOLEAN found = FALSE;
        for (ULONG j = 0; j < apiCount; j++) {
            if (apiPids[j] == kpid) { found = TRUE; break; }
        }

        if (!found) {
            PEPROCESS proc = nullptr;
            char msgBuf[220];
            if (NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(kpid), &proc))) {
                RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
                    "DKOM: process '%s' (pid=%lu) hidden from ZwQuerySystemInformation — "
                    "EPROCESS unlinked from ActiveProcessLinks",
                    PsGetProcessImageFileName(proc), kpid);
                ObDereferenceObject(proc);
            } else {
                RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
                    "DKOM: pid=%lu hidden from ZwQuerySystemInformation — "
                    "EPROCESS unlinked from ActiveProcessLinks", kpid);
            }
            EmitKernelCheckAlert(msgBuf, SetDkomBit);
        }
    }

    DbgPrint("[+] AntiTamper: DKOM check complete (%lu kernel / %lu API procs)\n",
             kernelCount, apiCount);
}

// ---------------------------------------------------------------------------
// CheckDseIntegrity — read g_CiEnabled from ci.dll's export table.
//
// g_CiEnabled is a DWORD in ci.dll that CI reads on each load decision.
// Patching it to 0 disables driver signature enforcement for the remainder of
// the boot session.  We read it from the live in-memory PE export table.
//
// Expected value: non-zero (typically 6 in normal production mode).
// Suspicious:     0 → DSE fully disabled.
// ---------------------------------------------------------------------------

static VOID CheckDseIntegrity()
{
    __try {
        // --- Find ci.dll in PsLoadedModuleList ---
        PLIST_ENTRY head  = PsLoadedModuleList;
        PLIST_ENTRY entry = head->Flink;
        PVOID ciBase = nullptr;

        while (entry != head) {
            if (!MmIsAddressValid(entry)) break;
            PLDR_DATA_TABLE_ENTRY ldte =
                CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (ldte->BaseDllName.Buffer &&
                ldte->BaseDllName.Length >= 6 * 2 /* "ci.dll" = 6 chars */ ) {

                // Case-insensitive match on the short name
                WCHAR lower[16] = {};
                USHORT copyLen = min(ldte->BaseDllName.Length / sizeof(WCHAR), 15u);
                for (USHORT i = 0; i < copyLen; i++) {
                    WCHAR c = ldte->BaseDllName.Buffer[i];
                    lower[i] = (c >= L'A' && c <= L'Z') ? c + 32 : c;
                }
                if (lower[0] == L'c' && lower[1] == L'i' &&
                    lower[2] == L'.' && lower[3] == L'd' &&
                    lower[4] == L'l' && lower[5] == L'l' && lower[6] == 0) {
                    ciBase = ldte->DllBase;
                    break;
                }
            }
            entry = entry->Flink;
        }

        if (!ciBase || !MmIsAddressValid(ciBase)) {
            DbgPrint("[-] DSE check: ci.dll not found in PsLoadedModuleList\n");
            return;
        }

        // --- Walk PE export table ---
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ciBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)
            ((ULONG_PTR)ciBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        ULONG expDirRva = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!expDirRva) return;

        PIMAGE_EXPORT_DIRECTORY expDir =
            (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ciBase + expDirRva);
        if (!MmIsAddressValid(expDir)) return;

        PULONG  names    = (PULONG) ((ULONG_PTR)ciBase + expDir->AddressOfNames);
        PUSHORT ordinals = (PUSHORT)((ULONG_PTR)ciBase + expDir->AddressOfNameOrdinals);
        PULONG  funcs    = (PULONG) ((ULONG_PTR)ciBase + expDir->AddressOfFunctions);

        PULONG gCiEnabled = nullptr;
        for (ULONG i = 0; i < expDir->NumberOfNames; i++) {
            const char* name = (const char*)((ULONG_PTR)ciBase + names[i]);
            if (!MmIsAddressValid((PVOID)name)) continue;
            if (strcmp(name, "g_CiEnabled") == 0) {
                USHORT ord = ordinals[i];
                gCiEnabled = (PULONG)((ULONG_PTR)ciBase + funcs[ord]);
                break;
            }
        }

        if (!gCiEnabled || !MmIsAddressValid(gCiEnabled)) {
            DbgPrint("[-] DSE check: g_CiEnabled not found in ci.dll exports\n");
            return;
        }

        ULONG ciVal = *gCiEnabled;
        DbgPrint("[+] AntiTamper: g_CiEnabled = %lu\n", ciVal);

        if (ciVal == 0) {
            char msg[160];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "DSE BYPASS: g_CiEnabled in ci.dll = 0 — "
                "driver signature enforcement disabled, unsigned kernel code may be loaded");
            EmitKernelCheckAlert(msg, SetDseBit);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] DSE check: exception reading ci.dll export\n");
    }
}

// ---------------------------------------------------------------------------
// CheckUnsignedModules — walk PsLoadedModuleList for drivers missing the
// LDRP_IMAGE_INTEGRITY_FORCED flag (0x20000000).
//
// CI sets this flag in KLDR_DATA_TABLE_ENTRY.Flags for every image it verifies.
// A driver loaded via DSE bypass, vulnerable driver exploit (BYOVD), or direct
// kernel memory write will lack this flag.
//
// False-positive note: very old legacy-signed drivers (pre-Win10) may not have
// this flag.  Whitelist ntoskrnl.exe and hal.dll which are loaded before CI.
// ---------------------------------------------------------------------------

#define LDRP_IMAGE_INTEGRITY_FORCED 0x20000000u

// Modules loaded before CI initialises — they legitimately lack the flag.
static const WCHAR* kPreCiModules[] = {
    L"ntoskrnl.exe", L"ntkrnlmp.exe", L"ntkrnlpa.exe", L"ntkrpamp.exe",
    L"hal.dll",
    nullptr
};

static BOOLEAN IsPreCiModule(PCUNICODE_STRING name)
{
    if (!name || !name->Buffer) return FALSE;
    for (int i = 0; kPreCiModules[i]; i++) {
        UNICODE_STRING candidate;
        RtlInitUnicodeString(&candidate, kPreCiModules[i]);
        if (RtlEqualUnicodeString(name, &candidate, TRUE)) return TRUE;
    }
    return FALSE;
}

static VOID CheckUnsignedModules()
{
    __try {
        PLIST_ENTRY head  = PsLoadedModuleList;
        PLIST_ENTRY entry = head->Flink;

        while (entry != head) {
            if (!MmIsAddressValid(entry)) break;
            PLDR_DATA_TABLE_ENTRY ldte =
                CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            // Skip entries with invalid DllBase or zero size
            if (!ldte->DllBase || ldte->SizeOfImage == 0) {
                entry = entry->Flink;
                continue;
            }

            // Skip pre-CI bootstrap modules
            if (IsPreCiModule(&ldte->BaseDllName)) {
                entry = entry->Flink;
                continue;
            }

            if (!(ldte->Flags & LDRP_IMAGE_INTEGRITY_FORCED)) {
                char modName[64] = "<unknown>";
                if (ldte->BaseDllName.Buffer && ldte->BaseDllName.Length > 0) {
                    ULONG copyLen = min(
                        (ULONG)(ldte->BaseDllName.Length / sizeof(WCHAR)), 63u);
                    for (ULONG i = 0; i < copyLen; i++) {
                        WCHAR c = ldte->BaseDllName.Buffer[i];
                        modName[i] = (c < 128) ? (char)c : '?';
                    }
                    modName[copyLen] = '\0';
                }

                char msg[220];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "UNSIGNED MODULE: '%s' at 0x%llX size=0x%lX — "
                    "LDRP_IMAGE_INTEGRITY_FORCED not set; possible BYOVD/rootkit payload",
                    modName,
                    (ULONG64)ldte->DllBase,
                    ldte->SizeOfImage);

                EmitKernelCheckAlert(msg, SetUmodBit);
            }

            entry = entry->Flink;
        }

        DbgPrint("[+] AntiTamper: unsigned module check complete\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] Unsigned module check: exception\n");
    }
}

// ---------------------------------------------------------------------------
// IntegrityWorkRoutine — runs at PASSIVE_LEVEL via system worker thread.
// Executes the full hook / integrity check suite.
// ---------------------------------------------------------------------------

static VOID IntegrityWorkRoutine(PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    // Allow the next DPC to enqueue another work item immediately.
    InterlockedExchange(&s_WorkPending, 0);

    // Bail out if Cleanup() has already been called.
    if (!s_Queue) return;

    DbgPrint("[*] AntiTamper: running periodic integrity check\n");

    // --- Hook checks (SSDT, inline, EAT, ETW, AltSyscall handler) ---
    SsdtUtils ssdtUtils;
    PVOID moduleBase = ssdtUtils.GetKernelBaseAddress();
    if (moduleBase) {
        FUNCTION_MAP kExports = ssdtUtils.GetAndStoreKernelExports(moduleBase);
        HookDetector::RunAllHookChecks(&kExports, moduleBase, s_Queue);
    } else {
        DbgPrint("[-] AntiTamper: could not resolve kernel base\n");
    }

    // --- PsLoadedModuleList delink detection ---
    CheckModuleVisibility();

    // --- DKOM process hiding detection ---
    CheckDkomHiding();

    // --- DSE (Code Integrity) bypass detection ---
    CheckDseIntegrity();

    // --- Unsigned kernel module detection ---
    CheckUnsignedModules();

    DbgPrint("[*] AntiTamper: periodic check complete\n");
}

// ---------------------------------------------------------------------------
// IntegrityDpc — fires at DISPATCH_LEVEL every 30 seconds.
// Only enqueues the work item; does no heavy lifting itself.
// ---------------------------------------------------------------------------

static VOID IntegrityDpc(
    PKDPC  Dpc,
    PVOID  ctx,
    PVOID  arg1,
    PVOID  arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    // Use compare-exchange so we never queue two concurrent work items.
    if (InterlockedCompareExchange(&s_WorkPending, 1, 0) == 0) {
        ExQueueWorkItem(&s_IntegrityWork, DelayedWorkQueue);
    }
}

// ---------------------------------------------------------------------------
// AntiTamper::Init
// ---------------------------------------------------------------------------

VOID AntiTamper::Init(PDRIVER_OBJECT driverObject, BufferQueue* queue)
{
    if (!driverObject || !queue) return;

    s_DriverObject = driverObject;
    s_Queue        = queue;

    // Hold an extra reference on the driver object.  The OS will not free the
    // driver until every reference is released.  An attacker calling
    // ZwUnloadDriver triggers DriverUnload but cannot complete the teardown
    // until our Cleanup() releases this reference — buying detection time.
    ObReferenceObject(driverObject);

    // Set up the periodic work machinery.
    ExInitializeWorkItem(&s_IntegrityWork, IntegrityWorkRoutine, nullptr);
    KeInitializeDpc(&s_IntegrityDpc, IntegrityDpc, nullptr);
    KeInitializeTimer(&s_IntegrityTimer);

    // Arm: first fire after 60 s, then every 30 s.
    // 100-nanosecond units; negative = relative time.
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -600000000LL; // 60 seconds
    KeSetTimerEx(&s_IntegrityTimer, dueTime, 30000, &s_IntegrityDpc);

    DbgPrint("[+] AntiTamper: initialized — 30 s periodic integrity check, driver refcount bumped\n");
}

// ---------------------------------------------------------------------------
// AntiTamper::Cleanup — cancel timer and release the extra reference.
// Called from UnloadDriver at PASSIVE_LEVEL.
// ---------------------------------------------------------------------------

VOID AntiTamper::Cleanup()
{
    // Signal any in-progress or pending work items to exit early.
    s_Queue = nullptr;

    // Stop the timer from firing again.
    KeCancelTimer(&s_IntegrityTimer);

    // Wait for any DPC that was already queued to drain.  After this call
    // no new DPCs from our timer can run.
    KeFlushQueuedDpcs();

    // Release the extra object reference taken in Init.
    if (s_DriverObject) {
        ObDereferenceObject(s_DriverObject);
        s_DriverObject = nullptr;
    }

    DbgPrint("[+] AntiTamper: cleanup complete\n");
}
