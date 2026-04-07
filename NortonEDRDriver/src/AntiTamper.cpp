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
