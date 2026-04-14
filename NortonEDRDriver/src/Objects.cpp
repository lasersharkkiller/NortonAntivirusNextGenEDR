#include "Globals.h"

// ---------------------------------------------------------------------------
// Static member definition
// ---------------------------------------------------------------------------

volatile LONG ObjectUtils::g_ServicePid = 0;

// ---------------------------------------------------------------------------
// Sensitive process list — handles to these processes receive extra scrutiny.
// Matched case-insensitively against the 15-char ANSI image filename.
// ---------------------------------------------------------------------------

static const char* kSensitiveProcesses[] = {
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "spoolsv.exe",     // Print Spooler — PrintNightmare (CVE-2021-34527) LPE target
    nullptr
};

BOOLEAN ObjectUtils::IsSensitiveProcess(PEPROCESS proc)
{
    if (!proc) return FALSE;
    char* name = PsGetProcessImageFileName(proc);
    if (!name) return FALSE;

    char lower[16] = {};
    for (int i = 0; i < 15 && name[i]; i++)
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];

    for (int i = 0; kSensitiveProcesses[i]; i++) {
        if (strcmp(lower, kSensitiveProcesses[i]) == 0) return TRUE;
    }
    return FALSE;
}

BOOLEAN ObjectUtils::IsLsass(PEPROCESS proc)
{
    if (!proc) return FALSE;
    char* name = PsGetProcessImageFileName(proc);
    if (!name) return FALSE;
    char lower[16] = {};
    for (int i = 0; i < 15 && name[i]; i++)
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];
    return strcmp(lower, "lsass.exe") == 0;
}

// ---------------------------------------------------------------------------
// EmitObjectAlert — enqueue a notification from an object callback.
// May be called at PASSIVE_LEVEL or APC_LEVEL (OB callbacks run at APC).
// ---------------------------------------------------------------------------

static VOID EmitObjectAlert(
    PEPROCESS callerProc,
    PEPROCESS targetProc,
    ACCESS_MASK original,
    ACCESS_MASK stripped,
    const char*  detail,
    BOOLEAN      critical)
{
    NotifQueue* q = CallbackObjects::GetNotifQueue();
    if (!q) return;

    char msg[240];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "%s: caller='%s' target='%s' original=0x%08lX stripped=0x%08lX — %s",
        critical ? "CRITICAL" : "WARNING",
        callerProc  ? PsGetProcessImageFileName(callerProc)  : "?",
        targetProc  ? PsGetProcessImageFileName(targetProc)  : "?",
        original, stripped, detail);

    SIZE_T msgLen = strlen(msg) + 1;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'obnt');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    if (critical) { SET_CRITICAL(*notif); } else { SET_WARNING(*notif); }
    SET_OBJECT_CHECK(*notif);
    notif->pid    = callerProc ? PsGetProcessId(callerProc) : 0;
    notif->isPath = FALSE;

    if (callerProc)
        RtlCopyMemory(notif->procName,
                      PsGetProcessImageFileName(callerProc), 14);
    if (targetProc)
        RtlCopyMemory(notif->targetProcName,
                      PsGetProcessImageFileName(targetProc), 14);

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'obmg');
    notif->bufSize = (ULONG)msgLen;
    if (notif->msg) {
        RtlCopyMemory(notif->msg, msg, msgLen);
        if (!q->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// ProcessPreCallback — OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
// on PsProcessType.
//
// Rights stripped per caller/target combination:
//
//  1. Self-protection (target == EDR service PID):
//       Strip PROCESS_TERMINATE, PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
//             PROCESS_SUSPEND_RESUME, PROCESS_SET_INFORMATION
//       from any unprotected caller (PPL Level == 0).
//       → Prevents taskkill / memory injection / process suspension of NortonEDR.
//
//  2. Injection-rights strip (cross-process to any target from unprotected caller):
//       Strip PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD,
//             PROCESS_SUSPEND_RESUME
//       → Prevents process injection and shellcode staging by unprivileged callers.
//       Only enforced when caller != target (self-writes are normal).
//
//  3. Sensitive-process PROCESS_VM_READ (credential dumping):
//       Strip PROCESS_VM_READ when target is lsass/csrss/smss/wininit/winlogon/services
//       and caller has PPL Level == 0.
//       → The original lsass-specific check, extended to all sensitive processes.
//
//  4. Handle duplication:
//       Same rules applied to OB_OPERATION_HANDLE_DUPLICATE so that duplicating
//       an existing handle with elevated rights doesn't bypass the create filter.
// ---------------------------------------------------------------------------

OB_PREOP_CALLBACK_STATUS ObjectUtils::ProcessPreCallback(
    PVOID                      RegContext,
    POB_PRE_OPERATION_INFORMATION OpInfo)
{
    UNREFERENCED_PARAMETER(RegContext);

    PEPROCESS targetProc  = (PEPROCESS)OpInfo->Object;
    PEPROCESS callerProc  = IoGetCurrentProcess();

    // Never restrict kernel or PPL callers — they are trusted.
    PPS_PROTECTION callerProt = PsGetProcessProtection(callerProc);
    if (callerProt && callerProt->Level != 0) return OB_PREOP_SUCCESS;

    // Ignore self-to-self and kernel-to-any.
    if (targetProc == callerProc) return OB_PREOP_SUCCESS;

    // Resolve the access mask for create vs. duplicate.
    ACCESS_MASK* pAccess = (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        ? &OpInfo->Parameters->CreateHandleInformation.DesiredAccess
        : &OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;

    ACCESS_MASK original = *pAccess;
    ACCESS_MASK toStrip  = 0;

    // -----------------------------------------------------------------------
    // Rule 1: Self-protection — protect the EDR service process.
    // -----------------------------------------------------------------------
    ULONG svcPid = (ULONG)InterlockedCompareExchange(&g_ServicePid, 0, 0);
    if (svcPid != 0 &&
        HandleToUlong(PsGetProcessId(targetProc)) == svcPid)
    {
        // Strip all useful attack rights from the service process handle.
        // PROCESS_SET_QUOTA is required by NtAssignProcessToJobObject —
        // stripping it prevents job-object kill (KILL_ON_JOB_CLOSE) attacks.
        const ACCESS_MASK kProtectMask =
            PROCESS_TERMINATE       |
            PROCESS_VM_WRITE        |
            PROCESS_VM_OPERATION    |
            PROCESS_SUSPEND_RESUME  |
            PROCESS_SET_INFORMATION |
            PROCESS_SET_QUOTA;

        toStrip = original & kProtectMask;
        if (toStrip) {
            *pAccess &= ~toStrip;
            EmitObjectAlert(callerProc, targetProc, original, toStrip,
                "EDR self-protection: dangerous rights stripped from NortonEDR service handle",
                TRUE);
        }
        return OB_PREOP_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Rule 2: Injection-rights strip — cross-process handle to any process.
    // Strip rights that enable code injection and process suspension.
    // -----------------------------------------------------------------------
    const ACCESS_MASK kInjectMask =
        PROCESS_VM_WRITE        |
        PROCESS_VM_OPERATION    |
        PROCESS_CREATE_THREAD   |
        PROCESS_SUSPEND_RESUME;

    ACCESS_MASK injectRights = original & kInjectMask;
    if (injectRights) {
        toStrip  |= injectRights;
        *pAccess &= ~injectRights;

        BOOLEAN isSensitive = IsSensitiveProcess(targetProc);
        EmitObjectAlert(callerProc, targetProc, original, injectRights,
            isSensitive
                ? "Injection rights stripped from handle to sensitive OS process"
                : "Cross-process injection rights stripped (VM_WRITE/CREATE_THREAD/SUSPEND)",
            isSensitive /* Critical if targeting sensitive process, Warning otherwise */);
    }

    // -----------------------------------------------------------------------
    // Rule 3: PROCESS_VM_READ on sensitive processes (credential dumping).
    // -----------------------------------------------------------------------
    if ((original & PROCESS_VM_READ) && IsSensitiveProcess(targetProc)) {
        *pAccess &= ~PROCESS_VM_READ;
        toStrip  |= PROCESS_VM_READ;
        EmitObjectAlert(callerProc, targetProc, original, PROCESS_VM_READ,
            "PROCESS_VM_READ stripped from handle to sensitive OS process (credential dump attempt)",
            IsLsass(targetProc) /* lsass = Critical, others = Warning */);
    }

    // -----------------------------------------------------------------------
    // Rule 3b: Enhanced LSASS protection — restrict additional rights used by
    // credential dumping tools (Tanium gap: 47 undetected credential dumps, 97.9% miss rate).
    // Strip PROCESS_QUERY_INFORMATION and SYNCHRONIZE from LSASS handles to
    // prevent procdump, mimikatz, and other dumpers from querying process state.
    // -----------------------------------------------------------------------
    if (IsLsass(targetProc)) {
        const ACCESS_MASK kLsassQueryMask =
            PROCESS_QUERY_INFORMATION |  // Mimikatz uses this to query process handles
            PROCESS_QUERY_LIMITED_INFORMATION |  // procdump enumeration
            SYNCHRONIZE;  // Some dumpers wait on process handle

        ACCESS_MASK lsassRights = original & kLsassQueryMask;
        if (lsassRights && !(toStrip & lsassRights)) {
            *pAccess &= ~lsassRights;
            toStrip  |= lsassRights;
            EmitObjectAlert(callerProc, targetProc, original, lsassRights,
                "LSASS access rights restricted — QUERY_INFORMATION/SYNCHRONIZE stripped (credential dumping protection)",
                TRUE /* Critical */);
        }
    }

    // -----------------------------------------------------------------------
    // Rule 4: PROCESS_VM_READ on any foreign process — visibility into memory
    // scraping even when target is not a "sensitive" OS process.
    // Only alert — don't strip. The caller may have a legitimate reason
    // (debugger, profiler). We want visibility, not breakage.
    // -----------------------------------------------------------------------
    if ((original & PROCESS_VM_READ) && !IsSensitiveProcess(targetProc) && !toStrip) {
        EmitObjectAlert(callerProc, targetProc, original, 0 /*nothing stripped*/,
            "PROCESS_VM_READ on foreign process — possible memory scraping / credential harvest",
            FALSE /* Warning */);
    }

    return OB_PREOP_SUCCESS;
}

// ---------------------------------------------------------------------------
// ThreadPreCallback — OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
// on PsThreadType.
//
// Strips THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, and THREAD_GET_CONTEXT
// from cross-process handles targeting threads inside sensitive processes.
// These rights are the core of thread-hijack / pass-the-hash / SetThreadContext
// injection techniques.
//
// This replaces the previous post-callback which only emitted an alert without
// stripping the right.
// ---------------------------------------------------------------------------

OB_PREOP_CALLBACK_STATUS ObjectUtils::ThreadPreCallback(
    PVOID                      RegContext,
    POB_PRE_OPERATION_INFORMATION OpInfo)
{
    UNREFERENCED_PARAMETER(RegContext);

    PETHREAD  targetThread  = (PETHREAD)OpInfo->Object;
    PEPROCESS targetProc    = IoThreadToProcess(targetThread);
    PEPROCESS callerProc    = IoGetCurrentProcess();

    // Never restrict kernel or PPL callers.
    PPS_PROTECTION callerProt = PsGetProcessProtection(callerProc);
    if (callerProt && callerProt->Level != 0) return OB_PREOP_SUCCESS;

    // Skip same-process thread access — normal.
    if (targetProc == callerProc) return OB_PREOP_SUCCESS;

    // Only enforce against threads inside sensitive OS processes.
    if (!IsSensitiveProcess(targetProc)) return OB_PREOP_SUCCESS;

    ACCESS_MASK* pAccess = (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        ? &OpInfo->Parameters->CreateHandleInformation.DesiredAccess
        : &OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;

    ACCESS_MASK original = *pAccess;

    // Rights that enable thread hijacking / context manipulation.
    const ACCESS_MASK kThreadAbuseMask =
        THREAD_SET_CONTEXT      |  // SetThreadContext — classic thread hijack
        THREAD_GET_CONTEXT      |  // GetThreadContext — credential scraping
        THREAD_SUSPEND_RESUME;     // SuspendThread/ResumeThread — execution control

    ACCESS_MASK toStrip = original & kThreadAbuseMask;
    if (!toStrip) return OB_PREOP_SUCCESS;

    *pAccess &= ~toStrip;

    char detail[120];
    RtlStringCbPrintfA(detail, sizeof(detail),
        "Thread handle rights stripped targeting %s thread (hijack/context-scrape prevention)",
        PsGetProcessImageFileName(targetProc));

    EmitObjectAlert(callerProc, targetProc, original, toStrip,
        detail, IsLsass(targetProc));

    return OB_PREOP_SUCCESS;
}

// ---------------------------------------------------------------------------
// PostOperationCallback — kept for compatibility; thread post-callback no
// longer needed since we now strip rights in the pre-callback.
// ---------------------------------------------------------------------------

POB_POST_OPERATION_CALLBACK ObjectUtils::PostOperationCallback(
    PVOID                       RegContext,
    POB_POST_OPERATION_INFORMATION OpInfo)
{
    UNREFERENCED_PARAMETER(RegContext);
    UNREFERENCED_PARAMETER(OpInfo);
    return 0;
}

// ---------------------------------------------------------------------------
// Legacy wrappers — bodies kept so existing callers that reference them
// directly (if any) still compile.  Both delegate to the new callbacks.
// ---------------------------------------------------------------------------

BOOLEAN ObjectUtils::isCredentialDumpAttempt(POB_PRE_OPERATION_INFORMATION OpInfo)
{
    PEPROCESS targetProc = (PEPROCESS)OpInfo->Object;
    if (PsGetProcessId(targetProc) == PsGetProcessId(IoGetCurrentProcess()))
        return FALSE;
    if (!IsLsass(targetProc)) return FALSE;
    if (OpInfo->Operation != OB_OPERATION_HANDLE_CREATE) return FALSE;
    PPS_PROTECTION prot = PsGetProcessProtection(IoGetCurrentProcess());
    if (prot && prot->Level != 0) return FALSE;
    return (OpInfo->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_READ) != 0;
}

BOOLEAN ObjectUtils::isRemoteContextMapipulation(POB_POST_OPERATION_INFORMATION OpInfo)
{
    // Preserved for any external callers; the real enforcement is now in ThreadPreCallback.
    if (OpInfo->Operation != OB_OPERATION_HANDLE_CREATE) return FALSE;
    PETHREAD  thread = (PETHREAD)OpInfo->Object;
    PEPROCESS proc   = IoThreadToProcess(thread);
    if (proc == IoGetCurrentProcess()) return FALSE;
    if (!IsLsass(proc)) return FALSE;
    PPS_PROTECTION prot = PsGetProcessProtection(IoGetCurrentProcess());
    if (prot && prot->Level != 0) return FALSE;
    return (OpInfo->Parameters->CreateHandleInformation.GrantedAccess & THREAD_SET_CONTEXT) != 0;
}

// ---------------------------------------------------------------------------
// setObjectNotificationCallback — register process + thread OB callbacks,
// covering both HANDLE_CREATE and HANDLE_DUPLICATE operations.
// ---------------------------------------------------------------------------

VOID ObjectUtils::setObjectNotificationCallback()
{
    NTSTATUS status;

    // --- Registration 1: Process handle pre-callback ---
    // Covers HANDLE_CREATE and HANDLE_DUPLICATE so that duplicating a handle
    // with escalated rights is caught the same as opening one fresh.
    RtlInitUnicodeString(&altitude, ALTITUDE);

    regPreOpRegistration.ObjectType = PsProcessType;
    regPreOpRegistration.Operations = OB_OPERATION_HANDLE_CREATE |
                                      OB_OPERATION_HANDLE_DUPLICATE;
    regPreOpRegistration.PreOperation  = ProcessPreCallback;
    regPreOpRegistration.PostOperation = NULL;

    objOpCallbackRegistration1.Version                    = OB_FLT_REGISTRATION_VERSION;
    objOpCallbackRegistration1.OperationRegistrationCount = 1;
    objOpCallbackRegistration1.Altitude                   = altitude;
    objOpCallbackRegistration1.RegistrationContext        = NULL;
    objOpCallbackRegistration1.OperationRegistration      = &regPreOpRegistration;

    status = ObRegisterCallbacks(&objOpCallbackRegistration1, &regHandle1);
    if (!NT_SUCCESS(status))
        DbgPrint("[-] ObRegisterCallbacks (process) failed: 0x%x\n", status);
    else
        DbgPrint("[+] ObRegisterCallbacks (process) success\n");

    // --- Registration 2: Thread handle pre-callback ---
    UNICODE_STRING altitude2;
    RtlInitUnicodeString(&altitude2, L"300022");

    threadPreOpRegistration.ObjectType = PsThreadType;
    threadPreOpRegistration.Operations = OB_OPERATION_HANDLE_CREATE |
                                         OB_OPERATION_HANDLE_DUPLICATE;
    threadPreOpRegistration.PreOperation  = ThreadPreCallback;
    threadPreOpRegistration.PostOperation = NULL;

    objOpCallbackRegistration2.Version                    = OB_FLT_REGISTRATION_VERSION;
    objOpCallbackRegistration2.OperationRegistrationCount = 1;
    objOpCallbackRegistration2.Altitude                   = altitude2;
    objOpCallbackRegistration2.RegistrationContext        = NULL;
    objOpCallbackRegistration2.OperationRegistration      = &threadPreOpRegistration;

    status = ObRegisterCallbacks(&objOpCallbackRegistration2, &regHandle2);
    if (!NT_SUCCESS(status))
        DbgPrint("[-] ObRegisterCallbacks (thread) failed: 0x%x\n", status);
    else
        DbgPrint("[+] ObRegisterCallbacks (thread) success\n");
}

VOID ObjectUtils::unsetObjectNotificationCallback()
{
    if (regHandle1) {
        ObUnRegisterCallbacks(regHandle1);
        DbgPrint("[+] ObUnRegisterCallbacks (process) success\n");
        regHandle1 = nullptr;
    }
    if (regHandle2) {
        ObUnRegisterCallbacks(regHandle2);
        DbgPrint("[+] ObUnRegisterCallbacks (thread) success\n");
        regHandle2 = nullptr;
    }
}
