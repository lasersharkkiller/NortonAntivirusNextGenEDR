/*
  TokenMonitor.cpp — Logon-session termination callback for token-theft detection.

  Technique background
  ────────────────────
  Token theft (pass-the-token / make-token attacks):

    1. An attacker duplicates or steals a high-privilege token from another
       process (e.g. SYSTEM token from a service) via OpenProcessToken +
       DuplicateToken, or by directly patching the token pointer in EPROCESS.

    2. The victim process or logon session then terminates.  In a normal run
       the OS tears down all tokens whose LogonId matches the dead session.
       A *stolen* token has had its LogonId either retained (impersonation)
       or spoofed, so it may outlive its parent session.

  SeRegisterLogonSessionTerminatedRoutine fires at PASSIVE_LEVEL for every
  logon session teardown.  We use it to:

    a. Walk PsActiveProcessHead looking for any process whose primary token
       still references the just-terminated LogonId.  A SYSTEM-token process
       surviving a non-SYSTEM session teardown is anomalous and warrants a
       Critical alert.

    b. Track impersonation token LogonId mismatches: if a thread holds an
       impersonation token whose LogonId matches a session that just died
       but the thread's process is still running, that is a strong indicator
       of a retained stolen token.

  We implement (a) only, which catches the most common offensive patterns
  (Incognito, mimikatz token::elevate, runas /savecred abuse) without
  requiring undocumented per-thread token enumeration.

  IRQL contract: SeRegisterLogonSessionTerminatedRoutine callback fires at
  PASSIVE_LEVEL.  All kernel APIs used here (PsLookupProcessByProcessId,
  SeQueryInformationToken, etc.) are safe at PASSIVE_LEVEL.
*/

#include "Globals.h"

// PsReferenceImpersonationToken and PsDereferenceImpersonationToken are
// already declared in ntifs.h (included via Globals.h).

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// ---------------------------------------------------------------------------
// Notification helper
// ---------------------------------------------------------------------------

static NotifQueue* s_TokenQueue = nullptr;

static VOID EmitTokenAlert(const char* msg, HANDLE pid, const char* procName)
{
    NotifQueue* q = s_TokenQueue;
    if (!q || !msg) return;

    SIZE_T msgLen = strlen(msg) + 1;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'tokn');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    SET_TOKEN_CHECK(*notif);
    notif->pid    = pid;
    notif->isPath = FALSE;
    if (procName)
        RtlCopyMemory(notif->procName, procName, min(strlen(procName), 14));

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'tkmg');
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
// TOKEN_STATISTICS — partial layout; only LogonId is needed.
// Full struct is defined in ntifs.h but may not be available in all SDKs.
// ---------------------------------------------------------------------------

typedef struct _TOKEN_STATISTICS_PARTIAL {
    LUID TokenId;
    LUID AuthenticationId;   // == LogonId
    // ... (remaining fields not needed)
} TOKEN_STATISTICS_PARTIAL;

// ---------------------------------------------------------------------------
// GetProcessTokenLogonId — retrieve the LogonId from a process's primary token.
// Returns FALSE if anything fails (access denied, paged out, etc.).
// ---------------------------------------------------------------------------

static BOOLEAN GetProcessTokenLogonId(PEPROCESS process, LUID* outLogonId)
{
    if (!process || !outLogonId) return FALSE;

    PACCESS_TOKEN token = PsReferencePrimaryToken(process);
    if (!token) return FALSE;

    TOKEN_STATISTICS_PARTIAL* stats = nullptr;
    NTSTATUS s = SeQueryInformationToken(
        token,
        (TOKEN_INFORMATION_CLASS)10,  // TokenStatistics
        (PVOID*)&stats);

    PsDereferencePrimaryToken(token);

    if (!NT_SUCCESS(s) || !stats) return FALSE;

    *outLogonId = stats->AuthenticationId;
    ExFreePool(stats);          // SeQueryInformationToken allocates from paged pool
    return TRUE;
}

// ---------------------------------------------------------------------------
// LogonSessionTerminatedCallback — called at PASSIVE_LEVEL when a logon
// session is torn down.  Walks all active processes and alerts on any that
// still hold a primary token tied to the now-dead session.
//
// Normal case: all processes in a session exit before (or as part of) the
//              session teardown.  A survivor = potential token theft.
//
// Known false-positive: services running as LocalSystem (LogonId S-1-5-18,
//   AuthenticationId = {0,999}) survive the interactive session teardown.
//   We exclude the well-known SYSTEM LogonId {0, 0x3e7} from alerts.
// ---------------------------------------------------------------------------

static const LUID kSystemLogonId   = { 0x3e7, 0 };   // SYSTEM (S-1-5-18)
static const LUID kLocalSvcLogonId = { 0x3e5, 0 };   // LOCAL SERVICE
static const LUID kNetSvcLogonId   = { 0x3e4, 0 };   // NETWORK SERVICE
static const LUID kAnonLogonId     = { 0x3e6, 0 };   // ANONYMOUS LOGON

static BOOLEAN IsBuiltinLogonId(const LUID* id)
{
    if (!id) return TRUE;
    if (id->HighPart != 0) return FALSE;
    return (id->LowPart == kSystemLogonId.LowPart   ||
            id->LowPart == kLocalSvcLogonId.LowPart ||
            id->LowPart == kNetSvcLogonId.LowPart   ||
            id->LowPart == kAnonLogonId.LowPart);
}

// ---------------------------------------------------------------------------
// GetTokenLogonIdFromToken — retrieve LogonId from a token object directly.
// ---------------------------------------------------------------------------
static BOOLEAN GetTokenLogonId(PACCESS_TOKEN token, LUID* outLogonId)
{
    if (!token || !outLogonId) return FALSE;

    TOKEN_STATISTICS_PARTIAL* stats = nullptr;
    NTSTATUS s = SeQueryInformationToken(
        token, (TOKEN_INFORMATION_CLASS)10, (PVOID*)&stats);
    if (!NT_SUCCESS(s) || !stats) return FALSE;

    *outLogonId = stats->AuthenticationId;
    ExFreePool(stats);
    return TRUE;
}

static NTSTATUS NTAPI LogonSessionTerminatedCallback(_In_ PLUID LogonId)
{
    if (!LogonId) return STATUS_SUCCESS;

    // Skip built-in session teardowns — they are expected to have survivors.
    if (IsBuiltinLogonId(LogonId)) return STATUS_SUCCESS;

    DbgPrint("[TokenMonitor] Logon session terminated: {0x%lX, 0x%lX}\n",
             LogonId->HighPart, LogonId->LowPart);

    // Walk PsActiveProcessHead via ZwQuerySystemInformation (class 5 =
    // SystemProcessInformation) to enumerate all live processes.
    // We cannot safely walk PsActiveProcessHead directly from a callback
    // (requires holding PsLoadedModuleList lock — risk of deadlock).
    // ZwQuerySystemInformation at PASSIVE_LEVEL is safe.

    ULONG bufSize = 0x40000; // 256 KB — enough for most systems
    PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, bufSize, 'tklg');
    if (!buf) return STATUS_SUCCESS;

    NTSTATUS s = ZwQuerySystemInformation(
        SystemProcessInformation,
        buf, bufSize, &bufSize);

    if (!NT_SUCCESS(s)) {
        ExFreePool(buf);
        return STATUS_SUCCESS;
    }

    PSYSTEM_PROCESS_INFORMATION entry =
        (PSYSTEM_PROCESS_INFORMATION)buf;

    ULONG alertCount = 0;

    for (;;) {
        HANDLE pid = entry->UniqueProcessId;

        // Skip System (PID 4) and Idle (PID 0)
        if (pid != nullptr && pid != (HANDLE)4) {
            PEPROCESS proc = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc))) {
                char* procName = PsGetProcessImageFileName(proc);

                // --- (a) Primary token check: process alive, session dead ---
                LUID procLogonId = {};
                if (GetProcessTokenLogonId(proc, &procLogonId)) {
                    if (procLogonId.LowPart  == LogonId->LowPart &&
                        procLogonId.HighPart == LogonId->HighPart)
                    {
                        char  alert[200];
                        RtlStringCbPrintfA(alert, sizeof(alert),
                            "Token theft / orphan token: pid=%llu ('%s') holds token "
                            "for terminated logon session {0x%lX,0x%lX} — "
                            "possible pass-the-token / incognito / make-token attack",
                            (ULONG64)(ULONG_PTR)pid,
                            procName ? procName : "?",
                            LogonId->HighPart, LogonId->LowPart);

                        EmitTokenAlert(alert, pid, procName);
                        alertCount++;
                    }
                }

                // --- (b) Per-thread impersonation token check ---
                // Walk each thread in this process. If any thread holds an
                // impersonation token whose LogonId matches the dead session,
                // the thread is using a stolen token that outlived its source.
                // This catches Incognito/mimikatz token::elevate/impersonation
                // attacks where the thread impersonates but the process primary
                // token doesn't change.
                for (ULONG ti = 0; ti < entry->NumberOfThreads && alertCount < 16; ti++) {
                    HANDLE tid = entry->Threads[ti].ClientId.UniqueThread;
                    PETHREAD thread = nullptr;
                    if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &thread))) {
                        BOOLEAN copyOnOpen = FALSE, effectiveOnly = FALSE;
                        SECURITY_IMPERSONATION_LEVEL impLevel = SecurityAnonymous;

                        PACCESS_TOKEN impToken = PsReferenceImpersonationToken(
                            thread, &copyOnOpen, &effectiveOnly, &impLevel);

                        if (impToken) {
                            LUID impLogonId = {};
                            if (GetTokenLogonId(impToken, &impLogonId)) {
                                if (impLogonId.LowPart == LogonId->LowPart &&
                                    impLogonId.HighPart == LogonId->HighPart)
                                {
                                    char alert[256];
                                    RtlStringCbPrintfA(alert, sizeof(alert),
                                        "Impersonation token theft: pid=%llu ('%s') "
                                        "tid=%llu holds impersonation token (level=%d) "
                                        "for terminated logon session {0x%lX,0x%lX} — "
                                        "stolen token retained on thread",
                                        (ULONG64)(ULONG_PTR)pid,
                                        procName ? procName : "?",
                                        (ULONG64)(ULONG_PTR)tid,
                                        (int)impLevel,
                                        LogonId->HighPart, LogonId->LowPart);

                                    EmitTokenAlert(alert, pid, procName);
                                    alertCount++;
                                }
                            }
                            PsDereferenceImpersonationToken(impToken);
                        }
                        ObDereferenceObject(thread);
                    }
                }

                if (alertCount >= 16) {
                    ObDereferenceObject(proc);
                    break;
                }

                ObDereferenceObject(proc);
            }
        }

        if (!entry->NextEntryOffset) break;
        entry = (PSYSTEM_PROCESS_INFORMATION)
            ((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePool(buf);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// TokenMonitor::Init / Cleanup
// ---------------------------------------------------------------------------

VOID TokenMonitor::Init(NotifQueue* queue)
{
    s_TokenQueue = queue;

    NTSTATUS s = SeRegisterLogonSessionTerminatedRoutine(
        LogonSessionTerminatedCallback);

    if (!NT_SUCCESS(s))
        DbgPrint("[-] TokenMonitor: SeRegisterLogonSessionTerminatedRoutine failed: 0x%x\n", s);
    else
        DbgPrint("[+] TokenMonitor: logon-session termination callback registered\n");
}

VOID TokenMonitor::Cleanup()
{
    SeUnregisterLogonSessionTerminatedRoutine(LogonSessionTerminatedCallback);
    s_TokenQueue = nullptr;
    DbgPrint("[+] TokenMonitor: cleanup complete\n");
}
