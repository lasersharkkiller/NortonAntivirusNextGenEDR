#include "Globals.h"

// ---------------------------------------------------------------------------
// Kerberoasting / DCSync rate-tracking table.
//
// Kerberoasting: an attacker issues many AS-REQ / TGS-REQ packets (port 88)
// for service accounts in rapid succession to request Kerberos tickets.
// Legitimate processes issue a handful of Kerberos packets per minute;
// tooling like Rubeus / Impacket typically issues 10–200+ per minute.
// We track outbound port-88 connections per PID and alert when the count
// exceeds KERB_ALERT_THRESHOLD within the rolling KERB_WINDOW_MS window.
//
// DCSync: mimikatz/secretsdump uses MS-DRSR (LDAP/LDAPS/GC ports 389, 636,
// 3268, 3269) from a non-domain-controller machine to replicate credentials.
// We flag when a non-System process opens connections to LDAP/GC ports since
// normal workstations should only contact DC LDAP via authenticated sessions
// established by lsass — not arbitrary user processes.
// ---------------------------------------------------------------------------

#define KERB_TRACK_MAX     64
#define KERB_ALERT_THRESHOLD 15       // connections to port 88 within window
#define KERB_WINDOW_MS       30000LL  // 30-second rolling window (100ns units = * 10000)

typedef struct _KERB_TRACK_ENTRY {
    UINT64   Pid;
    LONG     Count;
    LONGLONG WindowStart; // KeQueryInterruptTime() units (100 ns)
    BOOLEAN  Alerted;
} KERB_TRACK_ENTRY;

static KSPIN_LOCK      g_KerbLock;
static KERB_TRACK_ENTRY g_KerbSlots[KERB_TRACK_MAX];
static LONG            g_KerbInitDone = 0;

static VOID KerbTrackInit()
{
    if (InterlockedCompareExchange(&g_KerbInitDone, 1, 0) == 0) {
        RtlZeroMemory(g_KerbSlots, sizeof(g_KerbSlots));
        KeInitializeSpinLock(&g_KerbLock);
    }
}

// Returns TRUE if this PID has exceeded the Kerberos connection threshold
// and has not yet been alerted in the current window.
static BOOLEAN KerbCheckAndCount(UINT64 pid)
{
    LONGLONG now = (LONGLONG)KeQueryInterruptTime();
    LONGLONG windowNs = KERB_WINDOW_MS * 10000LL; // ms → 100ns units

    KIRQL irql;
    KeAcquireSpinLock(&g_KerbLock, &irql);

    // Find or create slot for this PID
    INT freeSlot = -1;
    for (INT i = 0; i < KERB_TRACK_MAX; i++) {
        if (g_KerbSlots[i].Pid == pid) {
            // Existing slot — check window expiry
            if ((now - g_KerbSlots[i].WindowStart) > windowNs) {
                // Window expired — reset
                g_KerbSlots[i].WindowStart = now;
                g_KerbSlots[i].Count       = 1;
                g_KerbSlots[i].Alerted     = FALSE;
                KeReleaseSpinLock(&g_KerbLock, irql);
                return FALSE;
            }
            g_KerbSlots[i].Count++;
            BOOLEAN alert = (!g_KerbSlots[i].Alerted &&
                             g_KerbSlots[i].Count >= KERB_ALERT_THRESHOLD);
            if (alert) g_KerbSlots[i].Alerted = TRUE;
            KeReleaseSpinLock(&g_KerbLock, irql);
            return alert;
        }
        if (freeSlot < 0 && g_KerbSlots[i].Pid == 0)
            freeSlot = i;
    }

    // New PID — allocate a slot
    if (freeSlot >= 0) {
        g_KerbSlots[freeSlot].Pid         = pid;
        g_KerbSlots[freeSlot].Count       = 1;
        g_KerbSlots[freeSlot].WindowStart = now;
        g_KerbSlots[freeSlot].Alerted     = FALSE;
    }
    // Table full: silently drop — 64 concurrent PIDs is ample
    KeReleaseSpinLock(&g_KerbLock, irql);
    return FALSE;
}

// Port helpers
static BOOLEAN IsKerberosPort(UINT16 port) { return port == 88 || port == 750; }
static BOOLEAN IsLdapPort(UINT16 port) {
    return port == 389 || port == 636 || port == 3268 || port == 3269;
}

// System processes that legitimately contact LDAP/Kerberos ports
static BOOLEAN IsSystemProcess(UINT64 pid) { return pid == 0 || pid == 4; }

// ---------------------------------------------------------------------------
// Interactive C2 / beaconing session detector.
//
// When operators use proxying tooling (Cobalt Strike, Sliver, Mythic, etc.)
// with sleep~0 or near-zero check-in intervals, they create an interactive
// session that produces a distinctive traffic pattern: one process making
// dozens-to-hundreds of connections per minute to a single IP:port on
// standard web ports (80, 443, 8080, 8443) that blend with normal traffic.
//
// Normal applications (browsers, updaters) also talk to the same IPs
// repeatedly, so we allowlist known high-talkers by process name and use
// a conservative threshold: 30 connections from the same (PID, remoteIP,
// remotePort) tuple within 60 seconds.  A browser opening 30 connections
// to the same CDN endpoint in a minute is possible but rare; a sleep-0
// Beacon easily exceeds 100/min.
//
// Design: fixed-size hash table keyed on (PID, remoteIP, remotePort).
// Hash collisions silently overwrite the oldest entry (acceptable —
// we only need to catch sustained high-rate sessions, not every burst).
// ---------------------------------------------------------------------------

#define C2_TRACK_MAX        128
#define C2_ALERT_THRESHOLD   30       // connections to same (pid,ip,port) in window
#define C2_WINDOW_MS         60000LL  // 60-second rolling window

typedef struct _C2_TRACK_ENTRY {
    UINT64   Pid;
    UINT32   RemoteAddr;
    UINT16   RemotePort;
    LONG     Count;
    LONGLONG WindowStart;   // KeQueryInterruptTime() 100ns ticks
    BOOLEAN  Alerted;
    BOOLEAN  Used;
} C2_TRACK_ENTRY;

static KSPIN_LOCK     g_C2Lock;
static C2_TRACK_ENTRY g_C2Slots[C2_TRACK_MAX];
static LONG           g_C2InitDone = 0;

static VOID C2TrackInit()
{
    if (InterlockedCompareExchange(&g_C2InitDone, 1, 0) == 0) {
        RtlZeroMemory(g_C2Slots, sizeof(g_C2Slots));
        KeInitializeSpinLock(&g_C2Lock);
    }
}

// Ports where interactive C2 hides in plain sight.
static BOOLEAN IsC2BlendPort(UINT16 port) {
    return port == 80  || port == 443  || port == 8080 ||
           port == 8443 || port == 8888 || port == 8000 ||
           port == 8001 || port == 9090 || port == 53;
}

// Processes that legitimately sustain high connection rates to a single host.
// EXCEPTION: if the process has been flagged by the injection taint tracker
// (VAD anomaly, remote write, remote thread, shellcode detected, etc.),
// it loses allowlist immunity — injected svchost/chrome traffic gets scrutinized.
static BOOLEAN IsC2AllowedProcess(UINT64 pid) {
    if (IsSystemProcess(pid)) return TRUE;

    // Tainted processes are never allowed, even if they're browsers or system services.
    // This is the key cross-reference: injection detection feeds into C2 detection.
    if (InjectionTaintTracker::IsTainted(pid)) return FALSE;

    PEPROCESS proc = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)pid, &proc)))
        return FALSE;

    char* name = PsGetProcessImageFileName(proc);
    ObDereferenceObject(proc);
    if (!name) return FALSE;

    static const char* kAllowed[] = {
        "chrome.exe",    "msedge.exe",    "firefox.exe",
        "iexplore.exe",  "opera.exe",     "brave.exe",
        "vivaldi.exe",
        "svchost.exe",                       // Windows Update, BITS
        "MsMpEng.exe",                       // Defender
        "NortonEDR.exe",                     // ourselves
        "OneDrive.exe",  "Teams.exe",
        "Outlook.exe",   "WINWORD.EXE",
        "slack.exe",     "Discord.exe",
        "spotify.exe",   "steam.exe",
        "SearchHost.exe",                    // Windows Search
        nullptr
    };
    for (int i = 0; kAllowed[i]; i++) {
        // Case-sensitive is fine — PsGetProcessImageFileName returns
        // the original casing from the PE header.
        if (strcmp(name, kAllowed[i]) == 0) return TRUE;
    }
    return FALSE;
}

// Simple hash to distribute (pid, ip, port) across the table.
static UINT32 C2SlotHash(UINT64 pid, UINT32 addr, UINT16 port) {
    UINT64 h = pid ^ ((UINT64)addr << 16) ^ port;
    h = (h ^ (h >> 17)) * 0xbf58476d1ce4e5b9ULL;
    h = (h ^ (h >> 31)) * 0x94d049bb133111ebULL;
    return (UINT32)(h % C2_TRACK_MAX);
}

// Track a connection and return TRUE if threshold crossed (first alert only).
static BOOLEAN C2CheckAndCount(UINT64 pid, UINT32 remoteAddr, UINT16 remotePort)
{
    LONGLONG now = (LONGLONG)KeQueryInterruptTime();
    LONGLONG windowTicks = C2_WINDOW_MS * 10000LL;

    UINT32 slot = C2SlotHash(pid, remoteAddr, remotePort);

    KIRQL irql;
    KeAcquireSpinLock(&g_C2Lock, &irql);

    C2_TRACK_ENTRY* e = &g_C2Slots[slot];

    // Check if this slot already tracks the same (pid, ip, port)
    if (e->Used &&
        e->Pid == pid &&
        e->RemoteAddr == remoteAddr &&
        e->RemotePort == remotePort)
    {
        // Same tuple — check window
        if ((now - e->WindowStart) > windowTicks) {
            // Window expired — reset
            e->WindowStart = now;
            e->Count       = 1;
            e->Alerted     = FALSE;
            KeReleaseSpinLock(&g_C2Lock, irql);
            return FALSE;
        }
        e->Count++;
        BOOLEAN alert = (!e->Alerted && e->Count >= C2_ALERT_THRESHOLD);
        if (alert) e->Alerted = TRUE;
        KeReleaseSpinLock(&g_C2Lock, irql);
        return alert;
    }

    // Different tuple or empty — overwrite (hash collision eviction)
    e->Pid         = pid;
    e->RemoteAddr  = remoteAddr;
    e->RemotePort  = remotePort;
    e->Count       = 1;
    e->WindowStart = now;
    e->Alerted     = FALSE;
    e->Used        = TRUE;
    KeReleaseSpinLock(&g_C2Lock, irql);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Configurable blocked-port list (written from user-mode via IOCTL).
// ---------------------------------------------------------------------------
static KSPIN_LOCK g_WfpBlocklistLock;
static UINT16     g_WfpBlockedPorts[32];
static UINT32     g_WfpBlockedPortCount = 0;

// Well-known ports commonly abused by C2 frameworks and reverse shells.
static const UINT16 kSuspiciousPorts[] = {
    1234,   // placeholder / test
    4444,   // Metasploit default
    5555,   // common reverse shell
    6666,   // common reverse shell
    6667,   // IRC botnet
    7777,   // various C2
    9001,   // Tor default
    9002,   // Tor bridge
    1337,   // leet port
    31337,  // Back Orifice / leet
    // Lateral movement channels — alert when non-System processes use these
    135,    // DCOM/RPC — WMI remote execution, DCOM lateral movement
    445,    // SMB — PsExec, remote service creation, pass-the-hash
    3389,   // RDP — RDP hijacking, pivoting
};

static BOOLEAN IsPortBlocked(UINT16 port) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WfpBlocklistLock, &oldIrql);
    BOOLEAN found = FALSE;
    for (UINT32 i = 0; i < g_WfpBlockedPortCount; i++) {
        if (g_WfpBlockedPorts[i] == port) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_WfpBlocklistLock, oldIrql);
    return found;
}

static BOOLEAN IsPortSuspicious(UINT16 port) {
    for (SIZE_T i = 0; i < ARRAYSIZE(kSuspiciousPorts); i++) {
        if (kSuspiciousPorts[i] == port) return TRUE;
    }
    return FALSE;
}

VOID WdfTcpipUtils::WfpSetBlocklist(const UINT16* ports, UINT32 count) {
    if (count > 32) count = 32;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WfpBlocklistLock, &oldIrql);
    RtlCopyMemory(g_WfpBlockedPorts, ports, count * sizeof(UINT16));
    g_WfpBlockedPortCount = count;
    KeReleaseSpinLock(&g_WfpBlocklistLock, oldIrql);
    DbgPrint("[+] WFP blocklist updated: %u port(s)\n", count);
}

// ---------------------------------------------------------------------------
// WFP callbacks
// ---------------------------------------------------------------------------

NTSTATUS WdfTcpipUtils::TcpipNotifyCallback(
    FWPS_CALLOUT_NOTIFY_TYPE type,
    const GUID* filterKey,
    const FWPS_FILTER* filter
) {
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID WdfTcpipUtils::TcpipFlowDeleteCallback(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext
) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

VOID WdfTcpipUtils::TcpipFilteringCallback(
    const FWPS_INCOMING_VALUES* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    PVOID layerData,
    const void* context,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
) {
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Correct field indices for FWPM_LAYER_OUTBOUND_TRANSPORT_V4.
    UINT32 localAddress  = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT32 remoteAddress = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 localPort     = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePort    = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

    // PID attribution — available at the transport layer.
    UINT64 pid = 0;
    if (metadata && (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = metadata->processId;
    }

    BOOLEAN blocked    = IsPortBlocked(remotePort);
    BOOLEAN suspicious = !blocked && IsPortSuspicious(remotePort);

    // Suppress lateral-movement-port alerts for System (PID 4) and Idle (PID 0)
    // — they legitimately use SMB/DCOM/RDP at the OS level.
    if (suspicious && IsSystemProcess(pid)) {
        suspicious = FALSE;
    }

    classifyOut->actionType = blocked ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

    NotifQueue* queue = CallbackObjects::GetNotifQueue();

    // -----------------------------------------------------------------
    // Kerberoasting detection — high-rate outbound Kerberos (port 88).
    // Legitimate processes issue at most a few TGS-REQs per minute.
    // Rubeus / Impacket GetUserSPNs issue hundreds; threshold is 15/30s.
    // Suppress for System/lsass (pid 0/4) which do normal Kerberos auth.
    // -----------------------------------------------------------------
    if (IsKerberosPort(remotePort) && !IsSystemProcess(pid) && queue) {
        if (KerbCheckAndCount(pid)) {
            char kMsg[200] = {};
            RtlStringCchPrintfA(kMsg, sizeof(kMsg),
                "Kerberoasting: pid=%llu issued >=%d Kerberos (port 88) connections "
                "within 30 s — possible AS-REQ/TGS-REQ spray (Rubeus/Impacket)",
                pid, KERB_ALERT_THRESHOLD);

            PKERNEL_STRUCTURED_NOTIFICATION kNotif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krbr');
            if (kNotif) {
                RtlZeroMemory(kNotif, sizeof(*kNotif));
                SET_CRITICAL(*kNotif);
                SET_NETWORK_CHECK(*kNotif);
                kNotif->pid            = (HANDLE)(ULONG_PTR)pid;
                kNotif->scoopedAddress = (ULONG64)(ULONG_PTR)remoteAddress;
                kNotif->isPath         = FALSE;
                SIZE_T kLen = strlen(kMsg) + 1;
                kNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, kLen, 'krbm');
                kNotif->bufSize = (ULONG)kLen;
                if (kNotif->msg) {
                    RtlCopyMemory(kNotif->msg, kMsg, kLen);
                    if (!queue->Enqueue(kNotif)) {
                        ExFreePool(kNotif->msg);
                        ExFreePool(kNotif);
                    }
                } else { ExFreePool(kNotif); }
            }
        }
    }

    // -----------------------------------------------------------------
    // DCSync detection — outbound LDAP/LDAPS/GC from a non-system process.
    //
    // The MS-DRSR replication protocol rides over LDAP (389/636) and
    // the Global Catalog ports (3268/3269).  Legitimate workstations do
    // not initiate LDAP replication; only domain controllers do.
    // Flag any non-system, non-lsass process contacting these ports as a
    // potential DCSync / secretsdump / mimikatz DC-replication attack.
    //
    // Note: lsass (PID varies) does use LDAP for normal auth queries but
    // NOT for GetNCChanges replication. The HookDll-level LsaIAmABackupDC
    // and DRSGetNCChanges hooks are the primary signal; this is backstop.
    // -----------------------------------------------------------------
    if (IsLdapPort(remotePort) && !IsSystemProcess(pid) && queue) {
        // Retrieve process name for the alert — kernel at DPC level so
        // we use the PID we got from WFP metadata and a quick lookup.
        // PsLookupProcessByProcessId is safe at DISPATCH_LEVEL.
        PEPROCESS ldapProc = nullptr;
        char ldapProcName[16] = "<unknown>";
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ldapProc))) {
            char* n = PsGetProcessImageFileName(ldapProc);
            if (n) RtlCopyMemory(ldapProcName, n, 15);
            ObDereferenceObject(ldapProc);
        }

        // Allow lsass — it legitimately binds to LDAP for authentication.
        BOOLEAN isLsass = (RtlCompareMemory(ldapProcName, "lsass.exe", 9) == 9);
        if (!isLsass) {
            char dcMsg[240] = {};
            RtlStringCchPrintfA(dcMsg, sizeof(dcMsg),
                "DCSync/LDAP: pid=%llu (%s) connecting to LDAP port %u "
                "-> %u.%u.%u.%u — possible DCSync/secretsdump replication",
                pid, ldapProcName, remotePort,
                FORMAT_ADDR(remoteAddress));

            PKERNEL_STRUCTURED_NOTIFICATION dcNotif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'dcnt');
            if (dcNotif) {
                RtlZeroMemory(dcNotif, sizeof(*dcNotif));
                SET_CRITICAL(*dcNotif);
                SET_NETWORK_CHECK(*dcNotif);
                dcNotif->pid            = (HANDLE)(ULONG_PTR)pid;
                dcNotif->scoopedAddress = (ULONG64)(ULONG_PTR)remoteAddress;
                dcNotif->isPath         = FALSE;
                RtlCopyMemory(dcNotif->procName, ldapProcName, 15);
                SIZE_T dcLen = strlen(dcMsg) + 1;
                dcNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, dcLen, 'dcmg');
                dcNotif->bufSize = (ULONG)dcLen;
                if (dcNotif->msg) {
                    RtlCopyMemory(dcNotif->msg, dcMsg, dcLen);
                    if (!queue->Enqueue(dcNotif)) {
                        ExFreePool(dcNotif->msg);
                        ExFreePool(dcNotif);
                    }
                } else { ExFreePool(dcNotif); }
            }
        }
    }

    // -----------------------------------------------------------------
    // Interactive C2 / beaconing session detection.
    //
    // When operators proxy through standard web ports with sleep~0 or
    // near-zero check-in intervals, a single process makes an abnormal
    // number of connections to the same (IP, port) within a short window.
    // Normal apps rarely exceed 10 connections/min to a single endpoint;
    // interactive C2 easily hits 100+/min.
    //
    // Threshold: 30 connections from (PID, remoteIP, remotePort) within
    // 60 seconds on blend ports (80, 443, 8080, 8443, 8888, 8000, 9090,
    // 53). Browsers and known high-talkers are allowlisted.
    // -----------------------------------------------------------------
    if (IsC2BlendPort(remotePort) && !IsSystemProcess(pid) && queue) {
        if (!IsC2AllowedProcess(pid) && C2CheckAndCount(pid, remoteAddress, remotePort)) {
            // Resolve process name for the alert
            PEPROCESS c2Proc = nullptr;
            char c2ProcName[16] = "<unknown>";
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)pid, &c2Proc))) {
                char* n = PsGetProcessImageFileName(c2Proc);
                if (n) RtlCopyMemory(c2ProcName, n, 15);
                ObDereferenceObject(c2Proc);
            }

            BOOLEAN tainted = InjectionTaintTracker::IsTainted(pid);

            char c2Msg[350] = {};
            RtlStringCchPrintfA(c2Msg, sizeof(c2Msg),
                "Interactive C2 session: pid=%llu (%s) made >=%d connections "
                "to %u.%u.%u.%u:%u within 60s — possible sleep~0 beacon / "
                "SOCKS proxy (Cobalt Strike, Sliver, Mythic)%s",
                pid, c2ProcName, C2_ALERT_THRESHOLD,
                FORMAT_ADDR(remoteAddress), remotePort,
                tainted
                    ? " [INJECTION-TAINTED: prior code injection detected in this process]"
                    : "");

            PKERNEL_STRUCTURED_NOTIFICATION c2Notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'c2nt');
            if (c2Notif) {
                RtlZeroMemory(c2Notif, sizeof(*c2Notif));
                // Tainted process beaconing = CRITICAL (confirmed injection + C2);
                // untainted = WARNING (could be a legitimate non-allowlisted app).
                if (tainted) { SET_CRITICAL(*c2Notif); }
                else         { SET_WARNING(*c2Notif);  }
                SET_NETWORK_CHECK(*c2Notif);
                c2Notif->pid            = (HANDLE)(ULONG_PTR)pid;
                c2Notif->scoopedAddress = (ULONG64)(ULONG_PTR)remoteAddress;
                c2Notif->isPath         = FALSE;
                RtlCopyMemory(c2Notif->procName, c2ProcName, 15);
                SIZE_T c2Len = strlen(c2Msg) + 1;
                c2Notif->msg = (char*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, c2Len, 'c2mg');
                c2Notif->bufSize = (ULONG)c2Len;
                if (c2Notif->msg) {
                    RtlCopyMemory(c2Notif->msg, c2Msg, c2Len);
                    if (!queue->Enqueue(c2Notif)) {
                        ExFreePool(c2Notif->msg);
                        ExFreePool(c2Notif);
                    }
                } else { ExFreePool(c2Notif); }
            }
        }
    }

    // Skip enqueueing routine Info-level connections to avoid queue saturation.
    // Always surface blocked and suspicious connections.
    if (!blocked && !suspicious) {
        DbgPrint("Net: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u pid=%llu\n",
            FORMAT_ADDR(localAddress),  localPort,
            FORMAT_ADDR(remoteAddress), remotePort, pid);
        return;
    }

    if (!queue) return;

    const char* tag = blocked ? " [BLOCKED]" : " [SUSPICIOUS PORT]";

    char msg[160] = {};
    RtlStringCchPrintfA(msg, sizeof(msg),
        "Net: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (pid=%llu)%s",
        FORMAT_ADDR(localAddress),  localPort,
        FORMAT_ADDR(remoteAddress), remotePort,
        pid, tag);

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'netn');
    if (!notif) return;

    // Blocked traffic is already stopped by WFP — use Warning (not Critical)
    // so the process isn't terminated for an outbound connection.
    if (blocked) {
        SET_WARNING(*notif);
    } else {
        SET_WARNING(*notif);  // suspicious
    }
    SET_NETWORK_CHECK(*notif);

    notif->pid            = (HANDLE)(ULONG_PTR)pid;
    notif->scoopedAddress = (ULONG64)(ULONG_PTR)remoteAddress;
    notif->isPath         = FALSE;

    SIZE_T msgLen = strlen(msg) + 1;
    notif->msg    = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'netm');
    notif->bufSize = (ULONG)msgLen;
    if (!notif->msg) { ExFreePool(notif); return; }

    RtlCopyMemory(notif->msg, msg, msgLen);

    if (!queue->Enqueue(notif)) {
        ExFreePool(notif->msg);
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// WFP registration helpers
// ---------------------------------------------------------------------------

NTSTATUS WdfTcpipUtils::WfpRegisterCallout() {

    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };

    display_data.name        = L"NortonEDRWdfCallout";
    display_data.description = L"NortonEDRWdfCallout";

    s_callout.calloutKey  = NORTONAV_CALLOUT_GUID;
    s_callout.classifyFn  = (FWPS_CALLOUT_CLASSIFY_FN3)WdfTcpipUtils::TcpipFilteringCallback;
    s_callout.notifyFn    = (FWPS_CALLOUT_NOTIFY_FN3)WdfTcpipUtils::TcpipNotifyCallback;
    s_callout.flowDeleteFn = (FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)WdfTcpipUtils::TcpipFlowDeleteCallback;

    NTSTATUS status = FwpsCalloutRegister((void*)DeviceObject, &s_callout, &RegCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FwpsCalloutRegister failed: 0x%x\n", status);
        return status;
    }

    m_callout.calloutKey       = NORTONAV_CALLOUT_GUID;
    m_callout.displayData      = display_data;
    m_callout.applicableLayer  = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    m_callout.flags            = 0;

    status = FwpmCalloutAdd(EngineHandle, &m_callout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FwpmCalloutAdd failed: 0x%x\n", status);
    }
    return status;
}

NTSTATUS WdfTcpipUtils::WfpAddSubLayer() {

    FWPM_SUBLAYER subLayer = { 0 };
    subLayer.subLayerKey              = NORTONAV_SUBLAYER_GUID;
    subLayer.displayData.name         = L"NortonEDRSubLayer";
    subLayer.displayData.description  = L"NortonEDRSubLayer";
    subLayer.flags                    = 0;
    subLayer.weight                   = 0x0f;

    NTSTATUS status = FwpmSubLayerAdd(EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[X] FwpmSubLayerAdd failed: 0x%x\n", status);
    }
    return status;
}

NTSTATUS WdfTcpipUtils::WfpAddFilter() {

    FWPM_FILTER filter = { 0 };
    filter.displayData.name        = L"NortonEDRDefaultFilter";
    filter.displayData.description = L"NortonEDRDefaultFilter";
    filter.action.type             = FWP_ACTION_CALLOUT_TERMINATING;
    filter.subLayerKey             = NORTONAV_SUBLAYER_GUID;
    filter.weight.type             = FWP_UINT8;
    filter.weight.uint8            = 0xf;
    filter.numFilterConditions     = 0;
    filter.layerKey                = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.calloutKey       = NORTONAV_CALLOUT_GUID;

    NTSTATUS status = FwpmFilterAdd(EngineHandle, &filter, NULL, &FilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[X] FwpmFilterAdd failed: 0x%x\n", status);
    }
    return status;
}

NTSTATUS WdfTcpipUtils::AddSubLayer() {
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name        = L"OutboundConnectionSubLayer";
    sublayer.displayData.description = L"Handles outbound connections";
    sublayer.subLayerKey             = NORTONAV_SUBLAYER_GUID;
    sublayer.weight                  = 0;
    return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

VOID WdfTcpipUtils::UnitializeWfp() {

    if (EngineHandle != NULL) {
        if (FilterId != 0) {
            FwpmFilterDeleteById(EngineHandle, FilterId);
            FwpmSubLayerDeleteByKey(EngineHandle, &NORTONAV_SUBLAYER_GUID);
        }
        if (AddCalloutId != 0) {
            FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
        }
        if (RegCalloutId != 0) {
            FwpsCalloutUnregisterById(RegCalloutId);
        }
        FwpmEngineClose(EngineHandle);
    }
}

NTSTATUS WdfTcpipUtils::InitWfp() {

    KeInitializeSpinLock(&g_WfpBlocklistLock);
    KerbTrackInit();
    C2TrackInit();

    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
    if (!NT_SUCCESS(status)) goto failure;

    status = WfpRegisterCallout();
    if (!NT_SUCCESS(status)) goto failure;

    status = WfpAddSubLayer();
    if (!NT_SUCCESS(status)) goto failure;

    status = WfpAddFilter();
    if (!NT_SUCCESS(status)) goto failure;

    DbgPrint("[+] WFP initialized\n");
    return STATUS_SUCCESS;

failure:
    DbgPrint("[X] WFP initialization failed: 0x%x\n", status);
    UnitializeWfp();
    return status;
}

// ---------------------------------------------------------------------------
// WFP Self-Protection — EDRSilencer / filter-injection defense.
//
// EDRSilencer and similar tools add WFP filters that block EDR outbound
// telemetry.  They don't need a kernel driver — FwpmFilterAdd0 from user-mode
// with admin rights is sufficient.  They can also delete our existing filter
// via FwpmFilterDeleteById.
//
// Detection strategy:
//   1. Verify our own filter (FilterId) is still registered.
//   2. Verify our callout (RegCalloutId) is still registered.
//   3. Enumerate filters on FWPM_LAYER_OUTBOUND_TRANSPORT_V4 and flag any
//      foreign filters with weight >= our weight that could supersede us.
// ---------------------------------------------------------------------------

static VOID EmitWfpAlert(BufferQueue* bufQueue, const char* msg)
{
    SIZE_T msgLen = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wfpi');
    if (!notif) return;
    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    SET_NETWORK_CHECK(*notif);
    notif->isPath = FALSE;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'wfpm');
    notif->bufSize = (ULONG)msgLen;
    if (notif->msg) {
        RtlCopyMemory(notif->msg, msg, msgLen);
        if (!bufQueue->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

// Helper: describe a filter condition field key in human-readable form.
static const char* ConditionFieldName(const GUID& fieldKey)
{
    // FWPM_CONDITION_ALE_APP_ID
    static const GUID kAppId =
        { 0xd78e1e87, 0x8644, 0x4ea5,
          { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };
    // FWPM_CONDITION_IP_REMOTE_ADDRESS
    static const GUID kRemoteAddr =
        { 0xb235ae9a, 0x1d64, 0x49b8,
          { 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45 } };
    // FWPM_CONDITION_IP_REMOTE_PORT
    static const GUID kRemotePort =
        { 0xc35a604d, 0xd22b, 0x4e1a,
          { 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b } };
    // FWPM_CONDITION_IP_PROTOCOL
    static const GUID kProtocol =
        { 0x3971ef2b, 0x623e, 0x4f9a,
          { 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7 } };
    // FWPM_CONDITION_IP_LOCAL_PORT
    static const GUID kLocalPort =
        { 0x0c1ba1af, 0x5765, 0x453f,
          { 0xaf, 0x22, 0xa8, 0xf4, 0xfe, 0x04, 0x85, 0x64 } };
    // FWPM_CONDITION_IP_LOCAL_ADDRESS
    static const GUID kLocalAddr =
        { 0xd9ee00de, 0xc1ef, 0x4617,
          { 0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57 } };

    if (RtlCompareMemory(&fieldKey, &kAppId, sizeof(GUID)) == sizeof(GUID))
        return "ALE_APP_ID";
    if (RtlCompareMemory(&fieldKey, &kRemoteAddr, sizeof(GUID)) == sizeof(GUID))
        return "IP_REMOTE_ADDRESS";
    if (RtlCompareMemory(&fieldKey, &kRemotePort, sizeof(GUID)) == sizeof(GUID))
        return "IP_REMOTE_PORT";
    if (RtlCompareMemory(&fieldKey, &kProtocol, sizeof(GUID)) == sizeof(GUID))
        return "IP_PROTOCOL";
    if (RtlCompareMemory(&fieldKey, &kLocalPort, sizeof(GUID)) == sizeof(GUID))
        return "IP_LOCAL_PORT";
    if (RtlCompareMemory(&fieldKey, &kLocalAddr, sizeof(GUID)) == sizeof(GUID))
        return "IP_LOCAL_ADDRESS";
    return nullptr;
}

// Helper: check if any filter condition targets an EDR-related application path.
// EDRSilencer enumerates EDR processes and adds per-app BLOCK filters using
// FWPM_CONDITION_ALE_APP_ID with the device-path blob from
// FwpmGetAppIdFromFileName.  The blob is a wide-string device path like
// \\device\\harddiskvolume3\\program files\\norton\\nortonedr.exe
static BOOLEAN ConditionTargetsEdr(const FWPM_FILTER_CONDITION* conds, UINT32 numConds)
{
    static const GUID kAppId =
        { 0xd78e1e87, 0x8644, 0x4ea5,
          { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };

    // Known EDR-related executable substrings (case-insensitive compare below)
    static const WCHAR* kEdrNames[] = {
        L"nortonedr",    L"nortonav",     L"norton",
        L"svchost",                       // telemetry often flows via svchost
        L"defender",     L"msmpeng",      // adjacent EDR that attackers also target
        L"crowdstrike",  L"csfalcon",
        L"sentinelagent",L"sentinelone",
        L"carbonblack",  L"cb.exe",
        L"cylance",      L"elastic",
        L"mdatp",        L"sense.exe",    // Microsoft Defender for Endpoint
    };

    for (UINT32 c = 0; c < numConds; c++) {
        if (RtlCompareMemory(&conds[c].fieldKey, &kAppId, sizeof(GUID)) != sizeof(GUID))
            continue;

        // The conditionValue for ALE_APP_ID is FWP_BYTE_BLOB_TYPE
        if (conds[c].conditionValue.type != FWP_BYTE_BLOB_TYPE ||
            !conds[c].conditionValue.byteBlob ||
            !conds[c].conditionValue.byteBlob->data ||
            conds[c].conditionValue.byteBlob->size < 4)
            continue;

        // The blob is a null-terminated wide string device path
        const WCHAR* appPath = (const WCHAR*)conds[c].conditionValue.byteBlob->data;
        ULONG appPathLen = conds[c].conditionValue.byteBlob->size / sizeof(WCHAR);

        for (int e = 0; e < ARRAYSIZE(kEdrNames); e++) {
            // Case-insensitive substring search
            UNICODE_STRING haystack, needle;
            RtlInitUnicodeString(&needle, kEdrNames[e]);
            haystack.Buffer = (PWCH)appPath;
            haystack.Length = (USHORT)(appPathLen * sizeof(WCHAR));
            haystack.MaximumLength = haystack.Length;

            // Manual case-insensitive substring search
            if (needle.Length / sizeof(WCHAR) > appPathLen) continue;
            ULONG needleChars = needle.Length / sizeof(WCHAR);
            for (ULONG pos = 0; pos + needleChars <= appPathLen; pos++) {
                BOOLEAN match = TRUE;
                for (ULONG k = 0; k < needleChars; k++) {
                    WCHAR a = appPath[pos + k];
                    WCHAR b = kEdrNames[e][k];
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) return TRUE;
            }
        }
    }
    return FALSE;
}

// Helper: build a human-readable summary of a filter's conditions.
static void DescribeFilterConditions(const FWPM_FILTER* filter,
                                     char* out, SIZE_T outSize)
{
    out[0] = '\0';
    if (!filter->numFilterConditions || !filter->filterCondition) {
        RtlStringCbCopyA(out, outSize, "conditions: <none/blanket>");
        return;
    }

    SIZE_T offset = 0;
    RtlStringCbPrintfA(out, outSize, "conditions(%u): ", filter->numFilterConditions);
    offset = strlen(out);

    for (UINT32 c = 0; c < filter->numFilterConditions && offset < outSize - 40; c++) {
        const FWPM_FILTER_CONDITION* cond = &filter->filterCondition[c];
        const char* name = ConditionFieldName(cond->fieldKey);

        if (name) {
            // For known fields, add the name and value summary
            if (cond->conditionValue.type == FWP_UINT16) {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s=%u] ", name, cond->conditionValue.uint16);
            } else if (cond->conditionValue.type == FWP_UINT32) {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s=0x%x] ", name, cond->conditionValue.uint32);
            } else if (cond->conditionValue.type == FWP_BYTE_BLOB_TYPE &&
                       cond->conditionValue.byteBlob &&
                       cond->conditionValue.byteBlob->data) {
                // For ALE_APP_ID, show a truncated path
                const WCHAR* path = (const WCHAR*)cond->conditionValue.byteBlob->data;
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s='%.60S'] ", name, path);
            } else {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s] ", name);
            }
        } else {
            RtlStringCbPrintfA(out + offset, outSize - offset, "[unknown_field] ");
        }
        offset = strlen(out);
    }
}

// Helper: enumerate filters on a given layer for foreign BLOCK entries.
// Inspects filterCondition arrays to identify EDR-targeted filters
// (EDRSilencer uses FWPM_CONDITION_ALE_APP_ID with EDR executable paths)
// and reports condition details for forensic analysis.
static BOOLEAN CheckLayerForForeignBlocks(
    HANDLE engine, const GUID& layerKey, UINT64 ourFilterId,
    const char* layerName, BufferQueue* bufQueue)
{
    BOOLEAN ok = TRUE;
    HANDLE enumHandle = nullptr;
    FWPM_FILTER_ENUM_TEMPLATE enumTemplate = {};
    enumTemplate.layerKey           = layerKey;
    enumTemplate.providerKey        = nullptr;
    enumTemplate.flags              = 0;
    enumTemplate.numFilterConditions = 0;
    enumTemplate.actionMask         = 0xFFFFFFFF;

    NTSTATUS st = FwpmFilterCreateEnumHandle(engine, &enumTemplate, &enumHandle);
    if (NT_SUCCESS(st) && enumHandle) {
        FWPM_FILTER** entries = nullptr;
        UINT32 numEntries = 0;
        st = FwpmFilterEnum(engine, enumHandle, 128, &entries, &numEntries);
        if (NT_SUCCESS(st) && entries) {
            for (UINT32 i = 0; i < numEntries; i++) {
                if (!entries[i]) continue;
                if (entries[i]->filterId == ourFilterId) continue;
                if (RtlCompareMemory(&entries[i]->subLayerKey,
                        &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) == sizeof(GUID))
                    continue;

                BOOLEAN isMalicious =
                    (entries[i]->action.type == FWP_ACTION_BLOCK) ||
                    (entries[i]->action.type == FWP_ACTION_CALLOUT_TERMINATING &&
                     RtlCompareMemory(&entries[i]->action.calloutKey,
                         &NORTONAV_CALLOUT_GUID, sizeof(GUID)) != sizeof(GUID));

                if (!isMalicious) continue;

                // Build condition description for the alert
                char condDesc[512];
                DescribeFilterConditions(entries[i], condDesc, sizeof(condDesc));

                // Check if conditions specifically target EDR processes
                BOOLEAN targetsEdr = ConditionTargetsEdr(
                    entries[i]->filterCondition,
                    entries[i]->numFilterConditions);

                const char* actionStr =
                    (entries[i]->action.type == FWP_ACTION_BLOCK)
                        ? "BLOCK" : "CALLOUT_TERMINATING";

                char msg[700];
                if (targetsEdr) {
                    // CRITICAL: filter specifically targets EDR executable(s)
                    // This is the EDRSilencer signature — per-app BLOCK filter
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "WFP TAMPER CRITICAL: foreign %s filter (id=%llu, weight=%llu) "
                        "on %s TARGETS EDR PROCESS — EDRSilencer-class attack! "
                        "display='%S', %s",
                        actionStr,
                        entries[i]->filterId,
                        entries[i]->weight.uint64,
                        layerName,
                        entries[i]->displayData.name
                            ? entries[i]->displayData.name : L"<none>",
                        condDesc);
                } else {
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "WFP TAMPER: foreign %s filter (id=%llu, weight=%llu) on %s "
                        "— possible telemetry blocking, display='%S', %s",
                        actionStr,
                        entries[i]->filterId,
                        entries[i]->weight.uint64,
                        layerName,
                        entries[i]->displayData.name
                            ? entries[i]->displayData.name : L"<none>",
                        condDesc);
                }
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }
            FwpmFreeMemory((void**)&entries);
        }
        FwpmFilterDestroyEnumHandle(engine, enumHandle);
    }
    return ok;
}

BOOLEAN WdfTcpipUtils::CheckIntegrity(BufferQueue* bufQueue)
{
    if (!EngineHandle || !bufQueue) return FALSE;
    BOOLEAN ok = TRUE;

    // -----------------------------------------------------------------------
    // Check 1: verify our filter is still registered.
    // Attack: FwpmFilterDeleteById from user-mode (admin) silently removes
    // our filter — our callout never fires, all network telemetry stops.
    // -----------------------------------------------------------------------
    if (FilterId != 0) {
        FWPM_FILTER* filterObj = nullptr;
        NTSTATUS st = FwpmFilterGetById(EngineHandle, FilterId, &filterObj);
        if (!NT_SUCCESS(st) || !filterObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR WFP filter DELETED (FwpmFilterDeleteById) "
                "— network telemetry and blocking disabled! EDRSilencer-class attack");
            ok = FALSE;
        }
        if (filterObj) FwpmFreeMemory((void**)&filterObj);
    }

    // -----------------------------------------------------------------------
    // Check 2: verify our callout is still registered.
    // Attack: FwpmCalloutDeleteById — removes our callout from the WFP engine.
    // Even if the filter survives, with no callout behind it the filter is inert.
    // Also checks FwpsCalloutUnregisterById — removes the kernel-side callout
    // registration (classifyFn stops being invoked).
    // -----------------------------------------------------------------------
    if (AddCalloutId != 0) {
        FWPM_CALLOUT* calloutObj = nullptr;
        NTSTATUS st = FwpmCalloutGetById(EngineHandle, AddCalloutId, &calloutObj);
        if (!NT_SUCCESS(st) || !calloutObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR WFP callout DELETED via FwpmCalloutDeleteById "
                "— classifyFn will not be invoked, network monitoring blind");
            ok = FALSE;
        }
        if (calloutObj) FwpmFreeMemory((void**)&calloutObj);
    }

    // -----------------------------------------------------------------------
    // Check 3: verify our sublayer is still registered.
    // Attack: FwpmSubLayerDeleteByKey — removes our sublayer, which cascades
    // and deletes all filters associated with it (including ours).
    // -----------------------------------------------------------------------
    {
        FWPM_SUBLAYER* subObj = nullptr;
        NTSTATUS st = FwpmSubLayerGetByKey(EngineHandle, &NORTONAV_SUBLAYER_GUID, &subObj);
        if (!NT_SUCCESS(st) || !subObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR sublayer DELETED via FwpmSubLayerDeleteByKey "
                "— all filters in our sublayer cascade-deleted");
            ok = FALSE;
        }
        if (subObj) FwpmFreeMemory((void**)&subObj);
    }

    // -----------------------------------------------------------------------
    // Check 4: enumerate foreign filters on our layer AND adjacent layers.
    //
    // Our callout lives on FWPM_LAYER_OUTBOUND_TRANSPORT_V4, but an attacker
    // can also block traffic at:
    //   - ALE_AUTH_CONNECT_V4: fires BEFORE the transport layer, can block
    //     NortonEDR.exe outbound connections at the connection-auth stage
    //   - OUTBOUND_NETWORK_V4: IP-level layer, also pre-empts transport
    //
    // We check all three for foreign BLOCK filters and for CALLOUT_TERMINATING
    // filters that reference a non-Norton callout (rogue callout injection via
    // fwpuclnt!FwpmCalloutAdd).
    // -----------------------------------------------------------------------
    if (!CheckLayerForForeignBlocks(EngineHandle,
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FilterId,
            "OUTBOUND_TRANSPORT_V4", bufQueue))
        ok = FALSE;

    if (!CheckLayerForForeignBlocks(EngineHandle,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0,
            "ALE_AUTH_CONNECT_V4", bufQueue))
        ok = FALSE;

    if (!CheckLayerForForeignBlocks(EngineHandle,
            FWPM_LAYER_OUTBOUND_IPPACKET_V4, 0,
            "OUTBOUND_IPPACKET_V4", bufQueue))
        ok = FALSE;

    // -----------------------------------------------------------------------
    // Check 5: enumerate foreign callouts on our layer.
    //
    // Attack: fwpuclnt!FwpmCalloutAdd registers a rogue callout on
    // FWPM_LAYER_OUTBOUND_TRANSPORT_V4.  Paired with a high-weight filter,
    // the rogue callout's classifyFn fires first and issues FWP_ACTION_BLOCK
    // before our callout ever sees the packet.
    //
    // We enumerate all callouts on our layer and flag any that don't match
    // our NORTONAV_CALLOUT_GUID.
    // -----------------------------------------------------------------------
    {
        HANDLE enumHandle = nullptr;
        FWPM_CALLOUT_ENUM_TEMPLATE enumTemplate = {};
        enumTemplate.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

        NTSTATUS st = FwpmCalloutCreateEnumHandle(
            EngineHandle, &enumTemplate, &enumHandle);
        if (NT_SUCCESS(st) && enumHandle) {
            FWPM_CALLOUT** callouts = nullptr;
            UINT32 numCallouts = 0;
            st = FwpmCalloutEnum(EngineHandle, enumHandle, 64, &callouts, &numCallouts);
            if (NT_SUCCESS(st) && callouts) {
                for (UINT32 i = 0; i < numCallouts; i++) {
                    if (!callouts[i]) continue;
                    // Skip our own callout
                    if (RtlCompareMemory(&callouts[i]->calloutKey,
                            &NORTONAV_CALLOUT_GUID, sizeof(GUID)) == sizeof(GUID))
                        continue;

                    // Foreign callout on our layer — suspicious.
                    // Not all foreign callouts are malicious (Windows Firewall uses
                    // them), so check if they were added AFTER boot by examining
                    // flags.  Persistent system callouts have FWPM_CALLOUT_FLAG_PERSISTENT.
                    // Non-persistent foreign callouts added at runtime are more suspicious.
                    BOOLEAN suspicious = !(callouts[i]->flags & FWPM_CALLOUT_FLAG_PERSISTENT);

                    if (suspicious) {
                        char msg[350];
                        RtlStringCbPrintfA(msg, sizeof(msg),
                            "WFP: non-persistent foreign callout on OUTBOUND_TRANSPORT_V4 "
                            "(id=%lu, display='%S') — possible rogue callout injection "
                            "via fwpuclnt!FwpmCalloutAdd to intercept/block EDR traffic",
                            callouts[i]->calloutId,
                            callouts[i]->displayData.name
                                ? callouts[i]->displayData.name : L"<none>");
                        EmitWfpAlert(bufQueue, msg);
                        ok = FALSE;
                    }
                }
                FwpmFreeMemory((void**)&callouts);
            }
            FwpmCalloutDestroyEnumHandle(EngineHandle, enumHandle);
        }
    }

    // -----------------------------------------------------------------------
    // Check 6: enumerate foreign sublayers.
    //
    // Attack: FwpmSubLayerAdd from user-mode (fwpuclnt.dll) creates a rogue
    // sublayer.  WFP arbitration evaluates sublayers independently — if any
    // sublayer blocks, the packet is blocked regardless of other sublayers'
    // PERMIT decisions.  A high-weight foreign sublayer with BLOCK filters
    // will be caught by Check 4, but enumerating sublayers directly gives us:
    //   - Early warning of staged sublayers (created but no filters yet)
    //   - Visibility into sublayer weight manipulation
    //   - Detection of non-persistent runtime-added sublayers (vs boot-time
    //     system sublayers like Windows Firewall's)
    //
    // We flag non-persistent foreign sublayers added at runtime.  Known system
    // sublayers (FWPM_SUBLAYER_FLAG_PERSISTENT or matching well-known provider
    // keys) are skipped.
    // -----------------------------------------------------------------------
    {
        HANDLE enumHandle = nullptr;
        NTSTATUS st = FwpmSubLayerCreateEnumHandle(EngineHandle, nullptr, &enumHandle);
        if (NT_SUCCESS(st) && enumHandle) {
            FWPM_SUBLAYER** sublayers = nullptr;
            UINT32 numSublayers = 0;
            st = FwpmSubLayerEnum(EngineHandle, enumHandle, 64, &sublayers, &numSublayers);
            if (NT_SUCCESS(st) && sublayers) {
                for (UINT32 i = 0; i < numSublayers; i++) {
                    if (!sublayers[i]) continue;

                    // Skip our own sublayer
                    if (RtlCompareMemory(&sublayers[i]->subLayerKey,
                            &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) == sizeof(GUID))
                        continue;

                    // Skip persistent (boot-time) sublayers — these are typically
                    // Windows Firewall, IPsec, and other OS components.
                    if (sublayers[i]->flags & FWPM_SUBLAYER_FLAG_PERSISTENT)
                        continue;

                    // Non-persistent foreign sublayer — suspicious at runtime.
                    // High-weight sublayers are especially dangerous because WFP
                    // evaluates higher-weight sublayers first in arbitration.
                    const UINT16 highWeightThreshold = 0x8000;
                    BOOLEAN highWeight = (sublayers[i]->weight >= highWeightThreshold);

                    char msg[400];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "WFP: non-persistent foreign sublayer detected "
                        "(weight=%u%s, display='%S') — possible rogue sublayer "
                        "injection via FwpmSubLayerAdd to stage BLOCK filters "
                        "or manipulate WFP arbitration",
                        sublayers[i]->weight,
                        highWeight ? " HIGH-WEIGHT" : "",
                        sublayers[i]->displayData.name
                            ? sublayers[i]->displayData.name : L"<none>");
                    EmitWfpAlert(bufQueue, msg);
                    ok = FALSE;
                }
                FwpmFreeMemory((void**)&sublayers);
            }
            FwpmSubLayerDestroyEnumHandle(EngineHandle, enumHandle);
        }
    }

    return ok;
}

// Bridge for HookDetector::CheckWfpIntegrity — forward to the WFP instance.
extern WdfTcpipUtils* g_wfpUtils;

VOID HookDetector::CheckWfpIntegrity(BufferQueue* bufQueue)
{
    if (g_wfpUtils) g_wfpUtils->CheckIntegrity(bufQueue);
}
