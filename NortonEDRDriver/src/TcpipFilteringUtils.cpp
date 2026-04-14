#include "Globals.h"

// Forward declarations
static VOID EmitWfpChangeAlert(const char* msg);

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
    // Weaver Ant: SOCKS proxy / ORB relay network ports
    1080,   // SOCKS5 default
    1081,   // SOCKS5 alternate
    9050,   // Tor SOCKS proxy
    9150,   // Tor Browser SOCKS
    8888,   // common proxy / C2
    3128,   // Squid / HTTP proxy
    1090,   // SOCKS alternate
};

// Weaver Ant: known SOCKS proxy / ORB relay ports for targeted alerting.
static BOOLEAN IsSocksProxyPort(UINT16 port) {
    return port == 1080 || port == 1081 || port == 9050 ||
           port == 9150 || port == 1090 || port == 3128;
}

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

    // ---------------------------------------------------------------
    // Detect whether we are on the V4 or V6 layer and extract the
    // correct field indices.  Both layers route to this single callback.
    // ---------------------------------------------------------------
    BOOLEAN isV6 = (values->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V6);

    UINT32 localAddressV4  = 0;
    UINT32 remoteAddressV4 = 0;
    UINT8  localAddressV6[16]  = {};
    UINT8  remoteAddressV6[16] = {};
    UINT16 localPort  = 0;
    UINT16 remotePort = 0;

    if (isV6) {
        // V6: addresses are FWP_BYTE_ARRAY16_TYPE (16 bytes).
        if (values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16)
            RtlCopyMemory(localAddressV6,
                values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16, 16);
        if (values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16)
            RtlCopyMemory(remoteAddressV6,
                values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
        localPort  = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
    } else {
        // V4: addresses are UINT32.
        localAddressV4  = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddressV4 = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort       = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort      = values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
    }

    // Pre-format address strings for alert messages.
    // V4: "a.b.c.d"   V6: "xxxx:xxxx:...:xxxx" (abbreviated)
    char localAddrStr[48]  = {};
    char remoteAddrStr[48] = {};
    if (isV6) {
        RtlStringCchPrintfA(localAddrStr, sizeof(localAddrStr),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            localAddressV6[0],  localAddressV6[1],  localAddressV6[2],  localAddressV6[3],
            localAddressV6[4],  localAddressV6[5],  localAddressV6[6],  localAddressV6[7],
            localAddressV6[8],  localAddressV6[9],  localAddressV6[10], localAddressV6[11],
            localAddressV6[12], localAddressV6[13], localAddressV6[14], localAddressV6[15]);
        RtlStringCchPrintfA(remoteAddrStr, sizeof(remoteAddrStr),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            remoteAddressV6[0],  remoteAddressV6[1],  remoteAddressV6[2],  remoteAddressV6[3],
            remoteAddressV6[4],  remoteAddressV6[5],  remoteAddressV6[6],  remoteAddressV6[7],
            remoteAddressV6[8],  remoteAddressV6[9],  remoteAddressV6[10], remoteAddressV6[11],
            remoteAddressV6[12], remoteAddressV6[13], remoteAddressV6[14], remoteAddressV6[15]);
    } else {
        RtlStringCchPrintfA(localAddrStr,  sizeof(localAddrStr),
            "%u.%u.%u.%u", FORMAT_ADDR(localAddressV4));
        RtlStringCchPrintfA(remoteAddrStr, sizeof(remoteAddrStr),
            "%u.%u.%u.%u", FORMAT_ADDR(remoteAddressV4));
    }

    // ---------------------------------------------------------------
    // Metadata extraction — use FWPS_IS_METADATA_FIELD_PRESENT macro
    // for each field as per Microsoft documentation.
    //
    // Available metadata at OUTBOUND_TRANSPORT V4/V6:
    //   PROCESS_ID         — PID of owning process
    //   PROCESS_PATH       — full NT path of owning executable
    //   TOKEN              — process token (privilege/impersonation)
    //   TRANSPORT_ENDPOINT_HANDLE — endpoint for association
    //   COMPARTMENT_ID     — network compartment (container isolation)
    // ---------------------------------------------------------------

    UINT64 pid = 0;
    if (metadata && FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = metadata->processId;
    }

    // Process path — full NT device path of the process creating the connection.
    // More reliable than PID lookup because:
    //   1. PID can be recycled by the time we alert
    //   2. Attacker can spoof PEB image path but WFP gets path from kernel
    //   3. Enables direct EDR-targeting detection (is this OUR process being blocked?)
    WCHAR processPath[260] = {};
    BOOLEAN hasProcessPath = FALSE;
    if (metadata && FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_PATH)) {
        if (metadata->processPath && metadata->processPath->size > 0 &&
            metadata->processPath->data) {
            ULONG copyLen = min((ULONG)(metadata->processPath->size), (ULONG)(sizeof(processPath) - sizeof(WCHAR)));
            RtlCopyMemory(processPath, metadata->processPath->data, copyLen);
            processPath[copyLen / sizeof(WCHAR)] = L'\0';
            hasProcessPath = TRUE;
        }
    }

    // Token access check — detect connections from elevated/SYSTEM processes.
    // Useful for identifying privilege escalation + network exfil combos.
    ULONG tokenAccessFlags = 0;
    if (metadata && FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TOKEN)) {
        tokenAccessFlags = metadata->token;
    }

    // Compartment ID — network compartment isolation.  Non-default compartments
    // may indicate container escape or attacker-created network namespaces.
    UINT32 compartmentId = 0;
    if (metadata && FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        compartmentId = metadata->compartmentId;
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
            char kMsg[400] = {};
            if (hasProcessPath) {
                RtlStringCchPrintfA(kMsg, sizeof(kMsg),
                    "Kerberoasting: pid=%llu ('%S') issued >=%d Kerberos (port 88) "
                    "connections within 30 s — possible AS-REQ/TGS-REQ spray "
                    "(Rubeus/Impacket)",
                    pid, processPath, KERB_ALERT_THRESHOLD);
            } else {
                RtlStringCchPrintfA(kMsg, sizeof(kMsg),
                    "Kerberoasting: pid=%llu issued >=%d Kerberos (port 88) connections "
                    "within 30 s — possible AS-REQ/TGS-REQ spray (Rubeus/Impacket)",
                    pid, KERB_ALERT_THRESHOLD);
            }

            PKERNEL_STRUCTURED_NOTIFICATION kNotif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krbr');
            if (kNotif) {
                RtlZeroMemory(kNotif, sizeof(*kNotif));
                SET_CRITICAL(*kNotif);
                SET_NETWORK_CHECK(*kNotif);
                kNotif->pid            = (HANDLE)(ULONG_PTR)pid;
                kNotif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
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
            char dcMsg[400] = {};
            if (hasProcessPath) {
                RtlStringCchPrintfA(dcMsg, sizeof(dcMsg),
                    "DCSync/LDAP: pid=%llu (%s, path='%S') connecting to LDAP port %u "
                    "-> %s — possible DCSync/secretsdump replication",
                    pid, ldapProcName, processPath, remotePort,
                    remoteAddrStr);
            } else {
                RtlStringCchPrintfA(dcMsg, sizeof(dcMsg),
                    "DCSync/LDAP: pid=%llu (%s) connecting to LDAP port %u "
                    "-> %s — possible DCSync/secretsdump replication",
                    pid, ldapProcName, remotePort,
                    remoteAddrStr);
            }

            PKERNEL_STRUCTURED_NOTIFICATION dcNotif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'dcnt');
            if (dcNotif) {
                RtlZeroMemory(dcNotif, sizeof(*dcNotif));
                SET_CRITICAL(*dcNotif);
                SET_NETWORK_CHECK(*dcNotif);
                dcNotif->pid            = (HANDLE)(ULONG_PTR)pid;
                dcNotif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
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
    // Weaver Ant: SOCKS proxy / ORB relay network detection.
    //
    // ORB (Operational Relay Box) networks chain compromised hosts via
    // SOCKS proxies for multi-hop C2 tunneling.  Non-system processes
    // connecting to known SOCKS ports (1080, 9050, etc.) are flagged.
    // The injection taint cross-reference elevates injected processes.
    // -----------------------------------------------------------------
    if (IsSocksProxyPort(remotePort) && !IsSystemProcess(pid) && queue) {
        PEPROCESS socksProc = nullptr;
        char socksProcName[16] = "<unknown>";
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)pid, &socksProc))) {
            char* n = PsGetProcessImageFileName(socksProc);
            if (n) RtlCopyMemory(socksProcName, n, 15);
            ObDereferenceObject(socksProc);
        }

        BOOLEAN tainted = InjectionTaintTracker::IsTainted(pid);

        char socksMsg[400] = {};
        RtlStringCchPrintfA(socksMsg, sizeof(socksMsg),
            "SOCKS/ORB: pid=%llu (%s) connecting to SOCKS port %u -> %s "
            "— possible ORB relay / proxy tunnel (Weaver Ant, Chisel, "
            "reGeorg, Neo-reGeorg)%s",
            pid, socksProcName, remotePort, remoteAddrStr,
            tainted ? " [INJECTION-TAINTED]" : "");

        PKERNEL_STRUCTURED_NOTIFICATION socksNotif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'sknt');
        if (socksNotif) {
            RtlZeroMemory(socksNotif, sizeof(*socksNotif));
            if (tainted) { SET_CRITICAL(*socksNotif); }
            else         { SET_WARNING(*socksNotif);  }
            SET_NETWORK_CHECK(*socksNotif);
            socksNotif->pid = (HANDLE)(ULONG_PTR)pid;
            socksNotif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
            socksNotif->isPath = FALSE;
            RtlCopyMemory(socksNotif->procName, socksProcName, 15);
            SIZE_T sLen = strlen(socksMsg) + 1;
            socksNotif->msg = (char*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sLen, 'skmg');
            socksNotif->bufSize = (ULONG)sLen;
            if (socksNotif->msg) {
                RtlCopyMemory(socksNotif->msg, socksMsg, sLen);
                if (!queue->Enqueue(socksNotif)) {
                    ExFreePool(socksNotif->msg);
                    ExFreePool(socksNotif);
                }
            } else { ExFreePool(socksNotif); }
        }
    }

    // -----------------------------------------------------------------
    // Weaver Ant: Web server outbound connection detection.
    //
    // Web server worker processes (w3wp.exe, httpd, nginx, tomcat, php)
    // should only accept inbound connections — outbound connections from
    // these processes indicate:
    //   - Reverse shell callback from a web shell
    //   - C2 beacon from an in-memory web shell
    //   - Data exfiltration via HTTP/S to attacker infrastructure
    //   - SSRF exploitation
    //
    // Exception: DNS (53), LDAP (389/636) for auth, and localhost (127.*)
    // are legitimate from web servers.
    // -----------------------------------------------------------------
    if (!IsSystemProcess(pid) && queue) {
        PEPROCESS webProc = nullptr;
        char webProcName[16] = {};
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)pid, &webProc))) {
            char* n = PsGetProcessImageFileName(webProc);
            if (n) RtlCopyMemory(webProcName, n, 15);
            ObDereferenceObject(webProc);
        }

        BOOLEAN isWebServer =
            (strcmp(webProcName, "w3wp.exe") == 0 ||
             strcmp(webProcName, "httpd.exe") == 0 ||
             strcmp(webProcName, "nginx.exe") == 0 ||
             strcmp(webProcName, "php-cgi.exe") == 0 ||
             strcmp(webProcName, "php.exe") == 0 ||
             strcmp(webProcName, "java.exe") == 0 ||
             strcmp(webProcName, "tomcat9.exe") == 0 ||
             strcmp(webProcName, "iisexpress.e") == 0);  // truncated to 15 chars

        if (isWebServer) {
            // Allowlist legitimate outbound ports for web servers
            BOOLEAN isLegitOutbound =
                remotePort == 53   ||   // DNS
                remotePort == 389  ||   // LDAP
                remotePort == 636  ||   // LDAPS
                remotePort == 88   ||   // Kerberos auth
                remotePort == 1433 ||   // SQL Server
                remotePort == 3306 ||   // MySQL
                remotePort == 5432 ||   // PostgreSQL
                remotePort == 6379 ||   // Redis
                remotePort == 27017;    // MongoDB

            // Allow localhost connections (127.0.0.0/8)
            if (!isV6 && ((remoteAddressV4 >> 24) & 0xFF) == 127)
                isLegitOutbound = TRUE;

            if (!isLegitOutbound) {
                BOOLEAN tainted = InjectionTaintTracker::IsTainted(pid);

                char webNetMsg[420] = {};
                RtlStringCchPrintfA(webNetMsg, sizeof(webNetMsg),
                    "Web shell C2: %s (pid=%llu) outbound connection to %s:%u "
                    "— web server processes should not initiate outbound "
                    "connections (reverse shell / C2 callback / exfil)%s",
                    webProcName, pid, remoteAddrStr, remotePort,
                    tainted ? " [INJECTION-TAINTED]" : "");

                PKERNEL_STRUCTURED_NOTIFICATION webNetNotif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wsnt');
                if (webNetNotif) {
                    RtlZeroMemory(webNetNotif, sizeof(*webNetNotif));
                    SET_CRITICAL(*webNetNotif);
                    SET_NETWORK_CHECK(*webNetNotif);
                    webNetNotif->pid = (HANDLE)(ULONG_PTR)pid;
                    webNetNotif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
                    webNetNotif->isPath = FALSE;
                    RtlCopyMemory(webNetNotif->procName, webProcName, 15);
                    SIZE_T wLen = strlen(webNetMsg) + 1;
                    webNetNotif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, wLen, 'wsmg');
                    webNetNotif->bufSize = (ULONG)wLen;
                    if (webNetNotif->msg) {
                        RtlCopyMemory(webNetNotif->msg, webNetMsg, wLen);
                        if (!queue->Enqueue(webNetNotif)) {
                            ExFreePool(webNetNotif->msg);
                            ExFreePool(webNetNotif);
                        }
                    } else { ExFreePool(webNetNotif); }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // T1047: wmiprvse.exe outbound network connection detection.
    //
    // WMI provider host (wmiprvse.exe) legitimately talks to local/domain
    // infrastructure but should NOT make outbound connections to arbitrary
    // remote hosts on uncommon ports.  Outbound from wmiprvse indicates:
    //   - Attacker-controlled WMI provider DLL with C2 callback
    //   - Lateral movement relay via WMI
    //   - Data exfiltration through rogue WMI provider
    //
    // Allowlist: DNS(53), LDAP(389/636), Kerberos(88), RPC endpoint
    // mapper(135), WMI dynamic RPC(49152-65535 to localhost only),
    // and localhost (127.*/::1).
    // -----------------------------------------------------------------
    if (!IsSystemProcess(pid) && queue) {
        PEPROCESS wmiProc = nullptr;
        char wmiProcName[16] = {};
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)pid, &wmiProc))) {
            char* wn = PsGetProcessImageFileName(wmiProc);
            if (wn) RtlCopyMemory(wmiProcName, wn, 15);
            ObDereferenceObject(wmiProc);
        }

        if (strcmp(wmiProcName, "WmiPrvSE.exe") == 0 ||
            strcmp(wmiProcName, "wmiprvse.exe") == 0) {
            BOOLEAN isLegitWmi =
                remotePort == 53   ||   // DNS
                remotePort == 88   ||   // Kerberos
                remotePort == 135  ||   // RPC endpoint mapper
                remotePort == 389  ||   // LDAP
                remotePort == 636  ||   // LDAPS
                remotePort == 445  ||   // SMB (WMI remote results)
                remotePort == 5985 ||   // WinRM HTTP
                remotePort == 5986;     // WinRM HTTPS

            // Allow localhost connections (127.0.0.0/8 or ::1)
            if (!isV6 && ((remoteAddressV4 >> 24) & 0xFF) == 127)
                isLegitWmi = TRUE;

            if (!isLegitWmi) {
                BOOLEAN tainted = InjectionTaintTracker::IsTainted(pid);

                char wmiNetMsg[420] = {};
                RtlStringCchPrintfA(wmiNetMsg, sizeof(wmiNetMsg),
                    "Rogue WMI provider C2: wmiprvse.exe (pid=%llu) outbound "
                    "connection to %s:%u — WMI provider host should not "
                    "initiate arbitrary outbound connections (T1047: rogue "
                    "provider DLL / lateral movement relay)%s",
                    pid, remoteAddrStr, remotePort,
                    tainted ? " [INJECTION-TAINTED]" : "");

                PKERNEL_STRUCTURED_NOTIFICATION wmiNetNotif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wmnt');
                if (wmiNetNotif) {
                    RtlZeroMemory(wmiNetNotif, sizeof(*wmiNetNotif));
                    SET_CRITICAL(*wmiNetNotif);
                    SET_NETWORK_CHECK(*wmiNetNotif);
                    wmiNetNotif->pid = (HANDLE)(ULONG_PTR)pid;
                    wmiNetNotif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
                    wmiNetNotif->isPath = FALSE;
                    RtlCopyMemory(wmiNetNotif->procName, wmiProcName, 15);
                    SIZE_T wmLen = strlen(wmiNetMsg) + 1;
                    wmiNetNotif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, wmLen, 'wmmg');
                    wmiNetNotif->bufSize = (ULONG)wmLen;
                    if (wmiNetNotif->msg) {
                        RtlCopyMemory(wmiNetNotif->msg, wmiNetMsg, wmLen);
                        if (!queue->Enqueue(wmiNetNotif)) {
                            ExFreePool(wmiNetNotif->msg);
                            ExFreePool(wmiNetNotif);
                        }
                    } else { ExFreePool(wmiNetNotif); }
                }
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
        // For V6, hash the 128-bit address into a UINT32 key for the C2 tracker.
        UINT32 c2AddrKey = isV6
            ? (UINT32)(*(UINT64*)remoteAddressV6 ^ *(UINT64*)(remoteAddressV6 + 8))
            : remoteAddressV4;
        if (!IsC2AllowedProcess(pid) && C2CheckAndCount(pid, c2AddrKey, remotePort)) {
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

            char c2Msg[500] = {};
            if (hasProcessPath) {
                RtlStringCchPrintfA(c2Msg, sizeof(c2Msg),
                    "Interactive C2 session: pid=%llu (%s, path='%S') made >=%d "
                    "connections to %s:%u within 60s — possible sleep~0 "
                    "beacon / SOCKS proxy (Cobalt Strike, Sliver, Mythic)%s",
                    pid, c2ProcName, processPath, C2_ALERT_THRESHOLD,
                    remoteAddrStr, remotePort,
                    tainted
                        ? " [INJECTION-TAINTED]"
                        : "");
            } else {
                RtlStringCchPrintfA(c2Msg, sizeof(c2Msg),
                    "Interactive C2 session: pid=%llu (%s) made >=%d connections "
                    "to %s:%u within 60s — possible sleep~0 beacon / "
                    "SOCKS proxy (Cobalt Strike, Sliver, Mythic)%s",
                    pid, c2ProcName, C2_ALERT_THRESHOLD,
                    remoteAddrStr, remotePort,
                    tainted
                        ? " [INJECTION-TAINTED]"
                        : "");
            }

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
                c2Notif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
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
        DbgPrint("Net: %s:%u -> %s:%u pid=%llu%s\n",
            localAddrStr, localPort, remoteAddrStr, remotePort, pid,
            isV6 ? " [IPv6]" : "");
        return;
    }

    if (!queue) return;

    const char* tag = blocked ? " [BLOCKED]" : " [SUSPICIOUS PORT]";

    char msg[450] = {};
    if (hasProcessPath) {
        RtlStringCchPrintfA(msg, sizeof(msg),
            "Net: %s:%u -> %s:%u (pid=%llu, '%S')%s%s",
            localAddrStr, localPort, remoteAddrStr, remotePort,
            pid, processPath, isV6 ? " [IPv6]" : "", tag);
    } else {
        RtlStringCchPrintfA(msg, sizeof(msg),
            "Net: %s:%u -> %s:%u (pid=%llu)%s%s",
            localAddrStr, localPort, remoteAddrStr, remotePort,
            pid, isV6 ? " [IPv6]" : "", tag);
    }

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
    notif->scoopedAddress = isV6 ? 0 : (ULONG64)remoteAddressV4;
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

// ---------------------------------------------------------------------------
// IPv6 callout + filter — mirrors V4 on FWPM_LAYER_OUTBOUND_TRANSPORT_V6.
// Uses a separate GUID so both callouts coexist.  The same classify callback
// handles both; it checks values->layerId to extract V4 or V6 fields.
// ---------------------------------------------------------------------------

NTSTATUS WdfTcpipUtils::WfpRegisterCalloutV6() {

    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };

    display_data.name        = L"NortonEDRWdfCalloutV6";
    display_data.description = L"NortonEDR IPv6 outbound transport callout";

    s_callout.calloutKey  = NORTONAV_CALLOUT_V6_GUID;
    s_callout.classifyFn  = (FWPS_CALLOUT_CLASSIFY_FN3)WdfTcpipUtils::TcpipFilteringCallback;
    s_callout.notifyFn    = (FWPS_CALLOUT_NOTIFY_FN3)WdfTcpipUtils::TcpipNotifyCallback;
    s_callout.flowDeleteFn = (FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)WdfTcpipUtils::TcpipFlowDeleteCallback;

    NTSTATUS status = FwpsCalloutRegister((void*)DeviceObject, &s_callout, &RegCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FwpsCalloutRegister V6 failed: 0x%x\n", status);
        return status;
    }

    m_callout.calloutKey       = NORTONAV_CALLOUT_V6_GUID;
    m_callout.displayData      = display_data;
    m_callout.applicableLayer  = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
    m_callout.flags            = 0;

    status = FwpmCalloutAdd(EngineHandle, &m_callout, NULL, &AddCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FwpmCalloutAdd V6 failed: 0x%x\n", status);
    }
    return status;
}

NTSTATUS WdfTcpipUtils::WfpAddFilterV6() {

    FWPM_FILTER filter = { 0 };
    filter.displayData.name        = L"NortonEDRDefaultFilterV6";
    filter.displayData.description = L"NortonEDR IPv6 outbound transport filter";
    filter.action.type             = FWP_ACTION_CALLOUT_TERMINATING;
    filter.subLayerKey             = NORTONAV_SUBLAYER_GUID;
    filter.weight.type             = FWP_UINT8;
    filter.weight.uint8            = 0xf;
    filter.numFilterConditions     = 0;
    filter.layerKey                = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
    filter.action.calloutKey       = NORTONAV_CALLOUT_V6_GUID;

    NTSTATUS status = FwpmFilterAdd(EngineHandle, &filter, NULL, &FilterIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[X] FwpmFilterAdd V6 failed: 0x%x\n", status);
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

    // Guard against premature/malicious invocation.
    // An attacker with kernel code execution (BYOVD, vulnerable driver) could
    // call UnitializeWfp directly via a function pointer or by triggering
    // our unload path.  The AuthorizeUnload() method must be called from
    // our legitimate UnloadDriver first.
    if (InterlockedCompareExchange(&UnloadAuthorized, 1, 1) != 1) {
        // Not authorized — this is a tamper attempt.
        EmitWfpChangeAlert(
            "WFP TAMPER CRITICAL: UnitializeWfp called WITHOUT authorization "
            "— attacker attempting to tear down WFP infrastructure via "
            "direct function call or premature unload trigger!");
        return;
    }

    if (EngineHandle != NULL) {
        // Unsubscribe from change notifications FIRST to avoid callbacks
        // firing during teardown (use-after-free risk).
        UnsubscribeWfpChangeNotifications();

        // Remove V6 filter/callout first (sublayer is shared).
        if (FilterIdV6 != 0) {
            FwpmFilterDeleteById(EngineHandle, FilterIdV6);
        }
        if (AddCalloutIdV6 != 0) {
            FwpmCalloutDeleteById(EngineHandle, AddCalloutIdV6);
        }
        if (RegCalloutIdV6 != 0) {
            FwpsCalloutUnregisterById(RegCalloutIdV6);
        }

        // Remove V4 filter/callout and the shared sublayer.
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
        EngineHandle = NULL;
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

    // IPv6 — register callout + filter on OUTBOUND_TRANSPORT_V6.
    status = WfpRegisterCalloutV6();
    if (!NT_SUCCESS(status)) goto failure;

    status = WfpAddFilterV6();
    if (!NT_SUCCESS(status)) goto failure;

    // Harden WFP object security descriptors — restrict admin to read-only,
    // forcing attackers to gain SYSTEM or use a kernel driver.
    HardenWfpObjectSecurity();

    // Subscribe to real-time WFP change notifications — detect filter/sublayer
    // add/delete immediately rather than waiting for the 30s poll cycle.
    SubscribeWfpChangeNotifications();

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

// ---------------------------------------------------------------------------
// WFP change subscription callbacks — real-time detection.
//
// Polling via CheckIntegrity runs every 30s.  An attacker can add a filter,
// block telemetry, and remove it within the polling gap.  Change callbacks
// fire synchronously when WFP objects are created/deleted/modified, giving
// us immediate visibility.
//
// FwpmFilterSubscribeChanges0 — fires on filter add/delete
// FwpmSubLayerSubscribeChanges0 — fires on sublayer add/delete
// FwpmBfeStateSubscribeChanges0 — fires when BFE service starts/stops
// ---------------------------------------------------------------------------

// Shared alert emitter for change callbacks (uses CallbackObjects queue
// since we don't have a BufferQueue* in the callback context).
static VOID EmitWfpChangeAlert(const char* msg)
{
    NotifQueue* queue = CallbackObjects::GetNotifQueue();
    if (!queue || !msg) return;

    SIZE_T msgLen = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wfpc');
    if (!notif) return;
    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    SET_NETWORK_CHECK(*notif);
    notif->isPath = FALSE;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'wfcm');
    notif->bufSize = (ULONG)msgLen;
    if (notif->msg) {
        RtlCopyMemory(notif->msg, msg, msgLen);
        if (!queue->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

// Callback: a WFP filter was added or deleted on any layer.
// Note: FwpmFilterSubscribeChanges0 is user-mode only; these callbacks are
// retained for future use if kernel-mode subscribe becomes available.
#pragma warning(push)
#pragma warning(disable:4505)
static VOID CALLBACK WfpFilterChangeCallback(
    _Inout_ VOID* context,
    _In_ const FWPM_FILTER_CHANGE* change)
{
    if (!change || !context) return;
    WdfTcpipUtils* wfp = (WdfTcpipUtils*)context;

    // If it's our own filter being deleted (caught more precisely in CheckIntegrity),
    // emit an immediate alert — don't wait for the 30s poll.
    if (change->changeType == FWPM_CHANGE_DELETE &&
        change->filterId == wfp->GetFilterId()) {
        EmitWfpChangeAlert(
            "WFP TAMPER REALTIME: NortonEDR filter DELETED — immediate "
            "detection via FwpmFilterSubscribeChanges (attacker used "
            "FwpmFilterDeleteById0 or FwpmFilterDeleteByKey0)");
        return;
    }

    // A new filter was added by someone else — flag it.
    // The periodic CheckIntegrity will do the deep inspection (conditions,
    // weight, action type, EDR targeting).  This callback provides the
    // real-time alert so the attacker can't add-and-remove within the gap.
    if (change->changeType == FWPM_CHANGE_ADD &&
        change->filterId != wfp->GetFilterId()) {
        char msg[300];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "WFP CHANGE: new filter added (id=%llu) — real-time detection. "
            "Full inspection will run at next integrity check cycle",
            change->filterId);
        EmitWfpChangeAlert(msg);
    }
}

// Callback: a WFP sublayer was added or deleted.
static VOID CALLBACK WfpSubLayerChangeCallback(
    _Inout_ VOID* context,
    _In_ const FWPM_SUBLAYER_CHANGE* change)
{
    UNREFERENCED_PARAMETER(context);
    if (!change) return;

    // Check if our sublayer was deleted.
    if (change->changeType == FWPM_CHANGE_DELETE &&
        RtlCompareMemory(&change->subLayerKey,
            &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) == sizeof(GUID)) {
        EmitWfpChangeAlert(
            "WFP TAMPER REALTIME: NortonEDR sublayer DELETED — immediate "
            "detection via FwpmSubLayerSubscribeChanges (cascade deletion "
            "of all NortonEDR filters!)");
        return;
    }

    // A new sublayer was added by someone else.
    if (change->changeType == FWPM_CHANGE_ADD &&
        RtlCompareMemory(&change->subLayerKey,
            &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) != sizeof(GUID)) {
        EmitWfpChangeAlert(
            "WFP CHANGE: new sublayer added — real-time detection via "
            "FwpmSubLayerSubscribeChanges. Possible rogue sublayer injection");
    }
}
#pragma warning(pop)

// Callback: BFE (Base Filtering Engine) state changed.
// If BFE stops, ALL WFP objects (filters, callouts, sublayers) are destroyed.
// This is a nuclear attack — stop the BFE service and all EDR network
// monitoring disappears.
static VOID CALLBACK WfpBfeStateChangeCallback(
    _Inout_ VOID* context,
    _In_ FWPM_SERVICE_STATE newState)
{
    UNREFERENCED_PARAMETER(context);

    if (newState == FWPM_SERVICE_STOPPED) {
        EmitWfpChangeAlert(
            "WFP TAMPER CRITICAL: BFE (Base Filtering Engine) service STOPPED "
            "— ALL WFP filters, callouts, and sublayers destroyed! "
            "Network monitoring completely disabled. Attack vector: "
            "'net stop bfe' / sc stop bfe / service control manager");
    } else if (newState == FWPM_SERVICE_STOP_PENDING) {
        EmitWfpChangeAlert(
            "WFP TAMPER: BFE service STOP PENDING — WFP teardown imminent, "
            "all network monitoring will be lost");
    }
}

// Subscribe to WFP change notifications for real-time tamper detection.
VOID WdfTcpipUtils::SubscribeWfpChangeNotifications()
{
    if (!EngineHandle) return;

    // Note: FwpmFilterSubscribeChanges0 / FwpmSubLayerSubscribeChanges0 are
    // user-mode only APIs (fwpuclnt.lib) — not available in kernel mode.
    // Filter/sublayer tampering is detected via periodic enumeration instead.

    // Subscribe to BFE state changes (kernel-mode available).
    NTSTATUS st = FwpmBfeStateSubscribeChanges(
        EngineHandle,
        WfpBfeStateChangeCallback, this,
        &BfeStateChangeHandle);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[!] WFP: FwpmBfeStateSubscribeChanges failed: 0x%x\n", st);
    }

    DbgPrint("[+] WFP: real-time change subscriptions active\n");
}

// Unsubscribe from WFP change notifications (called during teardown).
VOID WdfTcpipUtils::UnsubscribeWfpChangeNotifications()
{
    if (!EngineHandle) return;

    if (BfeStateChangeHandle) {
        FwpmBfeStateUnsubscribeChanges(BfeStateChangeHandle);
        BfeStateChangeHandle = NULL;
    }
}

// ---------------------------------------------------------------------------
// WFP object security hardening.
//
// By default, WFP objects inherit permissive DACLs that allow any admin to
// modify/delete them.  EDRSilencer exploits this — it just calls
// FwpmFilterAdd/FwpmFilterDeleteById from an elevated process.
//
// We harden our objects by setting restrictive security descriptors via
// FwpmFilterSetSecurityInfoByKey / FwpmSubLayerSetSecurityInfoByKey:
//   - SYSTEM: full control (needed for BFE service operations)
//   - Our driver: full control (via DACL inherited from engine session)
//   - Administrators: READ-ONLY (can enumerate but not modify/delete)
//
// This forces an attacker to either:
//   1. Gain SYSTEM privileges (not just admin)
//   2. Use a kernel driver to bypass WFP security
//   3. Stop BFE entirely (detected by our BFE state subscription)
// ---------------------------------------------------------------------------

VOID WdfTcpipUtils::HardenWfpObjectSecurity()
{
    if (!EngineHandle) return;

    // Build a security descriptor granting:
    //   SYSTEM — full control
    //   Administrators — read-only (GENERIC_READ | GENERIC_EXECUTE)
    //
    // SDDL: O:SYG:SYD:(A;;GA;;;SY)(A;;GRGX;;;BA)
    //   O:SY = Owner: SYSTEM
    //   G:SY = Group: SYSTEM
    //   A;;GA;;;SY = Allow SYSTEM: Generic All
    //   A;;GRGX;;;BA = Allow Builtin Administrators: Generic Read + Execute
    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl,
        L"O:SYG:SYD:(A;;GA;;;SY)(A;;GRGX;;;BA)");

    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sdSize = 0;

    // Use SeConvertStringSecurityDescriptor or a pre-built binary SD.
    // For kernel drivers, the simplest approach is a static binary SD.
    // However, FwpmFilterSetSecurityInfoByKey expects component DACLs,
    // so we use the DACL-only approach.

    // Build a minimal DACL with two ACEs.
    // ACE 1: SYSTEM (S-1-5-18) — GENERIC_ALL
    // ACE 2: Administrators (S-1-5-32-544) — GENERIC_READ

    // Well-known SIDs
    SID systemSid = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SYSTEM_RID } };
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    UCHAR adminSidBuf[SECURITY_MAX_SID_SIZE];
    PSID adminSid = (PSID)adminSidBuf;
    ULONG adminSidSize = sizeof(adminSidBuf);

    // Build Administrators SID: S-1-5-32-544
    SID* pAdminSid = (SID*)adminSidBuf;
    pAdminSid->Revision = SID_REVISION;
    pAdminSid->SubAuthorityCount = 2;
    pAdminSid->IdentifierAuthority = ntAuth;
    pAdminSid->SubAuthority[0] = SECURITY_BUILTIN_DOMAIN_RID;
    pAdminSid->SubAuthority[1] = DOMAIN_ALIAS_RID_ADMINS;

    // Calculate DACL size
    ULONG daclSize = sizeof(ACL) +
        2 * sizeof(ACCESS_ALLOWED_ACE) -
        2 * sizeof(ULONG) +       // ACCESS_ALLOWED_ACE includes one ULONG for SidStart
        RtlLengthSid(&systemSid) +
        RtlLengthSid(adminSid);

    PACL dacl = (PACL)ExAllocatePool2(POOL_FLAG_NON_PAGED, daclSize, 'wfsd');
    if (!dacl) return;

    NTSTATUS st = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(st)) { ExFreePool(dacl); return; }

    // ACE 1: SYSTEM — full control (FWP_ACTRL_MATCH_FILTER is the WFP-specific right)
    st = RtlAddAccessAllowedAce(dacl, ACL_REVISION,
        GENERIC_ALL, &systemSid);
    if (!NT_SUCCESS(st)) { ExFreePool(dacl); return; }

    // ACE 2: Administrators — read-only
    st = RtlAddAccessAllowedAce(dacl, ACL_REVISION,
        GENERIC_READ | GENERIC_EXECUTE, adminSid);
    if (!NT_SUCCESS(st)) { ExFreePool(dacl); return; }

    // Apply to our filter
    if (FilterId != 0) {
        st = FwpmFilterSetSecurityInfoByKey(
            EngineHandle, nullptr, // key not needed; use FilterId-based approach below
            DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr);
        // Note: FwpmFilterSetSecurityInfoByKey uses the filter key, not FilterId.
        // We need to retrieve our filter to get its key, or set security on the sublayer
        // which cascades to all filters within it.
    }

    // Apply to our sublayer — this is more effective because sublayer security
    // cascades to restrict operations on all filters within the sublayer.
    st = FwpmSubLayerSetSecurityInfoByKey(
        EngineHandle, &NORTONAV_SUBLAYER_GUID,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, dacl, nullptr);
    if (NT_SUCCESS(st)) {
        DbgPrint("[+] WFP: sublayer security hardened — admins restricted to read-only\n");
    } else {
        DbgPrint("[!] WFP: FwpmSubLayerSetSecurityInfoByKey failed: 0x%x\n", st);
    }

    ExFreePool(dacl);
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

// Helper: translate FWP_MATCH_TYPE to string — reveals attacker intent.
// FWP_MATCH_NOT_EQUAL inverts logic (block everything EXCEPT attacker's C2).
static const char* MatchTypeName(FWP_MATCH_TYPE mt)
{
    switch (mt) {
    case FWP_MATCH_EQUAL:               return "==";
    case FWP_MATCH_GREATER:             return ">";
    case FWP_MATCH_LESS:                return "<";
    case FWP_MATCH_GREATER_OR_EQUAL:    return ">=";
    case FWP_MATCH_LESS_OR_EQUAL:       return "<=";
    case FWP_MATCH_RANGE:               return "RANGE";
    case FWP_MATCH_FLAGS_ALL_SET:       return "FLAGS_ALL";
    case FWP_MATCH_FLAGS_ANY_SET:       return "FLAGS_ANY";
    case FWP_MATCH_FLAGS_NONE_SET:      return "FLAGS_NONE";
    case FWP_MATCH_EQUAL_CASE_INSENSITIVE: return "==i";
    case FWP_MATCH_NOT_EQUAL:           return "!=";
    case FWP_MATCH_PREFIX:              return "PREFIX";
    case FWP_MATCH_NOT_PREFIX:          return "!PREFIX";
    default:                            return "?";
    }
}

// Helper: translate FWP_DATA_TYPE enum to readable name for diagnostics.
static const char* DataTypeName(FWP_DATA_TYPE dt)
{
    switch (dt) {
    case FWP_EMPTY:                     return "EMPTY";
    case FWP_UINT8:                     return "UINT8";
    case FWP_UINT16:                    return "UINT16";
    case FWP_UINT32:                    return "UINT32";
    case FWP_UINT64:                    return "UINT64";
    case FWP_INT8:                      return "INT8";
    case FWP_INT16:                     return "INT16";
    case FWP_INT32:                     return "INT32";
    case FWP_INT64:                     return "INT64";
    case FWP_FLOAT:                     return "FLOAT";
    case FWP_DOUBLE:                    return "DOUBLE";
    case FWP_BYTE_ARRAY16_TYPE:         return "BYTE_ARRAY16";
    case FWP_BYTE_BLOB_TYPE:            return "BYTE_BLOB";
    case FWP_SID:                       return "SID";
    case FWP_SECURITY_DESCRIPTOR_TYPE:  return "SEC_DESC";
    case FWP_TOKEN_INFORMATION_TYPE:    return "TOKEN_INFO";
    case FWP_TOKEN_ACCESS_INFORMATION_TYPE: return "TOKEN_ACCESS";
    case FWP_V4_ADDR_MASK:              return "V4_ADDR_MASK";
    case FWP_V6_ADDR_MASK:              return "V6_ADDR_MASK";
    case FWP_RANGE_TYPE:                return "RANGE";
    default:                            return "UNKNOWN";
    }
}

// Helper: format an IPv4 address (network byte order UINT32) as dotted-quad.
static void FormatIPv4(UINT32 addr, char* out, SIZE_T outSize)
{
    RtlStringCbPrintfA(out, outSize, "%u.%u.%u.%u",
        (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF, addr & 0xFF);
}

// Helper: build a human-readable summary of a filter's conditions.
// Handles all FWP_DATA_TYPE values and includes FWP_MATCH_TYPE for each
// condition, which is critical for detecting inverted logic attacks
// (FWP_MATCH_NOT_EQUAL = "block everything EXCEPT this address/app").
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

    for (UINT32 c = 0; c < filter->numFilterConditions && offset < outSize - 60; c++) {
        const FWPM_FILTER_CONDITION* cond = &filter->filterCondition[c];
        const char* fieldName = ConditionFieldName(cond->fieldKey);
        const char* matchOp = MatchTypeName(cond->matchType);
        const char* field = fieldName ? fieldName : "unk_field";

        switch (cond->conditionValue.type) {

        case FWP_UINT8:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s %u] ", field, matchOp, cond->conditionValue.uint8);
            break;

        case FWP_UINT16:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s %u] ", field, matchOp, cond->conditionValue.uint16);
            break;

        case FWP_UINT32: {
            // IP_REMOTE_ADDRESS and IP_LOCAL_ADDRESS are UINT32 IPv4 addrs
            if (fieldName &&
                (_stricmp(fieldName, "IP_REMOTE_ADDRESS") == 0 ||
                 _stricmp(fieldName, "IP_LOCAL_ADDRESS") == 0)) {
                char ipStr[20];
                FormatIPv4(cond->conditionValue.uint32, ipStr, sizeof(ipStr));
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s %s] ", field, matchOp, ipStr);
            } else {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s 0x%x] ", field, matchOp, cond->conditionValue.uint32);
            }
            break;
        }

        case FWP_UINT64:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s 0x%llx] ", field, matchOp,
                cond->conditionValue.uint64 ? *cond->conditionValue.uint64 : 0ULL);
            break;

        case FWP_BYTE_BLOB_TYPE:
            if (cond->conditionValue.byteBlob &&
                cond->conditionValue.byteBlob->data) {
                const WCHAR* path = (const WCHAR*)cond->conditionValue.byteBlob->data;
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s '%.60S'] ", field, matchOp, path);
            } else {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s <blob>] ", field, matchOp);
            }
            break;

        case FWP_V4_ADDR_MASK:
            if (cond->conditionValue.v4AddrMask) {
                char addrStr[20], maskStr[20];
                FormatIPv4(cond->conditionValue.v4AddrMask->addr,
                           addrStr, sizeof(addrStr));
                FormatIPv4(cond->conditionValue.v4AddrMask->mask,
                           maskStr, sizeof(maskStr));
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s %s/%s] ", field, matchOp, addrStr, maskStr);
            } else {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s <v4mask>] ", field, matchOp);
            }
            break;

        case FWP_V6_ADDR_MASK:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s <v6mask>] ", field, matchOp);
            break;

        case FWP_BYTE_ARRAY16_TYPE:
            // IPv6 address — 16 bytes, show abbreviated
            if (cond->conditionValue.byteArray16) {
                const UINT8* b = cond->conditionValue.byteArray16->byteArray16;
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s %02x%02x:%02x%02x:..:%02x%02x] ", field, matchOp,
                    b[0], b[1], b[2], b[3], b[14], b[15]);
            } else {
                RtlStringCbPrintfA(out + offset, outSize - offset,
                    "[%s %s <ipv6>] ", field, matchOp);
            }
            break;

        case FWP_RANGE_TYPE:
            // FWP_RANGE contains valueLow and valueHigh — commonly port ranges
            if (cond->conditionValue.rangeValue) {
                FWP_RANGE* r = cond->conditionValue.rangeValue;
                if (r->valueLow.type == FWP_UINT16) {
                    RtlStringCbPrintfA(out + offset, outSize - offset,
                        "[%s %s %u-%u] ", field, matchOp,
                        r->valueLow.uint16, r->valueHigh.uint16);
                } else if (r->valueLow.type == FWP_UINT32) {
                    char loStr[20], hiStr[20];
                    FormatIPv4(r->valueLow.uint32, loStr, sizeof(loStr));
                    FormatIPv4(r->valueHigh.uint32, hiStr, sizeof(hiStr));
                    RtlStringCbPrintfA(out + offset, outSize - offset,
                        "[%s %s %s..%s] ", field, matchOp, loStr, hiStr);
                } else {
                    RtlStringCbPrintfA(out + offset, outSize - offset,
                        "[%s %s <range:%s>] ", field, matchOp,
                        DataTypeName(r->valueLow.type));
                }
            }
            break;

        case FWP_SID:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s <SID>] ", field, matchOp);
            break;

        case FWP_SECURITY_DESCRIPTOR_TYPE:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s <SEC_DESC>] ", field, matchOp);
            break;

        case FWP_TOKEN_INFORMATION_TYPE:
        case FWP_TOKEN_ACCESS_INFORMATION_TYPE:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s <TOKEN>] ", field, matchOp);
            break;

        default:
            RtlStringCbPrintfA(out + offset, outSize - offset,
                "[%s %s <type=%s>] ", field, matchOp,
                DataTypeName(cond->conditionValue.type));
            break;
        }
        offset = strlen(out);
    }
}

// Helper: check if any condition uses inverted match logic.
// FWP_MATCH_NOT_EQUAL is an attacker technique to create "block everything
// EXCEPT my C2 traffic" or "permit ONLY my exfil destination" rules.
static BOOLEAN HasInvertedMatchCondition(const FWPM_FILTER_CONDITION* conds,
                                         UINT32 numConds)
{
    for (UINT32 c = 0; c < numConds; c++) {
        if (conds[c].matchType == FWP_MATCH_NOT_EQUAL ||
            conds[c].matchType == FWP_MATCH_NOT_PREFIX)
            return TRUE;
    }
    return FALSE;
}

// Helper: translate FWP_ACTION_TYPE to readable string.
static const char* ActionTypeName(UINT32 actionType)
{
    switch (actionType) {
    case FWP_ACTION_BLOCK:                return "BLOCK";
    case FWP_ACTION_PERMIT:               return "PERMIT";
    case FWP_ACTION_CALLOUT_TERMINATING:  return "CALLOUT_TERMINATING";
    case FWP_ACTION_CALLOUT_INSPECTION:   return "CALLOUT_INSPECTION";
    case FWP_ACTION_CALLOUT_UNKNOWN:      return "CALLOUT_UNKNOWN";
    case FWP_ACTION_CONTINUE:             return "CONTINUE";
    case FWP_ACTION_NONE:                 return "NONE";
    case FWP_ACTION_NONE_NO_MATCH:        return "NONE_NO_MATCH";
    default:                              return "UNKNOWN_ACTION";
    }
}

// Helper: enumerate foreign filters on a given layer.
// Detects the full spectrum of WFP firewalling attacks:
//
//   BLOCK                  — EDRSilencer: block EDR telemetry outright
//   CALLOUT_TERMINATING    — rogue callout drops packets before ours fires
//   CALLOUT_INSPECTION     — silent MITM: inspect/modify packets without
//                            blocking; attacker can exfiltrate or tamper
//                            with telemetry content in-flight
//   CALLOUT_UNKNOWN        — undetermined callout that may block or pass
//   PERMIT (high-weight)   — whitelist attacker C2/exfil traffic past
//                            Windows Firewall BLOCK rules; also used to
//                            override our sublayer's BLOCK decisions via
//                            sublayer arbitration if placed in a different
//                            sublayer with higher weight
//   Inverted match logic   — FWP_MATCH_NOT_EQUAL conditions create
//                            "block everything EXCEPT <C2 addr>" rules
//   Blanket filters        — 0 conditions = affects ALL traffic on the layer
//
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
    enumTemplate.actionMask         = 0xFFFFFFFF;  // all action types

    NTSTATUS st = FwpmFilterCreateEnumHandle(engine, &enumTemplate, &enumHandle);
    if (!NT_SUCCESS(st) || !enumHandle) return ok;

    FWPM_FILTER** entries = nullptr;
    UINT32 numEntries = 0;
    st = FwpmFilterEnum(engine, enumHandle, 128, &entries, &numEntries);
    if (!NT_SUCCESS(st) || !entries) {
        FwpmFilterDestroyEnumHandle(engine, enumHandle);
        return ok;
    }

    for (UINT32 i = 0; i < numEntries; i++) {
        if (!entries[i]) continue;
        // Skip our own filter
        if (entries[i]->filterId == ourFilterId) continue;
        // Skip filters in our own sublayer
        if (RtlCompareMemory(&entries[i]->subLayerKey,
                &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) == sizeof(GUID))
            continue;

        const UINT32 action = entries[i]->action.type;
        BOOLEAN foreignCallout = FALSE;
        BOOLEAN suspicious = FALSE;
        const char* threatDesc = nullptr;

        // --- Category 1: BLOCK filters (EDRSilencer) ---
        if (action == FWP_ACTION_BLOCK) {
            suspicious = TRUE;
            threatDesc = "EDRSilencer / telemetry blocking";
        }

        // --- Category 2: CALLOUT_TERMINATING with foreign callout key ---
        // Rogue callout drops packets before ours fires.
        if (action == FWP_ACTION_CALLOUT_TERMINATING) {
            if (RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_GUID, sizeof(GUID)) != sizeof(GUID) &&
                RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_V6_GUID, sizeof(GUID)) != sizeof(GUID)) {
                suspicious = TRUE;
                foreignCallout = TRUE;
                threatDesc = "rogue terminating callout may drop packets "
                             "before NortonEDR callout fires";
            }
        }

        // --- Category 3: CALLOUT_INSPECTION with foreign callout key ---
        // Silent interception: callout can read/modify packet content
        // without blocking.  Used for MITM, telemetry tampering, or
        // covert exfil channel injection.
        if (action == FWP_ACTION_CALLOUT_INSPECTION) {
            if (RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_GUID, sizeof(GUID)) != sizeof(GUID) &&
                RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_V6_GUID, sizeof(GUID)) != sizeof(GUID)) {
                suspicious = TRUE;
                foreignCallout = TRUE;
                threatDesc = "silent inspection callout — may MITM, tamper "
                             "with, or exfiltrate packet data without blocking";
            }
        }

        // --- Category 4: CALLOUT_UNKNOWN with foreign callout key ---
        // Undetermined action — the callout decides at runtime whether to
        // block, permit, or continue.  Effectively a wildcard.
        if (action == FWP_ACTION_CALLOUT_UNKNOWN) {
            if (RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_GUID, sizeof(GUID)) != sizeof(GUID) &&
                RtlCompareMemory(&entries[i]->action.calloutKey,
                    &NORTONAV_CALLOUT_V6_GUID, sizeof(GUID)) != sizeof(GUID)) {
                suspicious = TRUE;
                foreignCallout = TRUE;
                threatDesc = "unknown-action callout — runtime decision to "
                             "block/permit, unpredictable interception";
            }
        }

        // --- Category 5: High-weight PERMIT filters ---
        // Attack: add a PERMIT filter at max weight to whitelist C2/exfil
        // traffic past Windows Firewall BLOCK rules, or to override our
        // sublayer's block decisions via WFP sublayer arbitration.
        // Explicit UINT64 weights always outrank auto UINT8 weights.
        // Non-persistent = added at runtime (not boot-time OS component).
        if (action == FWP_ACTION_PERMIT) {
            BOOLEAN highWeight =
                (entries[i]->weight.type == FWP_UINT64) ||  // explicit = always high
                (entries[i]->weight.type == FWP_UINT8 &&
                 entries[i]->weight.uint8 >= 13);
            BOOLEAN nonPersistent = !(entries[i]->flags & FWPM_FILTER_FLAG_PERSISTENT);

            if (highWeight && nonPersistent) {
                suspicious = TRUE;
                threatDesc = "high-weight non-persistent PERMIT — may whitelist "
                             "C2/exfil traffic or override BLOCK decisions";
            }
        }

        if (!suspicious) continue;

        // Build condition description with full FWP_DATA_TYPE + FWP_MATCH_TYPE
        char condDesc[700];
        DescribeFilterConditions(entries[i], condDesc, sizeof(condDesc));

        // Check if conditions specifically target EDR processes
        BOOLEAN targetsEdr = ConditionTargetsEdr(
            entries[i]->filterCondition,
            entries[i]->numFilterConditions);

        // Check for inverted match logic (NOT_EQUAL / NOT_PREFIX)
        BOOLEAN inverted = HasInvertedMatchCondition(
            entries[i]->filterCondition,
            entries[i]->numFilterConditions);

        // Check for blanket (no conditions) — affects ALL traffic
        BOOLEAN blanket = (entries[i]->numFilterConditions == 0);

        // Extract effective weight for reporting.
        // FWP_VALUE can store weight as UINT8 (auto-generated from BFE
        // auto-weight algorithm, 0-15), UINT64 (explicit weight set by
        // caller), or FWP_EMPTY.  WFP evaluates higher-weight filters
        // first within a sublayer.
        UINT64 effectiveWeight = 0;
        const char* weightType = "auto";
        if (entries[i]->weight.type == FWP_UINT64 && entries[i]->weight.uint64) {
            effectiveWeight = *entries[i]->weight.uint64;
            weightType = "explicit";
        } else if (entries[i]->weight.type == FWP_UINT8) {
            effectiveWeight = entries[i]->weight.uint8;
            weightType = "auto";
        }

        // Flag if the foreign filter outweighs ours (UINT8 0xf = 15).
        // Our filter uses auto-weight 0xf.  An explicit UINT64 weight always
        // outranks auto UINT8 weights.  Within UINT8, > 0xf outranks us.
        BOOLEAN outweighsUs =
            (entries[i]->weight.type == FWP_UINT64) ||  // explicit always wins
            (entries[i]->weight.type == FWP_UINT8 &&
             entries[i]->weight.uint8 >= 0xf);

        const char* actionStr = ActionTypeName(action);

        // Build weight context string
        char weightInfo[120];
        RtlStringCbPrintfA(weightInfo, sizeof(weightInfo),
            "weight=%llu(%s)%s",
            effectiveWeight, weightType,
            outweighsUs ? " OUTWEIGHS-NORTON" : "");

        // Build severity prefix and tactical context
        char msg[1000];
        if (targetsEdr) {
            RtlStringCbPrintfA(msg, sizeof(msg),
                "WFP TAMPER CRITICAL: foreign %s filter (id=%llu, %s) on %s "
                "TARGETS EDR PROCESS — %s. display='%S', %s",
                actionStr, entries[i]->filterId, weightInfo, layerName,
                threatDesc,
                entries[i]->displayData.name
                    ? entries[i]->displayData.name : L"<none>",
                condDesc);
        } else if (inverted) {
            RtlStringCbPrintfA(msg, sizeof(msg),
                "WFP TAMPER: foreign %s filter (id=%llu, %s) on %s uses "
                "INVERTED MATCH (NOT_EQUAL) — %s. Inverted logic may mean "
                "'block everything EXCEPT attacker traffic'. display='%S', %s",
                actionStr, entries[i]->filterId, weightInfo, layerName,
                threatDesc,
                entries[i]->displayData.name
                    ? entries[i]->displayData.name : L"<none>",
                condDesc);
        } else if (blanket) {
            RtlStringCbPrintfA(msg, sizeof(msg),
                "WFP TAMPER: foreign %s filter (id=%llu, %s) on %s with "
                "NO CONDITIONS (blanket rule affects ALL traffic) — %s. "
                "display='%S'",
                actionStr, entries[i]->filterId, weightInfo, layerName,
                threatDesc,
                entries[i]->displayData.name
                    ? entries[i]->displayData.name : L"<none>");
        } else {
            RtlStringCbPrintfA(msg, sizeof(msg),
                "WFP TAMPER: foreign %s filter (id=%llu, %s) on %s — %s. "
                "display='%S', %s",
                actionStr, entries[i]->filterId, weightInfo, layerName,
                threatDesc,
                entries[i]->displayData.name
                    ? entries[i]->displayData.name : L"<none>",
                condDesc);
        }
        EmitWfpAlert(bufQueue, msg);
        ok = FALSE;
    }

    FwpmFreeMemory((void**)&entries);
    FwpmFilterDestroyEnumHandle(engine, enumHandle);
    return ok;
}

BOOLEAN WdfTcpipUtils::CheckIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue) return FALSE;
    BOOLEAN ok = TRUE;

    // -----------------------------------------------------------------------
    // Check 0: verify our WFP engine handle is still valid.
    //
    // Attacks:
    //   - Handle closure: attacker with kernel access calls ObCloseHandle /
    //     ZwClose on our EngineHandle, or calls FwpmEngineClose0 from
    //     user-mode if they can duplicate our handle.
    //   - BFE service stop: stopping the BFE service invalidates all
    //     engine handles — every subsequent WFP API call returns
    //     STATUS_FWP_NOT_FOUND or similar.
    //   - Handle table corruption: DKOM attack zeroing our handle entry.
    //
    // We validate by attempting a lightweight WFP operation.
    // -----------------------------------------------------------------------
    if (!EngineHandle) {
        EmitWfpAlert(bufQueue,
            "WFP TAMPER CRITICAL: engine handle is NULL — WFP infrastructure "
            "has been torn down or handle was closed! All network monitoring "
            "is disabled. Attack vector: FwpmEngineClose / BFE service stop / "
            "handle table corruption via DKOM");
        return FALSE;
    }

    // Probe the engine handle with a lightweight query.
    // FwpmSubLayerGetByKey with our GUID is cheap and confirms the handle works.
    {
        FWPM_SUBLAYER* probeObj = nullptr;
        NTSTATUS probeSt = FwpmSubLayerGetByKey(EngineHandle,
            &NORTONAV_SUBLAYER_GUID, &probeObj);
        if (probeObj) FwpmFreeMemory((void**)&probeObj);

        // If the sublayer doesn't exist, Check 3 will catch it.
        // But if the ENGINE HANDLE itself is invalid, we get
        // STATUS_INVALID_HANDLE or STATUS_FWP_E_* errors.
        if (probeSt == STATUS_INVALID_HANDLE ||
            probeSt == STATUS_FWP_NOT_FOUND) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER CRITICAL: engine handle INVALIDATED — WFP API "
                "returned STATUS_INVALID_HANDLE/NOT_FOUND. BFE may have been "
                "restarted or handle was closed via NtClose/FwpmEngineClose");
            // Try to re-open the engine for self-healing
            HANDLE newHandle = NULL;
            NTSTATUS reopenSt = FwpmEngineOpen0(
                NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &newHandle);
            if (NT_SUCCESS(reopenSt) && newHandle) {
                EngineHandle = newHandle;
                DbgPrint("[!] WFP: engine handle re-opened after invalidation\n");
                // Note: our filter/callout/sublayer are gone if BFE restarted.
                // CheckIntegrity will detect this and alert on the missing objects.
            } else {
                return FALSE;  // Can't recover — BFE is down
            }
        }
    }

    // -----------------------------------------------------------------------
    // Check 1: verify our filter is still registered AND its properties
    // have not been tampered with.
    //
    // Attacks beyond simple deletion:
    //   - Weight downgrade: FwpmFilterSetSecurityInfoByKey / re-add at lower
    //     weight — our filter evaluates last, attacker's high-weight filter
    //     in the same sublayer blocks first.
    //   - Action type swap: change from CALLOUT_TERMINATING to PERMIT or
    //     CONTINUE — our callout classifyFn stops being invoked.
    //   - Callout key swap: redirect to a rogue callout GUID — our filter
    //     invokes attacker code instead of our classifyFn.
    //   - Layer migration: move filter to a different layer where it's inert.
    //   - Sublayer migration: move filter to attacker-controlled sublayer.
    //   - Condition injection: add filterConditions that restrict which
    //     packets reach our callout (e.g., exclude attacker C2 traffic).
    //
    // We baseline these values at registration and verify every cycle.
    // -----------------------------------------------------------------------
    if (FilterId != 0) {
        FWPM_FILTER* filterObj = nullptr;
        NTSTATUS st = FwpmFilterGetById(EngineHandle, FilterId, &filterObj);
        if (!NT_SUCCESS(st) || !filterObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR WFP filter DELETED (FwpmFilterDeleteById) "
                "— network telemetry and blocking disabled! EDRSilencer-class attack");
            ok = FALSE;
        } else {
            // Verify weight has not been downgraded.
            // We registered with FWP_UINT8 = 0xf.
            BOOLEAN weightOk = FALSE;
            if (filterObj->weight.type == FWP_UINT8 &&
                filterObj->weight.uint8 == 0xf)
                weightOk = TRUE;
            if (!weightOk) {
                char msg[300];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "WFP TAMPER: NortonEDR filter weight DOWNGRADED "
                    "(expected UINT8/0xf, got type=%u val=%llu) — attacker "
                    "filters at higher weight evaluate first, blocking before "
                    "our callout fires",
                    filterObj->weight.type,
                    (filterObj->weight.type == FWP_UINT64 && filterObj->weight.uint64)
                        ? *filterObj->weight.uint64
                        : (UINT64)filterObj->weight.uint8);
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }

            // Verify action type has not been swapped.
            if (filterObj->action.type != FWP_ACTION_CALLOUT_TERMINATING) {
                char msg[300];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "WFP TAMPER: NortonEDR filter action type CHANGED from "
                    "CALLOUT_TERMINATING to %s — classifyFn may not fire or "
                    "filter becomes a no-op",
                    ActionTypeName(filterObj->action.type));
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }

            // Verify callout key still points to our callout.
            if (RtlCompareMemory(&filterObj->action.calloutKey,
                    &NORTONAV_CALLOUT_GUID, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR filter callout key REDIRECTED to "
                    "foreign GUID — our filter now invokes attacker code "
                    "instead of NortonEDR classifyFn!");
                ok = FALSE;
            }

            // Verify filter is still on our layer.
            if (RtlCompareMemory(&filterObj->layerKey,
                    &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR filter MOVED to different layer "
                    "— no longer monitoring outbound transport traffic");
                ok = FALSE;
            }

            // Verify filter is still in our sublayer.
            if (RtlCompareMemory(&filterObj->subLayerKey,
                    &NORTONAV_SUBLAYER_GUID, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR filter MOVED to foreign sublayer "
                    "— no longer under NortonEDR sublayer arbitration control");
                ok = FALSE;
            }

            // Verify no conditions were injected.
            // We registered with numFilterConditions = 0 (blanket match).
            // Injecting conditions would restrict which packets reach our
            // callout — e.g., exclude attacker C2 traffic by adding a
            // NOT_EQUAL condition on IP_REMOTE_ADDRESS.
            if (filterObj->numFilterConditions != 0) {
                char condDesc[512];
                DescribeFilterConditions(filterObj, condDesc, sizeof(condDesc));
                char msg[700];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "WFP TAMPER: NortonEDR filter has %u CONDITIONS INJECTED "
                    "(registered with 0) — attacker restricting which packets "
                    "reach our callout. %s",
                    filterObj->numFilterConditions, condDesc);
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }
        }
        if (filterObj) FwpmFreeMemory((void**)&filterObj);
    }

    // Check 1b: Verify IPv6 filter integrity (mirrors V4 checks above).
    if (FilterIdV6 != 0) {
        FWPM_FILTER* filterObj = nullptr;
        NTSTATUS st = FwpmFilterGetById(EngineHandle, FilterIdV6, &filterObj);
        if (!NT_SUCCESS(st) || !filterObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR IPv6 WFP filter DELETED — "
                "IPv6 network telemetry and blocking disabled!");
            ok = FALSE;
        } else {
            if (filterObj->action.type != FWP_ACTION_CALLOUT_TERMINATING) {
                char msg[256];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "WFP TAMPER: NortonEDR IPv6 filter action type CHANGED from "
                    "CALLOUT_TERMINATING to %s",
                    ActionTypeName(filterObj->action.type));
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }
            if (RtlCompareMemory(&filterObj->action.calloutKey,
                    &NORTONAV_CALLOUT_V6_GUID, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR IPv6 filter callout key REDIRECTED "
                    "to foreign GUID!");
                ok = FALSE;
            }
            if (RtlCompareMemory(&filterObj->layerKey,
                    &FWPM_LAYER_OUTBOUND_TRANSPORT_V6, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR IPv6 filter MOVED to different layer");
                ok = FALSE;
            }
            if (filterObj->numFilterConditions != 0) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR IPv6 filter has CONDITIONS INJECTED "
                    "(registered with 0)");
                ok = FALSE;
            }
        }
        if (filterObj) FwpmFreeMemory((void**)&filterObj);
    }

    // -----------------------------------------------------------------------
    // Check 2: verify our callout is still registered AND on the correct layer.
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
        } else {
            // Verify callout is still on our layer.
            if (RtlCompareMemory(&calloutObj->applicableLayer,
                    &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR callout MOVED to different layer "
                    "— classifyFn no longer fires for outbound transport");
                ok = FALSE;
            }
        }
        if (calloutObj) FwpmFreeMemory((void**)&calloutObj);
    }

    // Check 2b: Verify IPv6 callout registration.
    if (AddCalloutIdV6 != 0) {
        FWPM_CALLOUT* calloutObj = nullptr;
        NTSTATUS st = FwpmCalloutGetById(EngineHandle, AddCalloutIdV6, &calloutObj);
        if (!NT_SUCCESS(st) || !calloutObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR IPv6 callout DELETED — "
                "IPv6 classifyFn will not be invoked");
            ok = FALSE;
        } else {
            if (RtlCompareMemory(&calloutObj->applicableLayer,
                    &FWPM_LAYER_OUTBOUND_TRANSPORT_V6, sizeof(GUID)) != sizeof(GUID)) {
                EmitWfpAlert(bufQueue,
                    "WFP TAMPER: NortonEDR IPv6 callout MOVED to different layer");
                ok = FALSE;
            }
        }
        if (calloutObj) FwpmFreeMemory((void**)&calloutObj);
    }

    // -----------------------------------------------------------------------
    // Check 3: verify our sublayer is still registered AND its weight has
    // not been tampered with.
    //
    // Attacks:
    //   - FwpmSubLayerDeleteByKey — removes our sublayer, cascading deletion
    //     of all our filters.
    //   - Weight downgrade: lower our sublayer weight so attacker sublayers
    //     at higher weight get evaluated first in WFP arbitration.  If the
    //     attacker's sublayer issues BLOCK, WFP blocks regardless of our
    //     sublayer's PERMIT decision.
    //   - Weight inversion: set our weight to 0 so we're dead last.
    // -----------------------------------------------------------------------
    {
        FWPM_SUBLAYER* subObj = nullptr;
        NTSTATUS st = FwpmSubLayerGetByKey(EngineHandle, &NORTONAV_SUBLAYER_GUID, &subObj);
        if (!NT_SUCCESS(st) || !subObj) {
            EmitWfpAlert(bufQueue,
                "WFP TAMPER: NortonEDR sublayer DELETED via FwpmSubLayerDeleteByKey "
                "— all filters in our sublayer cascade-deleted");
            ok = FALSE;
        } else {
            // We registered with weight = 0x0f.
            if (subObj->weight != 0x0f) {
                char msg[300];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "WFP TAMPER: NortonEDR sublayer weight CHANGED from "
                    "0x0f to 0x%04x — %s",
                    subObj->weight,
                    subObj->weight < 0x0f
                        ? "DOWNGRADED — attacker sublayers now outweigh ours "
                          "in WFP arbitration"
                        : "MODIFIED — sublayer arbitration order altered");
                EmitWfpAlert(bufQueue, msg);
                ok = FALSE;
            }
        }
        if (subObj) FwpmFreeMemory((void**)&subObj);
    }

    // -----------------------------------------------------------------------
    // Check 4: enumerate foreign filters across ALL attackable WFP layers.
    //
    // WFP has 20+ layers.  An attacker is not limited to the layer we monitor
    // — they can block, intercept, or modify traffic at any layer in the
    // network stack.  We check every layer category:
    //
    // OUTBOUND (block EDR telemetry leaving the host):
    //   - OUTBOUND_TRANSPORT_V4/V6 — our callout layer; most common target
    //   - OUTBOUND_IPPACKET_V4/V6  — IP-level; pre-empts transport
    //
    // ALE (connection lifecycle control):
    //   - ALE_AUTH_CONNECT_V4/V6      — block outbound connection auth
    //   - ALE_AUTH_RECV_ACCEPT_V4/V6  — block inbound connections to EDR
    //   - ALE_AUTH_LISTEN_V4/V6       — prevent EDR from binding listeners
    //   - ALE_RESOURCE_ASSIGNMENT_V4/V6 — prevent socket resource acquisition
    //   - ALE_ENDPOINT_CLOSURE_V4/V6  — force-close EDR connections
    //   - ALE_FLOW_ESTABLISHED_V4/V6  — intercept established flows
    //
    // STREAM (TCP content MITM — inspect/modify/drop stream data):
    //   - STREAM_V4/V6            — modify TCP payload in-flight
    //   - STREAM_PACKET_V4/V6    — raw TCP segment manipulation
    //   An attacker with a stream callout can silently modify telemetry
    //   payloads (change severity, drop detections, inject false data)
    //   without blocking the connection — invisible to our transport check.
    //
    // INBOUND (block telemetry server responses / C2 command replies):
    //   - INBOUND_TRANSPORT_V4/V6 — block inbound TCP/UDP
    //   - INBOUND_IPPACKET_V4/V6  — block at IP level
    //
    // DATAGRAM (UDP telemetry — DNS, syslog, SNMP traps):
    //   - DATAGRAM_DATA_V4/V6     — block/modify UDP payloads
    //
    // -----------------------------------------------------------------------

    // Structure to drive the layer scan — layer GUID + human-readable name.
    static const struct {
        const GUID* layerKey;
        const char* layerName;
    } kLayersToCheck[] = {
        // Outbound — block EDR telemetry
        { &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,        "OUTBOUND_TRANSPORT_V4" },
        { &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,        "OUTBOUND_TRANSPORT_V6" },
        { &FWPM_LAYER_OUTBOUND_IPPACKET_V4,         "OUTBOUND_IPPACKET_V4" },
        { &FWPM_LAYER_OUTBOUND_IPPACKET_V6,         "OUTBOUND_IPPACKET_V6" },
        // ALE — connection lifecycle attacks
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V4,           "ALE_AUTH_CONNECT_V4" },
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V6,           "ALE_AUTH_CONNECT_V6" },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,       "ALE_AUTH_RECV_ACCEPT_V4" },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,       "ALE_AUTH_RECV_ACCEPT_V6" },
        { &FWPM_LAYER_ALE_AUTH_LISTEN_V4,            "ALE_AUTH_LISTEN_V4" },
        { &FWPM_LAYER_ALE_AUTH_LISTEN_V6,            "ALE_AUTH_LISTEN_V6" },
        { &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,    "ALE_RESOURCE_ASSIGNMENT_V4" },
        { &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,    "ALE_RESOURCE_ASSIGNMENT_V6" },
        { &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,       "ALE_ENDPOINT_CLOSURE_V4" },
        { &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,       "ALE_ENDPOINT_CLOSURE_V6" },
        { &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,       "ALE_FLOW_ESTABLISHED_V4" },
        { &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,       "ALE_FLOW_ESTABLISHED_V6" },
        // Stream — TCP content MITM (silent telemetry modification)
        { &FWPM_LAYER_STREAM_V4,                     "STREAM_V4" },
        { &FWPM_LAYER_STREAM_V6,                     "STREAM_V6" },
        // Datagram — UDP telemetry (DNS, syslog, SNMP)
        { &FWPM_LAYER_DATAGRAM_DATA_V4,              "DATAGRAM_DATA_V4" },
        { &FWPM_LAYER_DATAGRAM_DATA_V6,              "DATAGRAM_DATA_V6" },
        // Inbound — block telemetry server responses
        { &FWPM_LAYER_INBOUND_TRANSPORT_V4,          "INBOUND_TRANSPORT_V4" },
        { &FWPM_LAYER_INBOUND_TRANSPORT_V6,          "INBOUND_TRANSPORT_V6" },
        { &FWPM_LAYER_INBOUND_IPPACKET_V4,           "INBOUND_IPPACKET_V4" },
        { &FWPM_LAYER_INBOUND_IPPACKET_V6,           "INBOUND_IPPACKET_V6" },
    };

    for (int li = 0; li < ARRAYSIZE(kLayersToCheck); li++) {
        // Pass our FilterId only for our own layer so it gets skipped
        UINT64 skipId = (RtlCompareMemory(kLayersToCheck[li].layerKey,
            &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, sizeof(GUID)) == sizeof(GUID))
            ? FilterId : 0;

        if (!CheckLayerForForeignBlocks(EngineHandle,
                *kLayersToCheck[li].layerKey, skipId,
                kLayersToCheck[li].layerName, bufQueue))
            ok = FALSE;
    }

    // -----------------------------------------------------------------------
    // Check 5: enumerate foreign callouts on critical layers.
    //
    // Attack: fwpuclnt!FwpmCalloutAdd registers a rogue callout.  Paired with
    // a high-weight CALLOUT_TERMINATING filter, the rogue callout's classifyFn
    // fires first and can block/modify traffic before ours.
    //
    // Stream layers are especially dangerous — a CALLOUT_INSPECTION callout
    // on STREAM_V4 can silently read/modify TCP payload data (MITM attack on
    // telemetry content) without blocking the connection at all.
    //
    // We enumerate callouts across our layer + stream + inbound layers.
    // -----------------------------------------------------------------------
    {
        static const struct {
            const GUID* layerKey;
            const char* layerName;
        } kCalloutLayers[] = {
            { &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "OUTBOUND_TRANSPORT_V4" },
            { &FWPM_LAYER_OUTBOUND_TRANSPORT_V6, "OUTBOUND_TRANSPORT_V6" },
            { &FWPM_LAYER_STREAM_V4,             "STREAM_V4" },
            { &FWPM_LAYER_STREAM_V6,             "STREAM_V6" },
            { &FWPM_LAYER_INBOUND_TRANSPORT_V4,  "INBOUND_TRANSPORT_V4" },
            { &FWPM_LAYER_INBOUND_TRANSPORT_V6,  "INBOUND_TRANSPORT_V6" },
            { &FWPM_LAYER_ALE_AUTH_CONNECT_V4,   "ALE_AUTH_CONNECT_V4" },
            { &FWPM_LAYER_ALE_AUTH_CONNECT_V6,   "ALE_AUTH_CONNECT_V6" },
        };

        for (int cl = 0; cl < ARRAYSIZE(kCalloutLayers); cl++) {
            HANDLE enumHandle = nullptr;
            FWPM_CALLOUT_ENUM_TEMPLATE enumTemplate = {};
            enumTemplate.layerKey = *kCalloutLayers[cl].layerKey;

            NTSTATUS st = FwpmCalloutCreateEnumHandle(
                EngineHandle, &enumTemplate, &enumHandle);
            if (!NT_SUCCESS(st) || !enumHandle) continue;

            FWPM_CALLOUT** callouts = nullptr;
            UINT32 numCallouts = 0;
            st = FwpmCalloutEnum(EngineHandle, enumHandle, 64, &callouts, &numCallouts);
            if (NT_SUCCESS(st) && callouts) {
                for (UINT32 i = 0; i < numCallouts; i++) {
                    if (!callouts[i]) continue;
                    // Skip our own callouts (V4 and V6)
                    if (RtlCompareMemory(&callouts[i]->calloutKey,
                            &NORTONAV_CALLOUT_GUID, sizeof(GUID)) == sizeof(GUID) ||
                        RtlCompareMemory(&callouts[i]->calloutKey,
                            &NORTONAV_CALLOUT_V6_GUID, sizeof(GUID)) == sizeof(GUID))
                        continue;

                    // Non-persistent foreign callouts are suspicious.
                    BOOLEAN suspicious = !(callouts[i]->flags & FWPM_CALLOUT_FLAG_PERSISTENT);

                    if (suspicious) {
                        // Stream layer callouts are especially dangerous — MITM
                        BOOLEAN isStreamLayer =
                            (RtlCompareMemory(kCalloutLayers[cl].layerKey,
                                &FWPM_LAYER_STREAM_V4, sizeof(GUID)) == sizeof(GUID)) ||
                            (RtlCompareMemory(kCalloutLayers[cl].layerKey,
                                &FWPM_LAYER_STREAM_V6, sizeof(GUID)) == sizeof(GUID));

                        char msg[400];
                        RtlStringCbPrintfA(msg, sizeof(msg),
                            "WFP: non-persistent foreign callout on %s "
                            "(id=%lu, display='%S') — %s",
                            kCalloutLayers[cl].layerName,
                            callouts[i]->calloutId,
                            callouts[i]->displayData.name
                                ? callouts[i]->displayData.name : L"<none>",
                            isStreamLayer
                                ? "STREAM LAYER MITM: callout can silently read/modify "
                                  "TCP payload data (telemetry tampering) without blocking!"
                                : "possible rogue callout injection via "
                                  "fwpuclnt!FwpmCalloutAdd to intercept/block traffic");
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
