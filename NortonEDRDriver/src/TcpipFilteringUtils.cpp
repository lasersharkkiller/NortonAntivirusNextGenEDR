#include "Globals.h"

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
    if (suspicious && (pid == 0 || pid == 4)) {
        suspicious = FALSE;
    }

    classifyOut->actionType = blocked ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

    // Skip enqueueing routine Info-level connections to avoid queue saturation.
    // Always surface blocked and suspicious connections.
    if (!blocked && !suspicious) {
        DbgPrint("Net: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u pid=%llu\n",
            FORMAT_ADDR(localAddress),  localPort,
            FORMAT_ADDR(remoteAddress), remotePort, pid);
        return;
    }

    NotifQueue* queue = CallbackObjects::GetNotifQueue();
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
