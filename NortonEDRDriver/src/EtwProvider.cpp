#include "Globals.h"
#include <evntprov.h>

// ---------------------------------------------------------------------------
// EtwProvider: registers the kernel driver as a manifest-free ETW provider
// and emits one structured event per detection notification.
//
// Provider GUID: {D6E3E932-B0B9-4E8C-A2C3-F7A9B8C5D4E1}
// Consume with:  xperf -on D6E3E932-B0B9-4E8C-A2C3-F7A9B8C5D4E1
//               or any real-time ETW consumer targeting the GUID.
//
// Event IDs:
//   1  Hook detected      (SSDT / Inline / EAT / ETW / AltSyscall)
//   2  PE / VAD scan      (reflective injection, anon RWX)
//   3  Process anomaly    (ghosting, PPID spoof, hollowing)
//   4  AMSI bypass        (export prologue patch detected)
//   5  Syscall            (direct / indirect syscall)
//   6  Generic / other
//
// Fields per event (in order):
//   [0] procName   ANSI string  (process name, 15 bytes max)
//   [1] message    ANSI string  (human-readable detail)
//   [2] pid        UINT32
//   [3] address    UINT64       (scooped address, 0 if N/A)
// ---------------------------------------------------------------------------

static const GUID kNortonEdrProviderGuid = {
    0xD6E3E932, 0xB0B9, 0x4E8C,
    {0xA2, 0xC3, 0xF7, 0xA9, 0xB8, 0xC5, 0xD4, 0xE1}
};

#define NORTONAV_EVT_HOOK       1
#define NORTONAV_EVT_PESCAN     2
#define NORTONAV_EVT_PROCESS    3
#define NORTONAV_EVT_AMSI       4
#define NORTONAV_EVT_SYSCALL    5
#define NORTONAV_EVT_GENERIC    6

static REGHANDLE g_EtwHandle = 0;

VOID EtwProvider::Init() {
    NTSTATUS status = EtwRegister(
        &kNortonEdrProviderGuid,
        nullptr,    // no enable/disable callback
        nullptr,    // no context
        &g_EtwHandle
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] EtwRegister failed: 0x%X\n", status);
        g_EtwHandle = 0;
    } else {
        DbgPrint("[+] EtwRegister success (provider GUID D6E3E932-...)\n");
    }
}

REGHANDLE EtwProvider::GetRegHandle() {
    return g_EtwHandle;
}

VOID EtwProvider::Cleanup() {
    if (g_EtwHandle) {
        EtwUnregister(g_EtwHandle);
        g_EtwHandle = 0;
    }
}

VOID EtwProvider::WriteDetectionEvent(PKERNEL_STRUCTURED_NOTIFICATION notif) {
    if (!g_EtwHandle || !notif) return;

    // Map method bits → event ID
    USHORT eventId = NORTONAV_EVT_GENERIC;
    if (notif->SsdtHookCheck || notif->InlineHookCheck ||
        notif->EatHookCheck  || notif->EtwHookCheck    ||
        notif->AltSyscallHandlerCheck)
        eventId = NORTONAV_EVT_HOOK;
    else if (notif->PeScanCheck)
        eventId = NORTONAV_EVT_PESCAN;
    else if (notif->CallingProcPidCheck || notif->SeAuditInfoCheck)
        eventId = NORTONAV_EVT_PROCESS;
    else if (notif->AmsiBypassCheck)
        eventId = NORTONAV_EVT_AMSI;
    else if (notif->SyscallCheck)
        eventId = NORTONAV_EVT_SYSCALL;

    // ETW severity: 2=Critical, 3=Warning, 4=Info
    UCHAR level = notif->Critical ? 2 : (notif->Warning ? 3 : 4);

    EVENT_DESCRIPTOR evtDesc;
    EventDescCreate(&evtDesc, eventId, 0, 0, level, 0, 0, 0);

    char emptyStr[] = "";
    char* msg = (notif->msg && SafeStringLength(notif->msg, 255) > 0)
                ? notif->msg : emptyStr;

    ULONG pid = (ULONG)(ULONG_PTR)notif->pid;

    EVENT_DATA_DESCRIPTOR fields[4];
    EventDataDescCreate(&fields[0],
        notif->procName,
        (ULONG)(SafeStringLength(notif->procName, 14) + 1));
    EventDataDescCreate(&fields[1],
        msg,
        (ULONG)(SafeStringLength(msg, 255) + 1));
    EventDataDescCreate(&fields[2], &pid, sizeof(pid));
    EventDataDescCreate(&fields[3], &notif->scoopedAddress,
        sizeof(notif->scoopedAddress));

    EtwWrite(g_EtwHandle, &evtDesc, nullptr, 4, fields);
}
