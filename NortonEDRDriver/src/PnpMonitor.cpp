/*
  PnpMonitor.cpp — IoRegisterPlugPlayNotification for USB / HID / disk arrival.

  Threat background
  ─────────────────
  BadUSB / HID injection attacks (Rubber Ducky, O.MG cable, Bash Bunny):
    A malicious USB device enumerates as a HID keyboard/mouse.  Windows
    auto-installs the driver and the device immediately starts replaying
    keystrokes.  There is no user-visible installation prompt for HID class
    devices.  Kernel-side we see EventCategoryDeviceInterfaceChange for
    GUID_DEVINTERFACE_HID the moment the OS accepts the device.

  USB mass-storage supply-chain attacks:
    Malicious thumb drives dropped in car parks / mailed to targets.
    We alert on GUID_DEVINTERFACE_DISK arrival from a removable device.

  Detection strategy
  ──────────────────
  IoRegisterPlugPlayNotification with EventCategoryDeviceInterfaceChange
  fires a callback at PASSIVE_LEVEL for every device-interface arrival and
  removal.  The DEVICE_INTERFACE_CHANGE_NOTIFICATION structure carries:

    • InterfaceClassGuid  — which class arrived (HID, USB, disk …)
    • SymbolicLinkName   — e.g. \??\HID#VID_05AC&PID_0250&…

  From the symbolic link we open the underlying PDO and query
  IOCTL_HID_GET_COLLECTION_INFORMATION to distinguish composite HID
  devices (keyboard + mouse) from pure mice.  Since that requires a
  full IRP stack we keep this simple: alert on ANY new HID arrival and
  let user-mode triage using the SymbolicLinkName.

  For disk arrivals we query the device for DevicePropertyRemovable via
  IoGetDeviceProperty and only alert if it is a removable device — this
  avoids noise from internal SATA/NVMe drives.

  IRQL contract: all callbacks fire at PASSIVE_LEVEL.
*/

#include "Globals.h"
#include <initguid.h>  // Required before wdmguid.h for DEFINE_GUID to emit storage
#include <wdmguid.h>   // GUID_DEVICE_INTERFACE_ARRIVAL

// Use DevicePropertyRemovalPolicy (0x13) to check if device is removable.
// CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL = 1 means non-removable.
#ifndef CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL
#define CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL 1
#endif

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

static PVOID s_HidNotifHandle   = nullptr;
static PVOID s_UsbNotifHandle   = nullptr;
static PVOID s_DiskNotifHandle  = nullptr;
static PVOID s_1394NotifHandle  = nullptr;
static NotifQueue* s_PnpQueue   = nullptr;

// ---------------------------------------------------------------------------
// EmitPnpAlert
// ---------------------------------------------------------------------------

static VOID EmitPnpAlert(const char* msg, BOOLEAN critical)
{
    NotifQueue* q = s_PnpQueue;
    if (!q || !msg) return;

    SIZE_T msgLen = strlen(msg) + 1;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'pnpn');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    if (critical) { SET_CRITICAL(*notif); } else { SET_WARNING(*notif); }
    SET_PNP_CHECK(*notif);
    notif->pid    = 0;
    notif->isPath = FALSE;

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'pnmg');
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
// NarrowSymLink — convert the UNICODE_STRING symbolic link to a narrow
// string (first 180 chars) for inclusion in the alert message.
// ---------------------------------------------------------------------------

static VOID NarrowSymLink(const UNICODE_STRING* us, char* out, SIZE_T outSz)
{
    if (!us || !us->Buffer || !out || outSz == 0) { out[0] = '\0'; return; }
    USHORT chars = us->Length / sizeof(WCHAR);
    if (chars >= (USHORT)outSz) chars = (USHORT)(outSz - 1);
    for (USHORT i = 0; i < chars; i++)
        out[i] = (us->Buffer[i] < 128) ? (char)us->Buffer[i] : '?';
    out[chars] = '\0';
}

// ---------------------------------------------------------------------------
// IsRemovableDisk — resolve the symbolic link to a PDEVICE_OBJECT and query
// DevicePropertyRemovable via IoGetDeviceProperty.
// Returns TRUE only for confirmed removable media; FALSE on any error.
// ---------------------------------------------------------------------------

static BOOLEAN IsRemovableDisk(const UNICODE_STRING* symLink)
{
    if (!symLink) return FALSE;

    // Resolve the symbolic link to a FILE_OBJECT / DEVICE_OBJECT.
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING)symLink,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb = {};
    NTSTATUS s = ZwOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(s)) return FALSE;

    PFILE_OBJECT fileObj = nullptr;
    s = ObReferenceObjectByHandle(h, 0, *IoFileObjectType,
        KernelMode, (PVOID*)&fileObj, nullptr);
    ZwClose(h);
    if (!NT_SUCCESS(s) || !fileObj) return FALSE;

    PDEVICE_OBJECT devObj = IoGetRelatedDeviceObject(fileObj);
    ObDereferenceObject(fileObj);
    if (!devObj) return FALSE;

    // Walk up to the PDO (bottom of the device stack) for the property query.
    PDEVICE_OBJECT pdo = IoGetDeviceAttachmentBaseRef(devObj);
    if (!pdo) return FALSE;

    ULONG removalPolicy = 0;
    ULONG resultLen = 0;
    s = IoGetDeviceProperty(pdo,
        DevicePropertyRemovalPolicy,
        sizeof(removalPolicy), &removalPolicy, &resultLen);

    ObDereferenceObject(pdo);

    if (!NT_SUCCESS(s)) return FALSE;
    return (removalPolicy != CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL);
}

// ---------------------------------------------------------------------------
// HidArrivalCallback — fires for every HID interface arrival/removal.
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI HidArrivalCallback(
    _In_ PVOID NotificationStructure,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notif =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;

    // Only care about arrivals, not removals.
    if (!IsEqualGUID(notif->Event, GUID_DEVICE_INTERFACE_ARRIVAL)) {
        return STATUS_SUCCESS;
    }

    char symNarrow[200] = {};
    NarrowSymLink(notif->SymbolicLinkName, symNarrow, sizeof(symNarrow));

    char msg[300];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "BadUSB/HID: new HID device interface arrived — %s "
        "— possible keyboard/mouse injection device (Rubber Ducky, O.MG cable)",
        symNarrow);

    DbgPrint("[PnpMonitor] HID arrival: %s\n", symNarrow);
    EmitPnpAlert(msg, TRUE);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// DiskArrivalCallback — fires for every disk interface arrival/removal.
// Only alerts on removable media.
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI DiskArrivalCallback(
    _In_ PVOID NotificationStructure,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notif =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;

    if (!IsEqualGUID(notif->Event, GUID_DEVICE_INTERFACE_ARRIVAL)) {
        return STATUS_SUCCESS;
    }

    // Only alert if this is a removable device.
    if (!IsRemovableDisk(notif->SymbolicLinkName)) {
        return STATUS_SUCCESS;
    }

    char symNarrow[200] = {};
    NarrowSymLink(notif->SymbolicLinkName, symNarrow, sizeof(symNarrow));

    char msg[300];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "USB mass storage: removable disk arrived — %s "
        "— possible supply-chain / dropped drive attack",
        symNarrow);

    DbgPrint("[PnpMonitor] Removable disk arrival: %s\n", symNarrow);
    EmitPnpAlert(msg, FALSE);  // Warning — not every USB drive is malicious

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// FireWireArrivalCallback — fires for every IEEE 1394 (FireWire) device arrival.
// 1394 has DMA by design via the OHCI spec; classic hardware DMA attack vector.
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI FireWireArrivalCallback(
    _In_ PVOID NotificationStructure,
    _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    PDEVICE_INTERFACE_CHANGE_NOTIFICATION notif =
        (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;

    // Only care about arrivals, not removals.
    if (!IsEqualGUID(notif->Event, GUID_DEVICE_INTERFACE_ARRIVAL)) {
        return STATUS_SUCCESS;
    }

    char symNarrow[200] = {};
    NarrowSymLink(notif->SymbolicLinkName, symNarrow, sizeof(symNarrow));

    char msg[320];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "DMA threat: FireWire/IEEE 1394 device arrived — %s "
        "— 1394 has DMA by design (OHCI); classic hardware DMA/IOMMU bypass vector "
        "(Inception, PCILeech 1394 attack)",
        symNarrow);

    DbgPrint("[PnpMonitor] FireWire arrival: %s\n", symNarrow);
    EmitPnpAlert(msg, TRUE);  // CRITICAL

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// PnpMonitor::Init / Cleanup
// ---------------------------------------------------------------------------

VOID PnpMonitor::InitWithDriver(PDRIVER_OBJECT driverObject, NotifQueue* queue)
{
    s_PnpQueue = queue;

    // HID interface arrival — any new HID device.
    NTSTATUS s = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
        (PVOID)&GUID_DEVINTERFACE_HID_LOCAL,
        driverObject,
        HidArrivalCallback,
        nullptr,
        &s_HidNotifHandle);

    if (!NT_SUCCESS(s))
        DbgPrint("[-] PnpMonitor: HID registration failed: 0x%x\n", s);
    else
        DbgPrint("[+] PnpMonitor: HID notification registered\n");

    // Disk/removable media arrival.
    s = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
        (PVOID)&GUID_DEVINTERFACE_DISK_LOCAL,
        driverObject,
        DiskArrivalCallback,
        nullptr,
        &s_DiskNotifHandle);

    if (!NT_SUCCESS(s))
        DbgPrint("[-] PnpMonitor: disk registration failed: 0x%x\n", s);
    else
        DbgPrint("[+] PnpMonitor: disk notification registered\n");

    // FireWire/IEEE 1394 arrival — DMA by design via OHCI spec.
    s = IoRegisterPlugPlayNotification(
        EventCategoryDeviceInterfaceChange,
        PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
        (PVOID)&GUID_DEVINTERFACE_1394_LOCAL,
        driverObject,
        FireWireArrivalCallback,
        nullptr,
        &s_1394NotifHandle);

    if (!NT_SUCCESS(s))
        DbgPrint("[-] PnpMonitor: 1394 registration failed: 0x%x\n", s);
    else
        DbgPrint("[+] PnpMonitor: 1394 notification registered\n");
}

VOID PnpMonitor::Cleanup()
{
    if (s_HidNotifHandle) {
        IoUnregisterPlugPlayNotificationEx(s_HidNotifHandle);
        s_HidNotifHandle = nullptr;
    }
    if (s_UsbNotifHandle) {
        IoUnregisterPlugPlayNotificationEx(s_UsbNotifHandle);
        s_UsbNotifHandle = nullptr;
    }
    if (s_DiskNotifHandle) {
        IoUnregisterPlugPlayNotificationEx(s_DiskNotifHandle);
        s_DiskNotifHandle = nullptr;
    }
    if (s_1394NotifHandle) {
        IoUnregisterPlugPlayNotificationEx(s_1394NotifHandle);
        s_1394NotifHandle = nullptr;
    }
    s_PnpQueue = nullptr;
    DbgPrint("[+] PnpMonitor: cleanup complete\n");
}
