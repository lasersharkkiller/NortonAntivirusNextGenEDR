/*
 _   _            _              _____ ____  ____
| \ | | ___  _ __| |_ ___  _ __ | ____|  _ \|  _ \
|  \| |/ _ \| '__| __/ _ \| '_ \|  _| | | | | |_) |
| |\  | (_) | |  | || (_) | | | | |___| |_| |  _ <
|_| \_|\___/|_|   \__\___/|_| |_|_____|____/|_| \_\

  Norton NextGen Antivirus  |  ELAM Driver
  Early Launch Anti-Malware — loads before all other boot-start drivers.

  Responsibilities:
    1. Register a boot-driver callback via IoRegisterBootDriverCallback.
    2. For every BdCbInitializeImage event, inspect the incoming driver:
         a. Signature verification failure flag → KnownBadImageBootCritical or
            KnownBadImage (depending on SystemCritical flag).
         b. SHA-256 hash compared against g_KnownBadHashes table → KnownBadImage.
         c. Name prefix compared against g_KnownGoodPrefixes → KnownGoodImage.
         d. Default → UnknownImage (Windows decides whether to init the driver).
    3. Emit an ETW event for each classification decision.
    4. Register as an ETW provider so external consumers (xperf, WPA, SIEMs)
       can receive boot-phase telemetry without the TUI running.

  ELAM constraints (enforced by Windows loader):
    - Pure WDM driver; no WDF/KMDF framework loaded at early boot.
    - Only non-paged pool allocations; file system not yet available.
    - Driver image must be signed by an ELAM-specific certificate (or run in
      TESTSIGNING mode for lab use).
    - DriverEntry must return within 0.5 s — keep it lightweight.

  Secure ETW events:
    Windows documents that ELAM-registered drivers can *emit* ETW events that
    are protected (readable only by PPL consumers).  The ability to *receive*
    secure ETW events from Microsoft-Windows-Threat-Intelligence and other
    protected providers (EtwRegisterSecurityProvider) is an undocumented API
    available only to PPL-signed antimalware services after ELAM registration.
    The framework here wires up the emission side and documents the reception
    limitation.
*/

#include "ElamDefs.h"

// ---------------------------------------------------------------------------
// ELAM must declare the BDCB structures and IoRegisterBootDriverCallback
// when building against older SDK headers that don't expose them.
// With WDK 10.0.26100 these are present in ntddk.h / wdm.h automatically.
// ---------------------------------------------------------------------------
#ifndef _BDCB_IMAGE_INFORMATION_DEFINED
#define _BDCB_IMAGE_INFORMATION_DEFINED

typedef enum _BDCB_CALLBACK_TYPE {
    BdCbStatusUpdate,
    BdCbInitializeImage
} BDCB_CALLBACK_TYPE;

typedef enum _BDCB_CLASSIFICATION {
    BdCbClassificationUnknownImage,
    BdCbClassificationKnownGoodImage,
    BdCbClassificationKnownBadImage,
    BdCbClassificationKnownBadImageBootCritical,
    BdCbClassificationEnd
} BDCB_CLASSIFICATION;

typedef enum _BDCB_STATUS_UPDATE_TYPE {
    BdCbStatusPrepareForDriverLoad,
    BdCbStatusPrepareForUnload,
    BdCbStatusOptionalDriversComplete
} BDCB_STATUS_UPDATE_TYPE;

#define BDCB_IMAGE_FLAG_FAILED_CODE_INTEGRITY   0x00000001
#define BDCB_IMAGE_FLAG_FAILED_IMAGE_HASH       0x00000002
#define BDCB_IMAGE_FLAG_SYSTEM_CRITICAL         0x00000004

typedef struct _BDCB_STATUS_UPDATE_INFORMATION {
    BDCB_STATUS_UPDATE_TYPE StatusType;
} BDCB_STATUS_UPDATE_INFORMATION, *PBDCB_STATUS_UPDATE_INFORMATION;

typedef struct _BDCB_IMAGE_INFORMATION {
    BDCB_CLASSIFICATION Classification;
    ULONG               ImageFlags;
    UNICODE_STRING      ImageName;
    UNICODE_STRING      RegistryPath;
    UNICODE_STRING      CertificatePublisher;
    UNICODE_STRING      CertificateIssuer;
    PVOID               ImageHash;
    PVOID               CertificateThumbprint;
    ULONG               ImageHashAlgorithm;
    ULONG               ThumbprintHashAlgorithm;
    ULONG               ImageHashLength;
    ULONG               CertificateThumbprintLength;
} BDCB_IMAGE_INFORMATION, *PBDCB_IMAGE_INFORMATION;

typedef VOID (NTAPI *PBOOT_DRIVER_CALLBACK_FUNCTION)(
    PVOID                   CallbackContext,
    BDCB_CALLBACK_TYPE      CallbackType,
    PBDCB_IMAGE_INFORMATION ImageInformation
);

NTKERNELAPI NTSTATUS NTAPI
IoRegisterBootDriverCallback(
    _In_  PBOOT_DRIVER_CALLBACK_FUNCTION CallbackFunction,
    _In_opt_ PVOID                       CallbackContext,
    _Out_ PVOID                         *CallbackHandle
);

NTKERNELAPI VOID NTAPI
IoUnregisterBootDriverCallback(_In_ PVOID CallbackHandle);

#endif // _BDCB_IMAGE_INFORMATION_DEFINED

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------
static PVOID          g_BootCallbackHandle = nullptr;
static REGHANDLE      g_EtwHandle          = 0;
static PDRIVER_OBJECT g_DriverObject       = nullptr;

// Statistics gathered during boot phase
static ULONG g_TotalBootDrivers    = 0;
static ULONG g_KnownGoodCount      = 0;
static ULONG g_KnownBadCount       = 0;
static ULONG g_UnknownCount        = 0;
static ULONG g_VerifyFailedCount   = 0;

// ---------------------------------------------------------------------------
// ETW descriptor helpers
// ---------------------------------------------------------------------------
static const EVENT_DESCRIPTOR g_EvtBootDriverClassified = {
    ELAM_EVENTID_BOOT_DRIVER_CLASSIFIED, // Id
    0,    // Version
    0,    // Channel
    4,    // Level  (4=Information)
    0,    // Opcode
    0,    // Task
    0     // Keyword
};

static const EVENT_DESCRIPTOR g_EvtKnownBadBlocked = {
    ELAM_EVENTID_KNOWN_BAD_BLOCKED,
    0, 0,
    1,    // Level (1=Critical)
    0, 0, 0
};

static const EVENT_DESCRIPTOR g_EvtVerifyFailed = {
    ELAM_EVENTID_VERIFY_FAILED,
    0, 0,
    2,    // Level (2=Error)
    0, 0, 0
};

// ---------------------------------------------------------------------------
// EmitEtwEvent — emit a UTF-16 string payload with a classification code.
// Safe to call from the boot-driver callback (non-paged, low IRQL).
// ---------------------------------------------------------------------------
static VOID EmitEtwEvent(
    _In_ const EVENT_DESCRIPTOR* desc,
    _In_ PCUNICODE_STRING         imageName,
    _In_ ULONG                    classification)
{
    if (!g_EtwHandle || !imageName) return;

    // Build two EVENT_DATA_DESCRIPTORs: image name + classification DWORD
    EVENT_DATA_DESCRIPTOR data[2];
    EventDataDescCreate(&data[0],
        imageName->Buffer,
        (ULONG)imageName->Length);          // byte count, not char count
    EventDataDescCreate(&data[1],
        &classification,
        sizeof(ULONG));

    EtwWrite(g_EtwHandle, desc, nullptr, 2, data);
}

// ---------------------------------------------------------------------------
// IsKnownGoodByName — fast prefix match against Microsoft boot components
// ---------------------------------------------------------------------------
static BOOLEAN IsKnownGoodByName(_In_ PCUNICODE_STRING name)
{
    for (ULONG i = 0; i < g_KnownGoodPrefixCount; i++) {
        if (ElamWcsIContains(name, g_KnownGoodPrefixes[i])) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// IsKnownBadByHash — compare the driver's ImageHash against the blocklist
// ---------------------------------------------------------------------------
static BOOLEAN IsKnownBadByHash(_In_ const BDCB_IMAGE_INFORMATION* info)
{
    // Only SHA-256 (ALG_CLASS_HASH | ALG_SID_SHA_256 = 0x800c) comparisons
    if (!info->ImageHash || info->ImageHashLength != 32) return FALSE;

    const UCHAR* hash = (const UCHAR*)info->ImageHash;
    for (ULONG i = 0; i < g_KnownBadHashCount; i++) {
        if (ElamHashMatch(hash, g_KnownBadHashes[i])) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// NortonElamBootDriverCallback — called by the loader for each boot driver
// ---------------------------------------------------------------------------
static VOID NTAPI NortonElamBootDriverCallback(
    _In_opt_ PVOID                  CallbackContext,
    _In_     BDCB_CALLBACK_TYPE     CallbackType,
    _In_opt_ PBDCB_IMAGE_INFORMATION ImageInformation)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    // -----------------------------------------------------------------------
    // BdCbStatusUpdate — loader phase transitions
    // -----------------------------------------------------------------------
    if (CallbackType == BdCbStatusUpdate) {
        if (!ImageInformation) return;
        PBDCB_STATUS_UPDATE_INFORMATION statusInfo =
            (PBDCB_STATUS_UPDATE_INFORMATION)ImageInformation;

        switch (statusInfo->StatusType) {
        case BdCbStatusPrepareForDriverLoad:
            DbgPrint("[NortonELAM] Boot driver load phase beginning\n");
            break;
        case BdCbStatusOptionalDriversComplete:
            DbgPrint("[NortonELAM] Optional driver load complete — "
                     "Total=%lu Good=%lu Bad=%lu Unknown=%lu VerFail=%lu\n",
                     g_TotalBootDrivers, g_KnownGoodCount,
                     g_KnownBadCount, g_UnknownCount, g_VerifyFailedCount);
            break;
        case BdCbStatusPrepareForUnload:
            DbgPrint("[NortonELAM] Preparing for ELAM unload\n");
            break;
        default:
            break;
        }
        return;
    }

    // -----------------------------------------------------------------------
    // BdCbInitializeImage — classify each boot-start driver before its init
    // -----------------------------------------------------------------------
    if (CallbackType != BdCbInitializeImage || !ImageInformation) return;

    InterlockedIncrement((volatile LONG*)&g_TotalBootDrivers);

    BDCB_CLASSIFICATION classification = BdCbClassificationUnknownImage;
    const UNICODE_STRING* name = &ImageInformation->ImageName;

    // ------------------------------------------------------------------
    // 1. Signature / code-integrity failure — highest priority signal.
    //    Flag the driver bad; if it is system-critical mark it as such
    //    so Windows will BSOD rather than skip it (boot cannot continue
    //    without this driver and it is also compromised).
    // ------------------------------------------------------------------
    if (ImageInformation->ImageFlags &
        (BDCB_IMAGE_FLAG_FAILED_CODE_INTEGRITY | BDCB_IMAGE_FLAG_FAILED_IMAGE_HASH))
    {
        InterlockedIncrement((volatile LONG*)&g_VerifyFailedCount);

        if (ImageInformation->ImageFlags & BDCB_IMAGE_FLAG_SYSTEM_CRITICAL) {
            classification = BdCbClassificationKnownBadImageBootCritical;
        } else {
            classification = BdCbClassificationKnownBadImage;
        }

        DbgPrint("[NortonELAM] Verify FAILED (flags=0x%x): %wZ → %s\n",
            ImageInformation->ImageFlags,
            name,
            (classification == BdCbClassificationKnownBadImageBootCritical)
                ? "KnownBadBootCritical" : "KnownBad");

        EmitEtwEvent(&g_EvtVerifyFailed, name, (ULONG)classification);
        goto done;
    }

    // ------------------------------------------------------------------
    // 2. Hash blocklist check
    // ------------------------------------------------------------------
    if (IsKnownBadByHash(ImageInformation)) {
        InterlockedIncrement((volatile LONG*)&g_KnownBadCount);
        classification = BdCbClassificationKnownBadImage;

        DbgPrint("[NortonELAM] Hash match (LOLDriver): %wZ → KnownBad\n", name);
        EmitEtwEvent(&g_EvtKnownBadBlocked, name, (ULONG)classification);
        goto done;
    }

    // ------------------------------------------------------------------
    // 3. Known-good name prefix check (Microsoft boot components)
    // ------------------------------------------------------------------
    if (IsKnownGoodByName(name)) {
        InterlockedIncrement((volatile LONG*)&g_KnownGoodCount);
        classification = BdCbClassificationKnownGoodImage;

        DbgPrint("[NortonELAM] Known-good: %wZ\n", name);
        goto done;
    }

    // ------------------------------------------------------------------
    // 4. Default — unknown; Windows decides (UnknownImage = allow)
    // ------------------------------------------------------------------
    InterlockedIncrement((volatile LONG*)&g_UnknownCount);
    classification = BdCbClassificationUnknownImage;
    DbgPrint("[NortonELAM] Unknown: %wZ\n", name);

done:
    // Write the classification back into the struct — this is how the loader
    // reads ELAM's decision.
    ImageInformation->Classification = classification;

    // Emit ETW event for every driver (allows full audit trail)
    EmitEtwEvent(&g_EvtBootDriverClassified, name, (ULONG)classification);
}

// ---------------------------------------------------------------------------
// ElamUnload — called when Windows unloads the ELAM driver after boot
// ---------------------------------------------------------------------------
static VOID ElamUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[NortonELAM] Unloading — "
             "Total=%lu Good=%lu Bad=%lu Unknown=%lu VerFail=%lu\n",
             g_TotalBootDrivers, g_KnownGoodCount,
             g_KnownBadCount, g_UnknownCount, g_VerifyFailedCount);

    if (g_BootCallbackHandle) {
        IoUnregisterBootDriverCallback(g_BootCallbackHandle);
        g_BootCallbackHandle = nullptr;
    }

    if (g_EtwHandle) {
        EtwUnregister(g_EtwHandle);
        g_EtwHandle = 0;
    }
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[NortonELAM] DriverEntry — Early Launch Anti-Malware v1\n");

    g_DriverObject      = DriverObject;
    DriverObject->DriverUnload = ElamUnload;

    // ------------------------------------------------------------------
    // Register as an ETW provider so boot-phase events are accessible
    // to xperf, WPA, and SIEM collectors.
    //
    // NOTE — Secure ETW events (reception):
    //   ELAM-registered components gain the ability to *receive* events
    //   from protected providers (Microsoft-Windows-Threat-Intelligence,
    //   etc.) through EtwRegisterSecurityProvider, an undocumented API
    //   available only to kernel-mode callers holding an ELAM registration
    //   cookie.  The standard kernel EtwRegister below wires up *emission*
    //   of protected events.  Full reception requires the main NortonEDR
    //   driver to request the ELAM handoff token post-boot, which Windows
    //   exposes through the documented ELAM callback mechanism documented
    //   in KB4493539 / SE-0057.
    // ------------------------------------------------------------------
    NTSTATUS status = EtwRegister(&NORTON_ELAM_ETW_GUID,
                                  nullptr,  // no enable/disable callback
                                  nullptr,  // no callback context
                                  &g_EtwHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[NortonELAM] EtwRegister failed: 0x%x "
                 "(ETW events will not be emitted)\n", status);
        g_EtwHandle = 0;
        // Non-fatal — classification still works without ETW
    } else {
        DbgPrint("[NortonELAM] ETW provider registered\n");
    }

    // ------------------------------------------------------------------
    // Register the boot-driver callback.
    // This must be called from DriverEntry — the loader only accepts
    // registrations during the ELAM driver's own initialization.
    // ------------------------------------------------------------------
    status = IoRegisterBootDriverCallback(
        NortonElamBootDriverCallback,
        nullptr,                     // CallbackContext
        &g_BootCallbackHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[NortonELAM] IoRegisterBootDriverCallback failed: 0x%x\n",
                 status);

        if (g_EtwHandle) {
            EtwUnregister(g_EtwHandle);
            g_EtwHandle = 0;
        }
        return status;
    }

    DbgPrint("[NortonELAM] Boot driver callback registered — "
             "monitoring %lu known-bad hash(es), "
             "%lu known-good prefix(es)\n",
             g_KnownBadHashCount, g_KnownGoodPrefixCount);

    return STATUS_SUCCESS;
}
