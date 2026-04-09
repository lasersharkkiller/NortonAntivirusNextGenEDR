#include "Globals.h"

// ---------------------------------------------------------------------------
// Minifilter altitude — FSFilter Activity Monitor range (260000–269999)
// Must match the value written to the registry by the user-mode installer.
// ---------------------------------------------------------------------------
#define NORTONAV_FS_ALTITUDE L"265000"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static PFLT_FILTER  g_FilterHandle = nullptr;
static NotifQueue*  g_FsQueue      = nullptr;

// ---------------------------------------------------------------------------
// Per-process write-burst tracker (ransomware detection)
// Counts user-mode writes per process in a sliding 5-second window.
// ---------------------------------------------------------------------------
#define FS_WRITE_WINDOW_100NS  50000000LL   // 5 seconds in 100-ns units
#define FS_WRITE_THRESHOLD     200           // writes per window before alert
#define FS_TRACKER_SLOTS       64

typedef struct _FS_WRITE_SLOT {
    HANDLE        Pid;
    ULONG         Count;
    LARGE_INTEGER WindowStart;
    BOOLEAN       Alerted;          // suppress duplicate alerts per process
} FS_WRITE_SLOT;

static FS_WRITE_SLOT g_WriteSlots[FS_TRACKER_SLOTS];
static KSPIN_LOCK    g_WriteSlotLock;

// ---------------------------------------------------------------------------
// Herpaderping: track FILE_OBJECTs backing active SEC_IMAGE sections.
// When NtCreateSection(SEC_IMAGE, fileHandle) is called, the FILE_OBJECT is
// added here. Any subsequent user-mode write to that file object is flagged
// as a potential Process Herpaderping attempt (write-after-section trick to
// hide the real on-disk content from scanners while the image runs).
// ---------------------------------------------------------------------------
#define HERP_TRACK_MAX 64

typedef struct _HERP_SLOT {
    PFILE_OBJECT FileObject;  // referenced pointer; NULL = free slot
} HERP_SLOT;

static HERP_SLOT  g_HerpSlots[HERP_TRACK_MAX];
static KSPIN_LOCK g_HerpLock;

// ---------------------------------------------------------------------------
// Sensitive credential file path fragments (lowercase for comparison)
// ---------------------------------------------------------------------------
static const PCWSTR kCredPaths[] = {
    L"\\config\\sam",
    L"\\config\\system",
    L"\\config\\security",
    L"\\ntds\\ntds.dit",
    L"lsass.dmp",
    L"\\memory.dmp",
    L".kirbi",              // Mimikatz/Rubeus Kerberos ticket export format
    L".ccache",             // Impacket/MIT Kerberos credential cache
    L"krb5cc_",             // MIT Kerberos default ccache filename prefix
};

// ---------------------------------------------------------------------------
// Ransomware-indicative rename target extensions (lowercase, with dot)
// ---------------------------------------------------------------------------
static const PCWSTR kRansomExts[] = {
    L".enc", L".locked", L".crypt", L".encrypted",
    L".locky", L".wncry", L".wnry", L".petya",
    L".cerber", L".zepto", L".kraken", L".darkside",
    L".ryuk", L".conti", L".lock", L".pay2decrypt",
};

// ---------------------------------------------------------------------------
// Executable extensions worth flagging when dropped in suspicious paths
// ---------------------------------------------------------------------------
static const PCWSTR kExecExts[] = {
    L".exe", L".dll", L".ps1", L".vbs",
    L".bat", L".js",  L".hta", L".scr", L".pif",
};

// ---------------------------------------------------------------------------
// Suspicious drop directories (lowercase)
// ---------------------------------------------------------------------------
static const PCWSTR kDropPaths[] = {
    L"\\temp\\",
    L"\\appdata\\",
    L"\\programdata\\",
    L"\\users\\public\\",
    L"\\recycle",
};

// ---------------------------------------------------------------------------
// Volume Shadow Copy paths (lowercase) — ransomware deletes VSS before encrypting
// ---------------------------------------------------------------------------
static const PCWSTR kVssPaths[] = {
    L"\\harddiskvolumeshadowcopy",
    L"\\globalroot\\device\\harddiskvolumeshadowcopy",
    L"\\shadowcopy",
};

// ---------------------------------------------------------------------------
// Allowed NTFS alternate data stream names (lowercase, exact match).
// Everything else is flagged as suspicious.
// ---------------------------------------------------------------------------
static const PCWSTR kAllowedStreams[] = {
    L":zone.identifier:$data",   // browser Mark-of-the-Web
    L":encryptable:$data",       // EFS marker
    L":smartscreen:$data",       // SmartScreen cache
    L":$data",                   // explicit default stream reference
};

// ---------------------------------------------------------------------------
// Per-process directory enumeration tracker (mass scan = ransomware pre-scan)
// ---------------------------------------------------------------------------
#define FS_DIR_ENUM_WINDOW_100NS  50000000LL   // 5 seconds in 100-ns units
#define FS_DIR_ENUM_THRESHOLD     500          // dir queries per window before alert

typedef struct _FS_DIR_SLOT {
    HANDLE        Pid;
    ULONG         Count;
    LARGE_INTEGER WindowStart;
    BOOLEAN       Alerted;
} FS_DIR_SLOT;

static FS_DIR_SLOT g_DirSlots[FS_TRACKER_SLOTS];
static KSPIN_LOCK  g_DirSlotLock;

// ---------------------------------------------------------------------------
// Helper: case-insensitive substring search in a UNICODE_STRING
// needle must already be lowercase.
// ---------------------------------------------------------------------------
static BOOLEAN WcsContainsLower(PUNICODE_STRING haystack, PCWSTR needle) {
    if (!haystack || !haystack->Buffer || haystack->Length == 0 || !needle) return FALSE;
    SIZE_T needleLen = wcslen(needle);
    USHORT hLen = haystack->Length / sizeof(WCHAR);
    if ((USHORT)needleLen > hLen) return FALSE;
    for (USHORT i = 0; i <= hLen - (USHORT)needleLen; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < needleLen; j++) {
            WCHAR hc = haystack->Buffer[i + j];
            if (hc >= L'A' && hc <= L'Z') hc += 32;
            if (hc != needle[j]) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Helper: case-insensitive extension match.
// ext: FLT_FILE_NAME_INFORMATION.Extension (no leading dot, e.g. L"exe")
// check: pattern with leading dot (e.g. L".exe"), must be lowercase
// ---------------------------------------------------------------------------
static BOOLEAN ExtMatch(PUNICODE_STRING ext, PCWSTR checkWithDot) {
    if (!ext || ext->Length == 0) return FALSE;
    PCWSTR check = checkWithDot + 1;   // skip dot
    SIZE_T checkLen = wcslen(check);
    if (ext->Length / sizeof(WCHAR) != checkLen) return FALSE;
    for (SIZE_T i = 0; i < checkLen; i++) {
        WCHAR ec = ext->Buffer[i];
        if (ec >= L'A' && ec <= L'Z') ec += 32;
        if (ec != check[i]) return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Helper: enqueue a structured notification onto the detection queue.
// msg must be a null-terminated ANSI string; this function copies it.
// ---------------------------------------------------------------------------
static VOID EnqueueFsAlert(
    HANDLE      pid,
    const char* procName,
    const char* msg,
    BOOLEAN     critical
) {
    if (!g_FsQueue || !msg) return;

    SIZE_T msgLen = strlen(msg) + 1;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'fsnt');
    if (!notif) return;

    if (critical) { SET_CRITICAL(*notif); } else { SET_WARNING(*notif); }
    SET_FSFILTER_CHECK(*notif);

    notif->pid            = pid;
    notif->isPath         = FALSE;
    notif->scoopedAddress = 0;

    if (procName) {
        SIZE_T nameLen = strlen(procName);
        if (nameLen >= sizeof(notif->procName)) nameLen = sizeof(notif->procName) - 1;
        RtlCopyMemory(notif->procName, procName, nameLen);
        notif->procName[nameLen] = '\0';
    }

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'fsms');
    notif->bufSize = (ULONG)msgLen;
    if (!notif->msg) { ExFreePool(notif); return; }
    RtlCopyMemory(notif->msg, msg, msgLen);

    if (!g_FsQueue->Enqueue(notif)) {
        ExFreePool(notif->msg);
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// Herpaderping file-object tracker
// ---------------------------------------------------------------------------

// Called from NtCreateSectionHandler (SyscallsTracing.cpp) when SEC_IMAGE + file handle.
// Takes an additional reference on FileObject so the slot survives handle closure.
VOID FsFilter::TrackImageSectionFile(PFILE_OBJECT FileObject) {
    if (!FileObject) return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HerpLock, &oldIrql);

    // Avoid duplicates — same file opened twice before first write
    for (int i = 0; i < HERP_TRACK_MAX; i++) {
        if (g_HerpSlots[i].FileObject == FileObject) {
            KeReleaseSpinLock(&g_HerpLock, oldIrql);
            return;
        }
    }

    // Find a free slot
    for (int i = 0; i < HERP_TRACK_MAX; i++) {
        if (g_HerpSlots[i].FileObject == nullptr) {
            ObReferenceObject(FileObject);   // keep alive until write or driver unload
            g_HerpSlots[i].FileObject = FileObject;
            KeReleaseSpinLock(&g_HerpLock, oldIrql);
            return;
        }
    }

    // Table full — drop silently (extremely rare; HERP_TRACK_MAX=64 is generous)
    KeReleaseSpinLock(&g_HerpLock, oldIrql);
}

// Remove a slot without alerting (e.g. on driver unload cleanup).
VOID FsFilter::UntrackImageSectionFile(PFILE_OBJECT FileObject) {
    if (!FileObject) return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HerpLock, &oldIrql);

    for (int i = 0; i < HERP_TRACK_MAX; i++) {
        if (g_HerpSlots[i].FileObject == FileObject) {
            ObDereferenceObject(FileObject);
            g_HerpSlots[i].FileObject = nullptr;
            break;
        }
    }

    KeReleaseSpinLock(&g_HerpLock, oldIrql);
}

// ---------------------------------------------------------------------------
// Write-burst tracker helpers
// ---------------------------------------------------------------------------
static VOID UpdateWriteTracker(HANDLE pid) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WriteSlotLock, &oldIrql);

    // Search for existing slot
    INT freeSlot = -1;
    for (INT i = 0; i < FS_TRACKER_SLOTS; i++) {
        if (g_WriteSlots[i].Pid == pid) {
            // Check if window expired
            if ((now.QuadPart - g_WriteSlots[i].WindowStart.QuadPart) > FS_WRITE_WINDOW_100NS) {
                // Reset window
                g_WriteSlots[i].Count       = 1;
                g_WriteSlots[i].WindowStart = now;
                g_WriteSlots[i].Alerted     = FALSE;
            } else {
                g_WriteSlots[i].Count++;
            }

            if (!g_WriteSlots[i].Alerted && g_WriteSlots[i].Count >= FS_WRITE_THRESHOLD) {
                g_WriteSlots[i].Alerted = TRUE;
                KeReleaseSpinLock(&g_WriteSlotLock, oldIrql);

                char alertMsg[96];
                RtlStringCchPrintfA(alertMsg, sizeof(alertMsg),
                    "FS: High-frequency write burst (%u writes/5s) — possible ransomware (pid=%llu)",
                    FS_WRITE_THRESHOLD, (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, nullptr, alertMsg, TRUE);
                return;
            }
            KeReleaseSpinLock(&g_WriteSlotLock, oldIrql);
            return;
        }
        if (freeSlot < 0 && g_WriteSlots[i].Pid == nullptr) freeSlot = i;
    }

    // New PID — claim a free slot (evict oldest if full)
    if (freeSlot < 0) {
        LONGLONG oldest = LLONG_MAX;
        for (INT i = 0; i < FS_TRACKER_SLOTS; i++) {
            if (g_WriteSlots[i].WindowStart.QuadPart < oldest) {
                oldest    = g_WriteSlots[i].WindowStart.QuadPart;
                freeSlot  = i;
            }
        }
    }
    if (freeSlot >= 0) {
        g_WriteSlots[freeSlot].Pid         = pid;
        g_WriteSlots[freeSlot].Count       = 1;
        g_WriteSlots[freeSlot].WindowStart = now;
        g_WriteSlots[freeSlot].Alerted     = FALSE;
    }
    KeReleaseSpinLock(&g_WriteSlotLock, oldIrql);
}

// ---------------------------------------------------------------------------
// Per-process directory enumeration tracker — mirrors write-burst tracker logic
// ---------------------------------------------------------------------------
static VOID UpdateDirTracker(HANDLE pid) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DirSlotLock, &oldIrql);

    INT freeSlot = -1;
    for (INT i = 0; i < FS_TRACKER_SLOTS; i++) {
        if (g_DirSlots[i].Pid == pid) {
            if ((now.QuadPart - g_DirSlots[i].WindowStart.QuadPart) > FS_DIR_ENUM_WINDOW_100NS) {
                g_DirSlots[i].Count       = 1;
                g_DirSlots[i].WindowStart = now;
                g_DirSlots[i].Alerted     = FALSE;
            } else {
                g_DirSlots[i].Count++;
            }
            if (!g_DirSlots[i].Alerted && g_DirSlots[i].Count >= FS_DIR_ENUM_THRESHOLD) {
                g_DirSlots[i].Alerted = TRUE;
                KeReleaseSpinLock(&g_DirSlotLock, oldIrql);
                char msg[128];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: Mass directory enumeration (%u queries/5s) — possible ransomware pre-scan (pid=%llu)",
                    FS_DIR_ENUM_THRESHOLD, (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, nullptr, msg, TRUE);
                return;
            }
            KeReleaseSpinLock(&g_DirSlotLock, oldIrql);
            return;
        }
        if (freeSlot < 0 && g_DirSlots[i].Pid == nullptr) freeSlot = i;
    }

    if (freeSlot < 0) {
        LONGLONG oldest = LLONG_MAX;
        for (INT i = 0; i < FS_TRACKER_SLOTS; i++) {
            if (g_DirSlots[i].WindowStart.QuadPart < oldest) {
                oldest   = g_DirSlots[i].WindowStart.QuadPart;
                freeSlot = i;
            }
        }
    }
    if (freeSlot >= 0) {
        g_DirSlots[freeSlot].Pid         = pid;
        g_DirSlots[freeSlot].Count       = 1;
        g_DirSlots[freeSlot].WindowStart = now;
        g_DirSlots[freeSlot].Alerted     = FALSE;
    }
    KeReleaseSpinLock(&g_DirSlotLock, oldIrql);
}

// ---------------------------------------------------------------------------
// FLT_REGISTRATION
// ---------------------------------------------------------------------------
static FLT_OPERATION_REGISTRATION g_FsCallbacks[] = {
    { IRP_MJ_CREATE,             0, FsFilter::PreCreate,            nullptr },
    { IRP_MJ_WRITE,              0, FsFilter::PreWrite,             nullptr },
    { IRP_MJ_SET_INFORMATION,    0, FsFilter::PreSetInformation,    nullptr },
    { IRP_MJ_DIRECTORY_CONTROL,  0, FsFilter::PreDirControl,        nullptr },
    { IRP_MJ_NETWORK_QUERY_OPEN, 0, FsFilter::PreNetworkQueryOpen,  nullptr },
    { IRP_MJ_OPERATION_END }
};

static FLT_REGISTRATION g_FltRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              // Flags
    nullptr,                        // ContextRegistration
    g_FsCallbacks,
    FsFilter::FilterUnloadCallback,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
};

// ---------------------------------------------------------------------------
// Init / Cleanup
// ---------------------------------------------------------------------------
NTSTATUS FsFilter::Init(PDRIVER_OBJECT DriverObject, NotifQueue* queue) {
    g_FsQueue = queue;
    RtlZeroMemory(g_WriteSlots, sizeof(g_WriteSlots));
    KeInitializeSpinLock(&g_WriteSlotLock);
    RtlZeroMemory(g_DirSlots, sizeof(g_DirSlots));
    KeInitializeSpinLock(&g_DirSlotLock);
    RtlZeroMemory(g_HerpSlots, sizeof(g_HerpSlots));
    KeInitializeSpinLock(&g_HerpLock);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FltRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] FltRegisterFilter failed: 0x%x\n", status);
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] FltStartFiltering failed: 0x%x\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = nullptr;
        return status;
    }

    DbgPrint("[+] Filesystem minifilter registered (altitude %ws)\n", NORTONAV_FS_ALTITUDE);
    return STATUS_SUCCESS;
}

VOID FsFilter::Cleanup() {
    // Release any outstanding herpaderping FILE_OBJECT references before unregistering
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HerpLock, &oldIrql);
    for (int i = 0; i < HERP_TRACK_MAX; i++) {
        if (g_HerpSlots[i].FileObject) {
            ObDereferenceObject(g_HerpSlots[i].FileObject);
            g_HerpSlots[i].FileObject = nullptr;
        }
    }
    KeReleaseSpinLock(&g_HerpLock, oldIrql);

    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = nullptr;
    }
}

NTSTATUS FLTAPI FsFilter::FilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    FsFilter::Cleanup();
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IRP_MJ_CREATE — credential access + executable drop detection
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreCreate(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    __try {
        if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo))) __leave;

        PEPROCESS process   = IoThreadToProcess(Data->Thread);
        HANDLE    pid       = PsGetProcessId(process);
        char*     procName  = PsGetProcessImageFileName(process);

        // ---- Credential file access ----
        for (SIZE_T i = 0; i < ARRAYSIZE(kCredPaths); i++) {
            if (WcsContainsLower(&nameInfo->Name, kCredPaths[i])) {
                char pathBuf[128] = {};
                ANSI_STRING ansi;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                    SIZE_T copyLen = ansi.Length < sizeof(pathBuf) - 1 ? ansi.Length : sizeof(pathBuf) - 1;
                    RtlCopyMemory(pathBuf, ansi.Buffer, copyLen);
                    RtlFreeAnsiString(&ansi);
                }
                char msg[192];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: Credential file access — %s (pid=%llu)",
                    pathBuf[0] ? pathBuf : "?", (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, FALSE);
                __leave;
            }
        }

        // ---- NTFS Alternate Data Stream (ADS) detection ----
        // nameInfo->Stream is non-empty for named streams, e.g. ":hidden:$DATA".
        // Exact-match against known-benign streams; flag everything else.
        if (nameInfo->Stream.Length > 0) {
            BOOLEAN isBenign = FALSE;
            for (SIZE_T i = 0; i < ARRAYSIZE(kAllowedStreams); i++) {
                SIZE_T checkLen = wcslen(kAllowedStreams[i]);
                if (nameInfo->Stream.Length / sizeof(WCHAR) == checkLen) {
                    BOOLEAN eq = TRUE;
                    for (SIZE_T j = 0; j < checkLen; j++) {
                        WCHAR sc = nameInfo->Stream.Buffer[j];
                        if (sc >= L'A' && sc <= L'Z') sc += 32;
                        if (sc != kAllowedStreams[i][j]) { eq = FALSE; break; }
                    }
                    if (eq) { isBenign = TRUE; break; }
                }
            }
            if (!isBenign) {
                char streamBuf[64] = {}, fileBuf[96] = {};
                ANSI_STRING ansiS;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiS, &nameInfo->Stream, TRUE))) {
                    SIZE_T n = ansiS.Length < sizeof(streamBuf) - 1 ? ansiS.Length : sizeof(streamBuf) - 1;
                    RtlCopyMemory(streamBuf, ansiS.Buffer, n);
                    RtlFreeAnsiString(&ansiS);
                }
                ANSI_STRING ansiF;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiF, &nameInfo->FinalComponent, TRUE))) {
                    SIZE_T n = ansiF.Length < sizeof(fileBuf) - 1 ? ansiF.Length : sizeof(fileBuf) - 1;
                    RtlCopyMemory(fileBuf, ansiF.Buffer, n);
                    RtlFreeAnsiString(&ansiF);
                }
                char msg[224];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: NTFS ADS access — stream=%s file=%s (pid=%llu)",
                    streamBuf[0] ? streamBuf : "?",
                    fileBuf[0]   ? fileBuf   : "?",
                    (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, FALSE);
            }
        }

        // ---- Volume Shadow Copy (VSS) access detection ----
        for (SIZE_T i = 0; i < ARRAYSIZE(kVssPaths); i++) {
            if (WcsContainsLower(&nameInfo->Name, kVssPaths[i])) {
                char msg[192];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: Shadow copy / VSS access by %s (pid=%llu)",
                    procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, TRUE);
                break;
            }
        }

        // ---- Executable drop in suspicious directory ----
        BOOLEAN isExec = FALSE;
        for (SIZE_T i = 0; i < ARRAYSIZE(kExecExts); i++) {
            if (ExtMatch(&nameInfo->Extension, kExecExts[i])) { isExec = TRUE; break; }
        }
        if (isExec) {
            ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            if (createDisposition == FILE_CREATE || createDisposition == FILE_OVERWRITE_IF ||
                createDisposition == FILE_SUPERSEDE) {
                for (SIZE_T i = 0; i < ARRAYSIZE(kDropPaths); i++) {
                    if (WcsContainsLower(&nameInfo->Name, kDropPaths[i])) {
                        char pathBuf[128] = {};
                        ANSI_STRING ansi;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T copyLen = ansi.Length < sizeof(pathBuf) - 1 ? ansi.Length : sizeof(pathBuf) - 1;
                            RtlCopyMemory(pathBuf, ansi.Buffer, copyLen);
                            RtlFreeAnsiString(&ansi);
                        }
                        char msg[192];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: Executable dropped in suspicious path — %s (pid=%llu)",
                            pathBuf[0] ? pathBuf : "?", (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, FALSE);
                        break;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_WRITE — ransomware burst detection
// File name query avoided here to prevent deadlocks; PID is sufficient.
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreWrite(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HANDLE pid = PsGetProcessId(IoThreadToProcess(Data->Thread));
    if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;  // skip System/Idle

    // Herpaderping detection: check if this write targets a file that backs an active SEC_IMAGE
    // section. Pattern: NtCreateSection(SEC_IMAGE, file) → write to same file → overwrite
    // on-disk content while the malicious image is already mapped and running.
    PFILE_OBJECT targetFo = Data->Iopb->TargetFileObject;
    if (targetFo) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_HerpLock, &oldIrql);
        BOOLEAN found = FALSE;
        for (int i = 0; i < HERP_TRACK_MAX; i++) {
            if (g_HerpSlots[i].FileObject == targetFo) {
                // Remove from table — one alert per file is enough; further writes are noise
                ObDereferenceObject(g_HerpSlots[i].FileObject);
                g_HerpSlots[i].FileObject = nullptr;
                found = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_HerpLock, oldIrql);

        if (found) {
            PEPROCESS proc = IoThreadToProcess(Data->Thread);
            char* pn = PsGetProcessImageFileName(proc);
            char msg[192];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "Process Herpaderping: write to SEC_IMAGE-backed file while image section active"
                " -- '%s' (pid=%llu) overwrote its own image on disk to evade AV scanning",
                pn ? pn : "<?>", (ULONG64)(ULONG_PTR)pid);
            EnqueueFsAlert(pid, pn, msg, TRUE);
        }
    }

    UpdateWriteTracker(pid);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_SET_INFORMATION — ransomware rename + hard link detection
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreSetInformation(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    BOOLEAN isRename   = (infoClass == FileRenameInformation ||
                          infoClass == FileRenameInformationEx);
    BOOLEAN isHardLink = (infoClass == FileLinkInformation ||
                          infoClass == FileLinkInformationEx);

    if (!isRename && !isHardLink) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PEPROCESS process  = IoThreadToProcess(Data->Thread);
    HANDLE    pid      = PsGetProcessId(process);
    char*     procName = PsGetProcessImageFileName(process);

    __try {
        if (isHardLink) {
            // Hard link creation — ransomware uses links to encrypt a file then delete the original
            FILE_LINK_INFORMATION* linkInfo =
                (FILE_LINK_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (!linkInfo || linkInfo->FileNameLength == 0) __leave;

            UNICODE_STRING targetName;
            targetName.Buffer        = linkInfo->FileName;
            targetName.Length        = (USHORT)min(linkInfo->FileNameLength, (ULONG)0xFFFE);
            targetName.MaximumLength = targetName.Length;

            char targetBuf[128] = {};
            ANSI_STRING ansi;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &targetName, TRUE))) {
                SIZE_T n = ansi.Length < sizeof(targetBuf) - 1 ? ansi.Length : sizeof(targetBuf) - 1;
                RtlCopyMemory(targetBuf, ansi.Buffer, n);
                RtlFreeAnsiString(&ansi);
            }
            char msg[192];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FS: Hard link created — target=%s (pid=%llu)",
                targetBuf[0] ? targetBuf : "?", (ULONG64)(ULONG_PTR)pid);
            EnqueueFsAlert(pid, procName, msg, FALSE);
        } else {
            // Rename — check target extension against known ransomware extensions
            FILE_RENAME_INFORMATION* renameInfo =
                (FILE_RENAME_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (!renameInfo || renameInfo->FileNameLength == 0) __leave;

            UNICODE_STRING targetName;
            targetName.Buffer        = renameInfo->FileName;
            targetName.Length        = (USHORT)renameInfo->FileNameLength;
            targetName.MaximumLength = targetName.Length;

            // Extract extension: scan backwards from end for '.'
            UNICODE_STRING ext = { 0, 0, nullptr };
            USHORT wLen = targetName.Length / sizeof(WCHAR);
            for (USHORT i = wLen; i > 0; i--) {
                if (targetName.Buffer[i - 1] == L'.') {
                    ext.Buffer        = &targetName.Buffer[i - 1];
                    ext.Length        = (USHORT)((wLen - (i - 1)) * sizeof(WCHAR));
                    ext.MaximumLength = ext.Length;
                    break;
                }
                if (targetName.Buffer[i - 1] == L'\\') break;
            }
            if (ext.Length == 0) __leave;

            for (SIZE_T i = 0; i < ARRAYSIZE(kRansomExts); i++) {
                PCWSTR check    = kRansomExts[i];
                SIZE_T checkLen = wcslen(check);
                if (ext.Length / sizeof(WCHAR) != checkLen) continue;
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < checkLen; j++) {
                    WCHAR ec = ext.Buffer[j];
                    if (ec >= L'A' && ec <= L'Z') ec += 32;
                    if (ec != check[j]) { match = FALSE; break; }
                }
                if (match) {
                    char extBuf[16] = {};
                    UNICODE_STRING extStr = { ext.Length, ext.MaximumLength, ext.Buffer };
                    ANSI_STRING ansiExt;
                    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiExt, &extStr, TRUE))) {
                        SIZE_T n = ansiExt.Length < sizeof(extBuf) - 1 ? ansiExt.Length : sizeof(extBuf) - 1;
                        RtlCopyMemory(extBuf, ansiExt.Buffer, n);
                        RtlFreeAnsiString(&ansiExt);
                    }
                    char msg[128];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: File renamed to ransomware extension %s (pid=%llu)",
                        extBuf[0] ? extBuf : "?", (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_DIRECTORY_CONTROL — mass enumeration detection (ransomware pre-scan)
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreDirControl(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HANDLE pid = PsGetProcessId(IoThreadToProcess(Data->Thread));
    if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    UpdateDirTracker(pid);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_NETWORK_QUERY_OPEN — fast-path SMB metadata query
// Covers credential and VSS path access that bypasses IRP_MJ_CREATE on the
// network redirector side (SMB/WebDAV mapped drives).
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreNetworkQueryOpen(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    __try {
        if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo))) __leave;

        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        for (SIZE_T i = 0; i < ARRAYSIZE(kCredPaths); i++) {
            if (WcsContainsLower(&nameInfo->Name, kCredPaths[i])) {
                char pathBuf[128] = {};
                ANSI_STRING ansi;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                    SIZE_T n = ansi.Length < sizeof(pathBuf) - 1 ? ansi.Length : sizeof(pathBuf) - 1;
                    RtlCopyMemory(pathBuf, ansi.Buffer, n);
                    RtlFreeAnsiString(&ansi);
                }
                char msg[192];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: Network fast-path credential file access — %s (pid=%llu)",
                    pathBuf[0] ? pathBuf : "?", (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, FALSE);
                break;
            }
        }

        for (SIZE_T i = 0; i < ARRAYSIZE(kVssPaths); i++) {
            if (WcsContainsLower(&nameInfo->Name, kVssPaths[i])) {
                char msg[192];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: Network fast-path VSS access by %s (pid=%llu)",
                    procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, TRUE);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
