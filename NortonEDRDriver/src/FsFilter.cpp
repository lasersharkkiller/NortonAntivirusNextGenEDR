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
// Sensitive credential file path fragments (lowercase for comparison)
// ---------------------------------------------------------------------------
static const PCWSTR kCredPaths[] = {
    L"\\config\\sam",
    L"\\config\\system",
    L"\\config\\security",
    L"\\ntds\\ntds.dit",
    L"lsass.dmp",
    L"\\memory.dmp",
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
// FLT_REGISTRATION
// ---------------------------------------------------------------------------
static FLT_OPERATION_REGISTRATION g_FsCallbacks[] = {
    { IRP_MJ_CREATE,          0, FsFilter::PreCreate,         nullptr },
    { IRP_MJ_WRITE,           0, FsFilter::PreWrite,          nullptr },
    { IRP_MJ_SET_INFORMATION, 0, FsFilter::PreSetInformation, nullptr },
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

    UpdateWriteTracker(pid);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_SET_INFORMATION — ransomware rename detection
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

    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        FILE_RENAME_INFORMATION* renameInfo =
            (FILE_RENAME_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (!renameInfo || renameInfo->FileNameLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // Build a UNICODE_STRING over the target filename buffer
        UNICODE_STRING targetName;
        targetName.Buffer        = renameInfo->FileName;
        targetName.Length        = (USHORT)renameInfo->FileNameLength;
        targetName.MaximumLength = targetName.Length;

        // Extract extension from target name: find last '.'
        UNICODE_STRING ext = { 0, 0, nullptr };
        USHORT wLen = targetName.Length / sizeof(WCHAR);
        for (USHORT i = wLen; i > 0; i--) {
            if (targetName.Buffer[i - 1] == L'.') {
                ext.Buffer        = &targetName.Buffer[i - 1];  // includes dot
                ext.Length        = (USHORT)((wLen - (i - 1)) * sizeof(WCHAR));
                ext.MaximumLength = ext.Length;
                break;
            }
            if (targetName.Buffer[i - 1] == L'\\') break; // hit directory separator
        }

        if (ext.Length == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // ext.Buffer[0] is '.'; check ext.Buffer[1..] against kRansomExts (which include dot)
        for (SIZE_T i = 0; i < ARRAYSIZE(kRansomExts); i++) {
            PCWSTR check    = kRansomExts[i];          // e.g. L".locked"
            SIZE_T checkLen = wcslen(check);            // includes dot
            if (ext.Length / sizeof(WCHAR) != checkLen) continue;
            BOOLEAN match = TRUE;
            for (SIZE_T j = 0; j < checkLen; j++) {
                WCHAR ec = ext.Buffer[j];
                if (ec >= L'A' && ec <= L'Z') ec += 32;
                if (ec != check[j]) { match = FALSE; break; }
            }
            if (match) {
                PEPROCESS process  = IoThreadToProcess(Data->Thread);
                HANDLE    pid      = PsGetProcessId(process);
                char*     procName = PsGetProcessImageFileName(process);

                char extBuf[16] = {};
                UNICODE_STRING extStr = { ext.Length, ext.MaximumLength, ext.Buffer };
                ANSI_STRING ansiExt;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiExt, &extStr, TRUE))) {
                    SIZE_T copyLen = ansiExt.Length < sizeof(extBuf) - 1 ? ansiExt.Length : sizeof(extBuf) - 1;
                    RtlCopyMemory(extBuf, ansiExt.Buffer, copyLen);
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
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
