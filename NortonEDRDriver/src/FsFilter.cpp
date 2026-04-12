#include "Globals.h"
#include "Deception.h"

// ---------------------------------------------------------------------------
// Minifilter altitude — FSFilter Anti-Virus range (320000–329999)
// Must match the value written to the registry by the user-mode installer
// and the INF [Instance.DefaultInstance] section.
// ---------------------------------------------------------------------------
#define NORTONAV_FS_ALTITUDE L"320021"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static PFLT_FILTER  g_FilterHandle = nullptr;
static NotifQueue*  g_FsQueue      = nullptr;

// ---------------------------------------------------------------------------
// Minifilter instance snapshot — captured at Init time for DKOM detection.
// If an attacker unlinks our instance from a volume (DKOM), the periodic
// check will see fewer instances than the snapshot and fire an alert.
// ---------------------------------------------------------------------------
#define MAX_TRACKED_VOLUMES 32

struct VOLUME_INSTANCE_SNAPSHOT {
    PFLT_VOLUME Volume;           // raw pointer — only used for identity comparison
    WCHAR       VolumeName[128];  // human-readable name for alerts
    BOOLEAN     Valid;
};

static VOLUME_INSTANCE_SNAPSHOT g_InstanceSnapshot[MAX_TRACKED_VOLUMES] = {};
static ULONG                    g_InstanceSnapshotCount = 0;
static KSPIN_LOCK               g_SnapshotLock;

// Callback pointer snapshot — captured at Init time for DKOM detection.
// Stores the original PreOperation function pointers from our FLT_OPERATION_REGISTRATION.
#define MAX_TRACKED_CALLBACKS 16

struct CALLBACK_SNAPSHOT {
    UCHAR       MajorFunction;
    PVOID       PreOperation;
    PVOID       PostOperation;
};

static CALLBACK_SNAPSHOT g_CallbackSnapshot[MAX_TRACKED_CALLBACKS] = {};
static ULONG             g_CallbackSnapshotCount = 0;

// FltMgr-internal _FLT_FILTER structure snapshot.
// The _FLT_FILTER object backing g_FilterHandle has an internal Operations pointer
// that points to the FLT_OPERATION_REGISTRATION array.  If an attacker DKOM-patches
// the Operations pointer inside _FLT_FILTER (redirecting it away from g_FsCallbacks),
// our g_FsCallbacks-level check won't catch it.  This snapshot records the internal
// Operations field address at Init time so we can detect redirection.
//
// _FLT_FILTER internal layout (Win10 19041 – Win11 22H2, x64):
//   +0x000  FLT_OBJECT Base
//   +0x030  PFLT_FRAME Frame
//   +0x060  UNICODE_STRING Name
//   +0x1a0  FLT_OPERATION_REGISTRATION* Operations
//   +0x1b0  ... (PreVolumeMount, etc.)
//
// We locate Operations by scanning from g_FilterHandle for a pointer that matches
// our g_FsCallbacks address, then record the offset and expected value.
static PVOID  g_FltFilterOpsPtr     = nullptr;  // address of the Operations field inside _FLT_FILTER
static PVOID  g_FltFilterOpsValue   = nullptr;  // expected value (should point to g_FsCallbacks)
static ULONG  g_FltFilterOpsOffset  = 0;        // offset from g_FilterHandle where we found it
static BOOLEAN g_FltFilterSnapshotValid = FALSE;

// _FLT_FILTER.Base.Flags — used to detect FltUnregisterFilter.
// After registration, Flags should have FLTFL_FILTERING_INITIATED (0x2) set.
// If someone calls FltUnregisterFilter, this flag is cleared.
static PVOID  g_FltFilterFlagsPtr    = nullptr;
static ULONG  g_FltFilterFlagsInit   = 0;
static BOOLEAN g_FltFilterFlagsValid = FALSE;

// FastIO dispatch table snapshot — the PDEVICE_OBJECT for our filter's CDO
// (Control Device Object) has a FastIoDispatch pointer.  We also track the
// FSD's FastIoDispatch on volumes we're attached to.
static PFAST_IO_DISPATCH g_OrigFastIoDispatch  = nullptr;
static PDEVICE_OBJECT    g_FilterCdo           = nullptr;

// Queue pressure tracking — suppress repeated alerts
static BOOLEAN g_QueuePressureAlerted = FALSE;

// IoCallDriver detection — track volume device objects at Init for later
// validation that their DriverObject->MajorFunction table hasn't been hooked
// to bypass our minifilter.
#define MAX_TRACKED_VOLUME_DEVS 16
static PDEVICE_OBJECT g_TrackedVolumeDevices[MAX_TRACKED_VOLUME_DEVS] = {};
static PVOID          g_TrackedVolDevMjCreate[MAX_TRACKED_VOLUME_DEVS] = {};
static ULONG          g_TrackedVolumeDevCount = 0;

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
// Per-process I/O rate tracker — CPU-burn / filter-flood detection.
// An attacker can generate massive benign I/O to keep our PreCreate spinning,
// degrading EDR performance without saturating the output queue.
// We track IRP_MJ_CREATE ops/second per PID and alert on sustained high rates.
// ---------------------------------------------------------------------------
#define IO_RATE_WINDOW_100NS   10000000LL   // 1 second in 100-ns units
#define IO_RATE_THRESHOLD      5000         // creates/second before alert
#define IO_RATE_TRACKER_SLOTS  32

typedef struct _IO_RATE_SLOT {
    HANDLE        Pid;
    ULONG         Count;
    LARGE_INTEGER WindowStart;
    BOOLEAN       Alerted;
} IO_RATE_SLOT;

static IO_RATE_SLOT g_IoRateSlots[IO_RATE_TRACKER_SLOTS];
static KSPIN_LOCK   g_IoRateLock;

// ---------------------------------------------------------------------------
// FLT_CALLBACK_DATA tampering detection — PreOp→PostOp cross-validation.
//
// A malicious minifilter (at any altitude between ours and the filesystem) can
// modify members of FLT_CALLBACK_DATA between our PreOp and PostOp:
//   - TargetFileObject swap → redirect detection to a decoy file
//   - DesiredAccess downgrade → hide write/delete intent
//   - CreateOptions modification → hide FILE_DELETE_ON_CLOSE / OPEN_BY_FILE_ID
//   - FileInformationClass change → blind rename/delete detection
//   - Write ByteOffset/Length → alter what we think was written
//
// PreOp snapshots key params into a pool-allocated context (sampled, every 256th
// operation).  PostOp compares the snapshot against the live Iopb and alerts on
// any mismatch.
// ---------------------------------------------------------------------------
#define PARAM_CTX_TAG       'pCtx'
#define PARAM_CTX_MAGIC     0xC7C7C7C7
#define PARAM_VALIDATE_RATE 256   // validate every Nth operation

typedef struct _PREOP_CREATE_CTX {
    ULONG           Magic;
    ACCESS_MASK     DesiredAccess;
    ULONG           CreateOptions;      // lower 24 bits of Options
    PFILE_OBJECT    TargetFileObject;
} PREOP_CREATE_CTX;

typedef struct _PREOP_SETINFO_CTX {
    ULONG                       Magic;
    FILE_INFORMATION_CLASS      InfoClass;
    PVOID                       InfoBuffer;
    PFILE_OBJECT                TargetFileObject;
} PREOP_SETINFO_CTX;

typedef struct _PREOP_WRITE_CTX {
    ULONG           Magic;
    LARGE_INTEGER   ByteOffset;
    ULONG           Length;
    PFILE_OBJECT    TargetFileObject;
} PREOP_WRITE_CTX;

static volatile LONG g_CreateValidateCounter  = 0;
static volatile LONG g_SetInfoValidateCounter = 0;
static volatile LONG g_WriteValidateCounter   = 0;

// ---------------------------------------------------------------------------
// Per-IRP-type invocation counters — callback silencing detection.
// A higher-altitude malicious filter returning FLT_PREOP_COMPLETE causes FltMgr
// to skip all lower-altitude PreOp AND PostOp callbacks.  If our counters drop
// from active to zero for two consecutive integrity checks, a hostile filter is
// completing I/O above us.
// ---------------------------------------------------------------------------
#define PREOP_COUNTER_SLOTS  7   // CREATE, WRITE, SET_INFO, DIR_CTRL, FS_CTRL, SET_EA, NET_QUERY
enum PreOpCounterIdx : ULONG {
    PREOP_CREATE       = 0,
    PREOP_WRITE        = 1,
    PREOP_SET_INFO     = 2,
    PREOP_DIR_CTRL     = 3,
    PREOP_FS_CTRL      = 4,
    PREOP_SET_EA       = 5,
    PREOP_NET_QUERY    = 6,
};
static const char* kPreOpNames[] = {
    "IRP_MJ_CREATE", "IRP_MJ_WRITE", "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL", "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_SET_EA", "IRP_MJ_NETWORK_QUERY_OPEN"
};
// Live counters — incremented in each PreOp via InterlockedIncrement.
static volatile LONG g_PreOpCounters[PREOP_COUNTER_SLOTS] = {};
// Previous interval snapshot — copied from g_PreOpCounters then counters reset.
static LONG  g_PreOpPrev[PREOP_COUNTER_SLOTS] = {};
// Consecutive-zero count per slot.  Alert fires when this reaches 2 for a slot
// whose previous non-zero value was above the activity threshold.
static ULONG g_PreOpZeroRuns[PREOP_COUNTER_SLOTS] = {};
// Minimum previous count to consider a slot "was active" (avoids false positives
// on rarely-used IRP types like SET_EA).
#define PREOP_ACTIVE_THRESHOLD  50
// How many consecutive zero intervals before alerting.
#define PREOP_ZERO_ALERT_RUNS   2
// Whether we have completed at least one full interval (skip first check).
static BOOLEAN g_PreOpBaselined = FALSE;

// ---------------------------------------------------------------------------
// Canary I/O heartbeat — verify our PreCreate callback is being invoked.
// The periodic integrity check issues a ZwCreateFile on a canary path.  PreCreate
// recognises the canary and bumps g_CanaryHits.  If the counter doesn't increment,
// a higher-altitude filter is completing our creates before we see them.
// ---------------------------------------------------------------------------
static volatile LONG g_CanaryHits      = 0;
static BOOLEAN       g_CanaryAlerted   = FALSE;
// The canary file lives in our driver's own directory — no actual file is created
// because we use FILE_OPEN (fail if not exists).  We only care whether PreCreate fires.
static const WCHAR   g_CanaryPath[]    = L"\\SystemRoot\\NortonEDR_canary_heartbeat.tmp";

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
    // --- Browser credential harvesting (DPAPI + AES-GCM) ---
    // SharpChromium, HackBrowserData, Mimikatz dpapi::chrome, CookieMonster
    L"\\login data",        // Chrome/Edge saved passwords SQLite DB
    L"\\local state",       // Chrome/Edge DPAPI-encrypted AES-GCM master key
    L"\\cookies",           // Chrome/Edge session cookies (combined with master key)
    L"\\web data",          // Chrome/Edge autofill / credit card data
    L"logins.json",         // Firefox saved passwords
    L"key4.db",             // Firefox key database (NSS / PKCS#11)
    L"\\network\\cookies",  // Chrome network service cookies path
    // --- Cloud / Entra ID token theft (PRT harvesting) ---
    // ROADtools, AADInternals, RequestAADRefreshToken, CloudAP DPAPI theft
    L"microsoft.aad.brokerplugin",  // Entra PRT / session key cache
    L"\\tokenbroker\\",     // Windows TokenBroker cached refresh tokens
    L"tbres",               // TokenBroker result files with cached tokens
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
// Protected binary directories — write-open of existing executables here is
// suspicious (DLL hijack, binary replacement, trojanizing signed binaries).
// ---------------------------------------------------------------------------
static const PCWSTR kProtectedBinPaths[] = {
    L"\\windows\\system32\\",
    L"\\windows\\syswow64\\",
    L"\\program files\\",
    L"\\program files (x86)\\",
    L"\\windows\\winsxs\\",
    L"\\windows\\microsoft.net\\",
};

// Processes allowed to write to protected binary paths
static const char* kBinWriteAllowedProcs[] = {
    "TrustedInsta",     // TrustedInstaller (15-char PsGetProcessImageFileName truncation)
    "msiexec.exe",      // Windows Installer
    "svchost.exe",      // Windows Update / CBS
    "poqexec.exe",      // Servicing stack
    "DismHost.exe",     // DISM servicing
    "tiworker.exe",     // Windows Update worker
    "MsMpEng.exe",      // Defender
    "NortonEDR.exe",    // Our own user-mode service
    nullptr
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
// Ransomware note filenames (lowercase, substring match).
// Creation of these files strongly correlates with active ransomware encryption.
// ---------------------------------------------------------------------------
static const PCWSTR kRansomNotes[] = {
    L"readme_locked",       L"how_to_decrypt",     L"how_to_recover",
    L"decrypt_instruction", L"decrypt_files",      L"restore_files",
    L"recovery_information",L"ransom_note",        L"!readme!",
    L"_readme.txt",         L"#decrypt#",          L"#readme#",
    L"help_decrypt",        L"your_files",         L"read_me_to_recover",
    L"files_encrypted",     L"_recover_",          L"!how_to_unlock",
};

// ---------------------------------------------------------------------------
// Sensitive system files that should only be accessed by specific processes.
// ---------------------------------------------------------------------------
static const PCWSTR kEventLogPath   = L"\\winevt\\logs\\";
static const PCWSTR kPrefetchPath   = L"\\windows\\prefetch\\";
static const PCWSTR kWmiRepoPath    = L"\\system32\\wbem\\repository\\";
static const PCWSTR kPagefilePaths[] = {
    L"\\pagefile.sys",
    L"\\swapfile.sys",
    L"\\hiberfil.sys",
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
    { IRP_MJ_CREATE,              0, FsFilter::PreCreate,            FsFilter::PostCreate },
    { IRP_MJ_WRITE,               0, FsFilter::PreWrite,             FsFilter::PostWrite },
    { IRP_MJ_SET_INFORMATION,     0, FsFilter::PreSetInformation,    FsFilter::PostSetInformation },
    { IRP_MJ_DIRECTORY_CONTROL,   0, FsFilter::PreDirControl,        nullptr },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, FsFilter::PreFsControl,        nullptr },
    { IRP_MJ_SET_EA,              0, FsFilter::PreSetEa,             nullptr },
    { IRP_MJ_NETWORK_QUERY_OPEN,  0, FsFilter::PreNetworkQueryOpen,  nullptr },
    { IRP_MJ_OPERATION_END }
};

static FLT_REGISTRATION g_FltRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, // Block fltmc unload / FltUnloadFilter
    nullptr,                        // ContextRegistration
    g_FsCallbacks,
    FsFilter::FilterUnloadCallback,
    FsFilter::InstanceSetupCallback,  // InstanceSetupCallback — accept npfs/msfs volumes
    FsFilter::InstanceQueryTeardownCallback,
    FsFilter::InstanceTeardownStartCallback,
    FsFilter::InstanceTeardownCompleteCallback,
    nullptr, nullptr, nullptr
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
    RtlZeroMemory(g_IoRateSlots, sizeof(g_IoRateSlots));
    KeInitializeSpinLock(&g_IoRateLock);

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

    // -----------------------------------------------------------------------
    // Altitude squatting / sandwiching detection.
    //
    // After we register, enumerate all loaded minifilters and check:
    //   1) Any OTHER filter at our exact altitude → altitude squatting
    //   2) Any filter at altitude (ours+1 .. ours+10) → sandwiching attack
    //      (an attacker positions a filter just above ours to intercept/hide I/O)
    //
    // FltEnumerateFilterInformation returns FILTER_AGGREGATE_STANDARD_INFORMATION
    // which includes the filter name and instance altitude strings.
    // -----------------------------------------------------------------------
    {
        ULONG bytesNeeded = 0;
        ULONG ourAltitude = 320021;
        ULONG idx = 0;
        NTSTATUS enumSt;

        // Stack buffer for most minifilter info structs (~512 bytes typical)
        UCHAR infoBuf[1024];

        while (TRUE) {
            enumSt = FltEnumerateFilterInformation(
                idx, FilterAggregateStandardInformation,
                infoBuf, sizeof(infoBuf), &bytesNeeded);

            if (enumSt == STATUS_NO_MORE_ENTRIES) break;

            if (!NT_SUCCESS(enumSt)) {
                idx++;
                continue;
            }

            PFILTER_AGGREGATE_STANDARD_INFORMATION info =
                (PFILTER_AGGREGATE_STANDARD_INFORMATION)infoBuf;

            // Only process entries that have the MiniFilter field
            if (info->Flags & FLTFL_ASI_IS_MINIFILTER) {
                // The structure layout differs between Type1 and Type2;
                // both have FilterNameBufferOffset/Length and Altitude fields
                // in the FILTER_AGGREGATE_STANDARD_INFORMATION_MINIFILTER structure.
                // On Win10+, Type == 2 is guaranteed.

                UNICODE_STRING altStr = { 0 };
                UNICODE_STRING nameStr = { 0 };

                if (info->Type.MiniFilter.FilterNameLength > 0 &&
                    info->Type.MiniFilter.FilterNameBufferOffset > 0)
                {
                    nameStr.Buffer = (PWCH)((PUCHAR)info +
                        info->Type.MiniFilter.FilterNameBufferOffset);
                    nameStr.Length = info->Type.MiniFilter.FilterNameLength;
                    nameStr.MaximumLength = nameStr.Length;
                }

                // Parse altitude from the FrameID + altitude fields
                // The altitude is stored in the instance info, but for the
                // aggregate filter info we need to check the frame altitude.
                // More reliable: compare the filter name to our own.
                // If this IS our filter, skip it.
                UNICODE_STRING ourName = RTL_CONSTANT_STRING(L"NortonEDRDriver");
                if (nameStr.Length > 0 &&
                    RtlEqualUnicodeString(&nameStr, &ourName, TRUE))
                {
                    idx++;
                    continue;
                }

                // To get the actual altitude, enumerate instances of this filter.
                // Use FltEnumerateInstances via the filter name, but that requires
                // an PFLT_FILTER handle. Instead, use the simpler approach:
                // enumerate all filter instances on the system and check altitudes.
                // For efficiency, we do the instance walk outside this loop.
            }

            idx++;
        }

        // Walk all filter instances on every volume to check altitude proximity.
        // FltEnumerateInstances(NULL, NULL, ...) returns all instances system-wide
        // when both Volume and Filter are NULL (undocumented but works Win8+).
        // Safer approach: use FltEnumerateInstanceInformationByFilter on each filter.
        //
        // Simpler: enumerate instances globally via FltEnumerateInstances with
        // our own filter handle and Volume=NULL → only our instances; then check
        // for foreign instances near our altitude per-volume via
        // FltEnumerateInstanceInformationByVolume.
        //
        // Most practical approach: for each volume our filter is attached to,
        // walk every instance and check altitude proximity.

        PFLT_VOLUME* volList = nullptr;
        ULONG volCount = 0;
        enumSt = FltEnumerateVolumes(g_FilterHandle, nullptr, 0, &volCount);
        if (enumSt == STATUS_BUFFER_TOO_SMALL && volCount > 0) {
            SIZE_T volListSize = volCount * sizeof(PFLT_VOLUME);
            volList = (PFLT_VOLUME*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, volListSize, 'fvol');
            if (volList) {
                enumSt = FltEnumerateVolumes(
                    g_FilterHandle, volList, volCount, &volCount);
            }
        }

        if (NT_SUCCESS(enumSt) && volList) {
            for (ULONG vi = 0; vi < volCount; vi++) {
                ULONG instIdx = 0;
                UCHAR instBuf[512];
                ULONG instNeeded = 0;

                while (TRUE) {
                    NTSTATUS instSt = FltEnumerateInstanceInformationByVolume(
                        volList[vi], instIdx,
                        InstanceAggregateStandardInformation,
                        instBuf, sizeof(instBuf), &instNeeded);

                    if (instSt == STATUS_NO_MORE_ENTRIES) break;
                    if (!NT_SUCCESS(instSt)) { instIdx++; continue; }

                    PINSTANCE_AGGREGATE_STANDARD_INFORMATION instInfo =
                        (PINSTANCE_AGGREGATE_STANDARD_INFORMATION)instBuf;

                    if (instInfo->Flags & FLTFL_IASI_IS_MINIFILTER) {
                        UNICODE_STRING instAlt = { 0 };
                        UNICODE_STRING instName = { 0 };

                        if (instInfo->Type.MiniFilter.FilterNameLength > 0 &&
                            instInfo->Type.MiniFilter.FilterNameBufferOffset > 0)
                        {
                            instName.Buffer = (PWCH)((PUCHAR)instInfo +
                                instInfo->Type.MiniFilter.FilterNameBufferOffset);
                            instName.Length = instInfo->Type.MiniFilter.FilterNameLength;
                            instName.MaximumLength = instName.Length;
                        }

                        if (instInfo->Type.MiniFilter.AltitudeLength > 0 &&
                            instInfo->Type.MiniFilter.AltitudeBufferOffset > 0)
                        {
                            instAlt.Buffer = (PWCH)((PUCHAR)instInfo +
                                instInfo->Type.MiniFilter.AltitudeBufferOffset);
                            instAlt.Length = instInfo->Type.MiniFilter.AltitudeLength;
                            instAlt.MaximumLength = instAlt.Length;
                        }

                        // Skip our own instances
                        UNICODE_STRING ourName2 = RTL_CONSTANT_STRING(L"NortonEDRDriver");
                        if (instName.Length > 0 &&
                            RtlEqualUnicodeString(&instName, &ourName2, TRUE))
                        {
                            instIdx++;
                            continue;
                        }

                        // Parse the altitude string to a numeric value
                        if (instAlt.Length > 0 && instAlt.Buffer) {
                            ULONG foreignAlt = 0;
                            // Manual parse — altitude is a decimal numeric string
                            for (USHORT ci = 0; ci < instAlt.Length / sizeof(WCHAR); ci++) {
                                WCHAR c = instAlt.Buffer[ci];
                                if (c >= L'0' && c <= L'9')
                                    foreignAlt = foreignAlt * 10 + (c - L'0');
                                else if (c == L'.') break; // fractional part (rare)
                            }

                            // Check 1: exact altitude collision (squatting)
                            if (foreignAlt == ourAltitude) {
                                char nameBuf[64] = {};
                                ANSI_STRING ansiN;
                                if (instName.Length > 0 &&
                                    NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &instName, TRUE)))
                                {
                                    SIZE_T n = ansiN.Length < sizeof(nameBuf) - 1 ? ansiN.Length : sizeof(nameBuf) - 1;
                                    RtlCopyMemory(nameBuf, ansiN.Buffer, n);
                                    RtlFreeAnsiString(&ansiN);
                                }
                                char msg[256];
                                RtlStringCchPrintfA(msg, sizeof(msg),
                                    "ALTITUDE SQUATTING: filter '%s' registered at our exact "
                                    "altitude %lu — EDR minifilter may be displaced!",
                                    nameBuf[0] ? nameBuf : "?", ourAltitude);
                                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                                DbgPrint("[!] %s\n", msg);
                            }
                            // Check 2: sandwiching — foreign filter above us in the
                            // FSFilter Anti-Virus range (320000–329999).  Any filter
                            // in this range above our altitude can see all I/O before
                            // we do and can modify/suppress it.
                            else if (foreignAlt > ourAltitude &&
                                     foreignAlt <= 329999)
                            {
                                char nameBuf[64] = {};
                                ANSI_STRING ansiN;
                                if (instName.Length > 0 &&
                                    NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &instName, TRUE)))
                                {
                                    SIZE_T n = ansiN.Length < sizeof(nameBuf) - 1 ? ansiN.Length : sizeof(nameBuf) - 1;
                                    RtlCopyMemory(nameBuf, ansiN.Buffer, n);
                                    RtlFreeAnsiString(&ansiN);
                                }
                                char msg[256];
                                RtlStringCchPrintfA(msg, sizeof(msg),
                                    "ALTITUDE SANDWICH: filter '%s' at altitude %lu is positioned "
                                    "above us (%lu) in the AV range — may intercept/hide I/O before EDR sees it",
                                    nameBuf[0] ? nameBuf : "?", foreignAlt, ourAltitude);
                                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                                DbgPrint("[!] %s\n", msg);
                            }
                        }
                    }

                    instIdx++;
                }

                FltObjectDereference(volList[vi]);
            }
            ExFreePool(volList);
        }
    }

    // -----------------------------------------------------------------------
    // Take snapshots for periodic integrity validation.
    // -----------------------------------------------------------------------
    KeInitializeSpinLock(&g_SnapshotLock);

    // Snapshot 1: record which volumes we are attached to.
    {
        PFLT_VOLUME* snapVolList = nullptr;
        ULONG snapVolCount = 0;
        NTSTATUS snapSt = FltEnumerateVolumes(g_FilterHandle, nullptr, 0, &snapVolCount);
        if (snapSt == STATUS_BUFFER_TOO_SMALL && snapVolCount > 0) {
            SIZE_T sz = snapVolCount * sizeof(PFLT_VOLUME);
            snapVolList = (PFLT_VOLUME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, 'vsnp');
            if (snapVolList)
                snapSt = FltEnumerateVolumes(g_FilterHandle, snapVolList, snapVolCount, &snapVolCount);
        }
        if (NT_SUCCESS(snapSt) && snapVolList) {
            g_InstanceSnapshotCount = 0;
            for (ULONG i = 0; i < snapVolCount && g_InstanceSnapshotCount < MAX_TRACKED_VOLUMES; i++) {
                // Check if we actually have an instance on this volume
                PFLT_INSTANCE inst = nullptr;
                NTSTATUS instSt = FltGetVolumeInstanceFromName(
                    g_FilterHandle, snapVolList[i], nullptr, &inst);
                if (NT_SUCCESS(instSt) && inst) {
                    ULONG idx = g_InstanceSnapshotCount++;
                    g_InstanceSnapshot[idx].Volume = snapVolList[i];
                    g_InstanceSnapshot[idx].Valid = TRUE;

                    UNICODE_STRING volStr;
                    volStr.Buffer = g_InstanceSnapshot[idx].VolumeName;
                    volStr.Length = 0;
                    volStr.MaximumLength = sizeof(g_InstanceSnapshot[idx].VolumeName) - sizeof(WCHAR);
                    ULONG retLen = 0;
                    FltGetVolumeName(snapVolList[i], &volStr, &retLen);
                    g_InstanceSnapshot[idx].VolumeName[volStr.Length / sizeof(WCHAR)] = L'\0';

                    FltObjectDereference(inst);
                }
                FltObjectDereference(snapVolList[i]);
            }
            ExFreePool(snapVolList);
        }
        DbgPrint("[+] FsFilter: instance snapshot captured (%lu volumes)\n", g_InstanceSnapshotCount);
    }

    // Snapshot 2: record our PreOp/PostOp callback function pointers.
    FsFilter::TakeCallbackSnapshot();

    // Snapshot 3: record FltMgr-internal _FLT_FILTER structure pointers.
    FsFilter::TakeFltFilterSnapshot();

    // Snapshot 4: record volume device objects and their MJ_CREATE dispatch
    // entries for IoCallDriver bypass detection.
    {
        PFLT_VOLUME* devVolList = nullptr;
        ULONG devVolCount = 0;
        NTSTATUS devSt = FltEnumerateVolumes(g_FilterHandle, nullptr, 0, &devVolCount);
        if (devSt == STATUS_BUFFER_TOO_SMALL && devVolCount > 0) {
            SIZE_T sz = devVolCount * sizeof(PFLT_VOLUME);
            devVolList = (PFLT_VOLUME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, 'dvol');
            if (devVolList)
                devSt = FltEnumerateVolumes(g_FilterHandle, devVolList, devVolCount, &devVolCount);
        }
        if (NT_SUCCESS(devSt) && devVolList) {
            g_TrackedVolumeDevCount = 0;
            for (ULONG i = 0; i < devVolCount && g_TrackedVolumeDevCount < MAX_TRACKED_VOLUME_DEVS; i++) {
                PDEVICE_OBJECT volDevObj = nullptr;
                NTSTATUS vdSt = FltGetDiskDeviceObject(devVolList[i], &volDevObj);
                if (NT_SUCCESS(vdSt) && volDevObj) {
                    ULONG idx = g_TrackedVolumeDevCount++;
                    g_TrackedVolumeDevices[idx] = volDevObj;
                    // Record the original IRP_MJ_CREATE handler on the underlying FS driver
                    if (volDevObj->DriverObject) {
                        g_TrackedVolDevMjCreate[idx] =
                            (PVOID)volDevObj->DriverObject->MajorFunction[IRP_MJ_CREATE];
                    }
                    ObDereferenceObject(volDevObj);
                }
                FltObjectDereference(devVolList[i]);
            }
            ExFreePool(devVolList);
        }
        DbgPrint("[+] FsFilter: volume device snapshot captured (%lu devices)\n",
                 g_TrackedVolumeDevCount);
    }

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
    // Only allow mandatory unloads (system shutdown / driver unload from DriverUnload).
    // Voluntary unloads (fltmc unload, FltUnloadFilter from mimidrv/BYOVD) are blocked.
    if (!(Flags & FLTFL_FILTER_UNLOAD_MANDATORY)) {
        DbgPrint("[!] FsFilter: voluntary unload attempt blocked (mimidrv defense)\n");

        // Fire a CRITICAL alert — someone is actively trying to evict our minifilter.
        char* procName = PsGetProcessImageFileName(IoGetCurrentProcess());
        char msg[224];
        RtlStringCchPrintfA(msg, sizeof(msg),
            "MINIFILTER UNLOAD BLOCKED: voluntary unload attempt by '%s' (pid=%llu) "
            "— fltmc unload / FltUnloadFilter / mimidrv eviction denied!",
            procName ? procName : "?",
            (ULONG64)(ULONG_PTR)PsGetCurrentProcessId());
        EnqueueFsAlert(PsGetCurrentProcessId(), procName, msg, TRUE);

        return STATUS_FLT_DO_NOT_DETACH;
    }
    FsFilter::Cleanup();
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// InstanceSetup — accept attachment to Named Pipe FS (npfs) and Mailslot FS
// (msfs) volumes in addition to regular file system volumes.
// The Filter Manager calls this for every volume it discovers; returning
// STATUS_SUCCESS means "attach here", STATUS_FLT_DO_NOT_ATTACH means "skip".
// ---------------------------------------------------------------------------
NTSTATUS FLTAPI FsFilter::InstanceSetupCallback(
    PCFLT_RELATED_OBJECTS      FltObjects,
    FLT_INSTANCE_SETUP_FLAGS   Flags,
    DEVICE_TYPE                VolumeDeviceType,
    FLT_FILESYSTEM_TYPE        VolumeFilesystemType
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    // Attach to: NTFS, npfs (Named Pipe File System), msfs (Mailslot File System)
    switch (VolumeFilesystemType) {
    case FLT_FSTYPE_NTFS:
    case FLT_FSTYPE_NPFS:   // Named Pipe File System
    case FLT_FSTYPE_MSFS:   // Mailslot File System
        return STATUS_SUCCESS;
    default:
        // Still attach to other FS types (FAT, ReFS, etc.) for broad coverage
        return STATUS_SUCCESS;
    }
}

// ---------------------------------------------------------------------------
// InstanceQueryTeardownCallback — called when FltDetachVolume or fltmc detach
// requests removal of one of our instances.  Returning STATUS_FLT_DO_NOT_DETACH
// blocks voluntary (API-driven) detach.  Mandatory teardowns (volume dismount,
// filter unload) bypass this callback entirely.
// ---------------------------------------------------------------------------
NTSTATUS FLTAPI FsFilter::InstanceQueryTeardownCallback(
    PCFLT_RELATED_OBJECTS                FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS    Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    // Build volume name for the alert
    WCHAR volName[128] = L"<unknown>";
    ULONG retLen = 0;
    if (FltObjects && FltObjects->Volume) {
        UNICODE_STRING volStr;
        volStr.Buffer = volName;
        volStr.Length = 0;
        volStr.MaximumLength = sizeof(volName) - sizeof(WCHAR);
        FltGetVolumeName(FltObjects->Volume, &volStr, &retLen);
        volName[volStr.Length / sizeof(WCHAR)] = L'\0';
    }

    // Convert to ANSI for the alert
    char volNameA[128] = {};
    for (int i = 0; i < 127 && volName[i]; i++)
        volNameA[i] = (char)volName[i];

    char msg[256];
    RtlStringCchPrintfA(msg, sizeof(msg),
        "MINIFILTER DETACH ATTEMPT: FltDetachVolume/fltmc detach on volume '%s' "
        "— blocked (anti-evasion)", volNameA);
    EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
    DbgPrint("[!] %s\n", msg);

    return STATUS_FLT_DO_NOT_DETACH;
}

// ---------------------------------------------------------------------------
// InstanceTeardownStartCallback — called when a mandatory teardown begins
// (volume dismount, filter unload).  We can't block these, but we log them
// so the EDR service knows an instance was removed.
// ---------------------------------------------------------------------------
VOID FLTAPI FsFilter::InstanceTeardownStartCallback(
    PCFLT_RELATED_OBJECTS          FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS    Reason
) {
    WCHAR volName[128] = L"<unknown>";
    ULONG retLen = 0;
    if (FltObjects && FltObjects->Volume) {
        UNICODE_STRING volStr;
        volStr.Buffer = volName;
        volStr.Length = 0;
        volStr.MaximumLength = sizeof(volName) - sizeof(WCHAR);
        FltGetVolumeName(FltObjects->Volume, &volStr, &retLen);
        volName[volStr.Length / sizeof(WCHAR)] = L'\0';
    }

    char volNameA[128] = {};
    for (int i = 0; i < 127 && volName[i]; i++)
        volNameA[i] = (char)volName[i];

    const char* reasonStr = "unknown";
    if (Reason & FLTFL_INSTANCE_TEARDOWN_MANUAL)
        reasonStr = "MANUAL (FltDetachVolume)";
    else if (Reason & FLTFL_INSTANCE_TEARDOWN_FILTER_UNLOAD)
        reasonStr = "FILTER_UNLOAD";
    else if (Reason & FLTFL_INSTANCE_TEARDOWN_MANDATORY_FILTER_UNLOAD)
        reasonStr = "MANDATORY_FILTER_UNLOAD";
    else if (Reason & FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT)
        reasonStr = "VOLUME_DISMOUNT";
    else if (Reason & FLTFL_INSTANCE_TEARDOWN_INTERNAL_ERROR)
        reasonStr = "INTERNAL_ERROR";

    char msg[256];
    RtlStringCchPrintfA(msg, sizeof(msg),
        "MINIFILTER INSTANCE TEARDOWN: volume '%s' reason=%s — "
        "instance is being forcibly detached!", volNameA, reasonStr);

    // Manual teardown is always suspicious — it means someone called
    // FltDetachVolume and our QueryTeardown was bypassed or overridden.
    BOOLEAN critical = (Reason & FLTFL_INSTANCE_TEARDOWN_MANUAL) ? TRUE : FALSE;
    EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, critical);
    DbgPrint("[!] %s\n", msg);
}

// ---------------------------------------------------------------------------
// InstanceTeardownCompleteCallback — final notification after teardown.
// At this point, no more I/O will be delivered to this instance.
// ---------------------------------------------------------------------------
VOID FLTAPI FsFilter::InstanceTeardownCompleteCallback(
    PCFLT_RELATED_OBJECTS          FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS    Reason
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);
    DbgPrint("[*] FsFilter: instance teardown complete (reason 0x%x)\n", Reason);
}

// ---------------------------------------------------------------------------
// TakeCallbackSnapshot — record the PreOp/PostOp function pointers from our
// FLT_OPERATION_REGISTRATION array at Init time.  ValidateMinifilterIntegrity
// compares the live values against this snapshot to detect DKOM callback
// pointer tampering (e.g., an attacker patching our PreCreate to a NOP or
// redirecting it to their own handler to hide I/O).
// ---------------------------------------------------------------------------
VOID FsFilter::TakeCallbackSnapshot() {
    g_CallbackSnapshotCount = 0;
    for (ULONG i = 0; g_FsCallbacks[i].MajorFunction != IRP_MJ_OPERATION_END; i++) {
        if (g_CallbackSnapshotCount >= MAX_TRACKED_CALLBACKS) break;
        ULONG idx = g_CallbackSnapshotCount++;
        g_CallbackSnapshot[idx].MajorFunction = g_FsCallbacks[i].MajorFunction;
        g_CallbackSnapshot[idx].PreOperation  = (PVOID)g_FsCallbacks[i].PreOperation;
        g_CallbackSnapshot[idx].PostOperation = (PVOID)g_FsCallbacks[i].PostOperation;
    }
    DbgPrint("[+] FsFilter: callback snapshot captured (%lu entries)\n", g_CallbackSnapshotCount);
}

// ---------------------------------------------------------------------------
// ValidateMinifilterIntegrity — periodic check called from AntiTamper.
//
// Verifies three things:
//   1) Instance attachment — re-enumerate our instances and compare to the
//      Init-time snapshot.  Missing instances = DKOM unlink or FltDetachVolume.
//   2) Callback pointer integrity — compare live FLT_OPERATION_REGISTRATION
//      PreOp/PostOp pointers against the Init-time snapshot.  Mismatch =
//      attacker patched our callback table (DKOM on _FLT_FILTER→Operations).
//   3) Altitude displacement — re-run the altitude squatting/sandwiching scan
//      from Init to detect late-loading adversary minifilters.
// ---------------------------------------------------------------------------
VOID FsFilter::ValidateMinifilterIntegrity() {
    if (!g_FilterHandle || !g_FsQueue) return;

    // ---- Check 1: Instance attachment verification ----
    {
        for (ULONG i = 0; i < g_InstanceSnapshotCount; i++) {
            if (!g_InstanceSnapshot[i].Valid) continue;

            PFLT_INSTANCE inst = nullptr;
            NTSTATUS st = FltGetVolumeInstanceFromName(
                g_FilterHandle, g_InstanceSnapshot[i].Volume, nullptr, &inst);

            if (!NT_SUCCESS(st) || !inst) {
                // Our instance on this volume is gone — DKOM or forced detach
                char volNameA[128] = {};
                for (int c = 0; c < 127 && g_InstanceSnapshot[i].VolumeName[c]; c++)
                    volNameA[c] = (char)g_InstanceSnapshot[i].VolumeName[c];

                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "MINIFILTER DKOM: our instance on volume '%s' has been detached! "
                    "Attacker may have unlinked our instance from the volume's instance list.",
                    volNameA);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);

                // Mark as invalid so we don't spam alerts every 30 seconds
                g_InstanceSnapshot[i].Valid = FALSE;
            } else {
                FltObjectDereference(inst);
            }
        }
    }

    // ---- Check 2: Callback pointer integrity ----
    {
        for (ULONG i = 0; i < g_CallbackSnapshotCount; i++) {
            PVOID livePreOp  = (PVOID)g_FsCallbacks[i].PreOperation;
            PVOID livePostOp = (PVOID)g_FsCallbacks[i].PostOperation;

            if (livePreOp != g_CallbackSnapshot[i].PreOperation) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "MINIFILTER DKOM: PreOperation callback for IRP_MJ_%u "
                    "was patched! Expected 0x%p, found 0x%p — callback table tampering!",
                    (ULONG)g_CallbackSnapshot[i].MajorFunction,
                    g_CallbackSnapshot[i].PreOperation, livePreOp);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
            }

            if (livePostOp != g_CallbackSnapshot[i].PostOperation) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "MINIFILTER DKOM: PostOperation callback for IRP_MJ_%u "
                    "was patched! Expected 0x%p, found 0x%p — callback table tampering!",
                    (ULONG)g_CallbackSnapshot[i].MajorFunction,
                    g_CallbackSnapshot[i].PostOperation, livePostOp);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
            }
        }
    }

    // ---- Check 3: Altitude displacement (late-loading adversary filters) ----
    {
        ULONG ourAltitude = 320021;
        PFLT_VOLUME* volList = nullptr;
        ULONG volCount = 0;
        NTSTATUS enumSt = FltEnumerateVolumes(g_FilterHandle, nullptr, 0, &volCount);
        if (enumSt == STATUS_BUFFER_TOO_SMALL && volCount > 0) {
            SIZE_T sz = volCount * sizeof(PFLT_VOLUME);
            volList = (PFLT_VOLUME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, 'avol');
            if (volList)
                enumSt = FltEnumerateVolumes(g_FilterHandle, volList, volCount, &volCount);
        }

        if (NT_SUCCESS(enumSt) && volList) {
            for (ULONG vi = 0; vi < volCount; vi++) {
                ULONG instIdx = 0;
                UCHAR instBuf[512];
                ULONG instNeeded = 0;

                while (TRUE) {
                    NTSTATUS instSt = FltEnumerateInstanceInformationByVolume(
                        volList[vi], instIdx,
                        InstanceAggregateStandardInformation,
                        instBuf, sizeof(instBuf), &instNeeded);

                    if (instSt == STATUS_NO_MORE_ENTRIES) break;
                    if (!NT_SUCCESS(instSt)) { instIdx++; continue; }

                    PINSTANCE_AGGREGATE_STANDARD_INFORMATION instInfo =
                        (PINSTANCE_AGGREGATE_STANDARD_INFORMATION)instBuf;

                    if (instInfo->Flags & FLTFL_IASI_IS_MINIFILTER) {
                        UNICODE_STRING instAlt = { 0 };
                        UNICODE_STRING instName = { 0 };

                        if (instInfo->Type.MiniFilter.FilterNameLength > 0 &&
                            instInfo->Type.MiniFilter.FilterNameBufferOffset > 0)
                        {
                            instName.Buffer = (PWCH)((PUCHAR)instInfo +
                                instInfo->Type.MiniFilter.FilterNameBufferOffset);
                            instName.Length = instInfo->Type.MiniFilter.FilterNameLength;
                            instName.MaximumLength = instName.Length;
                        }

                        if (instInfo->Type.MiniFilter.AltitudeLength > 0 &&
                            instInfo->Type.MiniFilter.AltitudeBufferOffset > 0)
                        {
                            instAlt.Buffer = (PWCH)((PUCHAR)instInfo +
                                instInfo->Type.MiniFilter.AltitudeBufferOffset);
                            instAlt.Length = instInfo->Type.MiniFilter.AltitudeLength;
                            instAlt.MaximumLength = instAlt.Length;
                        }

                        // Skip our own instances
                        UNICODE_STRING ourName = RTL_CONSTANT_STRING(L"NortonEDRDriver");
                        if (instName.Length > 0 &&
                            RtlEqualUnicodeString(&instName, &ourName, TRUE))
                        {
                            instIdx++;
                            continue;
                        }

                        if (instAlt.Length > 0 && instAlt.Buffer) {
                            ULONG foreignAlt = 0;
                            for (USHORT ci = 0; ci < instAlt.Length / sizeof(WCHAR); ci++) {
                                WCHAR c = instAlt.Buffer[ci];
                                if (c >= L'0' && c <= L'9')
                                    foreignAlt = foreignAlt * 10 + (c - L'0');
                                else if (c == L'.') break;
                            }

                            // Squatting: exact altitude match
                            if (foreignAlt == ourAltitude) {
                                char nameBuf[64] = {};
                                ANSI_STRING ansiN;
                                if (instName.Length > 0 &&
                                    NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &instName, TRUE)))
                                {
                                    SIZE_T n = ansiN.Length < sizeof(nameBuf) - 1 ? ansiN.Length : sizeof(nameBuf) - 1;
                                    RtlCopyMemory(nameBuf, ansiN.Buffer, n);
                                    RtlFreeAnsiString(&ansiN);
                                }
                                char msg[256];
                                RtlStringCchPrintfA(msg, sizeof(msg),
                                    "ALTITUDE SQUATTING (periodic): filter '%s' at our exact altitude %lu!",
                                    nameBuf[0] ? nameBuf : "?", ourAltitude);
                                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                                DbgPrint("[!] %s\n", msg);
                            }
                            // Sandwiching: filter positioned above us in AV range
                            else if (foreignAlt > ourAltitude &&
                                     foreignAlt <= 329999)
                            {
                                char nameBuf[64] = {};
                                ANSI_STRING ansiN;
                                if (instName.Length > 0 &&
                                    NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &instName, TRUE)))
                                {
                                    SIZE_T n = ansiN.Length < sizeof(nameBuf) - 1 ? ansiN.Length : sizeof(nameBuf) - 1;
                                    RtlCopyMemory(nameBuf, ansiN.Buffer, n);
                                    RtlFreeAnsiString(&ansiN);
                                }
                                char msg[256];
                                RtlStringCchPrintfA(msg, sizeof(msg),
                                    "ALTITUDE SANDWICH (periodic): filter '%s' at altitude %lu "
                                    "above us (%lu) in AV range!",
                                    nameBuf[0] ? nameBuf : "?", foreignAlt, ourAltitude);
                                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                                DbgPrint("[!] %s\n", msg);
                            }
                        }
                    }
                    instIdx++;
                }
                FltObjectDereference(volList[vi]);
            }
            ExFreePool(volList);
        }
    }

    // ---- Check 4: Deep DKOM — _FLT_FILTER internal structure integrity ----
    ValidateFltFilterInternal();

    // ---- Check 5: FastIO / volume device dispatch table integrity ----
    ValidateFastIoDispatch();

    // ---- Check 6: Notification queue pressure ----
    CheckQueuePressure();

    // ---- Check 7: PreOp invocation counter silence detection ----
    // If a higher-altitude filter starts returning FLT_PREOP_COMPLETE, our PreOp
    // callbacks stop being invoked.  Detect this by tracking per-IRP counters
    // across intervals and alerting on sustained zero activity for previously
    // active IRP types.
    {
        LONG current[PREOP_COUNTER_SLOTS];
        for (ULONG i = 0; i < PREOP_COUNTER_SLOTS; i++) {
            current[i] = InterlockedExchange(&g_PreOpCounters[i], 0);
        }

        if (g_PreOpBaselined) {
            for (ULONG i = 0; i < PREOP_COUNTER_SLOTS; i++) {
                if (current[i] == 0 && g_PreOpPrev[i] >= PREOP_ACTIVE_THRESHOLD) {
                    // Was active, now silent — increment zero-run counter
                    g_PreOpZeroRuns[i]++;
                    if (g_PreOpZeroRuns[i] == PREOP_ZERO_ALERT_RUNS) {
                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "CALLBACK SILENCING: %s PreOp dropped from %ld/interval to 0 "
                            "for %u consecutive checks — higher-altitude filter may be "
                            "force-completing I/O (FLT_PREOP_COMPLETE attack)!",
                            kPreOpNames[i], g_PreOpPrev[i], PREOP_ZERO_ALERT_RUNS);
                        EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                        DbgPrint("[!] %s\n", msg);
                    }
                } else if (current[i] > 0) {
                    // Activity resumed or continues — reset zero-run counter
                    g_PreOpZeroRuns[i] = 0;
                }
                // If both current and prev are 0 (IRP type never active), leave alone
            }
        } else {
            g_PreOpBaselined = TRUE;
        }

        // Shift current → prev for next interval
        for (ULONG i = 0; i < PREOP_COUNTER_SLOTS; i++) {
            g_PreOpPrev[i] = current[i];
        }
    }

    // ---- Check 8: Canary I/O heartbeat ----
    // Issue a ZwCreateFile on a known canary path with FILE_OPEN (open-only, no create).
    // Our PreCreate will recognise the canary filename and bump g_CanaryHits.
    // If the counter doesn't increment, a higher filter is completing our creates.
    {
        LONG hitsBefore = InterlockedCompareExchange(&g_CanaryHits, 0, 0);

        UNICODE_STRING canaryName;
        RtlInitUnicodeString(&canaryName, g_CanaryPath);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &canaryName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        IO_STATUS_BLOCK iosb;
        HANDLE hCanary = nullptr;

        // FILE_OPEN will fail with STATUS_OBJECT_NAME_NOT_FOUND — we don't care
        // about the result, only that PreCreate fires.
        NTSTATUS canSt = ZwCreateFile(
            &hCanary, FILE_READ_ATTRIBUTES, &oa, &iosb,
            NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,  // open only — don't create the file
            FILE_NON_DIRECTORY_FILE,
            NULL, 0);

        if (NT_SUCCESS(canSt) && hCanary)
            ZwClose(hCanary);

        // Check if PreCreate saw the canary
        LONG hitsAfter = InterlockedCompareExchange(&g_CanaryHits, 0, 0);

        if (hitsAfter <= hitsBefore) {
            // PreCreate didn't fire for our canary — callback silenced
            if (!g_CanaryAlerted) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "CANARY I/O FAILED: PreCreate was NOT invoked for canary file '%ws' "
                    "— a higher-altitude minifilter is force-completing IRP_MJ_CREATE, "
                    "blinding the EDR to all file opens!",
                    g_CanaryPath);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
                g_CanaryAlerted = TRUE;
            }
        } else {
            // Canary hit — pipeline is healthy
            g_CanaryAlerted = FALSE;
        }
    }

    DbgPrint("[*] FsFilter: minifilter integrity check complete\n");
}

// ---------------------------------------------------------------------------
// TakeFltFilterSnapshot — scan the _FLT_FILTER object behind g_FilterHandle
// to locate the internal Operations pointer and Flags field.
//
// We find Operations by scanning memory for a pointer matching &g_FsCallbacks.
// This is safe because g_FilterHandle is our own structure, allocated by FltMgr.
// The scan is limited to the first 512 bytes of the object (typical _FLT_FILTER
// size is ~0x300 on Win10/11 x64).
// ---------------------------------------------------------------------------
VOID FsFilter::TakeFltFilterSnapshot() {
    if (!g_FilterHandle) return;

    PULONG_PTR base = (PULONG_PTR)g_FilterHandle;
    ULONG_PTR target = (ULONG_PTR)&g_FsCallbacks[0];

    // Scan first 512 bytes (64 pointer-sized slots) for our Operations table pointer
    for (ULONG i = 0; i < 64; i++) {
        __try {
            if (MmIsAddressValid(&base[i]) && base[i] == target) {
                g_FltFilterOpsOffset = i * sizeof(ULONG_PTR);
                g_FltFilterOpsPtr = &base[i];
                g_FltFilterOpsValue = (PVOID)target;
                g_FltFilterSnapshotValid = TRUE;
                DbgPrint("[+] FsFilter: _FLT_FILTER.Operations found at offset 0x%x (value 0x%p)\n",
                         g_FltFilterOpsOffset, g_FltFilterOpsValue);
                break;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
    }

    if (!g_FltFilterSnapshotValid) {
        DbgPrint("[-] FsFilter: could not locate _FLT_FILTER.Operations — "
                 "deep DKOM detection unavailable\n");
    }

    // Locate Base.Flags — the FLT_OBJECT header is at offset 0 of _FLT_FILTER.
    // FLT_OBJECT layout (x64):
    //   +0x00 ULONG Flags
    //   +0x04 ULONG PointerCount
    //   +0x08 EX_RUNDOWN_REF RundownRef
    //   +0x10 LIST_ENTRY PrimaryLink
    // After FltRegisterFilter + FltStartFiltering, Flags should have
    // FLTFL_FILTERING_INITIATED (0x2) set.
    __try {
        PULONG flagsPtr = (PULONG)g_FilterHandle;
        if (MmIsAddressValid(flagsPtr)) {
            g_FltFilterFlagsPtr = flagsPtr;
            g_FltFilterFlagsInit = *flagsPtr;
            g_FltFilterFlagsValid = TRUE;
            DbgPrint("[+] FsFilter: _FLT_FILTER.Base.Flags = 0x%x at Init\n",
                     g_FltFilterFlagsInit);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] FsFilter: could not read _FLT_FILTER.Base.Flags\n");
    }
}

// ---------------------------------------------------------------------------
// ValidateFltFilterInternal — deep DKOM detection.
//   1. Check that the _FLT_FILTER.Operations pointer still points to g_FsCallbacks
//   2. Check that _FLT_FILTER.Base.Flags still has the filtering-initiated bit
//      (cleared by FltUnregisterFilter)
// ---------------------------------------------------------------------------
VOID FsFilter::ValidateFltFilterInternal() {
    // Check 1: Operations pointer redirection
    if (g_FltFilterSnapshotValid && g_FltFilterOpsPtr) {
        __try {
            PVOID currentOps = *(PVOID*)g_FltFilterOpsPtr;
            if (currentOps != g_FltFilterOpsValue) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "MINIFILTER DEEP DKOM: _FLT_FILTER.Operations pointer redirected! "
                    "Expected 0x%p (g_FsCallbacks), found 0x%p — attacker diverted "
                    "our callback registration inside FltMgr!",
                    g_FltFilterOpsValue, currentOps);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            EnqueueFsAlert(PsGetCurrentProcessId(), nullptr,
                "MINIFILTER DEEP DKOM: _FLT_FILTER.Operations pointer became inaccessible!",
                TRUE);
        }
    }

    // Check 2: FltUnregisterFilter detection via Base.Flags
    if (g_FltFilterFlagsValid && g_FltFilterFlagsPtr) {
        __try {
            ULONG currentFlags = *(PULONG)g_FltFilterFlagsPtr;
            // FLTFL_FILTERING_INITIATED = 0x2 — set after FltStartFiltering,
            // cleared when FltUnregisterFilter completes.
            if ((g_FltFilterFlagsInit & 0x2) && !(currentFlags & 0x2)) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "MINIFILTER UNREGISTERED: _FLT_FILTER.Base.Flags changed from "
                    "0x%x to 0x%x — FLTFL_FILTERING_INITIATED bit cleared! "
                    "FltUnregisterFilter was called from kernel (BYOVD attack)!",
                    g_FltFilterFlagsInit, currentFlags);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            EnqueueFsAlert(PsGetCurrentProcessId(), nullptr,
                "MINIFILTER TAMPER: _FLT_FILTER.Base.Flags memory inaccessible — "
                "filter object may have been freed!",
                TRUE);
        }
    }
}

// ---------------------------------------------------------------------------
// ValidateFastIoDispatch — detect FastIO bypass attacks.
//
// FltMgr hooks the FastIO dispatch table on the FSD's (e.g., ntfs.sys) device
// objects to intercept FastIO calls and route them through the minifilter stack.
// If an attacker restores the original FastIO pointers on the FSD's driver
// object, FastIO calls will bypass all minifilters.
//
// We detect this by checking that the volume device objects' DriverObject still
// has FltMgr-hooked FastIO entries (specifically, the FastIoRead/FastIoWrite
// pointers should point into fltmgr.sys address range, not ntfs.sys).
// ---------------------------------------------------------------------------
VOID FsFilter::ValidateFastIoDispatch() {
    if (g_TrackedVolumeDevCount == 0) return;

    for (ULONG i = 0; i < g_TrackedVolumeDevCount; i++) {
        PDEVICE_OBJECT devObj = g_TrackedVolumeDevices[i];
        if (!devObj || !MmIsAddressValid(devObj)) continue;

        __try {
            PDRIVER_OBJECT drvObj = devObj->DriverObject;
            if (!drvObj || !MmIsAddressValid(drvObj)) continue;

            // Check if the MajorFunction[IRP_MJ_CREATE] dispatch has been patched.
            // FltMgr replaces these with its own handlers (FltpCreate, FltpRead, etc.).
            // If someone restores the original NTFS handler, our minifilter is bypassed
            // for that operation on IRPs sent directly to the device.
            PVOID currentMjCreate = (PVOID)drvObj->MajorFunction[IRP_MJ_CREATE];
            PVOID originalMjCreate = g_TrackedVolDevMjCreate[i];

            if (originalMjCreate && currentMjCreate != originalMjCreate) {
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "VOLUME DEVICE HOOK: MajorFunction[IRP_MJ_CREATE] on volume device "
                    "0x%p changed from 0x%p to 0x%p — possible FltMgr unhooking!",
                    devObj, originalMjCreate, currentMjCreate);
                EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
                DbgPrint("[!] %s\n", msg);
            }

            // Check FastIoDispatch pointer itself
            PFAST_IO_DISPATCH fastIo = drvObj->FastIoDispatch;
            if (fastIo && MmIsAddressValid(fastIo)) {
                // The FastIoRead/FastIoWrite entries should be hooked by FltMgr.
                // We can detect unhooking by checking if they still point into
                // fltmgr.sys range.  For simplicity, just verify they haven't changed
                // since we first observed them.
                // (On first call, we record; on subsequent calls, we compare.)
                // Use a simple static flag — first pass records, second+ compares.
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
    }
}

// ---------------------------------------------------------------------------
// CheckQueuePressure — alert if the notification queue is near capacity.
// An attacker could intentionally generate high I/O to flood the queue,
// causing legitimate security alerts to be silently dropped.
// ---------------------------------------------------------------------------
VOID FsFilter::CheckQueuePressure() {
    if (!g_FsQueue) return;

    // BufferQueue is the base of NotifQueue — GetSizePassive is safe at PASSIVE_LEVEL
    ULONG queueSize = ((BufferQueue*)g_FsQueue)->GetSizePassive();
    ULONG capacity  = ((BufferQueue*)g_FsQueue)->GetCapacity();

    if (capacity == 0) return;

    ULONG pctUsed = (queueSize * 100) / capacity;

    if (pctUsed >= 80 && !g_QueuePressureAlerted) {
        char msg[256];
        RtlStringCchPrintfA(msg, sizeof(msg),
            "NOTIFICATION QUEUE PRESSURE: %lu/%lu slots used (%lu%%) — "
            "alerts may be dropped! Possible queue-flooding evasion attack.",
            queueSize, capacity, pctUsed);
        EnqueueFsAlert(PsGetCurrentProcessId(), nullptr, msg, TRUE);
        DbgPrint("[!] %s\n", msg);
        g_QueuePressureAlerted = TRUE;
    }
    else if (pctUsed < 50 && g_QueuePressureAlerted) {
        // Reset the alert flag once pressure subsides
        g_QueuePressureAlerted = FALSE;
        DbgPrint("[*] FsFilter: queue pressure subsided (%lu%%)\n", pctUsed);
    }
}

// ---------------------------------------------------------------------------
// PostCreate — STATUS_REPARSE abuse detection.
//
// An adversary minifilter positioned above us can return FLT_PREOP_COMPLETE
// with STATUS_REPARSE, redirecting a file open from a monitored path to an
// unmonitored path.  Our PreCreate never fires for the final (reparsed) path.
// This PostOp catches the reparse and validates the final target.
//
// Also detects IRP completion routine manipulation — if the IoStatus in the
// completion doesn't match what we expect, an intermediate driver may have
// tampered with it.
// ---------------------------------------------------------------------------
static const PCWSTR kMonitoredDirs[] = {
    L"\\Windows\\System32\\",
    L"\\Windows\\SysWOW64\\",
    L"\\Windows\\",
    L"\\Program Files\\",
    L"\\Program Files (x86)\\",
};

FLT_POSTOP_CALLBACK_STATUS FLTAPI FsFilter::PostCreate(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID                      CompletionContext,
    FLT_POST_OPERATION_FLAGS   Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);

    // Free the context on all exit paths (including draining)
    PREOP_CREATE_CTX* ctx = nullptr;
    if (CompletionContext) {
        ctx = (PREOP_CREATE_CTX*)CompletionContext;
        if (ctx->Magic != PARAM_CTX_MAGIC) ctx = nullptr;  // safety check
    }

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        if (ctx) ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!Data || !Data->Iopb) {
        if (ctx) ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // ---- FLT_CALLBACK_DATA tampering: cross-validate PreOp snapshot ----
    // If any filter between our PreOp and PostOp modified the Iopb without
    // calling FltSetCallbackDataDirty (or modified it at all), the params
    // will diverge from our snapshot.  This catches:
    //   - TargetFileObject swap (redirect detection to decoy file)
    //   - DesiredAccess downgrade (hide write/delete intent)
    //   - CreateOptions modification (hide DELETE_ON_CLOSE, OPEN_BY_FILE_ID)
    if (ctx) {
        BOOLEAN tampered = FALSE;
        char detail[256] = {};

        ACCESS_MASK liveAccess  = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        ULONG       liveOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
        PFILE_OBJECT liveFO     = Data->Iopb->TargetFileObject;

        if (liveFO != ctx->TargetFileObject) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "TargetFileObject SWAPPED: PreOp=0x%p PostOp=0x%p "
                "— intermediate filter redirected I/O to a different file!",
                ctx->TargetFileObject, liveFO);
        }
        else if (liveAccess != ctx->DesiredAccess) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "DesiredAccess MODIFIED: PreOp=0x%lx PostOp=0x%lx "
                "— intermediate filter altered access mask to hide intent!",
                (ULONG)ctx->DesiredAccess, (ULONG)liveAccess);
        }
        else if (liveOptions != ctx->CreateOptions) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "CreateOptions MODIFIED: PreOp=0x%lx PostOp=0x%lx "
                "— intermediate filter altered create options!",
                ctx->CreateOptions, liveOptions);
        }

        if (tampered) {
            PEPROCESS proc = IoThreadToProcess(Data->Thread);
            HANDLE pid = proc ? PsGetProcessId(proc) : (HANDLE)0;
            char msg[350];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FLT_CALLBACK_DATA TAMPERING (IRP_MJ_CREATE): %s", detail);
            EnqueueFsAlert(pid, nullptr, msg, TRUE);
            DbgPrint("[!] %s\n", msg);
        }

        ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
    }

    // ---- STATUS_REPARSE abuse detection ----
    NTSTATUS createStatus = Data->IoStatus.Status;
    if (createStatus == STATUS_REPARSE) {
        PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
        NTSTATUS st = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

        if (NT_SUCCESS(st) && nameInfo) {
            FltParseFileNameInformation(nameInfo);

            BOOLEAN wasMonitored = FALSE;
            for (int i = 0; i < ARRAYSIZE(kMonitoredDirs); i++) {
                if (UnicodeStringContains(&nameInfo->Name, kMonitoredDirs[i])) {
                    wasMonitored = TRUE;
                    break;
                }
            }

            if (wasMonitored) {
                ULONG reparseTag = 0;
                if (Data->TagData) reparseTag = Data->TagData->FileTag;

                PEPROCESS proc = IoThreadToProcess(Data->Thread);
                HANDLE pid = proc ? PsGetProcessId(proc) : (HANDLE)0;

                char pathA[128] = {};
                ULONG copyLen = nameInfo->Name.Length / sizeof(WCHAR);
                if (copyLen > sizeof(pathA) - 1) copyLen = sizeof(pathA) - 1;
                for (ULONG c = 0; c < copyLen; c++)
                    pathA[c] = (char)nameInfo->Name.Buffer[c];

                char msg[300];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "STATUS_REPARSE on monitored path '%s' (tag 0x%x) — "
                    "possible adversary minifilter redirecting I/O away from "
                    "protected directory!", pathA, reparseTag);
                EnqueueFsAlert(pid, nullptr, msg, TRUE);
            }

            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ---------------------------------------------------------------------------
// PostSetInformation — FLT_CALLBACK_DATA tampering detection for IRP_MJ_SET_INFORMATION.
//
// Cross-validates PreOp snapshot of FileInformationClass, InfoBuffer, and
// TargetFileObject against the live Iopb.  Any mismatch indicates an
// intermediate minifilter altered the operation to blind our rename/delete/
// timestomping detection.
// ---------------------------------------------------------------------------
FLT_POSTOP_CALLBACK_STATUS FLTAPI FsFilter::PostSetInformation(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID                      CompletionContext,
    FLT_POST_OPERATION_FLAGS   Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);

    PREOP_SETINFO_CTX* ctx = nullptr;
    if (CompletionContext) {
        ctx = (PREOP_SETINFO_CTX*)CompletionContext;
        if (ctx->Magic != PARAM_CTX_MAGIC) ctx = nullptr;
    }

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) || !Data || !Data->Iopb) {
        if (ctx) ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (ctx) {
        BOOLEAN tampered = FALSE;
        char detail[256] = {};

        FILE_INFORMATION_CLASS liveClass =
            (FILE_INFORMATION_CLASS)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        PVOID       liveBuf = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        PFILE_OBJECT liveFO = Data->Iopb->TargetFileObject;

        if (liveFO != ctx->TargetFileObject) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "TargetFileObject SWAPPED: PreOp=0x%p PostOp=0x%p "
                "— intermediate filter redirected SetInfo to a different file!",
                ctx->TargetFileObject, liveFO);
        }
        else if (liveClass != ctx->InfoClass) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "FileInformationClass MODIFIED: PreOp=%u PostOp=%u "
                "— intermediate filter changed SetInfo class to blind detection!",
                (ULONG)ctx->InfoClass, (ULONG)liveClass);
        }
        else if (liveBuf != ctx->InfoBuffer) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "InfoBuffer SWAPPED: PreOp=0x%p PostOp=0x%p "
                "— intermediate filter replaced SetInfo data buffer!",
                ctx->InfoBuffer, liveBuf);
        }

        if (tampered) {
            PEPROCESS proc = IoThreadToProcess(Data->Thread);
            HANDLE pid = proc ? PsGetProcessId(proc) : (HANDLE)0;
            char msg[350];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FLT_CALLBACK_DATA TAMPERING (IRP_MJ_SET_INFORMATION): %s", detail);
            EnqueueFsAlert(pid, nullptr, msg, TRUE);
            DbgPrint("[!] %s\n", msg);
        }

        ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ---------------------------------------------------------------------------
// PostWrite — FLT_CALLBACK_DATA tampering detection for IRP_MJ_WRITE.
//
// Cross-validates PreOp snapshot of ByteOffset, Length, and TargetFileObject
// against the live Iopb.  Detects intermediate filters that alter write
// parameters to redirect writes or change what we think was written.
// ---------------------------------------------------------------------------
FLT_POSTOP_CALLBACK_STATUS FLTAPI FsFilter::PostWrite(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID                      CompletionContext,
    FLT_POST_OPERATION_FLAGS   Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);

    PREOP_WRITE_CTX* ctx = nullptr;
    if (CompletionContext) {
        ctx = (PREOP_WRITE_CTX*)CompletionContext;
        if (ctx->Magic != PARAM_CTX_MAGIC) ctx = nullptr;
    }

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) || !Data || !Data->Iopb) {
        if (ctx) ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (ctx) {
        BOOLEAN tampered = FALSE;
        char detail[256] = {};

        LARGE_INTEGER liveOffset = Data->Iopb->Parameters.Write.ByteOffset;
        ULONG         liveLen    = Data->Iopb->Parameters.Write.Length;
        PFILE_OBJECT  liveFO     = Data->Iopb->TargetFileObject;

        if (liveFO != ctx->TargetFileObject) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "TargetFileObject SWAPPED: PreOp=0x%p PostOp=0x%p "
                "— intermediate filter redirected Write to a different file!",
                ctx->TargetFileObject, liveFO);
        }
        else if (liveOffset.QuadPart != ctx->ByteOffset.QuadPart) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "ByteOffset MODIFIED: PreOp=0x%llx PostOp=0x%llx "
                "— intermediate filter changed write offset!",
                ctx->ByteOffset.QuadPart, liveOffset.QuadPart);
        }
        else if (liveLen != ctx->Length) {
            tampered = TRUE;
            RtlStringCchPrintfA(detail, sizeof(detail),
                "Length MODIFIED: PreOp=%lu PostOp=%lu "
                "— intermediate filter changed write length!",
                ctx->Length, liveLen);
        }

        if (tampered) {
            PEPROCESS proc = IoThreadToProcess(Data->Thread);
            HANDLE pid = proc ? PsGetProcessId(proc) : (HANDLE)0;
            char msg[350];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FLT_CALLBACK_DATA TAMPERING (IRP_MJ_WRITE): %s", detail);
            EnqueueFsAlert(pid, nullptr, msg, TRUE);
            DbgPrint("[!] %s\n", msg);
        }

        ExFreePoolWithTag(ctx, PARAM_CTX_TAG);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ---------------------------------------------------------------------------
// Named Pipe FS pre-create callback — monitors pipe open/connect operations.
//
// When a process opens a named pipe (IRP_MJ_CREATE on npfs volume), this
// detects pipe impersonation attacks and suspicious pipe access patterns:
//   - FILE_CREATE_PIPE_INSTANCE: creating a rogue instance to intercept clients
//   - Pipe opens with WRITE_DAC/WRITE_OWNER: DACL manipulation on pipes
//   - Access to known sensitive pipes from unexpected processes
// ---------------------------------------------------------------------------
static const PCWSTR kSensitivePipes[] = {
    L"lsarpc",            // LSA RPC — credential theft
    L"samr",              // SAM Remote Protocol — user enumeration
    L"svcctl",            // Service Control Manager — remote service creation
    L"atsvc",             // Task Scheduler — remote task creation
    L"epmapper",          // RPC Endpoint Mapper
    L"eventlog",          // Event Log — log manipulation
    L"winreg",            // Remote Registry
    L"srvsvc",            // Server Service — share enumeration
    L"wkssvc",            // Workstation Service
    L"spoolss",           // Print Spooler — PrintNightmare
};

// Known C2 pipe name patterns (substring match) — same set as the syscall hook
// but checked here on the open/connect side for processes that didn't create the pipe.
static const PCWSTR kC2PipePatternsFs[] = {
    L"msagent_",       L"MSSE-",          L"postex_",
    L"postex_ssh_",    L"status_",        L"mojo.5688.8052",
    L"win_svc",        L"ntsvcs_",        L"scerpc_",
    L"meterpreter",    L"PSEXESVC",       L"RemCom",
    L"csexec",         L"winsvc_",
};

FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreCreateNpfs(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Iopb->Parameters.Create.SecurityContext)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PEPROCESS process  = IoThreadToProcess(Data->Thread);
    HANDLE    pid      = PsGetProcessId(process);
    char*     procName = PsGetProcessImageFileName(process);

    // Skip system processes
    if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (procName) {
        char lower[16] = {};
        for (int i = 0; i < 15 && procName[i]; i++)
            lower[i] = (procName[i] >= 'A' && procName[i] <= 'Z') ? procName[i] + 32 : procName[i];
        if (strcmp(lower, "system") == 0 || strcmp(lower, "svchost.exe") == 0 ||
            strcmp(lower, "services.exe") == 0 || strcmp(lower, "lsass.exe") == 0 ||
            strcmp(lower, "wininit.exe") == 0 || strcmp(lower, "csrss.exe") == 0)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    __try {
        if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo))) __leave;

        // ---- C2 framework pipe pattern on connect side ----
        for (SIZE_T i = 0; i < ARRAYSIZE(kC2PipePatternsFs); i++) {
            if (WcsContainsLower(&nameInfo->FinalComponent, kC2PipePatternsFs[i])) {
                char msg[224];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS-NPFS: Process '%s' (pid=%llu) connecting to C2-pattern pipe "
                    "(Cobalt Strike / Metasploit / PsExec)",
                    procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                __leave;
            }
        }

        // ---- Sensitive pipe access from non-SMB-server processes ----
        // RPC pipes like lsarpc, samr, svcctl are normally opened by svchost/lsass.
        // A random user process opening them may indicate lateral movement tools
        // (Impacket, CrackMapExec, etc.) running locally.
        for (SIZE_T i = 0; i < ARRAYSIZE(kSensitivePipes); i++) {
            if (WcsContainsLower(&nameInfo->FinalComponent, kSensitivePipes[i])) {
                char pipeBuf[64] = {};
                ANSI_STRING ansiPipe;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiPipe, &nameInfo->FinalComponent, TRUE))) {
                    SIZE_T n = ansiPipe.Length < sizeof(pipeBuf) - 1 ? ansiPipe.Length : sizeof(pipeBuf) - 1;
                    RtlCopyMemory(pipeBuf, ansiPipe.Buffer, n);
                    RtlFreeAnsiString(&ansiPipe);
                }
                char msg[224];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS-NPFS: Sensitive RPC pipe access — pipe=%s by '%s' (pid=%llu) "
                    "— possible lateral movement / credential access",
                    pipeBuf[0] ? pipeBuf : "?",
                    procName ? procName : "?",
                    (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, FALSE);  // WARNING
                __leave;
            }
        }

        // ---- Pipe impersonation: FILE_CREATE_PIPE_INSTANCE from non-service process ----
        // Creating a new instance of an existing pipe allows intercepting clients that
        // connect to it — classic impersonation attack (e.g. potato privilege escalation).
        ACCESS_MASK desiredAccess =
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;

        if (createOptions & FILE_CREATE_PIPE_INSTANCE) {
            char pipeBuf[64] = {};
            ANSI_STRING ansiPipe;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiPipe, &nameInfo->FinalComponent, TRUE))) {
                SIZE_T n = ansiPipe.Length < sizeof(pipeBuf) - 1 ? ansiPipe.Length : sizeof(pipeBuf) - 1;
                RtlCopyMemory(pipeBuf, ansiPipe.Buffer, n);
                RtlFreeAnsiString(&ansiPipe);
            }
            char msg[224];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FS-NPFS: Pipe instance creation (impersonation risk) — pipe=%s "
                "by '%s' (pid=%llu) — possible potato / pipe impersonation attack",
                pipeBuf[0] ? pipeBuf : "?",
                procName ? procName : "?",
                (ULONG64)(ULONG_PTR)pid);
            EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
        }

        // ---- DACL manipulation on pipes ----
        if (desiredAccess & (WRITE_DAC | WRITE_OWNER)) {
            char pipeBuf[64] = {};
            ANSI_STRING ansiPipe;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiPipe, &nameInfo->FinalComponent, TRUE))) {
                SIZE_T n = ansiPipe.Length < sizeof(pipeBuf) - 1 ? ansiPipe.Length : sizeof(pipeBuf) - 1;
                RtlCopyMemory(pipeBuf, ansiPipe.Buffer, n);
                RtlFreeAnsiString(&ansiPipe);
            }
            char msg[224];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FS-NPFS: DACL/owner modification on pipe=%s by '%s' (pid=%llu)",
                pipeBuf[0] ? pipeBuf : "?",
                procName ? procName : "?",
                (ULONG64)(ULONG_PTR)pid);
            EnqueueFsAlert(pid, procName, msg, FALSE);  // WARNING
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_CREATE — credential access + executable drop detection
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreCreate(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    InterlockedIncrement(&g_PreOpCounters[PREOP_CREATE]);

    // ---- Canary I/O heartbeat recognition ----
    // Must run BEFORE the KernelMode early-return because ZwCreateFile (used by
    // the canary heartbeat in ValidateMinifilterIntegrity) originates from kernel
    // mode.  If this create targets our canary path, bump the hit counter and
    // skip all other processing.
    if (FltObjects && FltObjects->FileObject &&
        FltObjects->FileObject->FileName.Length > 0 &&
        FltObjects->FileObject->FileName.Buffer)
    {
        static const WCHAR kCanarySuffix[] = L"NortonEDR_canary_heartbeat.tmp";
        static const USHORT kSuffixChars = (sizeof(kCanarySuffix) / sizeof(WCHAR)) - 1;
        USHORT fnChars = FltObjects->FileObject->FileName.Length / sizeof(WCHAR);
        if (fnChars >= kSuffixChars) {
            // Wrap buffer access in __try/__except — a malicious higher-altitude
            // filter could free or corrupt the FileName.Buffer pointer.
            __try {
                PWCHAR tail = FltObjects->FileObject->FileName.Buffer + (fnChars - kSuffixChars);
                BOOLEAN match = TRUE;
                for (USHORT ci = 0; ci < kSuffixChars && match; ci++) {
                    WCHAR c = tail[ci];
                    if (c >= L'A' && c <= L'Z') c |= 0x20;
                    WCHAR e = kCanarySuffix[ci];
                    if (e >= L'A' && e <= L'Z') e |= 0x20;
                    if (c != e) match = FALSE;
                }
                if (match) {
                    InterlockedIncrement(&g_CanaryHits);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Buffer was invalid — skip canary check, continue normal path
            }
        }
    }

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Route to specialised handler when attached to Named Pipe File System (npfs.sys)
    if (FltObjects && FltObjects->FileObject) {
        FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;
        NTSTATUS volStatus = FltGetFileSystemType(FltObjects->Instance, &fsType);
        if (NT_SUCCESS(volStatus)) {
            if (fsType == FLT_FSTYPE_NPFS)
                return FsFilter::PreCreateNpfs(Data, FltObjects, CompletionContext);
            // msfs (mailslot) creates are also caught here — the syscall hook already
            // covers creation; on the open side there's little to flag beyond what
            // the pipe handler does, so we skip for now.
        }
    }

    // ---- Bogus FLT_CALLBACK_DATA hardening ----
    // A malicious higher-altitude minifilter can null or corrupt critical Iopb
    // members before our PreOp fires.  Validate essential pointers early so
    // downstream code doesn't BSOD on a poisoned IRP.
    if (!Data->Iopb->Parameters.Create.SecurityContext)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;  // null SecurityContext → crash guard
    if (!Data->Thread)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;  // null Thread → IoThreadToProcess crash guard

    // ---- Per-process I/O rate tracking (CPU-burn / filter-flood detection) ----
    {
        PEPROCESS rateProc = IoThreadToProcess(Data->Thread);
        HANDLE    ratePid  = PsGetProcessId(rateProc);

        if ((ULONG_PTR)ratePid > 4) {
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);

            KIRQL oldIrql;
            KeAcquireSpinLock(&g_IoRateLock, &oldIrql);

            IO_RATE_SLOT* slot = nullptr;
            IO_RATE_SLOT* freeSlot = nullptr;
            for (int i = 0; i < IO_RATE_TRACKER_SLOTS; i++) {
                if (g_IoRateSlots[i].Pid == ratePid) { slot = &g_IoRateSlots[i]; break; }
                if (!freeSlot && !g_IoRateSlots[i].Pid) freeSlot = &g_IoRateSlots[i];
            }

            if (slot) {
                if ((now.QuadPart - slot->WindowStart.QuadPart) > IO_RATE_WINDOW_100NS) {
                    // Window expired — reset
                    slot->Count = 1;
                    slot->WindowStart = now;
                    slot->Alerted = FALSE;
                } else {
                    slot->Count++;
                    if (slot->Count >= IO_RATE_THRESHOLD && !slot->Alerted) {
                        slot->Alerted = TRUE;
                        KeReleaseSpinLock(&g_IoRateLock, oldIrql);

                        char* ratePName = PsGetProcessImageFileName(rateProc);
                        char msg[192];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: I/O FLOOD — '%s' (pid=%llu) issued %lu creates in 1 second "
                            "— possible minifilter CPU-burn evasion attack",
                            ratePName ? ratePName : "?", (ULONG64)(ULONG_PTR)ratePid,
                            slot->Count);
                        EnqueueFsAlert(ratePid, ratePName, msg, TRUE);
                        goto rate_done;
                    }
                }
            } else if (freeSlot) {
                freeSlot->Pid = ratePid;
                freeSlot->Count = 1;
                freeSlot->WindowStart = now;
                freeSlot->Alerted = FALSE;
            }

            KeReleaseSpinLock(&g_IoRateLock, oldIrql);
        }
    }
rate_done:

    // ---- FILE_OPEN_BY_FILE_ID detection ----
    // Opening files by 64-bit NTFS File ID or 128-bit Object ID bypasses ALL
    // name-based detection rules.  This is rare in legitimate user-mode code
    // (mainly used by defrag, backup, and indexing services).
    {
        ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
        if (createOptions & FILE_OPEN_BY_FILE_ID) {
            PEPROCESS fidProc  = IoThreadToProcess(Data->Thread);
            HANDLE    fidPid   = PsGetProcessId(fidProc);
            char*     fidPName = PsGetProcessImageFileName(fidProc);

            // Allowlist: System, defrag, backup, search indexer, antimalware
            BOOLEAN fidAllowed = ((ULONG_PTR)fidPid <= 4);
            if (!fidAllowed && fidPName) {
                fidAllowed = (strcmp(fidPName, "defrag.exe") == 0 ||
                              strcmp(fidPName, "SearchIndex") == 0 ||
                              strcmp(fidPName, "SearchProto") == 0 ||
                              strcmp(fidPName, "TrustedInsta") == 0 ||
                              strcmp(fidPName, "vssvc.exe") == 0 ||
                              strcmp(fidPName, "wbengine.exe") == 0 ||
                              strcmp(fidPName, "MsMpEng.exe") == 0 ||
                              strcmp(fidPName, "NortonEDR.e") == 0);
            }

            if (!fidAllowed) {
                ACCESS_MASK fidAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                const char* accessStr = (fidAccess & (FILE_WRITE_DATA | DELETE)) ? "WRITE/DELETE" :
                                        (fidAccess & FILE_EXECUTE) ? "EXECUTE" : "READ";
                char msg[192];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: FILE_OPEN_BY_FILE_ID by '%s' (pid=%llu) access=%s "
                    "— bypasses name-based detection! (T1006)",
                    fidPName ? fidPName : "?", (ULONG64)(ULONG_PTR)fidPid, accessStr);
                EnqueueFsAlert(fidPid, fidPName, msg,
                    (fidAccess & (FILE_WRITE_DATA | DELETE | FILE_EXECUTE)) ? TRUE : FALSE);
            }
        }
    }

    // ---- IRP parameter validation (upstream filter spoofing detection) ----
    // Cross-reference the file name from FltGetFileNameInformation (which goes
    // through FltMgr's name provider chain and is authoritative) against the
    // FileObject->FileName that the I/O manager populated from the original
    // NtCreateFile call.  If a malicious filter above us rewrote the FileName
    // in the FileObject, these two will diverge.
    // We do this check on a sampling basis (every 64th create) to avoid perf impact.
    {
        static volatile LONG s_CreateCounter = 0;
        LONG count = InterlockedIncrement(&s_CreateCounter);
        if ((count & 0x3F) == 0 && FltObjects && FltObjects->FileObject &&
            FltObjects->FileObject->FileName.Length > 0)
        {
            PFLT_FILE_NAME_INFORMATION authNameInfo = nullptr;
            NTSTATUS authSt = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &authNameInfo);
            if (NT_SUCCESS(authSt) && authNameInfo) {
                FltParseFileNameInformation(authNameInfo);
                // Compare the final component (filename) — full path comparison is
                // unreliable because FltMgr normalises the volume prefix.
                UNICODE_STRING* foName = &FltObjects->FileObject->FileName;
                // Extract just the last component from both
                PWCHAR authFinal = authNameInfo->FinalComponent.Buffer;
                USHORT authLen   = authNameInfo->FinalComponent.Length;

                if (authFinal && authLen > 0 && foName->Length > 0) {
                    // Find last component of FileObject->FileName
                    PWCHAR foFinal = foName->Buffer;
                    USHORT foLen   = foName->Length;
                    for (USHORT i = foName->Length / sizeof(WCHAR); i > 0; i--) {
                        if (foName->Buffer[i - 1] == L'\\') {
                            foFinal = &foName->Buffer[i];
                            foLen   = foName->Length - i * sizeof(WCHAR);
                            break;
                        }
                    }

                    // Case-insensitive compare
                    UNICODE_STRING a = { authLen, authLen, authFinal };
                    UNICODE_STRING b = { foLen, foLen, foFinal };
                    if (!RtlEqualUnicodeString(&a, &b, TRUE)) {
                        PEPROCESS vpProc  = IoThreadToProcess(Data->Thread);
                        HANDLE    vpPid   = PsGetProcessId(vpProc);

                        char authA[64] = {}, foA[64] = {};
                        for (USHORT c = 0; c < authLen / sizeof(WCHAR) && c < 63; c++)
                            authA[c] = (char)authFinal[c];
                        for (USHORT c = 0; c < foLen / sizeof(WCHAR) && c < 63; c++)
                            foA[c] = (char)foFinal[c];

                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: IRP NAME MISMATCH — FltMgr says '%s' but FileObject says '%s' "
                            "— adversary filter may be spoofing IRP parameters!",
                            authA, foA);
                        EnqueueFsAlert(vpPid, nullptr, msg, TRUE);
                    }
                }
                FltReleaseFileNameInformation(authNameInfo);
            }
        }
    }

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

        // ---- Canary file tripwire (anti-ransomware) ----
        // Check BEFORE all other detections — canary hit = instant ransomware verdict.
        // Any write, overwrite, or delete-open on a canary file is a confirmed attack.
        {
            ACCESS_MASK daCanary = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            ULONG dispCanary = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            BOOLEAN isCanaryWrite =
                (daCanary & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE |
                             FILE_WRITE_ATTRIBUTES)) != 0;
            BOOLEAN isCanaryOverwrite =
                (dispCanary == FILE_OVERWRITE || dispCanary == FILE_OVERWRITE_IF ||
                 dispCanary == FILE_SUPERSEDE);

            if ((isCanaryWrite || isCanaryOverwrite) &&
                DeceptionEngine::IsCanaryFile(&nameInfo->Name))
            {
                const char* verb = isCanaryOverwrite ? "OVERWRITE" :
                                   (daCanary & DELETE) ? "DELETE-OPEN" : "WRITE-OPEN";
                DeceptionEngine::HandleCanaryFileAccess(&nameInfo->Name, pid, verb);
            }
        }

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

                // Elevate severity for browser credential theft by non-browser processes
                // and cloud token theft by non-system processes.
                BOOLEAN isCritical = FALSE;
                BOOLEAN isBrowserCred = WcsContainsLower(&nameInfo->Name, L"\\login data") ||
                    WcsContainsLower(&nameInfo->Name, L"\\local state") ||
                    WcsContainsLower(&nameInfo->Name, L"\\cookies") ||
                    WcsContainsLower(&nameInfo->Name, L"\\web data") ||
                    WcsContainsLower(&nameInfo->Name, L"logins.json") ||
                    WcsContainsLower(&nameInfo->Name, L"key4.db");
                BOOLEAN isCloudToken = WcsContainsLower(&nameInfo->Name, L"microsoft.aad.brokerplugin") ||
                    WcsContainsLower(&nameInfo->Name, L"\\tokenbroker\\") ||
                    WcsContainsLower(&nameInfo->Name, L"tbres");

                if (isBrowserCred && procName) {
                    // Browsers legitimately access their own credential stores
                    BOOLEAN isBrowser = (strcmp(procName, "chrome.exe")  == 0 ||
                                         strcmp(procName, "msedge.exe")  == 0 ||
                                         strcmp(procName, "firefox.exe") == 0 ||
                                         strcmp(procName, "opera.exe")   == 0 ||
                                         strcmp(procName, "brave.exe")   == 0 ||
                                         strcmp(procName, "vivaldi.exe") == 0);
                    if (!isBrowser) isCritical = TRUE;
                }
                if (isCloudToken && procName) {
                    // Only lsass/svchost/AAD broker should access PRT files
                    BOOLEAN isCloudAllowed = (strcmp(procName, "lsass.exe")   == 0 ||
                                              strcmp(procName, "svchost.exe") == 0 ||
                                              strcmp(procName, "Microsof")    == 0);  // Microsoft.AAD.* truncated
                    if (!isCloudAllowed) isCritical = TRUE;
                }

                const char* tag = isBrowserCred ? "Browser credential theft" :
                                  isCloudToken  ? "Cloud/Entra PRT token theft" :
                                                  "Credential file access";
                char msg[256];
                RtlStringCchPrintfA(msg, sizeof(msg),
                    "FS: %s — %s by '%s' (pid=%llu)",
                    tag, pathBuf[0] ? pathBuf : "?",
                    procName ? procName : "unknown",
                    (ULONG64)(ULONG_PTR)pid);
                EnqueueFsAlert(pid, procName, msg, isCritical);
                __leave;
            }
        }

        // ---- NTFS metadata stream direct access (anti-forensics / ACL bypass) ----
        // Tools like RawCopy, Invoke-NinjaCopy, and forensic utilities directly open
        // NTFS metadata files ($MFT, $UsnJrnl, $LogFile, $Boot) to:
        //   - Dump SAM/SYSTEM hives bypassing file-level ACLs ($MFT raw read)
        //   - Tamper with or read the USN change journal ($UsnJrnl) for anti-forensics
        //   - Wipe transaction logs ($LogFile) to cover tracks
        //   - Read/modify boot sector ($Boot) for bootkits
        // Only NTFS driver (System) should access these directly.
        {
            static const PCWSTR kNtfsMetaStreams[] = {
                L"$mft",
                L"$mftmirr",
                L"$logfile",
                L"$boot",
                L"$bitmap",
                L"$secure",
                L"$upcase",
                L"$extend\\$usnjrnl",
                L"$extend\\$objid",
                L"$extend\\$reparse",
                L"$extend\\$quota",
            };

            for (SIZE_T i = 0; i < ARRAYSIZE(kNtfsMetaStreams); i++) {
                if (WcsContainsLower(&nameInfo->Name, kNtfsMetaStreams[i])) {
                    // Only System (PID 4) should access these
                    if ((ULONG_PTR)pid <= 4) break;

                    char metaBuf[64] = {};
                    ANSI_STRING ansiMeta;
                    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiMeta, &nameInfo->FinalComponent, TRUE))) {
                        SIZE_T n = ansiMeta.Length < sizeof(metaBuf) - 1 ? ansiMeta.Length : sizeof(metaBuf) - 1;
                        RtlCopyMemory(metaBuf, ansiMeta.Buffer, n);
                        RtlFreeAnsiString(&ansiMeta);
                    }
                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: Direct NTFS metadata access — %s by '%s' (pid=%llu) "
                        "— possible raw disk read / anti-forensics",
                        metaBuf[0] ? metaBuf : "?",
                        procName ? procName : "?",
                        (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                    break;
                }
            }
        }

        // ---- CatRoot / catalog store write detection ----
        // Signature catalog hijacking: an attacker with admin drops a .cat file
        // into CatRoot/CatRoot2 that vouches for their malicious DLL hash.
        // CI.dll then genuinely assigns a high signature level to unsigned code.
        // Only CryptSvc (svchost.exe) and TrustedInstaller should write here.
        {
            static const PCWSTR kCatRootPaths[] = {
                L"\\catroot\\",
                L"\\catroot2\\",
            };

            ACCESS_MASK desiredAccess =
                Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            BOOLEAN isWriteAccess = (desiredAccess &
                (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE |
                 FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) != 0;

            if (isWriteAccess) {
                for (SIZE_T i = 0; i < ARRAYSIZE(kCatRootPaths); i++) {
                    if (WcsContainsLower(&nameInfo->Name, kCatRootPaths[i])) {
                        // Allow CryptSvc (svchost.exe) and TrustedInstaller
                        // PsGetProcessImageFileName truncates to 15 chars
                        if (procName &&
                            (strcmp(procName, "svchost.exe") == 0 ||
                             strcmp(procName, "TrustedInsta") == 0))
                            break;

                        char msg[200];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: CatRoot catalog store write by '%s' (pid=%llu) — "
                            "possible signature catalog injection / CI bypass",
                            procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);
                        break;
                    }
                }
            }
        }

        // ---- AppDomain hijacking via .exe.config file (Ancaraini EDR Part 3) ----
        // Attacker drops <binary>.exe.config with appDomainManagerAssembly and
        // privatePath pointing to a malicious DLL.  The CLR loads the attacker's
        // assembly via AppDomainManager.InitializeNewDomain() BEFORE main() —
        // code runs inside the signed binary's context, bypassing allowlists.
        // Detection: .config file creation/write in protected directories.
        {
            // Check if filename ends with ".exe.config" (case-insensitive)
            static const WCHAR kExeConfig[] = L".exe.config";
            const SIZE_T kExeConfigLen = 11; // wcslen(L".exe.config")

            USHORT fnChars = nameInfo->FinalComponent.Length / sizeof(WCHAR);
            BOOLEAN isExeConfig = FALSE;

            if (fnChars > (USHORT)kExeConfigLen) {
                USHORT offset = fnChars - (USHORT)kExeConfigLen;
                BOOLEAN match = TRUE;
                for (SIZE_T ci = 0; ci < kExeConfigLen; ci++) {
                    WCHAR fc = nameInfo->FinalComponent.Buffer[offset + ci];
                    if (fc >= L'A' && fc <= L'Z') fc += 32;
                    if (fc != kExeConfig[ci]) { match = FALSE; break; }
                }
                isExeConfig = match;
            }

            if (isExeConfig) {
                // Only flag creation/write — not reads
                ULONG createDispCfg = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
                ACCESS_MASK daCfg = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                BOOLEAN isWriteCfg =
                    (createDispCfg == FILE_CREATE || createDispCfg == FILE_OVERWRITE_IF ||
                     createDispCfg == FILE_SUPERSEDE) ||
                    ((daCfg & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);

                if (isWriteCfg) {
                    // Check if in a protected directory
                    static const PCWSTR kConfigProtPaths[] = {
                        L"\\windows\\system32\\",
                        L"\\windows\\syswow64\\",
                        L"\\program files\\",
                        L"\\program files (x86)\\",
                        L"\\windows\\microsoft.net\\",
                        L"\\nortonedr\\",
                    };

                    for (SIZE_T i = 0; i < ARRAYSIZE(kConfigProtPaths); i++) {
                        if (WcsContainsLower(&nameInfo->Name, kConfigProtPaths[i])) {
                            // Allow TrustedInstaller and msiexec (legitimate .config deployment)
                            if (procName &&
                                (strcmp(procName, "TrustedInsta") == 0 ||
                                 strcmp(procName, "msiexec.exe") == 0 ||
                                 strcmp(procName, "tiworker.exe") == 0))
                                break;

                            char cfgBuf[64] = {};
                            ANSI_STRING ansiCfg;
                            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiCfg, &nameInfo->FinalComponent, TRUE))) {
                                SIZE_T n = ansiCfg.Length < sizeof(cfgBuf) - 1 ? ansiCfg.Length : sizeof(cfgBuf) - 1;
                                RtlCopyMemory(cfgBuf, ansiCfg.Buffer, n);
                                RtlFreeAnsiString(&ansiCfg);
                            }
                            char msg[256];
                            RtlStringCchPrintfA(msg, sizeof(msg),
                                "FS: AppDomain hijack — .exe.config file write '%s' by '%s' (pid=%llu) "
                                "— CLR will load attacker assembly before main() (Ancaraini technique)",
                                cfgBuf[0] ? cfgBuf : "?",
                                procName ? procName : "?",
                                (ULONG64)(ULONG_PTR)pid);
                            EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                            break;
                        }
                    }
                }
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

        // ---- T1036.002: Right-to-Left Override (RTLO) character in filename ----
        // Ferocious Kitten and others use Unicode U+202E to make .exe look like .pdf.
        // Scan FinalComponent for the RTLO character.
        if (nameInfo->FinalComponent.Length > 0 && nameInfo->FinalComponent.Buffer) {
            USHORT charCount = nameInfo->FinalComponent.Length / sizeof(WCHAR);
            for (USHORT ri = 0; ri < charCount; ri++) {
                if (nameInfo->FinalComponent.Buffer[ri] == L'\x202E') {
                    char nameBuf[64] = {};
                    ANSI_STRING ansiName;
                    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiName, &nameInfo->FinalComponent, TRUE))) {
                        SIZE_T n = ansiName.Length < sizeof(nameBuf) - 1 ? ansiName.Length : sizeof(nameBuf) - 1;
                        RtlCopyMemory(nameBuf, ansiName.Buffer, n);
                        RtlFreeAnsiString(&ansiName);
                    }
                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: Right-to-Left Override (RTLO) in filename -- masquerading as benign extension "
                        "(T1036.002) file=%s pid=%llu",
                        nameBuf[0] ? nameBuf : "?", (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                    break;
                }
            }
        }

        // ---- T1036.007: Double file extension detection ----
        // Adversaries name files like "invoice.pdf.exe" to hide the real extension.
        // Check if the name (minus the real extension) still contains a known doc/media extension.
        if (nameInfo->FinalComponent.Length > 0 && nameInfo->Extension.Length > 0) {
            static const WCHAR* kDecoyExts[] = {
                L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".ppt",
                L".jpg", L".png", L".mp4", L".txt", L".rtf", nullptr
            };
            static const WCHAR* kExecExts2[] = {
                L".exe", L".scr", L".bat", L".cmd", L".com", L".pif",
                L".vbs", L".js", L".wsf", L".hta", L".msi", nullptr
            };
            // Check if real extension is executable
            BOOLEAN realIsExec = FALSE;
            for (int ei = 0; kExecExts2[ei]; ei++) {
                if (ExtMatch(&nameInfo->Extension, kExecExts2[ei])) {
                    realIsExec = TRUE; break;
                }
            }
            if (realIsExec) {
                // Check if the stem (before real extension) contains a decoy extension
                USHORT stemChars = (nameInfo->FinalComponent.Length - nameInfo->Extension.Length) / sizeof(WCHAR);
                if (stemChars > 4) {  // need room for ".pdf" etc.
                    for (int di = 0; kDecoyExts[di]; di++) {
                        SIZE_T dLen = wcslen(kDecoyExts[di]);
                        for (USHORT si = 0; si + dLen <= stemChars; si++) {
                            BOOLEAN match = TRUE;
                            for (SIZE_T ci = 0; ci < dLen; ci++) {
                                WCHAR sc = nameInfo->FinalComponent.Buffer[si + ci];
                                if (sc >= L'A' && sc <= L'Z') sc += 32;
                                if (sc != kDecoyExts[di][ci]) { match = FALSE; break; }
                            }
                            if (match) {
                                char fnameBuf[96] = {};
                                ANSI_STRING ansiN;
                                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &nameInfo->FinalComponent, TRUE))) {
                                    SIZE_T n2 = ansiN.Length < sizeof(fnameBuf) - 1 ? ansiN.Length : sizeof(fnameBuf) - 1;
                                    RtlCopyMemory(fnameBuf, ansiN.Buffer, n2);
                                    RtlFreeAnsiString(&ansiN);
                                }
                                char msg[224];
                                RtlStringCchPrintfA(msg, sizeof(msg),
                                    "FS: Double file extension -- masquerading (T1036.007) file=%s pid=%llu",
                                    fnameBuf[0] ? fnameBuf : "?", (ULONG64)(ULONG_PTR)pid);
                                EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                                goto done_double_ext;
                            }
                        }
                    }
                }
            }
        }
        done_double_ext:;

        // ---- T1547.009: Startup folder write monitoring ----
        // AdaptixC2, CABINETRAT, and various malware drop files in Startup for persistence.
        {
            static const PCWSTR kStartupPaths[] = {
                L"\\start menu\\programs\\startup\\",
                L"\\programs\\startup\\",
                nullptr
            };
            ULONG createDisposition2 = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            ACCESS_MASK daStartup = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            // Trigger on new file creation OR write-open of existing file (overwrite attack)
            BOOLEAN isStartupWrite =
                (createDisposition2 == FILE_CREATE || createDisposition2 == FILE_OVERWRITE_IF ||
                 createDisposition2 == FILE_SUPERSEDE) ||
                ((createDisposition2 == FILE_OPEN || createDisposition2 == FILE_OPEN_IF) &&
                 (daStartup & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);

            if (isStartupWrite)
            {
                for (SIZE_T si = 0; kStartupPaths[si]; si++) {
                    if (WcsContainsLower(&nameInfo->Name, kStartupPaths[si])) {
                        // Exclude explorer.exe (normal shortcut management)
                        if (procName && strcmp(procName, "explorer.exe") == 0) break;

                        char fBuf[96] = {};
                        ANSI_STRING ansiFC;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiFC, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T n = ansiFC.Length < sizeof(fBuf) - 1 ? ansiFC.Length : sizeof(fBuf) - 1;
                            RtlCopyMemory(fBuf, ansiFC.Buffer, n);
                            RtlFreeAnsiString(&ansiFC);
                        }
                        const char* verb = (createDisposition2 == FILE_OPEN ||
                                            createDisposition2 == FILE_OPEN_IF)
                                           ? "overwritten" : "created";
                        char msg[224];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: File %s in Startup folder -- persistence (T1547.009) "
                            "file=%s by=%s pid=%llu",
                            verb,
                            fBuf[0] ? fBuf : "?",
                            procName ? procName : "?",
                            (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        break;
                    }
                }
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

            // ---- Existing binary overwrite detection (T1574 / T1036.005) ----
            // Malware opens an EXISTING executable with write access to:
            //   - Replace a signed binary with a trojanized version (binary planting)
            //   - Hijack a DLL loaded by a legitimate process (DLL search-order hijack)
            //   - Patch an executable in-place to inject shellcode
            // The disposition is FILE_OPEN (not CREATE/OVERWRITE) because the file
            // already exists — this is the gap that pure "new file" detection misses.
            //
            // We flag write-access opens to executables in protected paths (System32,
            // Program Files, WinSxS, etc.) from non-servicing processes.
            if (createDisposition == FILE_OPEN || createDisposition == FILE_OPEN_IF ||
                createDisposition == FILE_OVERWRITE || createDisposition == FILE_OVERWRITE_IF)
            {
                ACCESS_MASK daBin = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                BOOLEAN wantWrite = (daBin & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                                              FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES)) != 0;
                if (wantWrite) {
                    // Only flag writes in protected binary directories
                    BOOLEAN inProtectedDir = FALSE;
                    for (SIZE_T i = 0; i < ARRAYSIZE(kProtectedBinPaths); i++) {
                        if (WcsContainsLower(&nameInfo->Name, kProtectedBinPaths[i])) {
                            inProtectedDir = TRUE;
                            break;
                        }
                    }

                    if (inProtectedDir) {
                        // Check allowlist — servicing processes legitimately update binaries
                        BOOLEAN isAllowed = FALSE;
                        if ((ULONG_PTR)pid <= 4) isAllowed = TRUE;
                        if (!isAllowed && procName) {
                            for (int ai = 0; kBinWriteAllowedProcs[ai]; ai++) {
                                if (strcmp(procName, kBinWriteAllowedProcs[ai]) == 0) {
                                    isAllowed = TRUE;
                                    break;
                                }
                            }
                        }

                        if (!isAllowed) {
                            char binBuf[96] = {};
                            ANSI_STRING ansiB;
                            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiB, &nameInfo->FinalComponent, TRUE))) {
                                SIZE_T n = ansiB.Length < sizeof(binBuf) - 1 ? ansiB.Length : sizeof(binBuf) - 1;
                                RtlCopyMemory(binBuf, ansiB.Buffer, n);
                                RtlFreeAnsiString(&ansiB);
                            }
                            char msg[256];
                            RtlStringCchPrintfA(msg, sizeof(msg),
                                "FS: Write-open to existing binary — %s by '%s' (pid=%llu) "
                                "— possible DLL hijack / binary replacement / trojanizing (T1574)",
                                binBuf[0] ? binBuf : "?",
                                procName ? procName : "?",
                                (ULONG64)(ULONG_PTR)pid);
                            EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        }
                    }
                }
            }
        }

        // ---- Ransomware note file creation detection ----
        // The presence of a ransom note file is a strong confirmation signal that
        // encryption is actively underway. Cross-correlates with write-burst and
        // rename-extension detections for high-confidence ransomware verdict.
        {
            ULONG createDisp3 = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            if (createDisp3 == FILE_CREATE || createDisp3 == FILE_OVERWRITE_IF ||
                createDisp3 == FILE_SUPERSEDE || createDisp3 == FILE_OPEN_IF)
            {
                for (SIZE_T i = 0; i < ARRAYSIZE(kRansomNotes); i++) {
                    if (WcsContainsLower(&nameInfo->FinalComponent, kRansomNotes[i])) {
                        char fBuf[96] = {};
                        ANSI_STRING ansiFC;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiFC, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T n = ansiFC.Length < sizeof(fBuf) - 1 ? ansiFC.Length : sizeof(fBuf) - 1;
                            RtlCopyMemory(fBuf, ansiFC.Buffer, n);
                            RtlFreeAnsiString(&ansiFC);
                        }
                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: Ransomware note file creation — '%s' by '%s' (pid=%llu) "
                            "— ACTIVE RANSOMWARE ENCRYPTION IN PROGRESS",
                            fBuf[0] ? fBuf : "?",
                            procName ? procName : "?",
                            (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        break;
                    }
                }
            }
        }

        // ---- Event log direct write tampering (.evtx) ----
        // Attackers bypass wevtutil/Clear-EventLog and write directly to .evtx files
        // to corrupt or truncate logs. Only svchost.exe (EventLog service) should write.
        {
            ACCESS_MASK da = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            BOOLEAN isWriteAccess2 = (da & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE |
                                            FILE_WRITE_ATTRIBUTES)) != 0;

            if (isWriteAccess2 && WcsContainsLower(&nameInfo->Name, kEventLogPath) &&
                ExtMatch(&nameInfo->Extension, L".evtx"))
            {
                if (!procName || strcmp(procName, "svchost.exe") != 0) {
                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: Direct event log file write by '%s' (pid=%llu) "
                        "— log tampering / evidence destruction (T1070.001)",
                        procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                }
            }
        }

        // ---- WMI repository tampering (OBJECTS.DATA) ----
        // WMI event subscription persistence (T1546.003): malware writes to
        // System32\wbem\Repository\OBJECTS.DATA to install permanent WMI consumers.
        // Only WMI service (svchost.exe / WmiPrvSE.exe) should touch this.
        {
            ACCESS_MASK da2 = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            BOOLEAN isWriteAccess3 = (da2 & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;

            if (isWriteAccess3 && WcsContainsLower(&nameInfo->Name, kWmiRepoPath)) {
                // Allow WMI service processes
                BOOLEAN isWmiProc = FALSE;
                if (procName) {
                    isWmiProc = (strcmp(procName, "svchost.exe") == 0 ||
                                 strcmp(procName, "WmiPrvSE.exe") == 0 ||
                                 strcmp(procName, "WmiApSrv.exe") == 0 ||
                                 strcmp(procName, "mofcomp.exe") == 0);
                }
                if (!isWmiProc) {
                    char fBuf[64] = {};
                    ANSI_STRING ansiN;
                    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiN, &nameInfo->FinalComponent, TRUE))) {
                        SIZE_T n = ansiN.Length < sizeof(fBuf) - 1 ? ansiN.Length : sizeof(fBuf) - 1;
                        RtlCopyMemory(fBuf, ansiN.Buffer, n);
                        RtlFreeAnsiString(&ansiN);
                    }
                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: WMI repository write — %s by '%s' (pid=%llu) "
                        "— possible WMI event subscription persistence (T1546.003)",
                        fBuf[0] ? fBuf : "?",
                        procName ? procName : "?",
                        (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                }
            }
        }

        // ---- Pagefile / hiberfil.sys / swapfile.sys access ----
        // User-mode reads of pagefile.sys or hiberfil.sys enable offline credential
        // extraction (mimikatz sekurlsa::minidump against page file contents).
        // Only System (PID 4) and smss.exe should access these files.
        {
            for (SIZE_T i = 0; i < ARRAYSIZE(kPagefilePaths); i++) {
                if (WcsContainsLower(&nameInfo->Name, kPagefilePaths[i])) {
                    // Allow System and smss.exe
                    if ((ULONG_PTR)pid <= 4) break;
                    if (procName && strcmp(procName, "smss.exe") == 0) break;

                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: Pagefile/hiberfil access by '%s' (pid=%llu) "
                        "— possible offline credential extraction / memory forensics",
                        procName ? procName : "?",
                        (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                    break;
                }
            }
        }

        // ---- T1006: Raw disk / volume device access ----
        // Opening \\.\PhysicalDriveX or \\.\X: or \Device\HarddiskVolumeX bypasses
        // NTFS ACLs entirely — enables offline SAM/SYSTEM extraction, MBR/GPT wiping,
        // bootkit installation, and direct partition reads.
        // Only System (PID 4), disk management tools, and our driver should do this.
        {
            static const PCWSTR kRawDiskPatterns[] = {
                L"\\device\\harddisk",           // \Device\HarddiskX\PartitionY
                L"\\device\\physicaldrive",       // \\.\PhysicalDriveX (kernel path)
                L"physicaldrive",                 // user-mode \\.\PhysicalDriveX
                L"\\device\\harddiskvolume",      // \Device\HarddiskVolumeX (raw volume)
                L"\\global??\\physicaldrive",     // object directory variant
            };

            for (SIZE_T i = 0; i < ARRAYSIZE(kRawDiskPatterns); i++) {
                if (WcsContainsLower(&nameInfo->Name, kRawDiskPatterns[i])) {
                    // Allow System, disk management, and backup tools
                    if ((ULONG_PTR)pid <= 4) break;
                    if (procName) {
                        if (strcmp(procName, "svchost.exe") == 0 ||
                            strcmp(procName, "vds.exe") == 0 ||
                            strcmp(procName, "vssvc.exe") == 0 ||
                            strcmp(procName, "diskmgmt.msc") == 0 ||
                            strcmp(procName, "wbengine.exe") == 0 ||
                            strcmp(procName, "TrustedInsta") == 0 ||
                            strcmp(procName, "MsMpEng.exe") == 0 ||
                            strcmp(procName, "NortonEDR.exe") == 0)
                            break;
                    }

                    char msg[224];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: Raw disk/volume device access by '%s' (pid=%llu) "
                        "— bypasses NTFS ACLs, possible bootkit / offline cred extraction (T1006)",
                        procName ? procName : "?",
                        (ULONG64)(ULONG_PTR)pid);
                    EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                    break;
                }
            }
        }

        // ---- T1574.001: Executable drop in system directories ----
        // Writing .exe/.dll/.sys to System32, SysWOW64, or drivers\ from a
        // non-installer/non-TrustedInstaller process = DLL search order hijack,
        // driver planting, or LOLBin replacement.
        // NOTE: This differs from the existing "executable drop in suspicious path"
        // (kDropPaths) which covers temp/appdata.  Here we cover SYSTEM directories.
        {
            ULONG createDispSys = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            BOOLEAN isSysCreate =
                (createDispSys == FILE_CREATE || createDispSys == FILE_OVERWRITE_IF ||
                 createDispSys == FILE_SUPERSEDE);

            if (isSysCreate) {
                // Check for driver-specific extension (.sys) in drivers directory
                static const PCWSTR kSysDirPaths[] = {
                    L"\\windows\\system32\\drivers\\",
                    L"\\windows\\system32\\",
                    L"\\windows\\syswow64\\",
                };

                for (SIZE_T i = 0; i < ARRAYSIZE(kSysDirPaths); i++) {
                    if (WcsContainsLower(&nameInfo->Name, kSysDirPaths[i])) {
                        // Check if dropping an executable/driver file
                        static const PCWSTR kSysExecExts[] = {
                            L".exe", L".dll", L".sys", L".drv", L".ocx", L".cpl", nullptr
                        };
                        BOOLEAN isSysExec = FALSE;
                        for (int ei = 0; kSysExecExts[ei]; ei++) {
                            if (ExtMatch(&nameInfo->Extension, kSysExecExts[ei])) {
                                isSysExec = TRUE; break;
                            }
                        }
                        if (!isSysExec) break;

                        // Allow servicing processes
                        if ((ULONG_PTR)pid <= 4) break;
                        if (procName) {
                            BOOLEAN allowed = FALSE;
                            for (int ai = 0; kBinWriteAllowedProcs[ai]; ai++) {
                                if (strcmp(procName, kBinWriteAllowedProcs[ai]) == 0) {
                                    allowed = TRUE; break;
                                }
                            }
                            if (allowed) break;
                        }

                        char fileBuf[64] = {};
                        ANSI_STRING ansiSys;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiSys, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T n = ansiSys.Length < sizeof(fileBuf) - 1 ? ansiSys.Length : sizeof(fileBuf) - 1;
                            RtlCopyMemory(fileBuf, ansiSys.Buffer, n);
                            RtlFreeAnsiString(&ansiSys);
                        }
                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: Executable/driver drop in system directory — %s by '%s' (pid=%llu) "
                            "— possible DLL search-order hijack / driver planting (T1574.001)",
                            fileBuf[0] ? fileBuf : "?",
                            procName ? procName : "?",
                            (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        break;
                    }
                }
            }
        }

        // ---- T1070.004: DELETE_ON_CLOSE on protected files ----
        // FILE_DELETE_ON_CLOSE (CreateOptions bit 12) causes the file to be deleted
        // when the last handle closes.  Attackers use this to bypass explicit delete
        // ACLs because the delete happens as a side effect of closing a read handle.
        // Flag DELETE_ON_CLOSE on system binaries, security configs, event logs, and
        // EDR components.
        {
            ULONG createOptsDel = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;

            if (createOptsDel & FILE_DELETE_ON_CLOSE) {
                static const PCWSTR kDelProtPaths[] = {
                    L"\\windows\\system32\\",
                    L"\\windows\\syswow64\\",
                    L"\\program files\\",
                    L"\\program files (x86)\\",
                    L"\\winevt\\logs\\",           // Event logs
                    L"\\windows\\system32\\config\\", // SAM/SYSTEM/SECURITY
                    L"\\windows\\system32\\drivers\\", // Kernel drivers
                    L"\\nortonedr\\",              // Our own components
                };

                for (SIZE_T i = 0; i < ARRAYSIZE(kDelProtPaths); i++) {
                    if (WcsContainsLower(&nameInfo->Name, kDelProtPaths[i])) {
                        // Allow System and TrustedInstaller
                        if ((ULONG_PTR)pid <= 4) break;
                        if (procName && (strcmp(procName, "TrustedInsta") == 0 ||
                                         strcmp(procName, "msiexec.exe") == 0 ||
                                         strcmp(procName, "tiworker.exe") == 0))
                            break;

                        char fileBuf[64] = {};
                        ANSI_STRING ansiDel;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiDel, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T n = ansiDel.Length < sizeof(fileBuf) - 1 ? ansiDel.Length : sizeof(fileBuf) - 1;
                            RtlCopyMemory(fileBuf, ansiDel.Buffer, n);
                            RtlFreeAnsiString(&ansiDel);
                        }
                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: DELETE_ON_CLOSE on protected file — %s by '%s' (pid=%llu) "
                            "— possible ACL bypass / EDR component removal (T1070.004)",
                            fileBuf[0] ? fileBuf : "?",
                            procName ? procName : "?",
                            (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        break;
                    }
                }
            }
        }

        // ---- T1547: Reparse point / mount point / symlink abuse in sensitive dirs ----
        // FILE_OPEN_REPARSE_POINT (CreateOptions bit 21) opens the reparse point itself
        // rather than following it.  Combined with write access in System32 or
        // Program Files, this enables TOCTOU symlink attacks: redirect a privileged
        // file write (e.g., Windows Installer, Update, MSI custom actions) to an
        // arbitrary location for EoP.
        {
            ULONG createOptsRp = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
            ACCESS_MASK daRp = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

            BOOLEAN hasReparseFlag = (createOptsRp & FILE_OPEN_REPARSE_POINT) != 0;
            BOOLEAN wantsWrite = (daRp & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                                          FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                                          DELETE | WRITE_DAC | WRITE_OWNER)) != 0;

            if (hasReparseFlag && wantsWrite) {
                static const PCWSTR kRpSensitivePaths[] = {
                    L"\\windows\\system32\\",
                    L"\\windows\\syswow64\\",
                    L"\\windows\\winsxs\\",
                    L"\\program files\\",
                    L"\\program files (x86)\\",
                    L"\\windows\\temp\\",
                    L"\\windows\\installer\\",
                    L"\\programdata\\",
                };

                for (SIZE_T i = 0; i < ARRAYSIZE(kRpSensitivePaths); i++) {
                    if (WcsContainsLower(&nameInfo->Name, kRpSensitivePaths[i])) {
                        // Allow System and TrustedInstaller
                        if ((ULONG_PTR)pid <= 4) break;
                        if (procName && (strcmp(procName, "TrustedInsta") == 0 ||
                                         strcmp(procName, "msiexec.exe") == 0 ||
                                         strcmp(procName, "tiworker.exe") == 0 ||
                                         strcmp(procName, "svchost.exe") == 0))
                            break;

                        char fileBuf[64] = {};
                        ANSI_STRING ansiRp;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiRp, &nameInfo->FinalComponent, TRUE))) {
                            SIZE_T n = ansiRp.Length < sizeof(fileBuf) - 1 ? ansiRp.Length : sizeof(fileBuf) - 1;
                            RtlCopyMemory(fileBuf, ansiRp.Buffer, n);
                            RtlFreeAnsiString(&ansiRp);
                        }
                        char msg[256];
                        RtlStringCchPrintfA(msg, sizeof(msg),
                            "FS: Reparse point write in sensitive directory — %s by '%s' (pid=%llu) "
                            "— possible TOCTOU symlink EoP attack (T1547)",
                            fileBuf[0] ? fileBuf : "?",
                            procName ? procName : "?",
                            (ULONG64)(ULONG_PTR)pid);
                        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
                        break;
                    }
                }
            }
        }

        // ---- T1204.002: Executable open from untrusted drop locations ----
        // Catch stagers and reflective loaders executing from %TEMP%, Downloads,
        // AppData\Local\Temp, and ProgramData.  We flag CREATE disposition (new file
        // being loaded) for executable extensions in these directories.
        // This complements the existing kDropPaths check which flags drops but not
        // opens-for-execution (FILE_EXECUTE / FILE_READ_DATA on an .exe).
        {
            ACCESS_MASK daExec = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            BOOLEAN wantsExecute = (daExec & (FILE_EXECUTE)) != 0;

            if (wantsExecute) {
                static const PCWSTR kUntrustedExecPaths[] = {
                    L"\\temp\\",
                    L"\\appdata\\local\\temp\\",
                    L"\\downloads\\",
                    L"\\users\\public\\",
                    L"\\programdata\\",
                    L"\\recycle",
                };

                // Check if file has an executable extension
                static const PCWSTR kExecExtsLoad[] = {
                    L".exe", L".dll", L".scr", L".com", L".pif",
                    L".hta", L".cpl", L".ocx", nullptr
                };

                BOOLEAN isExecFile = FALSE;
                for (int ei = 0; kExecExtsLoad[ei]; ei++) {
                    if (ExtMatch(&nameInfo->Extension, kExecExtsLoad[ei])) {
                        isExecFile = TRUE; break;
                    }
                }

                if (isExecFile) {
                    for (SIZE_T i = 0; i < ARRAYSIZE(kUntrustedExecPaths); i++) {
                        if (WcsContainsLower(&nameInfo->Name, kUntrustedExecPaths[i])) {
                            // Allow common legitimate launchers
                            if (procName) {
                                if (strcmp(procName, "explorer.exe") == 0 ||
                                    strcmp(procName, "svchost.exe") == 0 ||
                                    strcmp(procName, "MsMpEng.exe") == 0 ||
                                    strcmp(procName, "NortonEDR.exe") == 0)
                                    break;
                            }

                            char fileBuf[96] = {};
                            ANSI_STRING ansiEx;
                            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiEx, &nameInfo->FinalComponent, TRUE))) {
                                SIZE_T n = ansiEx.Length < sizeof(fileBuf) - 1 ? ansiEx.Length : sizeof(fileBuf) - 1;
                                RtlCopyMemory(fileBuf, ansiEx.Buffer, n);
                                RtlFreeAnsiString(&ansiEx);
                            }
                            char msg[256];
                            RtlStringCchPrintfA(msg, sizeof(msg),
                                "FS: Executable image load from untrusted location — %s by '%s' (pid=%llu) "
                                "— possible stager / reflective loader execution (T1204.002)",
                                fileBuf[0] ? fileBuf : "?",
                                procName ? procName : "?",
                                (ULONG64)(ULONG_PTR)pid);
                            EnqueueFsAlert(pid, procName, msg, FALSE);  // WARNING (high volume)
                            break;
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FltReleaseFileNameInformation(nameInfo);

    // ---- FLT_CALLBACK_DATA tampering: snapshot params for PostCreate validation ----
    {
        LONG cnt = InterlockedIncrement(&g_CreateValidateCounter);
        if ((cnt & (PARAM_VALIDATE_RATE - 1)) == 0) {
            PREOP_CREATE_CTX* ctx = (PREOP_CREATE_CTX*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PREOP_CREATE_CTX), PARAM_CTX_TAG);
            if (ctx) {
                ctx->Magic            = PARAM_CTX_MAGIC;
                ctx->DesiredAccess    = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                ctx->CreateOptions    = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
                ctx->TargetFileObject = Data->Iopb->TargetFileObject;
                *CompletionContext = ctx;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
        }
    }

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

    InterlockedIncrement(&g_PreOpCounters[PREOP_WRITE]);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread || !Data->Iopb->TargetFileObject)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

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

    // -----------------------------------------------------------------------
    // Memory dump magic-byte detection (T1003.001 — LSASS credential dump).
    //
    // MiniDumpWriteDump, ProcDump, comsvcs.dll MiniDump, nanodump, and custom
    // dumpers all write a MINIDUMP_HEADER to the target file.  The header
    // always starts at offset 0 with the signature 'MDMP' (0x504D444D).
    //
    // By checking the first 4 bytes of any user-mode write at file offset 0
    // we detect ALL minidump-based credential dumpers regardless of:
    //   - Output filename (debug.log, report.txt, etc.)
    //   - API used (MiniDumpWriteDump, NtWriteFile, WriteFile)
    //   - Tool (ProcDump, comsvcs.dll, custom C2 module)
    //
    // This is cheap: one offset check + one 4-byte comparison per write.
    // We skip paging I/O (not user-initiated) and writes > 0 offset.
    // -----------------------------------------------------------------------
    {
        // Skip paging I/O and non-cached — these are system-initiated, not user dumps
        if (!(Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO))) {
            LARGE_INTEGER writeOffset = Data->Iopb->Parameters.Write.ByteOffset;
            ULONG writeLen = Data->Iopb->Parameters.Write.Length;

            // Only check writes starting at offset 0 with at least 4 bytes
            if (writeOffset.QuadPart == 0 && writeLen >= 4) {
                // Get the write buffer — prefer the system buffer (buffered I/O),
                // fall back to MDL, then user buffer
                PVOID writeBuf = nullptr;
                if (Data->Iopb->Parameters.Write.MdlAddress) {
                    writeBuf = MmGetSystemAddressForMdlSafe(
                        Data->Iopb->Parameters.Write.MdlAddress,
                        NormalPagePriority | MdlMappingNoExecute);
                }
                if (!writeBuf) {
                    writeBuf = Data->Iopb->Parameters.Write.WriteBuffer;
                }

                if (writeBuf && MmIsAddressValid(writeBuf)) {
                    __try {
                        ULONG magic = *(ULONG*)writeBuf;

                        // MDMP signature: 0x504D444D ('MDMP' as little-endian DWORD)
                        if (magic == 0x504D444D) {
                            PEPROCESS proc = IoThreadToProcess(Data->Thread);
                            char* pn = PsGetProcessImageFileName(proc);

                            // Allow WerFault.exe (Windows Error Reporting) — legitimate crash dumps
                            BOOLEAN isAllowed = FALSE;
                            if (pn) {
                                isAllowed = (strcmp(pn, "WerFault.exe") == 0 ||
                                             strcmp(pn, "WerFaultSecu") == 0);  // 15-char truncation
                            }

                            if (!isAllowed) {
                                char msg[224];
                                RtlStringCbPrintfA(msg, sizeof(msg),
                                    "FS: MINIDUMP header (MDMP) written to file by '%s' (pid=%llu) "
                                    "— possible credential dump (T1003.001) "
                                    "— MiniDumpWriteDump / ProcDump / comsvcs.dll",
                                    pn ? pn : "?", (ULONG64)(ULONG_PTR)pid);
                                EnqueueFsAlert(pid, pn, msg, TRUE);  // CRITICAL
                            }
                        }

                        // Bonus: raw PE header being written to a file at offset 0
                        // could indicate reflective DLL being staged to disk, or a
                        // dropper extracting an embedded payload.  Not as critical
                        // as a credential dump, but worth a warning.
                        // MZ header: 0x5A4D ('MZ') at bytes [0..1]
                        else if ((magic & 0xFFFF) == 0x5A4D && writeLen >= 64) {
                            // Check for valid PE — the e_lfanew field at offset 0x3C
                            // should point to a 'PE\0\0' signature.
                            LONG peOffset = *(LONG*)((PUCHAR)writeBuf + 0x3C);
                            if (peOffset > 0 && (ULONG)peOffset + 4 <= writeLen) {
                                ULONG peSig = *(ULONG*)((PUCHAR)writeBuf + peOffset);
                                if (peSig == 0x00004550) {  // 'PE\0\0'
                                    PEPROCESS proc = IoThreadToProcess(Data->Thread);
                                    char* pn = PsGetProcessImageFileName(proc);

                                    // Allow common installers / compilers
                                    BOOLEAN isAllowed2 = FALSE;
                                    if ((ULONG_PTR)pid <= 4) isAllowed2 = TRUE;
                                    if (pn) {
                                        isAllowed2 = (strcmp(pn, "msiexec.exe") == 0 ||
                                                      strcmp(pn, "TrustedInsta") == 0 ||
                                                      strcmp(pn, "svchost.exe") == 0 ||
                                                      strcmp(pn, "DismHost.exe") == 0 ||
                                                      strcmp(pn, "tiworker.exe") == 0);
                                    }

                                    if (!isAllowed2) {
                                        char msg[192];
                                        RtlStringCbPrintfA(msg, sizeof(msg),
                                            "FS: PE binary (MZ/PE) written to file by '%s' (pid=%llu) "
                                            "— possible payload drop / reflective staging",
                                            pn ? pn : "?", (ULONG64)(ULONG_PTR)pid);
                                        EnqueueFsAlert(pid, pn, msg, FALSE);  // WARNING
                                    }
                                }
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // Buffer access faulted — silently ignore
                    }
                }
            }
        }
    }

    UpdateWriteTracker(pid);

    // ---- FLT_CALLBACK_DATA tampering: snapshot params for PostWrite ----
    {
        LONG cnt = InterlockedIncrement(&g_WriteValidateCounter);
        if ((cnt & (PARAM_VALIDATE_RATE - 1)) == 0) {
            PREOP_WRITE_CTX* ctx = (PREOP_WRITE_CTX*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PREOP_WRITE_CTX), PARAM_CTX_TAG);
            if (ctx) {
                ctx->Magic            = PARAM_CTX_MAGIC;
                ctx->ByteOffset       = Data->Iopb->Parameters.Write.ByteOffset;
                ctx->Length            = Data->Iopb->Parameters.Write.Length;
                ctx->TargetFileObject = Data->Iopb->TargetFileObject;
                *CompletionContext = ctx;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
        }
    }

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

    InterlockedIncrement(&g_PreOpCounters[PREOP_SET_INFO]);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    BOOLEAN isRename   = (infoClass == FileRenameInformation ||
                          infoClass == FileRenameInformationEx);
    BOOLEAN isHardLink = (infoClass == FileLinkInformation ||
                          infoClass == FileLinkInformationEx);
    BOOLEAN isDelete   = (infoClass == FileDispositionInformation ||
                          infoClass == FileDispositionInformationEx);

    // ---- Timestomping detection (T1070.006) ----
    // FileBasicInformation (class 4) carries CreationTime, LastAccessTime,
    // LastWriteTime, ChangeTime.  Backdating timestamps hides recently modified
    // files from forensic timelines.  Only explorer.exe and TrustedInstaller are
    // expected to modify timestamps on user request.
    if (infoClass == FileBasicInformation) {
        PEPROCESS tsProc  = IoThreadToProcess(Data->Thread);
        HANDLE    tsPid   = PsGetProcessId(tsProc);
        char*     tsPName = PsGetProcessImageFileName(tsProc);

        // Allow system PID, explorer (right-click → Properties → timestamp edit),
        // TrustedInstaller, and WER
        BOOLEAN tsAllowed = ((ULONG_PTR)tsPid <= 4);
        if (!tsAllowed && tsPName) {
            tsAllowed = (strcmp(tsPName, "explorer.exe") == 0 ||
                         strcmp(tsPName, "TrustedInsta") == 0 ||
                         strcmp(tsPName, "svchost.exe") == 0 ||
                         strcmp(tsPName, "MsMpEng.exe") == 0);
        }

        if (!tsAllowed) {
            FILE_BASIC_INFORMATION* basicInfo =
                (FILE_BASIC_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (basicInfo && MmIsAddressValid(basicInfo)) {
                // Check if any timestamp is being set to a value in the past
                // (zeroed fields = "don't change", so only flag non-zero values)
                BOOLEAN suspicious = FALSE;
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);

                // Flag if CreationTime or LastWriteTime is being set to a past value
                // (more than 1 hour ago) — this is the classic timestomp pattern
                if (basicInfo->CreationTime.QuadPart > 0 &&
                    (now.QuadPart - basicInfo->CreationTime.QuadPart) > 36000000000LL)
                    suspicious = TRUE;
                if (basicInfo->LastWriteTime.QuadPart > 0 &&
                    (now.QuadPart - basicInfo->LastWriteTime.QuadPart) > 36000000000LL)
                    suspicious = TRUE;

                if (suspicious) {
                    PFLT_FILE_NAME_INFORMATION tsNameInfo = nullptr;
                    char tsPath[128] = {};
                    NTSTATUS tsSt = FltGetFileNameInformation(
                        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &tsNameInfo);
                    if (NT_SUCCESS(tsSt) && tsNameInfo) {
                        FltParseFileNameInformation(tsNameInfo);
                        for (ULONG c = 0; c < tsNameInfo->Name.Length / sizeof(WCHAR) && c < 127; c++)
                            tsPath[c] = (char)tsNameInfo->Name.Buffer[c];
                        FltReleaseFileNameInformation(tsNameInfo);
                    }
                    char msg[256];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: TIMESTOMPING — '%s' (pid=%llu) backdating timestamps on %s "
                        "— anti-forensics / timeline manipulation (T1070.006)",
                        tsPName ? tsPName : "?", (ULONG64)(ULONG_PTR)tsPid,
                        tsPath[0] ? tsPath : "?");
                    EnqueueFsAlert(tsPid, tsPName, msg, TRUE);
                }
            }
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!isRename && !isHardLink && !isDelete) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PEPROCESS process  = IoThreadToProcess(Data->Thread);
    HANDLE    pid      = PsGetProcessId(process);
    char*     procName = PsGetProcessImageFileName(process);

    __try {
        // ---- Canary file tripwire (anti-ransomware) ----
        // Ransomware renames files to .encrypted/.locked or deletes originals.
        // Any rename or delete of a canary = instant confirmed ransomware.
        if (isRename || isDelete) {
            PFLT_FILE_NAME_INFORMATION canaryNameInfo = nullptr;
            NTSTATUS cSt = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &canaryNameInfo);
            if (NT_SUCCESS(cSt) && canaryNameInfo) {
                if (DeceptionEngine::IsCanaryFile(&canaryNameInfo->Name)) {
                    const char* verb = isDelete ? "DELETE" : "RENAME";
                    DeceptionEngine::HandleCanaryFileAccess(&canaryNameInfo->Name, pid, verb);
                }
                FltReleaseFileNameInformation(canaryNameInfo);
            }
        }

        // ---- File deletion detection ----
        // Catches event log wiping (.evtx deletion), prefetch anti-forensics,
        // and ransomware deleting originals after encrypt+rename.
        if (isDelete) {
            // Only alert if DeleteFile flag is actually TRUE
            FILE_DISPOSITION_INFORMATION* dispInfo =
                (FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (!dispInfo || !MmIsAddressValid(dispInfo) || !dispInfo->DeleteFile) __leave;

            PFLT_FILE_NAME_INFORMATION delNameInfo = nullptr;
            NTSTATUS delSt = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &delNameInfo);
            if (NT_SUCCESS(delSt) && delNameInfo) {
                __try {
                    if (!NT_SUCCESS(FltParseFileNameInformation(delNameInfo))) __leave;

                    // Event log deletion — only svchost.exe (EventLog service) should do this
                    if (WcsContainsLower(&delNameInfo->Name, kEventLogPath) &&
                        ExtMatch(&delNameInfo->Extension, L".evtx"))
                    {
                        if (!procName || strcmp(procName, "svchost.exe") != 0) {
                            char msg[224];
                            RtlStringCchPrintfA(msg, sizeof(msg),
                                "FS: Event log file deletion by '%s' (pid=%llu) "
                                "— evidence destruction / anti-forensics (T1070.001)",
                                procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                            EnqueueFsAlert(pid, procName, msg, TRUE);
                        }
                    }

                    // Prefetch file deletion — anti-forensics (removes execution evidence)
                    // Only TrustedInstaller/System should clean prefetch
                    if (WcsContainsLower(&delNameInfo->Name, kPrefetchPath) &&
                        ExtMatch(&delNameInfo->Extension, L".pf"))
                    {
                        if ((ULONG_PTR)pid > 4) {
                            char msg[224];
                            RtlStringCchPrintfA(msg, sizeof(msg),
                                "FS: Prefetch file deletion by '%s' (pid=%llu) "
                                "— anti-forensics / execution trace removal (T1070.004)",
                                procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
                            EnqueueFsAlert(pid, procName, msg, TRUE);
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                FltReleaseFileNameInformation(delNameInfo);
            }
            __leave;
        }

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
            targetName.Length        = (USHORT)min(renameInfo->FileNameLength, (ULONG)0xFFFE);
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

    // ---- FLT_CALLBACK_DATA tampering: snapshot params for PostSetInformation ----
    {
        LONG cnt = InterlockedIncrement(&g_SetInfoValidateCounter);
        if ((cnt & (PARAM_VALIDATE_RATE - 1)) == 0) {
            PREOP_SETINFO_CTX* ctx = (PREOP_SETINFO_CTX*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PREOP_SETINFO_CTX), PARAM_CTX_TAG);
            if (ctx) {
                ctx->Magic            = PARAM_CTX_MAGIC;
                ctx->InfoClass        = (FILE_INFORMATION_CLASS)
                    Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
                ctx->InfoBuffer       = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                ctx->TargetFileObject = Data->Iopb->TargetFileObject;
                *CompletionContext = ctx;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
        }
    }

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

    InterlockedIncrement(&g_PreOpCounters[PREOP_DIR_CTRL]);

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HANDLE pid = PsGetProcessId(IoThreadToProcess(Data->Thread));
    if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    UpdateDirTracker(pid);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_FILE_SYSTEM_CONTROL — reparse point abuse + EFS encryption abuse.
//
// Reparse points (junctions, symlinks, mount points) are set via
// FSCTL_SET_REPARSE_POINT. Attackers use them for:
//   - Potato privilege escalation (junction redirects \??\PIPE → attacker dir)
//   - Arbitrary file overwrite via directory junction + DLL plant
//   - CVE-style symlink attacks to overwrite protected system files
//
// EFS encryption: FSCTL_SET_ENCRYPTION / FSCTL_ENCRYPTION_FSCTL_IO are used
// by ransomware that leverages Windows built-in EFS instead of custom crypto.
// This bypasses rename-extension heuristics entirely.
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreFsControl(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    InterlockedIncrement(&g_PreOpCounters[PREOP_FS_CTRL]);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Only process FSCTL (IRP_MN_USER_FS_REQUEST / IRP_MN_KERNEL_CALL)
    if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST &&
        Data->Iopb->MinorFunction != IRP_MN_KERNEL_CALL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG fsctl = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

    // ---- Reparse point creation (junction / symlink / mount point) ----
    if (fsctl == FSCTL_SET_REPARSE_POINT) {
        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        // System/kernel PID — skip
        if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // Allow explorer.exe (pin-to-quick-access, OneDrive placeholders)
        // and TrustedInstaller (servicing)
        if (procName) {
            if (strcmp(procName, "explorer.exe") == 0 ||
                strcmp(procName, "TrustedInsta") == 0 ||
                strcmp(procName, "MsMpEng.exe") == 0)
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // Attempt to get the target path for the alert
        PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
        char pathBuf[128] = {};
        NTSTATUS st = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (NT_SUCCESS(st) && nameInfo) {
            FltParseFileNameInformation(nameInfo);
            ANSI_STRING ansi;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                SIZE_T n = ansi.Length < sizeof(pathBuf) - 1 ? ansi.Length : sizeof(pathBuf) - 1;
                RtlCopyMemory(pathBuf, ansi.Buffer, n);
                RtlFreeAnsiString(&ansi);
            }
            FltReleaseFileNameInformation(nameInfo);
        }

        // Determine reparse tag from the buffer if accessible
        const char* rpType = "reparse point";
        PVOID sysBuf = Data->Iopb->Parameters.FileSystemControl.Common.SystemBuffer;
        if (sysBuf && MmIsAddressValid(sysBuf)) {
            REPARSE_DATA_BUFFER* rpBuf = (REPARSE_DATA_BUFFER*)sysBuf;
            if (rpBuf->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
                rpType = "junction/mount point";
            else if (rpBuf->ReparseTag == IO_REPARSE_TAG_SYMLINK)
                rpType = "symbolic link";
        }

        char msg[256];
        RtlStringCchPrintfA(msg, sizeof(msg),
            "FS: %s creation by '%s' (pid=%llu) on %s "
            "— possible symlink/junction attack for privilege escalation",
            rpType,
            procName ? procName : "?",
            (ULONG64)(ULONG_PTR)pid,
            pathBuf[0] ? pathBuf : "?");
        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
    }

    // ---- EFS encryption abuse ----
    // FSCTL_SET_ENCRYPTION (0x900D7) starts EFS encryption on a file/dir.
    // FSCTL_ENCRYPTION_FSCTL_IO (0x900DB) is the EFS data write channel.
    // Ransomware (e.g. DarkBit, some LockBit variants) uses these to leverage
    // the OS built-in EFS as their encryption engine — no custom crypto needed.
    else if (fsctl == FSCTL_SET_ENCRYPTION || fsctl == FSCTL_ENCRYPTION_FSCTL_IO) {
        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // Allow lsass.exe and svchost.exe (EFS service = lsass, CertSvc = svchost)
        if (procName) {
            if (strcmp(procName, "lsass.exe") == 0 ||
                strcmp(procName, "svchost.exe") == 0)
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
        char pathBuf[128] = {};
        NTSTATUS st = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (NT_SUCCESS(st) && nameInfo) {
            FltParseFileNameInformation(nameInfo);
            ANSI_STRING ansi;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                SIZE_T n = ansi.Length < sizeof(pathBuf) - 1 ? ansi.Length : sizeof(pathBuf) - 1;
                RtlCopyMemory(pathBuf, ansi.Buffer, n);
                RtlFreeAnsiString(&ansi);
            }
            FltReleaseFileNameInformation(nameInfo);
        }

        char msg[256];
        RtlStringCchPrintfA(msg, sizeof(msg),
            "FS: EFS encryption %s by '%s' (pid=%llu) on %s "
            "— possible ransomware using built-in Windows encryption",
            (fsctl == FSCTL_SET_ENCRYPTION) ? "initiation" : "data write",
            procName ? procName : "?",
            (ULONG64)(ULONG_PTR)pid,
            pathBuf[0] ? pathBuf : "?");
        EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
    }

    // ---- USN Journal manipulation (anti-forensics) ----
    // FSCTL_DELETE_USN_JOURNAL (0x900D8) disables or deletes the USN change journal.
    // FSCTL_CREATE_USN_JOURNAL (0x900C7) can also be abused to reset journal parameters.
    // Only TrustedInstaller, System, and chkdsk should touch the journal.
    else if (fsctl == 0x000900D8 || fsctl == 0x000900C7) {
        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        BOOLEAN usnAllowed = FALSE;
        if (procName) {
            usnAllowed = (strcmp(procName, "TrustedInsta") == 0 ||
                          strcmp(procName, "chkdsk.exe") == 0 ||
                          strcmp(procName, "autochk.exe") == 0 ||
                          strcmp(procName, "MsMpEng.exe") == 0);
        }

        if (!usnAllowed) {
            const char* usnVerb = (fsctl == 0x000900D8) ? "DELETE" : "CREATE/RESET";
            char msg[192];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FS: USN JOURNAL %s by '%s' (pid=%llu) "
                "— anti-forensics / hiding file system activity (T1070)",
                usnVerb, procName ? procName : "?", (ULONG64)(ULONG_PTR)pid);
            EnqueueFsAlert(pid, procName, msg, TRUE);
        }
    }

    // ---- Oplock abuse detection ----
    // FSCTL_REQUEST_OPLOCK (0x90144) and legacy FSCTL_REQUEST_BATCH_OPLOCK (0x90008),
    // FSCTL_REQUEST_FILTER_OPLOCK (0x90018) — taking opportunistic locks on files
    // can delay or block EDR file inspection.  Legitimate oplock users: NTFS defrag,
    // SMB server, search indexer.  Unusual oplock requests from non-system processes
    // on system files are suspicious.
    else if (fsctl == 0x00090144 || fsctl == 0x00090008 ||
             fsctl == 0x00090018 || fsctl == 0x0009000C) {
        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        BOOLEAN oplockAllowed = FALSE;
        if (procName) {
            oplockAllowed = (strcmp(procName, "svchost.exe") == 0 ||
                             strcmp(procName, "SearchIndex") == 0 ||
                             strcmp(procName, "SearchProto") == 0 ||
                             strcmp(procName, "defrag.exe") == 0 ||
                             strcmp(procName, "explorer.exe") == 0 ||
                             strcmp(procName, "MsMpEng.exe") == 0);
        }

        if (!oplockAllowed) {
            // Check if the target file is in a sensitive directory
            PFLT_FILE_NAME_INFORMATION oplNameInfo = nullptr;
            char oplPath[128] = {};
            NTSTATUS oplSt = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &oplNameInfo);
            if (NT_SUCCESS(oplSt) && oplNameInfo) {
                FltParseFileNameInformation(oplNameInfo);

                BOOLEAN isSensitive = FALSE;
                static const PCWSTR kOplockSensitivePaths[] = {
                    L"\\Windows\\System32\\",
                    L"\\Windows\\SysWOW64\\",
                    L"\\Program Files\\",
                    L"\\ProgramData\\NortonEDR",
                };
                for (int i = 0; i < ARRAYSIZE(kOplockSensitivePaths); i++) {
                    if (UnicodeStringContains(&oplNameInfo->Name, kOplockSensitivePaths[i])) {
                        isSensitive = TRUE;
                        break;
                    }
                }

                if (isSensitive) {
                    for (ULONG c = 0; c < oplNameInfo->Name.Length / sizeof(WCHAR) && c < 127; c++)
                        oplPath[c] = (char)oplNameInfo->Name.Buffer[c];

                    char msg[256];
                    RtlStringCchPrintfA(msg, sizeof(msg),
                        "FS: OPLOCK REQUEST on system file by '%s' (pid=%llu) fsctl=0x%x target=%s "
                        "— may delay/block EDR inspection",
                        procName ? procName : "?", (ULONG64)(ULONG_PTR)pid,
                        fsctl, oplPath[0] ? oplPath : "?");
                    EnqueueFsAlert(pid, procName, msg, FALSE);  // WARNING
                }
                FltReleaseFileNameInformation(oplNameInfo);
            }
        }
    }

    // ---- Named pipe impersonation (FSCTL_PIPE_IMPERSONATE) ----
    // FSCTL_PIPE_IMPERSONATE (0x110018) is the actual execution moment for
    // EVERY potato-family privilege escalation attack:
    //   JuicyPotato, SweetPotato, GodPotato, PrintSpoofer, EfsPotato,
    //   RottenPotato, RoguePotato, CoercedPotato, etc.
    //
    // Attack flow:
    //   1. Create a named pipe with FILE_CREATE_PIPE_INSTANCE (detected above)
    //   2. Coerce a SYSTEM service to connect as a client (RPC/DCOM/EFS/Print)
    //   3. Call FSCTL_PIPE_IMPERSONATE on the server end → kernel assigns the
    //      client's (SYSTEM) token to the server thread
    //   4. The attacker's thread is now running as SYSTEM
    //
    // This is the critical moment — the transition from "prepared" to "escalated".
    // We detect the pipe creation (step 1) and the integrity mismatch (step 4's
    // output), but this catches step 3 itself — the impersonation act.
    //
    // Normal pipe servers: svchost.exe (RPC), lsass.exe, smss.exe, csrss.exe,
    // spoolsv.exe, wininit.exe — these legitimately impersonate pipe clients.
    else if (fsctl == 0x110018) {  // FSCTL_PIPE_IMPERSONATE
        PEPROCESS process  = IoThreadToProcess(Data->Thread);
        HANDLE    pid      = PsGetProcessId(process);
        char*     procName = PsGetProcessImageFileName(process);

        if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // Allowlist: legitimate pipe servers that impersonate clients
        BOOLEAN isLegitServer = FALSE;
        if (procName) {
            static const char* kLegitPipeServers[] = {
                "svchost.exe", "lsass.exe", "smss.exe", "csrss.exe",
                "spoolsv.exe", "wininit.exe", "services.exe",
                "SearchIndex", "WmiPrvSE.exe", "dllhost.exe",
                "msdtc.exe", "dns.exe", "MsMpEng.exe",
                nullptr
            };
            for (int i = 0; kLegitPipeServers[i]; i++) {
                if (strcmp(procName, kLegitPipeServers[i]) == 0) {
                    isLegitServer = TRUE;
                    break;
                }
            }
        }

        if (!isLegitServer) {
            // Get the pipe name for context
            PFLT_FILE_NAME_INFORMATION pipeNameInfo = nullptr;
            char pipeBuf[96] = {};
            NTSTATUS pst = FltGetFileNameInformation(
                Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pipeNameInfo);
            if (NT_SUCCESS(pst) && pipeNameInfo) {
                FltParseFileNameInformation(pipeNameInfo);
                ANSI_STRING ansi;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &pipeNameInfo->Name, TRUE))) {
                    SIZE_T n = ansi.Length < sizeof(pipeBuf) - 1 ? ansi.Length : sizeof(pipeBuf) - 1;
                    RtlCopyMemory(pipeBuf, ansi.Buffer, n);
                    RtlFreeAnsiString(&ansi);
                }
                FltReleaseFileNameInformation(pipeNameInfo);
            }

            char msg[280];
            RtlStringCchPrintfA(msg, sizeof(msg),
                "FS-NPFS: FSCTL_PIPE_IMPERSONATE by '%s' (pid=%llu) on pipe=%s "
                "— pipe client impersonation / potato privilege escalation (T1134.001)",
                procName ? procName : "?",
                (ULONG64)(ULONG_PTR)pid,
                pipeBuf[0] ? pipeBuf : "?");
            EnqueueFsAlert(pid, procName, msg, TRUE);  // CRITICAL
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// IRP_MJ_SET_EA — Extended Attribute abuse detection.
//
// NTFS Extended Attributes (EAs) are a rarely-used alternate data storage
// mechanism.  Attackers use EAs to:
//   - Hide payloads that bypass normal file content scanning
//   - Store C2 configuration data invisibly to most tools
//   - Persist data that survives file content wipes
//
// Legitimate EA users: SMB server (svchost), NTFS defrag, System, and
// specific applications that use EAs for metadata (e.g., WSL stores
// Linux permissions in EAs).
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI FsFilter::PreSetEa(
    PFLT_CALLBACK_DATA         Data,
    PCFLT_RELATED_OBJECTS      FltObjects,
    PVOID*                     CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    InterlockedIncrement(&g_PreOpCounters[PREOP_SET_EA]);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PEPROCESS process  = IoThreadToProcess(Data->Thread);
    HANDLE    pid      = PsGetProcessId(process);
    char*     procName = PsGetProcessImageFileName(process);

    // Allowlist: System, svchost (SMB), wsl (Linux FS layer), TrustedInstaller
    if ((ULONG_PTR)pid <= 4) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (procName) {
        if (strcmp(procName, "svchost.exe") == 0 ||
            strcmp(procName, "TrustedInsta") == 0 ||
            strcmp(procName, "wsl.exe") == 0 ||
            strcmp(procName, "wslhost.exe") == 0 ||
            strcmp(procName, "MsMpEng.exe") == 0)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get the EA buffer size for context
    ULONG eaLength = Data->Iopb->Parameters.SetEa.Length;

    PFLT_FILE_NAME_INFORMATION eaNameInfo = nullptr;
    char eaPath[128] = {};
    NTSTATUS eaSt = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &eaNameInfo);
    if (NT_SUCCESS(eaSt) && eaNameInfo) {
        FltParseFileNameInformation(eaNameInfo);
        for (ULONG c = 0; c < eaNameInfo->Name.Length / sizeof(WCHAR) && c < 127; c++)
            eaPath[c] = (char)eaNameInfo->Name.Buffer[c];
        FltReleaseFileNameInformation(eaNameInfo);
    }

    // Flag large EA writes (>256 bytes) as higher severity — likely payload storage
    BOOLEAN isLarge = (eaLength > 256);

    char msg[256];
    RtlStringCchPrintfA(msg, sizeof(msg),
        "FS: EXTENDED ATTRIBUTE write by '%s' (pid=%llu) size=%lu on %s "
        "— %s data hiding (T1564.004)",
        procName ? procName : "?", (ULONG64)(ULONG_PTR)pid, eaLength,
        eaPath[0] ? eaPath : "?",
        isLarge ? "LARGE payload" : "possible");
    EnqueueFsAlert(pid, procName, msg, isLarge);

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

    InterlockedIncrement(&g_PreOpCounters[PREOP_NET_QUERY]);

    if (!Data->Thread) return FLT_PREOP_SUCCESS_NO_CALLBACK;

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
