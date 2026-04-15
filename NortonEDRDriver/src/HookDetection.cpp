#include "Globals.h"
#include "sha256utils.h"

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------

PSSDT_BASELINE_ENTRY HookDetector::ssdtBaseline       = nullptr;
ULONG                HookDetector::ssdtBaselineCount   = 0;
PVOID                HookDetector::cachedKiServiceTable = nullptr;

ObCallbackSnapshot   HookDetector::s_ProcessCbSnapshot = {};
ObCallbackSnapshot   HookDetector::s_ThreadCbSnapshot  = {};
BOOLEAN              HookDetector::s_CbSnapshotTaken   = FALSE;

PsCallbackSnapshot   HookDetector::s_ProcNotifyCbSnap   = {};
PsCallbackSnapshot   HookDetector::s_ThreadNotifyCbSnap = {};
PsCallbackSnapshot   HookDetector::s_ImageNotifyCbSnap  = {};

CmCallbackSnapshot   HookDetector::s_CmCbSnap           = {};

// ---------------------------------------------------------------------------
// CI.dll code integrity — SHA256 baseline of CI.dll's executable sections.
// Detects patching of g_CiOptions or function-level hooks (BYOVD bypass).
// ---------------------------------------------------------------------------

static PVOID   s_CiTextBase     = nullptr;
static SIZE_T  s_CiTextSize     = 0;
static BYTE    s_CiTextHash[SHA256_BLOCK_SIZE] = {};
static BOOLEAN s_CiBaselineValid = FALSE;

// Walk PsLoadedModuleList to find a kernel module by name.
static PVOID FindKernelModuleBase(const WCHAR* name, PULONG outSize) {
    PLIST_ENTRY head = PsLoadedModuleList;
    if (!head || !MmIsAddressValid(head)) return nullptr;

    SIZE_T nameLen = 0;
    while (name[nameLen]) nameLen++;

    PLIST_ENTRY entry = head->Flink;
    __try {
        while (entry != head && MmIsAddressValid(entry)) {
            PLDR_DATA_TABLE_ENTRY mod =
                CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0 &&
                mod->BaseDllName.Length / sizeof(WCHAR) == nameLen) {
                BOOLEAN match = TRUE;
                for (SIZE_T i = 0; i < nameLen; i++) {
                    WCHAR a = mod->BaseDllName.Buffer[i];
                    WCHAR b = name[i];
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) {
                    if (outSize) *outSize = (ULONG)(ULONG_PTR)mod->SizeOfImage;
                    return mod->DllBase;
                }
            }
            entry = entry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return nullptr;
}

// ---------------------------------------------------------------------------
// EPROCESS protection level monitoring — snapshot and periodic verification.
// Detects BYOVD zeroing of EPROCESS.Protection on PPL processes (lsass, csrss).
// ---------------------------------------------------------------------------

#define MAX_PROT_WATCH 8

struct ProtWatchEntry {
    ULONG   pid;
    UCHAR   initialLevel;        // PS_PROTECTION.Level (PPL)
    UCHAR   initialSigLevel;     // EPROCESS.SignatureLevel
    UCHAR   initialSectSigLevel; // EPROCESS.SectionSignatureLevel
    char    name[16];
    BOOLEAN active;
};

static ProtWatchEntry g_ProtWatch[MAX_PROT_WATCH] = {};

static const char* kProtWatchNames[] = {
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    nullptr
};

static BOOLEAN IsProtWatchTarget(const char* name) {
    char lower[16] = {};
    for (int i = 0; i < 15 && name[i]; i++)
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];
    for (int i = 0; kProtWatchNames[i]; i++)
        if (strcmp(lower, kProtWatchNames[i]) == 0) return TRUE;
    return FALSE;
}

// ---------------------------------------------------------------------------
// Private helper: classify the first bytes of a function as a hook type.
// ---------------------------------------------------------------------------

UCHAR HookDetector::DetectInlineHookType(PVOID functionAddress) {

    if (!functionAddress || !MmIsAddressValid(functionAddress))
        return HOOK_TYPE_NONE;

    __try {
        PUCHAR b = (PUCHAR)functionAddress;

        if (b[0] == 0xE9)
            return HOOK_TYPE_JMP_NEAR;

        if (b[0] == 0xFF && b[1] == 0x25)
            return HOOK_TYPE_JMP_FAR;

        if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0)
            return HOOK_TYPE_MOV_JMP;

        if (b[0] == 0x68 && b[5] == 0xC3)
            return HOOK_TYPE_PUSH_RET;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return HOOK_TYPE_NONE;
}

// ---------------------------------------------------------------------------
// Private helper: resolve the trampoline destination for a detected hook.
// ---------------------------------------------------------------------------

PVOID HookDetector::ResolveHookTarget(PVOID functionAddress, UCHAR hookType) {

    if (!functionAddress || hookType == HOOK_TYPE_NONE)
        return nullptr;

    __try {
        PUCHAR b = (PUCHAR)functionAddress;

        switch (hookType) {

        case HOOK_TYPE_JMP_NEAR: {
            LONG rel32 = *(PLONG)(b + 1);
            return (PVOID)((ULONG_PTR)functionAddress + 5 + rel32);
        }
        case HOOK_TYPE_JMP_FAR: {
            LONG ripRel = *(PLONG)(b + 2);
            PVOID* indirect = (PVOID*)((ULONG_PTR)functionAddress + 6 + ripRel);
            if (MmIsAddressValid(indirect))
                return *indirect;
            return nullptr;
        }
        case HOOK_TYPE_MOV_JMP:
            return *(PVOID*)(b + 2);

        case HOOK_TYPE_PUSH_RET:
            return (PVOID)(ULONG_PTR)(*(PULONG)(b + 1));

        default:
            return nullptr;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return nullptr;
}

// ---------------------------------------------------------------------------
// Internal: allocate and enqueue a hook-detection notification.
// ---------------------------------------------------------------------------

static VOID EnqueueHookNotif(
    BufferQueue* bufQueue,
    ULONG64      address,
    UCHAR        method2Flags,
    const char*  message
) {
    if (!bufQueue || !message) return;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'hknt'
        );
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
    SET_CRITICAL(*notif);
    notif->method2        |= method2Flags;
    notif->scoopedAddress  = address;

    // Measure message length (capped at 63 chars + null to match consumer limit)
    SIZE_T msgLen = 0;
    while (msgLen < 63 && message[msgLen] != '\0') msgLen++;
    msgLen++;

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'hkmg');
    if (notif->msg)
        RtlCopyMemory(notif->msg, message, msgLen);

    bufQueue->Enqueue(notif);
}

// ---------------------------------------------------------------------------
// TakeSsdtBaseline — snapshot SSDT function addresses at driver load time.
// kiServiceTable : raw nt!KiServiceTable pointer (encoded offsets array)
// count          : KeServiceDescriptorTable.NumberOfServices
// ---------------------------------------------------------------------------

VOID HookDetector::TakeSsdtBaseline(PVOID kiServiceTable, ULONG count) {

    if (!kiServiceTable || count == 0 || count > MAX_SSDT_ENTRIES) return;

    ssdtBaseline = (PSSDT_BASELINE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SSDT_BASELINE_ENTRY) * count,
        'bssd'
    );
    if (!ssdtBaseline) {
        DbgPrint("[-] HookDetector: SSDT baseline alloc failed\n");
        return;
    }

    RtlZeroMemory(ssdtBaseline, sizeof(SSDT_BASELINE_ENTRY) * count);
    cachedKiServiceTable = kiServiceTable;
    ssdtBaselineCount    = count;

    for (ULONG i = 0; i < count; i++) {
        __try {
            ULONG offset = *(PLONG)((DWORD64)kiServiceTable + 4 * i);
            if (offset != 0)
                ssdtBaseline[i].OriginalAddress =
                    (PVOID)((DWORD64)kiServiceTable + ((ULONG)offset >> 4));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    DbgPrint("[+] HookDetector: SSDT baseline captured (%lu entries)\n", count);
}

// ---------------------------------------------------------------------------
// CheckSsdtIntegrity — compare live SSDT entries against the baseline.
// Returns count of modified entries.
// ---------------------------------------------------------------------------

ULONG HookDetector::CheckSsdtIntegrity(BufferQueue* bufQueue) {

    if (!ssdtBaseline || !cachedKiServiceTable || ssdtBaselineCount == 0)
        return 0;

    ULONG detected = 0;

    for (ULONG i = 0; i < ssdtBaselineCount; i++) {

        if (!ssdtBaseline[i].OriginalAddress) continue;

        __try {
            ULONG offset = *(PLONG)((DWORD64)cachedKiServiceTable + 4 * i);
            if (offset == 0) continue;

            PVOID current =
                (PVOID)((DWORD64)cachedKiServiceTable + ((ULONG)offset >> 4));

            if (current != ssdtBaseline[i].OriginalAddress) {
                detected++;
                DbgPrint("[!] SSDT hook: SSN=%lu orig=%p curr=%p\n",
                    i, ssdtBaseline[i].OriginalAddress, current);

                char msg[64];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "SSDT hook SSN=%lu %p->%p",
                    i, ssdtBaseline[i].OriginalAddress, current);

                KERNEL_STRUCTURED_NOTIFICATION tmp = {};
                SET_SSDT_HOOK_CHECK(tmp);
                EnqueueHookNotif(bufQueue, (ULONG64)current, tmp.method2, msg);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    return detected;
}

// ---------------------------------------------------------------------------
// ScanKernelInlineHooks — inspect the prologue of every ntoskrnl export.
// Returns count of hooked functions.
// ---------------------------------------------------------------------------

ULONG HookDetector::ScanKernelInlineHooks(PFUNCTION_MAP exportsMap, BufferQueue* bufQueue) {

    if (!exportsMap) return 0;

    ULONG detected = 0;

    for (ULONG bucket = 0; bucket < HASH_TABLE_SIZE; bucket++) {

        PFUNCTION_NODE node = exportsMap->Buckets[bucket];

        while (node) {
            __try {
                UCHAR hookType = DetectInlineHookType(node->Address);

                if (hookType != HOOK_TYPE_NONE) {
                    PVOID target = ResolveHookTarget(node->Address, hookType);
                    detected++;

                    DbgPrint("[!] Inline hook: %ws addr=%p type=0x%02X target=%p\n",
                        node->FunctionName.Buffer ? node->FunctionName.Buffer : L"?",
                        node->Address, hookType, target);

                    char msg[64];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "InlineHook %p type=%02X->%p",
                        node->Address, hookType, target);

                    KERNEL_STRUCTURED_NOTIFICATION tmp = {};
                    SET_INLINE_HOOK_CHECK(tmp);
                    EnqueueHookNotif(bufQueue, (ULONG64)node->Address, tmp.method2, msg);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}

            node = node->Next;
        }
    }

    return detected;
}

// ---------------------------------------------------------------------------
// ScanKernelEatHooks — flag any EAT entry whose resolved address falls
// outside the kernel module's image bounds.
// Returns count of out-of-bounds entries.
// ---------------------------------------------------------------------------

ULONG HookDetector::ScanKernelEatHooks(PVOID moduleBase, BufferQueue* bufQueue) {

    if (!moduleBase) return 0;

    ULONG detected = 0;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        PIMAGE_NT_HEADERS nt =
            (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        PIMAGE_OPTIONAL_HEADER64 opt = &nt->OptionalHeader;
        ULONG imageSize = opt->SizeOfImage;

        PIMAGE_DATA_DIRECTORY expDir =
            &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir->VirtualAddress || !expDir->Size) return 0;

        PIMAGE_EXPORT_DIRECTORY exports =
            (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + expDir->VirtualAddress);

        ULONG*  addrOfFunctions    = (ULONG*)((PUCHAR)moduleBase + exports->AddressOfFunctions);
        ULONG*  addrOfNames        = (ULONG*)((PUCHAR)moduleBase + exports->AddressOfNames);
        USHORT* addrOfNameOrdinals = (USHORT*)((PUCHAR)moduleBase + exports->AddressOfNameOrdinals);

        ULONG_PTR base     = (ULONG_PTR)moduleBase;
        ULONG_PTR expStart = (ULONG_PTR)exports;
        ULONG_PTR expEnd   = expStart + expDir->Size;

        for (ULONG i = 0; i < exports->NumberOfNames; i++) {
            __try {
                ULONG_PTR funcAddr =
                    base + addrOfFunctions[addrOfNameOrdinals[i]];

                // Skip forwarder strings (they reside inside the export directory)
                if (funcAddr >= expStart && funcAddr < expEnd) continue;

                // Flag if resolved address falls outside the module image
                if (funcAddr < base || funcAddr >= base + imageSize) {
                    PCHAR name = (PCHAR)((PUCHAR)moduleBase + addrOfNames[i]);
                    detected++;

                    DbgPrint("[!] EAT hook: %s -> %p (outside module)\n",
                        name, (PVOID)funcAddr);

                    char msg[64];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "EAT hook %s->%p", name, (PVOID)funcAddr);

                    KERNEL_STRUCTURED_NOTIFICATION tmp = {};
                    SET_EAT_HOOK_CHECK(tmp);
                    EnqueueHookNotif(bufQueue, funcAddr, tmp.method2, msg);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] HookDetector: exception in ScanKernelEatHooks\n");
    }

    return detected;
}

// ---------------------------------------------------------------------------
// CheckEtwHooks — resolve exported ETW functions and inspect their prologues.
// Returns TRUE if any ETW function appears patched.
// ---------------------------------------------------------------------------

BOOLEAN HookDetector::CheckEtwHooks(BufferQueue* bufQueue) {

    static const WCHAR* etwExports[] = {
        L"EtwWrite",
        L"EtwWriteEx",
        L"EtwWriteTransfer",
        L"EtwRegister",
        L"EtwEventWriteTransfer",       // TraceLogging primary write path
        L"EtwEventWriteNoRegistration", // TraceLogging unregistered provider write
    };

    BOOLEAN anyFound = FALSE;

    for (ULONG i = 0; i < ARRAYSIZE(etwExports); i++) {

        UNICODE_STRING name;
        RtlInitUnicodeString(&name, etwExports[i]);

        PVOID fn = MmGetSystemRoutineAddress(&name);
        if (!fn) continue;

        UCHAR hookType = DetectInlineHookType(fn);
        if (hookType == HOOK_TYPE_NONE) continue;

        PVOID target = ResolveHookTarget(fn, hookType);
        anyFound = TRUE;

        DbgPrint("[!] ETW hook: %ws %p type=0x%02X target=%p\n",
            etwExports[i], fn, hookType, target);

        char msg[64];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ETW hook %p type=%02X->%p", fn, hookType, target);

        KERNEL_STRUCTURED_NOTIFICATION tmp = {};
        SET_ETW_HOOK_CHECK(tmp);
        EnqueueHookNotif(bufQueue, (ULONG64)fn, tmp.method2, msg);
    }

    return anyFound;
}

// ---------------------------------------------------------------------------
// ETW kernel structure integrity — undocumented structure monitoring.
//
// Techniques covered:
//   1. _ETW_REG_ENTRY EnableMask zeroing (Backstab, PPLdump)
//   2. _ETW_GUID_ENTRY ProviderEnableInfo zeroing (Phant0m, SyscallDumper)
//   3. _ETW_GUID_ENTRY RegList unlinking (_ETL_ENTRY disconnection)
//   4. TraceLogging _ETW_REG_ENTRY Callback pointer zeroing/redirection
//   5. EtwpDebuggerData global tampering
//   6. _WMI_LOGGER_CONTEXT.GetCpuClock pointer swap (InfinityHook)
//
// Strategy: use our own REGHANDLE from EtwRegister to derive the
// _ETW_REG_ENTRY pointer.  REGHANDLE is defined as:
//   bits [63:16] = _ETW_REG_ENTRY pointer (shifted right 4)
//   bits [15:0]  = index/validation
//
// From _ETW_REG_ENTRY we can reach:
//   +0x20 (Win10 21H2+): GuidEntry pointer → _ETW_GUID_ENTRY
//   +0x28 (Win10 21H2+): EnableMask (UCHAR)
//
// _ETW_GUID_ENTRY contains:
//   +0x80 (approx): ProviderEnableInfo (_TRACE_ENABLE_INFO) with IsEnabled at +0
//   +0x20 (approx): RegListHead (LIST_ENTRY)
//
// For EtwpDebuggerData: resolve via MmGetSystemRoutineAddress scanning.
//
// These offsets are version-dependent.  We use a heuristic approach:
// scan for known patterns near the resolved pointer to locate fields.
// ---------------------------------------------------------------------------

// Baselines for ETW structure integrity
static PVOID    s_EtwRegEntry        = nullptr;  // resolved _ETW_REG_ENTRY*
static PVOID    s_EtwGuidEntry       = nullptr;  // resolved _ETW_GUID_ENTRY*
static UCHAR    s_EnableMaskBaseline = 0;        // _ETW_REG_ENTRY.EnableMask
static PVOID    s_EnableMaskAddr     = nullptr;  // resolved address (captured at baseline)
static ULONG    s_ProviderEnableBaseline = 0;    // _ETW_GUID_ENTRY.ProviderEnableInfo.IsEnabled
// Full _TRACE_ENABLE_INFO struct baseline (32 bytes):
//   +0x00 ULONG     IsEnabled
//   +0x04 UCHAR     Level       ← level downgrade target
//   +0x05 UCHAR     Reserved1
//   +0x06 USHORT    LoggerId
//   +0x08 ULONG     EnableProperty
//   +0x0C ULONG     Reserved2
//   +0x10 ULONGLONG MatchAnyKeyword  ← keyword filter target
//   +0x18 ULONGLONG MatchAllKeyword
static PVOID    s_EnableInfoAddr         = nullptr;
static UCHAR    s_EnableInfoBaseline[32] = {};
static BOOLEAN  s_EnableInfoValid        = FALSE;
static ULONG    s_RegListCountBaseline = 0;      // count of _ETL_ENTRY nodes in RegList
static BOOLEAN  s_EtwStructureValid  = FALSE;

// EtwpDebuggerData baseline
static PVOID    s_EtwpDebuggerData     = nullptr;
static BYTE     s_EtwpDebuggerBaseline[64] = {};  // first 64 bytes
static BOOLEAN  s_EtwpDebuggerValid    = FALSE;

// _WMI_LOGGER_CONTEXT.GetCpuClock baseline
static PVOID    s_LoggerContext       = nullptr;
static PVOID    s_GetCpuClockBaseline = nullptr;
static BOOLEAN  s_LoggerContextValid  = FALSE;

// _ETW_GUID_ENTRY hash-table linkage baseline.
// _ETW_GUID_ENTRY is linked into EtwpGuidHashTable via the first LIST_ENTRY
// at offset 0 (Flink at +0x00, Blink at +0x08).  An attacker that unlinks
// the entry (sets neighbors to skip it) leaves the entry intact but removes
// it from provider lookups — our REGHANDLE→RegEntry→GuidEntry path still
// works, but EtwpFindGuidEntry no longer finds us, so providers appear
// gone from session enumeration.  Baseline the Flink/Blink at init; if
// either is zeroed or points outside the kernel range, the entry has been
// unlinked.
static PVOID    s_GuidHashFlinkBase = nullptr;
static PVOID    s_GuidHashBlinkBase = nullptr;
static BOOLEAN  s_GuidHashLinkValid = FALSE;

// Kernel ETW export address freeze.  Baseline the resolved addresses of
// NtTraceControl, NtTraceEvent, and EtwRegister at init.  If an attacker
// patches the ntoskrnl export directory to redirect these names to a
// malicious stub, MmGetSystemRoutineAddress will return a different value.
// PatchGuard-safe: read-only comparison, no writes to ntoskrnl.
struct EtwExportFreeze {
    const wchar_t* name;
    PVOID          baseline;
    BOOLEAN        valid;
};
static EtwExportFreeze s_EtwExports[] = {
    { L"NtTraceControl",   nullptr, FALSE },
    { L"NtTraceEvent",     nullptr, FALSE },
    { L"EtwRegister",      nullptr, FALSE },
    { L"EtwWrite",         nullptr, FALSE },
    { L"EtwWriteEx",       nullptr, FALSE },
    { nullptr,             nullptr, FALSE }
};

// _WMI_LOGGER_CONTEXT.LoggerMode baseline.
// LoggerMode is a ULONG containing EVENT_TRACE_* flags that control session
// behavior: CIRCULAR (0x2), BUFFERING (0x400), PRIVATE_LOGGER (0x800),
// SECURE (0x4), INDEPENDENT (0x08000000), SYSTEM_LOGGER (0x02000000), etc.
// Attackers flip BUFFERING to stop disk writes or INDEPENDENT to isolate the
// session from rundown events — all silent, no syscall.  Validated offset
// range (0x40..0x80) via plausible flag-only value (< 0x0FFFFFFF).
static PULONG   s_LoggerModeAddr      = nullptr;
static ULONG    s_LoggerModeBaseline  = 0;
static BOOLEAN  s_LoggerModeValid     = FALSE;

// TraceLogging metadata integrity baseline.
// _ETW_REG_ENTRY contains a Callback pointer (offset ~0x38-0x48) that for
// TraceLogging providers points to the _TlgProvider_t structure in the
// driver's .rdata section.  This structure starts with a signature magic
// "ETW0" (0x30575445).  Zeroing or redirecting this pointer disables
// self-describing event emission without touching ETW structures.
static PVOID    s_TlgCallbackAddr    = nullptr;  // address of Callback field
static PVOID    s_TlgCallbackBaseline = nullptr; // original Callback value
static BOOLEAN  s_TlgCallbackValid   = FALSE;

// Helper: emit an ETW structure tampering alert
static VOID EmitEtwStructureAlert(BufferQueue* bufQueue, const char* msg)
{
    if (!bufQueue) return;
    SIZE_T len = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION n =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'etst');
    if (!n) return;
    RtlZeroMemory(n, sizeof(*n));
    SET_CRITICAL(*n);
    SET_ETW_HOOK_CHECK(*n);
    n->bufSize = (ULONG)len;
    n->isPath = FALSE;
    n->pid = PsGetProcessId(IoGetCurrentProcess());
    n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'emsg');
    if (n->msg) {
        RtlCopyMemory(n->msg, msg, len);
        if (!bufQueue->Enqueue(n)) {
            ExFreePool(n->msg); ExFreePool(n);
        }
    } else {
        ExFreePool(n);
    }
}

// Derive _ETW_REG_ENTRY from REGHANDLE.
// REGHANDLE encoding (Windows 10+):
//   The upper 48 bits (>> 16) give a kernel-pool-tagged pointer to _ETW_REG_ENTRY
//   when shifted left by 4 (i.e., the pointer is stored >> 4 in bits [63:20]).
// Some builds encode it differently — we validate by checking pool tag 'EtwR'.
static PVOID RegHandleToRegEntry(REGHANDLE handle)
{
    if (handle == 0) return nullptr;

    // Common encoding: bits [63:16] contain the pointer directly
    ULONG_PTR raw = (ULONG_PTR)handle;
    PVOID candidate = (PVOID)(raw & ~0xFFFFULL);

    __try {
        if (MmIsAddressValid(candidate) &&
            MmIsAddressValid((PVOID)((ULONG_PTR)candidate + 0x40))) {
            return candidate;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return nullptr;
}

// Count nodes in a circular doubly-linked LIST_ENTRY.
static ULONG CountListEntries(PLIST_ENTRY head, ULONG maxWalk)
{
    if (!head || !MmIsAddressValid(head)) return 0;
    ULONG count = 0;
    __try {
        PLIST_ENTRY cur = head->Flink;
        while (cur != head && count < maxWalk) {
            if (!MmIsAddressValid(cur)) break;
            count++;
            cur = cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return count;
    }
    return count;
}

VOID HookDetector::TakeEtwStructureBaseline()
{
    REGHANDLE handle = EtwProvider::GetRegHandle();
    if (handle == 0) {
        DbgPrint("[-] EtwStructure: no REGHANDLE — skip baseline\n");
        return;
    }

    PVOID regEntry = RegHandleToRegEntry(handle);
    if (!regEntry) {
        DbgPrint("[-] EtwStructure: could not derive _ETW_REG_ENTRY from handle 0x%llX\n",
            (ULONG64)handle);
        return;
    }

    s_EtwRegEntry = regEntry;

    // Walk the _ETW_REG_ENTRY structure to find EnableMask.
    // On Win10 21H2+, EnableMask is at offset +0x28 (UCHAR).
    // We try multiple known offsets.
    __try {
        // Try common offsets for EnableMask: 0x28, 0x30, 0x20
        static const ULONG kEnableMaskOffsets[] = { 0x28, 0x30, 0x20 };
        for (int i = 0; i < 3; i++) {
            PVOID addr = (PVOID)((ULONG_PTR)regEntry + kEnableMaskOffsets[i]);
            if (MmIsAddressValid(addr)) {
                UCHAR val = *(PUCHAR)addr;
                // EnableMask should be nonzero if provider is enabled
                if (val != 0) {
                    s_EnableMaskBaseline = val;
                    s_EnableMaskAddr     = addr;   // lock address for partial-change detection
                    break;
                }
            }
        }

        // Try to find _ETW_GUID_ENTRY pointer (offset +0x20 or +0x18)
        static const ULONG kGuidEntryOffsets[] = { 0x20, 0x18, 0x28 };
        for (int i = 0; i < 3; i++) {
            PVOID addr = (PVOID)((ULONG_PTR)regEntry + kGuidEntryOffsets[i]);
            if (!MmIsAddressValid(addr)) continue;
            PVOID candidate = *(PVOID*)addr;
            if (!candidate || !MmIsAddressValid(candidate)) continue;
            // Validate: _ETW_GUID_ENTRY should have our GUID at +0x10
            // (GUID field is typically at offset 0x10 in the structure)
            PVOID guidAddr = (PVOID)((ULONG_PTR)candidate + 0x10);
            if (MmIsAddressValid(guidAddr) &&
                MmIsAddressValid((PVOID)((ULONG_PTR)guidAddr + sizeof(GUID) - 1))) {
                s_EtwGuidEntry = candidate;
                break;
            }
        }

        if (s_EtwGuidEntry) {
            // ProviderEnableInfo.IsEnabled is at ~+0x80 in _ETW_GUID_ENTRY.
            // Capture the full 32-byte _TRACE_ENABLE_INFO so we can diff Level,
            // MatchAnyKeyword, and MatchAllKeyword — not just IsEnabled.
            static const ULONG kEnableInfoOffsets[] = { 0x80, 0x78, 0x88, 0x70 };
            for (int i = 0; i < 4; i++) {
                PVOID addr = (PVOID)((ULONG_PTR)s_EtwGuidEntry + kEnableInfoOffsets[i]);
                if (!MmIsAddressValid(addr)) continue;
                if (!MmIsAddressValid((PVOID)((ULONG_PTR)addr + 31))) continue;
                ULONG val = *(PULONG)addr;
                if (val != 0) {
                    s_ProviderEnableBaseline = val;
                    s_EnableInfoAddr = addr;
                    RtlCopyMemory(s_EnableInfoBaseline, addr, 32);
                    s_EnableInfoValid = TRUE;
                    break;
                }
            }

            // RegListHead is at ~+0x20 in _ETW_GUID_ENTRY
            PLIST_ENTRY regList = (PLIST_ENTRY)((ULONG_PTR)s_EtwGuidEntry + 0x20);
            if (MmIsAddressValid(regList))
                s_RegListCountBaseline = CountListEntries(regList, 64);

            // Baseline the hash-table linkage at offset 0 (Flink/Blink).
            // Unlinking leaves the entry intact but removes it from
            // EtwpGuidHashTable — detected as Flink=Blink=self or as the
            // links pointing outside the kernel address range.
            PLIST_ENTRY hashLink = (PLIST_ENTRY)s_EtwGuidEntry;
            if (MmIsAddressValid(hashLink) &&
                MmIsAddressValid((PVOID)((ULONG_PTR)hashLink + sizeof(LIST_ENTRY) - 1)))
            {
                PVOID fl = hashLink->Flink;
                PVOID bl = hashLink->Blink;
                if (fl && bl &&
                    (ULONG_PTR)fl > 0xFFFF800000000000ULL &&
                    (ULONG_PTR)bl > 0xFFFF800000000000ULL)
                {
                    s_GuidHashFlinkBase = fl;
                    s_GuidHashBlinkBase = bl;
                    s_GuidHashLinkValid = TRUE;
                    DbgPrint("[+] EtwStructure: GuidEntry hash link Flink=%p "
                        "Blink=%p\n", fl, bl);
                }
            }
        }

        // TraceLogging metadata pointer — the Callback field in _ETW_REG_ENTRY
        // (offset ~0x38, 0x40, 0x48) for TraceLogging providers points to
        // _TlgProvider_t which starts with signature 0x30575445 ("ETW0").
        // Scanning multiple offsets to find a pointer whose target starts with
        // the ETW0 magic.
        {
            static const ULONG kCallbackOffsets[] = { 0x38, 0x40, 0x48, 0x30 };
            for (int ci = 0; ci < 4; ci++) {
                PVOID addr = (PVOID)((ULONG_PTR)regEntry + kCallbackOffsets[ci]);
                if (!MmIsAddressValid(addr)) continue;
                PVOID cbVal = *(PVOID*)addr;
                if (!cbVal || !MmIsAddressValid(cbVal)) continue;
                // Check for ETW0 magic (0x30575445) at the candidate pointer
                ULONG magic = *(PULONG)cbVal;
                if (magic == 0x30575445) {
                    s_TlgCallbackAddr = addr;
                    s_TlgCallbackBaseline = cbVal;
                    s_TlgCallbackValid = TRUE;
                    DbgPrint("[+] EtwStructure: TraceLogging metadata at %p "
                        "(Callback offset +0x%lX, _TlgProvider_t=%p)\n",
                        addr, kCallbackOffsets[ci], cbVal);
                    break;
                }
                // Also accept any non-null kernel-mode pointer as a generic
                // callback baseline even if not TraceLogging
                if ((ULONG_PTR)cbVal > 0xFFFF800000000000ULL && !s_TlgCallbackValid) {
                    s_TlgCallbackAddr = addr;
                    s_TlgCallbackBaseline = cbVal;
                    s_TlgCallbackValid = TRUE;
                    DbgPrint("[+] EtwStructure: REG_ENTRY Callback at %p "
                        "(offset +0x%lX, target=%p, non-TLG)\n",
                        addr, kCallbackOffsets[ci], cbVal);
                }
            }
        }

        s_EtwStructureValid = TRUE;
        DbgPrint("[+] EtwStructure: baseline taken — RegEntry=%p GuidEntry=%p "
            "EnableMask=0x%02X ProviderEnable=0x%lX RegListCount=%lu TlgCb=%s\n",
            s_EtwRegEntry, s_EtwGuidEntry,
            s_EnableMaskBaseline, s_ProviderEnableBaseline,
            s_RegListCountBaseline,
            s_TlgCallbackValid ? "yes" : "no");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] EtwStructure: exception during baseline capture\n");
    }

    // Freeze ETW-related kernel export addresses.  If any export redirect
    // happens later, MmGetSystemRoutineAddress returns a different pointer.
    __try {
        for (int i = 0; s_EtwExports[i].name; i++) {
            UNICODE_STRING u;
            RtlInitUnicodeString(&u, s_EtwExports[i].name);
            PVOID fn = MmGetSystemRoutineAddress(&u);
            if (fn) {
                s_EtwExports[i].baseline = fn;
                s_EtwExports[i].valid    = TRUE;
                DbgPrint("[+] EtwStructure: export %ws frozen at %p\n",
                    s_EtwExports[i].name, fn);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] EtwStructure: exception freezing ETW exports\n");
    }

    // Resolve EtwpDebuggerData by scanning near EtwWriteEx
    __try {
        UNICODE_STRING nameEtwWriteEx;
        RtlInitUnicodeString(&nameEtwWriteEx, L"EtwWriteEx");
        PVOID etwWriteEx = MmGetSystemRoutineAddress(&nameEtwWriteEx);
        if (etwWriteEx) {
            // EtwpDebuggerData is typically referenced within ~0x200 bytes of
            // EtwWriteEx via a LEA instruction (48 8D 0D xx xx xx xx).
            PUCHAR scan = (PUCHAR)etwWriteEx;
            for (int i = 0; i < 0x200; i++) {
                if (scan[i] == 0x48 && scan[i+1] == 0x8D &&
                    (scan[i+2] == 0x0D || scan[i+2] == 0x15)) {
                    // RIP-relative LEA — compute target
                    LONG offset = *(PLONG)(&scan[i+3]);
                    PVOID target = (PVOID)(&scan[i+7] + offset);
                    if (MmIsAddressValid(target) &&
                        MmIsAddressValid((PVOID)((ULONG_PTR)target + 63))) {
                        s_EtwpDebuggerData = target;
                        RtlCopyMemory(s_EtwpDebuggerBaseline, target, 64);
                        s_EtwpDebuggerValid = TRUE;
                        DbgPrint("[+] EtwpDebuggerData: resolved at %p\n", target);
                        break;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] EtwpDebuggerData: exception during resolve\n");
    }

    // Resolve _WMI_LOGGER_CONTEXT.GetCpuClock for InfinityHook detection.
    // InfinityHook swaps GetCpuClock (+0x28) in the CKCL session (logger ID 2)
    // to redirect every ETW event through an attacker callback.
    // Strategy: find EtwpLoggerContext[] array by scanning near NtTraceControl
    // for a LEA to the logger context pointer array, then read slot [2] (CKCL).
    __try {
        // Resolve known clock targets for validation
        UNICODE_STRING nameHalPerf;
        RtlInitUnicodeString(&nameHalPerf, L"KeQueryPerformanceCounter");
        PVOID halPerf = MmGetSystemRoutineAddress(&nameHalPerf);
        UNICODE_STRING nameGetSysTime;
        RtlInitUnicodeString(&nameGetSysTime, L"KeQuerySystemTimePrecise");
        PVOID sysTime = MmGetSystemRoutineAddress(&nameGetSysTime);

        // Scan from EtwpDebuggerData if available — the logger context array
        // pointer is typically stored as a field in EtwpDebuggerData.
        // Alternatively, scan near NtTraceControl for LEA referencing the
        // EtwpLoggerContext array.  We try both approaches.
        PVOID ckclContext = nullptr;

        // Approach 1: Scan NtTraceControl body for LEA to logger context array.
        // NtTraceControl references EtwpLoggerContext[] within its first ~0x600
        // bytes via a LEA with RIP-relative addressing (48 8D xx xx xx xx xx)
        // followed shortly by indexed access [rcx*8] for logger ID lookup.
        UNICODE_STRING nameNtTraceControl;
        RtlInitUnicodeString(&nameNtTraceControl, L"NtTraceControl");
        PVOID ntTraceCtl = MmGetSystemRoutineAddress(&nameNtTraceControl);
        if (ntTraceCtl) {
            PUCHAR scan = (PUCHAR)ntTraceCtl;
            for (int i = 0; i < 0x600; i++) {
                // Look for LEA reg, [rip+disp32] patterns:
                // 48 8D 0D/15/05/35 xx xx xx xx  (LEA rcx/rdx/rax/rsi, [rip+xx])
                // 4C 8D 25/2D/35    xx xx xx xx  (LEA r12/r13/r14, [rip+xx])
                if ((scan[i] == 0x48 || scan[i] == 0x4C) &&
                    scan[i+1] == 0x8D) {
                    LONG rDisp = *(PLONG)(&scan[i+3]);
                    PVOID target = (PVOID)(&scan[i+7] + rDisp);
                    if (!MmIsAddressValid(target)) continue;

                    // The logger context array is an array of pointers.
                    // Slot [2] is the CKCL session. Validate that reading
                    // slot [2] gives a plausible kernel pointer.
                    PVOID* arr = (PVOID*)target;
                    if (!MmIsAddressValid(&arr[2])) continue;
                    PVOID slot2 = arr[2];
                    if (slot2 == nullptr) continue;
                    if (!MmIsAddressValid(slot2)) continue;

                    // Validate: _WMI_LOGGER_CONTEXT starts with a known
                    // signature — check that GetCpuClock at +0x28 points
                    // to a kernel-mode address (above 0xFFFF800000000000).
                    PVOID* pGetCpuClock = (PVOID*)((ULONG_PTR)slot2 + 0x28);
                    if (!MmIsAddressValid(pGetCpuClock)) continue;
                    PVOID clockFn = *pGetCpuClock;
                    if ((ULONG_PTR)clockFn < 0xFFFF800000000000ULL) continue;

                    // Additional validation: GetCpuClock should point to one
                    // of the known clock functions or at least valid code.
                    if (!MmIsAddressValid(clockFn)) continue;

                    ckclContext = slot2;
                    s_LoggerContext = slot2;
                    s_GetCpuClockBaseline = clockFn;
                    s_LoggerContextValid = TRUE;
                    DbgPrint("[+] EtwStructure: CKCL _WMI_LOGGER_CONTEXT at %p, "
                        "GetCpuClock=%p (KeQueryPerf=%p, SysTime=%p)\n",
                        slot2, clockFn, halPerf, sysTime);

                    // Baseline LoggerMode — scan offsets 0x40..0x80 for a
                    // plausible flag-only ULONG (no high bits set by counters).
                    // Accept the first candidate whose bits match known ETW
                    // mode flags (low nibble + standard flag positions).
                    static const ULONG kModeOffsets[] = {
                        0x6C, 0x70, 0x68, 0x74, 0x78, 0x64, 0x60
                    };
                    for (int mi = 0;
                         mi < (int)(sizeof(kModeOffsets)/sizeof(kModeOffsets[0]));
                         mi++)
                    {
                        PULONG pMode = (PULONG)((ULONG_PTR)slot2 + kModeOffsets[mi]);
                        if (!MmIsAddressValid(pMode)) continue;
                        ULONG val = *pMode;
                        // LoggerMode uses bits in the range 0x00000001..0x0FFFFFFF
                        // and must be non-zero for an active session.  Reject
                        // values that look like timestamps/counters.
                        if (val == 0 || (val & 0xF0000000)) continue;
                        s_LoggerModeAddr     = pMode;
                        s_LoggerModeBaseline = val;
                        s_LoggerModeValid    = TRUE;
                        DbgPrint("[+] EtwStructure: LoggerMode at +0x%lX = 0x%08lX\n",
                            kModeOffsets[mi], val);
                        break;
                    }
                    break;
                }
            }
        }

        if (!ckclContext && halPerf) {
            DbgPrint("[*] EtwStructure: CKCL logger context not resolved, "
                "KeQueryPerformanceCounter at %p (reference only)\n", halPerf);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] EtwStructure: exception resolving GetCpuClock\n");
    }
}

VOID HookDetector::CheckEtwStructureIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue) return;

    // --- Check 1+3: _ETW_REG_ENTRY EnableMask and ProviderEnableInfo ---
    if (s_EtwStructureValid && s_EtwRegEntry) {
        __try {
            // EnableMask check — detect full zeroing (Backstab) AND partial
            // bit clearing that silences specific levels (e.g. 0x1F → 0x01 to
            // drop info/warning/error while leaving critical-only).  EnableMask
            // bits correspond to enabled levels: clearing a bit silently
            // suppresses all events of that level.
            if (s_EnableMaskBaseline != 0 && s_EnableMaskAddr &&
                MmIsAddressValid(s_EnableMaskAddr))
            {
                UCHAR current = *(PUCHAR)s_EnableMaskAddr;
                UCHAR cleared = s_EnableMaskBaseline & ~current; // bits that dropped
                if (cleared != 0) {
                    const char* kind = (current == 0)
                        ? "ZEROED (Backstab/PPLdump — full provider disable)"
                        : "PARTIALLY CLEARED (selective level suppression)";
                    char msg[320];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "ETW BYPASS CRITICAL: _ETW_REG_ENTRY.EnableMask %s "
                        "at %p (was 0x%02X, now 0x%02X, cleared bits=0x%02X) — "
                        "events matching cleared level bits silently dropped "
                        "(T1562.002)",
                        kind, s_EnableMaskAddr, s_EnableMaskBaseline,
                        current, cleared);
                    EmitEtwStructureAlert(bufQueue, msg);
                    // Restore original mask
                    *(PUCHAR)s_EnableMaskAddr = s_EnableMaskBaseline;
                    DbgPrint("[!] EtwStructure: EnableMask RESTORED 0x%02X→0x%02X\n",
                        current, s_EnableMaskBaseline);
                }
            }

            // ProviderEnableInfo check — compare full 32-byte _TRACE_ENABLE_INFO.
            // Catches:
            //   - Full zeroing (Phant0m/SyscallDumper)
            //   - Level downgrade (UCHAR at +0x04): attacker sets Level=1
            //     while IsEnabled stays 1, dropping info/warning/error
            //   - Keyword masking (ULONGLONG at +0x10 MatchAnyKeyword): attacker
            //     zeroes keywords, silently filtering all events
            if (s_EnableInfoValid && s_EnableInfoAddr &&
                MmIsAddressValid(s_EnableInfoAddr) &&
                MmIsAddressValid((PVOID)((ULONG_PTR)s_EnableInfoAddr + 31)))
            {
                UCHAR current[32] = {};
                RtlCopyMemory(current, s_EnableInfoAddr, 32);

                if (RtlCompareMemory(current, s_EnableInfoBaseline, 32) != 32) {
                    ULONG     baseIsEnabled = *(PULONG)&s_EnableInfoBaseline[0x00];
                    ULONG     curIsEnabled  = *(PULONG)&current[0x00];
                    UCHAR     baseLevel     = s_EnableInfoBaseline[0x04];
                    UCHAR     curLevel      = current[0x04];
                    ULONGLONG baseMatchAny  = *(PULONGLONG)&s_EnableInfoBaseline[0x10];
                    ULONGLONG curMatchAny   = *(PULONGLONG)&current[0x10];
                    ULONGLONG baseMatchAll  = *(PULONGLONG)&s_EnableInfoBaseline[0x18];
                    ULONGLONG curMatchAll   = *(PULONGLONG)&current[0x18];

                    const char* attack = "modified";
                    if (curIsEnabled == 0 && baseIsEnabled != 0)
                        attack = "ZEROED (Phant0m — provider silently disabled)";
                    else if (curLevel != 0 && curLevel < baseLevel)
                        attack = "LEVEL DOWNGRADE (selective event suppression)";
                    else if (curMatchAny == 0 && baseMatchAny != 0)
                        attack = "KEYWORD ZEROED (all events filtered by keyword)";
                    else if (curMatchAny != baseMatchAny)
                        attack = "KEYWORD MASK CHANGED (selective keyword suppression)";

                    char msg[384];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "ETW BYPASS CRITICAL: _ETW_GUID_ENTRY.ProviderEnableInfo "
                        "%s at %p — IsEnabled %lu→%lu, Level %u→%u, "
                        "MatchAnyKeyword 0x%llX→0x%llX, MatchAll 0x%llX→0x%llX "
                        "(T1562.002)",
                        attack, s_EnableInfoAddr,
                        baseIsEnabled, curIsEnabled,
                        baseLevel, curLevel,
                        baseMatchAny, curMatchAny,
                        baseMatchAll, curMatchAll);
                    EmitEtwStructureAlert(bufQueue, msg);

                    // Restore full baseline
                    RtlCopyMemory(s_EnableInfoAddr, s_EnableInfoBaseline, 32);
                    DbgPrint("[!] EtwStructure: ProviderEnableInfo RESTORED\n");
                }
            }

            // RegList unlinking check (gap 4)
            if (s_EtwGuidEntry && s_RegListCountBaseline > 0) {
                PLIST_ENTRY regList = (PLIST_ENTRY)((ULONG_PTR)s_EtwGuidEntry + 0x20);
                if (MmIsAddressValid(regList)) {
                    ULONG currentCount = CountListEntries(regList, 64);
                    if (currentCount < s_RegListCountBaseline) {
                        char msg[256];
                        RtlStringCbPrintfA(msg, sizeof(msg),
                            "ETW BYPASS CRITICAL: _ETW_GUID_ENTRY RegList nodes "
                            "UNLINKED — was %lu entries, now %lu — provider "
                            "disconnected from session without code modification "
                            "(T1562.002: _ETL_ENTRY unlinking attack)",
                            s_RegListCountBaseline, currentCount);
                        EmitEtwStructureAlert(bufQueue, msg);
                        // Update baseline (can't relink easily)
                        s_RegListCountBaseline = currentCount;
                    }
                }
            }
            // TraceLogging metadata pointer check — detect zeroing or redirection
            // of the _ETW_REG_ENTRY Callback pointer that targets _TlgProvider_t.
            if (s_TlgCallbackValid && s_TlgCallbackAddr) {
                PVOID currentCb = *(PVOID*)s_TlgCallbackAddr;
                if (currentCb != s_TlgCallbackBaseline) {
                    const char* attackType = "redirected";
                    if (currentCb == nullptr)
                        attackType = "ZEROED (TraceLogging provider silently disabled)";

                    char msg[300];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "ETW BYPASS CRITICAL: _ETW_REG_ENTRY Callback/TraceLogging "
                        "metadata pointer %s at %p (was %p, now %p) — "
                        "self-describing event emission disabled (T1562.002)",
                        attackType, s_TlgCallbackAddr,
                        s_TlgCallbackBaseline, currentCb);
                    EmitEtwStructureAlert(bufQueue, msg);

                    // Restore original pointer
                    *(PVOID*)s_TlgCallbackAddr = s_TlgCallbackBaseline;
                    DbgPrint("[!] EtwStructure: TraceLogging Callback RESTORED to %p\n",
                        s_TlgCallbackBaseline);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] EtwStructure: exception in integrity check\n");
        }
    }

    // --- Check 5: EtwpDebuggerData integrity ---
    if (s_EtwpDebuggerValid && s_EtwpDebuggerData) {
        __try {
            if (MmIsAddressValid(s_EtwpDebuggerData) &&
                MmIsAddressValid((PVOID)((ULONG_PTR)s_EtwpDebuggerData + 63)))
            {
                BYTE current[64];
                RtlCopyMemory(current, s_EtwpDebuggerData, 64);
                if (memcmp(current, s_EtwpDebuggerBaseline, 64) != 0) {
                    // Identify which bytes changed
                    int firstDiff = 0;
                    for (int i = 0; i < 64; i++) {
                        if (current[i] != s_EtwpDebuggerBaseline[i]) {
                            firstDiff = i;
                            break;
                        }
                    }

                    // Check for zeroing pattern (most common attack)
                    BOOLEAN isZeroed = TRUE;
                    for (int i = 0; i < 64; i++) {
                        if (current[i] != 0 && current[i] != s_EtwpDebuggerBaseline[i]) {
                            isZeroed = FALSE;
                            break;
                        }
                    }

                    char msg[300];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "ETW BYPASS CRITICAL: EtwpDebuggerData modified at %p "
                        "(first diff at +0x%X, %s) — kernel ETW debug/logger "
                        "state tampered (T1562.002)",
                        s_EtwpDebuggerData, firstDiff,
                        isZeroed ? "zeroing pattern detected" :
                                   "non-zero modification");
                    EmitEtwStructureAlert(bufQueue, msg);

                    // Restore original
                    RtlCopyMemory(s_EtwpDebuggerData, s_EtwpDebuggerBaseline, 64);
                    DbgPrint("[!] EtwpDebuggerData: RESTORED from baseline\n");
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] EtwpDebuggerData: exception in integrity check\n");
        }
    }

    // --- Check 6: _WMI_LOGGER_CONTEXT.GetCpuClock integrity (InfinityHook) ---
    // InfinityHook swaps GetCpuClock in the CKCL session to hijack every ETW
    // event call.  The pointer at +0x28 should remain the same kernel clock
    // function we baselined.
    if (s_LoggerContextValid && s_LoggerContext) {
        __try {
            PVOID* pGetCpuClock = (PVOID*)((ULONG_PTR)s_LoggerContext + 0x28);
            if (MmIsAddressValid(pGetCpuClock)) {
                PVOID currentClock = *pGetCpuClock;
                if (currentClock != s_GetCpuClockBaseline) {
                    const char* attackType = "SWAPPED (InfinityHook)";
                    if (currentClock == nullptr)
                        attackType = "ZEROED (CKCL clock disabled)";

                    char msg[350];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "ETW BYPASS CRITICAL: _WMI_LOGGER_CONTEXT.GetCpuClock "
                        "%s at CKCL session %p+0x28 (was %p, now %p) — "
                        "attacker redirected ETW clock callback to intercept "
                        "all kernel ETW events (T1562.002: InfinityHook)",
                        attackType, s_LoggerContext,
                        s_GetCpuClockBaseline, currentClock);
                    EmitEtwStructureAlert(bufQueue, msg);

                    // Restore original clock pointer
                    *pGetCpuClock = s_GetCpuClockBaseline;
                    DbgPrint("[!] EtwStructure: GetCpuClock RESTORED to %p "
                        "(InfinityHook remediated)\n", s_GetCpuClockBaseline);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] EtwStructure: exception in GetCpuClock check\n");
        }
    }

    // --- Check 7: _ETW_GUID_ENTRY hash-table linkage ---
    // Detects provider unlinking from EtwpGuidHashTable.  When a legit entry
    // sits in the table, its Flink/Blink at +0x00 point to neighbors in the
    // same kernel pool range.  Unlinking sets Flink==Blink==self (empty ring)
    // or redirects them to attacker memory.
    if (s_GuidHashLinkValid && s_EtwGuidEntry &&
        MmIsAddressValid(s_EtwGuidEntry))
    {
        __try {
            PLIST_ENTRY hashLink = (PLIST_ENTRY)s_EtwGuidEntry;
            PVOID fl = hashLink->Flink;
            PVOID bl = hashLink->Blink;

            bool unlinked =
                (fl == nullptr || bl == nullptr)           ||
                (fl == hashLink && bl == hashLink)         ||  // empty ring
                ((ULONG_PTR)fl < 0xFFFF800000000000ULL)    ||
                ((ULONG_PTR)bl < 0xFFFF800000000000ULL);

            if (unlinked) {
                char msg[320];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "ETW BYPASS CRITICAL: _ETW_GUID_ENTRY hash-table UNLINK "
                    "at %p (was Flink=%p Blink=%p, now Flink=%p Blink=%p) — "
                    "provider hidden from EtwpGuidHashTable lookup, events "
                    "bypass session without code patching (T1562.002)",
                    s_EtwGuidEntry, s_GuidHashFlinkBase, s_GuidHashBlinkBase,
                    fl, bl);
                EmitEtwStructureAlert(bufQueue, msg);

                // Restore original linkage
                hashLink->Flink = (PLIST_ENTRY)s_GuidHashFlinkBase;
                hashLink->Blink = (PLIST_ENTRY)s_GuidHashBlinkBase;
                DbgPrint("[!] EtwStructure: GuidEntry hash linkage RESTORED\n");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] EtwStructure: exception in GuidEntry hash check\n");
        }
    }

    // --- Check 8: ETW kernel export freeze ---
    // Re-resolve each ETW export and compare to baseline.  A change means
    // ntoskrnl's export directory was redirected — one of the last unpatched
    // vectors for silently hooking syscall-level entry points.
    __try {
        for (int i = 0; s_EtwExports[i].name; i++) {
            if (!s_EtwExports[i].valid) continue;
            UNICODE_STRING u;
            RtlInitUnicodeString(&u, s_EtwExports[i].name);
            PVOID cur = MmGetSystemRoutineAddress(&u);
            if (cur && cur != s_EtwExports[i].baseline) {
                char msg[320];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "ETW BYPASS CRITICAL: ntoskrnl export %ws redirected "
                    "(was %p, now %p) — export directory tampered, syscall "
                    "entry silently hooked without prologue patch "
                    "(T1562.002)",
                    s_EtwExports[i].name, s_EtwExports[i].baseline, cur);
                EmitEtwStructureAlert(bufQueue, msg);
                // No restore: writing to ntoskrnl export directory would
                // risk PatchGuard BSOD.  Alert + log only.
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] EtwStructure: exception in export freeze check\n");
    }

    // --- Check 9: _WMI_LOGGER_CONTEXT.LoggerMode tamper ---
    // Flipping CIRCULAR/BUFFERING/PRIVATE/SECURE/INDEPENDENT bits silently
    // changes session behavior (drop-to-ram, isolation) without any syscall.
    if (s_LoggerModeValid && s_LoggerModeAddr &&
        MmIsAddressValid(s_LoggerModeAddr))
    {
        __try {
            ULONG current = *s_LoggerModeAddr;
            if (current != s_LoggerModeBaseline) {
                ULONG setBits     = current & ~s_LoggerModeBaseline; // newly set
                ULONG clearedBits = s_LoggerModeBaseline & ~current; // newly dropped
                const char* attack = "modified";
                if ((setBits & 0x400) /* EVENT_TRACE_BUFFERING_MODE */)
                    attack = "BUFFERING bit set — events held in RAM, not flushed";
                else if ((setBits & 0x08000000) /* INDEPENDENT_SESSION_MODE */)
                    attack = "INDEPENDENT bit set — session isolated from rundown";
                else if ((clearedBits & 0x4) /* EVENT_TRACE_SECURE_MODE */)
                    attack = "SECURE bit cleared — tamper protections dropped";
                else if (clearedBits != 0)
                    attack = "flag bits cleared — mode downgrade";

                char msg[320];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "ETW BYPASS CRITICAL: _WMI_LOGGER_CONTEXT.LoggerMode %s "
                    "at %p (was 0x%08lX, now 0x%08lX, set=0x%08lX, "
                    "cleared=0x%08lX) — CKCL session flags tampered in memory "
                    "without calling NtTraceControl (T1562.002)",
                    attack, s_LoggerModeAddr, s_LoggerModeBaseline,
                    current, setBits, clearedBits);
                EmitEtwStructureAlert(bufQueue, msg);

                // Restore original mode bits
                *s_LoggerModeAddr = s_LoggerModeBaseline;
                DbgPrint("[!] EtwStructure: LoggerMode RESTORED 0x%08lX→0x%08lX\n",
                    current, s_LoggerModeBaseline);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] EtwStructure: exception in LoggerMode check\n");
        }
    }
}

// ---------------------------------------------------------------------------
// CheckAltSyscallHandlerIntegrity — verify that PspAltSystemCallHandlers[1]
// still points to SyscallsUtils::SyscallHandler and has not been nulled out
// or replaced by a third-party routine.
//
// Uses the same LeakPspAltSystemCallHandlers scan as InitAltSyscallHandler:
//   resolve PsRegisterAltSystemCallHandler -> scan for LEA R14,[RIP+] ->
//   read handlers[1].
// ---------------------------------------------------------------------------

static ULONGLONG FindPspAltSyscallHandlers(ULONGLONG rOffset) {

    for (int i = 0; i < 0x100; i++) {
        __try {
            UINT8 sig[] = { 0x4C, 0x8D, 0x35 };
            ULONGLONG opcodes = *(PULONGLONG)rOffset;

            if (starts_with_signature((ULONGLONG)&opcodes, sig, sizeof(sig))) {
                ULONGLONG correctOffset = ((*(PLONGLONG)(rOffset)) >> 24 & 0x0000FFFFFF);
                return rOffset + 7 + correctOffset;
            }
            rOffset += 2;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return NULL;
}

VOID HookDetector::CheckAltSyscallHandlerIntegrity(BufferQueue* bufQueue) {

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsRegisterAltSystemCallHandler");
    PVOID psRegAlt = MmGetSystemRoutineAddress(&name);

    if (!psRegAlt || !MmIsAddressValid(psRegAlt)) {
        DbgPrint("[-] HookDetector: PsRegisterAltSystemCallHandler not found\n");
        return;
    }

    LONGLONG* handlers = (LONGLONG*)FindPspAltSyscallHandlers((ULONGLONG)psRegAlt);

    if (!handlers || !MmIsAddressValid(handlers)) {
        DbgPrint("[-] HookDetector: PspAltSystemCallHandlers not found\n");
        return;
    }

    LONGLONG current  = handlers[1];
    LONGLONG expected = (LONGLONG)SyscallsUtils::SyscallHandler;

    if (current == 0) {

        DbgPrint("[!] AltSyscallHandler: slot 1 is NULL — handler was removed\n");

        char msg[64];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "AltSyscallHandler[1] NULL (removed)");

        KERNEL_STRUCTURED_NOTIFICATION tmp = {};
        SET_ALT_SYSCALL_HANDLER_CHECK(tmp);
        EnqueueHookNotif(bufQueue, (ULONG64)handlers, tmp.method2, msg);

    } else if (current != expected) {

        DbgPrint("[!] AltSyscallHandler: slot 1 tampered — expected=%p got=%p\n",
            (PVOID)expected, (PVOID)current);

        char msg[64];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "AltSyscallHandler[1] tampered %p->%p",
            (PVOID)expected, (PVOID)current);

        KERNEL_STRUCTURED_NOTIFICATION tmp = {};
        SET_ALT_SYSCALL_HANDLER_CHECK(tmp);
        EnqueueHookNotif(bufQueue, (ULONG64)current, tmp.method2, msg);

    } else {
        DbgPrint("[+] AltSyscallHandler: integrity OK (%p)\n", (PVOID)current);
    }
}

// ---------------------------------------------------------------------------
// ObCallback list helpers
//
// Layout (stable Win10 1507 – Win11 24H2, x64):
//   OBJECT_TYPE.CallbackList        : LIST_ENTRY at offset +0xC8
//   CALLBACK_ENTRY_ITEM.PreOperation: POB_PRE_OPERATION_CALLBACK at offset +0x28
//     from the start of the LIST_ENTRY node embedded in CALLBACK_ENTRY_ITEM
//
// PsProcessType / PsThreadType are exported as POBJECT_TYPE* (ptr-to-ptr).
// ---------------------------------------------------------------------------

#define OBJECT_TYPE_CALLBACKLIST_OFFSET    0xC8u
#define CALLBACK_ENTRY_PREOPERATION_OFFSET 0x28u

// EX_CALLBACK and EX_CALLBACK_ROUTINE_BLOCK (Ps*Notify arrays)
// EX_CALLBACK_ROUTINE_BLOCK.Function is at offset 8 on x64 (after EX_RUNDOWN_REF).
// Stable since Vista; verified through Win11 24H2.
#define EX_CALLBACK_FUNCTION_OFFSET   0x08u
// EX_FAST_REF low 4 bits are ref count on x64 — mask them to get the block pointer.
#define EX_FAST_REF_MASK              0xFull

static inline PVOID ExCallbackGetFunction(PVOID fastRefValue) {
	PVOID block = (PVOID)((ULONG_PTR)fastRefValue & ~EX_FAST_REF_MASK);
	if (!block || !MmIsAddressValid(block)) return nullptr;
	PVOID* fnSlot = (PVOID*)((PUCHAR)block + EX_CALLBACK_FUNCTION_OFFSET);
	return MmIsAddressValid(fnSlot) ? *fnSlot : nullptr;
}

// Collect all PreOp pointers currently in a CallbackList into dst[].
// Returns number of entries written (capped at OB_CALLBACK_SNAPSHOT_MAX).
static ULONG CollectCallbackPreOps(POBJECT_TYPE objType, PVOID* dst, ULONG dstMax)
{
    ULONG count = 0;
    if (!objType || !MmIsAddressValid(objType) || !dst || dstMax == 0) return 0;

    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)objType + OBJECT_TYPE_CALLBACKLIST_OFFSET);
    if (!MmIsAddressValid(head)) return 0;

    ULONG limit = 64;
    __try {
        for (PLIST_ENTRY e = head->Flink;
             e != head && limit-- > 0 && count < dstMax;
             e = e->Flink)
        {
            if (!MmIsAddressValid(e)) break;
            PVOID* preOpSlot = (PVOID*)((PUCHAR)e + CALLBACK_ENTRY_PREOPERATION_OFFSET);
            if (MmIsAddressValid(preOpSlot) && *preOpSlot)
                dst[count++] = *preOpSlot;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return count;
}

static BOOLEAN IsKnownInSnapshot(PVOID ptr, const ObCallbackSnapshot* snap)
{
    for (ULONG i = 0; i < snap->count; i++)
        if (snap->preOpPointers[i] == ptr) return TRUE;
    return FALSE;
}

static VOID EmitObAlert(BufferQueue* bufQueue, const char* msg, PVOID addr)
{
    SIZE_T msgLen = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'obck');
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    SET_OB_CALLBACK_CHECK(*notif);
    notif->pid            = 0;
    notif->isPath         = FALSE;
    notif->scoopedAddress = (ULONG64)addr;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);

    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'obmg');
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
// FindPsNotifyArrayBase — locate PspCreate*NotifyRoutine[] via LEA scan.
//
// Scans the first 0x200 bytes of setFn (a Ps*Set*NotifyRoutine* function) for LEA
// [RIP+disp32] instructions (any GPR destination). For each candidate resolved
// address, validates by scanning up to 64 slots looking for ourCallback.
// Returns array base if found, else null.
// ---------------------------------------------------------------------------

static const UCHAR g_LeaSecondBytes[] = { 0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D };

static PVOID FindPsNotifyArrayBase(PVOID setFn, PVOID ourCallback)
{
	if (!setFn || !MmIsAddressValid(setFn)) return nullptr;

	PUCHAR p = (PUCHAR)setFn;
	__try {
		for (ULONG i = 0; i < 0x200 - 7; i++) {
			// REX.W prefix (0x48 or 0x4C) + LEA opcode (0x8D) + ModRM
			if ((p[i] != 0x48 && p[i] != 0x4C) || p[i+1] != 0x8D)
				continue;
			BOOLEAN validModRM = FALSE;
			for (ULONG b = 0; b < ARRAYSIZE(g_LeaSecondBytes); b++)
				if (p[i+2] == g_LeaSecondBytes[b]) { validModRM = TRUE; break; }
			if (!validModRM) continue;

			// Decode 4-byte RIP-relative displacement
			LONG disp = *(LONG*)(p + i + 3);
			PVOID candidate = (PVOID)(p + i + 7 + disp);  // RIP = instr end = p+i+7
			if (!MmIsAddressValid(candidate)) continue;

			// Validate: walk up to 64 EX_CALLBACK slots (8 bytes each) looking for ourCallback
			PUCHAR arr = (PUCHAR)candidate;
			for (ULONG slot = 0; slot < 64; slot++) {
				PVOID* slotPtr = (PVOID*)(arr + slot * 8);
				if (!MmIsAddressValid(slotPtr)) break;
				PVOID fn = ExCallbackGetFunction(*slotPtr);
				if (fn == ourCallback) return candidate;  // confirmed
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return nullptr;
}

// ---------------------------------------------------------------------------
// EmitPsCallbackAlert — emit a CRITICAL alert for Ps*Notify callback removal.
// ---------------------------------------------------------------------------

static VOID EmitPsCallbackAlert(BufferQueue* bufQueue, const char* msg, PVOID addr)
{
	SIZE_T msgLen = strlen(msg) + 1;
	PKERNEL_STRUCTURED_NOTIFICATION notif =
		(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
			POOL_FLAG_NON_PAGED,
			sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'pscb');
	if (!notif) return;
	RtlZeroMemory(notif, sizeof(*notif));
	SET_CRITICAL(*notif);
	SET_PS_CALLBACK_CHECK(*notif);
	notif->scoopedAddress = (ULONG64)addr;
	RtlCopyMemory(notif->procName, "NortonEDR", 9);
	notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'psmg');
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
// TakeObCallbackSnapshot — called once after ObRegisterCallbacks succeeds.
// Records every PreOp pointer currently registered on PsProcessType and
// PsThreadType.  This becomes the whitelist for periodic integrity checks.
// ---------------------------------------------------------------------------

VOID HookDetector::TakeObCallbackSnapshot()
{
    const struct { const WCHAR* name; ObCallbackSnapshot* snap; } types[] = {
        { L"PsProcessType", &s_ProcessCbSnapshot },
        { L"PsThreadType",  &s_ThreadCbSnapshot  },
    };

    for (int i = 0; i < 2; i++) {
        UNICODE_STRING uName;
        RtlInitUnicodeString(&uName, types[i].name);
        POBJECT_TYPE* ppType = (POBJECT_TYPE*)MmGetSystemRoutineAddress(&uName);
        if (!ppType || !MmIsAddressValid(ppType)) continue;

        RtlZeroMemory(types[i].snap, sizeof(ObCallbackSnapshot));
        types[i].snap->count = CollectCallbackPreOps(
            *ppType,
            types[i].snap->preOpPointers,
            OB_CALLBACK_SNAPSHOT_MAX);

        DbgPrint("[+] HookDetector: %ws snapshot — %lu PreOp entries\n",
            types[i].name, types[i].snap->count);
    }

    s_CbSnapshotTaken = TRUE;
}

// ---------------------------------------------------------------------------
// TakePsCallbackSnapshot — called once after all Ps* callbacks are registered.
// Locates PspCreate*NotifyRoutine[] arrays via LEA scan of Ps*Set*NotifyRoutine*
// functions and records our callback function pointers.
// ---------------------------------------------------------------------------

VOID HookDetector::TakePsCallbackSnapshot()
{
	const struct {
		const WCHAR*       setFnName;    // PsSet*NotifyRoutine* to scan
		const WCHAR*       setFnFallback; // older API if Ex not found (image only)
		PVOID              ourCallback;  // our registered function pointer
		PsCallbackSnapshot* snap;
	} desc[] = {
		{ L"PsSetCreateProcessNotifyRoutineEx", nullptr,
			ProcessUtils::s_NotifyFn,  &s_ProcNotifyCbSnap   },
		{ L"PsSetCreateThreadNotifyRoutineEx",  nullptr,
			ThreadUtils::s_NotifyFn,   &s_ThreadNotifyCbSnap },
		{ L"PsSetLoadImageNotifyRoutineEx",     L"PsSetLoadImageNotifyRoutine",
			ImageUtils::s_NotifyFn,    &s_ImageNotifyCbSnap  },
	};

	for (int i = 0; i < 3; i++) {
		UNICODE_STRING uName;
		RtlInitUnicodeString(&uName, desc[i].setFnName);
		PVOID setFn = MmGetSystemRoutineAddress(&uName);

		if (!setFn && desc[i].setFnFallback) {
			RtlInitUnicodeString(&uName, desc[i].setFnFallback);
			setFn = MmGetSystemRoutineAddress(&uName);
		}

		desc[i].snap->ourCallback = desc[i].ourCallback;
		desc[i].snap->valid       = FALSE;

		if (!setFn) {
			DbgPrint("[-] HookDetector: %ws not found — Ps notify snap skipped\n",
				desc[i].setFnName);
			continue;
		}

		PVOID arr = FindPsNotifyArrayBase(setFn, desc[i].ourCallback);
		if (arr) {
			desc[i].snap->arrayBase = arr;
			desc[i].snap->valid     = TRUE;
			DbgPrint("[+] HookDetector: Ps notify array for %ws at %p\n",
				desc[i].setFnName, arr);
		} else {
			DbgPrint("[-] HookDetector: LEA scan failed for %ws\n", desc[i].setFnName);
		}
	}
}

// ---------------------------------------------------------------------------
// CheckPsCallbackIntegrity — verify our Ps*Notify callbacks are still registered.
// Called on each periodic scan; emits CRITICAL alert if any callback missing.
// ---------------------------------------------------------------------------

VOID HookDetector::CheckPsCallbackIntegrity(BufferQueue* bufQueue)
{
	const struct {
		const char*         label;
		PsCallbackSnapshot* snap;
	} checks[] = {
		{ "Process",     &s_ProcNotifyCbSnap   },
		{ "Thread",      &s_ThreadNotifyCbSnap },
		{ "ImageLoad",   &s_ImageNotifyCbSnap  },
	};

	for (int i = 0; i < 3; i++) {
		PsCallbackSnapshot* snap = checks[i].snap;
		if (!snap->valid || !snap->arrayBase || !snap->ourCallback) continue;

		BOOLEAN found     = FALSE;
		BOOLEAN slotEmpty = TRUE;   // was our slot zeroed (unlink) or replaced (overwrite)?
		PVOID   replacedWith = nullptr;
		PUCHAR arr = (PUCHAR)snap->arrayBase;

		__try {
			for (ULONG slot = 0; slot < 64; slot++) {
				PVOID* slotPtr = (PVOID*)(arr + slot * 8);
				if (!MmIsAddressValid(slotPtr)) break;
				PVOID raw = *slotPtr;
				PVOID fn  = ExCallbackGetFunction(raw);
				if (fn == snap->ourCallback) { found = TRUE; break; }

				// If we find a non-NULL slot with a function pointer that is NOT
				// ours and not NULL, track it — one of these might be an overwrite.
				// We can't know which slot was "ours" by index alone, but if the
				// total live count is the same as at init time but our pointer is
				// missing, the slot was overwritten rather than cleared.
				if (fn && fn != snap->ourCallback) {
					slotEmpty = FALSE;
					replacedWith = fn;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		if (!found) {
			char msg[220];
			if (replacedWith && !slotEmpty) {
				// Slot was replaced with a different function pointer —
				// this is a callback entry overwrite (pointer swap attack).
				RtlStringCbPrintfA(msg, sizeof(msg),
					"ANTI-TAMPER: Ps%sNotify callback OVERWRITTEN — "
					"function pointer replaced (was %p, possible redirect to %p) "
					"— EX_CALLBACK_ROUTINE_BLOCK.Function swap attack",
					checks[i].label, snap->ourCallback, replacedWith);
			} else {
				// Slot is empty — classic unlink (entry removed from array)
				RtlStringCbPrintfA(msg, sizeof(msg),
					"ANTI-TAMPER: Ps%sNotify callback UNLINKED from internal array — "
					"EDR telemetry silenced (PsRemoveCreate*NotifyRoutine or slot zeroed)",
					checks[i].label);
			}
			EmitPsCallbackAlert(bufQueue, msg, snap->ourCallback);
		}
	}
}

// ---------------------------------------------------------------------------
// CheckObCallbackIntegrity — run on each periodic scan.
//
// For each of PsProcessType and PsThreadType:
//
//   1. MISSING check: our own ProcessPreCallback / ThreadPreCallback must still
//      be present.  Absence = EDRSandblast/Terminator unlink attack.
//
//   2. FOREIGN check (requires snapshot): any PreOp pointer NOT in the init-time
//      snapshot is a new registration.  A rogue driver registering after us can
//      use its PreOp to re-strip rights that our PreOp grants (e.g., strip
//      PROCESS_TERMINATE from the EDR's handle to the attacker's process before
//      we see the request, or strip PROCESS_VM_READ from handles to lsass to
//      blind credential-dump detection).  Alert on every unknown entry.
// ---------------------------------------------------------------------------

VOID HookDetector::CheckObCallbackIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue) return;

    struct TypeDesc {
        const WCHAR*       exportName;
        PVOID              expectedPreOp;
        const char*        label;
        ObCallbackSnapshot* snap;
    } checks[] = {
        { L"PsProcessType", (PVOID)ObjectUtils::ProcessPreCallback,
          "Process", &s_ProcessCbSnapshot },
        { L"PsThreadType",  (PVOID)ObjectUtils::ThreadPreCallback,
          "Thread",  &s_ThreadCbSnapshot  },
    };

    for (int i = 0; i < 2; i++) {

        UNICODE_STRING uName;
        RtlInitUnicodeString(&uName, checks[i].exportName);
        POBJECT_TYPE* ppType = (POBJECT_TYPE*)MmGetSystemRoutineAddress(&uName);
        if (!ppType || !MmIsAddressValid(ppType)) continue;

        POBJECT_TYPE objType = *ppType;
        if (!objType || !MmIsAddressValid(objType)) continue;

        // Collect current live PreOp pointers.
        PVOID current[OB_CALLBACK_SNAPSHOT_MAX] = {};
        ULONG currentCount = CollectCallbackPreOps(objType, current, OB_CALLBACK_SNAPSHOT_MAX);

        // --- Check 1: our callback must still be present ---
        BOOLEAN ourFound = FALSE;
        for (ULONG j = 0; j < currentCount; j++) {
            if (current[j] == checks[i].expectedPreOp) { ourFound = TRUE; break; }
        }

        if (!ourFound) {
            DbgPrint("[!] HookDetector: Ob%sCallback unlinked!\n", checks[i].label);
            char msg[180];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ANTI-TAMPER: Ob%sCallback unlinked from OBJECT_TYPE.CallbackList "
                "— EDRSandblast/Terminator-style attack",
                checks[i].label);
            EmitObAlert(bufQueue, msg, checks[i].expectedPreOp);
        } else {
            DbgPrint("[+] HookDetector: Ob%sCallback present\n", checks[i].label);
        }

        // --- Check 2: no unknown PreOp pointers (requires snapshot) ---
        if (!s_CbSnapshotTaken) continue;

        for (ULONG j = 0; j < currentCount; j++) {
            if (IsKnownInSnapshot(current[j], checks[i].snap)) continue;

            // Unknown entry: a driver registered a new callback after our init.
            DbgPrint("[!] HookDetector: foreign Ob%sCallback registered: %p\n",
                checks[i].label, current[j]);

            char msg[220];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ROGUE ObCallback: unknown %s PreOp at %p registered after EDR init "
                "— may strip handle rights from defenders / protect attacker process",
                checks[i].label, current[j]);
            EmitObAlert(bufQueue, msg, current[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// CmRegisterCallback (CmpCallBackVector) integrity verification.
//
// CmpCallBackVector is an array of EX_CALLBACK slots — the same mechanism
// used by PspCreateProcessNotifyRoutine[].  We locate it by scanning
// CmRegisterCallbackEx for LEA [RIP+disp32] instructions, then validate
// by finding our own RegistryUtils::RegOpNotifyCallback in the slots.
//
// RegPhantom rootkit registers a rogue CmRegisterCallback as a covert C2
// channel and can hijack existing callback function pointers.  This check
// detects both attacks.
// ---------------------------------------------------------------------------

// Locate CmpCallBackVector by scanning CmRegisterCallbackEx for LEA instructions.
// Unlike PsNotify where we know our callback pointer, for CmCallbacks we scan
// CmRegisterCallbackEx (or CmUnRegisterCallback) which references CmpCallBackVector.
static PVOID FindCmCallbackArrayBase(PVOID cmRegFn, PVOID ourCallback)
{
    if (!cmRegFn || !MmIsAddressValid(cmRegFn)) return nullptr;

    PUCHAR p = (PUCHAR)cmRegFn;
    __try {
        // Scan a wider range for CmRegisterCallbackEx — it may reference
        // CmpCallBackVector deeper in the function than PsSet* functions.
        for (ULONG i = 0; i < 0x400 - 7; i++) {
            // REX.W prefix (0x48 or 0x4C) + LEA opcode (0x8D) + ModRM
            if ((p[i] != 0x48 && p[i] != 0x4C) || p[i+1] != 0x8D)
                continue;
            BOOLEAN validModRM = FALSE;
            for (ULONG b = 0; b < ARRAYSIZE(g_LeaSecondBytes); b++)
                if (p[i+2] == g_LeaSecondBytes[b]) { validModRM = TRUE; break; }
            if (!validModRM) continue;

            LONG disp = *(LONG*)(p + i + 3);
            PVOID candidate = (PVOID)(p + i + 7 + disp);
            if (!MmIsAddressValid(candidate)) continue;

            // Validate: walk EX_CALLBACK slots looking for our callback
            PUCHAR arr = (PUCHAR)candidate;
            for (ULONG slot = 0; slot < CM_CALLBACK_SNAPSHOT_MAX; slot++) {
                PVOID* slotPtr = (PVOID*)(arr + slot * 8);
                if (!MmIsAddressValid(slotPtr)) break;
                PVOID fn = ExCallbackGetFunction(*slotPtr);
                if (fn == ourCallback) return candidate;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return nullptr;
}

// TakeCmCallbackSnapshot — called once after CmRegisterCallbackEx succeeds.
// Records every callback function pointer in CmpCallBackVector[].

VOID HookDetector::TakeCmCallbackSnapshot()
{
    RtlZeroMemory(&s_CmCbSnap, sizeof(s_CmCbSnap));
    s_CmCbSnap.ourCallback = (PVOID)RegistryUtils::RegOpNotifyCallback;
    s_CmCbSnap.valid       = FALSE;

    // Resolve CmRegisterCallbackEx to scan for CmpCallBackVector
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, L"CmRegisterCallbackEx");
    PVOID cmRegFn = MmGetSystemRoutineAddress(&uName);
    if (!cmRegFn) {
        // Fallback: try CmUnRegisterCallback — it also references the array
        RtlInitUnicodeString(&uName, L"CmUnRegisterCallback");
        cmRegFn = MmGetSystemRoutineAddress(&uName);
    }

    if (!cmRegFn) {
        DbgPrint("[-] HookDetector: CmRegisterCallbackEx not found\n");
        return;
    }

    PVOID arr = FindCmCallbackArrayBase(cmRegFn, s_CmCbSnap.ourCallback);
    if (!arr) {
        DbgPrint("[-] HookDetector: CmpCallBackVector LEA scan failed\n");
        return;
    }

    s_CmCbSnap.arrayBase = arr;
    s_CmCbSnap.valid     = TRUE;

    // Snapshot all currently-registered callback function pointers
    __try {
        PUCHAR base = (PUCHAR)arr;
        for (ULONG slot = 0; slot < CM_CALLBACK_SNAPSHOT_MAX; slot++) {
            PVOID* slotPtr = (PVOID*)(base + slot * 8);
            if (!MmIsAddressValid(slotPtr)) break;
            PVOID fn = ExCallbackGetFunction(*slotPtr);
            if (fn) {
                s_CmCbSnap.callbacks[s_CmCbSnap.count++] = fn;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    DbgPrint("[+] HookDetector: CmCallback snapshot — %lu entries, array at %p\n",
        s_CmCbSnap.count, arr);
}

// Emit alert helper for CmCallback integrity issues.
static VOID EmitCmCallbackAlert(BufferQueue* bufQueue, const char* msg,
                                PVOID addr, BOOLEAN isCritical)
{
    SIZE_T msgLen = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'cmcb');
    if (!notif) return;
    RtlZeroMemory(notif, sizeof(*notif));
    if (isCritical) { SET_CRITICAL(*notif); }
    else            { SET_WARNING(*notif);  }
    SET_CM_CALLBACK_CHECK(*notif);
    notif->scoopedAddress = (ULONG64)addr;
    RtlCopyMemory(notif->procName, "NortonEDR", 9);
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'cmmg');
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

// CheckCmCallbackIntegrity — periodic verification of CmpCallBackVector[].
//
// Three checks:
//   1. OUR callback must still be present (unlink detection)
//   2. No NEW callbacks registered after init (rogue callback / RegPhantom C2)
//   3. No EXISTING callback function pointers changed (hijack detection)

VOID HookDetector::CheckCmCallbackIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue || !s_CmCbSnap.valid || !s_CmCbSnap.arrayBase)
        return;

    // Collect current live callback function pointers
    PVOID current[CM_CALLBACK_SNAPSHOT_MAX] = {};
    ULONG currentCount = 0;

    __try {
        PUCHAR base = (PUCHAR)s_CmCbSnap.arrayBase;
        for (ULONG slot = 0; slot < CM_CALLBACK_SNAPSHOT_MAX; slot++) {
            PVOID* slotPtr = (PVOID*)(base + slot * 8);
            if (!MmIsAddressValid(slotPtr)) break;
            PVOID fn = ExCallbackGetFunction(*slotPtr);
            if (fn) current[currentCount++] = fn;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] HookDetector: exception reading CmpCallBackVector\n");
        return;
    }

    // --- Check 1: our callback must still be present ---
    BOOLEAN ourFound = FALSE;
    for (ULONG i = 0; i < currentCount; i++) {
        if (current[i] == s_CmCbSnap.ourCallback) { ourFound = TRUE; break; }
    }

    if (!ourFound) {
        char msg[200];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ANTI-TAMPER: CmRegisterCallback unlinked from CmpCallBackVector "
            "-- EDR registry monitoring silenced (RegPhantom/rootkit attack)");
        EmitCmCallbackAlert(bufQueue, msg, s_CmCbSnap.ourCallback, TRUE);
    }

    // --- Check 2: detect new (foreign) callbacks not in snapshot ---
    for (ULONG i = 0; i < currentCount; i++) {
        BOOLEAN known = FALSE;
        for (ULONG j = 0; j < s_CmCbSnap.count; j++) {
            if (current[i] == s_CmCbSnap.callbacks[j]) { known = TRUE; break; }
        }
        if (!known) {
            char msg[220];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ROGUE CmCallback: unknown registry callback at %p registered after "
                "EDR init -- possible RegPhantom C2 channel or rootkit hook",
                current[i]);
            EmitCmCallbackAlert(bufQueue, msg, current[i], TRUE);
        }
    }

    // --- Check 3: detect removed/replaced callbacks (hijack) ---
    for (ULONG i = 0; i < s_CmCbSnap.count; i++) {
        BOOLEAN stillPresent = FALSE;
        for (ULONG j = 0; j < currentCount; j++) {
            if (s_CmCbSnap.callbacks[i] == current[j]) { stillPresent = TRUE; break; }
        }
        if (!stillPresent && s_CmCbSnap.callbacks[i] != s_CmCbSnap.ourCallback) {
            // A callback from our snapshot disappeared — possible hijack where the
            // function pointer was swapped (RegPhantom XOR-encoded pointer technique)
            char msg[220];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "CmCallback HIJACK: init-time callback %p no longer in CmpCallBackVector "
                "-- function pointer may have been replaced (RegPhantom technique)",
                s_CmCbSnap.callbacks[i]);
            EmitCmCallbackAlert(bufQueue, msg, s_CmCbSnap.callbacks[i], TRUE);
        }
    }

    DbgPrint("[+] HookDetector: CmCallback check done — live=%lu snapshot=%lu our=%s\n",
        currentCount, s_CmCbSnap.count, ourFound ? "present" : "MISSING");
}

// ---------------------------------------------------------------------------
// TakeCiBaseline — snapshot CI.dll's executable code section at init time.
// ---------------------------------------------------------------------------

VOID HookDetector::TakeCiBaseline() {
    ULONG modSize = 0;
    PVOID ciBase = FindKernelModuleBase(L"CI.dll", &modSize);
    if (!ciBase || !modSize) {
        DbgPrint("[-] HookDetector: CI.dll not found in loaded module list\n");
        return;
    }

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ciBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ciBase + dos->e_lfanew);
        if (!MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) return;

        // Find the first executable section (typically .text or PAGE)
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!MmIsAddressValid(&sec[i])) break;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                s_CiTextBase = (PVOID)((PUCHAR)ciBase + sec[i].VirtualAddress);
                s_CiTextSize = *(PULONG)&sec[i].Misc;  // Access Misc union as VirtualSize
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (!s_CiTextBase || !s_CiTextSize) {
        DbgPrint("[-] HookDetector: CI.dll executable section not found\n");
        return;
    }

    // SHA256 hash the executable section
    __try {
        SHA256_CTX ctx;
        SHA256Init(&ctx);
        SIZE_T remaining = s_CiTextSize;
        BYTE* ptr = (BYTE*)s_CiTextBase;
        while (remaining > 0) {
            SIZE_T chunk = min(remaining, (SIZE_T)4096);
            if (!MmIsAddressValid(ptr)) break;
            SHA256Update(&ctx, ptr, chunk);
            ptr += chunk;
            remaining -= chunk;
        }
        SHA256Final(s_CiTextHash, &ctx);
        s_CiBaselineValid = TRUE;
        DbgPrint("[+] HookDetector: CI.dll baseline captured (%p, %llu bytes)\n",
            s_CiTextBase, (ULONG64)s_CiTextSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] HookDetector: exception hashing CI.dll\n");
    }
}

// ---------------------------------------------------------------------------
// CheckCiIntegrity — re-hash CI.dll code section and compare to baseline.
// A mismatch means g_CiOptions was patched or a function was inline-hooked,
// both of which are BYOVD attack signatures to disable driver signing.
// ---------------------------------------------------------------------------

VOID HookDetector::CheckCiIntegrity(BufferQueue* bufQueue) {
    if (!s_CiBaselineValid || !s_CiTextBase || !s_CiTextSize || !bufQueue)
        return;

    BYTE rehash[SHA256_BLOCK_SIZE] = {};
    BOOLEAN hashed = FALSE;

    __try {
        SHA256_CTX ctx;
        SHA256Init(&ctx);
        SIZE_T remaining = s_CiTextSize;
        BYTE* ptr = (BYTE*)s_CiTextBase;
        while (remaining > 0) {
            SIZE_T chunk = min(remaining, (SIZE_T)4096);
            if (!MmIsAddressValid(ptr)) break;
            SHA256Update(&ctx, ptr, chunk);
            ptr += chunk;
            remaining -= chunk;
        }
        SHA256Final(rehash, &ctx);
        hashed = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!hashed) return;

    if (RtlCompareMemory(s_CiTextHash, rehash, SHA256_BLOCK_SIZE)
        != SHA256_BLOCK_SIZE)
    {
        DbgPrint("[!] HookDetector: CI.dll code section MODIFIED!\n");

        const char* msg =
            "ANTI-TAMPER: CI.dll code section modified — "
            "g_CiOptions patch or inline hook (BYOVD driver signing bypass)";
        SIZE_T msgLen = strlen(msg) + 1;

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'cint');
        if (notif) {
            RtlZeroMemory(notif, sizeof(*notif));
            SET_CRITICAL(*notif);
            SET_CI_INTEGRITY_CHECK(*notif);
            notif->scoopedAddress = (ULONG64)s_CiTextBase;
            RtlCopyMemory(notif->procName, "NortonEDR", 9);
            notif->msg = (char*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, msgLen, 'cimg');
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

        // Update baseline so we don't spam on every scan cycle
        RtlCopyMemory(s_CiTextHash, rehash, SHA256_BLOCK_SIZE);
    }
}

// ---------------------------------------------------------------------------
// SeCiCallbacks integrity — detect callback table overwrite in ntoskrnl.
//
// When CI.dll initialises, it registers validation callbacks into ntoskrnl's
// SeCiCallbacks table.  ntoskrnl functions like SeValidateImageHeader dispatch
// through this table via indirect calls (call [rip+disp32]).
//
// An attacker (BYOVD, rootkit) can overwrite these function pointers to
// redirect CI validation to a stub that always returns STATUS_SUCCESS —
// bypassing STATUS_INVALID_IMAGE_HASH without modifying CI.dll itself.
//
// Detection: resolve SeValidateImageHeader (exported by ntoskrnl), scan its
// prologue for FF 15 xx xx xx xx (call [rip+disp32]) instructions, compute
// the indirect target (= SeCiCallbacks entry), read the stored function
// pointer, and verify it falls within CI.dll's image range.
//
// Baseline: snapshot the callback addresses at init.  Periodically re-read
// and compare — any change = callback table tampered.
// ---------------------------------------------------------------------------

#define MAX_SECI_CALLBACKS 8

struct SeCiCallbackEntry {
    PVOID* tableSlot;      // address of the function pointer in ntoskrnl
    PVOID  expectedTarget; // CI.dll function address captured at baseline
    BOOLEAN used;
};

static SeCiCallbackEntry s_SeCiEntries[MAX_SECI_CALLBACKS] = {};
static ULONG             s_SeCiEntryCount = 0;
static PVOID             s_CiImageBase    = nullptr;
static ULONG             s_CiImageSize    = 0;
static BOOLEAN           s_SeCiBaselineValid = FALSE;

// Scan the first scanLen bytes of a function for FF 15 (call [rip+disp32])
// instructions whose indirect target falls in kernel address space.
// Records each discovered callback slot into s_SeCiEntries.
static VOID ScanForIndirectCalls(PUCHAR funcBase, SIZE_T scanLen)
{
    for (SIZE_T off = 0; off + 6 <= scanLen; off++) {
        if (funcBase[off] != 0xFF || funcBase[off + 1] != 0x15)
            continue;

        // RIP-relative disp32 — target = &funcBase[off+6] + (signed)disp32
        LONG disp32 = *(LONG*)(&funcBase[off + 2]);
        PVOID* slot = (PVOID*)((PUCHAR)&funcBase[off + 6] + disp32);

        if (!MmIsAddressValid(slot)) continue;

        // The slot should point into kernel space (CI.dll is a kernel module)
        PVOID target = *slot;
        if (!target || (ULONG_PTR)target < 0xFFFF800000000000ULL)
            continue;

        if (s_SeCiEntryCount < MAX_SECI_CALLBACKS) {
            s_SeCiEntries[s_SeCiEntryCount].tableSlot     = slot;
            s_SeCiEntries[s_SeCiEntryCount].expectedTarget = target;
            s_SeCiEntries[s_SeCiEntryCount].used           = TRUE;
            s_SeCiEntryCount++;
        }

        off += 5; // skip past this instruction
    }
}

VOID HookDetector::TakeSeCiCallbackBaseline()
{
    // Get CI.dll image range
    ULONG ciSize = 0;
    PVOID ciBase = FindKernelModuleBase(L"CI.dll", &ciSize);
    if (!ciBase || !ciSize) {
        DbgPrint("[-] SeCiCallback: CI.dll not found\n");
        return;
    }
    s_CiImageBase = ciBase;
    s_CiImageSize = ciSize;

    // Resolve SeValidateImageHeader and SeValidateImageData from ntoskrnl
    static const WCHAR* kFuncNames[] = {
        L"SeValidateImageHeader",
        L"SeValidateImageData",
        nullptr
    };

    __try {
        for (int i = 0; kFuncNames[i]; i++) {
            UNICODE_STRING uName;
            RtlInitUnicodeString(&uName, kFuncNames[i]);
            PVOID func = MmGetSystemRoutineAddress(&uName);
            if (!func || !MmIsAddressValid(func)) continue;

            // Scan first 128 bytes for indirect call targets
            ScanForIndirectCalls((PUCHAR)func, 128);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] SeCiCallback: exception during baseline scan\n");
        return;
    }

    if (s_SeCiEntryCount > 0) {
        s_SeCiBaselineValid = TRUE;
        DbgPrint("[+] SeCiCallback: baseline captured — %lu callback slots tracked\n",
            s_SeCiEntryCount);
        for (ULONG i = 0; i < s_SeCiEntryCount; i++) {
            DbgPrint("    slot[%lu]: %p → %p %s\n", i,
                s_SeCiEntries[i].tableSlot,
                s_SeCiEntries[i].expectedTarget,
                ((ULONG_PTR)s_SeCiEntries[i].expectedTarget >= (ULONG_PTR)ciBase &&
                 (ULONG_PTR)s_SeCiEntries[i].expectedTarget < (ULONG_PTR)ciBase + ciSize)
                    ? "(in CI.dll)" : "(OUTSIDE CI.dll!)");
        }
    } else {
        DbgPrint("[-] SeCiCallback: no indirect call targets found in Se*Validate* stubs\n");
    }
}

VOID HookDetector::CheckSeCiCallbackIntegrity(BufferQueue* bufQueue)
{
    if (!s_SeCiBaselineValid || !bufQueue || !s_CiImageBase) return;

    __try {
        for (ULONG i = 0; i < s_SeCiEntryCount; i++) {
            if (!s_SeCiEntries[i].used) continue;
            if (!MmIsAddressValid(s_SeCiEntries[i].tableSlot)) continue;

            PVOID current = *(s_SeCiEntries[i].tableSlot);

            // Check 1: callback changed from baseline
            if (current != s_SeCiEntries[i].expectedTarget) {
                char msg[300];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "ANTI-TAMPER: SeCiCallbacks[%lu] at %p changed from %p to %p — "
                    "CI validation callback redirected (STATUS_INVALID_IMAGE_HASH bypass)",
                    i, s_SeCiEntries[i].tableSlot,
                    s_SeCiEntries[i].expectedTarget, current);

                SIZE_T msgLen = strlen(msg) + 1;
                PKERNEL_STRUCTURED_NOTIFICATION notif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'seci');
                if (notif) {
                    RtlZeroMemory(notif, sizeof(*notif));
                    SET_CRITICAL(*notif);
                    SET_CI_INTEGRITY_CHECK(*notif);
                    notif->scoopedAddress = (ULONG64)current;
                    notif->isPath = FALSE;
                    RtlCopyMemory(notif->procName, "NortonEDR", 9);
                    notif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, msgLen, 'scim');
                    if (notif->msg) {
                        RtlCopyMemory(notif->msg, msg, msgLen);
                        notif->bufSize = (ULONG)msgLen;
                        if (!bufQueue->Enqueue(notif)) {
                            ExFreePool(notif->msg);
                            ExFreePool(notif);
                        }
                    } else { ExFreePool(notif); }
                }

                // Update baseline to avoid re-alerting
                s_SeCiEntries[i].expectedTarget = current;
            }

            // Check 2: callback points outside CI.dll image range
            if (current &&
                ((ULONG_PTR)current < (ULONG_PTR)s_CiImageBase ||
                 (ULONG_PTR)current >= (ULONG_PTR)s_CiImageBase + s_CiImageSize))
            {
                char msg[300];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "ANTI-TAMPER: SeCiCallbacks[%lu] target %p is OUTSIDE CI.dll "
                    "(%p–%p) — callback hijacked to attacker code",
                    i, current, s_CiImageBase,
                    (PVOID)((ULONG_PTR)s_CiImageBase + s_CiImageSize));

                SIZE_T msgLen = strlen(msg) + 1;
                PKERNEL_STRUCTURED_NOTIFICATION notif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'seci');
                if (notif) {
                    RtlZeroMemory(notif, sizeof(*notif));
                    SET_CRITICAL(*notif);
                    SET_CI_INTEGRITY_CHECK(*notif);
                    notif->scoopedAddress = (ULONG64)current;
                    notif->isPath = FALSE;
                    RtlCopyMemory(notif->procName, "NortonEDR", 9);
                    notif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, msgLen, 'scim');
                    if (notif->msg) {
                        RtlCopyMemory(notif->msg, msg, msgLen);
                        notif->bufSize = (ULONG)msgLen;
                        if (!bufQueue->Enqueue(notif)) {
                            ExFreePool(notif->msg);
                            ExFreePool(notif);
                        }
                    } else { ExFreePool(notif); }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] SeCiCallback: exception during integrity check\n");
    }
}

// ---------------------------------------------------------------------------
// TakeEprocessProtBaseline — snapshot protection levels of sensitive OS
// processes (lsass, csrss, etc.) for periodic downgrade detection.
// Must be called at PASSIVE_LEVEL.
// ---------------------------------------------------------------------------

VOID HookDetector::TakeEprocessProtBaseline() {
    ULONG bufSize = 0;
    ZwQuerySystemInformation(5, nullptr, 0, &bufSize);
    if (!bufSize) return;
    bufSize += 4096; // headroom for race

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'eprt');
    if (!buffer) return;

    if (!NT_SUCCESS(ZwQuerySystemInformation(5, buffer, bufSize, nullptr))) {
        ExFreePool(buffer);
        return;
    }

    ULONG watchIdx = 0;
    PSYSTEM_PROCESS_INFORMATION p = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (watchIdx < MAX_PROT_WATCH) {
        if (p->UniqueProcessId != 0) {
            PEPROCESS proc = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    p->UniqueProcessId, &proc))) {
                char* name = PsGetProcessImageFileName(proc);
                if (name && IsProtWatchTarget(name)) {
                    PPS_PROTECTION prot = PsGetProcessProtection(proc);
                    PUCHAR eproc = (PUCHAR)proc;
                    g_ProtWatch[watchIdx].pid = HandleToUlong(p->UniqueProcessId);
                    g_ProtWatch[watchIdx].initialLevel =
                        prot ? prot->Level : 0;
                    g_ProtWatch[watchIdx].initialSigLevel =
                        *(UCHAR*)(eproc + EPROCESS_SIGNATURE_LEVEL);
                    g_ProtWatch[watchIdx].initialSectSigLevel =
                        *(UCHAR*)(eproc + EPROCESS_SECTION_SIGNATURE_LEVEL);
                    char lower[16] = {};
                    for (int i = 0; i < 15 && name[i]; i++)
                        lower[i] = (name[i] >= 'A' && name[i] <= 'Z')
                            ? name[i] + 32 : name[i];
                    RtlCopyMemory(g_ProtWatch[watchIdx].name, lower, 16);
                    g_ProtWatch[watchIdx].active = TRUE;
                    watchIdx++;
                    DbgPrint("[+] HookDetector: EPROCESS prot snap — %s pid=%lu "
                        "level=0x%02X sigLvl=0x%02X sectSigLvl=0x%02X\n",
                        lower, HandleToUlong(p->UniqueProcessId),
                        prot ? prot->Level : 0,
                        g_ProtWatch[watchIdx - 1].initialSigLevel,
                        g_ProtWatch[watchIdx - 1].initialSectSigLevel);
                }
                ObDereferenceObject(proc);
            }
        }
        if (!p->NextEntryOffset) break;
        p = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)p + p->NextEntryOffset);
    }

    ExFreePool(buffer);
    DbgPrint("[+] HookDetector: EPROCESS protection baseline — %lu processes\n",
        watchIdx);
}

// ---------------------------------------------------------------------------
// CheckEprocessProtection — verify PPL levels and signature levels haven't
// been downgraded.  mimidrv zeroes Protection.Level (PPL strip) AND
// SignatureLevel / SectionSignatureLevel (CI policy bypass for unsigned DLL
// injection into lsass).  All three fields are checked.
// ---------------------------------------------------------------------------

// Helper: emit a CRITICAL EPROCESS-tamper alert.
static VOID EmitEprocessTamperAlert(BufferQueue* bufQueue, ProtWatchEntry* entry,
                                     const char* msg) {
    SIZE_T msgLen = strlen(msg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'epnt');
    if (!notif) return;
    RtlZeroMemory(notif, sizeof(*notif));
    SET_CRITICAL(*notif);
    SET_EPROCESS_PROT_CHECK(*notif);
    notif->pid = (HANDLE)(ULONG_PTR)entry->pid;
    RtlCopyMemory(notif->procName, entry->name, 15);
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'epmg');
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

VOID HookDetector::CheckEprocessProtection(BufferQueue* bufQueue) {
    if (!bufQueue) return;

    for (int i = 0; i < MAX_PROT_WATCH; i++) {
        if (!g_ProtWatch[i].active) continue;

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)g_ProtWatch[i].pid, &proc))) {
            g_ProtWatch[i].active = FALSE; // process exited
            continue;
        }

        PPS_PROTECTION prot = PsGetProcessProtection(proc);
        UCHAR currentLevel = prot ? prot->Level : 0;
        PUCHAR eproc = (PUCHAR)proc;
        UCHAR currentSigLevel = *(UCHAR*)(eproc + EPROCESS_SIGNATURE_LEVEL);
        UCHAR currentSectSigLevel = *(UCHAR*)(eproc + EPROCESS_SECTION_SIGNATURE_LEVEL);
        ObDereferenceObject(proc);

        // Check 1: PS_PROTECTION.Level downgrade (PPL strip)
        if (g_ProtWatch[i].initialLevel > 0 &&
            currentLevel < g_ProtWatch[i].initialLevel)
        {
            char msg[256];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ANTI-TAMPER: %s (pid=%lu) protection downgraded 0x%02X->0x%02X — "
                "BYOVD PPL-strip (EPROCESS.Protection zeroed, mimidrv technique)",
                g_ProtWatch[i].name, g_ProtWatch[i].pid,
                g_ProtWatch[i].initialLevel, currentLevel);
            EmitEprocessTamperAlert(bufQueue, &g_ProtWatch[i], msg);
            g_ProtWatch[i].initialLevel = currentLevel;
        }

        // Check 2: SignatureLevel downgrade — mimidrv zeros this to bypass CI
        // enforcement, allowing unsigned code to run in the target process.
        if (g_ProtWatch[i].initialSigLevel > 0 &&
            currentSigLevel < g_ProtWatch[i].initialSigLevel)
        {
            char msg[256];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ANTI-TAMPER: %s (pid=%lu) SignatureLevel downgraded 0x%02X->0x%02X — "
                "CI policy bypass (mimidrv / PPLmedic technique)",
                g_ProtWatch[i].name, g_ProtWatch[i].pid,
                g_ProtWatch[i].initialSigLevel, currentSigLevel);
            EmitEprocessTamperAlert(bufQueue, &g_ProtWatch[i], msg);
            g_ProtWatch[i].initialSigLevel = currentSigLevel;
        }

        // Check 3: SectionSignatureLevel downgrade — allows unsigned DLL loading
        // into the target process (credential dumping DLL into lsass).
        if (g_ProtWatch[i].initialSectSigLevel > 0 &&
            currentSectSigLevel < g_ProtWatch[i].initialSectSigLevel)
        {
            char msg[256];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ANTI-TAMPER: %s (pid=%lu) SectionSignatureLevel downgraded 0x%02X->0x%02X — "
                "unsigned DLL injection enabled (mimidrv credential dump technique)",
                g_ProtWatch[i].name, g_ProtWatch[i].pid,
                g_ProtWatch[i].initialSectSigLevel, currentSectSigLevel);
            EmitEprocessTamperAlert(bufQueue, &g_ProtWatch[i], msg);
            g_ProtWatch[i].initialSectSigLevel = currentSectSigLevel;
        }
    }
}

// ---------------------------------------------------------------------------
// Skeleton Key detection — periodic re-hash of lsass authentication DLLs.
//
// Mimikatz misc::skeleton patches msv1_0.dll (MsvpPasswordValidate) and
// kerberos.dll code in the lsass process to accept a master password.
// The phantom DLL hash only covers 200ms post-load; Skeleton Key patches
// happen hours later via mimidrv IOCTL.  We keep a permanent baseline hash
// of each auth DLL's mapped image and re-verify every 30 seconds.
// ---------------------------------------------------------------------------

#define MAX_LSASS_AUTH_DLLS 8

struct LsassAuthDllEntry {
    ULONG   lsassPid;
    PVOID   imageBase;
    SIZE_T  imageSize;
    BYTE    baselineHash[SHA256_BLOCK_SIZE];
    char    dllName[32];
    BOOLEAN active;
};

static LsassAuthDllEntry g_LsassAuthDlls[MAX_LSASS_AUTH_DLLS] = {};
static KSPIN_LOCK        g_LsassAuthLock;
static BOOLEAN           g_LsassAuthInitialized = FALSE;

// Called from Images.cpp ImageLoadNotifyRoutine when an auth DLL loads into lsass.
VOID HookDetector::RecordLsassAuthDll(ULONG pid, PVOID imageBase, SIZE_T imageSize,
                                       const BYTE* hash, const char* name) {
    KIRQL irql;
    KeAcquireSpinLock(&g_LsassAuthLock, &irql);
    for (int i = 0; i < MAX_LSASS_AUTH_DLLS; i++) {
        if (!g_LsassAuthDlls[i].active) {
            g_LsassAuthDlls[i].lsassPid = pid;
            g_LsassAuthDlls[i].imageBase = imageBase;
            g_LsassAuthDlls[i].imageSize = imageSize;
            RtlCopyMemory(g_LsassAuthDlls[i].baselineHash, hash, SHA256_BLOCK_SIZE);
            RtlStringCbCopyA(g_LsassAuthDlls[i].dllName,
                sizeof(g_LsassAuthDlls[i].dllName), name);
            g_LsassAuthDlls[i].active = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_LsassAuthLock, irql);
}

// Periodic check — called from RunAllHookChecks every 30 seconds.
// Re-attaches to lsass and re-hashes each auth DLL, comparing to baseline.
VOID HookDetector::CheckLsassAuthDllIntegrity(BufferQueue* bufQueue) {
    if (!bufQueue) return;

    for (int i = 0; i < MAX_LSASS_AUTH_DLLS; i++) {
        if (!g_LsassAuthDlls[i].active) continue;

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)g_LsassAuthDlls[i].lsassPid, &proc))) {
            g_LsassAuthDlls[i].active = FALSE; // lsass exited — shouldn't happen
            continue;
        }

        BYTE rehash[SHA256_BLOCK_SIZE] = {};
        BOOLEAN hashed = FALSE;

        KAPC_STATE apcState;
        KeStackAttachProcess(proc, &apcState);
        __try {
            SHA256_CTX ctx;
            SHA256Init(&ctx);
            SIZE_T remaining = g_LsassAuthDlls[i].imageSize;
            BYTE* ptr = (BYTE*)g_LsassAuthDlls[i].imageBase;
            while (remaining > 0) {
                SIZE_T chunk = min(remaining, (SIZE_T)4096);
                if (!MmIsAddressValid(ptr)) break;
                SHA256Update(&ctx, ptr, chunk);
                ptr += chunk;
                remaining -= chunk;
            }
            SHA256Final(rehash, &ctx);
            hashed = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(proc);

        if (!hashed) continue;

        if (RtlCompareMemory(g_LsassAuthDlls[i].baselineHash,
                rehash, SHA256_BLOCK_SIZE) != SHA256_BLOCK_SIZE) {
            // MISMATCH — Skeleton Key or code patch detected!
            char msg[256];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "SKELETON KEY: %s code modified in lsass (pid=%lu) — "
                "Mimikatz misc::skeleton authentication backdoor detected",
                g_LsassAuthDlls[i].dllName, g_LsassAuthDlls[i].lsassPid);

            SIZE_T msgLen = strlen(msg) + 1;
            PKERNEL_STRUCTURED_NOTIFICATION notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'skel');
            if (notif) {
                RtlZeroMemory(notif, sizeof(*notif));
                SET_CRITICAL(*notif);
                SET_IMAGE_LOAD_PATH_CHECK(*notif);
                notif->pid = (HANDLE)(ULONG_PTR)g_LsassAuthDlls[i].lsassPid;
                RtlStringCbCopyA(notif->procName, sizeof(notif->procName), "lsass.exe");
                notif->msg = (char*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, msgLen, 'skmg');
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

            // Update baseline so we fire once per modification
            RtlCopyMemory(g_LsassAuthDlls[i].baselineHash,
                rehash, SHA256_BLOCK_SIZE);
        }
    }
}

void HookDetector::InitLsassAuthLock() {
    KeInitializeSpinLock(&g_LsassAuthLock);
    g_LsassAuthInitialized = TRUE;
}

// ---------------------------------------------------------------------------
// MajorFunction dispatch table integrity — detect BYOVD patching of our
// IRP_MJ_DEVICE_CONTROL handler.  An attacker with kernel write can redirect
// or NOP our IOCTL dispatcher, silencing all user-kernel communication.
// ---------------------------------------------------------------------------

static PDRIVER_OBJECT s_DriverObj              = nullptr;
static PVOID          s_MajorFnBaseline[IRP_MJ_MAXIMUM_FUNCTION + 1] = {};
static BOOLEAN        s_MajorFnBaselineValid   = FALSE;

VOID HookDetector::TakeMajorFunctionBaseline(PDRIVER_OBJECT drvObj)
{
    if (!drvObj) return;
    s_DriverObj = drvObj;
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        s_MajorFnBaseline[i] = (PVOID)drvObj->MajorFunction[i];
    s_MajorFnBaselineValid = TRUE;
    DbgPrint("[+] HookDetector: MajorFunction baseline captured\n");
}

VOID HookDetector::CheckMajorFunctionIntegrity(BufferQueue* bufQueue)
{
    if (!s_MajorFnBaselineValid || !s_DriverObj || !bufQueue) return;

    // Check the three dispatch entries we actually set
    static const struct { int idx; const char* name; } kChecks[] = {
        { IRP_MJ_CREATE,         "IRP_MJ_CREATE" },
        { IRP_MJ_CLOSE,          "IRP_MJ_CLOSE" },
        { IRP_MJ_DEVICE_CONTROL, "IRP_MJ_DEVICE_CONTROL" },
    };

    for (int c = 0; c < 3; c++) {
        PVOID current  = (PVOID)s_DriverObj->MajorFunction[kChecks[c].idx];
        PVOID expected = s_MajorFnBaseline[kChecks[c].idx];
        if (current == expected) continue;

        char msg[200];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ANTI-TAMPER: NortonEDR %s handler patched %p->%p "
            "— BYOVD dispatch table overwrite (IOCTL silencing attack)",
            kChecks[c].name, expected, current);

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'mfnt');
        if (notif) {
            RtlZeroMemory(notif, sizeof(*notif));
            SET_CRITICAL(*notif);
            notif->pid    = 0;
            notif->isPath = FALSE;
            RtlCopyMemory(notif->procName, "NortonEDR", 9);
            SIZE_T msgLen = strlen(msg) + 1;
            notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'mfmg');
            notif->bufSize = (ULONG)msgLen;
            if (notif->msg) {
                RtlCopyMemory(notif->msg, msg, msgLen);
                if (!bufQueue->Enqueue(notif)) {
                    ExFreePool(notif->msg); ExFreePool(notif);
                }
            } else { ExFreePool(notif); }
        }

        // Restore the original handler
        InterlockedExchangePointer(
            (PVOID*)&s_DriverObj->MajorFunction[kChecks[c].idx], expected);
        DbgPrint("[!] HookDetector: restored %s handler\n", kChecks[c].name);
    }
}

// ---------------------------------------------------------------------------
// Callback prologue integrity — detect inline hooks on our own callbacks.
//
// A BYOVD attacker can keep all callback pointers intact but patch the first
// bytes of our callback function body with a JMP to a NOP/RET stub.  All
// pointer-based integrity checks pass, but the callback does nothing.
//
// Defense: baseline the first 16 bytes of each callback at init, re-verify
// every 30s.  If the prologue is modified, alert and restore the original bytes.
// ---------------------------------------------------------------------------

#define CB_PROLOGUE_SIZE 16
#define MAX_CB_PROLOGUE_ENTRIES 24

struct CbPrologueEntry {
    PVOID       address;              // function entry point
    BYTE        baseline[CB_PROLOGUE_SIZE];  // original prologue bytes
    const char* name;                 // human-readable label
    BOOLEAN     active;
};

static CbPrologueEntry s_CbPrologues[MAX_CB_PROLOGUE_ENTRIES] = {};
static ULONG            s_CbPrologueCount = 0;

static VOID RecordCbPrologue(PVOID fn, const char* name) {
    if (!fn || s_CbPrologueCount >= MAX_CB_PROLOGUE_ENTRIES) return;
    CbPrologueEntry& e = s_CbPrologues[s_CbPrologueCount];
    e.address = fn;
    e.name    = name;
    e.active  = TRUE;
    __try {
        RtlCopyMemory(e.baseline, fn, CB_PROLOGUE_SIZE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        e.active = FALSE;
        return;
    }
    s_CbPrologueCount++;
}

VOID HookDetector::TakeCallbackPrologueBaseline()
{
    s_CbPrologueCount = 0;

    // Kernel callbacks — the functions registered via Ob/Ps/Cm APIs
    RecordCbPrologue((PVOID)ObjectUtils::ProcessPreCallback,
                     "ObProcessPreCallback");
    RecordCbPrologue((PVOID)ObjectUtils::ThreadPreCallback,
                     "ObThreadPreCallback");
    RecordCbPrologue((PVOID)RegistryUtils::RegOpNotifyCallback,
                     "CmRegOpNotifyCallback");

    // Ps*Notify callbacks
    RecordCbPrologue(ProcessUtils::s_NotifyFn,
                     "PsProcessNotify");
    RecordCbPrologue(ThreadUtils::s_NotifyFn,
                     "PsThreadNotify");
    RecordCbPrologue(ImageUtils::s_NotifyFn,
                     "PsImageLoadNotify");

    // The IOCTL dispatch handler
    extern NTSTATUS DriverIoControl(PDEVICE_OBJECT, PIRP);
    RecordCbPrologue((PVOID)DriverIoControl,
                     "DriverIoControl");

    // WPP/ETW kernel APIs — malicious drivers (BYOVD) hook these to intercept
    // or block WPP provider registration/deregistration calls (T1562.002).
    // IoWMIRegistrationControl is the kernel API for WPP provider reg/dereg;
    // EtwRegister/EtwUnregister manage ETW provider lifecycle.
    // WmiTraceMessage is the core WPP trace emission function.
    {
        UNICODE_STRING fnNames[] = {
            RTL_CONSTANT_STRING(L"IoWMIRegistrationControl"),
            RTL_CONSTANT_STRING(L"EtwRegister"),
            RTL_CONSTANT_STRING(L"EtwUnregister"),
            RTL_CONSTANT_STRING(L"WmiTraceMessage"),
            RTL_CONSTANT_STRING(L"EtwWrite"),
            RTL_CONSTANT_STRING(L"EtwWriteEx"),
            // TraceLogging-specific: EtwEventWriteTransfer is the primary
            // write API for self-describing TraceLogging providers.
            RTL_CONSTANT_STRING(L"EtwEventWriteTransfer"),
            // EtwEventWriteNoRegistration allows events without prior
            // EtwRegister — TraceLogging fallback path.
            RTL_CONSTANT_STRING(L"EtwEventWriteNoRegistration"),
            // TraceLoggingRegister/Unregister are thin wrappers over
            // EtwRegister that target only TraceLogging providers.
            RTL_CONSTANT_STRING(L"TraceLoggingRegister"),
            RTL_CONSTANT_STRING(L"TraceLoggingUnregister"),
        };
        const char* fnLabels[] = {
            "IoWMIRegistrationControl",
            "EtwRegister",
            "EtwUnregister",
            "WmiTraceMessage",
            "EtwWrite",
            "EtwWriteEx",
            "EtwEventWriteTransfer",
            "EtwEventWriteNoRegistration",
            "TraceLoggingRegister",
            "TraceLoggingUnregister",
        };
        for (ULONG fi = 0; fi < ARRAYSIZE(fnNames); fi++) {
            PVOID addr = MmGetSystemRoutineAddress(&fnNames[fi]);
            if (addr) {
                RecordCbPrologue(addr, fnLabels[fi]);
            }
        }
    }

    DbgPrint("[+] HookDetector: callback prologue baseline captured (%lu entries)\n",
        s_CbPrologueCount);
}

VOID HookDetector::CheckCallbackPrologueIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue || s_CbPrologueCount == 0) return;

    for (ULONG i = 0; i < s_CbPrologueCount; i++) {
        CbPrologueEntry& e = s_CbPrologues[i];
        if (!e.active || !e.address) continue;

        BYTE current[CB_PROLOGUE_SIZE] = {};
        __try {
            if (!MmIsAddressValid(e.address)) continue;
            RtlCopyMemory(current, e.address, CB_PROLOGUE_SIZE);
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        if (RtlCompareMemory(current, e.baseline, CB_PROLOGUE_SIZE)
            == CB_PROLOGUE_SIZE)
            continue;

        // Prologue modified — classify the patch type
        const char* patchType = "unknown modification";
        if (current[0] == 0xE9)
            patchType = "JMP rel32 (near jump detour)";
        else if (current[0] == 0xFF && current[1] == 0x25)
            patchType = "JMP [rip+disp32] (indirect jump detour)";
        else if (current[0] == 0x48 && current[1] == 0xB8 &&
                 current[10] == 0xFF && current[11] == 0xE0)
            patchType = "MOV RAX,imm64 + JMP RAX (long detour)";
        else if (current[0] == 0xC3)
            patchType = "RET (callback neutered — returns immediately)";
        else if (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3)
            patchType = "XOR EAX,EAX + RET (forced success return)";
        else if (current[0] == 0x48 && current[1] == 0x31 &&
                 current[2] == 0xC0 && current[3] == 0xC3)
            patchType = "XOR RAX,RAX + RET (forced zero return)";

        char msg[280];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ANTI-TAMPER: %s at %p inline-hooked — %s "
            "(callback entry overwrite — BYOVD silencing attack)",
            e.name, e.address, patchType);

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'cpnt');
        if (notif) {
            RtlZeroMemory(notif, sizeof(*notif));
            SET_CRITICAL(*notif);
            notif->pid    = 0;
            notif->isPath = FALSE;
            notif->scoopedAddress = (ULONG64)e.address;
            RtlCopyMemory(notif->procName, "NortonEDR", 9);
            SIZE_T msgLen = strlen(msg) + 1;
            notif->msg = (char*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, msgLen, 'cpmg');
            notif->bufSize = (ULONG)msgLen;
            if (notif->msg) {
                RtlCopyMemory(notif->msg, msg, msgLen);
                if (!bufQueue->Enqueue(notif)) {
                    ExFreePool(notif->msg); ExFreePool(notif);
                }
            } else { ExFreePool(notif); }
        }

        // Restore original prologue — re-enable the callback
        __try {
            // Kernel code pages are read-only — we need to use CR0 WP-clear
            // or MDL mapping.  Use MDL for safety.
            PMDL mdl = IoAllocateMdl(e.address, CB_PROLOGUE_SIZE, FALSE, FALSE, NULL);
            if (mdl) {
                MmBuildMdlForNonPagedPool(mdl);
                // Map with read-write, overriding the page protection
                PVOID mapped = MmMapLockedPagesSpecifyCache(
                    mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
                if (mapped) {
                    RtlCopyMemory(mapped, e.baseline, CB_PROLOGUE_SIZE);
                    MmUnmapLockedPages(mapped, mdl);
                    DbgPrint("[!] HookDetector: restored %s prologue\n", e.name);
                }
                IoFreeMdl(mdl);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] HookDetector: failed to restore %s prologue\n", e.name);
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PspNotifyEnableMask integrity — the single-byte global kill switch.
//
// PspNotifyEnableMask is a UCHAR in ntoskrnl that acts as a bitmask controlling
// which Ps*Notify callback arrays are invoked.  If an attacker (via BYOVD or
// rootkit) clears any bit, ALL callbacks of that type stop firing — but the
// callback arrays themselves remain intact, so our array-integrity checks pass.
//
// Bit 0 = PsSetCreateProcessNotifyRoutine
// Bit 1 = PsSetCreateThreadNotifyRoutine
// Bit 2 = PsSetLoadImageNotifyRoutine
//
// Detection: resolve PspNotifyEnableMask by scanning PsSetCreateProcessNotifyRoutineEx
// for a MOV/TEST byte [rip+disp32] pattern near the LEA for PspCreateProcessNotifyRoutine.
// Snapshot the mask at init, verify periodically.
// ---------------------------------------------------------------------------

static PUCHAR  s_PspNotifyEnableMaskAddr = nullptr;
static UCHAR   s_PspNotifyEnableMaskBaseline = 0;
static BOOLEAN s_PspNotifyEnableMaskValid = FALSE;

VOID HookDetector::TakePspNotifyEnableMaskBaseline()
{
    // Scan PsSetCreateProcessNotifyRoutineEx for byte-sized RIP-relative memory
    // accesses near the callback array reference.  PspNotifyEnableMask is typically
    // accessed via TEST/OR byte ptr [rip+disp32] or MOV cl, [rip+disp32] within
    // the first 0x100 bytes of the function.

    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, L"PsSetCreateProcessNotifyRoutineEx");
    PVOID setFn = MmGetSystemRoutineAddress(&uName);
    if (!setFn || !MmIsAddressValid(setFn)) {
        DbgPrint("[-] PspNotifyEnableMask: PsSetCreateProcessNotifyRoutineEx not found\n");
        return;
    }

    PUCHAR p = (PUCHAR)setFn;
    __try {
        for (ULONG i = 0; i < 0x100 - 7; i++) {
            // Pattern 1: F6 05 xx xx xx xx yy = TEST byte ptr [rip+disp32], imm8
            if (p[i] == 0xF6 && p[i+1] == 0x05) {
                LONG disp = *(LONG*)(p + i + 2);
                PUCHAR candidate = p + i + 7 + disp; // 7 = opcode(2) + disp32(4) + imm8(1)
                // But TEST is 7 bytes total, RIP is at i+7
                candidate = p + i + 2 + 4 + 1 + disp; // wrong — let me recalculate
                // F6 05 [disp32] [imm8] — RIP points to next insn = p + i + 7
                candidate = (PUCHAR)((p + i + 7) + disp);
                if (MmIsAddressValid(candidate) && (ULONG_PTR)candidate > 0xFFFF800000000000ULL) {
                    UCHAR val = *candidate;
                    // Sanity: mask should have bits 0-2 set (all three callback types enabled)
                    if ((val & 0x07) == 0x07) {
                        s_PspNotifyEnableMaskAddr = candidate;
                        s_PspNotifyEnableMaskBaseline = val;
                        s_PspNotifyEnableMaskValid = TRUE;
                        DbgPrint("[+] PspNotifyEnableMask: found at %p, value=0x%02X\n",
                            candidate, val);
                        return;
                    }
                }
            }

            // Pattern 2: 80 0D xx xx xx xx yy = OR byte ptr [rip+disp32], imm8
            if (p[i] == 0x80 && p[i+1] == 0x0D) {
                LONG disp = *(LONG*)(p + i + 2);
                PUCHAR candidate = (PUCHAR)((p + i + 7) + disp);
                if (MmIsAddressValid(candidate) && (ULONG_PTR)candidate > 0xFFFF800000000000ULL) {
                    UCHAR val = *candidate;
                    if ((val & 0x07) == 0x07) {
                        s_PspNotifyEnableMaskAddr = candidate;
                        s_PspNotifyEnableMaskBaseline = val;
                        s_PspNotifyEnableMaskValid = TRUE;
                        DbgPrint("[+] PspNotifyEnableMask: found (OR pattern) at %p, value=0x%02X\n",
                            candidate, val);
                        return;
                    }
                }
            }

            // Pattern 3: 0F BA 2D xx xx xx xx yy = BTS dword ptr [rip+disp32], imm8
            // Used in some Windows builds to set individual bits.
            if (p[i] == 0x0F && p[i+1] == 0xBA && (p[i+2] & 0x38) == 0x28) {
                LONG disp = *(LONG*)(p + i + 3);
                PUCHAR candidate = (PUCHAR)((p + i + 8) + disp);
                if (MmIsAddressValid(candidate) && (ULONG_PTR)candidate > 0xFFFF800000000000ULL) {
                    UCHAR val = *candidate;
                    if ((val & 0x07) == 0x07) {
                        s_PspNotifyEnableMaskAddr = candidate;
                        s_PspNotifyEnableMaskBaseline = val;
                        s_PspNotifyEnableMaskValid = TRUE;
                        DbgPrint("[+] PspNotifyEnableMask: found (BTS pattern) at %p, value=0x%02X\n",
                            candidate, val);
                        return;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] PspNotifyEnableMask: exception during scan\n");
    }

    DbgPrint("[-] PspNotifyEnableMask: pattern not found — check disabled\n");
}

VOID HookDetector::CheckPspNotifyEnableMask(BufferQueue* bufQueue)
{
    if (!s_PspNotifyEnableMaskValid || !s_PspNotifyEnableMaskAddr || !bufQueue)
        return;

    __try {
        if (!MmIsAddressValid(s_PspNotifyEnableMaskAddr)) return;

        UCHAR current = *s_PspNotifyEnableMaskAddr;
        if (current == s_PspNotifyEnableMaskBaseline) return;

        // Determine which callback types were disabled
        UCHAR diff = s_PspNotifyEnableMaskBaseline & ~current;
        const char* disabled = "";
        if (diff & 0x01) disabled = "Process";
        else if (diff & 0x02) disabled = "Thread";
        else if (diff & 0x04) disabled = "Image";
        if ((diff & 0x07) > 0x04) disabled = "Multiple";

        char msg[300];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ANTI-TAMPER CRITICAL: PspNotifyEnableMask modified 0x%02X→0x%02X at %p — "
            "%s callback(s) globally disabled! All EDR/AV Ps*Notify callbacks silenced "
            "(BYOVD single-byte kill switch attack)",
            s_PspNotifyEnableMaskBaseline, current, s_PspNotifyEnableMaskAddr, disabled);

        EmitPsCallbackAlert(bufQueue, msg, s_PspNotifyEnableMaskAddr);

        // Update baseline to avoid spam — but keep alerting if further bits cleared
        s_PspNotifyEnableMaskBaseline = current;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ---------------------------------------------------------------------------
// RunAllHookChecks — run all detection routines in sequence.
// Call after driver init is complete (and periodically from AntiTamper).
// ---------------------------------------------------------------------------

VOID HookDetector::RunAllHookChecks(
    PFUNCTION_MAP exportsMap,
    PVOID         moduleBase,
    BufferQueue*  bufQueue
) {
    DbgPrint("[*] HookDetector: running full hook scan\n");

    ULONG ssdt   = CheckSsdtIntegrity(bufQueue);
    ULONG inl    = ScanKernelInlineHooks(exportsMap, bufQueue);
    ULONG eat    = ScanKernelEatHooks(moduleBase, bufQueue);
    BOOLEAN etw  = CheckEtwHooks(bufQueue);
    CheckEtwStructureIntegrity(bufQueue);
    CheckAltSyscallHandlerIntegrity(bufQueue);
    CheckObCallbackIntegrity(bufQueue);
    CheckPsCallbackIntegrity(bufQueue);
    CheckCmCallbackIntegrity(bufQueue);
    CheckCiIntegrity(bufQueue);
    CheckSeCiCallbackIntegrity(bufQueue);
    CheckEprocessProtection(bufQueue);
    CheckLsassAuthDllIntegrity(bufQueue);
    CheckMajorFunctionIntegrity(bufQueue);
    CheckCallbackPrologueIntegrity(bufQueue);
    CheckPspNotifyEnableMask(bufQueue);
    CheckWfpIntegrity(bufQueue);

    DbgPrint("[*] HookDetector results — SSDT=%lu Inline=%lu EAT=%lu ETW=%d\n",
        ssdt, inl, eat, (int)etw);
}

// ---------------------------------------------------------------------------
// Init — derive the SSDT table pointer and take the baseline snapshot.
// Call once after SyscallsUtils::InitAltSyscallHandler().
// ---------------------------------------------------------------------------

VOID HookDetector::Init(BufferQueue* bufQueue) {

    UNREFERENCED_PARAMETER(bufQueue);

    ULONGLONG kiSystemServiceUser = SsdtUtils::LeakKiSystemServiceUser();
    if (!kiSystemServiceUser) {
        DbgPrint("[-] HookDetector: could not resolve KiSystemServiceUser\n");
        return;
    }

    ULONGLONG sdtAddr =
        SsdtUtils::LeakKeServiceDescriptorTable(kiSystemServiceUser);
    if (!sdtAddr) {
        DbgPrint("[-] HookDetector: could not resolve KeServiceDescriptorTable\n");
        return;
    }

    __try {
        PSERVICE_DESCRIPTOR_TABLE sdt = (PSERVICE_DESCRIPTOR_TABLE)sdtAddr;
        PVOID kiServiceTable  = sdt->ServiceTableBase;
        ULONG  count           = sdt->NumberOfServices;

        if (kiServiceTable && count > 0 && count <= MAX_SSDT_ENTRIES)
            TakeSsdtBaseline(kiServiceTable, count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] HookDetector: exception reading SDT in Init\n");
    }
}

// ---------------------------------------------------------------------------
// Cleanup — free the baseline allocation on driver unload.
// ---------------------------------------------------------------------------

VOID HookDetector::Cleanup() {

    if (ssdtBaseline) {
        ExFreePoolWithTag(ssdtBaseline, 'bssd');
        ssdtBaseline         = nullptr;
        ssdtBaselineCount    = 0;
        cachedKiServiceTable = nullptr;
    }
}
