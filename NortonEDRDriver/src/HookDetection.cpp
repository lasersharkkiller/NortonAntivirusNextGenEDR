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
    UCHAR   initialLevel;
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
    };

    BOOLEAN anyFound = FALSE;

    for (ULONG i = 0; i < 4; i++) {

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

		BOOLEAN found = FALSE;
		PUCHAR arr    = (PUCHAR)snap->arrayBase;

		__try {
			for (ULONG slot = 0; slot < 64 && !found; slot++) {
				PVOID* slotPtr = (PVOID*)(arr + slot * 8);
				if (!MmIsAddressValid(slotPtr)) break;
				PVOID fn = ExCallbackGetFunction(*slotPtr);
				if (fn == snap->ourCallback) found = TRUE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		if (!found) {
			char msg[128];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"ANTI-TAMPER: Ps%sNotify callback unregistered from internal array — "
				"EDR telemetry silenced (PsRemoveCreate*NotifyRoutine or direct patch)",
				checks[i].label);
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
                s_CiTextSize = sec[i].Misc.VirtualSize;
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
                    g_ProtWatch[watchIdx].pid = HandleToUlong(p->UniqueProcessId);
                    g_ProtWatch[watchIdx].initialLevel =
                        prot ? prot->Level : 0;
                    char lower[16] = {};
                    for (int i = 0; i < 15 && name[i]; i++)
                        lower[i] = (name[i] >= 'A' && name[i] <= 'Z')
                            ? name[i] + 32 : name[i];
                    RtlCopyMemory(g_ProtWatch[watchIdx].name, lower, 16);
                    g_ProtWatch[watchIdx].active = TRUE;
                    watchIdx++;
                    DbgPrint("[+] HookDetector: EPROCESS prot snap — %s pid=%lu level=0x%02X\n",
                        lower, HandleToUlong(p->UniqueProcessId),
                        prot ? prot->Level : 0);
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
// CheckEprocessProtection — verify PPL levels haven't been downgraded.
// A decrease in PS_PROTECTION.Level means a BYOVD driver zeroed the field.
// ---------------------------------------------------------------------------

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
        ObDereferenceObject(proc);

        // Only alert on decrease — if the initial level was 0, the process
        // was never PPL-protected (e.g. RunAsPPL not enabled for lsass).
        if (g_ProtWatch[i].initialLevel > 0 &&
            currentLevel < g_ProtWatch[i].initialLevel)
        {
            char msg[200];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "ANTI-TAMPER: %s (pid=%lu) protection downgraded 0x%02X->0x%02X — "
                "BYOVD PPL-strip (EPROCESS.Protection zeroed)",
                g_ProtWatch[i].name, g_ProtWatch[i].pid,
                g_ProtWatch[i].initialLevel, currentLevel);

            SIZE_T msgLen = strlen(msg) + 1;
            PKERNEL_STRUCTURED_NOTIFICATION notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'epnt');
            if (notif) {
                RtlZeroMemory(notif, sizeof(*notif));
                SET_CRITICAL(*notif);
                SET_EPROCESS_PROT_CHECK(*notif);
                notif->pid = (HANDLE)(ULONG_PTR)g_ProtWatch[i].pid;
                RtlCopyMemory(notif->procName, g_ProtWatch[i].name, 15);
                notif->msg = (char*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, msgLen, 'epmg');
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

            // Update snapshot so we only fire once per downgrade
            g_ProtWatch[i].initialLevel = currentLevel;
        }
    }
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
    CheckAltSyscallHandlerIntegrity(bufQueue);
    CheckObCallbackIntegrity(bufQueue);
    CheckPsCallbackIntegrity(bufQueue);
    CheckCmCallbackIntegrity(bufQueue);
    CheckCiIntegrity(bufQueue);
    CheckEprocessProtection(bufQueue);

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
