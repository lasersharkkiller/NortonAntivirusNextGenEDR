#include "Globals.h"

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------

PSSDT_BASELINE_ENTRY HookDetector::ssdtBaseline       = nullptr;
ULONG                HookDetector::ssdtBaselineCount   = 0;
PVOID                HookDetector::cachedKiServiceTable = nullptr;

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
// CheckObCallbackIntegrity — verify that our ObRegisterCallbacks entries are
// still linked into PsProcessType->CallbackList and PsThreadType->CallbackList.
//
// Attack: EDRSandblast / Terminator walk the undocumented CallbackList inside
// OBJECT_TYPE and unlink our _CALLBACK_ENTRY_ITEM nodes.  After unlinking, the
// OS no longer calls our PreOperation callbacks, silently disabling handle-right
// stripping and process/thread self-protection.
//
// Layout used (stable Win10 1507 – Win11 24H2, x64):
//   OBJECT_TYPE.CallbackList        : LIST_ENTRY at offset +0xC8
//   CALLBACK_ENTRY_ITEM.PreOperation: POB_PRE_OPERATION_CALLBACK at offset +0x28
//     from the LIST_ENTRY node (i.e., from the Flink/Blink pointer itself)
//
// PsProcessType and PsThreadType are exported by ntoskrnl as POBJECT_TYPE*
// (pointer-to-pointer), so we dereference once to reach the OBJECT_TYPE.
// ---------------------------------------------------------------------------

#define OBJECT_TYPE_CALLBACKLIST_OFFSET  0xC8u
#define CALLBACK_ENTRY_PREOPERATION_OFFSET 0x28u

VOID HookDetector::CheckObCallbackIntegrity(BufferQueue* bufQueue)
{
    if (!bufQueue) return;

    struct TypeDesc {
        const WCHAR* exportName;
        PVOID        expectedPreOp;
        const char*  label;
    } checks[] = {
        { L"PsProcessType", (PVOID)ObjectUtils::ProcessPreCallback, "Process" },
        { L"PsThreadType",  (PVOID)ObjectUtils::ThreadPreCallback,  "Thread"  },
    };

    for (int i = 0; i < 2; i++) {

        UNICODE_STRING uName;
        RtlInitUnicodeString(&uName, checks[i].exportName);

        // PsProcessType / PsThreadType are exported as POBJECT_TYPE* (ptr-to-ptr).
        POBJECT_TYPE* ppType = (POBJECT_TYPE*)MmGetSystemRoutineAddress(&uName);
        if (!ppType || !MmIsAddressValid(ppType)) {
            DbgPrint("[-] HookDetector: could not resolve %ws\n", checks[i].exportName);
            continue;
        }

        POBJECT_TYPE objType = *ppType;
        if (!objType || !MmIsAddressValid(objType)) continue;

        // Locate the CallbackList head embedded in the OBJECT_TYPE.
        PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)objType + OBJECT_TYPE_CALLBACKLIST_OFFSET);
        if (!MmIsAddressValid(head)) continue;

        BOOLEAN found = FALSE;
        ULONG   limit = 64;   // guard against a corrupt/circular list

        __try {
            for (PLIST_ENTRY entry = head->Flink;
                 entry != head && limit-- > 0;
                 entry = entry->Flink)
            {
                if (!MmIsAddressValid(entry)) break;

                // PreOperation pointer lives at +0x28 from the LIST_ENTRY node.
                PVOID* preOpSlot = (PVOID*)((PUCHAR)entry + CALLBACK_ENTRY_PREOPERATION_OFFSET);
                if (MmIsAddressValid(preOpSlot) && *preOpSlot == checks[i].expectedPreOp) {
                    found = TRUE;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] HookDetector: exception walking %s CallbackList\n", checks[i].label);
        }

        if (found) {
            DbgPrint("[+] HookDetector: Ob%sCallback integrity OK\n", checks[i].label);
            continue;
        }

        // Our callback is missing — emit a Critical alert.
        DbgPrint("[!] HookDetector: Ob%sCallback unlinked from CallbackList!\n", checks[i].label);

        char msg[160];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "ANTI-TAMPER: Ob%sCallback unlinked from OBJECT_TYPE.CallbackList "
            "— EDRSandblast/Terminator-style attack",
            checks[i].label);

        SIZE_T msgLen = strlen(msg) + 1;

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KERNEL_STRUCTURED_NOTIFICATION),
                'obck');
        if (!notif) continue;

        RtlZeroMemory(notif, sizeof(*notif));
        SET_CRITICAL(*notif);
        SET_OB_CALLBACK_CHECK(*notif);
        notif->pid           = 0;
        notif->isPath        = FALSE;
        notif->scoopedAddress = (ULONG64)checks[i].expectedPreOp;
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
