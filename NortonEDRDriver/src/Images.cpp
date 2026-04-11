#include "Globals.h"
#include "sha256utils.h"

KMUTEX ImageUtils::g_HashQueueMutex;

// ---------------------------------------------------------------------------
// ntdll double-load detection
//
// Telemetry context: 0.04% of 27M observed processes loaded ntdll.dll more
// than once over one month — an extremely rare event in clean populations,
// and the dominant signature of the ntdll remap / hook-evasion technique
// (fresh ntdll mapped from disk to get unhooked function pointers or to
// overwrite the hooked copy in memory).
//
// We track the first ntdll load per PID with a spin-lock protected table
// and emit Critical on any repeat load for the same PID.
// ---------------------------------------------------------------------------
#define MAX_NTDLL_TRACKED_PIDS 2048
static ULONG      g_NtdllSeenPids[MAX_NTDLL_TRACKED_PIDS] = {};
static LONG       g_NtdllSeenCount = 0;
static KSPIN_LOCK g_NtdllPidLock;

// Returns TRUE if ntdll.dll has been seen for this PID before; records it on first call.
static BOOLEAN NtdllSeenBefore(ULONG pid) {
    KIRQL irql;
    KeAcquireSpinLock(&g_NtdllPidLock, &irql);
    for (LONG i = 0; i < g_NtdllSeenCount; i++) {
        if (g_NtdllSeenPids[i] == pid) {
            KeReleaseSpinLock(&g_NtdllPidLock, irql);
            return TRUE;
        }
    }
    if (g_NtdllSeenCount < MAX_NTDLL_TRACKED_PIDS)
        g_NtdllSeenPids[g_NtdllSeenCount++] = pid;
    KeReleaseSpinLock(&g_NtdllPidLock, irql);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Secondary ntdll mapping tracker
//
// When a second copy of ntdll.dll is mapped into a process (hook evasion,
// or a kernel driver resolving LdrLoadDll from a fresh mapped copy), we
// record the base address and size of that secondary mapping.
//
// This allows the APC and thread-creation handlers to detect when an APC
// NormalRoutine or a StartRoutine points into a secondary ntdll copy
// rather than the primary loader-managed one — the hallmark of a driver
// resolving LdrLoadDll from a privately mapped ntdll to bypass user-mode
// hooks and ASLR.
//
// The primary ntdll (first load per PID) is NOT recorded here — only
// the second+ mappings.
// ---------------------------------------------------------------------------
#define MAX_SECONDARY_NTDLL 256

struct SecondaryNtdllEntry {
    ULONG  pid;
    PVOID  imageBase;
    SIZE_T imageSize;
    BOOLEAN used;
};

static SecondaryNtdllEntry g_SecNtdll[MAX_SECONDARY_NTDLL] = {};
static KSPIN_LOCK          g_SecNtdllLock;

static VOID RecordSecondaryNtdll(ULONG pid, PVOID base, SIZE_T size) {
    KIRQL irql;
    KeAcquireSpinLock(&g_SecNtdllLock, &irql);
    // Check for duplicate
    for (int i = 0; i < MAX_SECONDARY_NTDLL; i++) {
        if (g_SecNtdll[i].used && g_SecNtdll[i].pid == pid &&
            g_SecNtdll[i].imageBase == base) {
            KeReleaseSpinLock(&g_SecNtdllLock, irql);
            return;
        }
    }
    // Find free slot
    for (int i = 0; i < MAX_SECONDARY_NTDLL; i++) {
        if (!g_SecNtdll[i].used) {
            g_SecNtdll[i].pid       = pid;
            g_SecNtdll[i].imageBase = base;
            g_SecNtdll[i].imageSize = size;
            g_SecNtdll[i].used      = TRUE;
            KeReleaseSpinLock(&g_SecNtdllLock, irql);
            DbgPrint("[!] Secondary ntdll mapping recorded: pid=%lu base=%p size=0x%llX\n",
                     pid, base, (ULONG64)size);
            return;
        }
    }
    KeReleaseSpinLock(&g_SecNtdllLock, irql);
}

// Exported: checks if an address falls within a secondary ntdll mapping for any PID.
// Used by NtQueueApcThread/NtCreateThreadEx to detect LdrLoadDll-from-remap attacks.
BOOLEAN ImageUtils::IsAddressInSecondaryNtdll(ULONG pid, ULONG64 address) {
    KIRQL irql;
    KeAcquireSpinLock(&g_SecNtdllLock, &irql);
    for (int i = 0; i < MAX_SECONDARY_NTDLL; i++) {
        if (g_SecNtdll[i].used && g_SecNtdll[i].pid == pid) {
            ULONG64 base = (ULONG64)g_SecNtdll[i].imageBase;
            ULONG64 end  = base + g_SecNtdll[i].imageSize;
            if (address >= base && address < end) {
                KeReleaseSpinLock(&g_SecNtdllLock, irql);
                return TRUE;
            }
        }
    }
    KeReleaseSpinLock(&g_SecNtdllLock, irql);
    return FALSE;
}

// Cleanup on process exit
VOID ImageUtils::RemoveSecondaryNtdll(ULONG pid) {
    KIRQL irql;
    KeAcquireSpinLock(&g_SecNtdllLock, &irql);
    for (int i = 0; i < MAX_SECONDARY_NTDLL; i++) {
        if (g_SecNtdll[i].used && g_SecNtdll[i].pid == pid)
            g_SecNtdll[i].used = FALSE;
    }
    KeReleaseSpinLock(&g_SecNtdllLock, irql);
}

// Initialize spinlock — called from ImageUtils init path
VOID ImageUtils::InitSecondaryNtdllTracker() {
    KeInitializeSpinLock(&g_SecNtdllLock);
}

// ---------------------------------------------------------------------------
// Periodic APC queue scanner — KeInsertQueueApc blind spot mitigation
//
// When a kernel-mode driver (malicious or BYOVD) calls KeInsertQueueApc
// directly, our NtQueueApcThread/NtQueueApcThreadEx syscall hooks never
// fire — the call originates in ring 0 and never traverses the SSDT.
//
// This scanner runs every 5 seconds (piggybacked on the injection-confirmation
// timer) and walks the user-mode APC queue of EVERY user-mode thread across
// ALL processes.  For each queued APC with a non-NULL NormalRoutine it checks:
//
//   1. Skip our own HookDll APCs (DllInjector::IsOurApc)
//   2. NormalRoutine in secondary ntdll → CRITICAL
//      (kernel driver resolved LdrLoadDll from a privately mapped ntdll copy)
//   3. NormalRoutine in private executable VAD → CRITICAL
//      (kernel driver allocated RWX, wrote shellcode, queued APC to it)
//
// Performance: most threads have an empty user-mode APC queue (Flink==ListHead),
// so the fast-path is a single pointer comparison per thread.  The VAD walk
// only runs when a suspicious NormalRoutine is found.
//
// Limitation: APCs that fire and are dequeued between scan intervals will be
// missed.  This is a best-effort probabilistic detection complementing the
// syscall hooks.
// ---------------------------------------------------------------------------
VOID ImageUtils::ScanApcQueues() {
    KERNEL_STRUCTURES_OFFSET* offsets = OffsetsMgt::GetOffsets();
    if (!offsets) return;

    __try {
        PEPROCESS currentProcess = PsInitialSystemProcess;
        PLIST_ENTRY procListHead = (PLIST_ENTRY)(
            (PUCHAR)currentProcess + offsets->ActiveProcessLinks);
        PLIST_ENTRY procEntry = procListHead->Flink;
        int procCount = 0;

        do {
            if (!MmIsAddressValid(procEntry)) break;

            currentProcess = (PEPROCESS)(
                (PUCHAR)procEntry - offsets->ActiveProcessLinks);
            if (!currentProcess || !MmIsAddressValid(currentProcess)) break;

            ULONG pid = HandleToUlong(PsGetProcessId(currentProcess));

            // Skip Idle (0) and System (4) — no user-mode APCs
            if (pid <= 4 || ++procCount > 4096) {
                procEntry = procEntry->Flink;
                continue;
            }

            PLIST_ENTRY threadListHead = (PLIST_ENTRY)(
                (PUCHAR)currentProcess + offsets->ThreadListHead);

            if (!MmIsAddressValid(threadListHead) ||
                !MmIsAddressValid(threadListHead->Flink)) {
                procEntry = procEntry->Flink;
                continue;
            }

            // VAD root — only resolved when needed for shellcode check
            RTL_AVL_TREE* vadRoot = (RTL_AVL_TREE*)(
                (PUCHAR)currentProcess + offsets->VadRoot);

            PLIST_ENTRY threadEntry = threadListHead->Flink;
            int threadCount = 0;

            while (threadEntry != threadListHead && threadCount++ < 1024) {
                if (!MmIsAddressValid(threadEntry)) break;

                PETHREAD eThread = (PETHREAD)(
                    (PUCHAR)threadEntry - offsets->ThreadListEntry);
                if (!MmIsAddressValid(eThread)) {
                    threadEntry = threadEntry->Flink;
                    continue;
                }

                // User-mode APC list head
                PLIST_ENTRY userApcListHead = (PLIST_ENTRY)(
                    (PUCHAR)eThread +
                    KTHREAD_APCSTATE_OFFSET +
                    KAPCSTATE_USERLIST_OFFSET);

                if (!MmIsAddressValid(userApcListHead) ||
                    !MmIsAddressValid(userApcListHead->Flink)) {
                    threadEntry = threadEntry->Flink;
                    continue;
                }

                // Fast-path: skip empty APC queues (vast majority of threads)
                if (userApcListHead->Flink == userApcListHead) {
                    threadEntry = threadEntry->Flink;
                    continue;
                }

                PLIST_ENTRY apcEntry = userApcListHead->Flink;
                int apcCount = 0;

                while (apcEntry != userApcListHead && apcCount++ < 64) {
                    if (!MmIsAddressValid(apcEntry)) break;

                    PUCHAR kapcBase = (PUCHAR)apcEntry - KAPC_APCLISTENTRY_OFFSET;
                    if (!MmIsAddressValid(kapcBase) ||
                        !MmIsAddressValid(kapcBase + KAPC_NORMALROUTINE_OFFSET)) {
                        apcEntry = apcEntry->Flink;
                        continue;
                    }

                    PVOID normalRoutine = *(PVOID*)(kapcBase + KAPC_NORMALROUTINE_OFFSET);

                    // Skip NULL NormalRoutine (special kernel APCs / I/O completion)
                    if (!normalRoutine) {
                        apcEntry = apcEntry->Flink;
                        continue;
                    }

                    // Skip our own HookDll injection APCs
                    if (DllInjector::IsOurApc(normalRoutine, pid)) {
                        apcEntry = apcEntry->Flink;
                        continue;
                    }

                    char* procName = PsGetProcessImageFileName(currentProcess);
                    HANDLE tid = PsGetThreadId(eThread);
                    const char* reason = nullptr;

                    // Check 1: NormalRoutine in secondary ntdll mapping
                    if (IsAddressInSecondaryNtdll(pid, (ULONG64)normalRoutine)) {
                        reason = "NormalRoutine points into secondary ntdll — "
                                 "kernel driver injection via privately resolved LdrLoadDll";
                    }
                    // Check 2: NormalRoutine in private executable VAD (shellcode)
                    else if (MmIsAddressValid(vadRoot) &&
                             VadUtils::IsAddressInPrivateExecVad(
                                 (PRTL_BALANCED_NODE)vadRoot, (ULONG64)normalRoutine)) {
                        reason = "NormalRoutine points into private executable memory — "
                                 "kernel driver APC injection via shellcode in allocated RWX";
                    }

                    if (reason) {
                        char msg[450];
                        RtlStringCbPrintfA(msg, sizeof(msg),
                            "KeInsertQueueApc bypass: user-mode APC "
                            "(NormalRoutine=0x%llX) in '%s' (pid=%lu tid=%lu) — %s",
                            (ULONG64)normalRoutine,
                            procName ? procName : "?",
                            pid, HandleToUlong(tid),
                            reason);

                        PKERNEL_STRUCTURED_NOTIFICATION notif =
                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED,
                                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'apcq');
                        if (notif) {
                            RtlZeroMemory(notif, sizeof(*notif));
                            SET_CRITICAL(*notif);
                            SET_SYSCALL_CHECK(*notif);
                            notif->scoopedAddress = (ULONG64)normalRoutine;
                            notif->pid = (HANDLE)(ULONG_PTR)pid;
                            notif->isPath = FALSE;
                            if (procName)
                                RtlStringCbCopyA(notif->procName,
                                    sizeof(notif->procName), procName);

                            SIZE_T msgLen = strlen(msg) + 1;
                            notif->msg = (char*)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED, msgLen, 'apcm');
                            if (notif->msg) {
                                RtlCopyMemory(notif->msg, msg, msgLen);
                                notif->bufSize = (ULONG)msgLen;
                                if (!CallbackObjects::GetNotifQueue()->Enqueue(notif)) {
                                    ExFreePool(notif->msg);
                                    ExFreePool(notif);
                                }
                            } else { ExFreePool(notif); }
                        }

                        InjectionTaintTracker::MarkTainted((HANDLE)(ULONG_PTR)pid);

                        DbgPrint("[!] APC queue scan: KeInsertQueueApc bypass — "
                                 "NormalRoutine=%p pid=%lu tid=%lu\n",
                                 normalRoutine, pid, HandleToUlong(tid));
                    }

                    apcEntry = apcEntry->Flink;
                }

                threadEntry = threadEntry->Flink;
            }

            procEntry = procEntry->Flink;
        } while (procEntry != procListHead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] APC queue scan: exception during process walk\n");
    }
}

// ---------------------------------------------------------------------------
// Image hash verification — anti-phantom-DLL defense (Fast and Furious)
//
// SHA256 critical DLLs at ImageLoadNotifyRoutine time, then re-verify 200ms
// later via a deferred work item.  A mismatch means the mapped image was
// replaced between callback and execution (phantom DLL / process hollowing).
// ---------------------------------------------------------------------------
#define MAX_IMAGE_HASHES 512

struct ImageHashEntry {
    ULONG  pid;
    PVOID  imageBase;
    SIZE_T imageSize;
    BYTE   hash[SHA256_BLOCK_SIZE];   // 32 bytes
    BOOLEAN used;
};

static ImageHashEntry g_ImageHashes[MAX_IMAGE_HASHES] = {};
static KSPIN_LOCK     g_ImageHashLock;

// Work item context for deferred re-verification
struct HashVerifyCtx {
    PIO_WORKITEM workItem;
    ULONG        pid;
    PVOID        imageBase;
    SIZE_T       imageSize;
    BYTE         originalHash[SHA256_BLOCK_SIZE];
};

// DLLs worth hashing — high-value targets for phantom DLL / unhooking attacks.
static BOOLEAN ShouldHashImage(PUNICODE_STRING fullImageName) {
    if (!fullImageName || !fullImageName->Buffer) return FALSE;
    static const WCHAR* kHashTargets[] = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
        L"amsi.dll", L"clr.dll", L"clrjit.dll", nullptr
    };
    for (int i = 0; kHashTargets[i]; i++) {
        if (UnicodeStringContains(fullImageName, kHashTargets[i]))
            return TRUE;
    }
    return FALSE;
}

// Forward declarations for deferred hash verification
static VOID QueueHashVerification(ULONG pid, PVOID imageBase, SIZE_T imageSize, BYTE* hash);
static VOID HashVerifyWorker(PDEVICE_OBJECT DevObj, PVOID Context);

// ---------------------------------------------------------------------------
// Argument-spoofing discrepancy detection (Adam Chester / Cobalt Strike "argue")
//
// At CreateProcessNotifyEx time the kernel gives us CreateInfo->CommandLine —
// the ORIGINAL command line passed to NtCreateUserProcess, before any parent
// can patch the child's PEB.  We save that per-PID here.
//
// When the child resumes and loads its first user DLL (kernel32, etc.), our
// ImageLoadNotifyRoutine fires while still attached to the process.  At that
// point the parent's PEB patch (if any) has already been applied.  We read
// PEB->ProcessParameters->CommandLine and compare to the saved kernel copy.
// A length or content difference = argument spoofing in progress.
// ---------------------------------------------------------------------------
#define MAX_CMDLINE_RECORDS   512
#define MAX_CMDLINE_CHARS     256

struct CMDLINE_RECORD {
	ULONG   pid;
	WCHAR   kernelCmd[MAX_CMDLINE_CHARS + 1];
	USHORT  kernelLen;    // chars
	BOOLEAN checked;      // TRUE once we've compared — only fire once per process
};

static CMDLINE_RECORD g_CmdLineRecs[MAX_CMDLINE_RECORDS] = {};
static LONG           g_CmdLineRecCount = 0;
static KSPIN_LOCK     g_CmdLineRecLock;

VOID ImageUtils::SaveKernelCmdLine(ULONG pid, PCUNICODE_STRING cmd)
{
	if (!cmd || !cmd->Buffer || !cmd->Length) return;
	KIRQL irql;
	KeAcquireSpinLock(&g_CmdLineRecLock, &irql);
	// Don't double-add the same PID
	for (LONG i = 0; i < g_CmdLineRecCount; i++) {
		if (g_CmdLineRecs[i].pid == pid) {
			KeReleaseSpinLock(&g_CmdLineRecLock, irql);
			return;
		}
	}
	if (g_CmdLineRecCount < MAX_CMDLINE_RECORDS) {
		CMDLINE_RECORD* rec = &g_CmdLineRecs[g_CmdLineRecCount++];
		rec->pid     = pid;
		rec->checked = FALSE;
		USHORT chars = cmd->Length / sizeof(WCHAR);
		if (chars > MAX_CMDLINE_CHARS) chars = MAX_CMDLINE_CHARS;
		RtlCopyMemory(rec->kernelCmd, cmd->Buffer, chars * sizeof(WCHAR));
		rec->kernelCmd[chars] = L'\0';
		rec->kernelLen = chars;
	}
	KeReleaseSpinLock(&g_CmdLineRecLock, irql);
}

VOID ImageUtils::RemoveCmdLineRec(ULONG pid)
{
	KIRQL irql;
	KeAcquireSpinLock(&g_CmdLineRecLock, &irql);
	for (LONG i = 0; i < g_CmdLineRecCount; i++) {
		if (g_CmdLineRecs[i].pid == pid) {
			g_CmdLineRecs[i] = g_CmdLineRecs[--g_CmdLineRecCount];
			break;
		}
	}
	KeReleaseSpinLock(&g_CmdLineRecLock, irql);
}

// Must be called while already KeStackAttachProcess'd to proc.
VOID ImageUtils::CheckCmdLineDiscrepancy(ULONG pid, PEPROCESS proc)
{
	// Step 1: grab kernel cmdline copy under spinlock, mark as checked
	WCHAR  kernelBuf[MAX_CMDLINE_CHARS + 1] = {};
	USHORT kernelLen = 0;

	KIRQL irql;
	KeAcquireSpinLock(&g_CmdLineRecLock, &irql);
	for (LONG i = 0; i < g_CmdLineRecCount; i++) {
		if (g_CmdLineRecs[i].pid == pid && !g_CmdLineRecs[i].checked) {
			g_CmdLineRecs[i].checked = TRUE;
			kernelLen = g_CmdLineRecs[i].kernelLen;
			RtlCopyMemory(kernelBuf, g_CmdLineRecs[i].kernelCmd, kernelLen * sizeof(WCHAR));
			break;
		}
	}
	KeReleaseSpinLock(&g_CmdLineRecLock, irql);

	if (kernelLen == 0) return;

	// Step 2: read PEB->ProcessParameters->CommandLine (caller is attached)
	WCHAR  pebBuf[MAX_CMDLINE_CHARS + 1] = {};
	USHORT pebLen = 0;

	__try {
		PPEB peb = (PPEB)PsGetProcessPeb(proc);
		if (!peb || !MmIsAddressValid(peb)) return;
		PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;
		if (!params || !MmIsAddressValid(params)) return;
		PWSTR  cmdBuf = params->CommandLine.Buffer;
		USHORT cmdLen = params->CommandLine.Length;
		if (!cmdBuf || !cmdLen) return;
		pebLen = cmdLen / sizeof(WCHAR);
		if (pebLen > MAX_CMDLINE_CHARS) pebLen = MAX_CMDLINE_CHARS;
		if (!MmIsAddressValid(cmdBuf)) return;
		RtlCopyMemory(pebBuf, cmdBuf, pebLen * sizeof(WCHAR));
		pebBuf[pebLen] = L'\0';
	} __except (EXCEPTION_EXECUTE_HANDLER) { return; }

	// Step 3: case-insensitive comparison (ASCII range only)
	BOOLEAN mismatch = (pebLen != kernelLen);
	if (!mismatch) {
		for (USHORT i = 0; i < kernelLen && !mismatch; i++) {
			WCHAR k = kernelBuf[i], p = pebBuf[i];
			if (k >= L'A' && k <= L'Z') k |= 0x20;
			if (p >= L'A' && p <= L'Z') p |= 0x20;
			if (k != p) mismatch = TRUE;
		}
	}
	if (!mismatch) return;

	// Step 4: emit Critical alert with both copies (first 80 chars, narrow)
	char kernelNarrow[81] = {}, pebNarrow[81] = {};
	for (int i = 0; i < 80 && i < kernelLen; i++)
		kernelNarrow[i] = (kernelBuf[i] < 128) ? (char)kernelBuf[i] : '?';
	for (int i = 0; i < 80 && i < pebLen; i++)
		pebNarrow[i] = (pebBuf[i] < 128) ? (char)pebBuf[i] : '?';

	char msg[320];
	RtlStringCbPrintfA(msg, sizeof(msg),
		"Argument Spoofing: kernel cmdline != PEB cmdline | "
		"kernel=[%s] peb=[%s]",
		kernelNarrow, pebNarrow);

	SIZE_T msgLen = strlen(msg);
	PKERNEL_STRUCTURED_NOTIFICATION n = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
	if (!n) return;
	RtlZeroMemory(n, sizeof(*n));
	SET_CRITICAL(*n);
	SET_CALLING_PROC_PID_CHECK(*n);
	n->pid    = (HANDLE)(ULONG_PTR)pid;
	n->isPath = FALSE;
	char* procName = PsGetProcessImageFileName(proc);
	if (procName) RtlStringCbCopyA(n->procName, sizeof(n->procName), procName);
	n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen + 1, 'msg');
	if (n->msg) {
		RtlCopyMemory(n->msg, msg, msgLen + 1);
		n->bufSize = (ULONG)(msgLen + 1);
		if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
			ExFreePool(n->msg);
			ExFreePool(n);
		}
	} else {
		ExFreePool(n);
	}
}

// ---------------------------------------------------------------------------
// Phantom DLL deferred re-verification — fires 200ms after image load to
// detect post-callback content replacement (enSilo "Fast and Furious" attack).
// ---------------------------------------------------------------------------

static VOID HashVerifyWorker(PDEVICE_OBJECT DevObj, PVOID Context) {
    UNREFERENCED_PARAMETER(DevObj);
    HashVerifyCtx* ctx = (HashVerifyCtx*)Context;
    if (!ctx) return;

    // Small delay to let the attacker's swap happen (if any)
    LARGE_INTEGER delay;
    delay.QuadPart = -200 * 10000LL;  // 200ms relative
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    // Re-attach to the process and re-hash
    PEPROCESS process = nullptr;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ctx->pid, &process);
    if (!NT_SUCCESS(s) || !process) goto cleanup;

    {
        KAPC_STATE apcState;
        KeStackAttachProcess(process, &apcState);

        BYTE rehash[SHA256_BLOCK_SIZE] = {};
        BOOLEAN hashOk = FALSE;
        __try {
            SHA256_CTX sha;
            SHA256Init(&sha);
            SIZE_T remaining = ctx->imageSize;
            BYTE* ptr = (BYTE*)ctx->imageBase;
            while (remaining > 0) {
                SIZE_T chunk = min(remaining, (SIZE_T)4096);
                if (!MmIsAddressValid(ptr)) break;
                SHA256Update(&sha, ptr, chunk);
                ptr += chunk;
                remaining -= chunk;
            }
            SHA256Final(rehash, &sha);
            hashOk = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Process may have exited or memory unmapped
        }

        KeUnstackDetachProcess(&apcState);

        if (hashOk &&
            RtlCompareMemory(ctx->originalHash, rehash, SHA256_BLOCK_SIZE) != SHA256_BLOCK_SIZE)
        {
            // MISMATCH — phantom DLL detected!
            char msg[256];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "Phantom DLL: mapped image at %p (pid=%lu) content modified after "
                "ImageLoadNotifyRoutine — race condition exploit detected",
                ctx->imageBase, ctx->pid);

            PKERNEL_STRUCTURED_NOTIFICATION notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
            if (notif) {
                RtlZeroMemory(notif, sizeof(*notif));
                SET_CRITICAL(*notif);
                SET_IMAGE_LOAD_PATH_CHECK(*notif);
                notif->pid    = (HANDLE)(ULONG_PTR)ctx->pid;
                notif->isPath = FALSE;
                char* procName = PsGetProcessImageFileName(process);
                if (procName) RtlStringCbCopyA(notif->procName, sizeof(notif->procName), procName);
                SIZE_T msgLen = strlen(msg) + 1;
                notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
                if (notif->msg) {
                    RtlCopyMemory(notif->msg, msg, msgLen);
                    notif->bufSize = (ULONG)msgLen;
                    if (!CallbackObjects::GetNotifQueue()->Enqueue(notif)) {
                        ExFreePool(notif->msg); ExFreePool(notif);
                    }
                } else { ExFreePool(notif); }
            }
        }

        ObDereferenceObject(process);
    }

    // Remove entry from hash table
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_ImageHashLock, &irql);
        for (int i = 0; i < MAX_IMAGE_HASHES; i++) {
            if (g_ImageHashes[i].used &&
                g_ImageHashes[i].pid == ctx->pid &&
                g_ImageHashes[i].imageBase == ctx->imageBase) {
                g_ImageHashes[i].used = FALSE;
                break;
            }
        }
        KeReleaseSpinLock(&g_ImageHashLock, irql);
    }

cleanup:
    IoFreeWorkItem(ctx->workItem);
    ExFreePoolWithTag(ctx, 'hvwi');
}

static VOID QueueHashVerification(ULONG pid, PVOID imageBase, SIZE_T imageSize, BYTE* hash) {
    extern PDEVICE_OBJECT g_DeviceObject;
    if (!g_DeviceObject) return;

    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    if (!workItem) return;

    HashVerifyCtx* ctx = (HashVerifyCtx*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HashVerifyCtx), 'hvwi');
    if (!ctx) { IoFreeWorkItem(workItem); return; }

    ctx->workItem  = workItem;
    ctx->pid       = pid;
    ctx->imageBase = imageBase;
    ctx->imageSize = imageSize;
    RtlCopyMemory(ctx->originalHash, hash, SHA256_BLOCK_SIZE);

    IoQueueWorkItem(workItem, HashVerifyWorker, DelayedWorkQueue, ctx);
}

// ---------------------------------------------------------------------------
// LOLDriver runtime detection.
//
// The ELAM driver blocks known-bad drivers at boot.  This catches drivers
// loaded post-boot via NtLoadDriver (which fires an image-load notification
// with ProcessId == 0, i.e., kernel image).  We check the basename of each
// kernel image against a list of known vulnerable/malicious driver basenames.
//
// Sources: loldrivers.io, MSRC driver blocklist, public Sigma rules.
// ---------------------------------------------------------------------------

static const char* kLolDriverNames[] = {
    // Exploit / privilege escalation
    "winring0x64.sys",    // WinRing0 — CPUID/MSR abuse, used by ransomware
    "winring0.sys",
    "rtcore64.sys",       // MSI Afterburner — arbitrary kernel R/W (CVE-2019-16098)
    "rtcore32.sys",
    "dbutil_2_3.sys",     // Dell DBUtil — local priv-esc (CVE-2021-21551)
    "asrdrv103.sys",      // ASRock — arbitrary kernel R/W (CVE-2020-15368)
    "gdrv.sys",           // GIGABYTE — arbitrary kernel R/W
    "speedfan.sys",       // SpeedFan — arbitrary port I/O
    "physmem.sys",        // WinPmem — physical memory access
    "rwdrv.sys",          // RWEverything — arbitrary kernel R/W
    "elby clonecd.sys",   // CloneCD — SCSI passthrough
    "kprocesshacker.sys", // Process Hacker — kernel object access
    "procexp152.sys",     // Process Explorer (old signed) — kernel handle access
    "nvflash.sys",        // NVIDIA flash — ring-0 access
    "atillk64.sys",       // ATI Tray Tools — arbitrary kernel R/W
    "bs_hwmio64_w10.sys", // BattlEye — abused version
    "mhyprot2.sys",       // miHoYo anti-cheat — arbitrary R/W, used by ransomware
    "zemana.sys",         // Zemana AntiMalware driver — abused for termination
    "asio.sys",           // ASIO — abused for ring-0 access

    // DMA attack / physical memory access (IOMMU bypass)
    "pcileech.sys",       // PCILeech — direct PCIe DMA framework
    "leechcore.sys",      // LeechCore — PCILeech core driver
    "oxpcie.sys",         // OxPCIe — Oxford PCIe UART (PCILeech FPGA)
    "fpga_driver.sys",    // Generic PCILeech FPGA driver
    "km.sys",             // PCILeech km.sys payload carrier
    "pmxdrv.sys",         // PassMark — physical memory read (CVE abused by DMA tools)
    "iomem64.sys",        // IOMemory — arbitrary physical memory access
    "memdrv.sys",         // Generic memory access driver
    "asmmap64.sys",       // ASMedia — arbitrary physical memory map
    "inpoutx64.sys",      // InpOut — direct port I/O / physical memory

    // --- Active ransomware / EDR killer campaigns (2024-2026) ---

    // Zemana family — single most weaponized driver family across Terminator,
    // Spyboy, Killer Ultra, EDRKillShifter, BlackByte, BlackCat, Qilin, RansomHub.
    "zamguard64.sys",     // Zemana Anti-Malware (CVE-2024-1853) — arbitrary process kill
    "zamguard32.sys",
    "zam64.sys",          // Zemana Anti-Logger — same codebase as zamguard
    "zam32.sys",
    "amsdk.sys",          // WatchDog/Zemana SDK — Silver Fox APT / ValleyRAT
    "wamsdk.sys",         // alias for amsdk

    "truesight.sys",      // RogueKiller Antirootkit — 2500+ tampered variants, HiddenGh0st RAT
    "aswarpot.sys",       // Avast Anti-Rootkit — GHOSTENGINE cryptojacker, EDR killers
    "iobitunlocker.sys",  // IOBit Unlocker — GHOSTENGINE (kernel file deletion of EDR binaries)
    "smuol.sys",          // ABYSSWORKER fake CrowdStrike driver — Medusa ransomware (2024-2025)
    "rentdrv2.sys",       // RentDrv2 — EDRKillShifter (RansomHub), process termination
    "tfsysmon.sys",       // ThreatFire SysMon — EDRKillShifter, BianLian, Medusa, Play
    "iqvw64e.sys",        // Intel Ethernet diag — arbitrary kernel exec (CVE-2015-2291), Scattered Spider
    "biontdrv.sys",       // Paragon Partition Mgr — five kernel write CVEs (CVE-2025-0285..0289), 0-day
    "nseckrnl.sys",       // NSecKrnl — Reynolds/Warlock ransomware (2026)
    "402.sys",            // alias for nseckrnl
    "enportv.sys",        // EnCase forensic — 18+ IOCTLs incl KillProc, DKOM (Huntress Jan 2026)
    "dbutildrv2.sys",     // Dell DBUtilDrv2 v2.5-2.7 (CVE-2021-36276) — Metasploit module
    "procexp.sys",        // Old Process Explorer v16.32 — AuKill, Medusa Locker, LockBit
    "echo_driver.sys",    // Inspect Element — token theft (CVE-2023-38817), cert revoked

    // --- MS blocklist / Sigma rules / documented BYOVD tooling ---
    "ene.sys",            // ENE Technology RGB — UNC2970 APT LIGHTSHOW tool
    "lenovodiagnosticsdriver.sys",  // Lenovo Diag — phys/virt mem R/W (CVE-2022-3699)
    "capcom.sys",         // Capcom anti-cheat — direct kernel code exec from usermode
    "dbk64.sys",          // Cheat Engine kernel — arbitrary kernel R/W, process manipulation
    "dbk32.sys",
    "hw.sys",             // HWiNFO — arbitrary physical memory / port I/O
    "ntiolib_x64.sys",    // MSI NTIOLib — arbitrary phys mem and MSR access
    "ntiolib.sys",
    "winio64.sys",        // WinIO library — arbitrary I/O port and phys mem (CVE-2024-55407)
    "winio32.sys",
    "directio64.sys",     // DirectIO — arbitrary port I/O and phys mem map
    "directio.sys",
    "rzpnk.sys",          // Razer Synapse — arbitrary kernel R/W
    "cpuz141.sys",        // CPU-Z — MSR / phys mem access
    "cpuz_x64.sys",
    "lnvmsrio.sys",       // Lenovo Dispatcher MSR I/O — kernel code exec (CVE-2025-8061)
    "iqvw64.sys",         // Intel Network Adapter Diag — kernel code exec (CVE-2015-2291) variant
    "iqvw32.sys",
    "asrdrv104.sys",      // ASRock variants beyond asrdrv103
    "asrdrv106.sys",
    "asrdrv101.sys",
    "asrdrv10.sys",
    "vboxdrv.sys",        // VirtualBox kernel — arbitrary kernel R/W via IOCTL
    "gmer64.sys",         // GMER anti-rootkit — weaponized as EDR killer
    "gmer.sys",
    "blackbonedrv10.sys", // Blackbone — kernel mem R/W, manual mapping, offensive tooling

    // --- Lower frequency, still documented BYOVD targets ---
    "semav6msr.sys",      // SEMAV6 MSR — arbitrary MSR R/W
    "elrawdsk.sys",       // ElRawDisk — raw disk sector access (Shamoon-style wiping)
    "amifldrv64.sys",     // AMI BIOS flash — ring-0 phys mem access
    "alsysio64.sys",      // Alcor Micro USB — arbitrary phys mem / port I/O
    "bdapiutil64.sys",    // Baidu Antivirus — process termination (ESET 2026 EDR killer research)
    "piddrv64.sys",       // ProtectID — arbitrary kernel mem R/W
    "piddrv.sys",
    "phymemx64.sys",      // Physical memory access variants
    "phymem64.sys",
    "stdcdrv64.sys",      // Intel Graphics diag — arbitrary phys mem access
    "netflt.sys",         // Netfilter rootkit — Microsoft-signed malicious driver (2021)
    "netfilterdrv.sys",
    "msio64.sys",         // MICSYS MSI I/O — arbitrary phys mem / port access
    "msio32.sys",

    // --- Mimikatz / credential-theft tooling ---
    "mimidrv.sys",        // Mimikatz kernel driver — PPL strip, token theft, minifilter kill
    "wdnmd.sys",          // Mimikatz mimidrv repack — renamed deployments
    "fgme.sys",           // FGme exploit driver — Mimikatz PPL bypass helper

    // --- Offensive toolkit kernel drivers ---
    "dsefix.sys",         // DSEFix — patches g_CiEnabled to disable driver signing enforcement
    "ppldump.sys",        // PPLdump — dumps PPL process memory via exploit driver
    "pplmedic.sys",       // PPLmedic — downgrades PPL protection via WSCI exploit
    "reddriver.sys",      // RedDriver — browser traffic interception via WFP hijack
    "edrsilencer.sys",    // EDRSilencer — blocks EDR network telemetry via WFP rules
    "kdu.sys",            // Kernel Driver Utility (hfiref0x) — maps unsigned drivers via BYOVD

    // --- RegPhantom rootkit IOCs (Nextron Systems, March 2026) ---
    "mapdriver.sys",
    "mydriver.sys",
    "testdriver.sys",
    "fsfilter.sys",       // NOT our own NortonEDR driver — this is the rootkit's filename
    "devdriver.sys",
    "0629.sys",
    nullptr
};

// Case-insensitive check: does charBuf contain the given needle as a path component?
static BOOLEAN IsLolDriverName(const char* charBuf, SIZE_T charLen, const char* needle)
{
    SIZE_T needleLen = 0;
    while (needle[needleLen]) needleLen++;
    if (charLen < needleLen) return FALSE;

    // Search from the right — we want the filename component match
    for (SIZE_T i = 0; i <= charLen - needleLen; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < needleLen; j++) {
            if ((charBuf[i + j] | 0x20) != needle[j]) { match = FALSE; break; }
        }
        if (match) {
            // Ensure we matched at a path separator boundary (or start of string)
            if (i == 0 || charBuf[i - 1] == '\\' || charBuf[i - 1] == '/')
                return TRUE;
        }
    }
    return FALSE;
}

// Case-insensitive suffix check: does buf (len bytes) end with "ntdll.dll"?
static BOOLEAN IsNtdllPath(const char* buf, SIZE_T len) {
    if (len < 9) return FALSE;
    static const char kSuffix[] = "ntdll.dll";
    const char* tail = buf + len - 9;
    for (int i = 0; i < 9; i++) {
        if ((tail[i] | 0x20) != kSuffix[i]) return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Suspicious Authenticode certificate signer detection for kernel drivers.
//
// Opens the driver file, reads the PE security directory (WIN_CERTIFICATE),
// and searches the raw certificate bytes for known-bad organizations and
// adversary-nation country codes.
// ---------------------------------------------------------------------------

// Known-bad certificate organizations used to sign malicious kernel drivers.
// Substring match in raw certificate DER bytes (the org name is stored as
// PrintableString/UTF8String, so ASCII substrings work).
static const char* kMaliciousSignerOrgs[] = {
    // RegPhantom rootkit (Nextron Systems, March 2026)
    "Guangzhou Xuanfeng",
    "Autel Intelligent Technology",
    // FiveSys rootkit (Bitdefender, 2021)
    "Hainan YouHu",
    // Netfilter rootkit (Microsoft, 2021)
    "Ningbo Gaoxinqu zhidian",
    "Beijing JoinHope Image Technology",
    // Chinese APT / rootkit signing certs (various threat intel)
    "Zhuhai liancheng Technology",
    "Shanghai Yulian Software",
    "Beijing Kate Zhanhong Technology",
    "Shenzhen Luyoudashi Technology",
    // FakeCert / stolen Chinese certs used by multiple ransomware groups
    "Beijing Chunbai Technology",
    nullptr
};

// Adversary-nation 2-letter country codes (ISO 3166-1 alpha-2).
// DER encoding: OID 2.5.4.6 (countryName) = 55 04 06, then PrintableString
// tag 13, length 02, followed by the 2 ASCII bytes.
static const UCHAR kOidCountryPrefix[] = { 0x55, 0x04, 0x06, 0x13, 0x02 };

static const struct {
    UCHAR  code[2];
    const char* label;
} kAdversaryCountries[] = {
    { { 'C', 'N' }, "China (CN)"        },
    { { 'R', 'U' }, "Russia (RU)"       },
    { { 'I', 'R' }, "Iran (IR)"         },
    { { 'K', 'P' }, "North Korea (KP)"  },
    { { 'B', 'Y' }, "Belarus (BY)"      },
};

// Legitimate vendors from adversary nations whose kernel drivers are expected.
// Searched as substrings in the same certificate blob.
static const char* kTrustedAdversaryNationSigners[] = {
    "Realtek Semiconductor",
    "Realtek",               // some certs use short form
    "MediaTek",
    "Lenovo",
    "Huawei",
    "Tencent Technology",
    "Qihoo 360",
    "Beijing Kingsoft",
    "Kaspersky",
    "Doctor Web",
    "Dahua Technology",
    "Hangzhou Hikvision",
    "Yandex",
    "TP-LINK",
    "Tenda Technology",
    "ZTE Corporation",
    "DJI Technology",
    nullptr
};

// Case-insensitive substring search in a byte buffer.
static BOOLEAN CertBlobContains(const UCHAR* blob, SIZE_T blobLen,
                                const char* needle)
{
    SIZE_T needleLen = 0;
    while (needle[needleLen]) needleLen++;
    if (blobLen < needleLen) return FALSE;

    for (SIZE_T i = 0; i <= blobLen - needleLen; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < needleLen; j++) {
            UCHAR a = blob[i + j];
            UCHAR b = (UCHAR)needle[j];
            // case-insensitive for ASCII letters
            if ((a | 0x20) != (b | 0x20)) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

static VOID EmitSignerAlert(const char* alertMsg, BOOLEAN isCritical)
{
    SIZE_T msgLen = strlen(alertMsg) + 1;
    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'sgn');
    if (!notif) return;
    RtlZeroMemory(notif, sizeof(*notif));
    if (isCritical) { SET_CRITICAL(*notif); }
    else            { SET_WARNING(*notif);  }
    SET_SUSPECT_SIGNER_CHECK(*notif);
    notif->pid    = PsGetProcessId(PsGetCurrentProcess());
    notif->isPath = FALSE;
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'sgmg');
    notif->bufSize = (ULONG)msgLen;
    if (notif->msg) {
        RtlCopyMemory(notif->msg, alertMsg, msgLen);
        if (!CallbackObjects::GetNotifQueue()->Enqueue(notif)) {
            ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    } else {
        ExFreePool(notif);
    }
}

static VOID CheckDriverCertificateSigner(PUNICODE_STRING imagePath)
{
    if (!imagePath || !imagePath->Buffer || imagePath->Length == 0)
        return;

    // Open the driver file on disk
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    InitializeObjectAttributes(&oa, imagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = ZwOpenFile(&fileHandle,
        FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) return;

    // Read DOS header
    IMAGE_DOS_HEADER dosHdr = {};
    LARGE_INTEGER offset = {};
    offset.QuadPart = 0;
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb,
        &dosHdr, sizeof(dosHdr), &offset, NULL);
    if (!NT_SUCCESS(status) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        ZwClose(fileHandle);
        return;
    }

    // Read NT headers (use 64-bit; DataDirectory offset is the same for our purpose)
    IMAGE_NT_HEADERS64 ntHdr = {};
    offset.QuadPart = dosHdr.e_lfanew;
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb,
        &ntHdr, sizeof(ntHdr), &offset, NULL);
    if (!NT_SUCCESS(status) || ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        ZwClose(fileHandle);
        return;
    }

    // Security directory (IMAGE_DIRECTORY_ENTRY_SECURITY = index 4)
    // Note: VirtualAddress here is a FILE offset, not an RVA.
    IMAGE_DATA_DIRECTORY secDir =
        ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (secDir.VirtualAddress == 0 || secDir.Size == 0 || secDir.Size > 128 * 1024) {
        ZwClose(fileHandle);
        return;  // no embedded certificate or unreasonably large
    }

    UCHAR* certBlob = (UCHAR*)ExAllocatePool2(
        POOL_FLAG_PAGED, secDir.Size, 'cert');
    if (!certBlob) { ZwClose(fileHandle); return; }

    offset.QuadPart = secDir.VirtualAddress;
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb,
        certBlob, secDir.Size, &offset, NULL);
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(certBlob, 'cert');
        return;
    }

    SIZE_T blobLen = (SIZE_T)secDir.Size;

    // --- Tier 1: known-bad signer organizations (CRITICAL) ---
    for (int i = 0; kMaliciousSignerOrgs[i]; i++) {
        if (CertBlobContains(certBlob, blobLen, kMaliciousSignerOrgs[i])) {
            // Narrow the image path for the alert message
            char pathNarrow[100] = {};
            USHORT chars = imagePath->Length / sizeof(WCHAR);
            if (chars > 99) chars = 99;
            for (USHORT c = 0; c < chars; c++)
                pathNarrow[c] = (imagePath->Buffer[c] < 128)
                                ? (char)imagePath->Buffer[c] : '?';

            char msg[300];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "MALICIOUS SIGNER: kernel driver '%s' signed by known-bad org '%s' "
                "(rootkit/APT certificate)",
                pathNarrow, kMaliciousSignerOrgs[i]);
            EmitSignerAlert(msg, TRUE);

            ExFreePoolWithTag(certBlob, 'cert');
            return;  // already CRITICAL, no need for Tier 2 check
        }
    }

    // --- Tier 2: adversary-nation country code (WARNING unless trusted) ---
    for (SIZE_T i = 0; i + sizeof(kOidCountryPrefix) + 2 <= blobLen; i++) {
        if (RtlCompareMemory(certBlob + i, kOidCountryPrefix,
                             sizeof(kOidCountryPrefix)) != sizeof(kOidCountryPrefix))
            continue;

        UCHAR cc[2] = { certBlob[i + 5], certBlob[i + 6] };

        for (int ci = 0; ci < ARRAYSIZE(kAdversaryCountries); ci++) {
            if (cc[0] != kAdversaryCountries[ci].code[0] ||
                cc[1] != kAdversaryCountries[ci].code[1])
                continue;

            // Check if the signer is in the trusted whitelist
            BOOLEAN trusted = FALSE;
            for (int ti = 0; kTrustedAdversaryNationSigners[ti]; ti++) {
                if (CertBlobContains(certBlob, blobLen,
                                     kTrustedAdversaryNationSigners[ti])) {
                    trusted = TRUE;
                    break;
                }
            }
            if (trusted) break;

            // Not in whitelist — emit WARNING
            char pathNarrow[100] = {};
            USHORT chars = imagePath->Length / sizeof(WCHAR);
            if (chars > 99) chars = 99;
            for (USHORT c = 0; c < chars; c++)
                pathNarrow[c] = (imagePath->Buffer[c] < 128)
                                ? (char)imagePath->Buffer[c] : '?';

            char msg[300];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "SUSPECT SIGNER: kernel driver '%s' signed with %s certificate "
                "not in trusted vendor whitelist",
                pathNarrow, kAdversaryCountries[ci].label);
            EmitSignerAlert(msg, FALSE);

            ExFreePoolWithTag(certBlob, 'cert');
            return;
        }
    }

    // --- Tier 3: certificate expiry date check ---
    //
    // X.509 validity dates are encoded as either:
    //   UTCTime (tag 0x17):        YYMMDDHHMMSSZ   (13 bytes, year < 50 → 20YY, ≥ 50 → 19YY)
    //   GeneralizedTime (tag 0x18): YYYYMMDDHHMMSSZ (15 bytes)
    //
    // X.509 certificates contain a SEQUENCE { notBefore, notAfter } in the
    // TBSCertificate.validity field.  In a PKCS#7 SignedData blob there may be
    // multiple certificates (signing cert + intermediates + root).  We scan for
    // ALL time fields and track the latest notAfter — that's the signing cert's
    // expiry (intermediates/roots typically expire later, but we want the leaf).
    //
    // We actually want the EARLIEST notAfter across all certs in the chain,
    // because the chain is only as valid as its weakest link — but in practice
    // the leaf cert always has the shortest lifetime, so we track the latest
    // notBefore-companion notAfter pair by looking at sequential time pairs.
    {
        USHORT latestNotAfterYear = 9999;  // we want the minimum notAfter year
        BOOLEAN foundAny = FALSE;

        for (SIZE_T i = 0; i + 2 < blobLen; i++) {
            USHORT year = 0;
            SIZE_T fieldLen = 0;

            if (certBlob[i] == 0x17 && certBlob[i + 1] == 13) {
                // UTCTime: YYMMDDHHMMSSZ
                if (i + 2 + 13 > blobLen) continue;
                UCHAR y0 = certBlob[i + 2] - '0';
                UCHAR y1 = certBlob[i + 3] - '0';
                if (y0 > 9 || y1 > 9) continue;
                USHORT yy = y0 * 10 + y1;
                year = (yy < 50) ? (2000 + yy) : (1900 + yy);
                fieldLen = 13;
            } else if (certBlob[i] == 0x18 && certBlob[i + 1] == 15) {
                // GeneralizedTime: YYYYMMDDHHMMSSZ
                if (i + 2 + 15 > blobLen) continue;
                UCHAR y0 = certBlob[i + 2] - '0';
                UCHAR y1 = certBlob[i + 3] - '0';
                UCHAR y2 = certBlob[i + 4] - '0';
                UCHAR y3 = certBlob[i + 5] - '0';
                if (y0 > 9 || y1 > 9 || y2 > 9 || y3 > 9) continue;
                year = y0 * 1000 + y1 * 100 + y2 * 10 + y3;
                fieldLen = 15;
            } else {
                continue;
            }

            if (year < 1990 || year > 2100) continue;  // sanity

            // Time fields in X.509 validity come in pairs: notBefore, notAfter.
            // We're interested in notAfter — the second of each pair.
            // Simple heuristic: track every time field, and the minimum year
            // that's plausibly a notAfter (> 2000) gives us the leaf cert expiry.
            // Skip obvious notBefore values (very early years).
            if (year >= 2005) {
                if (year < latestNotAfterYear) {
                    latestNotAfterYear = year;
                    foundAny = TRUE;
                }
            }

            // Advance past this time field to avoid re-scanning
            i += 1 + fieldLen;
        }

        if (foundAny && latestNotAfterYear < 2019) {
            char pathNarrow[100] = {};
            USHORT chars = imagePath->Length / sizeof(WCHAR);
            if (chars > 99) chars = 99;
            for (USHORT c = 0; c < chars; c++)
                pathNarrow[c] = (imagePath->Buffer[c] < 128)
                                ? (char)imagePath->Buffer[c] : '?';

            BOOLEAN isCritical = (latestNotAfterYear < 2015);
            char msg[300];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "%s: kernel driver '%s' signing certificate expired in %hu "
                "-- %s",
                isCritical ? "EXPIRED CERT" : "STALE CERT",
                pathNarrow, latestNotAfterYear,
                isCritical
                    ? "pre-2015 cross-signing era cert, high likelihood of abuse"
                    : "cert expired 7+ years ago, legitimate vendors would have re-signed");
            EmitSignerAlert(msg, isCritical);
        }
    }

    ExFreePoolWithTag(certBlob, 'cert');
}

VOID ImageUtils::ImageLoadNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL) {
        DbgPrint("[-] Invalid parameters\n");
        return;
    }

    if (ImageInfo->ImageSize == 0) {
        DbgPrint("[-] Image size is zero\n");
        return;
    }

    // -----------------------------------------------------------------
    // LOLDriver runtime check — fires for every kernel image load
    // (ProcessId == NULL means the image is loading into kernel space).
    // Matches the filename component of FullImageName against the
    // known-vulnerable driver basename list.
    // -----------------------------------------------------------------
    if (ProcessId == NULL) {
        // Convert full image path to narrow for matching
        ULONG charBufSz = FullImageName->Length / sizeof(WCHAR) + 1;
        char* charBuf = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, charBufSz, 'loln');
        if (charBuf) {
            UNICODE_STRING us;
            RtlInitUnicodeString(&us, FullImageName->Buffer);
            ANSI_STRING ansi;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &us, TRUE))) {
                RtlCopyMemory(charBuf, ansi.Buffer, ansi.Length);
                charBuf[ansi.Length] = '\0';
                SIZE_T cbLen = (SIZE_T)ansi.Length;
                RtlFreeAnsiString(&ansi);

                for (int li = 0; kLolDriverNames[li]; li++) {
                    if (IsLolDriverName(charBuf, cbLen, kLolDriverNames[li])) {
                        char lolMsg[200];
                        RtlStringCbPrintfA(lolMsg, sizeof(lolMsg),
                            "LOLDriver loaded: %s — known vulnerable/malicious kernel driver",
                            kLolDriverNames[li]);
                        SIZE_T lolLen = strlen(lolMsg) + 1;

                        PKERNEL_STRUCTURED_NOTIFICATION lolNotif =
                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED,
                                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'ldrn');
                        if (lolNotif) {
                            RtlZeroMemory(lolNotif, sizeof(*lolNotif));
                            SET_CRITICAL(*lolNotif);
                            SET_IMAGE_LOAD_PATH_CHECK(*lolNotif);
                            lolNotif->pid    = PsGetProcessId(PsGetCurrentProcess());
                            lolNotif->isPath = FALSE;
                            lolNotif->msg = (char*)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED, lolLen, 'ldrm');
                            lolNotif->bufSize = (ULONG)lolLen;
                            if (lolNotif->msg) {
                                RtlCopyMemory(lolNotif->msg, lolMsg, lolLen);
                                if (!CallbackObjects::GetNotifQueue()->Enqueue(lolNotif)) {
                                    ExFreePool(lolNotif->msg);
                                    ExFreePool(lolNotif);
                                }
                            } else { ExFreePool(lolNotif); }
                        }
                        break; // one alert per image load
                    }
                }
            }
            ExFreePool(charBuf);
        }
        // ---------------------------------------------------------------
        // Suspicious Authenticode signer detection for kernel drivers.
        //
        // Opens the driver file on disk, reads the PE security directory
        // (Authenticode signature), and searches the raw certificate blob
        // for:
        //   Tier 1 (CRITICAL) — known-bad organizations used by rootkits
        //     and APT groups (RegPhantom, FiveSys, Netfilter, etc.)
        //   Tier 2 (WARNING) — adversary-nation country codes (CN/RU/IR/KP)
        //     NOT in a trusted-signer whitelist.
        //
        // The country code is extracted by matching the DER-encoded OID
        // 2.5.4.6 (countryName): bytes 55 04 06 13 02 XX XX.
        // ---------------------------------------------------------------
        CheckDriverCertificateSigner(FullImageName);

        // Kernel image — no further per-process analysis needed.
        return;
    }

    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;

    __try {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProcess))) {
            DbgPrint("[-] PsLookupProcessByProcessId failed\n");
            return;
        }

        KeStackAttachProcess(targetProcess, &apcState);
        attached = TRUE;
    
        __try {

                if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
                    ULONG charBufferSize = FullImageName->Length / sizeof(WCHAR) + 1;
                    char* charBuffer = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, charBufferSize, 'jedb');

                    if (charBuffer) {
                        UNICODE_STRING unicodeString;
                        ANSI_STRING ansiString;

                        RtlInitUnicodeString(&unicodeString, FullImageName->Buffer);
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, TRUE))) {

                            RtlCopyMemory(charBuffer, ansiString.Buffer, ansiString.Length);
                            charBuffer[ansiString.Length] = '\0';

							PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

                            if (kernelNotif) {

                                SET_INFO(*kernelNotif);

                                kernelNotif->pid = PsGetProcessId(targetProcess);
                                kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ansiString.Length + 1, 'msg');
								kernelNotif->bufSize = ansiString.Length + 1;

                                if (kernelNotif->msg) {

                                    RtlCopyMemory(kernelNotif->msg, charBuffer, ansiString.Length + 1);
                                    kernelNotif->isPath = TRUE;

                                    if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
                                        ExFreePool(kernelNotif->msg);
                                        ExFreePool(kernelNotif);
                                    }
                                }
                                else {
                                    ExFreePool(kernelNotif);
                                }
                            }
                           
                            RtlFreeAnsiString(&ansiString);

                            // Detect amsi.dll load and scan exports for bypass patches.
                            // We are still attached to the target process here.
                            if (ImageInfo->ImageBase != NULL && ImageInfo->ImageSize > 0) {
                                SIZE_T cbLen = SafeStringLength(charBuffer, charBufferSize - 1);
                                BOOLEAN isAmsiDll = FALSE;
                                for (SIZE_T k = 0; k + 8 <= cbLen; k++) {
                                    if (((charBuffer[k]   | 0x20) == 'a') &&
                                        ((charBuffer[k+1] | 0x20) == 'm') &&
                                        ((charBuffer[k+2] | 0x20) == 's') &&
                                        ((charBuffer[k+3] | 0x20) == 'i') &&
                                         (charBuffer[k+4]         == '.') &&
                                        ((charBuffer[k+5] | 0x20) == 'd') &&
                                        ((charBuffer[k+6] | 0x20) == 'l') &&
                                        ((charBuffer[k+7] | 0x20) == 'l')) {
                                        isAmsiDll = TRUE;
                                        break;
                                    }
                                }
                                if (isAmsiDll) {
                                    AmsiDetector::ScanAmsiBypassPatterns(
                                        ImageInfo->ImageBase,
                                        ImageInfo->ImageSize,
                                        ProcessId,
                                        PsGetProcessImageFileName(targetProcess),
                                        CallbackObjects::GetNotifQueue()
                                    );
                                }

                                // Detect unmanaged PowerShell hosting:
                                // System.Management.Automation.dll loading into any process
                                // that is not a known legitimate PowerShell host is a strong
                                // indicator of the "spawn email client + host PS runtime" evasion
                                // technique (and reflective PS injection in general).
                                BOOLEAN isSMADll = FALSE;
                                for (SIZE_T k = 0; k + 28 <= cbLen; k++) {
                                    if (((charBuffer[k]    | 0x20) == 's') &&
                                        ((charBuffer[k+1]  | 0x20) == 'y') &&
                                        ((charBuffer[k+2]  | 0x20) == 's') &&
                                        ((charBuffer[k+3]  | 0x20) == 't') &&
                                        ((charBuffer[k+4]  | 0x20) == 'e') &&
                                        ((charBuffer[k+5]  | 0x20) == 'm') &&
                                         (charBuffer[k+6]           == '.') &&
                                        ((charBuffer[k+7]  | 0x20) == 'm') &&
                                        ((charBuffer[k+8]  | 0x20) == 'a') &&
                                        ((charBuffer[k+9]  | 0x20) == 'n') &&
                                        ((charBuffer[k+10] | 0x20) == 'a') &&
                                        ((charBuffer[k+11] | 0x20) == 'g') &&
                                        ((charBuffer[k+12] | 0x20) == 'e') &&
                                        ((charBuffer[k+13] | 0x20) == 'm') &&
                                        ((charBuffer[k+14] | 0x20) == 'e') &&
                                        ((charBuffer[k+15] | 0x20) == 'n') &&
                                        ((charBuffer[k+16] | 0x20) == 't') &&
                                         (charBuffer[k+17]          == '.') &&
                                        ((charBuffer[k+18] | 0x20) == 'a') &&
                                        ((charBuffer[k+19] | 0x20) == 'u') &&
                                        ((charBuffer[k+20] | 0x20) == 't') &&
                                        ((charBuffer[k+21] | 0x20) == 'o') &&
                                        ((charBuffer[k+22] | 0x20) == 'm') &&
                                        ((charBuffer[k+23] | 0x20) == 'a') &&
                                        ((charBuffer[k+24] | 0x20) == 't') &&
                                        ((charBuffer[k+25] | 0x20) == 'i') &&
                                        ((charBuffer[k+26] | 0x20) == 'o') &&
                                        ((charBuffer[k+27] | 0x20) == 'n')) {
                                        isSMADll = TRUE;
                                        break;
                                    }
                                }

                                if (isSMADll) {
                                    char* hostName = PsGetProcessImageFileName(targetProcess);
                                    if (hostName != NULL &&
                                        strcmp(hostName, "powershell.exe")   != 0 &&
                                        strcmp(hostName, "pwsh.exe")         != 0 &&
                                        strcmp(hostName, "wsmprovhost.exe")  != 0 &&
                                        strcmp(hostName, "powershell_ise")   != 0) {

                                        const char* smaMsg = "Unmanaged PowerShell hosting: System.Management.Automation.dll in unexpected process";
                                        SIZE_T smaMsgLen = 84;

                                        PKERNEL_STRUCTURED_NOTIFICATION smaNotif =
                                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

                                        if (smaNotif) {
                                            SET_CRITICAL(*smaNotif);
                                            SET_IMAGE_LOAD_PATH_CHECK(*smaNotif);
                                            SET_CALLING_PROC_PID_CHECK(*smaNotif);

                                            smaNotif->pid    = PsGetProcessId(targetProcess);
                                            smaNotif->isPath = FALSE;

                                            RtlStringCbCopyA(smaNotif->procName,
                                                             sizeof(smaNotif->procName),
                                                             hostName);

                                            char* msgBuf = (char*)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED, smaMsgLen + 1, 'msg');

                                            if (msgBuf) {
                                                RtlCopyMemory(msgBuf, smaMsg, smaMsgLen);
                                                msgBuf[smaMsgLen] = '\0';
                                                smaNotif->msg     = msgBuf;
                                                smaNotif->bufSize = (ULONG)(smaMsgLen + 1);

                                                if (!CallbackObjects::GetNotifQueue()->Enqueue(smaNotif)) {
                                                    ExFreePool(smaNotif->msg);
                                                    ExFreePool(smaNotif);
                                                }
                                            } else {
                                                ExFreePool(smaNotif);
                                            }
                                        }
                                    }
                                }

                                // -------------------------------------------------------
                                // Category 2: Mimikatz-family DLL import fingerprinting
                                //
                                // These DLLs have rarity score 100 (zero clean samples)
                                // and cluster in the differential as Mimikatz/credential-
                                // dumping tool signatures. Loading any of them into a
                                // non-system, non-lsass process is a Critical indicator.
                                //
                                // Covered DLLs and their attack role:
                                //   samlib.dll    — SAM database enumeration
                                //   cryptdll.dll  — Mimikatz crypto primitives (MD5Init etc.)
                                //   msasn1.dll    — Mimikatz certificate/ASN.1 parsing
                                //   winscard.dll  — Smart card credential theft
                                //   rstrtmgr.dll  — Ransomware: unlock files before encryption
                                //   fltlib.dll    — Enumerate minifilter drivers (EDR hunting)
                                //   winsta.dll    — RDP session hijacking / enumeration
                                //   mpr.dll       — Lateral movement via network share mapping
                                //   netapi32.dll  — Domain replication / Mimikatz DC attacks
                                //   dbghelp.dll   — MiniDumpWriteDump (LSASS dump)
                                //   secur32.dll   — LsaCallAuthenticationPackage (SSP abuse)
                                // -------------------------------------------------------

                                struct {
                                    const char* dll;        // substring to match in charBuffer
                                    SIZE_T      dllLen;
                                    const char* threat;     // description for the alert message
                                    BOOLEAN     alwaysCritical; // TRUE = Critical regardless of host
                                } kMimikatzDlls[] = {
                                    { "samlib.dll",   11, "SAM database enumeration (Mimikatz/secretsdump)",         TRUE  },
                                    { "cryptdll.dll", 12, "Mimikatz crypto primitives (MD5Init/CDLocateCSystem)",    TRUE  },
                                    { "msasn1.dll",   10, "Mimikatz ASN.1/certificate parsing",                     TRUE  },
                                    { "winscard.dll", 12, "Smart card credential theft",                            TRUE  },
                                    { "rstrtmgr.dll", 12, "Ransomware file-unlock (RmGetList/RmShutdown)",          TRUE  },
                                    { "fltlib.dll",   10, "Minifilter driver enumeration (EDR hunting)",            TRUE  },
                                    { "winsta.dll",   10, "RDP session hijacking/enumeration",                      TRUE  },
                                    { "mpr.dll",       7, "Network share lateral movement (WNetAddConnection2)",    FALSE },
                                    { "dbghelp.dll",  11, "MiniDumpWriteDump — LSASS/process memory dump",          TRUE  },
                                    { "secur32.dll",  11, "LsaCallAuthenticationPackage / SSP credential abuse",    TRUE  },
                                    { "netapi32.dll", 12, "Domain replication attack (I_NetServerAuthenticate2)",   TRUE  },
                                    { "comsvcs.dll",  12, "LOLBin MiniDump export — rundll32 comsvcs.dll,MiniDump lsass dump", TRUE },
                                    { "system.identitymodel.dll", 26, "Kerberos S4U delegation abuse (Rubeus/S4U2Self/S4U2Proxy)", TRUE },
                                    { nullptr, 0, nullptr, FALSE }
                                };

                                // Processes that legitimately load these DLLs
                                static const char* kAllowedHosts[] = {
                                    "lsass.exe", "svchost.exe", "services.exe",
                                    "winlogon.exe", "csrss.exe", "smss.exe",
                                    "wininit.exe", "spoolsv.exe", nullptr
                                };

                                char* loadingProcess = PsGetProcessImageFileName(targetProcess);
                                BOOLEAN isAllowedHost = FALSE;
                                if (loadingProcess) {
                                    for (int ah = 0; kAllowedHosts[ah] != nullptr; ah++) {
                                        if (strcmp(loadingProcess, kAllowedHosts[ah]) == 0) {
                                            isAllowedHost = TRUE;
                                            break;
                                        }
                                    }
                                }

                                if (!isAllowedHost) {
                                    for (int di = 0; kMimikatzDlls[di].dll != nullptr; di++) {
                                        const char* dll    = kMimikatzDlls[di].dll;
                                        SIZE_T      dllLen = kMimikatzDlls[di].dllLen;

                                        // Case-insensitive substring search for the DLL name
                                        BOOLEAN found = FALSE;
                                        if (cbLen >= dllLen) {
                                            for (SIZE_T k = 0; k <= cbLen - dllLen; k++) {
                                                BOOLEAN match = TRUE;
                                                for (SIZE_T m = 0; m < dllLen; m++) {
                                                    if ((charBuffer[k+m] | 0x20) != dll[m]) {
                                                        match = FALSE;
                                                        break;
                                                    }
                                                }
                                                if (match) { found = TRUE; break; }
                                            }
                                        }

                                        if (!found) continue;

                                        const char* threat = kMimikatzDlls[di].threat;
                                        SIZE_T      tLen   = strlen(threat);

                                        PKERNEL_STRUCTURED_NOTIFICATION mzNotif =
                                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED,
                                                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
                                        if (!mzNotif) break;

                                        if (kMimikatzDlls[di].alwaysCritical) {
                                            SET_CRITICAL(*mzNotif);
                                        } else {
                                            SET_WARNING(*mzNotif);
                                        }
                                        SET_IMAGE_LOAD_PATH_CHECK(*mzNotif);
                                        SET_CALLING_PROC_PID_CHECK(*mzNotif);

                                        mzNotif->pid    = PsGetProcessId(targetProcess);
                                        mzNotif->isPath = FALSE;
                                        if (loadingProcess) {
                                            RtlStringCbCopyA(mzNotif->procName,
                                                             sizeof(mzNotif->procName),
                                                             loadingProcess);
                                        }

                                        char* msgBuf = (char*)ExAllocatePool2(
                                            POOL_FLAG_NON_PAGED, tLen + 1, 'msg');
                                        if (msgBuf) {
                                            RtlCopyMemory(msgBuf, threat, tLen);
                                            msgBuf[tLen]    = '\0';
                                            mzNotif->msg    = msgBuf;
                                            mzNotif->bufSize = (ULONG)(tLen + 1);

                                            if (!CallbackObjects::GetNotifQueue()->Enqueue(mzNotif)) {
                                                ExFreePool(mzNotif->msg);
                                                ExFreePool(mzNotif);
                                            }
                                        } else {
                                            ExFreePool(mzNotif);
                                        }
                                        // Only fire one alert per image load event
                                        break;
                                    }
                                }

                            // -------------------------------------------------------
                            // CLR injection detection (Cobalt Strike execute-assembly)
                            //
                            // clr.dll / clrjit.dll / coreclr.dll loading into a
                            // process whose PE header lacks a COM descriptor
                            // (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, index 14) means
                            // the host is a native executable hosting the CLR at
                            // runtime — the hallmark of Cobalt Strike execute-assembly,
                            // Covenant GruntStager, and similar in-memory .NET
                            // assembly injection techniques.
                            //
                            // Check: parse PEB->ImageBaseAddress PE headers for the
                            // COM descriptor directory. Handle both PE32 and PE32+
                            // (WOW64 and native 64-bit processes).
                            // -------------------------------------------------------
                            BOOLEAN isClrLoad =
                                IsLolDriverName(charBuffer, cbLen, "clr.dll") ||
                                IsLolDriverName(charBuffer, cbLen, "clrjit.dll") ||
                                IsLolDriverName(charBuffer, cbLen, "coreclr.dll");

                            if (isClrLoad) {
                                BOOLEAN isDotNet = FALSE;
                                __try {
                                    PPEB peb = (PPEB)PsGetProcessPeb(targetProcess);
                                    if (peb && MmIsAddressValid(peb)) {
                                        PVOID imgBase = peb->ImageBaseAddress;
                                        if (imgBase && MmIsAddressValid(imgBase)) {
                                            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imgBase;
                                            if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
                                                dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                                                PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)
                                                    ((BYTE*)imgBase + dos->e_lfanew);
                                                if (MmIsAddressValid(ntHdr) &&
                                                    ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                                                    WORD magic = ntHdr->OptionalHeader.Magic;
                                                    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                                                        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHdr;
                                                        if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
                                                            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)
                                                            isDotNet = TRUE;
                                                    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                                                        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHdr;
                                                        if (nt32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
                                                            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)
                                                            isDotNet = TRUE;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                                if (!isDotNet) {
                                    // Native processes that legitimately host the CLR
                                    static const char* kLegitClrHosts[] = {
                                        "w3wp.exe",       // IIS worker process
                                        "mmc.exe",        // Management Console (.NET snap-ins)
                                        "sqlservr.exe",   // SQL Server CLR integration
                                        "iisexpress.exe", // IIS Express
                                        "dllhost.exe",    // COM+ surrogate for .NET COM
                                        "wmiprvse.exe",   // WMI .NET providers
                                        nullptr
                                    };

                                    BOOLEAN isAllowedClrHost = FALSE;
                                    if (loadingProcess) {
                                        for (int ch = 0; kLegitClrHosts[ch]; ch++) {
                                            if (strcmp(loadingProcess, kLegitClrHosts[ch]) == 0) {
                                                isAllowedClrHost = TRUE;
                                                break;
                                            }
                                        }
                                    }

                                    if (!isAllowedClrHost) {
                                        InjectionTaintTracker::MarkTainted(
                                            PsGetProcessId(targetProcess));

                                        char clrMsg[200];
                                        RtlStringCbPrintfA(clrMsg, sizeof(clrMsg),
                                            "CLR loaded into non-.NET process '%s' — "
                                            "possible execute-assembly / in-memory .NET injection",
                                            loadingProcess ? loadingProcess : "?");
                                        SIZE_T clrLen = strlen(clrMsg) + 1;

                                        PKERNEL_STRUCTURED_NOTIFICATION clrNotif =
                                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED,
                                                sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
                                        if (clrNotif) {
                                            RtlZeroMemory(clrNotif, sizeof(*clrNotif));
                                            SET_CRITICAL(*clrNotif);
                                            SET_IMAGE_LOAD_PATH_CHECK(*clrNotif);
                                            SET_CALLING_PROC_PID_CHECK(*clrNotif);
                                            clrNotif->pid = PsGetProcessId(targetProcess);
                                            clrNotif->isPath = FALSE;
                                            if (loadingProcess)
                                                RtlStringCbCopyA(clrNotif->procName,
                                                                 sizeof(clrNotif->procName),
                                                                 loadingProcess);
                                            clrNotif->msg = (char*)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED, clrLen, 'msg');
                                            if (clrNotif->msg) {
                                                RtlCopyMemory(clrNotif->msg, clrMsg, clrLen);
                                                clrNotif->bufSize = (ULONG)clrLen;
                                                if (!CallbackObjects::GetNotifQueue()->Enqueue(clrNotif)) {
                                                    ExFreePool(clrNotif->msg);
                                                    ExFreePool(clrNotif);
                                                }
                                            } else {
                                                ExFreePool(clrNotif);
                                            }
                                        }
                                    }
                                }
                            }

                            // ntdll double-load detection: second ntdll.dll image load
                            // into the same process is an extremely rare event in clean
                            // populations (0.04% over 27M processes/month) and is the
                            // primary signature of ntdll remap and hook-evasion tooling.
                            if (IsNtdllPath(charBuffer, cbLen)) {
                                ULONG curPid = HandleToUlong(PsGetProcessId(targetProcess));
                                if (NtdllSeenBefore(curPid)) {
                                    // Record the secondary mapping so APC/thread handlers
                                    // can detect LdrLoadDll resolved from this private copy.
                                    if (ImageInfo->ImageBase && ImageInfo->ImageSize > 0)
                                        RecordSecondaryNtdll(curPid,
                                            ImageInfo->ImageBase, ImageInfo->ImageSize);

                                    const char* msg =
                                        "ntdll.dll loaded more than once into process — "
                                        "ntdll remap/hook-evasion technique detected";
                                    SIZE_T msgLen = strlen(msg);
                                    PKERNEL_STRUCTURED_NOTIFICATION n =
                                        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                            POOL_FLAG_NON_PAGED,
                                            sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
                                    if (n) {
                                        RtlZeroMemory(n, sizeof(*n));
                                        SET_CRITICAL(*n);
                                        SET_IMAGE_LOAD_PATH_CHECK(*n);
                                        n->pid    = PsGetProcessId(targetProcess);
                                        n->isPath = FALSE;
                                        if (loadingProcess)
                                            RtlStringCbCopyA(n->procName, sizeof(n->procName),
                                                             loadingProcess);
                                        n->msg = (char*)ExAllocatePool2(
                                            POOL_FLAG_NON_PAGED, msgLen + 1, 'msg');
                                        if (n->msg) {
                                            RtlCopyMemory(n->msg, msg, msgLen + 1);
                                            n->bufSize = (ULONG)(msgLen + 1);
                                            if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
                                                ExFreePool(n->msg);
                                                ExFreePool(n);
                                            }
                                        } else {
                                            ExFreePool(n);
                                        }
                                    }
                                }
                            }

                            // -------------------------------------------------------
                            // DLL sideloading detection (MITRE T1574.002)
                            //
                            // Adversaries place a malicious copy of a Windows system
                            // DLL in the same directory as a legitimate signed exe.
                            // Windows DLL search order loads the local copy first,
                            // executing attacker code inside a trusted process.
                            //
                            // Detection: when a known system DLL loads from outside
                            // \Windows\System32\, \Windows\SysWOW64\, or
                            // \Windows\WinSxS\, emit a WARNING.
                            //
                            // Common usage: APT41 (version.dll), Lazarus (winhttp),
                            // MuddyWater (winmm), SolarWinds toolchain, numerous
                            // ransomware initial-access loaders.
                            // -------------------------------------------------------
                            {
                                struct {
                                    const char* name;
                                    SIZE_T      nameLen;
                                } kSideloadTargets[] = {
                                    { "version.dll",          11 },  // #1 sideloaded DLL globally
                                    { "winmm.dll",             9 },  // Audio API — APT10, MuddyWater
                                    { "winhttp.dll",          11 },  // HTTP client — Lazarus, APT29
                                    { "cryptbase.dll",        13 },  // Crypto primitives
                                    { "cryptsp.dll",          10 },  // Crypto service provider
                                    { "profapi.dll",          11 },  // User profile API
                                    { "sspicli.dll",          11 },  // SSPI auth client
                                    { "dwmapi.dll",           10 },  // Desktop Window Manager API
                                    { "propsys.dll",          11 },  // Property system
                                    { "wtsapi32.dll",         12 },  // Terminal services API
                                    { "uxtheme.dll",          11 },  // Visual theme engine
                                    { "msimg32.dll",          11 },  // Image manipulation
                                    { "userenv.dll",          11 },  // User environment/profile
                                    { "iphlpapi.dll",         12 },  // Network interface enum
                                    { "netutils.dll",         12 },  // Network utility functions
                                    { "npmproxy.dll",         12 },  // Network provider proxy
                                    { "dpapi.dll",             9 },  // Data protection API
                                    { "edgegdi.dll",          11 },  // GDI proxy — SUNBURST chain
                                    { nullptr, 0 }
                                };

                                // System directories where these DLLs legitimately reside.
                                // Compared case-insensitively against the full NT path.
                                static const char* kLegitDirs[] = {
                                    "\\windows\\system32\\",
                                    "\\windows\\syswow64\\",
                                    "\\windows\\winsxs\\",
                                    "\\windows\\systemapps\\",
                                    "\\windows\\microsoft.net\\",
                                    nullptr
                                };

                                // Extract just the filename from charBuffer
                                const char* slLastSlash = nullptr;
                                for (SIZE_T si = 0; si < cbLen; si++) {
                                    if (charBuffer[si] == '\\')
                                        slLastSlash = &charBuffer[si];
                                }
                                const char* slFileName = slLastSlash
                                    ? (slLastSlash + 1) : charBuffer;
                                SIZE_T slNameLen = cbLen -
                                    (SIZE_T)(slFileName - charBuffer);

                                for (int st = 0; kSideloadTargets[st].name; st++) {
                                    if (slNameLen != kSideloadTargets[st].nameLen)
                                        continue;

                                    // Case-insensitive filename compare
                                    BOOLEAN nameHit = TRUE;
                                    for (SIZE_T ci = 0; ci < slNameLen; ci++) {
                                        char a = slFileName[ci];
                                        char b = kSideloadTargets[st].name[ci];
                                        if (a >= 'A' && a <= 'Z') a |= 0x20;
                                        if (b >= 'A' && b <= 'Z') b |= 0x20;
                                        if (a != b) {
                                            nameHit = FALSE;
                                            break;
                                        }
                                    }
                                    if (!nameHit) continue;

                                    // Name matches — verify path is a system directory
                                    BOOLEAN fromSysDir = FALSE;
                                    for (int ld = 0; kLegitDirs[ld]; ld++) {
                                        SIZE_T ldLen = strlen(kLegitDirs[ld]);
                                        if (cbLen < ldLen) continue;
                                        for (SIZE_T sp = 0;
                                             sp <= cbLen - ldLen; sp++) {
                                            BOOLEAN dm = TRUE;
                                            for (SIZE_T sm = 0; sm < ldLen;
                                                 sm++) {
                                                char c = charBuffer[sp + sm];
                                                if (c >= 'A' && c <= 'Z')
                                                    c |= 0x20;
                                                if (c != kLegitDirs[ld][sm]) {
                                                    dm = FALSE;
                                                    break;
                                                }
                                            }
                                            if (dm) {
                                                fromSysDir = TRUE;
                                                break;
                                            }
                                        }
                                        if (fromSysDir) break;
                                    }

                                    if (!fromSysDir) {
                                        char slMsg[350];
                                        RtlStringCbPrintfA(slMsg, sizeof(slMsg),
                                            "DLL sideloading (T1574.002): "
                                            "'%s' loaded from non-system "
                                            "path '%.*s' by '%s'",
                                            kSideloadTargets[st].name,
                                            (int)(cbLen > 200 ? 200 : cbLen),
                                            charBuffer,
                                            loadingProcess
                                                ? loadingProcess : "?");
                                        SIZE_T slLen = strlen(slMsg) + 1;

                                        PKERNEL_STRUCTURED_NOTIFICATION slN =
                                            (PKERNEL_STRUCTURED_NOTIFICATION)
                                            ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED,
                                                sizeof(KERNEL_STRUCTURED_NOTIFICATION),
                                                'krnl');
                                        if (slN) {
                                            RtlZeroMemory(slN, sizeof(*slN));
                                            SET_WARNING(*slN);
                                            SET_IMAGE_LOAD_PATH_CHECK(*slN);
                                            SET_CALLING_PROC_PID_CHECK(*slN);
                                            slN->pid = PsGetProcessId(
                                                targetProcess);
                                            slN->isPath = TRUE;
                                            if (loadingProcess)
                                                RtlStringCbCopyA(
                                                    slN->procName,
                                                    sizeof(slN->procName),
                                                    loadingProcess);
                                            slN->msg = (char*)
                                                ExAllocatePool2(
                                                    POOL_FLAG_NON_PAGED,
                                                    slLen, 'msg');
                                            if (slN->msg) {
                                                RtlCopyMemory(slN->msg,
                                                    slMsg, slLen);
                                                slN->bufSize = (ULONG)slLen;
                                                if (!CallbackObjects::
                                                    GetNotifQueue()->
                                                    Enqueue(slN)) {
                                                    ExFreePool(slN->msg);
                                                    ExFreePool(slN);
                                                }
                                            } else {
                                                ExFreePool(slN);
                                            }
                                        }
                                    }
                                    break;  // one match per image load
                                }
                            }

                            // Argument-spoofing discrepancy check (Adam Chester / CS "argue"):
                            // compare the kernel's authentic cmdline (saved at CreateProcessNotifyEx)
                            // with what's now in the PEB, while still attached to the process.
                            // By the time the first user DLL loads, any parent PEB patch has occurred.
                            ImageUtils::CheckCmdLineDiscrepancy(
                                HandleToUlong(ProcessId), targetProcess);

                            ExFreePool(charBuffer);
                        }
                        else {
                            ExFreePool(charBuffer);
                        }
                    }
                
            }
            else {
                DbgPrint("[-] Failed to allocate memory for section data\n");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception in ImageLoadNotifyRoutine\n");
        }

        // --- Phantom DLL detection: hash critical images for deferred re-verification ---
        if (ImageInfo->ImageBase && ImageInfo->ImageSize > 0 &&
            ShouldHashImage(FullImageName))
        {
            BYTE digest[SHA256_BLOCK_SIZE] = {};
            BOOLEAN hashed = FALSE;
            __try {
                SHA256_CTX hashCtx;
                SHA256Init(&hashCtx);
                SIZE_T remaining = ImageInfo->ImageSize;
                BYTE* ptr = (BYTE*)ImageInfo->ImageBase;
                while (remaining > 0) {
                    SIZE_T chunk = min(remaining, (SIZE_T)4096);
                    if (!MmIsAddressValid(ptr)) break;
                    SHA256Update(&hashCtx, ptr, chunk);
                    ptr += chunk;
                    remaining -= chunk;
                }
                SHA256Final(digest, &hashCtx);
                hashed = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}

            if (hashed) {
                KIRQL hashIrql;
                KeAcquireSpinLock(&g_ImageHashLock, &hashIrql);
                for (int hi = 0; hi < MAX_IMAGE_HASHES; hi++) {
                    if (!g_ImageHashes[hi].used) {
                        g_ImageHashes[hi].pid       = HandleToUlong(ProcessId);
                        g_ImageHashes[hi].imageBase = ImageInfo->ImageBase;
                        g_ImageHashes[hi].imageSize = ImageInfo->ImageSize;
                        RtlCopyMemory(g_ImageHashes[hi].hash, digest, SHA256_BLOCK_SIZE);
                        g_ImageHashes[hi].used      = TRUE;
                        break;
                    }
                }
                KeReleaseSpinLock(&g_ImageHashLock, hashIrql);

                QueueHashVerification(
                    HandleToUlong(ProcessId),
                    ImageInfo->ImageBase,
                    ImageInfo->ImageSize,
                    digest);
            }
        }

        // --- Signature level sanity check for critical system DLLs ---
        // Windows 10 1709+ populates ImageSignatureLevel in IMAGE_INFO.Properties
        // (bits 12-15). Microsoft-signed system DLLs (ntdll, kernel32, kernelbase,
        // amsi, clr, clrjit) should have level >= SE_SIGNING_LEVEL_MICROSOFT (8).
        // A level of 1-7 means CI checked and found the image below Microsoft-signed
        // threshold — CI.dll was bypassed or the image catalog was tampered with.
        // Level 0 (UNCHECKED) is ambiguous (could be old OS) so we skip it.
        if (ShouldHashImage(FullImageName)) {
            ULONG sigLevel = (ImageInfo->Properties >> 12) & 0xF;
            if (sigLevel >= 1 && sigLevel <= 7) {
                char sigMsg[200];
                RtlStringCbPrintfA(sigMsg, sizeof(sigMsg),
                    "Critical DLL signature level below Microsoft-signed "
                    "(level=%lu) — CI bypass or catalog tampering detected",
                    sigLevel);
                SIZE_T sigLen = strlen(sigMsg) + 1;

                PKERNEL_STRUCTURED_NOTIFICATION sigNotif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
                if (sigNotif) {
                    RtlZeroMemory(sigNotif, sizeof(*sigNotif));
                    SET_CRITICAL(*sigNotif);
                    SET_IMAGE_LOAD_PATH_CHECK(*sigNotif);
                    SET_CI_INTEGRITY_CHECK(*sigNotif);
                    sigNotif->pid = PsGetProcessId(targetProcess);
                    sigNotif->isPath = FALSE;
                    char* procName = PsGetProcessImageFileName(targetProcess);
                    if (procName)
                        RtlStringCbCopyA(sigNotif->procName,
                                         sizeof(sigNotif->procName), procName);
                    sigNotif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sigLen, 'msg');
                    if (sigNotif->msg) {
                        RtlCopyMemory(sigNotif->msg, sigMsg, sigLen);
                        sigNotif->bufSize = (ULONG)sigLen;
                        if (!CallbackObjects::GetNotifQueue()->Enqueue(sigNotif)) {
                            ExFreePool(sigNotif->msg);
                            ExFreePool(sigNotif);
                        }
                    } else {
                        ExFreePool(sigNotif);
                    }
                }
            }
        }

        // Queue HookDll APC while still attached — allocates path buffer in target process.
        DllInjector::TryInject(targetProcess, FullImageName);

        KeUnstackDetachProcess(&apcState);
        attached = FALSE;
    }
    __finally {
        if (attached) {
            KeUnstackDetachProcess(&apcState);
        }
        if (targetProcess) {
            ObDereferenceObject(targetProcess);
        }
    }
}

// Exposed for Ps*Notify integrity check in HookDetection
PVOID ImageUtils::s_NotifyFn = (PVOID)ImageLoadNotifyRoutine;

// ---------------------------------------------------------------------------
// PsSetLoadImageNotifyRoutineEx — Win10 1709+.
// Flags = 0 covers standard image loads including Pico process image maps.
// Resolved at runtime; falls back to PsSetLoadImageNotifyRoutine.
// Removal always uses PsRemoveLoadImageNotifyRoutine for both variants.
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnPsSetLoadImageNotifyRoutineEx)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
    ULONG_PTR                  Flags);

static pfnPsSetLoadImageNotifyRoutineEx g_pSetImageEx = nullptr;

VOID ImageUtils::setImageNotificationCallback() {

    KeInitializeSpinLock(&g_NtdllPidLock);
    KeInitializeSpinLock(&g_CmdLineRecLock);
    KeInitializeSpinLock(&g_ImageHashLock);
    InitSecondaryNtdllTracker();

    // Prefer Ex (subsystem-aware, Win10 1709+).
    UNICODE_STRING usEx;
    RtlInitUnicodeString(&usEx, L"PsSetLoadImageNotifyRoutineEx");
    g_pSetImageEx = (pfnPsSetLoadImageNotifyRoutineEx)
        MmGetSystemRoutineAddress(&usEx);

    NTSTATUS status;
    if (g_pSetImageEx) {
        status = g_pSetImageEx(ImageLoadNotifyRoutine, 0);
        if (NT_SUCCESS(status)) {
            DbgPrint("[+] PsSetLoadImageNotifyRoutineEx (subsystems) success\n");
            return;
        }
        DbgPrint("[-] PsSetLoadImageNotifyRoutineEx failed — falling back\n");
    }

	status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);
	if (!NT_SUCCESS(status))
		DbgPrint("[-] PsSetLoadImageNotifyRoutine failed\n");
    else
		DbgPrint("[+] PsSetLoadImageNotifyRoutine success\n");
}

VOID ImageUtils::unsetImageNotificationCallback() {

	// PsRemoveLoadImageNotifyRoutine removes callbacks registered by either
	// PsSetLoadImageNotifyRoutine or PsSetLoadImageNotifyRoutineEx.
	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsRemoveLoadImageNotifyRoutine failed\n");
    }
    else {
		DbgPrint("[+] PsRemoveLoadImageNotifyRoutine success\n");
    }

}