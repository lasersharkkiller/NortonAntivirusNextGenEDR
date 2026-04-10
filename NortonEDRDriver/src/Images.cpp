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

                            // ntdll double-load detection: second ntdll.dll image load
                            // into the same process is an extremely rare event in clean
                            // populations (0.04% over 27M processes/month) and is the
                            // primary signature of ntdll remap and hook-evasion tooling.
                            if (IsNtdllPath(charBuffer, cbLen)) {
                                ULONG curPid = HandleToUlong(PsGetProcessId(targetProcess));
                                if (NtdllSeenBefore(curPid)) {
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