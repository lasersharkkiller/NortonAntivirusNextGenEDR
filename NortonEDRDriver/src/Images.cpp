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