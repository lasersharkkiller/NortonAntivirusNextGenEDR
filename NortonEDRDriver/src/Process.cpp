#include "Globals.h"

// ---------------------------------------------------------------------------
// PsGetProcessMitigationPolicy — resolved once on first use.
// Available from Windows 10 1703+.  Returns the same struct layout as the
// user-mode GetProcessMitigationPolicy for each PROCESS_MITIGATION_POLICY
// enum value (query buffer is a DWORD of bit-flags).
//
// We use this to detect two EDR-evasion mitigations set on a child process:
//   ProcessSignaturePolicy (8) bit 0 = MicrosoftSignedOnly  → blocks HookDll injection
//   ProcessDynamicCodePolicy (2) bit 0 = ProhibitDynamicCode → blocks RWX trampoline pool
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnPsGetProcessMitigationPolicy)(
    PEPROCESS Process,
    ULONG     MitigationPolicy,   // PROCESS_MITIGATION_POLICY enum value
    PVOID     Buffer,
    SIZE_T    BufferSize);

static volatile LONG             g_MitigInitDone = 0;
static pfnPsGetProcessMitigationPolicy g_PsGetMitig = nullptr;

static VOID EnsureMitigationResolver() {
    if (InterlockedCompareExchange(&g_MitigInitDone, 1, 0) == 0) {
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"PsGetProcessMitigationPolicy");
        g_PsGetMitig = (pfnPsGetProcessMitigationPolicy)MmGetSystemRoutineAddress(&us);
    }
}

// ---------------------------------------------------------------------------
// ForkRunTracker implementation
// ---------------------------------------------------------------------------

static FORK_TRACK_ENTRY g_ForkSlots[FORK_TRACK_MAX];
static KSPIN_LOCK        g_ForkLock;
static LONG              g_ForkInitDone = 0;

VOID ForkRunTracker::Init() {
    if (InterlockedCompareExchange(&g_ForkInitDone, 1, 0) == 0) {
        RtlZeroMemory(g_ForkSlots, sizeof(g_ForkSlots));
        KeInitializeSpinLock(&g_ForkLock);
    }
}

VOID ForkRunTracker::TrackProcess(HANDLE pid, BOOLEAN knownHost, BOOLEAN suspiciousCmdLine) {
    if (!pid) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_ForkLock, &irql);
    // Check for duplicate (re-use if process restarted with same PID — rare but safe)
    for (int i = 0; i < FORK_TRACK_MAX; i++) {
        if (g_ForkSlots[i].Pid == pid) {
            // Update flags on duplicate
            g_ForkSlots[i].KnownHost         |= knownHost;
            g_ForkSlots[i].SuspiciousCmdLine  |= suspiciousCmdLine;
            KeReleaseSpinLock(&g_ForkLock, irql);
            return;
        }
    }
    for (int i = 0; i < FORK_TRACK_MAX; i++) {
        if (g_ForkSlots[i].Pid == nullptr) {
            g_ForkSlots[i].Pid               = pid;
            g_ForkSlots[i].KnownHost         = knownHost;
            g_ForkSlots[i].SuspiciousCmdLine = suspiciousCmdLine;
            g_ForkSlots[i].WrittenTo         = FALSE;
            g_ForkSlots[i].Alerted           = FALSE;
            break;
        }
    }
    // Table full: silently drop (64 concurrent injections is an unrealistic load)
    KeReleaseSpinLock(&g_ForkLock, irql);
}

VOID ForkRunTracker::MarkWritten(HANDLE targetPid) {
    if (!targetPid) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_ForkLock, &irql);
    for (int i = 0; i < FORK_TRACK_MAX; i++) {
        if (g_ForkSlots[i].Pid == targetPid) {
            g_ForkSlots[i].WrittenTo = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ForkLock, irql);
}

BOOLEAN ForkRunTracker::CheckForkRun(HANDLE targetPid) {
    if (!targetPid) return FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_ForkLock, &irql);
    BOOLEAN fire = FALSE;
    for (int i = 0; i < FORK_TRACK_MAX; i++) {
        if (g_ForkSlots[i].Pid == targetPid &&
            g_ForkSlots[i].WrittenTo        &&
            !g_ForkSlots[i].Alerted) {
            g_ForkSlots[i].Alerted = TRUE;
            fire = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ForkLock, irql);
    return fire;
}

VOID ForkRunTracker::Remove(HANDLE pid) {
    if (!pid) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_ForkLock, &irql);
    for (int i = 0; i < FORK_TRACK_MAX; i++) {
        if (g_ForkSlots[i].Pid == pid) {
            RtlZeroMemory(&g_ForkSlots[i], sizeof(FORK_TRACK_ENTRY));
            break;
        }
    }
    KeReleaseSpinLock(&g_ForkLock, irql);
}

// ---------------------------------------------------------------------------
// InjectionTaintTracker implementation
//
// When any subsystem detects code injection into a process, it calls
// MarkTainted(pid).  The WFP C2 beaconing detector then strips allowlist
// immunity for that PID so traffic from injected svchost/chrome/etc. gets
// frequency-checked.  Entries expire after TAINT_EXPIRY_MS (10 min).
// ---------------------------------------------------------------------------

static TaintEntry   g_TaintSlots[TAINT_TABLE_MAX];
static KSPIN_LOCK   g_TaintLock;
static LONG         g_TaintInitDone = 0;

VOID InjectionTaintTracker::Init() {
    if (InterlockedCompareExchange(&g_TaintInitDone, 1, 0) == 0) {
        RtlZeroMemory(g_TaintSlots, sizeof(g_TaintSlots));
        KeInitializeSpinLock(&g_TaintLock);
    }
}

VOID InjectionTaintTracker::MarkTainted(HANDLE pid) {
    if (!pid) return;
    ULONG uPid = HandleToUlong(pid);
    LONGLONG now = (LONGLONG)KeQueryInterruptTime();

    KIRQL irql;
    KeAcquireSpinLock(&g_TaintLock, &irql);

    // Check if already present
    for (int i = 0; i < TAINT_TABLE_MAX; i++) {
        if (g_TaintSlots[i].Used && g_TaintSlots[i].Pid == uPid) {
            g_TaintSlots[i].Timestamp = now;  // refresh expiry
            KeReleaseSpinLock(&g_TaintLock, irql);
            return;
        }
    }

    // Find a free or expired slot
    LONGLONG expiryTicks = TAINT_EXPIRY_MS * 10000LL;
    int freeSlot  = -1;
    int oldestIdx = 0;
    LONGLONG oldestTs = 0x7FFFFFFFFFFFFFFFLL;

    for (int i = 0; i < TAINT_TABLE_MAX; i++) {
        if (!g_TaintSlots[i].Used) {
            if (freeSlot < 0) freeSlot = i;
            continue;
        }
        // Evict expired entries opportunistically
        if ((now - g_TaintSlots[i].Timestamp) > expiryTicks) {
            g_TaintSlots[i].Used = FALSE;
            if (freeSlot < 0) freeSlot = i;
            continue;
        }
        if (g_TaintSlots[i].Timestamp < oldestTs) {
            oldestTs  = g_TaintSlots[i].Timestamp;
            oldestIdx = i;
        }
    }

    int slot = (freeSlot >= 0) ? freeSlot : oldestIdx;  // evict oldest if full
    g_TaintSlots[slot].Pid       = uPid;
    g_TaintSlots[slot].Timestamp = now;
    g_TaintSlots[slot].Used      = TRUE;

    KeReleaseSpinLock(&g_TaintLock, irql);
    DbgPrint("[+] InjectionTaintTracker: PID %lu tainted\n", uPid);
}

BOOLEAN InjectionTaintTracker::IsTainted(UINT64 pid) {
    ULONG uPid = (ULONG)pid;
    LONGLONG now = (LONGLONG)KeQueryInterruptTime();
    LONGLONG expiryTicks = TAINT_EXPIRY_MS * 10000LL;

    KIRQL irql;
    KeAcquireSpinLock(&g_TaintLock, &irql);
    for (int i = 0; i < TAINT_TABLE_MAX; i++) {
        if (g_TaintSlots[i].Used && g_TaintSlots[i].Pid == uPid) {
            if ((now - g_TaintSlots[i].Timestamp) > expiryTicks) {
                g_TaintSlots[i].Used = FALSE;  // expired
                KeReleaseSpinLock(&g_TaintLock, irql);
                return FALSE;
            }
            KeReleaseSpinLock(&g_TaintLock, irql);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_TaintLock, irql);
    return FALSE;
}

VOID InjectionTaintTracker::Remove(HANDLE pid) {
    if (!pid) return;
    ULONG uPid = HandleToUlong(pid);
    KIRQL irql;
    KeAcquireSpinLock(&g_TaintLock, &irql);
    for (int i = 0; i < TAINT_TABLE_MAX; i++) {
        if (g_TaintSlots[i].Used && g_TaintSlots[i].Pid == uPid) {
            g_TaintSlots[i].Used = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_TaintLock, irql);
}

// Known Cobalt Strike spawnto / process-injection host binaries (lowercase).
// This list covers CS defaults and the most common attacker-configured targets.
static const char* kSpawntoHosts[] = {
    "rundll32.exe",
    "dllhost.exe",
    "werfault.exe",   // WerFault.exe — CS default on x64
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "gpupdate.exe",
    "explorer.exe",
    nullptr
};

// Returns TRUE if procName (already lowercase-normalised) is a known spawnto host.
static BOOLEAN IsKnownSpawntoHost(const char* procName) {
    if (!procName) return FALSE;
    for (int i = 0; kSpawntoHosts[i]; i++) {
        if (strcmp(procName, kSpawntoHosts[i]) == 0) return TRUE;
    }
    return FALSE;
}

// Returns TRUE if the command line looks like a process spawned with no real
// arguments — just the binary name (or empty), which is the fork-and-run default.
// needle: lowercase 15-char ANSI image filename from PsGetProcessImageFileName.
static BOOLEAN IsSuspiciousCmdLine(PCUNICODE_STRING cmdLine, const char* imgName) {
    if (!cmdLine || !cmdLine->Buffer || cmdLine->Length == 0) return TRUE; // empty = suspicious

    USHORT chars = cmdLine->Length / sizeof(WCHAR);

    // Strip leading quote and path, find actual argument portion.
    // Format is typically: "C:\Windows\System32\rundll32.exe" [args]
    // or: C:\Windows\System32\rundll32.exe [args]
    USHORT argStart = 0;
    BOOLEAN inQuote = (cmdLine->Buffer[0] == L'"');
    if (inQuote) {
        // Find closing quote
        for (USHORT i = 1; i < chars; i++) {
            if (cmdLine->Buffer[i] == L'"') { argStart = i + 1; break; }
        }
    } else {
        // Find first space after the exe path
        for (USHORT i = 0; i < chars; i++) {
            if (cmdLine->Buffer[i] == L' ') { argStart = i + 1; break; }
        }
    }

    // Skip leading spaces in the argument portion
    while (argStart < chars && cmdLine->Buffer[argStart] == L' ') argStart++;

    // Fewer than 2 characters of actual arguments = suspicious
    return (BOOLEAN)((chars - argStart) < 2);
}

BOOLEAN ProcessUtils::isProcessImageTampered() {

	NTSTATUS status;
	BOOLEAN isTampered = FALSE;

	char* fileName = PsGetProcessImageFileName(this->process);

	if (fileName != NULL) {

		ANSI_STRING ansiString;
		RtlInitAnsiString(&ansiString, fileName);

		UNICODE_STRING unicodeString;
		RtlZeroMemory(&unicodeString, sizeof(UNICODE_STRING));

		status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[!] Failed to convert ANSI String to Unicode String !");
			return FALSE;
		}

		vadUtils.exploreVadTreeAndVerifyLdrIngtegrity(
			vadUtils.getVadRoot()->BalancedRoot,
			&unicodeString,
			&isTampered
		);

		RtlFreeUnicodeString(&unicodeString);
	}

	return isTampered;
}

BOOLEAN ProcessUtils::isProcessParentPidSpoofed(
	PPS_CREATE_NOTIFY_INFO CreateInfo
) {
	if (CreateInfo->ParentProcessId != CreateInfo->CreatingThreadId.UniqueProcess) {

		return TRUE;
	}

	return FALSE;
}

BOOLEAN ProcessUtils::isProcessGhosted() {

	SE_AUDIT_PROCESS_CREATION_INFO* SeAuditProcessCreationInfo = (SE_AUDIT_PROCESS_CREATION_INFO*)((PUCHAR)this->process + OffsetsMgt::GetOffsets()->SeAuditProcessCreationInfo);

	if (MmIsAddressValid(SeAuditProcessCreationInfo) && SeAuditProcessCreationInfo->ImageFileName != NULL) {	
		if (SeAuditProcessCreationInfo->ImageFileName->Name.Buffer == NULL) {
			return TRUE;
		}
	}

	return FALSE;
}

// ---------------------------------------------------------------------------
// Command line argument analysis helpers
// ---------------------------------------------------------------------------

// Case-insensitive substring search over a UNICODE_STRING.
// needle must be a lowercase literal — only the haystack characters are
// lowercased at comparison time (ASCII range only; non-ASCII chars are left
// as-is, so non-ASCII needles will match exactly).
static BOOLEAN CmdContains(PCUNICODE_STRING cmd, PCWSTR needle) {
    if (!cmd || !cmd->Buffer || !needle) return FALSE;
    SIZE_T nLen = wcslen(needle);
    if (!nLen) return FALSE;
    USHORT cmdChars = cmd->Length / sizeof(WCHAR);
    if (cmdChars < (USHORT)nLen) return FALSE;
    __try {
        for (USHORT i = 0; i <= cmdChars - (USHORT)nLen; i++) {
            BOOLEAN match = TRUE;
            for (SIZE_T j = 0; j < nLen && match; j++) {
                WCHAR c = cmd->Buffer[i + j];
                if (c >= L'A' && c <= L'Z') c |= 0x20;
                if (c != needle[j]) match = FALSE;
            }
            if (match) return TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FALSE;
}

// Allocate and enqueue a command-line alert.  Embeds the first 100 chars of
// the command line as narrow ASCII so analysts get immediate context without
// needing a second query.
static VOID EmitCmdLineAlert(
    PEPROCESS        newProcess,
    PCUNICODE_STRING cmdLine,
    const char*      desc,
    BOOLEAN          critical)
{
    char msg[280];
    SIZE_T prefixLen = 0;
    RtlStringCbPrintfA(msg, sizeof(msg), "CmdLine[%s]: ", desc);
    prefixLen = strlen(msg);

    // Append first 100 WCHAR of cmdline as narrow (non-ASCII → '?')
    if (cmdLine && cmdLine->Buffer) {
        SIZE_T cmdChars = cmdLine->Length / sizeof(WCHAR);
        SIZE_T copy     = min(cmdChars, (SIZE_T)100);
        __try {
            for (SIZE_T i = 0; i < copy && (prefixLen + i) < sizeof(msg) - 1; i++) {
                WCHAR wc = cmdLine->Buffer[i];
                msg[prefixLen + i] = (wc < 128) ? (char)wc : '?';
            }
            msg[prefixLen + copy] = '\0';
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    SIZE_T msgLen = strlen(msg);
    PKERNEL_STRUCTURED_NOTIFICATION n = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
    if (!n) return;
    RtlZeroMemory(n, sizeof(*n));
    if (critical) { SET_CRITICAL(*n); } else { SET_WARNING(*n); }
    SET_CALLING_PROC_PID_CHECK(*n);
    n->isPath   = FALSE;
    n->pid      = PsGetProcessId(newProcess);
    RtlCopyMemory(n->procName, PsGetProcessImageFileName(newProcess), 14);
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

VOID ProcessUtils::CreateProcessNotifyEx(
	PEPROCESS Process,
	HANDLE handle,
	PPS_CREATE_NOTIFY_INFO CreateInfo
) {

	ProcessUtils procUtils = ProcessUtils(Process);
	
	if (CreateInfo) {

		// Save kernel-authentic command line for later discrepancy detection.
		// Must happen before any other work so the record exists when the child's
		// first DLL load fires ImageLoadNotifyRoutine.
		if (CreateInfo->CommandLine)
			ImageUtils::SaveKernelCmdLine(HandleToUlong(PsGetProcessId(Process)),
			                              CreateInfo->CommandLine);

		// -----------------------------------------------------------------------
		// Fork-and-run tracker: record this process if it is a known spawnto
		// host or has a suspiciously empty command line.
		// -----------------------------------------------------------------------
		{
			// Normalise image file name to lowercase ANSI for comparison.
			char imgLower[16] = {};
			char* rawName = PsGetProcessImageFileName(Process);
			if (rawName) {
				for (int i = 0; i < 15 && rawName[i]; i++) {
					char c = rawName[i];
					if (c >= 'A' && c <= 'Z') c |= 0x20;
					imgLower[i] = c;
				}
			}

			BOOLEAN knownHost      = IsKnownSpawntoHost(imgLower);
			BOOLEAN suspiciousCmd  = IsSuspiciousCmdLine(CreateInfo->CommandLine, imgLower);

			if (knownHost || suspiciousCmd) {
				ForkRunTracker::TrackProcess(PsGetProcessId(Process), knownHost, suspiciousCmd);
			}
		}

		// PE scan: walk the new process VAD for suspicious executable regions
		PeScanner::ScanProcessVad(Process, CallbackObjects::GetNotifQueue());

		if (procUtils.isProcessParentPidSpoofed(CreateInfo)) {

			// Build an actionable alert:
			//   child    = the process being spawned (Process / handle)
			//   creator  = the real creating process (CreatingThreadId.UniqueProcess)
			//   fakeParent = the process set via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
			//
			// In a clean system these are always equal.  Any mismatch means the
			// caller used UpdateProcThreadAttribute(PARENT_PROCESS) to masquerade
			// as a different parent — a foundational technique for blending
			// malicious child processes into legitimate parent chains.
			PEPROCESS fakeParentProc = NULL;
			char fakeParentName[16]  = "<unknown>";
			if (NT_SUCCESS(PsLookupProcessByProcessId(
					CreateInfo->ParentProcessId, &fakeParentProc))) {
				char* n = PsGetProcessImageFileName(fakeParentProc);
				if (n) RtlStringCbCopyA(fakeParentName, sizeof(fakeParentName), n);
				ObDereferenceObject(fakeParentProc);
			}

			char* childName   = PsGetProcessImageFileName(Process);
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			char msg[240];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"PPID Spoofing: child='%s' (pid=%llu) real_creator='%s' (pid=%llu) "
				"spoofed_parent='%s' (pid=%llu)",
				childName   ? childName   : "?", (ULONG64)PsGetProcessId(Process),
				creatorName ? creatorName : "?", (ULONG64)PsGetProcessId(IoGetCurrentProcess()),
				fakeParentName,                  (ULONG64)CreateInfo->ParentProcessId);

			SIZE_T msgLen = strlen(msg);
			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
			if (kernelNotif) {
				RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
				SET_CRITICAL(*kernelNotif);
				SET_CALLING_PROC_PID_CHECK(*kernelNotif);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid    = PsGetProcessId(Process);  // the spawned child
				if (creatorName)
					RtlCopyMemory(kernelNotif->procName, creatorName, 14);
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen + 1, 'msg');
				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, msgLen + 1);
					kernelNotif->bufSize = (ULONG)(msgLen + 1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				} else {
					ExFreePool(kernelNotif);
				}
			}
		}

		if (procUtils.isProcessGhosted()) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Process is Ghosted ! [BLOCKED]";

				SET_CRITICAL(*kernelNotif);
				SET_SE_AUDIT_INFO_CHECK(*kernelNotif);

				kernelNotif->bufSize = (ULONG)(strlen(msg) + 1);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(Process);  // ghosted child, not parent
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				char procName[15];
				RtlCopyMemory(procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);
				RtlCopyMemory(kernelNotif->procName, procName, 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg) + 1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				}
				else {
					ExFreePool(kernelNotif);
				}

			}

			// Block execution before it starts
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}

		// -----------------------------------------------------------------------
		// EPROCESS image-file structural anomaly checks (three related signals).
		//
		// (1) NULL ImageFilePointer in a non-minimal, non-pico process.
		//     EPROCESS.ImageFilePointer (FILE_OBJECT*) is set by the kernel to the
		//     backing FILE_OBJECT of the process image file.  It is NULL when:
		//       - the process was created from a manually-constructed SEC_IMAGE section
		//         that has no on-disk file backing (e.g. reflective/shellcode PE loader),
		//       - the ControlArea was built without a FILE_OBJECT at all.
		//     Minimal processes (WSL pico, Secure System) legitimately have no image
		//     file; all others should have one.
		//
		// (2) PEB→ProcessParameters→ImagePathName ≠ EPROCESS ImageFileName.
		//     SeAuditProcessCreationInfo→ImageFileName is set by the kernel at creation
		//     time and is not writable from user-mode.  ProcessParameters→ImagePathName
		//     lives in the PEB (user-mode memory) and can be patched before resuming
		//     the main thread via WriteProcessMemory / NtWriteVirtualMemory.
		//     Any mismatch in the final path component indicates PEB path spoofing —
		//     the process appears to tools reading the PEB to be a different binary.
		//
		// (3) Ghost-variant: ImageFilePointer non-null but ControlArea FilePointerNull
		//     flag set (section was built without a file object).  This covers the
		//     case where the EPROCESS pointer was patched post-creation but the
		//     ControlArea was never backed by a real file.
		// -----------------------------------------------------------------------
		{
			PKERNEL_STRUCTURES_OFFSET offs = OffsetsMgt::GetOffsets();
			char* childName   = PsGetProcessImageFileName(Process);
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());
			HANDLE childPid   = PsGetProcessId(Process);

			// --- (1) + (3): NULL ImageFilePointer or ControlArea FilePointerNull ---
			__try {
				PVOID imageFilePtrRaw =
					*(PVOID*)((PUCHAR)Process + offs->ImageFilePointer);

				ULONG flags3 = *(ULONG*)((PUCHAR)Process + offs->Flags3);
				ULONG flags2 = *(ULONG*)((PUCHAR)Process + offs->Flags2);

				// Flags3 bit 0 = MinimalProcess; Flags2 bit 10 = PicoCreated
				BOOLEAN isMinimal = (flags3 & 0x1) != 0;
				BOOLEAN isPico    = (flags2 & 0x400) != 0;

				if (!isMinimal && !isPico) {

					if (!imageFilePtrRaw) {
						// (1) No FILE_OBJECT for a normal Win32 process — file-less
						// section creation or post-creation pointer wipe.
						char msg[220];
						RtlStringCbPrintfA(msg, sizeof(msg),
							"Null EPROCESS.ImageFilePointer: '%s' (pid=%llu) creator='%s'"
							" -- image section has no backing FILE_OBJECT;"
							" file-less section injection or ghosting variant",
							childName ? childName : "?",
							(ULONG64)childPid,
							creatorName ? creatorName : "?");

						PKERNEL_STRUCTURED_NOTIFICATION n =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
						if (n) {
							RtlZeroMemory(n, sizeof(*n));
							SET_CRITICAL(*n);
							SET_SE_AUDIT_INFO_CHECK(*n);
							n->isPath = FALSE;
							n->pid    = childPid;
							if (creatorName) RtlCopyMemory(n->procName, creatorName, 14);
							SIZE_T msgLen = strlen(msg) + 1;
							n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
							if (n->msg) {
								RtlCopyMemory(n->msg, msg, msgLen);
								n->bufSize = (ULONG)msgLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
									ExFreePool(n->msg); ExFreePool(n);
								}
							} else { ExFreePool(n); }
						}
					} else {
						// (3) ImageFilePointer non-null — verify the backing ControlArea
						// actually has a file object (FilePointerNull == 0 in flags).
						// Navigate: EPROCESS.ImageFilePointer → FILE_OBJECT →
						// SectionObjectPointer → DataSectionObject → ControlArea.
						// Simpler path: walk the process image VAD's ControlArea directly.
						// ControlArea.Flags.FilePointerNull (bit 19 of u.LongFlags) means
						// the ControlArea was built without a backing file, i.e. section
						// created from anonymous or deleted memory.
						__try {
							PVOID controlAreaGuess =
								*(PVOID*)((PUCHAR)imageFilePtrRaw + 0x38);  // FILE_OBJECT.SectionObjectPointer

							// Walk the image section VAD to get the real ControlArea.
							// This is more reliable than deriving from FILE_OBJECT chains.
							RTL_AVL_TREE* vadRoot =
								(RTL_AVL_TREE*)((PUCHAR)Process + offs->VadRoot);
							if (MmIsAddressValid(vadRoot) && vadRoot->BalancedRoot) {
								// Fast path: read the main image VadRoot's first VadImageMap node.
								// Full walk is in WalkVadHiddenMappings; here we just read the
								// ControlArea from the process VAD known from SectionBaseAddress.
								PVOID sectionBase =
									*(PVOID*)((PUCHAR)Process + 0x530); // EPROCESS.SectionBaseAddress
								if (sectionBase) {
									ULONG64 vpn = (ULONG64)sectionBase >> 12;
									// Linear scan not needed — just check via ControlArea flag
									// on the file object we already have.
									PVOID secObjPtr =
										*(PVOID*)((PUCHAR)imageFilePtrRaw + 0x38);
									if (secObjPtr && MmIsAddressValid(secObjPtr)) {
										// DataSectionObject → ControlArea
										PVOID ctrlArea = *(PVOID*)secObjPtr;
										if (ctrlArea && MmIsAddressValid(ctrlArea)) {
											ULONG caFlags = *(ULONG*)((PUCHAR)ctrlArea + 0x28);
											BOOLEAN fpNull = (caFlags & (1UL << 19)) != 0;
											if (fpNull) {
												char msg[220];
												RtlStringCbPrintfA(msg, sizeof(msg),
													"ControlArea.FilePointerNull: '%s' (pid=%llu)"
													" creator='%s' -- image section ControlArea"
													" has no backing file object;"
													" anonymous or ghosted section",
													childName  ? childName  : "?",
													(ULONG64)childPid,
													creatorName ? creatorName : "?");

												PKERNEL_STRUCTURED_NOTIFICATION n =
													(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
														POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
												if (n) {
													RtlZeroMemory(n, sizeof(*n));
													SET_CRITICAL(*n);
													SET_SE_AUDIT_INFO_CHECK(*n);
													n->isPath = FALSE;
													n->pid    = childPid;
													if (creatorName) RtlCopyMemory(n->procName, creatorName, 14);
													SIZE_T msgLen = strlen(msg) + 1;
													n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
													if (n->msg) {
														RtlCopyMemory(n->msg, msg, msgLen);
														n->bufSize = (ULONG)msgLen;
														if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
															ExFreePool(n->msg); ExFreePool(n);
														}
													} else { ExFreePool(n); }
												}
											}
										}
									}
								}
							}
						} __except (EXCEPTION_EXECUTE_HANDLER) {}
					}
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			// --- (2) PEB ImagePathName vs kernel ImageFileName mismatch ---
			// Only meaningful when both sides are available.
			SE_AUDIT_PROCESS_CREATION_INFO* seAudit =
				(SE_AUDIT_PROCESS_CREATION_INFO*)((PUCHAR)Process + offs->SeAuditProcessCreationInfo);

			if (MmIsAddressValid(seAudit) &&
				seAudit->ImageFileName &&
				seAudit->ImageFileName->Name.Buffer &&
				seAudit->ImageFileName->Name.Length > 0) {

				// Extract the last path component from the kernel-authoritative path.
				// NT path: \Device\HarddiskVolume3\...\notepad.exe → "notepad.exe"
				const UNICODE_STRING* kPath = &seAudit->ImageFileName->Name;
				USHORT kChars  = kPath->Length / sizeof(WCHAR);
				USHORT kSlash  = 0;
				for (USHORT i = 0; i < kChars; i++)
					if (kPath->Buffer[i] == L'\\' || kPath->Buffer[i] == L'/') kSlash = i + 1;

				char kName[64] = {};
				USHORT kCopy = min((USHORT)(kChars - kSlash), (USHORT)(sizeof(kName) - 1));
				for (USHORT i = 0; i < kCopy; i++) {
					WCHAR wc = kPath->Buffer[kSlash + i];
					if (wc >= L'A' && wc <= L'Z') wc |= 0x20;
					kName[i] = (wc < 128) ? (char)wc : '?';
				}

				// Now attach and read PEB→ProcessParameters→ImagePathName.
				// PEB.ProcessParameters at PEB+0x20 (64-bit).
				// RTL_USER_PROCESS_PARAMETERS.ImagePathName at +0x60.
				KAPC_STATE apcState;
				KeStackAttachProcess(Process, &apcState);

				__try {
					PVOID peb = PsGetProcessPeb(Process);
					if (peb && MmIsAddressValid(peb)) {
						PVOID ppRaw = nullptr;
						ProbeForRead((PUCHAR)peb + 0x20, sizeof(PVOID), sizeof(BYTE));
						RtlCopyMemory(&ppRaw, (PUCHAR)peb + 0x20, sizeof(PVOID));

						if (ppRaw && MmIsAddressValid(ppRaw)) {
							// ImagePathName is UNICODE_STRING at +0x60; Buffer pointer at +0x68.
							UNICODE_STRING pebPath;
							ProbeForRead((PUCHAR)ppRaw + 0x60, sizeof(UNICODE_STRING), sizeof(BYTE));
							RtlCopyMemory(&pebPath, (PUCHAR)ppRaw + 0x60, sizeof(UNICODE_STRING));

							if (pebPath.Buffer && pebPath.Length > 0 &&
								MmIsAddressValid(pebPath.Buffer)) {

								ProbeForRead(pebPath.Buffer, pebPath.Length, sizeof(BYTE));

								USHORT pChars = pebPath.Length / sizeof(WCHAR);
								USHORT pSlash = 0;
								for (USHORT i = 0; i < pChars; i++)
									if (pebPath.Buffer[i] == L'\\' || pebPath.Buffer[i] == L'/')
										pSlash = i + 1;

								char pName[64] = {};
								USHORT pCopy = min((USHORT)(pChars - pSlash), (USHORT)(sizeof(pName) - 1));
								for (USHORT i = 0; i < pCopy; i++) {
									WCHAR wc = pebPath.Buffer[pSlash + i];
									if (wc >= L'A' && wc <= L'Z') wc |= 0x20;
									pName[i] = (wc < 128) ? (char)wc : '?';
								}

								// Compare the filename components.
								if (kName[0] && pName[0] && strcmp(kName, pName) != 0) {
									char msg[280];
									RtlStringCbPrintfA(msg, sizeof(msg),
										"PEB path spoofing: '%s' (pid=%llu) creator='%s'"
										" PEB.ImagePathName='%s' != kernel.ImageFileName='%s'"
										" -- parent patched PEB before thread resumed",
										childName  ? childName  : "?",
										(ULONG64)childPid,
										creatorName ? creatorName : "?",
										pName, kName);

									PKERNEL_STRUCTURED_NOTIFICATION n =
										(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
											POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
									if (n) {
										RtlZeroMemory(n, sizeof(*n));
										SET_CRITICAL(*n);
										SET_SE_AUDIT_INFO_CHECK(*n);
										n->isPath = FALSE;
										n->pid    = childPid;
										if (creatorName) RtlCopyMemory(n->procName, creatorName, 14);
										SIZE_T msgLen = strlen(msg) + 1;
										n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
										if (n->msg) {
											RtlCopyMemory(n->msg, msg, msgLen);
											n->bufSize = (ULONG)msgLen;
											if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
												ExFreePool(n->msg); ExFreePool(n);
											}
										} else { ExFreePool(n); }
									}
								}
							}
						}
					}
						// ---------------------------------------------------------
						// T1546.011: PEB pShimData pointer validation.
						//
						// When a shim database targets a process, shimeng.dll
						// sets PEB.pShimData to a SHIM_DATA structure.
						// Flag non-NULL pShimData on security-sensitive processes.
						// ---------------------------------------------------------
						if (peb && MmIsAddressValid(peb)) {
							PVOID shimDataPtr = nullptr;
							// PEB.pShimData offset 0x2D8 (Win10/11 x64)
							PVOID pShimField = (PUCHAR)peb + 0x2D8;
							if (MmIsAddressValid(pShimField)) {
								ProbeForRead(pShimField, sizeof(PVOID), sizeof(BYTE));
								RtlCopyMemory(&shimDataPtr, pShimField, sizeof(PVOID));
							}

							if (shimDataPtr != nullptr) {
								const char* procBase = childName ? childName : "";
								BOOLEAN isSensitive =
									(strcmp(procBase, "lsass.exe")     == 0 ||
									 strcmp(procBase, "csrss.exe")     == 0 ||
									 strcmp(procBase, "services.exe")  == 0 ||
									 strcmp(procBase, "svchost.exe")   == 0 ||
									 strcmp(procBase, "NortonEDR.exe") == 0 ||
									 strcmp(procBase, "smss.exe")      == 0 ||
									 strcmp(procBase, "wininit.exe")   == 0 ||
									 strcmp(procBase, "winlogon.exe")  == 0 ||
									 strcmp(procBase, "spoolsv.exe")   == 0);

								if (isSensitive) {
									char shimMsg[300];
									RtlStringCbPrintfA(shimMsg, sizeof(shimMsg),
										"PEB SHIM INJECTION: %s (pid=%llu) has non-NULL "
										"pShimData (%p) — shim database active on "
										"security-sensitive process! T1546.011: "
										"possible DLL injection via InjectDll shim",
										procBase, (ULONG64)childPid, shimDataPtr);

									PKERNEL_STRUCTURED_NOTIFICATION sn =
										(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
											POOL_FLAG_NON_PAGED,
											sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
									if (sn) {
										RtlZeroMemory(sn, sizeof(*sn));
										SET_CRITICAL(*sn);
										SET_SE_AUDIT_INFO_CHECK(*sn);
										sn->isPath = FALSE;
										sn->pid = childPid;
										if (creatorName)
											RtlCopyMemory(sn->procName, creatorName, 14);
										SIZE_T smLen = strlen(shimMsg) + 1;
										sn->msg = (char*)ExAllocatePool2(
											POOL_FLAG_NON_PAGED, smLen, 'msg');
										if (sn->msg) {
											RtlCopyMemory(sn->msg, shimMsg, smLen);
											sn->bufSize = (ULONG)smLen;
											if (!CallbackObjects::GetNotifQueue()->Enqueue(sn)) {
												ExFreePool(sn->msg);
												ExFreePool(sn);
											}
										} else { ExFreePool(sn); }
									}
								}
							}
						}
				} __except (EXCEPTION_EXECUTE_HANDLER) {}

				KeUnstackDetachProcess(&apcState);
			}
		}

		// -----------------------------------------------------------------------
		// Legacy process creation via NtCreateProcessEx / NtCreateProcess:
		// kernel signal — FileOpenNameAvailable == 0 with a non-NULL ImageFileName.
		//
		// FileOpenNameAvailable = 1  → image path comes from an actual file open
		//                              (normal NtCreateUserProcess / CreateProcess path)
		// FileOpenNameAvailable = 0  → image path is derived from a section object,
		//                              not from opening a file; the kernel never opened
		//                              the file on this code path.
		//
		// When combined with CommandLine == NULL (NtCreateUserProcess always sets one),
		// this strongly indicates direct NtCreateProcessEx / NtCreateProcess usage.
		// Ghosted processes are excluded (they already fire their own Critical alert).
		// -----------------------------------------------------------------------
		if (!CreateInfo->FileOpenNameAvailable && !procUtils.isProcessGhosted()) {
			BOOLEAN noCommandLine = (CreateInfo->CommandLine == nullptr ||
			                         CreateInfo->CommandLine->Buffer == nullptr ||
			                         CreateInfo->CommandLine->Length == 0);

			char* childName   = PsGetProcessImageFileName(Process);
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			char imageNameBuf[128] = "<unknown>";
			if (CreateInfo->ImageFileName &&
			    CreateInfo->ImageFileName->Buffer &&
			    CreateInfo->ImageFileName->Length > 0) {
				USHORT copyChars = min(
				    (USHORT)(CreateInfo->ImageFileName->Length / sizeof(WCHAR)),
				    (USHORT)(sizeof(imageNameBuf) - 1));
				for (USHORT i = 0; i < copyChars; i++) {
					WCHAR wc = CreateInfo->ImageFileName->Buffer[i];
					imageNameBuf[i] = (wc < 128) ? (char)wc : '?';
				}
				imageNameBuf[copyChars] = '\0';
			}

			char msg[280];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"Legacy process creation: '%s' (creator='%s') image loaded from section"
				" not file (FileOpenNameAvailable=0%s) -- NtCreateProcessEx/NtCreateProcess"
				" path; image='%s'",
				childName   ? childName   : "?",
				creatorName ? creatorName : "?",
				noCommandLine ? ", CommandLine=NULL" : "",
				imageNameBuf);

			PKERNEL_STRUCTURED_NOTIFICATION n =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
			if (n) {
				RtlZeroMemory(n, sizeof(*n));
				SET_CRITICAL(*n);
				SET_SE_AUDIT_INFO_CHECK(*n);
				n->isPath = FALSE;
				n->pid    = PsGetProcessId(Process);
				if (creatorName) RtlCopyMemory(n->procName, creatorName, 14);
				SIZE_T msgLen = strlen(msg) + 1;
				n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
				if (n->msg) {
					RtlCopyMemory(n->msg, msg, msgLen);
					n->bufSize = (ULONG)msgLen;
					if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
						ExFreePool(n->msg);
						ExFreePool(n);
					}
				} else { ExFreePool(n); }
			}
		}

		// -----------------------------------------------------------------------
		// Lateral movement / WMI execution: remote execution host spawning
		// child processes.
		//
		// WMI process call create (T1047) and WinRM (T1021.006) use
		// wmiprvse.exe / wsmprovhost.exe as the parent process for all
		// remotely executed commands.  Attackers also use scrcons.exe
		// (ActiveScriptEventConsumer) for WMI persistence execution.
		//
		// Detection levels:
		//   CRITICAL: shells, LOLBins, compilers (confirmed lateral move / exec)
		//   HIGH: any other child from WMI hosts (unusual, worth investigating)
		//
		// Also detect mofcomp.exe spawning — MOF compilation for WMI persistence.
		// -----------------------------------------------------------------------
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {

				char* parentName = PsGetProcessImageFileName(parentProcess);

				// Category 1: WMI/WinRM/DCOM remote execution hosts
				BOOLEAN isRemoteExecHost = (parentName != NULL &&
					(strcmp(parentName, "wmiprvse.exe") == 0 ||
					 strcmp(parentName, "wsmprovhost.") == 0 ||  // truncated to 15 chars
					 strcmp(parentName, "winrshost.exe") == 0 ||
					 strcmp(parentName, "dllhost.exe") == 0 ||
					 strcmp(parentName, "mmc.exe") == 0));

				// Category 2: WMI persistence execution hosts
				BOOLEAN isWmiPersistHost = (parentName != NULL &&
					(strcmp(parentName, "scrcons.exe") == 0));  // ActiveScriptEventConsumer

				if (isRemoteExecHost || isWmiPersistHost) {
					char* childName = PsGetProcessImageFileName(Process);

					// Known-dangerous children — definitive lateral movement / persistence exec
					BOOLEAN isCriticalChild = FALSE;
					if (CreateInfo->ImageFileName != NULL) {
						static const WCHAR* kWmiCriticalChildren[] = {
							// Shells
							L"cmd.exe", L"powershell.exe", L"pwsh.exe",
							L"wscript.exe", L"cscript.exe", L"mshta.exe",
							// LOLBins commonly used in WMI lateral movement
							L"certutil.exe", L"bitsadmin.exe", L"rundll32.exe",
							L"regsvr32.exe", L"msbuild.exe", L"installutil.exe",
							L"msiexec.exe", L"schtasks.exe", L"reg.exe",
							// .NET compilers (in-memory payload compilation)
							L"csc.exe", L"vbc.exe", L"jsc.exe",
							// Network recon / exfil
							L"net.exe", L"net1.exe", L"nltest.exe",
							L"dsquery.exe", L"wmic.exe",
							// Process manipulation
							L"taskkill.exe", L"sc.exe",
							nullptr
						};
						for (int i = 0; kWmiCriticalChildren[i]; i++) {
							if (UnicodeStringContains(CreateInfo->ImageFileName, kWmiCriticalChildren[i])) {
								isCriticalChild = TRUE;
								break;
							}
						}
					}

					// Allowlist: legitimate children of wmiprvse
					BOOLEAN isAllowedChild = FALSE;
					if (childName) {
						static const char* kWmiAllowedChildren[] = {
							"WmiPrvSE.exe", "WmiApSrv.exe", "mofcomp.exe",
							"wmiadap.exe", "conhost.exe",
							nullptr
						};
						for (int i = 0; kWmiAllowedChildren[i]; i++) {
							if (strcmp(childName, kWmiAllowedChildren[i]) == 0) {
								isAllowedChild = TRUE;
								break;
							}
						}
					}

					if (!isAllowedChild) {
						const char* technique = isWmiPersistHost
							? "WMI Persistence Execution (T1546.003)"
							: "Lateral Movement via WMI/WinRM/DCOM (T1047)";

						char wmiMsg[350];
						RtlStringCbPrintfA(wmiMsg, sizeof(wmiMsg),
							"%s: %s (pid=%llu) spawned '%s' (pid=%llu)%s",
							technique,
							parentName,
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							childName ? childName : "?",
							(ULONG64)PsGetProcessId(Process),
							isCriticalChild ? " [SHELL/LOLBIN]" : "");

						PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wmnt');
						if (kernelNotif) {
							RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
							if (isCriticalChild) { SET_CRITICAL(*kernelNotif); }
							else                 { SET_WARNING(*kernelNotif);  }
							SET_CALLING_PROC_PID_CHECK(*kernelNotif);
							kernelNotif->isPath = FALSE;
							kernelNotif->pid = PsGetProcessId(Process);
							RtlCopyMemory(kernelNotif->procName, parentName, 15);
							SIZE_T mLen = strlen(wmiMsg) + 1;
							kernelNotif->msg = (char*)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, mLen, 'wmmg');
							if (kernelNotif->msg) {
								RtlCopyMemory(kernelNotif->msg, wmiMsg, mLen);
								kernelNotif->bufSize = (ULONG)mLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
									ExFreePool(kernelNotif->msg);
									ExFreePool(kernelNotif);
								}
							} else { ExFreePool(kernelNotif); }
						}
					}
				}

				ObDereferenceObject(parentProcess);
			}
		}

		// -----------------------------------------------------------------------
		// UAC Bypass via auto-elevating binaries (T1548.002)
		//
		// fodhelper.exe and eventvwr.exe are Microsoft-signed binaries that
		// auto-elevate without a UAC prompt.  Attackers hijack their registry
		// lookups (e.g. ms-settings or mscfile shell\open\command) to spawn
		// an arbitrary elevated child process.
		//
		// Any child process from these parents is suspicious — they are not
		// intended to launch user-controlled children in normal operation.
		// -----------------------------------------------------------------------
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {

				char* parentName = PsGetProcessImageFileName(parentProcess);

				BOOLEAN isUacBypassHost = (parentName != NULL &&
					(strcmp(parentName, "fodhelper.exe") == 0 ||
					 strcmp(parentName, "eventvwr.exe") == 0 ||
					 strcmp(parentName, "computerdef") == 0 ||    // computerdefaults.exe (truncated)
					 strcmp(parentName, "sdclt.exe") == 0 ||
					 strcmp(parentName, "slui.exe") == 0 ||
					 strcmp(parentName, "wsreset.exe") == 0 ||
					 strcmp(parentName, "dccw.exe") == 0 ||
					 strcmp(parentName, "CompMgmtLau") == 0 ||    // compmgmtlauncher.exe (truncated)
					 strcmp(parentName, "msconfig.exe") == 0 ||
					 strcmp(parentName, "silentclean") == 0 ||    // silentcleanup.exe (truncated)
					 strcmp(parentName, "changepk.exe") == 0 ||
					 strcmp(parentName, "iscsicpl.exe") == 0 ||
					 strcmp(parentName, "perfmon.exe") == 0));

				if (isUacBypassHost) {
					char* childName = PsGetProcessImageFileName(Process);

					// Allowlist: legitimate children
					BOOLEAN isAllowedChild = FALSE;
					if (childName) {
						static const char* kUacAllowedChildren[] = {
							"conhost.exe",
							nullptr
						};
						for (int i = 0; kUacAllowedChildren[i]; i++) {
							if (strcmp(childName, kUacAllowedChildren[i]) == 0) {
								isAllowedChild = TRUE;
								break;
							}
						}
					}

					if (!isAllowedChild) {
						// Check if child is a shell/LOLBin — makes it critical
						BOOLEAN isCriticalChild = FALSE;
						if (CreateInfo->ImageFileName != NULL) {
							static const WCHAR* kUacCriticalChildren[] = {
								L"cmd.exe", L"powershell.exe", L"pwsh.exe",
								L"wscript.exe", L"cscript.exe", L"mshta.exe",
								L"rundll32.exe", L"regsvr32.exe", L"certutil.exe",
								nullptr
							};
							for (int i = 0; kUacCriticalChildren[i]; i++) {
								if (UnicodeStringContains(CreateInfo->ImageFileName, kUacCriticalChildren[i])) {
									isCriticalChild = TRUE;
									break;
								}
							}
						}

						char uacMsg[350];
						RtlStringCbPrintfA(uacMsg, sizeof(uacMsg),
							"UAC Bypass (T1548.002): %s (pid=%llu) spawned '%s' (pid=%llu)%s",
							parentName,
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							childName ? childName : "?",
							(ULONG64)PsGetProcessId(Process),
							isCriticalChild ? " [SHELL/LOLBIN]" : "");

						PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'uact');
						if (kernelNotif) {
							RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
							SET_CRITICAL(*kernelNotif);  // All UAC bypass children are critical
							SET_CALLING_PROC_PID_CHECK(*kernelNotif);
							kernelNotif->isPath = FALSE;
							kernelNotif->pid = PsGetProcessId(Process);
							RtlCopyMemory(kernelNotif->procName, parentName, 15);
							SIZE_T mLen = strlen(uacMsg) + 1;
							kernelNotif->msg = (char*)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, mLen, 'uamg');
							if (kernelNotif->msg) {
								RtlCopyMemory(kernelNotif->msg, uacMsg, mLen);
								kernelNotif->bufSize = (ULONG)mLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
									ExFreePool(kernelNotif->msg);
									ExFreePool(kernelNotif);
								}
							} else { ExFreePool(kernelNotif); }
						}
					}
				}

				ObDereferenceObject(parentProcess);
			}
		}

		// -----------------------------------------------------------------------
		// Office application child process detection (T1566.001 / T1204.002)
		//
		// WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSACCESS.EXE should almost
		// never spawn interactive child processes.  When a macro, OLE object,
		// or embedded payload runs, the Office host becomes the parent of
		// cmd.exe, powershell.exe, wscript.exe, etc.  This is one of the
		// highest-signal malware delivery indicators — 76 sigma hits across
		// 19K malware samples in our VT corpus.
		//
		// Detection: any child from an Office parent that is not an allowed
		// Office-internal process triggers CRITICAL.
		// -----------------------------------------------------------------------
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {

				char* parentName = PsGetProcessImageFileName(parentProcess);

				BOOLEAN isOfficeHost = (parentName != NULL &&
					(strcmp(parentName, "WINWORD.EXE") == 0 ||
					 strcmp(parentName, "EXCEL.EXE") == 0 ||
					 strcmp(parentName, "POWERPNT.EXE") == 0 ||
					 strcmp(parentName, "MSACCESS.EXE") == 0 ||
					 strcmp(parentName, "OUTLOOK.EXE") == 0 ||
					 strcmp(parentName, "MSPUB.EXE") == 0));

				if (isOfficeHost) {
					char* childName = PsGetProcessImageFileName(Process);

					// Allowlist: legitimate Office helper processes
					BOOLEAN isAllowedChild = FALSE;
					if (childName) {
						static const char* kOfficeAllowed[] = {
							"splwow64.exe",     // print driver host
							"conhost.exe",
							"ai.exe",           // Office AI/Copilot
							"OSPPSVC.EXE",      // Office protection platform
							"OfficeClickT",     // OfficeClickToRun (truncated)
							"AppVShNotify",     // App-V shell notification
							"MSOSREC.EXE",      // crash recovery
							"DW20.EXE",         // Dr. Watson crash reporting
							"FLTLDR.EXE",       // filter loader
							nullptr
						};
						for (int i = 0; kOfficeAllowed[i]; i++) {
							if (strcmp(childName, kOfficeAllowed[i]) == 0) {
								isAllowedChild = TRUE;
								break;
							}
						}
					}

					if (!isAllowedChild) {
						BOOLEAN isCriticalChild = FALSE;
						if (CreateInfo->ImageFileName != NULL) {
							static const WCHAR* kOfficeDangerousChildren[] = {
								L"cmd.exe", L"powershell.exe", L"pwsh.exe",
								L"wscript.exe", L"cscript.exe", L"mshta.exe",
								L"rundll32.exe", L"regsvr32.exe", L"certutil.exe",
								L"bitsadmin.exe", L"schtasks.exe", L"msbuild.exe",
								L"installutil.exe", L"regasm.exe", L"regsvcs.exe",
								L"msxsl.exe", L"forfiles.exe", L"pcalua.exe",
								nullptr
							};
							for (int i = 0; kOfficeDangerousChildren[i]; i++) {
								if (UnicodeStringContains(CreateInfo->ImageFileName, kOfficeDangerousChildren[i])) {
									isCriticalChild = TRUE;
									break;
								}
							}
						}

						char offMsg[350];
						RtlStringCbPrintfA(offMsg, sizeof(offMsg),
							"Office child process (T1566.001): %s (pid=%llu) spawned '%s' (pid=%llu)%s",
							parentName,
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							childName ? childName : "?",
							(ULONG64)PsGetProcessId(Process),
							isCriticalChild ? " [SHELL/LOLBIN]" : "");

						PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'ofnt');
						if (kernelNotif) {
							RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
							if (isCriticalChild) { SET_CRITICAL(*kernelNotif); }
							else                 { SET_WARNING(*kernelNotif);  }
							SET_CALLING_PROC_PID_CHECK(*kernelNotif);
							kernelNotif->isPath = FALSE;
							kernelNotif->pid = PsGetProcessId(Process);
							RtlCopyMemory(kernelNotif->procName, parentName, 15);
							SIZE_T mLen = strlen(offMsg) + 1;
							kernelNotif->msg = (char*)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, mLen, 'ofmg');
							if (kernelNotif->msg) {
								RtlCopyMemory(kernelNotif->msg, offMsg, mLen);
								kernelNotif->bufSize = (ULONG)mLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
									ExFreePool(kernelNotif->msg);
									ExFreePool(kernelNotif);
								}
							} else { ExFreePool(kernelNotif); }
						}
					}
				}

				ObDereferenceObject(parentProcess);
			}
		}

		// -----------------------------------------------------------------------
		// mofcomp.exe execution detection — MOF compilation for WMI persistence.
		//
		// Attackers compile .mof files containing __EventFilter, __EventConsumer,
		// and __FilterToConsumerBinding definitions to install WMI persistence
		// without touching PowerShell or the WMI scripting API (T1546.003).
		//
		// mofcomp.exe is rarely used in normal operations — flag any invocation.
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName &&
			UnicodeStringContains(CreateInfo->ImageFileName, L"mofcomp.exe"))
		{
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			// Extract command line for MOF file path context
			char cmdBuf[200] = {};
			if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer &&
				CreateInfo->CommandLine->Length > 0)
			{
				USHORT copyChars = min(
					(USHORT)(CreateInfo->CommandLine->Length / sizeof(WCHAR)),
					(USHORT)(sizeof(cmdBuf) - 1));
				for (USHORT ci = 0; ci < copyChars; ci++) {
					WCHAR wc = CreateInfo->CommandLine->Buffer[ci];
					cmdBuf[ci] = (wc < 128) ? (char)wc : '?';
				}
			}

			// Parse dangerous mofcomp flags and UNC paths from command line
			const char* mofFlags = "";
			BOOLEAN hasAutoRecover = FALSE;
			BOOLEAN hasUncPath = FALSE;
			BOOLEAN hasNamespace = FALSE;
			BOOLEAN hasCheckFlag = FALSE;

			if (cmdBuf[0]) {
				// Case-insensitive scan of the command line buffer
				char cmdLower[200];
				for (int li = 0; li < 200; li++) {
					cmdLower[li] = (cmdBuf[li] >= 'A' && cmdBuf[li] <= 'Z')
						? (char)(cmdBuf[li] + 32) : cmdBuf[li];
					if (cmdBuf[li] == 0) break;
				}

				if (strstr(cmdLower, "-autorecover") || strstr(cmdLower, "/autorecover"))
					hasAutoRecover = TRUE;
				if (strstr(cmdLower, "-check") || strstr(cmdLower, "/check"))
					hasCheckFlag = TRUE;
				if (strstr(cmdLower, "-n:") || strstr(cmdLower, "/n:") ||
					strstr(cmdLower, "-namespace:") || strstr(cmdLower, "/namespace:") ||
					strstr(cmdLower, "#pragma namespace"))
					hasNamespace = TRUE;
				if (strstr(cmdLower, "\\\\"))
					hasUncPath = TRUE;

				if (hasAutoRecover) mofFlags = " [AUTORECOVER]";
				else if (hasUncPath) mofFlags = " [UNC_PATH]";
				else if (hasNamespace) mofFlags = " [NAMESPACE]";
			}

			char mofMsg[512];
			if (hasUncPath) {
				RtlStringCbPrintfA(mofMsg, sizeof(mofMsg),
					"Remote MOF Compilation (T1546.003+T1021.002): mofcomp.exe "
					"referencing UNC path — spawned by '%s' (pid=%llu) — cmd: %.180s",
					creatorName ? creatorName : "?",
					(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
					cmdBuf);
			} else if (hasAutoRecover) {
				RtlStringCbPrintfA(mofMsg, sizeof(mofMsg),
					"MOF AutoRecover Persistence (T1546.003): mofcomp.exe -autorecover "
					"— survives WMI rebuild — spawned by '%s' (pid=%llu) — cmd: %.180s",
					creatorName ? creatorName : "?",
					(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
					cmdBuf);
			} else {
				RtlStringCbPrintfA(mofMsg, sizeof(mofMsg),
					"WMI MOF Compilation (T1546.003): mofcomp.exe spawned by '%s' "
					"(pid=%llu)%s — cmd: %.180s",
					creatorName ? creatorName : "?",
					(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
					mofFlags,
					cmdBuf[0] ? cmdBuf : "<empty>");
			}

			PKERNEL_STRUCTURED_NOTIFICATION mofNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'mfnt');
			if (mofNotif) {
				RtlZeroMemory(mofNotif, sizeof(*mofNotif));
				SET_CRITICAL(*mofNotif);
				SET_CALLING_PROC_PID_CHECK(*mofNotif);
				mofNotif->isPath = FALSE;
				mofNotif->pid = PsGetProcessId(Process);
				if (creatorName) RtlCopyMemory(mofNotif->procName, creatorName, 14);
				SIZE_T mLen = strlen(mofMsg) + 1;
				mofNotif->msg = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, mLen, 'mfmg');
				if (mofNotif->msg) {
					RtlCopyMemory(mofNotif->msg, mofMsg, mLen);
					mofNotif->bufSize = (ULONG)mLen;
					if (!CallbackObjects::GetNotifQueue()->Enqueue(mofNotif)) {
						ExFreePool(mofNotif->msg);
						ExFreePool(mofNotif);
					}
				} else { ExFreePool(mofNotif); }
			}
		}

		// -----------------------------------------------------------------------
		// scrcons.exe execution detection — WMI ActiveScriptEventConsumer host.
		//
		// scrcons.exe is the process that executes VBScript/JScript payloads
		// registered via WMI ActiveScriptEventConsumer persistence.
		// It should almost never run on modern systems — flag any invocation.
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName &&
			UnicodeStringContains(CreateInfo->ImageFileName, L"scrcons.exe"))
		{
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			char scrMsg[280];
			RtlStringCbPrintfA(scrMsg, sizeof(scrMsg),
				"WMI Script Consumer (T1546.003): scrcons.exe launched by '%s' "
				"(pid=%llu) — ActiveScriptEventConsumer executing VBS/JS payload",
				creatorName ? creatorName : "?",
				(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);

			PKERNEL_STRUCTURED_NOTIFICATION scrNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'scnt');
			if (scrNotif) {
				RtlZeroMemory(scrNotif, sizeof(*scrNotif));
				SET_CRITICAL(*scrNotif);
				SET_CALLING_PROC_PID_CHECK(*scrNotif);
				scrNotif->isPath = FALSE;
				scrNotif->pid = PsGetProcessId(Process);
				if (creatorName) RtlCopyMemory(scrNotif->procName, creatorName, 14);
				SIZE_T sLen = strlen(scrMsg) + 1;
				scrNotif->msg = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sLen, 'scmg');
				if (scrNotif->msg) {
					RtlCopyMemory(scrNotif->msg, scrMsg, sLen);
					scrNotif->bufSize = (ULONG)sLen;
					if (!CallbackObjects::GetNotifQueue()->Enqueue(scrNotif)) {
						ExFreePool(scrNotif->msg);
						ExFreePool(scrNotif);
					}
				} else { ExFreePool(scrNotif); }
			}
		}

		// -----------------------------------------------------------------------
		// Print Spooler exploitation detection (CVE-2021-34527 PrintNightmare,
		// CVE-2021-1675, CVE-2022-21999, and similar spoolsv.exe LPE/RCE).
		//
		// PrintNightmare abuses RpcAddPrinterDriverEx to load a malicious DLL
		// into spoolsv.exe (SYSTEM).  Detection:
		//  1. spoolsv.exe spawning unexpected child processes (shell, LOLBin)
		//  2. DLL writes to \spool\drivers\ are covered in FsFilter
		//
		// spoolsv.exe should only spawn splwow64.exe, conhost.exe, and
		// PrintIsolationHost.exe in normal operation.  Any other child is
		// a strong exploit indicator.
		// -----------------------------------------------------------------------
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {

				char* parentName = PsGetProcessImageFileName(parentProcess);

				BOOLEAN isSpoolsv = (parentName != NULL &&
					(strcmp(parentName, "spoolsv.exe") == 0));

				if (isSpoolsv) {
					char* childName = PsGetProcessImageFileName(Process);

					// Allowlist: legitimate spoolsv children
					BOOLEAN isAllowedChild = FALSE;
					if (childName) {
						static const char* kSpoolAllowed[] = {
							"splwow64.exe",     // 32-bit print driver host
							"conhost.exe",
							"PrintIsolati",     // PrintIsolationHost.exe (truncated)
							nullptr
						};
						for (int i = 0; kSpoolAllowed[i]; i++) {
							if (strcmp(childName, kSpoolAllowed[i]) == 0) {
								isAllowedChild = TRUE;
								break;
							}
						}
					}

					if (!isAllowedChild) {
						char spoolMsg[380];
						RtlStringCbPrintfA(spoolMsg, sizeof(spoolMsg),
							"Print Spooler Exploit (T1068/CVE-2021-34527): spoolsv.exe "
							"(pid=%llu) spawned unexpected child '%s' (pid=%llu) "
							"— possible PrintNightmare or spooler LPE",
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							childName ? childName : "?",
							(ULONG64)PsGetProcessId(Process));

						PKERNEL_STRUCTURED_NOTIFICATION spNotif =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'spnt');
						if (spNotif) {
							RtlZeroMemory(spNotif, sizeof(*spNotif));
							SET_CRITICAL(*spNotif);
							SET_CALLING_PROC_PID_CHECK(*spNotif);
							spNotif->isPath = FALSE;
							spNotif->pid = PsGetProcessId(Process);
							if (parentName) RtlCopyMemory(spNotif->procName, parentName, 14);
							SIZE_T mLen = strlen(spoolMsg) + 1;
							spNotif->msg = (char*)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, mLen, 'spmg');
							if (spNotif->msg) {
								RtlCopyMemory(spNotif->msg, spoolMsg, mLen);
								spNotif->bufSize = (ULONG)mLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(spNotif)) {
									ExFreePool(spNotif->msg);
									ExFreePool(spNotif);
								}
							} else { ExFreePool(spNotif); }
						}
					}
				}

				ObDereferenceObject(parentProcess);
			}
		}

		// -----------------------------------------------------------------------
		// msxsl.exe execution detection — XSL script processing LOLBin (T1220).
		//
		// msxsl.exe is a legitimate Microsoft XML/XSL transform tool that can
		// execute embedded JScript/VBScript via <msxsl:script>.  Attackers use
		// it to run arbitrary code from local or remote XSL stylesheets, often
		// to bypass application whitelisting (e.g. wmic /format:evil.xsl).
		//
		// msxsl.exe is almost never present on modern systems — any execution
		// is highly suspicious.  Detect at process creation for coverage
		// beyond command-line pattern matching (catches renamed binaries if
		// ImageFileName still resolves to msxsl.exe).
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName &&
			UnicodeStringContains(CreateInfo->ImageFileName, L"msxsl.exe"))
		{
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			char cmdBuf[200] = {};
			if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer &&
				CreateInfo->CommandLine->Length > 0)
			{
				USHORT copyChars = min(
					(USHORT)(CreateInfo->CommandLine->Length / sizeof(WCHAR)),
					(USHORT)(sizeof(cmdBuf) - 1));
				for (USHORT ci = 0; ci < copyChars; ci++) {
					WCHAR wc = CreateInfo->CommandLine->Buffer[ci];
					cmdBuf[ci] = (wc < 128) ? (char)wc : '?';
				}
			}

			// Check for remote XSL (http/https/UNC) — extra dangerous
			BOOLEAN hasRemote = FALSE;
			if (cmdBuf[0]) {
				char cmdLower[200];
				for (int li = 0; li < 200; li++) {
					cmdLower[li] = (cmdBuf[li] >= 'A' && cmdBuf[li] <= 'Z')
						? (char)(cmdBuf[li] + 32) : cmdBuf[li];
					if (cmdBuf[li] == 0) break;
				}
				if (strstr(cmdLower, "http://") || strstr(cmdLower, "https://") ||
					strstr(cmdLower, "\\\\"))
					hasRemote = TRUE;
			}

			char xslMsg[350];
			RtlStringCbPrintfA(xslMsg, sizeof(xslMsg),
				"XSL Script Processing LOLBin (T1220): msxsl.exe spawned by '%s' "
				"(pid=%llu)%s — cmd: %.180s",
				creatorName ? creatorName : "?",
				(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
				hasRemote ? " [REMOTE XSL]" : "",
				cmdBuf[0] ? cmdBuf : "<empty>");

			PKERNEL_STRUCTURED_NOTIFICATION xslNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'xsnt');
			if (xslNotif) {
				RtlZeroMemory(xslNotif, sizeof(*xslNotif));
				SET_CRITICAL(*xslNotif);
				SET_CALLING_PROC_PID_CHECK(*xslNotif);
				xslNotif->isPath = FALSE;
				xslNotif->pid = PsGetProcessId(Process);
				if (creatorName) RtlCopyMemory(xslNotif->procName, creatorName, 14);
				SIZE_T mLen = strlen(xslMsg) + 1;
				xslNotif->msg = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, mLen, 'xsmg');
				if (xslNotif->msg) {
					RtlCopyMemory(xslNotif->msg, xslMsg, mLen);
					xslNotif->bufSize = (ULONG)mLen;
					if (!CallbackObjects::GetNotifQueue()->Enqueue(xslNotif)) {
						ExFreePool(xslNotif->msg);
						ExFreePool(xslNotif);
					}
				} else { ExFreePool(xslNotif); }
			}
		}

		// -----------------------------------------------------------------------
		// wbemtest.exe execution detection — alternative MOF compilation tool.
		//
		// wbemtest.exe is a graphical WMI testing tool that can compile MOF,
		// create WMI class instances, and execute arbitrary WQL queries.
		// Rarely used legitimately — flag any invocation (T1546.003 / T1047).
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName &&
			UnicodeStringContains(CreateInfo->ImageFileName, L"wbemtest.exe"))
		{
			char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

			char wbtMsg[280];
			RtlStringCbPrintfA(wbtMsg, sizeof(wbtMsg),
				"WMI Tool Execution (T1546.003): wbemtest.exe launched by '%s' "
				"(pid=%llu) — can compile MOF / create WMI persistence",
				creatorName ? creatorName : "?",
				(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);

			PKERNEL_STRUCTURED_NOTIFICATION wbtNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wbnt');
			if (wbtNotif) {
				RtlZeroMemory(wbtNotif, sizeof(*wbtNotif));
				SET_CRITICAL(*wbtNotif);
				SET_CALLING_PROC_PID_CHECK(*wbtNotif);
				wbtNotif->isPath = FALSE;
				wbtNotif->pid = PsGetProcessId(Process);
				if (creatorName) RtlCopyMemory(wbtNotif->procName, creatorName, 14);
				SIZE_T wLen = strlen(wbtMsg) + 1;
				wbtNotif->msg = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, wLen, 'wbmg');
				if (wbtNotif->msg) {
					RtlCopyMemory(wbtNotif->msg, wbtMsg, wLen);
					wbtNotif->bufSize = (ULONG)wLen;
					if (!CallbackObjects::GetNotifQueue()->Enqueue(wbtNotif)) {
						ExFreePool(wbtNotif->msg);
						ExFreePool(wbtNotif);
					}
				} else { ExFreePool(wbtNotif); }
			}
		}

		// -----------------------------------------------------------------------
		// WPP / ETW trace tool execution detection (T1562.002 / T1005).
		//
		// Windows Software Trace Preprocessor (WPP) tools from WDK/ADK can
		// start/stop/decode WPP and ETW trace sessions.  Attackers use these
		// to blind telemetry or exfiltrate sensitive WPP trace data (.etl).
		// Also covers infdefaultinstall.exe (T1218 LOLBIN).
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName) {
			struct WppToolEntry {
				const WCHAR* imageName;
				const char*  alertMsg;
				BOOLEAN      isCritical;
			};
			static const WppToolEntry kWppTools[] = {
				{ L"tracelog.exe",
				  "WPP Session Control (T1562.002): tracelog.exe — can start/stop/flush WPP trace sessions",
				  TRUE },
				{ L"tracefmt.exe",
				  "WPP Trace Decode (T1005): tracefmt.exe — decodes binary .etl WPP traces to plaintext (recon/exfil)",
				  FALSE },
				{ L"tracepdb.exe",
				  "WPP Symbol Extraction (T1005): tracepdb.exe — extracts TMF format files from PDBs for trace decoding",
				  FALSE },
				{ L"traceview.exe",
				  "WPP Session Control (T1562.002): traceview.exe — GUI WPP session controller",
				  TRUE },
				{ L"tracerpt.exe",
				  "ETW/WPP Trace Export (T1005): tracerpt.exe — converts .etl to XML/CSV (exfil preparation)",
				  FALSE },
				{ L"xperf.exe",
				  "ETW/WPP Session Control (T1562.002): xperf.exe — WPA/WPT trace session capture and control",
				  TRUE },
				{ L"infdefaultinstall.exe",
				  "LOLBIN Execution (T1218): infdefaultinstall.exe — signed INF installer, can install WPP drivers or run setup commands",
				  TRUE },
				// ETW provider recon tools (FindETWProviderImage attack chain)
				{ L"FindETWProviderI",
				  "ETW Provider Recon (T1518.001): FindETWProviderImage — scans binaries for provider GUIDs (pre-attack recon)",
				  TRUE },
				{ L"EtwExplorer.exe",
				  "ETW Provider Recon (T1518.001): EtwExplorer — GUI ETW manifest/provider explorer (zodiacon)",
				  TRUE },
				{ L"ETWListicle.exe",
				  "ETW Provider Recon (T1518.001): ETWListicle — lists ETW providers in process registration table",
				  TRUE },
				{ L"ETWInspector.exe",
				  "ETW Provider Recon (T1518.001): ETWInspector — ETW provider inspection tool",
				  TRUE },
				{ L"EtwProviderBrow",
				  "ETW Provider Recon (T1518.001): EtwProviderBrowser — ETW provider enumeration tool",
				  TRUE },
				{ L"logman.exe",
				  "ETW Session Tool (T1562.002): logman.exe — ETW/WPP trace session management",
				  FALSE },
			};

			for (ULONG wt = 0; wt < ARRAYSIZE(kWppTools); wt++) {
				if (UnicodeStringContains(CreateInfo->ImageFileName, kWppTools[wt].imageName)) {
					char* creatorName = PsGetProcessImageFileName(IoGetCurrentProcess());

					// Extract command line for context
					char wppCmd[200] = {};
					if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer &&
						CreateInfo->CommandLine->Length > 0)
					{
						USHORT copyChars = min(
							(USHORT)(CreateInfo->CommandLine->Length / sizeof(WCHAR)),
							(USHORT)(sizeof(wppCmd) - 1));
						for (USHORT ci = 0; ci < copyChars; ci++) {
							WCHAR wc = CreateInfo->CommandLine->Buffer[ci];
							wppCmd[ci] = (wc < 128) ? (char)wc : '?';
						}
					}

					// Determine effective severity — start with table value,
					// then escalate based on command-line context.
					BOOLEAN effectiveCritical = kWppTools[wt].isCritical;
					const char* escalationReason = nullptr;

					// Gap 15: logman severity escalation — if logman.exe is
					// launched with dangerous arguments, upgrade to Critical.
					if (UnicodeStringContains(CreateInfo->ImageFileName, L"logman.exe") &&
						!effectiveCritical && wppCmd[0]) {
						// Build lowercase copy for flag scanning
						char wppLower[200];
						for (int li = 0; li < sizeof(wppLower) - 1 && wppCmd[li]; li++) {
							wppLower[li] = (wppCmd[li] >= 'A' && wppCmd[li] <= 'Z')
								? (char)(wppCmd[li] + 32) : wppCmd[li];
							wppLower[li + 1] = '\0';
						}
						// Dangerous logman subcommands that weren't already Critical
						if (strstr(wppLower, "logman start") ||
							strstr(wppLower, "logman query")) {
							// Check for dangerous flags that upgrade these to Critical
							if (strstr(wppLower, " -nb ") ||
								strstr(wppLower, " -ct ") ||
								strstr(wppLower, " -p {") ||
								strstr(wppLower, " -p \"")) {
								effectiveCritical = TRUE;
								escalationReason = "dangerous flags (-nb/-ct/-p) detected";
							}
						}
					}

					// Gap 16: xperf parent-process suspicion — xperf spawned
					// by cmd.exe, powershell, or conhost is highly suspicious
					// vs WPA/WPRUI launching it as part of normal WPT workflow.
					if (UnicodeStringContains(CreateInfo->ImageFileName, L"xperf.exe") &&
						creatorName) {
						static const char* kSusParents[] = {
							"cmd.exe", "powershel", "pwsh.exe",
							"conhost.e", "wscript.e", "cscript.e",
							"mshta.exe", "rundll32.", "regsvr32.",
							"explorer.", "svchost.e"
						};
						for (int sp = 0; sp < ARRAYSIZE(kSusParents); sp++) {
							if (_strnicmp(creatorName, kSusParents[sp],
								strlen(kSusParents[sp])) == 0) {
								effectiveCritical = TRUE;
								escalationReason = "suspicious parent (non-WPT)";
								break;
							}
						}
					}

					char wppMsg[480];
					if (escalationReason) {
						RtlStringCbPrintfA(wppMsg, sizeof(wppMsg),
							"%s — ESCALATED (%s) — spawned by '%s' "
							"(pid=%llu) — cmd: %.150s",
							kWppTools[wt].alertMsg,
							escalationReason,
							creatorName ? creatorName : "?",
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							wppCmd[0] ? wppCmd : "<empty>");
					} else {
						RtlStringCbPrintfA(wppMsg, sizeof(wppMsg),
							"%s — spawned by '%s' (pid=%llu) — cmd: %.180s",
							kWppTools[wt].alertMsg,
							creatorName ? creatorName : "?",
							(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
							wppCmd[0] ? wppCmd : "<empty>");
					}

					PKERNEL_STRUCTURED_NOTIFICATION wppNotif =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wpnt');
					if (wppNotif) {
						RtlZeroMemory(wppNotif, sizeof(*wppNotif));
						if (effectiveCritical) { SET_CRITICAL(*wppNotif); }
						else { SET_WARNING(*wppNotif); }
						SET_CALLING_PROC_PID_CHECK(*wppNotif);
						wppNotif->isPath = FALSE;
						wppNotif->pid = PsGetProcessId(Process);
						if (creatorName) RtlCopyMemory(wppNotif->procName, creatorName, 14);
						SIZE_T wLen = strlen(wppMsg) + 1;
						wppNotif->msg = (char*)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, wLen, 'wpmg');
						if (wppNotif->msg) {
							RtlCopyMemory(wppNotif->msg, wppMsg, wLen);
							wppNotif->bufSize = (ULONG)wLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(wppNotif)) {
								ExFreePool(wppNotif->msg);
								ExFreePool(wppNotif);
							}
						} else { ExFreePool(wppNotif); }
					}
					break;  // one tool match is enough
				}
			}
		}

		// -----------------------------------------------------------------------
		// Weaver Ant: Web shell child process detection (China Chopper, INMemory)
		//
		// Web shells execute OS commands by spawning child processes from the web
		// server worker process.  China Chopper uses JScript eval() to spawn cmd.exe;
		// INMemory web shells use in-memory .NET Assembly.Load to spawn arbitrary
		// processes.  Detect cmd/powershell/certutil/etc. spawned from IIS, Apache,
		// nginx, Tomcat, or PHP worker processes.
		// -----------------------------------------------------------------------
		{
			PEPROCESS webParent = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &webParent))) {

				char* webParentName = PsGetProcessImageFileName(webParent);

				if (webParentName != NULL &&
					(strcmp(webParentName, "w3wp.exe")     == 0 ||
					 strcmp(webParentName, "httpd.exe")    == 0 ||
					 strcmp(webParentName, "nginx.exe")    == 0 ||
					 strcmp(webParentName, "tomcat9.exe")  == 0 ||
					 strcmp(webParentName, "java.exe")     == 0 ||
					 strcmp(webParentName, "php-cgi.exe")  == 0 ||
					 strcmp(webParentName, "php.exe")      == 0 ||
					 strcmp(webParentName, "iisexpress.exe") == 0)) {

					// Any child process from a web server is suspicious;
					// interactive shells and LOLBins are critical.
					BOOLEAN isCriticalChild = FALSE;
					if (CreateInfo->ImageFileName != NULL) {
						static const WCHAR* kWebShellChildren[] = {
							L"cmd.exe", L"powershell.exe", L"pwsh.exe",
							L"wscript.exe", L"cscript.exe", L"mshta.exe",
							L"certutil.exe", L"bitsadmin.exe", L"rundll32.exe",
							L"regsvr32.exe", L"msbuild.exe", L"installutil.exe",
							L"net.exe", L"net1.exe", L"whoami.exe", L"ipconfig.exe",
							L"systeminfo.exe", L"tasklist.exe", L"arp.exe",
							L"nslookup.exe", L"ping.exe", L"curl.exe",
							// INMemory web shell: runtime .NET compilation
							// Behinder/Godzilla compile C#/VB.NET payloads on the fly
							L"csc.exe", L"vbc.exe", L"jsc.exe",
							// Additional recon / exfil LOLBins
							L"nltest.exe", L"dsquery.exe", L"csvde.exe",
							L"ldifde.exe", L"netstat.exe", L"route.exe",
							L"schtasks.exe", L"reg.exe", L"wmic.exe",
							L"attrib.exe", L"icacls.exe", L"takeown.exe",
							L"findstr.exe", L"xcopy.exe", L"robocopy.exe",
							nullptr
						};
						for (int i = 0; kWebShellChildren[i]; i++) {
							if (UnicodeStringContains(CreateInfo->ImageFileName, kWebShellChildren[i])) {
								isCriticalChild = TRUE;
								break;
							}
						}
					}

					char* childName = PsGetProcessImageFileName(Process);
					char webMsg[320];
					RtlStringCbPrintfA(webMsg, sizeof(webMsg),
						"Web shell: %s (pid=%llu) spawned child '%s' (pid=%llu) — "
						"China Chopper / Weaver Ant / ASPX web shell%s",
						webParentName,
						(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
						childName ? childName : "?",
						(ULONG64)PsGetProcessId(Process),
						isCriticalChild ? " [SHELL/LOLBIN]" : "");

					PKERNEL_STRUCTURED_NOTIFICATION webNotif =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'wshl');
					if (webNotif) {
						RtlZeroMemory(webNotif, sizeof(*webNotif));
						SET_CRITICAL(*webNotif);
						SET_CALLING_PROC_PID_CHECK(*webNotif);
						webNotif->isPath = FALSE;
						webNotif->pid = PsGetProcessId(Process);
						RtlCopyMemory(webNotif->procName, webParentName, 15);
						SIZE_T wLen = strlen(webMsg) + 1;
						webNotif->msg = (char*)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, wLen, 'wsmg');
						if (webNotif->msg) {
							RtlCopyMemory(webNotif->msg, webMsg, wLen);
							webNotif->bufSize = (ULONG)wLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(webNotif)) {
								ExFreePool(webNotif->msg);
								ExFreePool(webNotif);
							}
						} else { ExFreePool(webNotif); }
					}
				}

				ObDereferenceObject(webParent);
			}
		}

		// --- System binary masquerade detection ---
		// Attacker copies cmd.exe (or accessibility tool) to a non-standard path
		// and executes from there to avoid name-based detection.
		if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer &&
			CreateInfo->ImageFileName->Length > 0)
		{
			static const WCHAR* kSensitiveBinaries[] = {
				L"cmd.exe", L"powershell.exe", L"sethc.exe", L"utilman.exe",
				L"osk.exe", L"narrator.exe", L"magnify.exe", L"displayswitch.exe", nullptr
			};
			for (int i = 0; kSensitiveBinaries[i]; i++) {
				if (UnicodeStringContains(CreateInfo->ImageFileName, kSensitiveBinaries[i])) {
					BOOLEAN fromLegitPath =
						UnicodeStringContains(CreateInfo->ImageFileName, L"\\Windows\\System32\\") ||
						UnicodeStringContains(CreateInfo->ImageFileName, L"\\Windows\\SysWOW64\\") ||
						UnicodeStringContains(CreateInfo->ImageFileName, L"\\Windows\\WinSxS\\");
					if (!fromLegitPath) {
						char narrowPath[256] = "<unknown>";
						USHORT copyChars = min(
							(USHORT)(CreateInfo->ImageFileName->Length / sizeof(WCHAR)),
							(USHORT)(sizeof(narrowPath) - 1));
						for (USHORT j = 0; j < copyChars; j++) {
							WCHAR wc = CreateInfo->ImageFileName->Buffer[j];
							narrowPath[j] = (wc < 128) ? (char)wc : '?';
						}
						char* procName = PsGetProcessImageFileName(Process);
						char msg[320];
						RtlStringCbPrintfA(msg, sizeof(msg),
							"Masquerading: '%s' running from non-standard path '%s' "
							"(copied system binary / sticky keys replacement executed)",
							procName ? procName : "?", narrowPath);

						PKERNEL_STRUCTURED_NOTIFICATION n =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
						if (n) {
							RtlZeroMemory(n, sizeof(*n));
							SET_CRITICAL(*n);
							SET_CALLING_PROC_PID_CHECK(*n);
							n->isPath = FALSE;
							n->pid    = PsGetProcessId(Process);
							if (procName) RtlCopyMemory(n->procName, procName, 14);
							SIZE_T msgLen = strlen(msg) + 1;
							n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
							if (n->msg) {
								RtlCopyMemory(n->msg, msg, msgLen);
								n->bufSize = (ULONG)msgLen;
								if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
									ExFreePool(n->msg); ExFreePool(n);
								}
							} else { ExFreePool(n); }
						}
					}
					break;
				}
			}
		}

		// -----------------------------------------------------------------------
		// Suspicious execution path detection (T1204 / T1059)
		//
		// Executables running from Temp, Public, AppData\Local\Temp,
		// Downloads, or Recycle Bin are strong indicators of malware delivery.
		// 308 sigma "Suspicious Script Execution From Temp Folder" + 211
		// "Suspicious Binaries and Scripts in Public Folder" + 276 "Script
		// Interpreter Execution From Suspicious Folder" in 19K VT corpus.
		//
		// Only flag PE executables (not scripts — those are caught by the
		// cmdline pattern engine).  Skip if the process is a known installer.
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer &&
			CreateInfo->ImageFileName->Length > 0)
		{
			// Check if the image path contains a suspicious directory
			static const WCHAR* kSuspiciousPaths[] = {
				L"\\AppData\\Local\\Temp\\",
				L"\\AppData\\Roaming\\",     // non-standard exe location
				L"\\Users\\Public\\",
				L"\\Windows\\Temp\\",
				L"\\$Recycle.Bin\\",
				L"\\ProgramData\\",          // ProgramData without a known publisher subfolder
				nullptr
			};

			BOOLEAN isSuspiciousPath = FALSE;
			const WCHAR* matchedPath = nullptr;
			for (int i = 0; kSuspiciousPaths[i]; i++) {
				if (UnicodeStringContains(CreateInfo->ImageFileName, kSuspiciousPaths[i])) {
					isSuspiciousPath = TRUE;
					matchedPath = kSuspiciousPaths[i];
					break;
				}
			}

			if (isSuspiciousPath) {
				char* procName = PsGetProcessImageFileName(Process);

				// Allowlist: common legitimate processes that run from temp paths
				BOOLEAN isAllowedProcess = FALSE;
				if (procName) {
					static const char* kTempAllowed[] = {
						"setup.exe", "install.exe", "update.exe",
						"msiexec.exe", "TrustedInsta",
						"MicrosoftEd",   // Edge updater (truncated)
						"GoogleUpdate",  // Google updater (truncated)
						"ChromeSetup",
						"OfficeSetup",
						"vs_installe",   // Visual Studio installer (truncated)
						"NortonEDR.e",   // our own service (truncated)
						nullptr
					};
					for (int i = 0; kTempAllowed[i]; i++) {
						if (strcmp(procName, kTempAllowed[i]) == 0) {
							isAllowedProcess = TRUE;
							break;
						}
					}
				}

				if (!isAllowedProcess) {
					// Narrow the matched path for the message
					char narrowMatch[48] = {};
					for (int j = 0; j < 47 && matchedPath[j]; j++) {
						narrowMatch[j] = (matchedPath[j] < 128) ? (char)matchedPath[j] : '?';
					}

					char tempMsg[300];
					RtlStringCbPrintfA(tempMsg, sizeof(tempMsg),
						"Suspicious execution path: '%s' (pid=%llu) "
						"running from '%s' — possible malware staging/drop",
						procName ? procName : "?",
						(ULONG64)PsGetProcessId(Process),
						narrowMatch);

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'tpnt');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_WARNING(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid = PsGetProcessId(Process);
						if (procName) RtlCopyMemory(n->procName, procName, 14);
						SIZE_T mLen = strlen(tempMsg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, mLen, 'tpmg');
						if (n->msg) {
							RtlCopyMemory(n->msg, tempMsg, mLen);
							n->bufSize = (ULONG)mLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
				}
			}
		}

		// -----------------------------------------------------------------------
		// svchost.exe parent validation (T1036.004 / T1055)
		//
		// Legitimate svchost.exe is ALWAYS spawned by services.exe.  Any
		// svchost.exe whose parent is NOT services.exe is either:
		//   - A renamed malware binary masquerading as svchost.exe
		//   - An injected/hollowed process
		//   - A persistence payload registered as a bogus service
		//
		// 397 sigma "Uncommon Svchost Command Line Parameter" + 135
		// "Uncommon Svchost Parent Process" across 19K VT malware samples.
		// -----------------------------------------------------------------------
		if (CreateInfo->ImageFileName &&
			UnicodeStringContains(CreateInfo->ImageFileName, L"svchost.exe"))
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {
				char* parentName = PsGetProcessImageFileName(parentProcess);

				BOOLEAN isLegitParent = (parentName != NULL &&
					(strcmp(parentName, "services.exe") == 0 ||
					 strcmp(parentName, "MsMpEng.exe") == 0));  // Defender can restart svchost

				if (!isLegitParent) {
					char* childName = PsGetProcessImageFileName(Process);

					char svchMsg[300];
					RtlStringCbPrintfA(svchMsg, sizeof(svchMsg),
						"Suspicious svchost parent (T1036.004): svchost.exe (pid=%llu) "
						"spawned by '%s' (pid=%llu) — expected parent is services.exe",
						(ULONG64)PsGetProcessId(Process),
						parentName ? parentName : "?",
						(ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'svnt');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_CRITICAL(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid = PsGetProcessId(Process);
						if (parentName) RtlCopyMemory(n->procName, parentName, 14);
						SIZE_T mLen = strlen(svchMsg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, mLen, 'svmg');
						if (n->msg) {
							RtlCopyMemory(n->msg, svchMsg, mLen);
							n->bufSize = (ULONG)mLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
				}

				ObDereferenceObject(parentProcess);
			}
		}

		// --- Kerberos delegation / ticket attack tool detection ---
		// Detect known Kerberos attack tool binaries at process creation.
		{
			static const WCHAR* kKerberosAttackTools[] = {
				L"rubeus.exe",     // C# Kerberos abuse (S4U, delegation, AS-REP roast)
				L"kekeo.exe",      // Kerberos toolbox (TGT/TGS manipulation, delegation)
				L"rodcpwn.exe",    // RODC golden ticket / key list attack (Elad Shamir)
				L"getcchanges.exe",// RODC replication abuse / credential extraction
				L"klist.exe",      // Built-in but suspicious from non-system context
				nullptr
			};

			char* krbProcName = PsGetProcessImageFileName(Process);
			if (krbProcName && CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
				for (int i = 0; kKerberosAttackTools[i]; i++) {
					if (!UnicodeStringContains(CreateInfo->ImageFileName, kKerberosAttackTools[i]))
						continue;

					// klist.exe is legitimate from System32 — only flag from other paths
					if (i == 4) {
						if (UnicodeStringContains(CreateInfo->ImageFileName, L"\\Windows\\System32\\") ||
							UnicodeStringContains(CreateInfo->ImageFileName, L"\\Windows\\SysWOW64\\"))
							continue;
					}

					char narrowPath[256] = {};
					USHORT copyChars = min(
						(USHORT)(CreateInfo->ImageFileName->Length / sizeof(WCHAR)),
						(USHORT)(sizeof(narrowPath) - 1));
					for (USHORT j = 0; j < copyChars; j++) {
						WCHAR wc = CreateInfo->ImageFileName->Buffer[j];
						narrowPath[j] = (wc < 128) ? (char)wc : '?';
					}

					char msg[320];
					RtlStringCbPrintfA(msg, sizeof(msg),
						"Kerberos attack tool: '%s' launched from '%s' "
						"(delegation abuse / ticket manipulation — Rubeus/Kekeo/Impacket)",
						krbProcName, narrowPath);

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_CRITICAL(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid    = PsGetProcessId(Process);
						if (krbProcName) RtlCopyMemory(n->procName, krbProcName, 14);
						SIZE_T msgLen = strlen(msg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
						if (n->msg) {
							RtlCopyMemory(n->msg, msg, msgLen);
							n->bufSize = (ULONG)msgLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
					break;
				}
			}
		}

		// --- Tunneling / proxy tool detection ---
		// Attackers deploy tunneling tools on compromised hosts to proxy C2 traffic,
		// pivot laterally, or relay attack tools (Impacket, CrackMapExec) without
		// placing binaries on the target. Detect the tunnel endpoints.
		{
			static const WCHAR* kTunnelingTools[] = {
				L"chisel.exe",         // HTTP/SOCKS tunnel
				L"ligolo-agent.exe",   // Ligolo-ng agent
				L"ligolo-proxy.exe",   // Ligolo-ng proxy
				L"frpc.exe",           // Fast Reverse Proxy client
				L"frps.exe",           // Fast Reverse Proxy server
				L"gost.exe",           // GO Simple Tunnel
				L"plink.exe",          // PuTTY CLI — SSH tunnels
				L"socat.exe",          // Socket relay
				L"ncat.exe",           // Nmap netcat variant
				L"iox.exe",            // Port forwarding / SOCKS proxy
				L"earthworm.exe",      // EarthWorm tunnel (APT tool)
				L"ew.exe",             // EarthWorm short name
				L"ngrok.exe",          // Reverse tunnel to public endpoint
				L"rathole.exe",        // Rust reverse proxy
				L"bore.exe",           // Minimal tunnel
				L"revsocks.exe",       // Reverse SOCKS5 proxy
				L"rsocx.exe",          // Rust SOCKS proxy
				L"code-tunnel.exe",    // VS Code standalone tunnel CLI
				L"devtunnel.exe",      // Microsoft Dev Tunnels CLI
				nullptr
			};

			if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
				for (int i = 0; kTunnelingTools[i]; i++) {
					if (!UnicodeStringContains(CreateInfo->ImageFileName, kTunnelingTools[i]))
						continue;

					char narrowPath[256] = {};
					USHORT copyChars = min(
						(USHORT)(CreateInfo->ImageFileName->Length / sizeof(WCHAR)),
						(USHORT)(sizeof(narrowPath) - 1));
					for (USHORT j = 0; j < copyChars; j++) {
						WCHAR wc = CreateInfo->ImageFileName->Buffer[j];
						narrowPath[j] = (wc < 128) ? (char)wc : '?';
					}

					char* tunnelProc = PsGetProcessImageFileName(Process);
					char msg[320];
					RtlStringCbPrintfA(msg, sizeof(msg),
						"Tunneling tool: '%s' launched from '%s' "
						"(network pivot / C2 relay)",
						tunnelProc ? tunnelProc : "?", narrowPath);

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_CRITICAL(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid    = PsGetProcessId(Process);
						if (tunnelProc) RtlCopyMemory(n->procName, tunnelProc, 14);
						SIZE_T msgLen = strlen(msg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
						if (n->msg) {
							RtlCopyMemory(n->msg, msg, msgLen);
							n->bufSize = (ULONG)msgLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
					break;
				}
			}
		}

		// --- T1219: Remote access tool / IDE tunneling detection ---
		// Adversaries deploy legitimate remote access software (AnyDesk, TeamViewer,
		// ScreenConnect, etc.) and VS Code tunnels for persistent C2 and interactive
		// control. Chaos, Akira, DeadLock ransomware all use this pattern.
		{
			static const struct {
				const WCHAR* name;
				const char*  desc;
				BOOLEAN      critical;
			} kRemoteAccessTools[] = {
				// --- T1219.002: Remote desktop software ---
				{ L"anydesk.exe",        "AnyDesk remote access tool (Chaos/Akira/DeadLock ransomware)", TRUE  },
				{ L"teamviewer.exe",     "TeamViewer remote access tool",                               FALSE },
				{ L"screenconnect.exe",  "ScreenConnect/ConnectWise remote access",                     TRUE  },
				{ L"connectwisecontrol", "ConnectWise Control remote access",                           TRUE  },
				{ L"splashtop.exe",      "Splashtop Streamer remote access",                           FALSE },
				{ L"rustdesk.exe",       "RustDesk remote access tool (Akira ransomware)",              TRUE  },
				{ L"mobaxterm.exe",      "MobaXterm remote access (Akira ransomware)",                  FALSE },
				{ L"optitune.exe",       "OptiTune RMM (Chaos ransomware)",                            FALSE },
				{ L"syncrosetup.exe",    "Syncro RMM tool (Chaos ransomware)",                         FALSE },
				{ L"remcos.exe",         "Remcos RAT -- known malware",                                TRUE  },
				{ L"remoteutilities",    "Remote Utilities -- dual-use RAT",                           FALSE },
				{ L"action1_agent.exe",  "Action1 RMM (ransomware abuse)",                             FALSE },
				{ L"meshagent.exe",      "MeshCentral agent (ransomware/APT use)",                     FALSE },
				{ L"cloudflared.exe",    "Cloudflare Tunnel (Akira C2 relay)",                         TRUE  },
				{ nullptr, nullptr, FALSE }
			};

			if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
				for (int i = 0; kRemoteAccessTools[i].name; i++) {
					if (!UnicodeStringContains(CreateInfo->ImageFileName, kRemoteAccessTools[i].name))
						continue;

					// TeamViewer/Splashtop from Program Files are likely IT-managed — skip
					if (!kRemoteAccessTools[i].critical &&
						(UnicodeStringContains(CreateInfo->ImageFileName, L"\\Program Files\\") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"\\Program Files (x86)\\")))
						continue;

					char* ratProc = PsGetProcessImageFileName(Process);
					char msg[320];
					RtlStringCbPrintfA(msg, sizeof(msg),
						"Remote access tool: %s",
						kRemoteAccessTools[i].desc);

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						if (kRemoteAccessTools[i].critical) { SET_CRITICAL(*n); }
						else { SET_WARNING(*n); }
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid    = PsGetProcessId(Process);
						if (ratProc) RtlCopyMemory(n->procName, ratProc, 14);
						SIZE_T msgLen = strlen(msg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
						if (n->msg) {
							RtlCopyMemory(n->msg, msg, msgLen);
							n->bufSize = (ULONG)msgLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
					break;
				}
			}

			// --- T1219.001: VS Code IDE tunnel detection ---
			// Adversaries execute "code.exe tunnel" to create a reverse tunnel through
			// Microsoft Azure, providing browser-based shell access to the compromised host.
			if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer &&
				CreateInfo->CommandLine->Length > 0)
			{
				PCUNICODE_STRING cmdLine = CreateInfo->CommandLine;
				if (CmdContains(cmdLine, L"code.exe tunnel") ||
					CmdContains(cmdLine, L"code tunnel") ||
					CmdContains(cmdLine, L"code-insiders.exe tunnel"))
				{
					char* vsProc = PsGetProcessImageFileName(Process);
					char msg[256];
					RtlStringCbPrintfA(msg, sizeof(msg),
						"VS Code IDE tunnel: 'code.exe tunnel' detected -- "
						"reverse tunnel via Azure relay (T1219.001)");

					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_CRITICAL(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->isPath = FALSE;
						n->pid    = PsGetProcessId(Process);
						if (vsProc) RtlCopyMemory(n->procName, vsProc, 14);
						SIZE_T msgLen = strlen(msg) + 1;
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
						if (n->msg) {
							RtlCopyMemory(n->msg, msg, msgLen);
							n->bufSize = (ULONG)msgLen;
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg); ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
				}
			}
		}

		// -----------------------------------------------------------------------
		// Mitigation policy check — detect policies that block our HookDll injection
		// or prevent trampoline installation, leaving the process unwatched.
		//
		// ProcessSignaturePolicy (8), bit 0 = MicrosoftSignedOnly:
		//   LoadLibraryW(HookDll.dll) will be rejected by the kernel loader because
		//   HookDll is not Microsoft-signed. Our APC injection silently fails.
		//
		// ProcessDynamicCodePolicy (2), bit 0 = ProhibitDynamicCode:
		//   VirtualAlloc(PAGE_EXECUTE_READWRITE) for the trampoline pool fails even
		//   if HookDll loads. Inline hooks cannot be installed; only IAT patches apply.
		// -----------------------------------------------------------------------
		EnsureMitigationResolver();
		if (g_PsGetMitig) {
			DWORD sigFlags = 0, dynFlags = 0;

			BOOLEAN sigBlocked =
				NT_SUCCESS(g_PsGetMitig(Process, 8 /*ProcessSignaturePolicy*/, &sigFlags, sizeof(sigFlags))) &&
				(sigFlags & 0x1); // bit 0 = MicrosoftSignedOnly

			BOOLEAN dynBlocked =
				NT_SUCCESS(g_PsGetMitig(Process, 2 /*ProcessDynamicCodePolicy*/, &dynFlags, sizeof(dynFlags))) &&
				(dynFlags & 0x1); // bit 0 = ProhibitDynamicCode

			if (sigBlocked) {
				PKERNEL_STRUCTURED_NOTIFICATION n = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
				if (n) {
					const char* msg = "ProcessSignaturePolicy:MicrosoftSignedOnly — HookDll injection will be blocked; process has reduced EDR coverage";
					SET_WARNING(*n);
					SET_CALLING_PROC_PID_CHECK(*n);
					n->isPath = FALSE;
					n->pid = PsGetProcessId(Process);
					RtlCopyMemory(n->procName, PsGetProcessImageFileName(Process), 14);
					SIZE_T msgLen = strlen(msg) + 1;
					n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
					if (n->msg) {
						RtlCopyMemory(n->msg, msg, msgLen);
						if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
							ExFreePool(n->msg);
							ExFreePool(n);
						}
					} else { ExFreePool(n); }
				}
			}

			if (dynBlocked) {
				PKERNEL_STRUCTURED_NOTIFICATION n = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
				if (n) {
					const char* msg = "ProcessDynamicCodePolicy:ProhibitDynamicCode — RWX trampoline pool blocked; HookDll inline hooks will not install";
					SET_WARNING(*n);
					SET_CALLING_PROC_PID_CHECK(*n);
					n->isPath = FALSE;
					n->pid = PsGetProcessId(Process);
					RtlCopyMemory(n->procName, PsGetProcessImageFileName(Process), 14);
					SIZE_T msgLen = strlen(msg) + 1;
					n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
					if (n->msg) {
						RtlCopyMemory(n->msg, msg, msgLen);
						if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
							ExFreePool(n->msg);
							ExFreePool(n);
						}
					} else { ExFreePool(n); }
				}
			}
		}

		// -----------------------------------------------------------------------
		// Command line argument analysis -- flag suspicious patterns used by
		// living-off-the-land attacks, PowerShell downloaders, LOLBins, and
		// obfuscated script execution.  Checked against the raw command line so
		// nothing is lost even when argc/argv parsing is bypassed.
		// -----------------------------------------------------------------------
		if (CreateInfo->CommandLine &&
		    CreateInfo->CommandLine->Buffer &&
		    CreateInfo->CommandLine->Length > 0)
		{
			PCUNICODE_STRING cmd = CreateInfo->CommandLine;

			static const struct {
				const WCHAR* needle;
				const char*  desc;
				BOOLEAN      critical;
			} kPatterns[] = {
				// --- Critical: direct download / execution primitives ---
				{ L"-encodedcommand",       "PowerShell -EncodedCommand (base64 payload)",        TRUE  },
				{ L" -enc ",                "PowerShell -enc abbreviation (base64 payload)",       TRUE  },
				{ L"downloadstring(",       "PowerShell DownloadString -- in-memory execution",    TRUE  },
				{ L"frombase64string(",     "FromBase64String -- encoded payload decoding",         TRUE  },
				{ L"-urlcache",             "certutil -urlcache download lolbin",                  TRUE  },
				{ L"/transfer",             "BITS transfer download lolbin",                       TRUE  },
				// --- T1197: BITS job abuse for execution/persistence (Diavol, HAFNIUM) ---
				// bitsadmin /SetNotifyCmdLine triggers execution when a BITS job
				// completes — used by Diavol ransomware, HAFNIUM, and others to
				// execute payloads via the BITS service (svchost.exe -k netsvcs).
				{ L"/setnotifycmdline",     "BITS SetNotifyCmdLine — execution via BITS job completion callback (T1197)", TRUE },
				{ L"/setnotifyflags",       "BITS SetNotifyFlags — BITS job notification config (T1197 setup)",          FALSE },
				{ L"bitsadmin /create",     "BITS job creation — potential persistence/execution staging (T1197)",        FALSE },
				{ L"bitsadmin /resume",     "BITS job resume — triggers staged BITS execution (T1197)",                  FALSE },
				{ L"bitsadmin /addfile",    "BITS AddFile — file staging via BITS job (T1197)",                           FALSE },
				{ L"bitsadmin /rawreturn",  "BITS RawReturn — suppress output for stealth BITS operations",              FALSE },
				{ L"/i:http",               "msiexec /i:http remote install lolbin",               TRUE  },
				// --- T1059.001 / T1105: download cradles ---
				{ L"downloaddata(",         "PowerShell DownloadData -- in-memory byte fetch (cradle T1105)",          TRUE  },
				{ L"downloadfile(",         "PowerShell DownloadFile -- disk-staged fetch (cradle T1105)",              TRUE  },
				{ L"invoke-webrequest",     "Invoke-WebRequest cradle (T1105)",                                         TRUE  },
				{ L"invoke-restmethod",     "Invoke-RestMethod cradle (T1105)",                                         TRUE  },
				{ L"iwr -uri",              "PS iwr alias cradle (T1105)",                                              TRUE  },
				{ L"irm -uri",              "PS irm alias cradle (T1105)",                                              TRUE  },
				{ L"iwr http",              "PS iwr http cradle (T1105)",                                               TRUE  },
				{ L"irm http",              "PS irm http cradle (T1105)",                                               TRUE  },
				{ L"start-bitstransfer",    "Start-BitsTransfer cradle (T1197/T1105)",                                  TRUE  },
				{ L"import-module bitstransfer", "BitsTransfer module import — cradle staging (T1197)",                 FALSE },
				{ L"msxml2.xmlhttp",        "MSXML2.XMLHTTP COM cradle (JScript/VBS/PS T1059)",                         TRUE  },
				{ L"msxml2.serverxmlhttp",  "MSXML2.ServerXMLHTTP COM cradle (T1059)",                                  TRUE  },
				{ L"winhttp.winhttprequest",  "WinHttp.WinHttpRequest COM cradle (T1059)",                              TRUE  },
				{ L"-comobject msxml2",     "New-Object -ComObject MSXML2 cradle (T1059.001)",                          TRUE  },
				{ L"-com msxml2",           "New-Object -Com MSXML2 cradle (T1059.001)",                                TRUE  },
				{ L"-com winhttp",          "New-Object -Com WinHttp cradle (T1059.001)",                               TRUE  },
				{ L"certutil -urlcache -split -f", "certutil urlcache split -f cradle (T1105)",                         TRUE  },
				{ L"certutil.exe -urlcache", "certutil urlcache cradle (T1105)",                                        TRUE  },
				{ L"certutil -urlcache -f", "certutil urlcache -f cradle (T1105)",                                      TRUE  },
				{ L"mshta http",            "mshta HTTP cradle — remote .hta exec (T1218.005)",                         TRUE  },
				{ L"mshta vbscript:",       "mshta vbscript: URI cradle (T1218.005)",                                   TRUE  },
				{ L"mshta javascript:",     "mshta javascript: URI cradle (T1218.005)",                                 TRUE  },
				{ L"regsvr32 /s /n /u /i:http", "regsvr32 scrobj URL cradle — Squiblydoo (T1218.010)",                  TRUE  },
				{ L"rundll32 javascript:",  "rundll32 javascript: URI cradle (T1218.011)",                              TRUE  },
				{ L"rundll32.exe javascript:", "rundll32.exe javascript: URI cradle (T1218.011)",                       TRUE  },
				{ L"rundll32 url.dll,openurl", "rundll32 url.dll OpenURL — browser-less URL fetch (T1218.011)",         TRUE  },
				{ L"rundll32 url.dll,fileprotocolhandler", "rundll32 url.dll FileProtocolHandler — LOLBin cradle",      TRUE  },
				{ L"curl.exe -o",           "curl.exe -o download cradle (T1105)",                                      FALSE },
				{ L"curl -s http",          "curl -s silent download cradle (T1105)",                                   FALSE },
				{ L"wget http",             "wget http download cradle (T1105)",                                        FALSE },
				{ L"wsl -e curl",           "wsl -e curl cradle — WSL-proxied download (T1202)",                        TRUE  },
				{ L"wsl curl http",         "wsl curl http cradle — WSL-proxied download (T1202)",                      TRUE  },
				{ L"iex (new-object",       "IEX (New-Object ...) — cradle-to-exec chain (T1059.001)",                  TRUE  },
				{ L"iex(new-object",        "IEX(New-Object ...) — cradle-to-exec chain (T1059.001)",                   TRUE  },
				{ L"iex (iwr",              "IEX (iwr ...) — cradle-to-exec chain (T1059.001)",                         TRUE  },
				{ L"iex(iwr",               "IEX(iwr ...) — cradle-to-exec chain (T1059.001)",                          TRUE  },
				{ L"iex (invoke-webrequest", "IEX (Invoke-WebRequest ...) — cradle-to-exec chain (T1059.001)",          TRUE  },
				{ L"[reflection.assembly]::load((new-object", "Reflective Assembly.Load from WebClient bytes (T1620)", TRUE },
				{ L"[system.reflection.assembly]::load((new-object", "Reflective Assembly.Load from WebClient bytes (T1620)", TRUE },
				{ L"resolve-dnsname -type txt", "Resolve-DnsName TXT — DNS cradle / TXT-record payload (T1071.004)",    TRUE  },
				{ L"invoke-dnsexfiltrator",  "Invoke-DNSExfiltrator — DNS cradle framework (T1071.004)",                TRUE  },
				// Char-split obfuscated cradles (Invoke-Obfuscation / Empire)
				{ L"\"download\"+\"string\"", "Char-split DownloadString — Invoke-Obfuscation cradle",                  TRUE  },
				{ L"\"downloads\"+\"tring\"", "Char-split DownloadString variant — Invoke-Obfuscation cradle",          TRUE  },
				{ L"\"down\"+\"loadstring\"", "Char-split DownloadString variant — Invoke-Obfuscation cradle",          TRUE  },
				{ L"\"invoke\"+\"-expression\"", "Char-split Invoke-Expression — Invoke-Obfuscation cradle",            TRUE  },
				// --- Fileless / in-memory-only script execution (T1059.001 + T1027.011) ---
				{ L"[scriptblock]::create(",      "ScriptBlock::Create — in-memory-only script compile (T1059.001)",           TRUE  },
				{ L"[system.management.automation.scriptblock]::create(", "FQN ScriptBlock::Create — in-memory script compile", TRUE  },
				{ L"$executioncontext.invokecommand.invokescript", "$ExecutionContext.InvokeCommand.InvokeScript — fileless exec", TRUE },
				{ L"$executioncontext.invokecommand.newscriptblock", "$ExecutionContext NewScriptBlock — fileless exec",       TRUE },
				{ L".addscript(",                "PowerShell.AddScript — Runspace-hosted in-memory script exec",              TRUE  },
				{ L"[powershell]::create()",     "[PowerShell]::Create() — embedded PS runspace (fileless host)",              TRUE  },
				{ L"[runspacefactory]::createrunspace", "RunspaceFactory::CreateRunspace — embedded PS runtime (fileless)",   TRUE  },
				{ L"[runspacefactory]::createrunspacepool", "RunspaceFactory::CreateRunspacePool — embedded multi-script host", TRUE },
				{ L"& ([scriptblock]::create(",  "& ScriptBlock::Create — in-memory script invocation chain",                  TRUE  },
				{ L". ([scriptblock]::create(",  ". ScriptBlock::Create — in-memory script dot-source chain",                  TRUE  },
				{ L"iex $",                       "IEX on variable — payload lives as string before exec (T1027.011)",         TRUE  },
				{ L"invoke-expression $",        "Invoke-Expression on variable — fileless string exec (T1027.011)",           TRUE  },
				{ L"[appdomain]::currentdomain.load(", "AppDomain.Load — fileless .NET assembly load from byte buffer (T1620)", TRUE },
				{ L"[parser]::parseinput(",      "[Parser]::ParseInput — AST-based dynamic script construction (fileless)",    TRUE  },
				// --- T1562.001: IOfficeAntiVirus (mpoav) disable/redirect ---
				{ L"hklm\\software\\microsoft\\officeantivirus", "HKLM OfficeAntiVirus key touch — potential macro AV disable (T1562.001)", TRUE },
				{ L"hkey_local_machine\\software\\microsoft\\officeantivirus", "HKLM OfficeAntiVirus key touch — macro AV disable (T1562.001)", TRUE },
				{ L"\\clsid\\{2781761e-28e0-4109-99fe-b9d127c57afe}", "Defender mpoav CLSID touch — IOfficeAntiVirus provider tamper (T1562.001)", TRUE },
				{ L"{2781761e-28e0-4109-99fe-b9d127c57afe}", "Defender mpoav CLSID reference — IOfficeAntiVirus tamper target", TRUE },
				{ L"component categories\\{56ffcc30-d398-11d0-b2ae-00a0c908fa49}", "IOfficeAntiVirus component category reference — provider tamper", TRUE },
				{ L"reg delete \"hklm\\software\\microsoft\\officeantivirus\"", "reg delete OfficeAntiVirus — macro AV unregister (T1562.001)", TRUE },
				{ L"reg add \"hklm\\software\\microsoft\\office\" /v disableav", "Office DisableAV registry tamper (T1562.001)", TRUE },
				{ L"officeantivirus /v disabled", "OfficeAntiVirus Disabled value set (T1562.001)",                             TRUE  },
				{ L"applicationguard /v enabled /t reg_dword /d 0", "ApplicationGuard disable — macro sandbox bypass",           TRUE  },
				{ L"disableattachmentscanning", "DisableAttachmentScanning — Office/Outlook macro AV bypass",                  TRUE  },
				{ L"vbawarnings /t reg_dword /d 1", "Office VBAWarnings=1 (Enable all macros) — macro policy bypass (T1562.001)", TRUE },
				{ L"accessvbom /t reg_dword /d 1",  "Office AccessVBOM=1 — VBA project model access bypass",                    TRUE  },
				{ L"javascript:",           "javascript: URI -- script execution via shell",        TRUE  },
				{ L"vbscript:",             "vbscript: URI -- script execution via shell",          TRUE  },
				{ L"//e:vbscript",          "wscript/cscript //E:vbscript engine override",         TRUE  },
				{ L"//e:jscript",           "wscript/cscript //E:jscript engine override",          TRUE  },
				{ L"installutil",           "InstallUtil lolbin -- bypasses AppLocker/SRP",         TRUE  },
				{ L"regsvr32 /s /u /i:",    "Squiblydoo: regsvr32 COM scriptlet download",          TRUE  },
				{ L"scrobj.dll",            "scrobj.dll COM scriptlet execution",                   TRUE  },
				// --- T1219.001 / T1059: VS Code malware abuse taxonomy ---
				// code-tunnel.exe is the standalone CLI — no full VS Code install needed
				{ L"code-tunnel",               "code-tunnel.exe standalone CLI tunnel (T1219.001)",                           TRUE  },
				{ L"devtunnel.exe",             "Microsoft Dev Tunnels CLI — reverse tunnel (T1219.001)",                     TRUE  },
				{ L"devtunnel host",            "devtunnel host — start Dev Tunnel listener (T1219.001)",                    TRUE  },
				{ L"code serve-web",            "code serve-web — VS Code web server (T1219.001)",                            TRUE  },
				{ L"code.exe serve-web",        "code.exe serve-web — VS Code web server (T1219.001)",                       TRUE  },
				// Silent extension install — attackers push trojanized .vsix
				{ L"--install-extension",       "VS Code --install-extension — silent extension sideload (T1059)",             TRUE  },
				{ L"code --install-extension",  "code --install-extension — extension install (T1059)",                        TRUE  },
				{ L"code-insiders --install-extension", "code-insiders --install-extension — extension install",               TRUE  },
				// Extension dir override — loads extensions from attacker-controlled path
				{ L"--extensions-dir",          "VS Code --extensions-dir override — extension sideload from custom path",    TRUE  },
				// VS Code tunnel service registration (persistence)
				{ L"tunnel service install",    "VS Code tunnel service install — persistent tunnel registration (T1543)",     TRUE  },
				{ L"tunnel service uninstall",  "VS Code tunnel service uninstall — cleanup after tunnel use",                FALSE },
				{ L"tunnel --accept-server-license-terms", "VS Code tunnel auto-accept — non-interactive tunnel setup",       TRUE  },
				{ L"tunnel --name",             "VS Code tunnel --name — named tunnel (hands-on-keyboard indicator)",         TRUE  },
				// VS Code tasks.json / launch.json command injection
				{ L"\"command\":",              "VS Code tasks/launch.json command field — potential auto-exec",               FALSE },
				{ L"tasks.json",                "VS Code tasks.json reference — potential auto-exec configuration",            FALSE },
				// code.exe spawning shell processes (common C2-over-tunnel pattern)
				{ L"code.exe --ms-enable-electron-run-as-node", "VS Code Electron run-as-node — Node.js exec from code.exe", TRUE  },
				{ L"--ms-enable-electron-run-as-node", "Electron run-as-node flag — code.exe/electron shell escape",          TRUE  },
				// --- T1562.001: AMSI provider enumeration / tampering (WhoAMSI recon) ---
				{ L"\\microsoft\\amsi\\providers", "AMSI Providers registry path — provider enumeration / WhoAMSI recon (T1562.001)", TRUE },
				{ L"hklm\\software\\microsoft\\amsi", "HKLM AMSI registry path — provider enumeration / tampering (T1562.001)", TRUE },
				{ L"reg query \"hklm\\software\\microsoft\\amsi\"", "reg query AMSI — provider enumeration (WhoAMSI technique)", TRUE },
				{ L"get-childitem \"hklm:\\software\\microsoft\\amsi", "PS Get-ChildItem AMSI — provider enumeration (T1562.001)", TRUE },
				{ L"get-itemproperty \"hklm:\\software\\classes\\clsid\\{", "PS Get-ItemProperty CLSID — InProcServer32 recon", FALSE },
				{ L"remove-item \"hklm:\\software\\microsoft\\amsi", "PS Remove-Item AMSI — provider deletion attack (T1562.001)", TRUE },
				{ L"reg delete \"hklm\\software\\microsoft\\amsi", "reg delete AMSI — provider deletion attack (T1562.001)", TRUE },
				// --- Warning: evasion / stealth options ---
				{ L"invoke-expression",       "Invoke-Expression (IEX) -- dynamic execution",      FALSE },
				{ L"-executionpolicy bypass", "PowerShell ExecutionPolicy bypass",                 FALSE },
				{ L"-exec bypass",            "PowerShell -exec bypass abbreviation",              FALSE },
				{ L"-windowstyle hidden",     "PowerShell hidden window -- stealth execution",     FALSE },
				{ L"-w hidden",               "PowerShell -w hidden abbreviation",                 FALSE },
				{ L"[system.reflection",      "Reflection Assembly load -- in-memory .NET",        FALSE },
				// --- Proxied lateral movement / tunneling patterns ---
				{ L"interface portproxy",     "netsh portproxy -- local port forwarding pivot",     TRUE  },
				{ L"> \\\\127.0.0.1\\",        "smbexec: UNC output redirection to localhost",      TRUE  },
				{ L"\\\\c$\\__output",         "smbexec: C$ admin share __output file pattern",     TRUE  },
				{ L"> \\\\localhost\\",         "smbexec: UNC output redirection variant",           TRUE  },
				{ L"connectaddress=",         "netsh portproxy connectaddress -- pivot forwarding", TRUE  },
				// --- T1562: Defense impairment patterns ---
				{ L"systemsettingsadminflows", "SystemSettingsAdminFlows Defender disable (Deadlock ransomware)", TRUE },
				{ L"wevtutil.exe cl",          "wevtutil event log clearing (Mimic ransomware)",   TRUE  },
				{ L"wevtutil cl ",             "wevtutil event log clearing (short form)",          TRUE  },
				{ L"vssadmin delete shadows",  "VSS shadow deletion -- ransomware pre-encryption", TRUE  },
				{ L"vssadmin.exe delete shadows", "VSS shadow deletion -- ransomware (full path)", TRUE  },
				{ L"shadowcopy delete",        "wmic shadowcopy delete -- ransomware VSS wipe",    TRUE  },
				{ L"add-mppreference",         "Add-MpPreference -- Defender config tampering",    TRUE  },
				{ L"-exclusionpath",           "Defender ExclusionPath abuse (Chihuahua Stealer)",  TRUE  },
				{ L"-exclusionprocess",        "Defender ExclusionProcess abuse",                   TRUE  },
				{ L"-exclusionextension",      "Defender ExclusionExtension abuse",                 TRUE  },
				{ L"set-mppreference",         "Set-MpPreference -- Defender config tampering",     TRUE  },
				{ L"disablerealtimemonitoring", "Disable-RealtimeMonitoring via PowerShell",        TRUE  },
				{ L"advfirewall set",          "netsh advfirewall -- firewall disable (Medusa)",    TRUE  },
				{ L"firewall set opmode disable", "netsh firewall opmode disable (legacy)",         TRUE  },
				{ L"sc stop windefend",        "Stop Windows Defender service",                     TRUE  },
				{ L"sc delete windefend",      "Delete Windows Defender service",                   TRUE  },
				{ L"sc config windefend start=disabled", "Disable Defender autostart",              TRUE  },
				{ L"sc stop sense",            "Stop Defender ATP sensor service",                  TRUE  },
				{ L"sc config eventlog start=disabled", "Disable Windows Event Log service",        TRUE  },
				{ L"bcdedit /set safeboot",    "bcdedit safeboot -- EDR bypass via Safe Mode",      TRUE  },
				{ L"bcdedit.exe /set {default} recoveryenabled no", "Disable recovery (ransomware)", TRUE },
				{ L"bcdedit /set testsigning",  "bcdedit testsigning -- DSE bypass allows unsigned drivers", TRUE },
				{ L"bcdedit /set nointegritychecks", "bcdedit nointegritychecks -- CI bypass disables image hash validation", TRUE },
				{ L"bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS", "bcdedit DISABLE_INTEGRITY_CHECKS -- CI bypass via boot options", TRUE },
				{ L"bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS", "bcdedit DDISABLE_INTEGRITY_CHECKS -- CI bypass (double-D variant)", TRUE },
				// --- T1562: fltmc.exe minifilter evasion ---
				{ L"fltmc unload",             "fltmc unload -- minifilter unload attempt",          TRUE  },
				{ L"fltmc.exe unload",         "fltmc.exe unload -- minifilter unload attempt",      TRUE  },
				{ L"fltmc detach",             "fltmc detach -- minifilter instance detach attempt",  TRUE  },
				{ L"fltmc.exe detach",         "fltmc.exe detach -- minifilter instance detach",      TRUE  },
				// --- Reconnaissance: fltmc.exe enumeration ---
				{ L"fltmc instances",          "fltmc instances -- minifilter recon enumeration",     FALSE },
				{ L"fltmc.exe instances",      "fltmc.exe instances -- minifilter recon enumeration", FALSE },
				{ L"fltmc filters",            "fltmc filters -- minifilter recon enumeration",       FALSE },
				{ L"fltmc.exe filters",        "fltmc.exe filters -- minifilter recon enumeration",   FALSE },
				{ L"fltmc volumes",            "fltmc volumes -- minifilter recon enumeration",       FALSE },
				{ L"fltmc.exe volumes",        "fltmc.exe volumes -- minifilter recon enumeration",   FALSE },
				// --- T1546.011: Application shimming ---
				// sdbinst.exe registers a shim database (.sdb) for persistence/injection.
				{ L"sdbinst",                  "sdbinst: shim database installation — T1546.011 persistence/DLL injection via AppCompat shim", TRUE },
				{ L"sdbinst.exe",              "sdbinst.exe: shim database installation — T1546.011 persistence/DLL injection", TRUE },
				// Direct AppCompat manipulation via reg.exe
				{ L"appcompatflags\\custom",    "reg write to AppCompatFlags\\Custom — shim database registration (T1546.011)", TRUE },
				{ L"appcompatflags\\installedsdb", "reg write to AppCompatFlags\\InstalledSDB — shim persistence (T1546.011)", TRUE },
				// --- T1562: BFE service stop (nuclear WFP attack) ---
				{ L"sc stop bfe",              "Stop Base Filtering Engine service — nuclear WFP teardown!", TRUE },
				{ L"net stop bfe",             "net stop bfe — nuclear WFP teardown!",               TRUE  },

				// --- T1518.001 / Reconnaissance: firewall & WFP rule enumeration ---
				// Attackers enumerate firewall rules and WFP state before adding
				// BLOCK filters (EDRSilencer) or disabling firewall profiles.
				// Pre-attack recon is Warning-level (not destructive yet).

				// netsh firewall/advfirewall show commands
				{ L"advfirewall show",          "netsh advfirewall show — firewall profile/rule recon",                 FALSE },
				{ L"advfirewall firewall show", "netsh advfirewall firewall show — firewall rule enumeration",          FALSE },
				{ L"advfirewall firewall show rule name=all", "netsh firewall show ALL rules — full ruleset dump",      FALSE },
				{ L"advfirewall export",        "netsh advfirewall export — firewall policy export for offline analysis", FALSE },
				// netsh WFP state/filter dump (reveals EDR WFP filters, callouts, sublayers)
				{ L"netsh wfp show",            "netsh wfp show — WFP filter/state/callout enumeration (pre-EDRSilencer recon)", FALSE },
				{ L"netsh wfp show filters",    "netsh wfp show filters — WFP filter enumeration (reveals EDR filter IDs)",     FALSE },
				{ L"netsh wfp show state",      "netsh wfp show state — full WFP state dump (filters+callouts+sublayers)",      FALSE },
				{ L"netsh wfp show netevents",  "netsh wfp show netevents — WFP network event monitoring",                      FALSE },
				{ L"netsh wfp capture",         "netsh wfp capture — WFP diagnostic capture (advanced recon)",                  FALSE },
				// PowerShell firewall enumeration
				{ L"get-netfirewallrule",       "Get-NetFirewallRule — PowerShell firewall rule enumeration",           FALSE },
				{ L"get-netfirewallprofile",    "Get-NetFirewallProfile — PowerShell firewall profile recon",           FALSE },
				{ L"get-netfirewallsetting",    "Get-NetFirewallSetting — PowerShell firewall global settings recon",   FALSE },
				{ L"get-netfirewallportfilter", "Get-NetFirewallPortFilter — PowerShell port filter enumeration",       FALSE },
				{ L"get-netfirewalladdressfilter", "Get-NetFirewallAddressFilter — PowerShell address filter recon",    FALSE },
				{ L"get-netfirewallapplicationfilter", "Get-NetFirewallApplicationFilter — PowerShell app filter recon (reveals EDR exe paths)", FALSE },
				// Defender configuration enumeration (pre-exclusion/disable recon)
				{ L"get-mppreference",          "Get-MpPreference — Defender configuration recon (exclusions, scan settings)", FALSE },
				{ L"get-mpcomputerstatus",      "Get-MpComputerStatus — Defender status/version recon",                FALSE },
				{ L"get-mpthreatdetection",     "Get-MpThreatDetection — Defender detection history recon",            FALSE },
				// NtObjectManager PowerShell module (James Forshaw) — advanced WFP enumeration
				// These cmdlets call WFP APIs directly and are used by red-teamers for
				// pre-EDRSilencer reconnaissance (enumerate filters/sublayers/callouts/providers).
				{ L"get-fwfilter",              "Get-FwFilter — NtObjectManager WFP filter enumeration (reveals EDR filter objects)",          FALSE },
				{ L"get-fwsublayer",            "Get-FwSubLayer — NtObjectManager WFP sublayer enumeration (reveals EDR sublayer GUID/weight)", FALSE },
				{ L"get-fwcallout",             "Get-FwCallout — NtObjectManager WFP callout enumeration (reveals EDR inspection hooks)",      FALSE },
				{ L"get-fwprovider",            "Get-FwProvider — NtObjectManager WFP provider enumeration (fingerprints security products)",  FALSE },
				{ L"get-fwengine",              "Get-FwEngine — NtObjectManager WFP engine handle acquisition",                                FALSE },
				{ L"get-fwlayer",               "Get-FwLayer — NtObjectManager WFP layer enumeration (maps all monitored layers)",             FALSE },
				{ L"get-fwnetwork",             "Get-FwNetworkEvent — NtObjectManager WFP network event enumeration",                          FALSE },
				{ L"ntobjectmanager",           "NtObjectManager module reference — advanced Windows object/WFP/token recon toolkit",           FALSE },
				// WFP diagnostic tool
				{ L"wfpdiag",                   "wfpdiag — Microsoft WFP diagnostic tool (reveals all WFP state)",     FALSE },

				// --- T1047: WMI abuse (wmic.exe suspicious command lines) ---
				{ L"wmic process call create",  "wmic process call create — remote/local process spawn via WMI",       TRUE  },
				{ L"wmic /node:",               "wmic /node: — remote WMI execution against target host",             TRUE  },
				{ L"wmic shadowcopy list",      "wmic shadowcopy list — VSS recon (pre-ransomware)",                  FALSE },
				{ L"wmic useraccount",          "wmic useraccount — user account enumeration via WMI",                FALSE },
				{ L"wmic group",                "wmic group — group enumeration via WMI",                             FALSE },
				{ L"wmic service call",         "wmic service call — WMI service manipulation",                       TRUE  },
				{ L"wmic os get",               "wmic os get — OS version/architecture recon via WMI",                FALSE },
				{ L"wmic qfe",                  "wmic qfe — installed patch enumeration (vuln recon)",                FALSE },
				{ L"wmic product call",         "wmic product call — MSI uninstall/repair via WMI",                   TRUE  },
				{ L"wmic logicaldisk",          "wmic logicaldisk — disk enumeration (ransomware target recon)",      FALSE },
				{ L"wmic nicconfig",            "wmic nicconfig — network adapter recon via WMI",                     FALSE },
				{ L"wmic startup",              "wmic startup — persistence listing via WMI startup entries",         FALSE },
				{ L"wmic /format:",             "wmic /format: — XSL stylesheet execution (Squiblytwo T1220)",        TRUE  },
				{ L"wmic /compile:",            "wmic /compile: — MOF compilation via wmic (T1546.003)",              TRUE  },

				// --- T1562.002: ETW session/provider tampering via command line ---
				// xperf — WPA/WPT trace session control (Windows Performance Toolkit)
				{ L"xperf -stop",               "xperf -stop — ETW session stop (T1562.002 telemetry blinding)",        TRUE  },
				{ L"xperf -cancel",             "xperf -cancel — ETW session cancel/abort (T1562.002)",                 TRUE  },
				{ L"xperf -on",                 "xperf -on — ETW session start with provider capture (T1562.002)",      TRUE  },
				{ L"xperf -d ",                 "xperf -d — merge/dump and stop trace session (T1562.002)",             TRUE  },
				{ L"xperf -flush",              "xperf -flush — force-flush session buffers (data loss vector T1562.002)", TRUE },
				{ L"xperf -setprofinterval",    "xperf -setprofinterval — alter CPU profiling timer (PMC telemetry degradation T1562.002)", TRUE },
				{ L"xperf -buffering",          "xperf -buffering — set session buffer count (buffer exhaustion T1562.002)", TRUE },
				{ L"xperf -minbuffers",         "xperf -minbuffers — set minimum buffer count (starvation T1562.002)", TRUE },
				{ L"xperf -maxbuffers",         "xperf -maxbuffers — set maximum buffer count (starvation T1562.002)", TRUE },
				{ L"xperf -providers",          "xperf -providers — enumerate all registered ETW providers (recon T1518.001)", FALSE },
				{ L"xperf -loggers",            "xperf -loggers — list all active ETW sessions (recon T1518.001)",     FALSE },
				{ L"xperf -dumper",             "xperf -dumper — dump ETW session data in real time (recon T1005)",    FALSE },
				// logman — stops or deletes ETW trace sessions (bypasses prologue checks)
				{ L"logman stop",               "logman stop — ETW trace session stop (T1562.002 telemetry blinding)",  TRUE  },
				{ L"logman delete",             "logman delete — ETW trace session deletion (T1562.002 persistent blind)", TRUE },
				{ L"logman update",             "logman update — ETW trace session modification (T1562.002)",           TRUE  },
				// wevtutil — channel disable (we already catch 'cl' for clearing)
				{ L"wevtutil sl ",              "wevtutil set-log — event channel config modification (T1562.002)",     TRUE  },
				{ L"wevtutil set-log",          "wevtutil set-log — event channel disable/modify (T1562.002)",         TRUE  },
				{ L"/e:false",                  "Event channel disable (/e:false) — ETW channel blinding (T1562.002)", TRUE  },
				// wevtutil — manifest install/uninstall and provider enumeration
				{ L"wevtutil im ",              "wevtutil install-manifest — register rogue ETW provider manifest (T1562.002)", TRUE },
				{ L"wevtutil install-manifest", "wevtutil install-manifest — register rogue ETW provider manifest (T1562.002)", TRUE },
				{ L"wevtutil um ",              "wevtutil uninstall-manifest — unregister ETW provider (T1562.002 blinding)", TRUE },
				{ L"wevtutil uninstall-manifest", "wevtutil uninstall-manifest — remove ETW provider definition (T1562.002)", TRUE },
				{ L"wevtutil ep",               "wevtutil enum-publishers — ETW provider enumeration (pre-manifest-tamper recon)", FALSE },
				{ L"wevtutil enum-publishers",  "wevtutil enum-publishers — ETW provider enumeration (pre-manifest-tamper recon)", FALSE },
				{ L"wevtutil gp ",              "wevtutil get-publisher — ETW provider detail dump (GUID, channels, message DLL)", FALSE },
				{ L"wevtutil get-publisher",    "wevtutil get-publisher — ETW provider detail dump (GUID, channels, message DLL)", FALSE },
				// PowerShell ETW provider/session manipulation
				{ L"remove-etwtraceprovider",   "Remove-EtwTraceProvider — ETW provider removal (T1562.002)",          TRUE  },
				{ L"set-etwtraceprovider",      "Set-EtwTraceProvider — ETW provider config tampering (T1562.002)",    TRUE  },
				{ L"stop-etwtracesession",      "Stop-EtwTraceSession — ETW session stop via PowerShell (T1562.002)",  TRUE  },
				{ L"remove-etwtracesession",    "Remove-EtwTraceSession — ETW session removal via PowerShell (T1562.002)", TRUE },
				{ L"new-autologgerconfig",      "New-AutologgerConfig — AutoLogger creation/modification (T1562.002)", FALSE },
				// ETW recon (pre-attack enumeration of active sessions/providers)
				{ L"get-etwtracesession",       "Get-EtwTraceSession — ETW session enumeration (pre-attack recon)",    FALSE },
				{ L"get-etwtraceprovider",      "Get-EtwTraceProvider — ETW provider enumeration (pre-attack recon)",  FALSE },
				{ L"logman query",              "logman query — ETW trace session enumeration (pre-attack recon)",      FALSE },
				{ L"logman -ets",               "logman -ets — real-time ETW/WPP session manipulation (T1562.002)",   TRUE  },
				{ L"logman start",              "logman start — ETW/WPP trace session creation (T1562.002)",          FALSE },
				{ L"logman create",             "logman create — persistent ETW/WPP data collector creation (T1562.002 rogue session persistence)", TRUE },
				{ L"logman import",             "logman import — import ETW session config from XML (T1562.002 portable session attack)", TRUE },
				{ L"logman export",             "logman export — export ETW session config to XML (recon/portability)", FALSE },
				// logman dangerous flags — these are combined with create/start/update
				{ L" -nb ",                     "logman -nb — custom min/max buffer count (buffer exhaustion T1562.002)", TRUE },
				{ L" -bs ",                     "logman -bs — custom buffer size (buffer manipulation T1562.002)",       FALSE },
				{ L" -rt",                      "logman -rt — real-time session mode (consumer attachment T1562.002)",   FALSE },
				{ L" -ct ",                     "logman -ct — clock type override (InfinityHook-adjacent T1562.002)",   TRUE  },
				{ L" -p {",                     "logman -p {GUID} — explicit provider GUID targeting (T1562.002)",     TRUE  },
				{ L" -p \"",                    "logman -p \"GUID\" — explicit provider GUID targeting (T1562.002)",   TRUE  },
				{ L"trace-command",             "Trace-Command — PowerShell tracing/ETW recon",                        FALSE },
				// TraceLogging / TDH provider enumeration — pre-attack recon
				{ L"logman query providers",    "logman query providers — enumerate all ETW/TraceLogging provider GUIDs (recon)", FALSE },
				{ L"logman query -ets",         "logman query -ets — enumerate running ETW/TraceLogging sessions (recon)",       FALSE },
				// TdhEnumerateProviders is a user-mode API — no cmd pattern, but tools that
				// wrap it are detectable via process name (covered in WPP tool table).
				// PowerShell .NET wrapper for TDH enumeration
				{ L"tdhenumerateproviders",     "TdhEnumerateProviders — .NET/P-Invoke ETW provider enumeration (recon)", FALSE },
				{ L"get-tracelogging",          "Get-TraceLogging* — TraceLogging provider enumeration (recon)",          FALSE },

				// --- T1518.001: Security software discovery ---
				// Attackers enumerate installed EDR/AV before evasion attempts.
				{ L"sc query windefend",        "sc query windefend — Defender service status recon",                   FALSE },
				{ L"sc qc windefend",           "sc qc windefend — Defender service config recon",                     FALSE },
				{ L"sc query sense",            "sc query sense — Defender ATP sensor recon",                          FALSE },
				{ L"fltmc",                     "fltmc — bare minifilter enumeration (EDR discovery)",                 FALSE },
				{ L"driverquery",               "driverquery — kernel driver enumeration (EDR/AV driver discovery)",   FALSE },
				{ L"tasklist /svc",             "tasklist /svc — service-to-process mapping (EDR process discovery)",  FALSE },

				// --- T1136.001: Local Account Creation ---
				{ L"net user /add",             "net user /add — local account creation (T1136.001)",                 TRUE  },
				{ L"net1 user /add",            "net1 user /add — local account creation via net1 (T1136.001)",      TRUE  },
				{ L"net user /ad",              "net user /ad — local account creation (abbreviated T1136.001)",      TRUE  },
				{ L"new-localuser",             "New-LocalUser — PowerShell local account creation (T1136.001)",     TRUE  },
				{ L"new-localgroup",            "New-LocalGroup — PowerShell local group creation (T1136.001)",      TRUE  },
				{ L"add-localgroupmember",      "Add-LocalGroupMember — PowerShell group membership add (T1136.001)", TRUE },
				{ L"net localgroup administrators", "net localgroup administrators /add — admin group add (T1136.001)", TRUE },
				// Hidden account creation ($ suffix hides from net user listing)
				{ L"net user /add $",           "net user /add $ — hidden account creation (T1136.001 evasion)",     TRUE  },

				// --- T1078.003: Valid Accounts / Lateral Movement via local creds ---
				{ L"runas /user:",              "runas /user: — execution as alternate local account (T1078.003)",    TRUE  },
				{ L"runas /netonly",            "runas /netonly — network-only impersonation (T1078.003)",            TRUE  },
				{ L"runas /savecred",           "runas /savecred — cached credential reuse (T1078.003)",             TRUE  },

				// --- T1124: System Time Discovery ---
				{ L"w32tm /query",              "w32tm /query — time service query (T1124 time discovery)",          FALSE },
				{ L"w32tm /stripchart",         "w32tm /stripchart — time offset measurement (T1124)",              FALSE },
				{ L"net time",                  "net time — domain/remote time query (T1124 time discovery)",        FALSE },
				{ L"get-date",                  "Get-Date — PowerShell time query (T1124 time discovery)",          FALSE },

				// --- T1087.001: Local Account Discovery ---
				{ L"net user",                  "net user — local account enumeration (T1087.001)",                  FALSE },
				{ L"net1 user",                 "net1 user — local account enumeration via net1 (T1087.001)",       FALSE },
				{ L"get-localuser",             "Get-LocalUser — PowerShell local account enumeration (T1087.001)", FALSE },
				{ L"get-localgroupmember",      "Get-LocalGroupMember — local group member enum (T1087.001)",       FALSE },
				{ L"wmic useraccount",          "wmic useraccount — WMI local account enumeration (T1087.001)",    FALSE },
				{ L"get-wmiobject win32_useraccount", "Get-WmiObject Win32_UserAccount — WMI user enum (T1087.001)", FALSE },

				// --- T1560.001: Archive via Utility (data staging/exfil prep) ---
				{ L"7z.exe a ",                 "7z archive creation — data staging for exfiltration (T1560.001)",   TRUE  },
				{ L"7za.exe a ",                "7za standalone archive creation (T1560.001)",                       TRUE  },
				{ L"rar.exe a ",                "rar archive creation — data staging (T1560.001)",                   TRUE  },
				{ L"winrar.exe a ",             "WinRAR archive creation (T1560.001)",                              TRUE  },
				{ L"makecab ",                  "makecab — Cabinet archive creation (T1560.001 staging)",           FALSE },
				{ L"compact /c",                "compact /c — NTFS compression (T1560.001 evasion variant)",       FALSE },
				{ L"tar -c",                    "tar -cf — tar archive creation (T1560.001 staging)",               FALSE },
				{ L"compress-archive",          "Compress-Archive — PowerShell ZIP creation (T1560.001)",           TRUE  },
				{ L"io.compression.zipfile",    "[IO.Compression.ZipFile] — .NET ZIP creation (T1560.001)",        TRUE  },

				// --- T1027: Obfuscated Files / Encoding (partial gap) ---
				{ L"certutil -encode",          "certutil -encode — Base64 file encoding (T1027 obfuscation)",      TRUE  },
				{ L"certutil /encode",          "certutil /encode — Base64 file encoding variant (T1027)",          TRUE  },
				{ L"certutil -decodehex",       "certutil -decodehex — hex decoding (T1027/T1140)",                TRUE  },
				{ L"certutil /decodehex",       "certutil /decodehex — hex decoding variant (T1027)",              TRUE  },
				{ L"-nop -w hidden -e",         "PowerShell -nop -w hidden -e — obfuscated stager (T1027)",        TRUE  },
				// PowerShell Empire launcher signatures
				{ L"-noni -nop -w hidden",      "PowerShell -NonInteractive -NoProfile -WindowStyle Hidden — classic Empire launcher prologue", TRUE  },
				{ L"-noni -w hidden -e",        "PowerShell -NonInteractive -WindowStyle Hidden -EncodedCommand — Empire stager shape",          TRUE  },
				{ L"\\syswow64\\windowspowershell", "WoW64 PowerShell redirection — Empire launcher targets 32-bit PS for AMSI-bypass-on-old-hosts", TRUE },
				{ L"/s /c powershell -nop",     "cmd /s /c powershell -nop — Empire bat launcher wrapper",                                         TRUE  },

				// --- Extended LOLBAS coverage (T1218 Signed Binary Proxy Execution) ---
				{ L"pubprn.vbs",                "pubprn.vbs — signed-script proxy exec LOLBAS (T1216.002)",                                        TRUE  },
				{ L"syncappvpublishingserver",  "SyncAppvPublishingServer proxy-exec — PowerShell launch via AppV publishing helper",              TRUE  },
				{ L"cl_invocation.ps1",         "cl_invocation.ps1 — signed-script LOLBAS for script execution proxy",                             TRUE  },
				{ L"cl_mutexverifiers.ps1",     "cl_mutexverifiers.ps1 — signed-script LOLBAS for PS payload proxy",                               TRUE  },
				{ L"manage-bde.wsf",            "manage-bde.wsf — signed-script LOLBAS (T1216.002 proxy execution)",                               TRUE  },
				{ L"pester.bat",                "Pester.bat LOLBAS — arbitrary command exec via test harness",                                      TRUE  },

				// Signed-binary proxy exec (T1218)
				{ L"mavinject.exe",             "mavinject.exe — DLL injection via AppV bootstrapper (T1218.013)",                                 TRUE  },
				{ L"atbroker.exe",              "atbroker.exe — accessibility-tool launcher, GUI-less exec primitive",                             TRUE  },
				{ L"scriptrunner.exe",          "ScriptRunner.exe LOLBAS — arbitrary script/exec proxy",                                            TRUE  },
				{ L"presentationhost.exe",      "PresentationHost.exe — XBAP exec LOLBAS (T1218)",                                                   TRUE  },
				{ L"ieexec.exe",                "IEExec.exe — .NET-via-IE LOLBAS for remote binary execution (T1218)",                              TRUE  },
				{ L"ie4uinit.exe -basesettings","ie4uinit.exe -BaseSettings — proxy-exec LOLBAS pattern",                                            TRUE  },
				{ L"cdb.exe -cf",               "cdb.exe -cf — Windows debugger command-file exec (payload via debugger)",                         TRUE  },
				{ L"wsl.exe -e",                "wsl.exe -e — arbitrary-exec via WSL1/2 (T1202 indirect cmd exec)",                                 TRUE  },
				{ L"wsl.exe --exec",            "wsl.exe --exec variant",                                                                            TRUE  },
				{ L"dnscmd.exe",                "dnscmd.exe — potential ServerLevelPluginDll DLL-load abuse on DNS server",                         FALSE },
				{ L"/serverlevelplugindll",     "dnscmd /ServerLevelPluginDll — load attacker DLL in dns.exe (T1574)",                              TRUE  },
				{ L"print.exe /d:\\\\",          "print.exe /D:\\\\ — WebDAV file copy LOLBAS (T1105)",                                             TRUE  },
				{ L"finger.exe",                "finger.exe — rare binary used as ingress-tool transfer proxy (T1105)",                            TRUE  },
				{ L"wt.exe -- ",                "wt.exe -- — Windows Terminal command proxy-exec (T1202)",                                          TRUE  },
				{ L"wt.exe new-tab",            "wt.exe new-tab — Terminal profile-based exec primitive",                                            TRUE  },
				{ L"diskshadow.exe /s",         "diskshadow.exe /s — script-mode VSS abuse (shadow mount + exfil)",                                 TRUE  },
				{ L"ftp.exe -s:",               "ftp.exe -s: — script-mode FTP command LOLBAS (T1105 ingress)",                                    TRUE  },

				// msbuild XML-inline code execution (T1127.001)
				{ L"msbuild.exe ",              "msbuild.exe — possible C#-via-XML inline task exec (T1127.001)",                                  FALSE },
				{ L".xml -nologo",              "msbuild -nologo with .xml project — inline task exec (T1127.001)",                                 TRUE  },
				{ L".csproj -nologo",           "msbuild inline .csproj exec",                                                                       TRUE  },
				{ L"<usingtask",                "MSBuild UsingTask inline-task signature in cmdline (T1127.001)",                                    TRUE  },

				// regsvcs/regasm COM-registration exec (T1218.009/.010)
				{ L"regsvcs.exe",               "regsvcs.exe — .NET COM+ registration exec LOLBAS (T1218.009)",                                     TRUE  },
				{ L"regasm.exe /u",             "regasm.exe /u — .NET assembly unregistration proxy exec (T1218.010)",                              TRUE  },

				// WMI + COM proxy execution
				{ L"xwizard.exe runwizard",     "xwizard.exe RunWizard — COM proxy exec LOLBAS",                                                    TRUE  },
				{ L"verclsid.exe /s /c",        "verclsid.exe /S /C — COM class verifier proxy exec",                                               TRUE  },
				{ L"odbcconf.exe /a",           "odbcconf.exe /A — DLL loader LOLBAS (REGSVR / CONFIGDRIVER)",                                      TRUE  },
				{ L"configsysdsn",              "odbcconf ConfigSysDsn — driver DLL load from attacker path",                                        TRUE  },
				{ L"cmstp.exe /s ",             "cmstp.exe /s — INF-based proxy exec + UAC bypass (T1218.003)",                                     TRUE  },
				{ L"cmstp.exe /au ",            "cmstp.exe /au — INF-driven auto-install exec path",                                                 TRUE  },

				// LOLScript launches (extension-based)
				{ L"wscript.exe //e:vbscript ", "wscript //E:VBScript — script-host override launcher (T1059.005)",                                 FALSE },
				{ L"cscript.exe //nologo ",     "cscript //NoLogo — scripted-task launcher signature",                                               FALSE },
				{ L"mshta.exe http",            "mshta.exe http(s):// — remote HTA exec (T1218.005)",                                               TRUE  },
				{ L"mshta.exe javascript:",     "mshta.exe javascript: — inline JS exec via HTA engine (T1218.005)",                                TRUE  },
				{ L"mshta.exe vbscript:",       "mshta.exe vbscript: — inline VBS exec via HTA engine",                                              TRUE  },

				// Signed-script proxy exec (T1216) — developer command-line tools
				{ L"winrm.vbs -r:",             "winrm.vbs -r: — WinRM command-proxy LOLBAS",                                                        TRUE  },
				{ L"slmgr.vbs",                 "slmgr.vbs — WMI-host script-invocation primitive",                                                 FALSE },
				{ L"gpscript.exe",              "gpscript.exe — Group Policy script runner proxy-exec LOLBAS",                                      TRUE  },

				// LOLBin-loads-DLL-from-userwritable (Side-Loading T1574.002 tells)
				{ L"rundll32.exe ,",            "rundll32 <dll>,<ordinal> with no dll path — abuses search-order (T1574.002)",                     FALSE },
				{ L"rundll32 javascript:",      "rundll32 javascript: mshtml,RunHTMLApplication — Poweliks pattern (T1218.011)",                   TRUE  },
				{ L"url.dll,fileprotocolhandler", "rundll32 url.dll,FileProtocolHandler — remote-URL handler exec",                                 TRUE  },
				{ L"shell32.dll,shellexec_rundll", "rundll32 shell32.dll,ShellExec_RunDLL — chained exec primitive",                                TRUE  },
				{ L"zipfldr.dll,routethecall",  "rundll32 zipfldr.dll,RouteTheCall — shell proxy exec LOLBAS",                                      TRUE  },
				{ L"pcwutl.dll,launchapplication", "rundll32 pcwutl.dll,LaunchApplication — app-compat proxy exec",                                 TRUE  },
				{ L"comsvcs.dll,minidump",      "rundll32 comsvcs.dll MiniDump — lsass credential dump LOLBAS (T1003.001)",                         TRUE  },
				{ L"advpack.dll,launchinfsection", "rundll32 advpack.dll,LaunchINFSection — INF-driven exec",                                       TRUE  },
				{ L"setupapi.dll,installhinfsection", "rundll32 setupapi.dll,InstallHinfSection — INF-driven registry write / exec",                TRUE  },
				{ L"ieadvpack.dll,launchinfsection", "rundll32 ieadvpack.dll,LaunchINFSection — IE variant INF proxy exec",                         TRUE  },
				{ L"davclnt.dll,davsetcookie",  "rundll32 davclnt.dll — WebDAV cookie-set payload-fetch primitive",                                  TRUE  },

				// HTML-Help compiled help abuse (T1218.001)
				{ L"hh.exe http",               "hh.exe http(s):// — remote .chm exec (T1218.001)",                                                 TRUE  },
				{ L".chm::",                    ".chm:: — in-CHM script exec URI (HtmlHelp)",                                                       TRUE  },

				// Control panel applet abuse (T1218.002)
				{ L"control.exe ",              "control.exe — .cpl applet exec vector (T1218.002)",                                                FALSE },
				{ L".cpl,",                     ".cpl,@<entry> — CPL applet entry-point exec",                                                      TRUE  },

				// --- Additional base64 obfuscation shapes (T1027 / T1140) ---
				{ L"-e JAB",                    "PowerShell -EncodedCommand starting with UTF-16LE '$' (JAB*) — canonical base64-of-PS header",  TRUE  },
				{ L"-e IAB",                    "PowerShell -EncodedCommand starting with UTF-16LE ' ' (IAB*) — whitespace-prefixed encoded block", TRUE },
				{ L"-e SQBF",                   "PowerShell -EncodedCommand starting with UTF-16LE 'IE' (SQBFAFg) — IEX base64 header",          TRUE  },
				{ L"-encodedcommand jab",       "PowerShell -EncodedCommand JAB* — base64-of-UTF-16 PowerShell variable prefix",                   TRUE  },
				{ L"-encodedcommand sqbf",      "PowerShell -EncodedCommand SQBF* — base64 IEX header",                                            TRUE  },
				{ L"-encodedcommand iab",       "PowerShell -EncodedCommand IAB* — whitespace-prefixed encoded command",                          TRUE  },
				{ L"-encodedcommand cwbl",      "PowerShell -EncodedCommand cwBl* — 'se'-prefixed (Set-/Select-) encoded header",                 FALSE },
				{ L"-encodedcommand abi",       "PowerShell -EncodedCommand AB*I — base64-of-UTF16 'I' prefix",                                   FALSE },
				{ L"certutil -decode",          "certutil -decode — base64-decoded dropper stage (T1140)",                                         TRUE  },
				{ L"certutil -decodehex",       "certutil -decodehex — hex-decoded dropper stage (T1140)",                                         TRUE  },
				{ L"certutil /decode",          "certutil /decode — base64 decode (slash form)",                                                   TRUE  },
				{ L"certutil -f -decode",       "certutil -f -decode — forced base64 decode (dropper)",                                           TRUE  },
				{ L"[convert]::frombase64",     "[Convert]::FromBase64String — inline PS base64 decode",                                          TRUE  },
				{ L"tobase64string(",           "ToBase64String( — PS base64 encode call (outbound exfil staging)",                              FALSE },
				{ L"-e JABw",                   "PowerShell -e JABw — base64-of-UTF16 '$p' (Empire's $powershell variable prefix)",              TRUE  },
				{ L"-e JABj",                   "PowerShell -e JABj — base64-of-UTF16 '$c' (common Empire/CS beacon variable)",                   TRUE  },
				{ L"-e JABh",                   "PowerShell -e JABh — base64-of-UTF16 '$a' (common stager variable)",                            TRUE  },
				{ L"[system.convert]::frombase64string", "[System.Convert]::FromBase64String full form — base64 payload decode",                TRUE  },
				{ L"[text.encoding]::ascii.getstring([convert]::frombase64", "Compact base64→UTF8→IEX decode sandwich",                           TRUE  },

				// Classic CS/Empire stager stub prefix (literal once b64'd)
				{ L"TVqQAAMAAAAEAAAA",          "TVqQAAMAAAAEAAAA — base64 of 'MZ\\x90\\x00\\x03…' (embedded PE header in script/registry)",    TRUE  },
				{ L"TVpQAAIAAAAEAA",            "TVpQAAIAAAAEAA — base64 of DOS 'MZP' PE header variant",                                         TRUE  },
				{ L"UEsDB",                     "UEsDB — base64 of 'PK\\x03\\x04' (ZIP/Office document embedded in script/registry)",            FALSE },
				{ L"[convert]::tobase64",       "[Convert]::ToBase64String — PS Base64 encoding (T1027)",          FALSE },
				{ L"[convert]::frombase64",     "[Convert]::FromBase64String — PS Base64 decoding (T1027/T1140)",  FALSE },

				// --- T1614: System Location Discovery ---
				{ L"get-winhomelocation",       "Get-WinHomeLocation — geographic location query (T1614)",          FALSE },
				{ L"get-timezone",              "Get-TimeZone — timezone query (T1614 location discovery)",         FALSE },
				{ L"tzutil /g",                 "tzutil /g — timezone query (T1614 location discovery)",            FALSE },

				// --- T1489: Service Stop (ransomware pre-encryption service killing) ---
				{ L"taskkill /f /im",           "taskkill /F /IM — force-kill process by name (T1489 service stop)", TRUE },
				{ L"taskkill /im",              "taskkill /IM — kill process by name (T1489 service stop)",         FALSE },
				{ L"taskkill /f /pid",           "taskkill /F /PID — force-kill process by PID (T1489)",            TRUE  },
				{ L"net stop samss",            "net stop samss — AD service stop (T1489 ransomware pre-encrypt)", TRUE  },
				{ L"net stop veeam",            "net stop veeam* — backup service stop (T1489 ransomware)",        TRUE  },
				{ L"net stop sql",              "net stop sql* — SQL service stop (T1489 ransomware)",             TRUE  },
				{ L"net stop mysql",            "net stop mysql — MySQL service stop (T1489 ransomware)",          TRUE  },
				{ L"net stop oracle",           "net stop oracle — Oracle service stop (T1489 ransomware)",        TRUE  },
				{ L"net stop exchange",         "net stop exchange — Exchange service stop (T1489 ransomware)",    TRUE  },
				{ L"net stop backup",           "net stop backup — backup service stop (T1489 ransomware)",        TRUE  },
				{ L"net stop shadow",           "net stop shadow — VSS shadow copy svc stop (T1489/T1490)",        TRUE  },
				{ L"net stop vss",              "net stop vss — VSS service stop (T1489/T1490)",                   TRUE  },
				{ L"net stop sophos",           "net stop sophos — AV/EDR service stop (T1489/T1562.001)",        TRUE  },
				{ L"net stop mba",              "net stop mba* — managed backup service stop (T1489)",            TRUE  },

				// --- T1003.002/004: Credential dumping via reg save ---
				{ L"reg save hklm\\sam",        "reg save SAM — credential hive dump (T1003.002)",                 TRUE  },
				{ L"reg save hklm\\security",   "reg save SECURITY — LSA secrets hive dump (T1003.004)",          TRUE  },
				{ L"reg save hklm\\system",     "reg save SYSTEM — boot key hive dump (T1003.002)",               TRUE  },
				{ L"reg.exe save hklm\\sam",    "reg.exe save SAM — credential hive dump (T1003.002)",            TRUE  },
				{ L"reg.exe save hklm\\security", "reg.exe save SECURITY — LSA secrets dump (T1003.004)",         TRUE  },
				{ L"reg.exe save hklm\\system", "reg.exe save SYSTEM — boot key dump (T1003.002)",               TRUE  },

				// --- T1543.003: Suspicious service creation via sc create ---
				{ L"sc create",                 "sc create — new service creation (T1543.003 persistence)",        TRUE  },
				{ L"sc.exe create",             "sc.exe create — new service creation (T1543.003)",                TRUE  },
				{ L"new-service",               "New-Service — PowerShell service creation (T1543.003)",          TRUE  },

				// --- T1016: Network configuration discovery ---
				{ L"net config workstation",    "net config workstation — domain/network config recon (T1016)",    FALSE },
				{ L"net config server",         "net config server — server config recon (T1016)",                 FALSE },

				// --- T1135: Network share discovery ---
				{ L"net share",                 "net share — network share enumeration (T1135)",                    FALSE },
				{ L"net1 share",                "net1 share — network share enumeration (T1135)",                  FALSE },
				{ L"get-smbshare",              "Get-SmbShare — PowerShell share enumeration (T1135)",            FALSE },

				// --- T1070: Anti-forensics ---
				{ L"fsutil usn deletejournal",  "fsutil usn deletejournal — USN journal wipe (T1070.006 anti-forensics)", TRUE },
				{ L"fsutil usn deletejournal /d", "fsutil usn deletejournal /D — full USN wipe (T1070.006)",     TRUE  },

				// --- T1220: XSL Script Processing ---
				{ L"msxsl.exe",                 "msxsl.exe — XSL script processing LOLBin (T1220)",                TRUE  },
				{ L"msxsl ",                    "msxsl — XSL transform execution (T1220)",                         TRUE  },

				// --- T1003/T1218: esentutl LOLBin ---
				{ L"esentutl.exe /y",           "esentutl /y — copy locked file (T1003 cred dump LOLBin)",        TRUE  },
				{ L"esentutl /y",               "esentutl /y — copy locked file bypass (T1003)",                  TRUE  },
				{ L"esentutl.exe /vss",         "esentutl /vss — VSS file copy (T1003 NTDS/SAM exfil)",          TRUE  },
				{ L"esentutl /vss",             "esentutl /vss — VSS-based file copy (T1003)",                    TRUE  },
				{ L"esentutl.exe /p",           "esentutl /p — database repair (T1003 NTDS manipulation)",        FALSE },

				// --- T1057/T1082: Additional recon tools ---
				{ L"qprocess",                  "qprocess — process/session enumeration (T1057 recon)",            FALSE },
				{ L"hostname",                  "hostname — hostname discovery (T1082 system info)",               FALSE },
				{ L"getmac",                    "getmac — MAC address enumeration (T1016 network recon)",         FALSE },

				// --- T1021.006: WinRM lateral movement ---
				{ L"invoke-command -computer",  "Invoke-Command -ComputerName — WinRM remote exec (T1021.006)",   TRUE  },
				{ L"enter-pssession",           "Enter-PSSession — WinRM interactive session (T1021.006)",        TRUE  },
				{ L"new-pssession",             "New-PSSession — WinRM session creation (T1021.006)",             TRUE  },
				{ L"winrm quickconfig",         "winrm quickconfig — enable WinRM (T1021.006 prep)",              TRUE  },
				{ L"enable-psremoting",         "Enable-PSRemoting — enable PS remoting (T1021.006 prep)",        TRUE  },

				// --- T1003.001/006/008: Credential dumping tools (Tanium gap: 47 undetected, 97.9% miss rate) ---
				{ L"mimikatz",                  "mimikatz execution — pass-the-hash/ticket credential dumping (T1003.008)", TRUE },
				{ L".exe sekurlsa",             "mimikatz sekurlsa module — LSASS credential extraction (T1003.008)", TRUE },
				{ L"sekurlsa::logonpasswords",  "mimikatz logonpasswords — plaintext credential dump (T1003.008)",   TRUE },
				{ L"sekurlsa::minidump",        "mimikatz minidump — LSASS dump for offline parsing (T1003.008)",    TRUE },
				{ L"lsadump::sam",              "mimikatz lsadump::sam — SAM credential dump (T1003.002)",           TRUE },
				{ L"lsadump::lsa",              "mimikatz lsadump::lsa — LSA secrets dump (T1003.004)",              TRUE },
				{ L"token::elevate",            "mimikatz token::elevate — token privilege escalation (T1134.003)",   TRUE },
				{ L"lazagne",                   "Lazagne credential dumper — browser/email password extraction (T1555)", TRUE },
				{ L"procdump",                  "procdump LSASS — process memory dump utility (T1003.001)",           TRUE },
				{ L"procdump.exe -ma lsass",    "procdump LSASS dump — credential extraction (T1003.001)",           TRUE },
				{ L"/Y /U /MI lsass",           "comsvcs.exe MiniDump — LSASS dump via COM marshaller (T1003.001)",  TRUE },
				{ L"rundll32 comsvcs.dll MiniDump", "rundll32 comsvcs MiniDump — LSASS dump (T1003.001)",          TRUE },
				{ L"ntdsutil.exe ifm",          "ntdsutil IFM — NTDS database snapshot (T1003.003 domain cred dump)", TRUE },
				{ L"invoke-mimikatz",           "Invoke-Mimikatz — PowerShell wrapper for mimikatz (T1003.008)",      TRUE },
				{ L"invoke-ninjacopy",          "Invoke-NinjaCopy — undetected LSASS dump (T1003.001)",              TRUE },
				{ L"get-clipboardtext",         "Get-ClipboardText — clipboard credential harvesting (T1115)",       FALSE },

				// --- T1574.001: DLL side-loading via process injection (Tanium gap: 135 undetected, 94.9% miss rate) ---
				{ L"reflectivepe",              "ReflectivePEInjection — in-memory PE loading (T1574.001)",           TRUE },
				{ L"hollowprocessinjection",    "HollowProcessInjection — process hollowing (T1055.012)",            TRUE },
				{ L"writeprocmem",              "WriteProcessMemory usage pattern — cross-process memory write (T1055)", FALSE },
				{ L"createremotethread",        "CreateRemoteThread pattern — thread injection (T1055.001)",         FALSE },
				{ L"queueuserapc",              "QueueUserAPC pattern — async injection callback (T1055.004)",       FALSE },
				{ L"rtlfillmemory",             "RtlFillMemory callback injection — async code execution (T1055)", FALSE },
				{ L"createthreadpoolwait",      "CreateThreadPoolWait callback injection — threadpool callback exec (T1055)", FALSE },

				// --- T1070.002: Clear command history / Obfuscation (Tanium gap: 42 undetected, 87.5% miss rate) ---
				{ L"clear-history",             "Clear-History — PowerShell command history wipe (T1070.002)",       TRUE },
				{ L"remove-item (get-psreadlineoptionhistorysavepath)", "Remove PSReadline history — PS history file deletion (T1070.002)", TRUE },
				{ L"set-psreadlineoption -historysavesstyle saveinnothing", "Disable PSReadline history — block future history recording (T1070.002)", TRUE },

				// --- T1052: Exfiltration via removable media / Named pipes (Tanium gap: 68 undetected, 91.9% miss rate) ---
				{ L"\\\\?\\pipe\\lsass",        "LSASS named pipe access — credential dumping C2 channel (T1055/C2)", TRUE },
				{ L"\\\\?\\pipe\\msagent",      "CobaltStrike default named pipe (msagent_*) — C2 communication (T1571)", TRUE },
				{ L"\\\\?\\pipe\\mojo",         "Mojo named pipe — potential C2 framework (T1571)",                   FALSE },
				{ L"\\\\?\\pipe\\status_*",     "CobaltStrike status pipe — C2 internal communication (T1571)",       TRUE },
				{ L"wmic /node:\\\\",           "WMIC remote code execution — lateral movement C2 (T1047)",           TRUE },

				// --- T1518.001 / T1087: Additional recon patterns (Tanium gap: various recon attacks undetected) ---
				{ L"adfind",                    "Adfind — AD reconnaissance tool (T1087.002 domain enum)",           TRUE },
				{ L"ldaputility",               "ldaputility — LDAP AD enumeration (T1087.002 domain enum)",        TRUE },
				{ L"bloodhound",                "BloodHound — AD exploitation path finder (T1087.002 domain enum)",  TRUE },
				{ L"sharpmapexec",              "SharpMapExec — credential reuse exploitation tool (T1021.006)",    TRUE },
				{ L"get-computerinfo",          "Get-ComputerInfo — extended system enumeration (T1082 recon)",    FALSE },
				{ L"systeminfo.exe",            "systeminfo — system configuration enumeration (T1082 recon)",      FALSE },

				// --- T1059/T1036: Encoded/obfuscated execution (Tanium gap: 42 undetected obfuscation variants) ---
				{ L"iex(new-object",            "IEX + DownloadString — download+execute pattern (T1059.001)",      TRUE },
				{ L"sal",                       "Set-Alias PowerShell abbreviation — command obfuscation (T1027)",  FALSE },
				{ L"gcm",                       "Get-Command abbreviation — command enumeration obfuscation (T1027)", FALSE },
				{ L"iwr",                       "Invoke-WebRequest abbreviation — download obfuscation (T1027)",     FALSE },
				{ L"@('",                       "PowerShell char array obfuscation — T1027/T1036 evasion",           FALSE },
				{ L"join(",                     "PowerShell join() obfuscation — T1027/T1036 evasion",              FALSE },

				// --- T1562.002: ETW environment variable bypass ---
				// Attacker sets COMPlus_ETWEnabled=0 / DOTNET_ETWEnabled=0 before
				// launching .NET payloads — CLR reads these at startup and permanently
				// disables all .NET ETW providers in that process.  Pattern: cmd /c
				// "set COMPlus_ETWEnabled=0 && payload.exe" or PowerShell $env:.
				{ L"complus_etwenabled=0",      "COMPlus_ETWEnabled=0 — CLR ETW providers DISABLED, .NET telemetry blind (T1562.002)", TRUE },
				{ L"dotnet_etwenabled=0",       "DOTNET_ETWEnabled=0 — .NET 6+ ETW providers DISABLED (T1562.002)",  TRUE },
				{ L"complus_etwflags=0",        "COMPlus_ETWFlags=0 — CLR ETW keyword mask zeroed, all events filtered (T1562.002)", TRUE },
				{ L"complus_enableeventlog=0",  "COMPlus_EnableEventLog=0 — CLR event log writing disabled (T1562.002)", TRUE },
				// PowerShell $env: variants for setting these env vars
				{ L"$env:complus_etwenabled",   "$env:COMPlus_ETWEnabled — PowerShell CLR ETW disable (T1562.002)",  TRUE },
				{ L"$env:dotnet_etwenabled",    "$env:DOTNET_ETWEnabled — PowerShell .NET 6+ ETW disable (T1562.002)", TRUE },
				{ L"$env:complus_etwflags",     "$env:COMPlus_ETWFlags — PowerShell CLR keyword mask zeroing (T1562.002)", TRUE },
				// SetEnvironmentVariable API call patterns in PowerShell
				{ L"setenvironmentvariable(\"complus_etw", "SetEnvironmentVariable(COMPlus_ETW*) — API-based CLR ETW disable (T1562.002)", TRUE },
				{ L"setenvironmentvariable(\"dotnet_etw",  "SetEnvironmentVariable(DOTNET_ETW*) — API-based .NET 6+ ETW disable (T1562.002)", TRUE },

				// --- T1059.001: PowerShell Constrained Language Mode bypass ---
				{ L"languagemode",              "LanguageMode reference — potential CLM bypass probe (T1059.001)",              FALSE },
				{ L"fulllanguage",              "FullLanguage mode set — CLM bypass restoring unrestricted PS (T1059.001)",    TRUE  },
				{ L"$executioncontext.sessionstate.languagemode", "$ExecutionContext.SessionState.LanguageMode — CLM bypass (T1059.001)", TRUE },
				{ L"constrainedlanguage",       "ConstrainedLanguage reference — CLM bypass recon/set (T1059.001)",            TRUE  },

				// --- T1059.001: PowerShell downgrade attack (v2 lacks AMSI) ---
				{ L"powershell -version 2",     "PowerShell -Version 2 downgrade — bypasses AMSI/ScriptBlock logging (T1059.001)", TRUE },
				{ L"powershell.exe -version 2", "PowerShell.exe -Version 2 downgrade — bypasses AMSI (T1059.001)",            TRUE  },
				{ L"powershell -v 2",           "PowerShell -v 2 downgrade — bypasses AMSI (T1059.001)",                       TRUE  },
				{ L"powershell.exe -v 2",       "PowerShell.exe -v 2 downgrade — bypasses AMSI (T1059.001)",                  TRUE  },
				{ L"-version 2.0",              "PowerShell -Version 2.0 downgrade — bypasses AMSI (T1059.001)",               TRUE  },

				// --- T1059.001: Add-Type C# compilation (arbitrary P/Invoke) ---
				{ L"add-type -typedefinition",  "Add-Type -TypeDefinition — inline C# compilation (T1059.001)",                TRUE  },
				{ L"add-type -memberdefinition","Add-Type -MemberDefinition — inline P/Invoke definition (T1059.001)",         TRUE  },
				{ L"add-type -assemblyname",    "Add-Type -AssemblyName — .NET assembly load (T1059.001)",                     FALSE },
				{ L"add-type -path",            "Add-Type -Path — C# file compilation (T1059.001)",                            FALSE },
				{ L"[dllimport(",               "[DllImport( — P/Invoke declaration in PS Add-Type (T1059.001)",               TRUE  },

				// --- T1059.001: Reflection / Marshal interop ---
				{ L"[system.runtime.interopservices.marshal]::", "System.Runtime.InteropServices.Marshal — memory manipulation (T1059.001)", TRUE },
				{ L"getdelegateforfunctionpointer", "GetDelegateForFunctionPointer — native function call from managed code",  TRUE  },
				{ L"allochglobal",              "Marshal.AllocHGlobal — unmanaged memory allocation from PS",                  TRUE  },
				{ L"structuretoptr",            "Marshal.StructureToPtr — managed-to-native struct marshal",                   TRUE  },

				// --- T1546.003: WMI event subscription persistence (PS cmdlets) ---
				{ L"register-wmievent",         "Register-WmiEvent — WMI event subscription persistence (T1546.003)",          TRUE  },
				{ L"set-wmiinstance",           "Set-WmiInstance — WMI instance creation/persistence (T1546.003)",             TRUE  },
				{ L"__eventfilter",             "__EventFilter — WMI event filter (T1546.003)",                                TRUE  },
				{ L"__eventconsumer",           "__EventConsumer — WMI event consumer (T1546.003)",                            TRUE  },
				{ L"commandlineeventconsumer",  "CommandLineEventConsumer — WMI command exec on event (T1546.003)",            TRUE  },
				{ L"activescripteventconsumer", "ActiveScriptEventConsumer — WMI script exec on event (T1546.003)",            TRUE  },
				{ L"__filtertoconsumerbinding", "__FilterToConsumerBinding — WMI persistence binding (T1546.003)",             TRUE  },

				// --- T1546.013: PowerShell profile persistence ---
				{ L"$profile",                  "$PROFILE — PowerShell profile reference (T1546.013 persistence)",             FALSE },
				{ L"profile.ps1",               "profile.ps1 — PowerShell profile file (T1546.013 persistence)",               TRUE  },
				{ L"microsoft.powershell_profile.ps1", "Microsoft.PowerShell_profile.ps1 — all-users PS profile (T1546.013)", TRUE  },
				{ L"microsoft.powershellise_profile.ps1", "Microsoft.PowerShellISE_profile.ps1 — ISE profile (T1546.013)",    TRUE  },
				{ L"set-content $profile",      "Set-Content $PROFILE — PS profile write / backdoor (T1546.013)",              TRUE  },
				{ L"add-content $profile",      "Add-Content $PROFILE — PS profile append / backdoor (T1546.013)",             TRUE  },

				// --- T1059.001: Alternate PowerShell hosts ---
				{ L"powershell_ise.exe",        "PowerShell ISE — alternate PS host (T1059.001)",                              FALSE },
				{ L"system.management.automation.dll", "System.Management.Automation.dll — PS runtime loaded by non-PS host (T1059.001)", TRUE },

				// --- T1555 / T1552: Credential access PowerShell cmdlets ---
				{ L"get-credential",            "Get-Credential — interactive credential prompt (T1552)",                       FALSE },
				{ L"convertto-securestring",    "ConvertTo-SecureString — credential handling (T1552)",                        FALSE },
				{ L"convertfrom-securestring",  "ConvertFrom-SecureString — credential extraction (T1552)",                    TRUE  },
				{ L"[net.networkcredential]",   "[Net.NetworkCredential] — credential extraction from SecureString (T1552)",   TRUE  },
				{ L"cmdkey /add",               "cmdkey /add — stored credential creation (T1555.004)",                        TRUE  },
				{ L"cmdkey /list",              "cmdkey /list — stored credential enumeration (T1555.004)",                    FALSE },
				{ L"vaultcmd /listcreds",       "vaultcmd /listcreds — Windows Vault credential extraction (T1555.004)",      TRUE  },
				{ L"vaultcmd /listproperties",  "vaultcmd /listproperties — Windows Vault credential recon (T1555.004)",      TRUE  },
				{ L"dpapi::masterkey",          "DPAPI MasterKey — Mimikatz DPAPI credential decryption (T1555.001)",         TRUE  },
				{ L"dpapi::cred",               "DPAPI Cred — Mimikatz DPAPI credential extraction (T1555.001)",              TRUE  },

				// --- T1547.001: Registry persistence via PowerShell ---
				{ L"set-itemproperty",          "Set-ItemProperty — registry value set (potential persistence T1547.001)",     FALSE },
				{ L"new-itemproperty",          "New-ItemProperty — registry value create (potential persistence T1547.001)",  FALSE },
				{ L"currentversion\\run",       "CurrentVersion\\Run — autorun registry path (T1547.001)",                     TRUE  },
				{ L"currentversion\\runonce",   "CurrentVersion\\RunOnce — autorun registry path (T1547.001)",                TRUE  },
				{ L"currentversion\\winlogon",  "CurrentVersion\\Winlogon — Winlogon persistence (T1547.004)",                TRUE  },
				{ L"\\environment\\userinitmprlogonscript", "UserInitMprLogonScript — logon script persistence (T1037.001)",   TRUE  },

				// --- T1053.005: Scheduled task creation via PowerShell ---
				{ L"register-scheduledtask",    "Register-ScheduledTask — PS scheduled task creation (T1053.005)",             TRUE  },
				{ L"new-scheduledtaskaction",   "New-ScheduledTaskAction — PS scheduled task action (T1053.005)",              TRUE  },
				{ L"new-scheduledtasktrigger",  "New-ScheduledTaskTrigger — PS scheduled task trigger (T1053.005)",            TRUE  },
				{ L"new-scheduledtasksettingsset", "New-ScheduledTaskSettingsSet — PS scheduled task settings (T1053.005)",    FALSE },
				{ L"schtasks /create",          "schtasks /create — scheduled task creation (T1053.005)",                      TRUE  },
				{ L"schtasks.exe /create",      "schtasks.exe /create — scheduled task creation (T1053.005)",                  TRUE  },
				{ L"schtasks /change",          "schtasks /change — scheduled task modification (T1053.005)",                  TRUE  },

				// --- T1562.001: PS logging evasion (registry-based) ---
				{ L"$env:psmoduleanalysiscachepath", "$env:PSModuleAnalysisCachePath — module analysis cache redirect (T1562.001)", TRUE },
				{ L"psmoduleanalysiscachepath", "PSModuleAnalysisCachePath — module analysis cache redirect (T1562.001)",      TRUE  },
				{ L"scriptblocklogging",        "ScriptBlockLogging — PS logging policy reference (T1562.001)",                TRUE  },
				{ L"enablescriptblocklogging",  "EnableScriptBlockLogging — PS ScriptBlock logging policy (T1562.001)",        TRUE  },
				{ L"enablescriptblockinvocationlogging", "EnableScriptBlockInvocationLogging — PS invocation logging policy",  TRUE  },

				// =====================================================================
				// .NET malware techniques (T1218 / T1059.001 / T1055 / T1027.004)
				// =====================================================================

				// --- Unmanaged CLR hosting — load CLR into native process (T1218) ---
				{ L"clrcreateinstance",         "CLRCreateInstance — unmanaged CLR hosting (T1218)",                            TRUE  },
				{ L"corbindtoruntimeex",        "CorBindToRuntimeEx — legacy unmanaged CLR hosting (T1218)",                   TRUE  },
				{ L"iclrruntimehost",           "ICLRRuntimeHost — unmanaged CLR execute-assembly (T1218)",                    TRUE  },
				{ L"executeindefaultappdomain",  "ExecuteInDefaultAppDomain — CLR host code execution (T1218)",                TRUE  },
				{ L"icorruntimehost",           "ICorRuntimeHost — legacy CLR hosting interface (T1218)",                      TRUE  },
				{ L"clrruntimehost",            "CLRRuntimeHost — unmanaged CLR hosting class (T1218)",                        TRUE  },
				{ L"mscoree.dll",               "mscoree.dll — CLR shim loader reference (T1218)",                             FALSE },

				// --- .NET LOLBin abuse (T1218) ---
				{ L"regsvcs.exe",               "RegSvcs.exe — .NET LOLBin (T1218.009)",                                      TRUE  },
				{ L"regsvcs /u",                "RegSvcs /U unregister — .NET LOLBin abuse (T1218.009)",                       TRUE  },
				{ L"regasm.exe",                "RegAsm.exe — .NET COM registration LOLBin (T1218.009)",                       TRUE  },
				{ L"regasm /u",                 "RegAsm /U unregister — .NET LOLBin abuse (T1218.009)",                        TRUE  },
				{ L"installutil /logfile= /logtoconsole=false", "InstallUtil silent exec — .NET LOLBin (T1218.004)",           TRUE  },
				{ L"installutil.exe /logfile= /logtoconsole=false", "InstallUtil.exe silent exec (T1218.004)",                 TRUE  },
				{ L"addinprocess.exe",          "AddInProcess.exe — .NET LOLBin for code execution (T1218)",                   TRUE  },
				{ L"addinprocess32.exe",        "AddInProcess32.exe — .NET LOLBin 32-bit (T1218)",                             TRUE  },
				{ L"addinutil.exe",             "AddInUtil.exe — .NET add-in utility LOLBin (T1218)",                          TRUE  },
				{ L"csc.exe /noconfig /fullpaths", "csc.exe /noconfig — suspicious C# compilation flags (T1027.004)",          TRUE  },
				{ L"vbc.exe /noconfig /fullpaths", "vbc.exe /noconfig — suspicious VB compilation flags (T1027.004)",          TRUE  },

				// --- .NET runtime compilation (T1027.004) ---
				{ L"csharpcodeprovider",        "CSharpCodeProvider — runtime C# compilation (T1027.004)",                     TRUE  },
				{ L"compileassemblyfromsource",  "CompileAssemblyFromSource — runtime code compilation (T1027.004)",            TRUE  },
				{ L"codedomprovider",           "CodeDomProvider — .NET CodeDOM runtime compilation (T1027.004)",              TRUE  },
				{ L"generateinmemory",          "GenerateInMemory — compile assembly to memory only (T1027.004)",              TRUE  },

				// --- .NET dynamic type/IL generation (T1055) ---
				{ L"activator.createinstance",   "Activator.CreateInstance — dynamic .NET type instantiation (T1055)",          TRUE  },
				{ L"system.reflection.emit",    "System.Reflection.Emit — dynamic IL generation (T1055)",                     TRUE  },
				{ L"definemethod",              "DefineMethod — IL method builder (T1055)",                                    FALSE },
				{ L"definetype",                "DefineType — dynamic type builder (T1055)",                                   FALSE },
				{ L"dynamicmethod",             "DynamicMethod — anonymous IL method creation (T1055)",                        TRUE  },
				{ L"ilgenerator",               "ILGenerator — IL instruction emitter (T1055)",                                TRUE  },
				{ L"opcodes.calli",             "OpCodes.Calli — indirect function call via IL (T1055)",                       TRUE  },

				// --- .NET assembly manipulation libraries ---
				{ L"dnlib.dotnet",              "dnlib.DotNet — runtime PE/.NET assembly manipulation",                        TRUE  },
				{ L"mono.cecil",                "Mono.Cecil — runtime PE/.NET assembly manipulation",                          TRUE  },

				// --- .NET GAC hijacking (T1574.001) ---
				{ L"gacutil /i",                "gacutil /i — Global Assembly Cache install (T1574.001)",                       TRUE  },
				{ L"gacutil.exe /i",            "gacutil.exe /i — GAC install (T1574.001)",                                    TRUE  },
				{ L"\\assembly\\gac_msil\\",    "GAC_MSIL path — Global Assembly Cache reference (T1574.001)",                 TRUE  },
				{ L"\\assembly\\gac_64\\",      "GAC_64 path — Global Assembly Cache reference (T1574.001)",                   TRUE  },

				// --- COR_PROFILER .NET hijack env vars (T1574.012) ---
				{ L"cor_enable_profiling=1",    "COR_ENABLE_PROFILING=1 — .NET profiler hijack (T1574.012)",                   TRUE  },
				{ L"cor_profiler=",             "COR_PROFILER= — .NET profiler CLSID hijack (T1574.012)",                      TRUE  },
				{ L"cor_profiler_path=",        "COR_PROFILER_PATH= — .NET profiler DLL path (T1574.012)",                     TRUE  },
				{ L"coreclr_enable_profiling=1", "CORECLR_ENABLE_PROFILING=1 — .NET Core profiler hijack (T1574.012)",         TRUE  },
				{ L"coreclr_profiler=",         "CORECLR_PROFILER= — .NET Core profiler CLSID (T1574.012)",                    TRUE  },

				// --- AppDomainManager injection (T1574.014) ---
				{ L"appdomainmanagerassembly",   "appDomainManagerAssembly — AppDomainManager injection (T1574.014)",           TRUE  },
				{ L"appdomainmanagertype",       "appDomainManagerType — AppDomainManager hijack (T1574.014)",                  TRUE  },

				// --- Donut loader / shellcode .NET signatures ---
				{ L"donut_instance",            "Donut_Instance — Donut shellcode .NET loader",                                TRUE  },
				{ L"module_exe",                "module_exe — Donut module type (in-memory .NET execution)",                    TRUE  },
				{ L"amsi_result_clean",         "AMSI_RESULT_CLEAN — hardcoded AMSI bypass in loader",                         TRUE  },

				// --- TypeConfuseDelegate (T1055) ---
				{ L"typeconfusedelegate",        "TypeConfuseDelegate — .NET type confusion exploit (T1055)",                   TRUE  },

				// --- .NET COM hijacking (T1546.015) ---
				{ L"inprocserver32",            "InProcServer32 — COM in-process server registration (T1546.015)",             FALSE },

				// =====================================================================
				// Malicious JavaScript / Windows Script Host (T1059.007 / T1059.005)
				// =====================================================================

				// --- WSH execution with suspicious flags ---
				{ L"wscript.exe /b /e:jscript", "WScript silent JScript exec — batch mode (T1059.007)",                       TRUE  },
				{ L"cscript.exe /b /e:jscript",  "CScript silent JScript exec — batch mode (T1059.007)",                      TRUE  },
				{ L"wscript.exe /b /e:vbscript", "WScript silent VBScript exec — batch mode (T1059.005)",                     TRUE  },
				{ L"cscript.exe /b /e:vbscript",  "CScript silent VBScript exec — batch mode (T1059.005)",                    TRUE  },
				{ L"wscript //b //e:jscript",    "WScript //B //E:JScript — silent engine override (T1059.007)",              TRUE  },
				{ L"cscript //b //e:jscript",    "CScript //B //E:JScript — silent engine override (T1059.007)",              TRUE  },
				{ L".jse",                       ".jse — JScript.Encode encoded script file (T1059.007)",                      TRUE  },
				{ L".vbe",                       ".vbe — VBScript.Encode encoded script file (T1059.005)",                     TRUE  },
				{ L".wsf",                       ".wsf — Windows Script File polyglot (T1059.007)",                            FALSE },
				{ L".wsh",                       ".wsh — Windows Script Host settings file (T1059.007)",                       FALSE },
				{ L"//e:jscript",                "//E:JScript — WSH engine override to JScript (T1059.007)",                   TRUE  },
				{ L"//e:vbscript",               "//E:VBScript — WSH engine override to VBScript (T1059.005)",                 TRUE  },
				{ L"rundll32 javascript:",        "rundll32 javascript: — inline JS execution via rundll32 (T1218.011)",       TRUE  },

				// --- Node.js abuse (T1059.007) ---
				{ L"node.exe -e",               "node.exe -e — Node.js inline eval execution (T1059.007)",                     TRUE  },
				{ L"node.exe --eval",            "node.exe --eval — Node.js inline eval execution (T1059.007)",                TRUE  },
				{ L"node -e \"",                "node -e — Node.js inline eval execution (T1059.007)",                         TRUE  },
				{ L"node --eval",               "node --eval — Node.js inline eval execution (T1059.007)",                     TRUE  },
				{ L"child_process",             "child_process — Node.js command execution module (T1059.007)",                TRUE  },
				{ L"npm run preinstall",         "npm run preinstall — npm lifecycle hook abuse (T1059.007)",                   TRUE  },
				{ L"npm run postinstall",        "npm run postinstall — npm lifecycle hook abuse (T1059.007)",                  TRUE  },

				// --- JScript.NET / jsc.exe (T1059.007) ---
				{ L"jsc.exe",                   "jsc.exe — JScript.NET compilation LOLBin (T1059.007)",                        TRUE  },
				{ L"jsc /nologo",               "jsc /nologo — JScript.NET silent compilation (T1059.007)",                    TRUE  },

				// --- MSScriptControl (T1059.007) ---
				{ L"msscriptcontrol.scriptcontrol", "MSScriptControl.ScriptControl — COM-based script engine (T1059.007)",     TRUE  },
				{ L"scriptcontrol.language",     "ScriptControl.Language — COM script engine language set (T1059.007)",         TRUE  },

				// --- XSL script processing (T1220) ---
				{ L"wmic /format:",             "WMIC /format: — remote XSL loading (T1220)",                                  TRUE  },
				{ L"wmic os get /format:",      "WMIC os get /format: — XSL execution via WMIC (T1220)",                       TRUE  },
				{ L"wmic process call create",  "WMIC process call create — WMI process creation (T1047)",                     TRUE  },

				// --- JS dropper persistence patterns ---
				{ L"wscript.shell",             "WScript.Shell — COM shell execution object (T1059.007)",                      FALSE },
				{ L"shell.application",         "Shell.Application — COM shell execution (T1059.007)",                         FALSE },
				{ L"schedule.service",          "Schedule.Service — COM task scheduler (T1053.005)",                            TRUE  },
				{ L"shellexecute",              "ShellExecute — COM shell execution method (T1059.007)",                        FALSE },

				// =====================================================================
				// VBScript-specific malware techniques (T1059.005)
				// =====================================================================

				// --- VBScript runtime code execution ---
				{ L"executeglobal",             "ExecuteGlobal — VBScript runtime code execution (T1059.005)",                  TRUE  },
				{ L"execute(",                  "Execute( — VBScript runtime code execution (T1059.005)",                       TRUE  },
				{ L"execute request(",          "Execute Request( — VBScript web shell pattern (T1059.005)",                    TRUE  },
				{ L"getref(",                   "GetRef( — VBScript function pointer creation (T1059.005)",                     TRUE  },

				// --- VBScript obfuscation ---
				{ L"chr(",                      "Chr( — VBScript character code obfuscation (T1027)",                           FALSE },
				{ L"chrw(",                     "Chrw( — VBScript wide character obfuscation (T1027)",                          FALSE },
				{ L"strreverse(",               "StrReverse( — VBScript string reversal deobfuscation (T1027)",                 TRUE  },
				{ L"execute(replace(",          "Execute(Replace( — VBScript deobfuscation chain (T1027)",                      TRUE  },
				{ L"clng(\"&h\"",               "CLng(\"&H\" — VBScript hex decode pattern (T1027)",                            TRUE  },

				// --- VBScript self-reference / self-deletion ---
				{ L"wscript.scriptfullname",    "WScript.ScriptFullName — VBScript self-reference (T1059.005)",                 TRUE  },
				{ L"wscript.scriptname",        "WScript.ScriptName — VBScript self-reference (T1059.005)",                     FALSE },
				{ L"deletefile(wscript.",        "DeleteFile(WScript. — VBScript self-deletion (T1070.004)",                    TRUE  },

				// --- VBScript sandbox evasion ---
				{ L"wscript.sleep",             "WScript.Sleep — VBScript sleep-based sandbox evasion (T1497.003)",             FALSE },
				{ L"wscript.arguments",         "WScript.Arguments — VBScript parameter-driven payload (T1059.005)",            FALSE },

				// --- InternetExplorer.Application COM ---
				{ L"internetexplorer.application", "InternetExplorer.Application — hidden IE COM for HTTP (T1071.001)",         TRUE  },

				// --- DCOM lateral movement ---
				{ L"mmc20.application",         "MMC20.Application — DCOM lateral movement (T1021.003)",                        TRUE  },
				{ L"shellbrowserwindow",        "ShellBrowserWindow — DCOM lateral movement (T1021.003)",                       TRUE  },
				{ L"shellwindows",              "ShellWindows — DCOM lateral movement (T1021.003)",                             TRUE  },

				// --- MSXML2.DOMDocument Base64 decode ---
				{ L"msxml2.domdocument",        "MSXML2.DOMDocument — VBScript Base64 decode via XML transform (T1140)",        TRUE  },
				{ L"nodetypedvalue",            "NodeTypedValue — MSXML2 Base64 decode extraction (T1140)",                     TRUE  },

				// --- VBScript class auto-exec ---
				{ L"class_initialize",          "Class_Initialize — VBScript class auto-execution (T1059.005)",                 TRUE  },
				{ L"class_terminate",           "Class_Terminate — VBScript class cleanup auto-exec (T1059.005)",               TRUE  },

				// =====================================================================
				// VBA macro malware techniques (T1059.005 / T1137)
				// =====================================================================

				// --- VBA callback / delayed execution ---
				{ L"application.ontime",        "Application.OnTime — VBA delayed/callback execution (T1137)",                  TRUE  },
				{ L"application.onkey",         "Application.OnKey — VBA keystroke-triggered execution (T1137)",                 TRUE  },

				// --- VBA anti-analysis ---
				{ L"application.enableevents = false", "Application.EnableEvents=False — VBA event suppression (T1564)",        TRUE  },
				{ L"application.screenupdating = false", "Application.ScreenUpdating=False — VBA UI hiding (T1564)",            TRUE  },
				{ L"application.displayalerts = false", "Application.DisplayAlerts=False — VBA dialog suppression (T1564)",     TRUE  },

				// --- VBA programmatic DDE ---
				{ L"ddeinitiate",               "DDEInitiate — VBA programmatic DDE channel (T1559.002)",                       TRUE  },
				{ L"ddeexecute",                "DDEExecute — VBA DDE command execution (T1559.002)",                           TRUE  },
				{ L"ddepoke",                   "DDEPoke — VBA DDE data injection (T1559.002)",                                 TRUE  },

				// --- VBA self-modification ---
				{ L"vbproject.vbcomponents",    "VBProject.VBComponents — VBA self-modifying code (T1137.001)",                 TRUE  },
				{ L"vbcomponents.add",          "VBComponents.Add — VBA runtime module injection (T1137.001)",                  TRUE  },
				{ L"codemodule.insertlines",    "CodeModule.InsertLines — VBA runtime code injection (T1137.001)",              TRUE  },
				{ L"codemodule.addfrombuffer",   "CodeModule.AddFromBuffer — VBA runtime code load (T1137.001)",                TRUE  },

				// --- VBA keystroke injection ---
				{ L"sendkeys",                  "SendKeys — VBA keystroke injection (T1059.005)",                               TRUE  },

				// --- VBA persistence ---
				{ L"savesetting",               "SaveSetting — VBA registry persistence (T1547.001)",                           TRUE  },
				{ L"getsetting",                "GetSetting — VBA registry read (T1547.001)",                                   FALSE },
				{ L"application.macrooptions",  "Application.MacroOptions — VBA macro UI hiding (T1564)",                       TRUE  },

				// =====================================================================
				// Windows Script Host infrastructure abuse (T1059.005 / T1059.007)
				// =====================================================================

				// --- COM scriptlet (.sct/.wsc) execution ---
				{ L".sct",                      ".sct — COM scriptlet file (T1218.010)",                                        TRUE  },
				{ L".wsc",                      ".wsc — Windows Script Component file (T1218.010)",                             TRUE  },
				{ L"scrobj.dll",                "scrobj.dll — COM scriptlet runtime DLL (T1218.010)",                            TRUE  },
				{ L"regsvr32 /i:",              "regsvr32 /i: — scriptlet registration Squiblydoo (T1218.010)",                 TRUE  },
				{ L"regsvr32.exe /i:",          "regsvr32.exe /i: — scriptlet registration Squiblydoo (T1218.010)",             TRUE  },
				{ L"regsvr32 /s /n /u /i:",     "regsvr32 /s /n /u /i: — Squiblydoo silent scriptlet (T1218.010)",             TRUE  },

				// --- script: moniker (remote/local scriptlet load) ---
				{ L"getobject(\"script:",       "GetObject(\"script: — COM scriptlet moniker load (T1218.010)",                 TRUE  },
				{ L"getobject(\"script:http",   "GetObject(\"script:http — remote scriptlet load (T1218.010)",                  TRUE  },

				// --- WSH remote execution ---
				{ L"wshcontroller",             "WshController — WSH remote script execution (T1021.006)",                      TRUE  },
				{ L"wshremote",                 "WshRemote — WSH remote script object (T1021.006)",                             TRUE  },
				{ L"createscript(",             "CreateScript( — WshController remote script launch (T1021.006)",                TRUE  },
				{ L"wscript.connectobject",     "WScript.ConnectObject — WSH event sink attachment (T1059)",                    TRUE  },
				{ L"wscript.disconnectobject",  "WScript.DisconnectObject — WSH event sink detach (T1059)",                     FALSE },

				// --- WSH flag abuse ---
				{ L"//d ",                      "//D — WSH debugger flag (T1059)",                                              TRUE  },
				{ L"//h:cscript",               "//H:CScript — change default WSH host (T1059)",                                TRUE  },
				{ L"//h:wscript",               "//H:WScript — change default WSH host (T1059)",                                TRUE  },
				{ L"//job:",                    "//Job: — WSF job selection flag (T1059)",                                       TRUE  },
				{ L"//s",                       "//S — save WSH settings as default (T1059)",                                   FALSE },
				{ L"wscript.timeout",           "WScript.Timeout — WSH timeout setting (sandbox evasion T1497)",                TRUE  },

				// --- Remote DCOM instantiation ---
				{ L"getobject(\"new:",          "GetObject(\"new: — DCOM CLSID instantiation (T1021.003)",                      TRUE  },
				{ L"winmgmts:\\\\",             "winmgmts:\\\\ — remote WMI namespace connection (T1047)",                     TRUE  },
				{ L"\\\\root\\cimv2",           "\\\\root\\cimv2 — remote WMI CIMv2 namespace (T1047)",                        TRUE  },

				// --- WSH network / lateral movement ---
				{ L"wscript.network",           "WScript.Network — WSH network enumeration (T1016)",                            FALSE },
				{ L".mapnetworkdrive(",         ".MapNetworkDrive( — WSH network drive mapping (T1021.002)",                    TRUE  },
				{ L".removenetworkdrive(",      ".RemoveNetworkDrive( — WSH network drive removal (T1070)",                     FALSE },

				// --- WSH policy tampering ---
				{ L"\\windows script host\\settings", "Windows Script Host\\Settings — WSH policy registry (T1562)",            TRUE  },
				{ L"trustpolicy",               "TrustPolicy — WSH trust policy setting (T1562)",                               TRUE  },

				// =====================================================================
				// UAC bypass techniques (T1548.002)
				// =====================================================================

				// --- HKCU class handler registry hijack (auto-elevate abuse) ---
				{ L"ms-settings\\shell\\open\\command", "ms-settings handler hijack — UAC bypass (T1548.002)",                  TRUE  },
				{ L"mscfile\\shell\\open\\command",     "mscfile handler hijack — eventvwr UAC bypass (T1548.002)",             TRUE  },
				{ L"exefile\\shell\\open\\command",     "exefile handler hijack — sdclt UAC bypass (T1548.002)",                TRUE  },
				{ L"\\shell\\open\\command",            "Shell\\Open\\command — handler hijack pattern (T1548.002)",            TRUE  },
				{ L"delegateexecute",           "DelegateExecute — UAC bypass delegation value (T1548.002)",                    TRUE  },

				// --- Environment variable UAC bypass ---
				{ L"\\environment\\windir",     "HKCU\\Environment\\windir — env var UAC bypass (T1548.002)",                   TRUE  },
				{ L"\\environment\\systemroot",  "HKCU\\Environment\\systemroot — env var UAC bypass (T1548.002)",              TRUE  },

				// --- COM object UAC bypass CLSIDs ---
				{ L"{3e5fc7f9-9a51-4367-9063-a120244fbec7}", "CMSTPLUA CLSID — COM UAC bypass (T1548.002)",                    TRUE  },
				{ L"{d2e7025f-8b69-4ae6-a3b1-c2bc0f92a3b2}", "ColorDataProxy CLSID — COM UAC bypass (T1548.002)",             TRUE  },
				{ L"cmstplua",                  "CMSTPLUA — COM UAC bypass interface (T1548.002)",                              TRUE  },
				{ L"icmluautil",                "ICMLuaUtil — COM UAC bypass ShellExec method (T1548.002)",                     TRUE  },

				// --- AMSI FeatureBits tamper (T1562.001) ---
				{ L"amsi\\featurebits",         "AMSI\\FeatureBits — AMSI enable/disable registry key (T1562.001)",             TRUE  },
				{ L"\\microsoft\\amsi",         "\\Microsoft\\AMSI — AMSI registry hive reference (T1562.001)",                 TRUE  },

				// --- UAC policy tampering ---
				{ L"enablelua",                 "EnableLUA — UAC disable policy key (T1548.002)",                               TRUE  },
				{ L"consentpromptbehavioradmin", "ConsentPromptBehaviorAdmin — UAC prompt policy (T1548.002)",                  TRUE  },
				{ L"promptonsecuredesktop",     "PromptOnSecureDesktop — UAC secure desktop disable (T1548.002)",              TRUE  },

				// --- DLL hijack for UAC bypass (trusted directory) ---
				{ L"windows \\system32",        "C:\\Windows \\System32 — trailing space trusted directory DLL hijack (T1548.002)", TRUE },
				{ L"sysprep\\",                 "sysprep\\ — UAC DLL hijack target directory (T1548.002)",                      FALSE },

				// --- Token manipulation APIs ---
				{ L"createprocesswithtokenw",    "CreateProcessWithTokenW — token impersonation process create (T1134.001)",    TRUE  },
				{ L"createprocesswithlogonw",    "CreateProcessWithLogonW — logon token process create (T1134.002)",            TRUE  },
				{ L"ntsetinformationtoken",      "NtSetInformationToken — token manipulation (T1134)",                          TRUE  },

				// --- Auto-elevating binary invocation from script ---
				{ L"fodhelper.exe",             "fodhelper.exe — auto-elevating binary invoked from script (T1548.002)",         TRUE  },
				{ L"wsreset.exe",               "wsreset.exe — file-less UAC bypass binary (T1548.002)",                        TRUE  },
				{ L"computerdefaults.exe",      "computerdefaults.exe — auto-elevating binary (T1548.002)",                     TRUE  },
				{ L"changepk.exe",              "changepk.exe — auto-elevating binary (T1548.002)",                             TRUE  },

				// =====================================================================
				// AMSI / Authenticode / code-signing tampering (T1562.001 / T1553)
				// =====================================================================

				// --- AMSI in-memory / DLL tampering ---
				{ L"amsiscanbuffer",            "AmsiScanBuffer — AMSI scan function reference (T1562.001)",                    TRUE  },
				{ L"amsiscanstring",            "AmsiScanString — AMSI scan function reference (T1562.001)",                    TRUE  },
				{ L"amsiopensession",           "AmsiOpenSession — AMSI session function reference (T1562.001)",                TRUE  },
				{ L"amsi.dll",                  "amsi.dll — AMSI runtime DLL reference (T1562.001)",                            TRUE  },
				{ L"amsiinitfailed",            "amsiInitFailed — AMSI context bypass field (T1562.001)",                       TRUE  },
				{ L"amsiclosesession",          "AmsiCloseSession — AMSI session teardown target (T1562.001)",                  TRUE  },
				{ L"amsiuacscan",               "AmsiUacScan — undocumented AMSI UAC scan function (T1562.001)",                TRUE  },

				// --- AMSI reflection bypass (Matt Graeber / rasta-mouse) ---
				{ L"system.management.automation.amsiutils", "System.Management.Automation.AmsiUtils — reflection AMSI bypass target (T1562.001)", TRUE },
				{ L"getfield('amsiinitfailed'",  "GetField('amsiInitFailed') — reflection AMSI bypass (T1562.001)",             TRUE  },
				{ L"getfield(\"amsiinitfailed\"", "GetField(\"amsiInitFailed\") — reflection AMSI bypass (T1562.001)",          TRUE  },
				{ L"getfield('amsicontext'",     "GetField('amsiContext') — reflection AMSI context bypass (T1562.001)",        TRUE  },
				{ L"getfield(\"amsicontext\"",   "GetField(\"amsiContext\") — reflection AMSI context bypass (T1562.001)",      TRUE  },
				{ L"getfield('amsisession'",     "GetField('amsiSession') — reflection AMSI session bypass (T1562.001)",        TRUE  },
				{ L".setvalue($null,$true)",      "SetValue($null,$true) — reflection field flip (T1562.001)",                  TRUE  },
				{ L".setvalue($null, $true)",     "SetValue($null, $true) — reflection field flip (T1562.001)",                 TRUE  },
				{ L"[ref].assembly.gettype",     "[Ref].Assembly.GetType — reflection type lookup (T1562.001)",                 TRUE  },

				// --- AMSI parameter corruption / return forcing ---
				{ L"0x80070057",                "E_INVALIDARG (0x80070057) — AMSI return value forcing (T1562.001)",             TRUE  },
				{ L"amsi_result_clean",         "AMSI_RESULT_CLEAN — AMSI result override constant (T1562.001)",                TRUE  },
				{ L"addvectoredexceptionhandler", "AddVectoredExceptionHandler — VEH for HW breakpoint AMSI bypass (T1562.001)", TRUE },
				{ L"setunhandledexceptionfilter", "SetUnhandledExceptionFilter — alternate exception handler for AMSI bypass (T1562.001)", TRUE },
				{ L"setthreadcontext",          "SetThreadContext — debug register manipulation for AMSI bypass (T1562.001)",    TRUE  },
				{ L"getthreadcontext",          "GetThreadContext — read debug registers for HW BP enumeration (T1562.001)",     TRUE  },
				{ L"ntsetcontextthread",        "NtSetContextThread — direct syscall debug register manipulation (T1562.001)",   TRUE  },
				{ L"ntgetcontextthread",        "NtGetContextThread — direct syscall DR register read (T1562.001)",              TRUE  },
				{ L"ntcontinue",                "NtContinue — exception path debug register installation (T1562.001)",           TRUE  },
				{ L"context_debug_registers",   "CONTEXT_DEBUG_REGISTERS — HW breakpoint context flag (T1562.001)",              TRUE  },
				{ L"exception_single_step",     "EXCEPTION_SINGLE_STEP — HW breakpoint exception code (T1562.001)",              TRUE  },
				{ L"threadhidefromdebugger",    "ThreadHideFromDebugger — anti-debug before HW BP install (T1562.001)",          TRUE  },
				{ L"loadlibrary(\"amsi",        "LoadLibrary(\"amsi.dll\") — force AMSI load for patching (T1562.001)",          TRUE  },
				{ L"getmodulehandle(\"amsi.dll\")", "GetModuleHandle(\"amsi.dll\") — resolve amsi.dll base for HW BP (T1562.001)", TRUE },

				// --- AMSI alternate bypass techniques ---
				{ L"dotnettojscript",           "DotNetToJScript — .NET code via JScript bypassing AMSI (T1562.001)",          TRUE  },
				{ L"gadgettojscript",           "GadgetToJScript — .NET gadget chain via JScript (T1562.001)",                 TRUE  },
				{ L"uselegacyv2runtimeactivationpolicy", "useLegacyV2RuntimeActivationPolicy — force legacy CLR to skip AMSI (T1562.001)", TRUE },
				{ L"initialsessionstate.create()", "InitialSessionState.Create() — blank session without AMSI (T1562.001)",    TRUE  },
				{ L"amsiutils.scanstring",       "AmsiUtils.ScanString — internal .NET AMSI call site (T1562.001)",            TRUE  },
				{ L"amsiutils.scancontent",      "AmsiUtils.ScanContent — internal .NET AMSI call site (T1562.001)",           TRUE  },
				{ L"amsiutils.amsiinitialized",  "AmsiUtils.amsiInitialized — internal .NET AMSI init field (T1562.001)",      TRUE  },
				{ L"test-path variable:amsiinitfailed", "Test-Path variable:amsiInitFailed — AMSI bypass probe (T1562.001)",   TRUE  },
				{ L"system.management.automation.dll", "System.Management.Automation.dll — PS engine DLL reference (T1562.001)", FALSE },

				// --- AMSI internal COM method / vtable patching ---
				{ L"camsiantimalware",          "CAmsiAntimalware — AMSI internal COM class reference (T1562.001)",             TRUE  },
				{ L"camsistream",               "CAmsiStream — AMSI internal stream class reference (T1562.001)",              TRUE  },
				{ L"camsibufferstream",          "CAmsiBufferStream — AMSI internal buffer stream class (T1562.001)",          TRUE  },
				{ L"amsiantimalware::scan",      "CAmsiAntimalware::Scan — internal provider-iteration method (T1562.001)",    TRUE  },
				{ L"amsi!camsi",                "amsi!CAmsi — WinDbg-qualified AMSI internal method (T1562.001)",              TRUE  },
				{ L"iamsistream",               "IAmsiStream — AMSI COM interface reference (T1562.001)",                      TRUE  },
				{ L"iantimalware",              "IAntimalware — AMSI COM interface reference (T1562.001)",                      TRUE  },

				// --- AMSI attribute tampering ---
				{ L"amsi_attribute_content_size",    "AMSI_ATTRIBUTE_CONTENT_SIZE — attribute tamper target (T1562.001)",        TRUE  },
				{ L"amsi_attribute_content_address", "AMSI_ATTRIBUTE_CONTENT_ADDRESS — attribute tamper target (T1562.001)",     TRUE  },
				{ L"amsi_attribute_content_name",    "AMSI_ATTRIBUTE_CONTENT_NAME — attribute tamper target (T1562.001)",        TRUE  },
				{ L"amsi_attribute_session",         "AMSI_ATTRIBUTE_SESSION — attribute tamper target (T1562.001)",             TRUE  },
				{ L"amsi_attribute_app_name",        "AMSI_ATTRIBUTE_APP_NAME — attribute tamper target (T1562.001)",            TRUE  },
				{ L"amsi_attribute_quiet",           "AMSI_ATTRIBUTE_QUIET — silence AMSI scanning (T1562.001)",                TRUE  },

				// --- AMSI string obfuscation evasion (T1027 / T1562.001) ---
				{ L"\"am\"+\"si\"",              "String concat 'Am'+'si' — AMSI bypass obfuscation (T1562.001)",               TRUE  },
				{ L"'am'+'si'",                  "String concat 'am'+'si' — AMSI bypass obfuscation (T1562.001)",               TRUE  },
				{ L"-f 'amsi'",                  "Format-string -f 'amsi' — AMSI bypass obfuscation (T1562.001)",               TRUE  },
				{ L"-f \"amsi\"",                "Format-string -f \"amsi\" — AMSI bypass obfuscation (T1562.001)",             TRUE  },
				{ L"a`m`s`i",                    "Backtick A`m`s`i — AMSI bypass tick obfuscation (T1562.001)",                 TRUE  },
				{ L"am`si",                      "Backtick am`si — AMSI bypass tick obfuscation (T1562.001)",                   TRUE  },
				{ L"[char]65,[char]109,[char]115,[char]105", "[char] array 'AMSI' construction (T1562.001)",                    TRUE  },
				{ L"]-join''",                   "]-join'' — env-var char extraction obfuscation (T1027)",                       FALSE },
				{ L"]-join\"\"",                 "]-join\"\" — env-var char extraction obfuscation (T1027)",                     FALSE },
				{ L"$env:comspec[",              "$env:comspec char extraction — string obfuscation (T1027)",                    FALSE },

				// --- AMSI provider in-process patching (T1562.001) ---
				{ L"iantimalwareprovider",       "IAntimalwareProvider interface — AMSI provider vtable target (T1562.001)",     TRUE  },
				{ L"b2cabfe3-fe04-42b1",         "IAntimalwareProvider GUID — COM provider enumeration (T1562.001)",            TRUE  },
				{ L"freelibrary",                "FreeLibrary — potential AMSI provider DLL unload (T1562.001)",                FALSE },
				{ L"ldrunloaddll",               "LdrUnloadDll — ntdll provider DLL unload (T1562.001)",                       TRUE  },
				{ L"marshal.readintptr",         "Marshal.ReadIntPtr — COM vtable read for patching (T1562.001)",               TRUE  },
				{ L"marshal.writeintptr",        "Marshal.WriteIntPtr — COM vtable write/redirect (T1562.001)",                 TRUE  },

				{ L"setdlldirectory",           "SetDllDirectory — DLL search order redirect (T1574.001)",                      TRUE  },
				{ L"adddlldirectory",           "AddDllDirectory — DLL search path manipulation (T1574.001)",                   TRUE  },

				// --- WLDP (Windows Lockdown Policy) bypass ---
				{ L"wldpquerydynamiccodetrust",  "WldpQueryDynamicCodeTrust — WLDP bypass target (T1553)",                     TRUE  },
				{ L"wldpisclassinapprovedlist",  "WldpIsClassInApprovedList — WLDP bypass target (T1553)",                     TRUE  },
				{ L"wldp.dll",                  "wldp.dll — Windows Lockdown Policy DLL (T1553)",                               TRUE  },

				// --- SIP (Subject Interface Package) hijack ---
				{ L"cryptsipdll",               "CryptSIPDll — SIP DLL registry path (T1553.003)",                              TRUE  },
				{ L"cryptsipdllverifyindirectdata", "CryptSIPDllVerifyIndirectData — SIP verification hijack (T1553.003)",      TRUE  },
				{ L"cryptsipdllgetsigneddatamsg", "CryptSIPDllGetSignedDataMsg — SIP signed data hijack (T1553.003)",           TRUE  },
				{ L"\\cryptography\\oid\\",     "Cryptography\\OID — OID registry path (T1553.003)",                            TRUE  },

				// --- Trust provider / WinVerifyTrust tampering ---
				{ L"winverifytrust",            "WinVerifyTrust — Authenticode verification API (T1553.003)",                   TRUE  },
				{ L"wintrust.dll",              "wintrust.dll — Windows Trust DLL reference (T1553.003)",                       TRUE  },

				// --- Certificate store manipulation ---
				{ L"certutil -addstore root",    "certutil -addstore root — root CA injection (T1553.004)",                     TRUE  },
				{ L"certutil -addstore trustedpublisher", "certutil -addstore TrustedPublisher — trusted publisher injection (T1553.004)", TRUE },
				{ L"certutil -delstore",         "certutil -delstore — certificate removal from store (T1553.004)",             TRUE  },
				{ L"certutil -importpfx",        "certutil -importPFX — PFX certificate import (T1553.004)",                   TRUE  },
				{ L"import-certificate",         "Import-Certificate — PS certificate import cmdlet (T1553.004)",               TRUE  },
				{ L"export-certificate",         "Export-Certificate — PS certificate export cmdlet (T1553.004)",               TRUE  },
				{ L"\\systemcertificates\\root", "SystemCertificates\\ROOT — root CA store path (T1553.004)",                   TRUE  },
				{ L"\\systemcertificates\\trustedpublisher", "SystemCertificates\\TrustedPublisher — trusted publisher store (T1553.004)", TRUE },
				{ L"\\systemcertificates\\disallowed", "SystemCertificates\\Disallowed — certificate blocklist store (T1553.004)", TRUE },

				// --- Catalog file tampering ---
				{ L"\\catroot\\",               "CatRoot — catalog file directory (T1553.003)",                                 FALSE },
				{ L"\\catroot2\\",              "CatRoot2 — catalog database directory (T1553.003)",                             FALSE },
				{ L"cryptcatadmin",             "CryptCATAdmin — catalog admin API (T1553.003)",                                TRUE  },

				// --- Code Integrity / Device Guard / HVCI ---
				{ L"bcdedit /set nointegritychecks", "bcdedit /set nointegritychecks — disable Code Integrity (T1553.006)",     TRUE  },
				{ L"bcdedit /set testsigning",   "bcdedit /set testsigning — enable test-signed drivers (T1553.006)",           TRUE  },
				{ L"bcdedit /set hypervisorlaunchtype off", "bcdedit /set hypervisorlaunchtype off — disable HVCI (T1553.006)", TRUE  },
				{ L"bcdedit /set vsmlaunchtype off", "bcdedit /set vsmlaunchtype off — disable VBS (T1553.006)",                TRUE  },
				{ L"ci.dll",                    "ci.dll — Code Integrity DLL reference (T1553.006)",                            TRUE  },
				{ L"set-ruleOption",            "Set-RuleOption — WDAC policy modification cmdlet (T1553.006)",                 TRUE  },

				{ nullptr, nullptr, FALSE }
			};

			for (int i = 0; kPatterns[i].needle; i++) {
				if (CmdContains(cmd, kPatterns[i].needle)) {
					EmitCmdLineAlert(Process, cmd, kPatterns[i].desc, kPatterns[i].critical);
				}
			}
		}

		// -----------------------------------------------------------------------
		// Parent-child token integrity level mismatch detection (T1134.002)
		//
		// When potato/PrintSpoofer/GodPotato/EfsPotato-style attacks succeed,
		// the output is a SYSTEM-integrity child spawned from a medium-integrity
		// parent. Similarly, mimikatz token::elevate + CreateProcessAsUser yields
		// a high/system-integrity child under a low-privilege parent.
		//
		// Normal elevation (UAC) always goes through consent.exe or svchost.exe
		// as the actual creator — the real parent never appears as the low-priv
		// process. So a direct medium→SYSTEM parent-child link with no consent.exe
		// intermediary is a strong indicator of token impersonation abuse.
		//
		// We compare the primary token integrity level of the child process vs.
		// the creating process. If child is SYSTEM/High and creator is Medium/Low,
		// and the creator is not a known legitimate elevation broker, alert.
		// -----------------------------------------------------------------------
		{
			PEPROCESS creator = IoGetCurrentProcess();
			HANDLE creatorPid = PsGetProcessId(creator);
			HANDLE childPid   = PsGetProcessId(Process);

			// Only check if both are user-mode processes
			if ((ULONG_PTR)creatorPid > 4 && (ULONG_PTR)childPid > 4) {
				// Get integrity levels via token
				PACCESS_TOKEN creatorToken = PsReferencePrimaryToken(creator);
				PACCESS_TOKEN childToken   = PsReferencePrimaryToken(Process);

				if (creatorToken && childToken) {
					// Query TOKEN_MANDATORY_LABEL (IntegrityLevel)
					// SeQueryInformationToken(TokenIntegrityLevel) returns TOKEN_MANDATORY_LABEL
					// which has a SID — last sub-authority is the integrity RID.
					typedef struct _TOKEN_MANDATORY_LABEL2 {
						SID_AND_ATTRIBUTES Label;
					} TOKEN_MANDATORY_LABEL2;

					TOKEN_MANDATORY_LABEL2* creatorLabel = nullptr;
					TOKEN_MANDATORY_LABEL2* childLabel   = nullptr;
					// TokenIntegrityLevel = 25 in TOKEN_INFORMATION_CLASS
					NTSTATUS s1 = SeQueryInformationToken(
						creatorToken, (TOKEN_INFORMATION_CLASS)25, (PVOID*)&creatorLabel);
					NTSTATUS s2 = SeQueryInformationToken(
						childToken, (TOKEN_INFORMATION_CLASS)25, (PVOID*)&childLabel);

					if (NT_SUCCESS(s1) && NT_SUCCESS(s2) && creatorLabel && childLabel) {
						// Extract integrity RID (last sub-authority of the SID)
						SID* creatorSid = (SID*)creatorLabel->Label.Sid;
						SID* childSid   = (SID*)childLabel->Label.Sid;

						if (creatorSid && childSid &&
							creatorSid->SubAuthorityCount > 0 &&
							childSid->SubAuthorityCount > 0)
						{
							ULONG creatorIntegrity = creatorSid->SubAuthority[creatorSid->SubAuthorityCount - 1];
							ULONG childIntegrity   = childSid->SubAuthority[childSid->SubAuthorityCount - 1];

							// Integrity levels: 0x0000=Untrusted, 0x1000=Low,
							// 0x2000=Medium, 0x3000=High, 0x4000=System
							BOOLEAN creatorIsLow = (creatorIntegrity <= 0x2000); // Medium or below
							BOOLEAN childIsHigh  = (childIntegrity >= 0x3000);   // High or System

							if (creatorIsLow && childIsHigh) {
								// Check if creator is a legitimate elevation broker
								char* cName = PsGetProcessImageFileName(creator);
								BOOLEAN isBroker = FALSE;
								if (cName) {
									isBroker = (strcmp(cName, "consent.exe") == 0 ||
									            strcmp(cName, "svchost.exe") == 0 ||
									            strcmp(cName, "services.exe") == 0 ||
									            strcmp(cName, "lsass.exe") == 0 ||
									            strcmp(cName, "winlogon.exe") == 0 ||
									            strcmp(cName, "csrss.exe") == 0 ||
									            strcmp(cName, "smss.exe") == 0 ||
									            strcmp(cName, "wininit.exe") == 0 ||
									            strcmp(cName, "RuntimeBroke") == 0 ||  // RuntimeBroker.exe truncated
									            strcmp(cName, "ShellExperie") == 0);   // ShellExperienceHost truncated
								}

								if (!isBroker) {
									char* chName = PsGetProcessImageFileName(Process);
									char alertMsg[280];
									RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
										"Token integrity mismatch: '%s' (pid=%llu integrity=0x%X/Medium) "
										"spawned '%s' (pid=%llu integrity=0x%X/%s) — "
										"privilege escalation via token impersonation "
										"(potato/PrintSpoofer/token::elevate) (T1134.002)",
										cName ? cName : "?",
										(ULONG64)(ULONG_PTR)creatorPid,
										creatorIntegrity,
										chName ? chName : "?",
										(ULONG64)(ULONG_PTR)childPid,
										childIntegrity,
										childIntegrity >= 0x4000 ? "SYSTEM" : "High");

									PKERNEL_STRUCTURED_NOTIFICATION n =
										(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
											POOL_FLAG_NON_PAGED,
											sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
									if (n) {
										RtlZeroMemory(n, sizeof(*n));
										SET_CRITICAL(*n);
										SET_TOKEN_CHECK(*n);
										n->isPath = FALSE;
										n->pid    = childPid;
										if (cName) RtlCopyMemory(n->procName, cName, min(strlen(cName), 14u));
										SIZE_T msgLen = strlen(alertMsg) + 1;
										n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
										if (n->msg) {
											RtlCopyMemory(n->msg, alertMsg, msgLen);
											n->bufSize = (ULONG)msgLen;
											if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
												ExFreePool(n->msg); ExFreePool(n);
											}
										} else { ExFreePool(n); }
									}
								}
							}
						}
					}
					if (creatorLabel) ExFreePool(creatorLabel);
					if (childLabel) ExFreePool(childLabel);
				}

				if (creatorToken) PsDereferencePrimaryToken(creatorToken);
				if (childToken) PsDereferencePrimaryToken(childToken);
			}
		}

		// -----------------------------------------------------------------------
		// SeLoadDriverPrivilege presence check at process creation (T1543.003)
		//
		// If an attacker steals a token that already has SeLoadDriverPrivilege
		// enabled (via token theft / impersonation rather than NtAdjustPrivilegesToken),
		// the syscall-level privilege enablement detection never fires.
		// This check catches that by inspecting the child process's primary token
		// at creation time — any non-system process with SeLoadDriverPrivilege is
		// a BYOVD pre-attack signal.
		//
		// SeLoadDriverPrivilege LUID = { 10, 0 } on all Windows versions.
		// SE_PRIVILEGE_ENABLED = 0x00000002
		// -----------------------------------------------------------------------
		{
			HANDLE childPidLdp = PsGetProcessId(Process);
			if ((ULONG_PTR)childPidLdp > 4) {
				PACCESS_TOKEN childTok = PsReferencePrimaryToken(Process);
				if (childTok) {
					// TokenPrivileges = 3 in TOKEN_INFORMATION_CLASS
					TOKEN_PRIVILEGES* privs = nullptr;
					NTSTATUS pSt = SeQueryInformationToken(
						childTok, TokenPrivileges, (PVOID*)&privs);
					if (NT_SUCCESS(pSt) && privs) {
						for (ULONG pi = 0; pi < privs->PrivilegeCount; pi++) {
							// SeLoadDriverPrivilege = LUID { LowPart=10, HighPart=0 }
							if (privs->Privileges[pi].Luid.LowPart == 10 &&
								privs->Privileges[pi].Luid.HighPart == 0 &&
								(privs->Privileges[pi].Attributes & SE_PRIVILEGE_ENABLED))
							{
								char* ldpName = PsGetProcessImageFileName(Process);

								// Allowlist: services.exe, svchost.exe, TrustedInstaller,
								// csrss.exe, lsass.exe, wininit.exe — these legitimately
								// hold SeLoadDriverPrivilege
								BOOLEAN ldpAllowed = FALSE;
								if (ldpName) {
									ldpAllowed = (strcmp(ldpName, "services.exe") == 0 ||
									              strcmp(ldpName, "svchost.exe") == 0 ||
									              strcmp(ldpName, "TrustedInsta") == 0 ||
									              strcmp(ldpName, "csrss.exe") == 0 ||
									              strcmp(ldpName, "lsass.exe") == 0 ||
									              strcmp(ldpName, "wininit.exe") == 0 ||
									              strcmp(ldpName, "smss.exe") == 0 ||
									              strcmp(ldpName, "MsMpEng.exe") == 0);
								}

								if (!ldpAllowed) {
									PEPROCESS creatorLdp = IoGetCurrentProcess();
									char* creatorName = PsGetProcessImageFileName(creatorLdp);

									char alertMsg[280];
									RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
										"SeLoadDriverPrivilege ENABLED in new process '%s' "
										"(pid=%llu) created by '%s' — token may have been "
										"stolen/impersonated; BYOVD attack imminent (T1543.003)",
										ldpName ? ldpName : "?",
										(ULONG64)(ULONG_PTR)childPidLdp,
										creatorName ? creatorName : "?");

									PKERNEL_STRUCTURED_NOTIFICATION n =
										(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
											POOL_FLAG_NON_PAGED,
											sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
									if (n) {
										RtlZeroMemory(n, sizeof(*n));
										SET_CRITICAL(*n);
										SET_TOKEN_CHECK(*n);
										n->isPath = FALSE;
										n->pid    = childPidLdp;
										if (ldpName) RtlCopyMemory(n->procName, ldpName, min(strlen(ldpName), 14u));
										SIZE_T msgLen = strlen(alertMsg) + 1;
										n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
										if (n->msg) {
											RtlCopyMemory(n->msg, alertMsg, msgLen);
											n->bufSize = (ULONG)msgLen;
											if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
												ExFreePool(n->msg); ExFreePool(n);
											}
										} else { ExFreePool(n); }
									}
								}
								break;  // found the privilege, no need to continue
							}
						}
						ExFreePool(privs);
					}
					PsDereferencePrimaryToken(childTok);
				}
			}
		}

	} else {
		// Process exit — free the cmdline record, fork-run tracker, taint, ntdll tracker,
		// and AMSI image base slots.
		ULONG exitPid = HandleToUlong(PsGetProcessId(Process));
		ImageUtils::RemoveCmdLineRec(exitPid);
		ImageUtils::RemoveSecondaryNtdll(exitPid);
		ForkRunTracker::Remove(PsGetProcessId(Process));
		InjectionTaintTracker::Remove(PsGetProcessId(Process));
		AmsiDetector::RemoveAmsiImageBase(PsGetProcessId(Process));
	}
}

// Exposed for Ps*Notify integrity check in HookDetection
PVOID ProcessUtils::s_NotifyFn = (PVOID)CreateProcessNotifyEx;

// ---------------------------------------------------------------------------
// PsSetCreateProcessNotifyRoutineEx2 — Win10 1703+.
// Extends Ex with PsCreateProcessNotifySubsystems (=0) which additionally
// fires for Pico processes (WSL1 / Drawbridge).  Resolved at runtime so the
// driver loads on older systems; falls back to Ex on failure.
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnPsSetCreateProcessNotifyRoutineEx2)(
    PSCREATEPROCESSNOTIFYTYPE NotifyType,
    PVOID                     NotifyInformation,
    BOOLEAN                   Remove);

static pfnPsSetCreateProcessNotifyRoutineEx2 g_pSetProcessEx2 = nullptr;
static BOOLEAN                               g_usedProcessEx2 = FALSE;

VOID ProcessUtils::setProcessNotificationCallback() {

	// Prefer Ex2 (subsystem-aware) — covers Win32 + Pico (WSL1) processes.
	UNICODE_STRING usEx2;
	RtlInitUnicodeString(&usEx2, L"PsSetCreateProcessNotifyRoutineEx2");
	g_pSetProcessEx2 = (pfnPsSetCreateProcessNotifyRoutineEx2)
	    MmGetSystemRoutineAddress(&usEx2);

	if (g_pSetProcessEx2) {
		NTSTATUS status = g_pSetProcessEx2(
		    PsCreateProcessNotifySubsystems,
		    (PVOID)CreateProcessNotifyEx,
		    FALSE);
		if (NT_SUCCESS(status)) {
			g_usedProcessEx2 = TRUE;
			DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx2 (subsystems) success\n");
			return;
		}
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx2 failed — falling back\n");
	}

	// Fallback: Win32 only
	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
	if (!NT_SUCCESS(status))
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx failed\n");
	else
		DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx success\n");
}

VOID ProcessUtils::unsetProcessNotificationCallback() {

	NTSTATUS status;
	if (g_usedProcessEx2 && g_pSetProcessEx2) {
		status = g_pSetProcessEx2(
		    PsCreateProcessNotifySubsystems,
		    (PVOID)CreateProcessNotifyEx,
		    TRUE);
		if (!NT_SUCCESS(status))
			DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx2 remove failed\n");
		else
			DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx2 remove success\n");
	} else {
		status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
		if (!NT_SUCCESS(status))
			DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx remove failed\n");
		else
			DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx remove success\n");
	}
}