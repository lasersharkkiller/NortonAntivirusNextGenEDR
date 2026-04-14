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

    if (InterlockedCompareExchange(&g_MitigInitDone, 1, 0) == 0) {
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"PsGetProcessMitigationPolicy");
        g_PsGetMitig = (pfnPsGetProcessMitigationPolicy)MmGetSystemRoutineAddress(&us);
    }
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
					 strcmp(parentName, "slui.exe") == 0));

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
				{ L"/i:http",               "msiexec /i:http remote install lolbin",               TRUE  },
				{ L"javascript:",           "javascript: URI -- script execution via shell",        TRUE  },
				{ L"vbscript:",             "vbscript: URI -- script execution via shell",          TRUE  },
				{ L"//e:vbscript",          "wscript/cscript //E:vbscript engine override",         TRUE  },
				{ L"//e:jscript",           "wscript/cscript //E:jscript engine override",          TRUE  },
				{ L"installutil",           "InstallUtil lolbin -- bypasses AppLocker/SRP",         TRUE  },
				{ L"regsvr32 /s /u /i:",    "Squiblydoo: regsvr32 COM scriptlet download",          TRUE  },
				{ L"scrobj.dll",            "scrobj.dll COM scriptlet execution",                   TRUE  },
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
		// Process exit — free the cmdline record, fork-run tracker, taint, and ntdll tracker slots.
		ULONG exitPid = HandleToUlong(PsGetProcessId(Process));
		ImageUtils::RemoveCmdLineRec(exitPid);
		ImageUtils::RemoveSecondaryNtdll(exitPid);
		ForkRunTracker::Remove(PsGetProcessId(Process));
		InjectionTaintTracker::Remove(PsGetProcessId(Process));
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