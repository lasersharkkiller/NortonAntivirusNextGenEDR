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

		// Lateral movement: remote execution host (WMI, WinRM) spawning interactive shell
		{
			PEPROCESS parentProcess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {

				char* parentName = PsGetProcessImageFileName(parentProcess);

				if (parentName != NULL &&
					(strcmp(parentName, "wmiprvse.exe") == 0 ||
					 strcmp(parentName, "wsmprovhost.exe") == 0 ||
					 strcmp(parentName, "winrshost.exe") == 0)) {

					if (CreateInfo->ImageFileName != NULL &&
						(UnicodeStringContains(CreateInfo->ImageFileName, L"cmd.exe") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"powershell.exe") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"pwsh.exe") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"wscript.exe") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"cscript.exe") ||
						 UnicodeStringContains(CreateInfo->ImageFileName, L"mshta.exe"))) {

						PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
							(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
								POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

						if (kernelNotif) {
							char* msg = "Lateral Movement: Remote exec host spawned shell process";

							SET_CRITICAL(*kernelNotif);
							SET_CALLING_PROC_PID_CHECK(*kernelNotif);

							kernelNotif->bufSize = (ULONG)(strlen(msg) + 1);
							kernelNotif->isPath = FALSE;
							kernelNotif->pid = PsGetProcessId(Process);  // the spawned shell
							RtlCopyMemory(kernelNotif->procName, parentName, 15);
							kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

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
					}
				}

				ObDereferenceObject(parentProcess);
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
				{ nullptr, nullptr, FALSE }
			};

			for (int i = 0; kPatterns[i].needle; i++) {
				if (CmdContains(cmd, kPatterns[i].needle)) {
					EmitCmdLineAlert(Process, cmd, kPatterns[i].desc, kPatterns[i].critical);
				}
			}
		}

	} else {
		// Process exit — free the cmdline record and fork-run tracker slot.
		ImageUtils::RemoveCmdLineRec(HandleToUlong(PsGetProcessId(Process)));
		ForkRunTracker::Remove(PsGetProcessId(Process));
	}
}

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