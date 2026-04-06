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
		// Process exit — free the cmdline record so the slot can be reused.
		ImageUtils::RemoveCmdLineRec(HandleToUlong(PsGetProcessId(Process)));
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