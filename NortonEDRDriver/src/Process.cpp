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

VOID ProcessUtils::CreateProcessNotifyEx(
	PEPROCESS Process,
	HANDLE handle,
	PPS_CREATE_NOTIFY_INFO CreateInfo
) {

	ProcessUtils procUtils = ProcessUtils(Process);
	
	if (CreateInfo) {

		// PE scan: walk the new process VAD for suspicious executable regions
		PeScanner::ScanProcessVad(Process, CallbackObjects::GetNotifQueue());

		if (procUtils.isProcessParentPidSpoofed(CreateInfo)) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Parent Process PID (PPID) Seems Spoofed";

				SET_WARNING(*kernelNotif);
				SET_CALLING_PROC_PID_CHECK(*kernelNotif);

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
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

	}
}

VOID ProcessUtils::setProcessNotificationCallback() {

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
		CreateProcessNotifyEx,
		FALSE
	);

	if (!NT_SUCCESS(status)) {
		
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx failed\n");
	}
	else {
		DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx success\n");
	}
}

VOID ProcessUtils::unsetProcessNotificationCallback() {

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
		CreateProcessNotifyEx,
		TRUE
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx failed\n");
	}
	else {	
		DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx success\n");
	}

}