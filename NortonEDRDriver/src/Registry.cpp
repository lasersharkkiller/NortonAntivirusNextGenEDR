#include "Globals.h"
#include "Deception.h"

LARGE_INTEGER RegistryUtils::cookie = { 0 };

// Registry paths associated with persistence, firmware abuse, and supply-chain
// staging.  Grouped by threat category for clarity.
static const WCHAR* kPersistencePaths[] = {
    // --- Classic autorun ---
    L"\\CurrentVersion\\Run",
    L"\\CurrentVersion\\RunOnce",
    L"\\CurrentVersion\\RunOnce\\Setup",
    L"\\CurrentVersion\\RunServices",
    L"\\CurrentVersion\\RunServicesOnce",

    // --- Boot-execute / session manager (firmware / pre-OS persistence) ---
    // BootExecute is run before the Win32 subsystem starts — FancyBear / VPNFilter pattern.
    L"\\Session Manager\\BootExecute",
    // PendingFileRenameOperations is abused to drop malware on next reboot.
    L"\\Session Manager\\PendingFileRenameOperations",
    L"\\Session Manager\\PendingFileRenameOperations2",
    // SetupExecute and Execute are early-boot execution points.
    L"\\Session Manager\\SetupExecute",
    L"\\Session Manager\\Execute",

    // --- Service image path (new service installation = lateral movement / persistence) ---
    L"\\Services\\",   // broad — catches new service registry key creation

    // --- Image File Execution Options (IFEO) debugger hijack, Sticky Keys) ---
    L"Image File Execution Options",

    // --- AppInit_DLLs (deprecated but still active on non-SB systems) ---
    L"\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",

    // --- Winlogon shell / userinit hijack ---
    L"\\Winlogon\\Shell",
    L"\\Winlogon\\Userinit",
    L"\\Winlogon\\Notify",

    // --- COM object hijack (persistence via InprocServer32) ---
    // Too broad to include globally; covered by LOLBin/supply-chain pattern instead.

    // --- Boot configuration / EFI (firmware tampering, BlackLotus) ---
    // HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot is read-only from usermode
    // normally; any write attempt is suspicious.
    L"\\Control\\SecureBoot",
    // EFI variables via registry path (Windows exposes some EFI vars here)
    L"\\Firmware\\ESRT",

    // --- Scheduled task COM / legacy task paths ---
    L"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule",

    // --- WMI subscription persistence (fileless) ---
    // WMI event subscriptions write to this hive path.
    L"\\Microsoft\\WBEM",

    // --- T1547.002: Authentication Package persistence ---
    // Adversaries add custom DLLs to be loaded by LSA at boot.
    L"\\Control\\Lsa\\Authentication Packages",

    // --- T1547.005: Security Support Provider persistence ---
    // SSP DLLs loaded into lsass.exe at boot; Mimikatz mimilib.dll abuses this.
    L"\\Control\\Lsa\\Security Packages",

    // --- T1547.008: LSASS Driver persistence ---
    L"\\Control\\Lsa\\Notification Packages",

    // --- T1547.010: Port Monitor persistence ---
    // Adversaries register a malicious DLL as a port monitor loaded by spoolsv.exe.
    L"\\Control\\Print\\Monitors",

    // --- T1547.012: Print Processor persistence ---
    // Malicious print processor DLLs loaded by the print spooler service.
    L"\\Control\\Print\\Environments",

    // --- T1547.015: Active Setup persistence ---
    // Per-user execution at logon via StubPath value.
    L"\\Active Setup\\Installed Components",

    nullptr
};

// Per-path alert severity (mirrors position in kPersistencePaths).
// TRUE = Critical, FALSE = Warning.
static const BOOLEAN kPersistenceCritical[] = {
    FALSE, FALSE, FALSE, FALSE, FALSE, // Classic autorun — Warning
    TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  // Boot-execute / SessionMgr — Critical
    TRUE,                              // Services — Critical
    TRUE,                              // IFEO — Critical
    TRUE,                              // AppInit_DLLs — Critical
    TRUE,  TRUE,  TRUE,               // Winlogon — Critical
    TRUE,  TRUE,                       // SecureBoot / EFI — Critical
    FALSE,                             // Scheduled tasks — Warning
    FALSE,                             // WMI — Warning
    TRUE,                              // LSA Authentication Packages — Critical
    TRUE,                              // LSA Security Packages (SSP) — Critical
    TRUE,                              // LSA Notification Packages — Critical
    TRUE,                              // Print Monitors — Critical
    TRUE,                              // Print Processors — Critical
    TRUE,                              // Active Setup — Critical
};

BOOLEAN RegistryUtils::isRegistryPersistenceBehavior(
	PUNICODE_STRING regPath
) {
	for (int i = 0; kPersistencePaths[i]; i++) {
		if (UnicodeStringContains(regPath, kPersistencePaths[i]))
			return TRUE;
	}
	return FALSE;
}

// Returns the severity for a matched persistence path (TRUE = Critical).
static BOOLEAN PersistencePathIsCritical(PUNICODE_STRING regPath) {
	for (int i = 0; kPersistencePaths[i]; i++) {
		if (UnicodeStringContains(regPath, kPersistencePaths[i]))
			return kPersistenceCritical[i];
	}
	return FALSE;
}

NTSTATUS RegistryUtils::RegOpNotifyCallback(
	PVOID CallbackContext,
	PVOID Arg1,
	PVOID Arg2
) {
	
	NTSTATUS status;
	PREG_POST_OPERATION_INFORMATION queryKeyInfo;
	PREG_QUERY_VALUE_KEY_INFORMATION queryValueInfo;
	PCUNICODE_STRING regPath;
	PUNICODE_STRING imageFileName;

	REG_NOTIFY_CLASS regNotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Arg1;

	switch (regNotifyClass) {
	case RegNtPreSetValueKey:
	// fall through — same analysis applies to value writes as to key creates
	case RegNtPreCreateKeyEx:

		queryKeyInfo = (PREG_POST_OPERATION_INFORMATION)Arg2;

		if (queryKeyInfo == NULL) {
			break;
		}

		if (queryKeyInfo->Object == NULL || !MmIsAddressValid(queryKeyInfo->Object)) {
			break;
		}

		status = CmCallbackGetKeyObjectIDEx(
			&cookie,
			queryKeyInfo->Object,
			NULL,
			&regPath,
			0
		);

		if (!NT_SUCCESS(status) || regPath == NULL || regPath->Length == 0 || !MmIsAddressValid(regPath->Buffer)) {
			break;
		}

		else {

			// Honeypot check — any access to our fake credential keys is a
			// high-confidence indicator of a credential-hunting tool.
			// Access is ALLOWED so the attacker receives the canary data.
			if (DeceptionEngine::IsHoneypotRegistryAccess(regPath)) {
				DeceptionEngine::HandleHoneypotRegistryAccess(
					regPath,
					PsGetProcessId(IoGetCurrentProcess()),
					FALSE);
			}

			if (isRegistryPersistenceBehavior((PUNICODE_STRING)regPath)) {

				BOOLEAN isCritical = PersistencePathIsCritical((PUNICODE_STRING)regPath);

				// Build a descriptive message that includes the key path (first 120 chars).
				char pathNarrow[121] = {};
				if (regPath->Buffer && regPath->Length > 0) {
					USHORT chars = regPath->Length / sizeof(WCHAR);
					if (chars > 120) chars = 120;
					for (USHORT ci = 0; ci < chars; ci++)
						pathNarrow[ci] = (regPath->Buffer[ci] < 128)
						                 ? (char)regPath->Buffer[ci] : '?';
				}

				char alertMsg[200];
				RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
					"%s Registry persistence/boot key write: %s",
					isCritical ? "CRITICAL" : "Warning",
					pathNarrow);
				SIZE_T alertLen = strlen(alertMsg) + 1;

				PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
					(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
						POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

				if (kernelNotif) {
					RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));

					if (isCritical) { SET_CRITICAL(*kernelNotif); }
					else            { SET_WARNING(*kernelNotif);  }
					SET_SYSCALL_CHECK(*kernelNotif);

					kernelNotif->bufSize = (ULONG)alertLen;
					kernelNotif->isPath  = FALSE;
					kernelNotif->pid     = PsGetProcessId(IoGetCurrentProcess());
					kernelNotif->msg     = (char*)ExAllocatePool2(
						POOL_FLAG_NON_PAGED, alertLen, 'msg');

					RtlCopyMemory(kernelNotif->procName,
					              PsGetProcessImageFileName(IoGetCurrentProcess()), 14);

					if (kernelNotif->msg) {
						RtlCopyMemory(kernelNotif->msg, alertMsg, alertLen);
						if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
							ExFreePool(kernelNotif->msg);
							ExFreePool(kernelNotif);
						}
					} else {
						ExFreePool(kernelNotif);
					}
				}
			}
		}
		break;

	default:
		break;
	}
	

	return STATUS_SUCCESS;
}

VOID RegistryUtils::setRegistryNotificationCallback() {

	NTSTATUS status;
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(ALTITUDE);

	status = CmRegisterCallbackEx(
		RegistryUtils::RegOpNotifyCallback, 
		&altitude, 
		CallbackObjects::GetDriverObject(),
		NULL, 
		&cookie, 
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] CmRegisterCallbackEx failed\n");
		return;
	}

	DbgPrint("[+] CmRegisterCallbackEx success\n");
}

VOID RegistryUtils::unsetRegistryNotificationCallback() {

	NTSTATUS status = CmUnRegisterCallback(cookie);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] CmUnRegisterCallback failed\n");
		return;
	}

	DbgPrint("[+] CmUnRegisterCallback success\n");
}