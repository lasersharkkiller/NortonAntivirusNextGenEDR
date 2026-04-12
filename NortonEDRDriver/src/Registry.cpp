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

// ---------------------------------------------------------------------------
// Defense evasion registry paths — T1562 (Impair Defenses)
// These are value writes that disable security controls.  Separate from
// persistence because they need caller-aware filtering (Windows Update and
// Group Policy legitimately touch some of these keys).
// ---------------------------------------------------------------------------

struct DefenseEvasionEntry {
    const WCHAR* keySubstr;    // key path substring to match
    const WCHAR* valueName;    // specific value name (NULL = any value write)
    const char*  description;  // human-readable alert text
    BOOLEAN      isCritical;   // TRUE = Critical, FALSE = Warning
};

static const DefenseEvasionEntry kDefenseEvasionPaths[] = {
    // --- T1562.001: Disable Windows Defender ---
    { L"\\Windows Defender\\",               L"DisableAntiSpyware",
      "Defender disabled: DisableAntiSpyware",                          TRUE  },
    { L"\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring",
      "Defender RTP disabled: DisableRealtimeMonitoring",               TRUE  },
    { L"\\Windows Defender\\Real-Time Protection", L"DisableBehaviorMonitoring",
      "Defender behavior monitoring disabled",                          TRUE  },
    { L"\\Windows Defender\\Real-Time Protection", L"DisableOnAccessProtection",
      "Defender on-access protection disabled",                         TRUE  },
    { L"\\Windows Defender\\Real-Time Protection", L"DisableScanOnRealtimeEnable",
      "Defender scan-on-RTP-enable disabled",                           TRUE  },
    { L"\\Windows Defender\\SpyNet",         L"SpyNetReporting",
      "Defender cloud reporting (SpyNet) modified",                     FALSE },
    { L"\\Windows Defender\\SpyNet",         L"SubmitSamplesConsent",
      "Defender sample submission modified",                            FALSE },
    { L"\\Windows Defender\\",               L"DisableAntiVirus",
      "Defender AV disabled: DisableAntiVirus",                         TRUE  },
    { L"\\Windows Defender\\Features",       L"TamperProtection",
      "Defender Tamper Protection modified",                            TRUE  },

    // --- T1562.004: Disable Windows Firewall ---
    { L"\\FirewallPolicy\\StandardProfile",  L"EnableFirewall",
      "Firewall disabled: StandardProfile",                             TRUE  },
    { L"\\FirewallPolicy\\DomainProfile",    L"EnableFirewall",
      "Firewall disabled: DomainProfile",                               TRUE  },
    { L"\\FirewallPolicy\\PublicProfile",    L"EnableFirewall",
      "Firewall disabled: PublicProfile",                               TRUE  },

    // --- T1548.002: UAC Bypass / Disable ---
    { L"\\Policies\\System",                 L"EnableLUA",
      "UAC disabled: EnableLUA set to 0",                               TRUE  },
    { L"\\Policies\\System",                 L"ConsentPromptBehaviorAdmin",
      "UAC prompt behavior modified (potential bypass)",                 FALSE },
    { L"\\Policies\\System",                 L"LocalAccountTokenFilterPolicy",
      "Remote UAC filtering disabled — enables pass-the-hash",          TRUE  },

    // --- T1562.002: Disable Event Logging ---
    { L"\\EventLog\\Security",              L"MaxSize",
      "Security event log MaxSize modified — log tampering",            TRUE  },
    { L"\\EventLog\\System",                L"MaxSize",
      "System event log MaxSize modified — log tampering",              FALSE },
    { L"\\EventLog\\Application",           L"MaxSize",
      "Application event log MaxSize modified — log tampering",         FALSE },
    // Sysmon, PowerShell, and other diagnostic logs are under this path
    { L"\\Microsoft\\Windows\\EventLog",    NULL,
      "Diagnostic event log configuration modified",                    FALSE },

    // --- T1562.003: Disable PowerShell Logging ---
    { L"\\PowerShell\\ScriptBlockLogging",  L"EnableScriptBlockLogging",
      "PowerShell ScriptBlock logging disabled",                        TRUE  },
    { L"\\PowerShell\\ModuleLogging",       L"EnableModuleLogging",
      "PowerShell Module logging disabled",                             TRUE  },
    { L"\\PowerShell\\Transcription",       L"EnableTranscripting",
      "PowerShell transcription logging disabled",                      TRUE  },

    // --- T1112: Credential access via registry ---
    // Storing cleartext passwords in WDigest (Mimikatz UseLogonCredential)
    { L"\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential",
      "WDigest cleartext credential caching enabled (Mimikatz technique)", TRUE },

    // --- T1112: LSA protection downgrade ---
    { L"\\Control\\Lsa",                    L"RunAsPPL",
      "LSA RunAsPPL protection modified — credential guard downgrade",  TRUE  },

    // --- Misc defense evasion ---
    // AMSI provider unregistration (COM CLSID nuke)
    { L"\\AMSI\\Providers",                 NULL,
      "AMSI provider registry modification — potential AMSI bypass",    TRUE  },

    { nullptr, nullptr, nullptr, FALSE }
};

// Trusted processes that legitimately modify security-related registry values.
// PsGetProcessImageFileName returns at most 14 chars (EPROCESS.ImageFileName).
static BOOLEAN IsDefenseEvasionTrustedCaller() {
    char* name = PsGetProcessImageFileName(IoGetCurrentProcess());
    if (!name) return FALSE;
    return (strcmp(name, "services.exe")  == 0 ||
            strcmp(name, "svchost.exe")   == 0 ||
            strcmp(name, "TrustedInsta")  == 0 ||
            strcmp(name, "msiexec.exe")   == 0 ||
            strcmp(name, "tiworker.exe")  == 0 ||
            strcmp(name, "MsMpEng.exe")   == 0 ||
            strcmp(name, "SecurityHeal")  == 0 ||
            strcmp(name, "MpCmdRun.exe")  == 0);
}

// Check if a SetValueKey operation matches a defense evasion pattern.
// Returns the matched entry or NULL.
static const DefenseEvasionEntry* MatchDefenseEvasion(
    PCUNICODE_STRING regPath,
    PREG_SET_VALUE_KEY_INFORMATION setValInfo)
{
    for (int i = 0; kDefenseEvasionPaths[i].keySubstr; i++) {
        if (!UnicodeStringContains((PUNICODE_STRING)regPath,
                                   kDefenseEvasionPaths[i].keySubstr))
            continue;

        // If entry requires a specific value name, check it
        if (kDefenseEvasionPaths[i].valueName) {
            if (!setValInfo || !setValInfo->ValueName ||
                !setValInfo->ValueName->Buffer ||
                setValInfo->ValueName->Length == 0 ||
                !MmIsAddressValid(setValInfo->ValueName->Buffer))
                continue;

            UNICODE_STRING target;
            RtlInitUnicodeString(&target, kDefenseEvasionPaths[i].valueName);
            if (!RtlEqualUnicodeString(setValInfo->ValueName, &target, TRUE))
                continue;
        }

        return &kDefenseEvasionPaths[i];
    }
    return nullptr;
}

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

			// ---- EDR self-protection: block modifications to our own service key ----
			// Any write to Services\NortonEDR (ImagePath, Start, Type, etc.)
			// from a non-trusted caller is blocked outright and alerted.
			// This prevents attackers from disabling/redirecting the EDR on reboot.
			if (UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Services\\NortonEDR")) {
				char* procName = PsGetProcessImageFileName(IoGetCurrentProcess());
				BOOLEAN trustedSvc = procName && (
					strcmp(procName, "services.exe") == 0 ||
					strcmp(procName, "TrustedInsta") == 0 ||
					strcmp(procName, "msiexec.exe")  == 0);
				if (!trustedSvc) {
					char selfMsg[200];
					RtlStringCbPrintfA(selfMsg, sizeof(selfMsg),
						"ANTI-TAMPER: NortonEDR service key modification BLOCKED "
						"— %s attempted to modify Services\\NortonEDR",
						procName ? procName : "unknown");
					SIZE_T selfLen = strlen(selfMsg) + 1;

					PKERNEL_STRUCTURED_NOTIFICATION sNotif =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED,
							sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (sNotif) {
						RtlZeroMemory(sNotif, sizeof(*sNotif));
						SET_CRITICAL(*sNotif);
						SET_SYSCALL_CHECK(*sNotif);
						sNotif->bufSize = (ULONG)selfLen;
						sNotif->isPath  = FALSE;
						sNotif->pid     = PsGetProcessId(IoGetCurrentProcess());
						sNotif->msg     = (char*)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, selfLen, 'msg');
						if (procName)
							RtlCopyMemory(sNotif->procName, procName, 14);
						if (sNotif->msg) {
							RtlCopyMemory(sNotif->msg, selfMsg, selfLen);
							if (!CallbackObjects::GetNotifQueue()->Enqueue(sNotif)) {
								ExFreePool(sNotif->msg); ExFreePool(sNotif);
							}
						} else {
							ExFreePool(sNotif);
						}
					}
					return STATUS_ACCESS_DENIED;  // BLOCK the write
				}
			}

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

				// ---- Service config hijacking: value-name + caller awareness ----
				// For RegNtPreSetValueKey on service keys, detect modification of
				// high-risk values (ImagePath, ServiceDll, FailureCommand) by
				// non-service-manager processes.  Suppresses noisy generic alerts
				// for routine service value writes from trusted callers.
				BOOLEAN isServicePath = UnicodeStringContains(
					(PUNICODE_STRING)regPath, L"\\Services\\");
				BOOLEAN isServiceHijack = FALSE;
				char hijackDetail[350] = {};

				if (isServicePath && regNotifyClass == RegNtPreSetValueKey) {
					PREG_SET_VALUE_KEY_INFORMATION setValInfo =
						(PREG_SET_VALUE_KEY_INFORMATION)Arg2;

					BOOLEAN highRiskValue = FALSE;
					if (setValInfo && setValInfo->ValueName &&
						setValInfo->ValueName->Buffer &&
						setValInfo->ValueName->Length > 0 &&
						MmIsAddressValid(setValInfo->ValueName->Buffer))
					{
						// T1543.003 — service binary/DLL path & failure recovery
						static const WCHAR* kHijackVals[] = {
							L"ImagePath",       // service binary
							L"ServiceDll",      // svchost-hosted service DLL
							L"FailureCommand",  // failure recovery command exec
							nullptr
						};
						for (int v = 0; kHijackVals[v]; v++) {
							UNICODE_STRING target;
							RtlInitUnicodeString(&target, kHijackVals[v]);
							if (RtlEqualUnicodeString(
									setValInfo->ValueName, &target, TRUE)) {
								highRiskValue = TRUE;
								break;
							}
						}
					}

					if (highRiskValue) {
						char* procName =
							PsGetProcessImageFileName(IoGetCurrentProcess());
						// Legitimate writers: services.exe (SCM), TrustedInstaller,
						// svchost.exe (self-config), msiexec.exe (Windows Installer)
						BOOLEAN trusted = procName && (
							strcmp(procName, "services.exe") == 0 ||
							strcmp(procName, "TrustedInsta") == 0 ||
							strcmp(procName, "svchost.exe")  == 0 ||
							strcmp(procName, "msiexec.exe")  == 0);

						if (!trusted) {
							isServiceHijack = TRUE;
							isCritical = TRUE;

							// Narrow the value name
							char valNarrow[40] = {};
							USHORT vc =
								setValInfo->ValueName->Length / sizeof(WCHAR);
							if (vc > 39) vc = 39;
							for (USHORT ci = 0; ci < vc; ci++)
								valNarrow[ci] =
									(setValInfo->ValueName->Buffer[ci] < 128)
									? (char)setValInfo->ValueName->Buffer[ci]
									: '?';

							// Extract new value data (REG_SZ / REG_EXPAND_SZ)
							char newPath[100] = {};
							if (setValInfo->Data && setValInfo->DataSize > 0 &&
								MmIsAddressValid(setValInfo->Data) &&
								(setValInfo->Type == REG_SZ ||
								 setValInfo->Type == REG_EXPAND_SZ))
							{
								__try {
									WCHAR* wd = (WCHAR*)setValInfo->Data;
									ULONG nc =
										setValInfo->DataSize / sizeof(WCHAR);
									if (nc > 99) nc = 99;
									for (ULONG ci = 0;
										 ci < nc && wd[ci]; ci++)
										newPath[ci] = (wd[ci] < 128)
											? (char)wd[ci] : '?';
								} __except (EXCEPTION_EXECUTE_HANDLER) {}
							}

							RtlStringCbPrintfA(hijackDetail,
								sizeof(hijackDetail),
								"Service config hijack: %s modified %s "
								"-> \"%s\" (non-service-manager writer "
								"-- MITRE T1543.003)",
								procName ? procName : "unknown",
								valNarrow,
								newPath[0] ? newPath : "<binary data>");
						}
					}

					// Suppress noisy generic alerts for routine service
					// value writes — only fire on confirmed hijacking
					if (!isServiceHijack) goto skip_persistence_alert;
				}

				// Build a descriptive message that includes the key path (first 120 chars).
				char pathNarrow[121] = {};
				if (regPath->Buffer && regPath->Length > 0) {
					USHORT chars = regPath->Length / sizeof(WCHAR);
					if (chars > 120) chars = 120;
					for (USHORT ci = 0; ci < chars; ci++)
						pathNarrow[ci] = (regPath->Buffer[ci] < 128)
						                 ? (char)regPath->Buffer[ci] : '?';
				}

				char alertMsg[350];
				if (isServiceHijack) {
					RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
						"%s", hijackDetail);
				} else {
					RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
						"%s Registry persistence/boot key write: %s",
						isCritical ? "CRITICAL" : "Warning",
						pathNarrow);
				}
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
skip_persistence_alert:

			// ---- Defense evasion detection (T1562) ----
			// Only fires on RegNtPreSetValueKey — key creation alone is not
			// defense evasion (the values do the damage, not the keys).
			if (regNotifyClass == RegNtPreSetValueKey) {
				PREG_SET_VALUE_KEY_INFORMATION setValInfo =
					(PREG_SET_VALUE_KEY_INFORMATION)Arg2;

				const DefenseEvasionEntry* match =
					MatchDefenseEvasion(regPath, setValInfo);

				if (match && !IsDefenseEvasionTrustedCaller()) {
					char* procName =
						PsGetProcessImageFileName(IoGetCurrentProcess());

					char evasionMsg[300];
					RtlStringCbPrintfA(evasionMsg, sizeof(evasionMsg),
						"Defense evasion (T1562): %s by %s",
						match->description,
						procName ? procName : "unknown");
					SIZE_T evasionLen = strlen(evasionMsg) + 1;

					PKERNEL_STRUCTURED_NOTIFICATION eNotif =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED,
							sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (eNotif) {
						RtlZeroMemory(eNotif, sizeof(*eNotif));
						if (match->isCritical) { SET_CRITICAL(*eNotif); }
						else                   { SET_WARNING(*eNotif);  }
						SET_SYSCALL_CHECK(*eNotif);
						eNotif->bufSize = (ULONG)evasionLen;
						eNotif->isPath  = FALSE;
						eNotif->pid     = PsGetProcessId(IoGetCurrentProcess());
						eNotif->msg     = (char*)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, evasionLen, 'msg');
						if (procName)
							RtlCopyMemory(eNotif->procName, procName, 14);
						if (eNotif->msg) {
							RtlCopyMemory(eNotif->msg, evasionMsg, evasionLen);
							if (!CallbackObjects::GetNotifQueue()->Enqueue(eNotif)) {
								ExFreePool(eNotif->msg);
								ExFreePool(eNotif);
							}
						} else {
							ExFreePool(eNotif);
						}
					}
				}
			}
		}
		break;

	// ---- Minifilter altitude registry enumeration (T1518.001 / T1082) ----
	// Attackers enumerate HKLM\SYSTEM\CCS\Services\<driver>\Instances\<inst>\Altitude
	// to map all minifilter drivers, their altitudes, and find gaps to insert a
	// malicious filter above/below an EDR.  Tools: fltmc, EDRSandblast, custom recon.
	// Also catches reads of DefaultInstance values used to resolve instance names.
	// We detect value reads on any key path containing "\Instances\" under "\Services\"
	// where the queried value is "Altitude", "DefaultInstance", or "Flags".
	case RegNtPreQueryValueKey:
	{
		PREG_QUERY_VALUE_KEY_INFORMATION qvInfo =
			(PREG_QUERY_VALUE_KEY_INFORMATION)Arg2;
		if (!qvInfo || !qvInfo->Object || !MmIsAddressValid(qvInfo->Object))
			break;
		if (!qvInfo->ValueName || !qvInfo->ValueName->Buffer ||
			qvInfo->ValueName->Length == 0 ||
			!MmIsAddressValid(qvInfo->ValueName->Buffer))
			break;

		// Only care about minifilter-related value names
		static const WCHAR* kFilterValues[] = {
			L"Altitude", L"DefaultInstance", L"Flags", nullptr
		};
		BOOLEAN isFilterValue = FALSE;
		for (int i = 0; kFilterValues[i]; i++) {
			UNICODE_STRING target;
			RtlInitUnicodeString(&target, kFilterValues[i]);
			if (RtlEqualUnicodeString(qvInfo->ValueName, &target, TRUE)) {
				isFilterValue = TRUE;
				break;
			}
		}
		if (!isFilterValue) break;

		status = CmCallbackGetKeyObjectIDEx(
			&cookie, qvInfo->Object, NULL, &regPath, 0);
		if (!NT_SUCCESS(status) || !regPath || !regPath->Length ||
			!MmIsAddressValid(regPath->Buffer))
			break;

		// Must be under a Services\<driver>\Instances path
		if (!UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Services\\") ||
			!UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Instances"))
			break;

		// Allowlist system processes that legitimately enumerate filters
		char* procName = PsGetProcessImageFileName(IoGetCurrentProcess());
		if (procName) {
			if (strcmp(procName, "services.exe") == 0 ||
				strcmp(procName, "svchost.exe")  == 0 ||
				strcmp(procName, "TrustedInsta") == 0 ||
				strcmp(procName, "msiexec.exe")  == 0 ||
				strcmp(procName, "System")       == 0 ||
				strcmp(procName, "MsMpEng.exe")  == 0 ||
				strcmp(procName, "lsass.exe")    == 0 ||
				strcmp(procName, "csrss.exe")    == 0 ||
				strcmp(procName, "smss.exe")     == 0 ||
				strcmp(procName, "wininit.exe")  == 0 ||
				strcmp(procName, "fltMC.exe")    == 0 ||  // fltmc itself — caught by cmdline detection
				strcmp(procName, "NortonEDR.ex") == 0)
				break;
		}

		// Convert path to narrow for alert
		char pathBuf[160] = {};
		USHORT copyLen = min(regPath->Length / sizeof(WCHAR), (USHORT)(sizeof(pathBuf) - 1));
		for (USHORT i = 0; i < copyLen; i++) {
			WCHAR wc = regPath->Buffer[i];
			pathBuf[i] = (wc < 128) ? (char)wc : '?';
		}

		// Convert value name to narrow
		char valBuf[64] = {};
		USHORT valLen = min(qvInfo->ValueName->Length / sizeof(WCHAR), (USHORT)(sizeof(valBuf) - 1));
		for (USHORT i = 0; i < valLen; i++) {
			WCHAR wc = qvInfo->ValueName->Buffer[i];
			valBuf[i] = (wc < 128) ? (char)wc : '?';
		}

		char msg[350];
		RtlStringCbPrintfA(msg, sizeof(msg),
			"Minifilter altitude recon (T1518.001): %s queried '%s' at %s "
			"— mapping minifilter driver altitudes for evasion/sandwiching",
			procName ? procName : "unknown", valBuf, pathBuf);
		SIZE_T msgLen = strlen(msg) + 1;

		PKERNEL_STRUCTURED_NOTIFICATION n =
			(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
				POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
		if (n) {
			RtlZeroMemory(n, sizeof(*n));
			SET_WARNING(*n);
			SET_SYSCALL_CHECK(*n);
			n->bufSize = (ULONG)msgLen;
			n->isPath  = FALSE;
			n->pid     = PsGetProcessId(IoGetCurrentProcess());
			if (procName) RtlCopyMemory(n->procName, procName, 14);
			n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
			if (n->msg) {
				RtlCopyMemory(n->msg, msg, msgLen);
				if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
					ExFreePool(n->msg); ExFreePool(n);
				}
			} else {
				ExFreePool(n);
			}
		}
		break;
	}

	// ---- Minifilter service key enumeration (RegNtPreEnumerateKey) ----
	// Attackers enumerate subkeys under Services\<driver>\Instances to discover
	// all registered minifilter instances.  This complements value read detection
	// above — catches breadth-first registry walking tools.
	case RegNtPreEnumerateKey:
	{
		PREG_ENUMERATE_KEY_INFORMATION ekInfo =
			(PREG_ENUMERATE_KEY_INFORMATION)Arg2;
		if (!ekInfo || !ekInfo->Object || !MmIsAddressValid(ekInfo->Object))
			break;

		status = CmCallbackGetKeyObjectIDEx(
			&cookie, ekInfo->Object, NULL, &regPath, 0);
		if (!NT_SUCCESS(status) || !regPath || !regPath->Length ||
			!MmIsAddressValid(regPath->Buffer))
			break;

		// Only trigger on Instances subkey enumeration under Services
		if (!UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Services\\") ||
			!UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Instances"))
			break;

		// Same allowlist
		char* procName = PsGetProcessImageFileName(IoGetCurrentProcess());
		if (procName) {
			if (strcmp(procName, "services.exe") == 0 ||
				strcmp(procName, "svchost.exe")  == 0 ||
				strcmp(procName, "TrustedInsta") == 0 ||
				strcmp(procName, "msiexec.exe")  == 0 ||
				strcmp(procName, "System")       == 0 ||
				strcmp(procName, "MsMpEng.exe")  == 0 ||
				strcmp(procName, "lsass.exe")    == 0 ||
				strcmp(procName, "csrss.exe")    == 0 ||
				strcmp(procName, "smss.exe")     == 0 ||
				strcmp(procName, "wininit.exe")  == 0 ||
				strcmp(procName, "fltMC.exe")    == 0 ||
				strcmp(procName, "NortonEDR.ex") == 0)
				break;
		}

		// Rate-limit: only alert on Index == 0 (start of enumeration) to avoid
		// flooding with one alert per subkey when a tool walks the entire tree.
		if (ekInfo->Index != 0) break;

		char pathBuf[160] = {};
		USHORT copyLen = min(regPath->Length / sizeof(WCHAR), (USHORT)(sizeof(pathBuf) - 1));
		for (USHORT i = 0; i < copyLen; i++) {
			WCHAR wc = regPath->Buffer[i];
			pathBuf[i] = (wc < 128) ? (char)wc : '?';
		}

		char msg[300];
		RtlStringCbPrintfA(msg, sizeof(msg),
			"Minifilter instance enum (T1518.001): %s enumerating subkeys of %s "
			"— mapping minifilter driver instances",
			procName ? procName : "unknown", pathBuf);
		SIZE_T msgLen = strlen(msg) + 1;

		PKERNEL_STRUCTURED_NOTIFICATION n =
			(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
				POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
		if (n) {
			RtlZeroMemory(n, sizeof(*n));
			SET_WARNING(*n);
			SET_SYSCALL_CHECK(*n);
			n->bufSize = (ULONG)msgLen;
			n->isPath  = FALSE;
			n->pid     = PsGetProcessId(IoGetCurrentProcess());
			if (procName) RtlCopyMemory(n->procName, procName, 14);
			n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
			if (n->msg) {
				RtlCopyMemory(n->msg, msg, msgLen);
				if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
					ExFreePool(n->msg); ExFreePool(n);
				}
			} else {
				ExFreePool(n);
			}
		}
		break;
	}

	// ---- Value deletion monitoring ----
	// Attackers use `reg delete` to remove security-related values.
	// E.g., deleting DisableAntiSpyware after GPO enforcement,
	// or removing RunAsPPL to downgrade LSA protection.
	// REG_DELETE_VALUE_KEY_INFORMATION has Object + ValueName.
	case RegNtPreDeleteValueKey:
	{
		PREG_DELETE_VALUE_KEY_INFORMATION delInfo =
			(PREG_DELETE_VALUE_KEY_INFORMATION)Arg2;
		if (!delInfo || !delInfo->Object || !MmIsAddressValid(delInfo->Object))
			break;

		status = CmCallbackGetKeyObjectIDEx(
			&cookie, delInfo->Object, NULL, &regPath, 0);
		if (!NT_SUCCESS(status) || !regPath || !regPath->Length ||
			!MmIsAddressValid(regPath->Buffer))
			break;

		// Self-protection: block value deletion from NortonEDR service key
		if (UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Services\\NortonEDR")) {
			char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
			BOOLEAN trusted = pn && (
				strcmp(pn, "services.exe") == 0 ||
				strcmp(pn, "TrustedInsta") == 0);
			if (!trusted) return STATUS_ACCESS_DENIED;
		}

		// Check if this deletion targets a security-sensitive key+value
		// by matching against defense evasion paths that have a valueName.
		if (!delInfo->ValueName || !delInfo->ValueName->Buffer ||
			delInfo->ValueName->Length == 0 ||
			!MmIsAddressValid(delInfo->ValueName->Buffer))
			break;

		for (int i = 0; kDefenseEvasionPaths[i].keySubstr; i++) {
			if (!kDefenseEvasionPaths[i].valueName) continue;
			if (!UnicodeStringContains((PUNICODE_STRING)regPath,
			                           kDefenseEvasionPaths[i].keySubstr))
				continue;

			UNICODE_STRING target;
			RtlInitUnicodeString(&target, kDefenseEvasionPaths[i].valueName);
			if (!RtlEqualUnicodeString(delInfo->ValueName, &target, TRUE))
				continue;

			if (IsDefenseEvasionTrustedCaller()) break;

			char* procName =
				PsGetProcessImageFileName(IoGetCurrentProcess());

			char delMsg[300];
			RtlStringCbPrintfA(delMsg, sizeof(delMsg),
				"Defense evasion (T1562): %s DELETED by %s",
				kDefenseEvasionPaths[i].description,
				procName ? procName : "unknown");
			SIZE_T delLen = strlen(delMsg) + 1;

			PKERNEL_STRUCTURED_NOTIFICATION dNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED,
					sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
			if (dNotif) {
				RtlZeroMemory(dNotif, sizeof(*dNotif));
				SET_CRITICAL(*dNotif);
				SET_SYSCALL_CHECK(*dNotif);
				dNotif->bufSize = (ULONG)delLen;
				dNotif->isPath  = FALSE;
				dNotif->pid     = PsGetProcessId(IoGetCurrentProcess());
				dNotif->msg     = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, delLen, 'msg');
				if (procName)
					RtlCopyMemory(dNotif->procName, procName, 14);
				if (dNotif->msg) {
					RtlCopyMemory(dNotif->msg, delMsg, delLen);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(dNotif)) {
						ExFreePool(dNotif->msg);
						ExFreePool(dNotif);
					}
				} else {
					ExFreePool(dNotif);
				}
			}
			break;  // matched — one alert per deletion
		}
		break;
	}

	// ---- Key deletion: protect our service key from being wiped ----
	case RegNtPreDeleteKey:
	{
		PREG_DELETE_KEY_INFORMATION dkInfo =
			(PREG_DELETE_KEY_INFORMATION)Arg2;
		if (!dkInfo || !dkInfo->Object || !MmIsAddressValid(dkInfo->Object))
			break;

		status = CmCallbackGetKeyObjectIDEx(
			&cookie, dkInfo->Object, NULL, &regPath, 0);
		if (!NT_SUCCESS(status) || !regPath || !regPath->Length ||
			!MmIsAddressValid(regPath->Buffer))
			break;

		if (UnicodeStringContains((PUNICODE_STRING)regPath, L"\\Services\\NortonEDR")) {
			char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
			BOOLEAN trusted = pn && (
				strcmp(pn, "services.exe") == 0 ||
				strcmp(pn, "TrustedInsta") == 0);
			if (!trusted) return STATUS_ACCESS_DENIED;
		}
		break;
	}

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