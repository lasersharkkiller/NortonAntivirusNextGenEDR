#include "Globals.h"

// PsGetThreadWin32StartAddress is undocumented; resolve dynamically
typedef PVOID (*PsGetThreadWin32StartAddress_t)(PETHREAD Thread);
static PsGetThreadWin32StartAddress_t g_pfnPsGetThreadWin32StartAddress = nullptr;

static PVOID SafePsGetThreadWin32StartAddress(PETHREAD Thread) {
    if (!g_pfnPsGetThreadWin32StartAddress) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"PsGetThreadWin32StartAddress");
        g_pfnPsGetThreadWin32StartAddress =
            (PsGetThreadWin32StartAddress_t)MmGetSystemRoutineAddress(&name);
    }
    if (g_pfnPsGetThreadWin32StartAddress)
        return g_pfnPsGetThreadWin32StartAddress(Thread);
    return nullptr;
}

BOOLEAN ThreadUtils::isThreadRemotelyCreated(HANDLE procId) {

	if (PsGetCurrentProcessId() != procId) {
		return TRUE;
	}

	return FALSE;
}

BOOLEAN ThreadUtils::isThreadInjected(ULONG64* addr) {

	BOOLEAN isAddressOutOfSystem32Ntdll = FALSE;
	BOOLEAN isAddressOutOfWow64Ntdll = FALSE;
	BOOLEAN isWow64 = FALSE;

	ULONG64 stackStart = stackUtils.getStackStartRtl();
	if (stackStart == NULL) {
		return FALSE;
	}

	if(((ULONG64)stackStart >> 36) != 0x7FF) {

		if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL) {
			isWow64 = TRUE;
		}

		this->getVadUtils()->isAddressOutOfNtdll(
			(PRTL_BALANCED_NODE)this->getVadUtils()->getVadRoot(),
			stackStart,
			&isWow64,
			&isAddressOutOfSystem32Ntdll,
			&isAddressOutOfWow64Ntdll
		);

		*addr = stackStart;

		if (isWow64) {
			if (isAddressOutOfSystem32Ntdll ^ isAddressOutOfWow64Ntdll) {
				return TRUE;
			}
		}
		else {
			return isAddressOutOfSystem32Ntdll;
		}
	}

	return FALSE;
}

VOID ThreadUtils::CreateThreadNotifyRoutine(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create
) {
	
	if (Create) {

		ULONG64 outAddr;

		SyscallsUtils::SetInformationAltSystemCall(PsGetCurrentProcessId());

		SyscallsUtils::EnableAltSycallForThread(PsGetCurrentThread());

		PEPROCESS eProcess;
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &eProcess);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] PsLookupProcessByProcessId failed\n");
			return;
		}

		PETHREAD eThread;
		status = PsLookupThreadByThreadId(ThreadId, &eThread);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] PsLookupThreadByThreadId failed\n");
			ObDereferenceObject(eProcess);
			return;
		}

		// -----------------------------------------------------------------------
		// Remote thread detection.
		// CreateThreadNotifyRoutine fires in the context of the CREATING thread.
		// IoGetCurrentProcess() = creator; eProcess = host of the new thread.
		// If they differ, this is cross-process thread injection — a foundational
		// primitive for classic injection, process hollowing, and APC abuse.
		//
		// This kernel-callback path catches ALL mechanisms: Win32 API, direct
		// syscall, and driver-level injection — unlike the user-mode hooks which
		// only cover API callers in the injecting process.
		// -----------------------------------------------------------------------
		PEPROCESS creatorProcess = IoGetCurrentProcess();
		if (eProcess != creatorProcess) {
			PVOID startAddr = SafePsGetThreadWin32StartAddress(eThread);

			char msg[220];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"Remote thread injected into '%s' (pid=%llu) startAddr=0x%llX by '%s'",
				PsGetProcessImageFileName(eProcess),
				(ULONG64)PsGetProcessId(eProcess),
				(ULONG64)startAddr,
				PsGetProcessImageFileName(creatorProcess));

			// Scan target process VAD for SEC_IMAGE sections not in its LDR —
			// the attacker likely used NtMapViewOfSection to stage a DLL there
			// before creating this remote thread to run it.
			VadUtils::ScanForHiddenMappings(eProcess, CallbackObjects::GetNotifQueue());

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
			if (kernelNotif) {
				RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
				SET_CRITICAL(*kernelNotif);
				SET_STACK_BASE_VAD_CHECK(*kernelNotif);
				kernelNotif->isPath          = FALSE;
				kernelNotif->pid             = PsGetProcessId(creatorProcess);
				kernelNotif->scoopedAddress  = (ULONG64)startAddr;
				RtlCopyMemory(kernelNotif->procName,
				              PsGetProcessImageFileName(creatorProcess), 14);
				RtlCopyMemory(kernelNotif->targetProcName,
				              PsGetProcessImageFileName(eProcess), 14);

				SIZE_T msgLen = strlen(msg);
				kernelNotif->msg = (char*)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, msgLen + 1, 'msg');
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

		ThreadUtils threadUtils = ThreadUtils(
			IoGetCurrentProcess(),
			PsGetCurrentThread()
		);

		if (threadUtils.isProcessImageTampered()) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Process Image Tampering";

				SET_CRITICAL(*kernelNotif);
				SET_PROC_VAD_CHECK(*kernelNotif);
				InjectionTaintTracker::MarkTainted(PsGetCurrentProcessId());

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				char procName[15];
				RtlCopyMemory(procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);
				RtlCopyMemory(kernelNotif->procName, procName, 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg)+1);
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

		if (threadUtils.isThreadInjected(&outAddr)) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Injected Thread";

				SET_CRITICAL(*kernelNotif);
				SET_STACK_BASE_VAD_CHECK(*kernelNotif);

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');
				kernelNotif->scoopedAddress = outAddr;

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

		ObDereferenceObject(eThread);
		ObDereferenceObject(eProcess);
	}
	else {
		SyscallsUtils::DisableAltSycallForThread(PsGetCurrentThread());
	}
}

// Exposed for Ps*Notify integrity check in HookDetection
PVOID ThreadUtils::s_NotifyFn = (PVOID)CreateThreadNotifyRoutine;

// ---------------------------------------------------------------------------
// PsSetCreateThreadNotifyRoutineEx — Win10 1703+.
// PsCreateThreadNotifySubsystems (=0) extends coverage to Pico process
// threads (WSL1).  Resolved at runtime; falls back to base routine.
// Removal always uses PsRemoveCreateThreadNotifyRoutine for both variants.
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnPsSetCreateThreadNotifyRoutineEx)(
    PSCREATETHREADNOTIFYTYPE NotifyType,
    PVOID                    NotifyInformation);

static pfnPsSetCreateThreadNotifyRoutineEx g_pSetThreadEx  = nullptr;
static BOOLEAN                             g_usedThreadEx  = FALSE;

VOID ThreadUtils::setThreadNotificationCallback() {

	// Prefer Ex (subsystem-aware) — covers Win32 + Pico (WSL1) threads.
	UNICODE_STRING usEx;
	RtlInitUnicodeString(&usEx, L"PsSetCreateThreadNotifyRoutineEx");
	g_pSetThreadEx = (pfnPsSetCreateThreadNotifyRoutineEx)
	    MmGetSystemRoutineAddress(&usEx);

	if (g_pSetThreadEx) {
		NTSTATUS status = g_pSetThreadEx(
		    PsCreateThreadNotifySubsystems,
		    (PVOID)CreateThreadNotifyRoutine);
		if (NT_SUCCESS(status)) {
			g_usedThreadEx = TRUE;
			DbgPrint("[+] PsSetCreateThreadNotifyRoutineEx (subsystems) success\n");
			return;
		}
		DbgPrint("[-] PsSetCreateThreadNotifyRoutineEx failed — falling back\n");
	}

	// Fallback: Win32 only
	NTSTATUS status = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status))
		DbgPrint("[-] PsSetCreateThreadNotifyRoutine failed\n");
	else
		DbgPrint("[+] PsSetCreateThreadNotifyRoutine success\n");
}

VOID ThreadUtils::unsetThreadNotificationCallback() {

	// PsRemoveCreateThreadNotifyRoutine removes callbacks registered by either
	// PsSetCreateThreadNotifyRoutine or PsSetCreateThreadNotifyRoutineEx.
	NTSTATUS status = PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status))
		DbgPrint("[-] PsRemoveCreateThreadNotifyRoutine failed\n");
	else
		DbgPrint("[+] PsRemoveCreateThreadNotifyRoutine success\n");
}