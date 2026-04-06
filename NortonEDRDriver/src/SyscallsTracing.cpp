#include "Globals.h"
#include "Deception.h"

// User-mode access masks not defined in kernel headers
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION  0x0040
#endif

PSSDT_TABLE SyscallsUtils::ssdtTable = nullptr;
PFUNCTION_MAP SyscallsUtils::exportsMap = nullptr;
ZwSetInformationProcess SyscallsUtils::pZwSetInformationProcess = nullptr;
RegionTracker* SyscallsUtils::vmRegionTracker = nullptr;
HANDLE SyscallsUtils::lastNotifedCidStackCorrupt = 0;

// Fixed Syscall IDs from Win10 1507 to Win11 24H2
// Sourced from: https://j00ru.vexillium.org/syscalls/nt/64/

ULONG SyscallsUtils::NtAllocId = 0x0018;
ULONG SyscallsUtils::NtWriteId = 0x003a;
ULONG SyscallsUtils::NtProtectId = 0x0050;
ULONG SyscallsUtils::NtFreeId = 0x001e;
ULONG SyscallsUtils::NtReadId = 0x0006;
ULONG SyscallsUtils::NtWriteFileId = 0x0008;
ULONG SyscallsUtils::NtQueueApcThreadId = 0x0045;
ULONG SyscallsUtils::NtMapViewOfSectionId = 0x0028;
ULONG SyscallsUtils::NtResumeThreadId = 0x0052;
ULONG SyscallsUtils::NtContinueId = 0x0043;

// Variable Syscalls IDs within the same Win versions range

ULONG SyscallsUtils::NtQueueApcThreadExId = 0;
ULONG SyscallsUtils::NtSetContextThreadId = 0;
ULONG SyscallsUtils::NtContinueEx = 0;
// Stable at 0x0041 across Win10 1507 through Win11 24H2 (j00ru's syscall table)
ULONG SyscallsUtils::NtAdjustPrivilegesTokenId = 0x0041;

// Fixed: NtOpenProcess is 0x0026 across all Win10/11 builds (j00ru's table)
ULONG SyscallsUtils::NtOpenProcessId = 0x0026;
// Variable: resolved at runtime via SSDT in InitIds()
ULONG SyscallsUtils::NtCreateThreadExId = 0;
ULONG SyscallsUtils::NtSuspendThreadId = 0;
ULONG SyscallsUtils::NtCreateSectionId = 0;
ULONG SyscallsUtils::NtUnmapViewOfSectionId = 0;
ULONG SyscallsUtils::NtLoadDriverId = 0;

BufferQueue* SyscallsUtils::bufQueue = nullptr;
StackUtils* SyscallsUtils::stackUtils = nullptr;

BOOLEAN SyscallsUtils::tracingEnabed() {
	return isTracingEnabled;
}

VOID SyscallsUtils::enableTracing() {
	isTracingEnabled = TRUE;
}

VOID SyscallsUtils::disableTracing() {
	isTracingEnabled = FALSE;
}

VOID SyscallsUtils::InitStackUtils() {

	stackUtils = (StackUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(StackUtils), 'stku');
	if (!stackUtils) {
		DbgPrint("[-] Failed to allocate memory for StackUtils\n");
		return;
	}

}

ULONGLONG SyscallsUtils::LeakPspAltSystemCallHandlers(ULONGLONG rOffset) {

	for (int i = 0; i < 0x100; i++) {
		__try {

			UINT8 sig_bytes[] = { 0x4C, 0x8D, 0x35 };
			ULONGLONG opcodes = *(PULONGLONG)rOffset;

			if (starts_with_signature((ULONGLONG)&opcodes, sig_bytes, sizeof(sig_bytes))) {
				ULONGLONG correctOffset = ((*(PLONGLONG)(rOffset)) >> 24 & 0x0000FFFFFF);
				return rOffset + 7 + correctOffset;
			}
			rOffset += 2;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] Exception\n");
			return NULL;
		}
	}

	return NULL;
};


VOID SyscallsUtils::NtVersionPreCheck() {

	RTL_OSVERSIONINFOW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	NTSTATUS status = RtlGetVersion(&versionInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] Failed to get version info\n");
		return;
	}

	switch (versionInfo.dwBuildNumber) {

		case 10240:{
	
			NtQueueApcThreadExId = 0x014b;
			NtSetContextThreadId = 0x016f;

		};
		case 10586:	{

			NtQueueApcThreadExId = 0x014e;
			NtSetContextThreadId = 0x0172;

		};
		case 14393: {

			NtQueueApcThreadExId = 0x0152;
			NtSetContextThreadId = 0x0178;

		};
		case 15063: {

			NtQueueApcThreadExId = 0x0158;
			NtSetContextThreadId = 0x017e;

		};
		case 16299: {

			NtQueueApcThreadExId = 0x015b;
			NtSetContextThreadId = 0x0181;


		};
		case 17134: {

			NtQueueApcThreadExId = 0x015d;
			NtSetContextThreadId = 0x0183;


		};
		case 17763: {

			NtQueueApcThreadExId = 0x015e;
			NtSetContextThreadId = 0x0184;

		};
		case 18362: {

			NtQueueApcThreadExId = 0x015f;
			NtSetContextThreadId = 0x0185;

		};
		case 18363: {

			NtQueueApcThreadExId = 0x015f;
			NtSetContextThreadId = 0x0185;

		};
		case 19041: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19042: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19043: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19044: {

			NtQueueApcThreadExId = 0x0166;
			NtSetContextThreadId = 0x018d;

		};
		case 19045: {

			NtQueueApcThreadExId = 0x0166;
			NtSetContextThreadId = 0x018d;

		};
		case 20348: {

			NtQueueApcThreadExId = 0x016b;
			NtSetContextThreadId = 0x0193;

		};
		case 22000: {

			NtQueueApcThreadExId = 0x016d;
			NtSetContextThreadId = 0x0195;

		};
		case 22621: {

			NtQueueApcThreadExId = 0x0170;
			NtSetContextThreadId = 0x0198;

		};
		case 22631: {

			NtQueueApcThreadExId = 0x0170;
			NtSetContextThreadId = 0x0198;

		};
		case 25000: {

			NtQueueApcThreadExId = 0x0171;
			NtSetContextThreadId = 0x0199;

		};
		case 26000: {

			NtQueueApcThreadExId = 0x0172;
			NtSetContextThreadId = 0x019a;

		};
		default: {

			NtQueueApcThreadExId = 0;
			NtSetContextThreadId = 0;

		};
	}
}

BOOLEAN SyscallsUtils::SyscallHandler(PKTRAP_FRAME trapFrame) {

	PVOID spoofedAddr = NULL;

	ULONG id = (ULONG)trapFrame->Rax;

	if (lastNotifedCidStackCorrupt == PsGetCurrentProcessId()) {
		return FALSE;
	}

	if (id == NtAllocId || id == NtWriteId || id == NtProtectId) {
		
			if(stackUtils->isStackCorruptedRtlCET(&spoofedAddr)) {

			lastNotifedCidStackCorrupt = PsGetCurrentProcessId();

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) { 

				char* msg = "Corrupted Thread Call Stack";

				SET_WARNING(*kernelNotif);
				SET_SHADOW_STACK_CHECK(*kernelNotif);

				kernelNotif->scoopedAddress = (ULONG64)spoofedAddr;
				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);

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
			return FALSE;
		}
	}
	
	

	PULONGLONG pArg5 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x28);
	PULONGLONG pArg6 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x30);

	ULONGLONG arg5 = 0;
	ULONGLONG arg6 = 0;

	if (MmIsAddressValid(pArg5)) {
		arg5 = *pArg5;
	}

	if (MmIsAddressValid(pArg6)) {
		arg6 = *pArg6;
	}

	if ((ULONG)id == NtAllocId) {		// NtAllocateVirtualMemory

		NtAllocVmHandler(				
			(HANDLE)trapFrame->Rcx,
			(PVOID*)trapFrame->Rdx,
			trapFrame->R8,
			(SIZE_T*)trapFrame->R9,
			(ULONG)arg5,
			(ULONG)arg6
		);
	}
	else if (id == NtResumeThreadId) {   // NtResumeThread

		NtResumeThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(PULONG)trapFrame->Rdx
		);
	}
	else if (id == NtContinueId) {		// NtContinue

		NtContinueHandler(
			(PCONTEXT)trapFrame->Rcx,
			(BOOLEAN)trapFrame->Rdx
		);
	}
	else if (id == 0x0050) {			// NtProtectVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtProtectVirtualMemory");

		NtProtectVmHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(SIZE_T*)trapFrame->R8,
			(ULONG)trapFrame->R9,
			(PULONG)arg5
		);
	}
	else if (id == 0x003a) {			// NtWriteVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtWriteVirtualMemory");

		NtWriteVmHandler(				
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(SIZE_T)trapFrame->R9,
			(PSIZE_T)arg6
		);
	}
	else if (id == 0x0045) {			// NtQueueApcThread | Win 10 -> Win11 24H2

		NtQueueApcThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(PPS_APC_ROUTINE)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PVOID)arg5
		);
	}
	else if (id == NtQueueApcThreadExId) {		 // NtQueueApcThreadEx

		NtQueueApcThreadExHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx,
			(PPS_APC_ROUTINE)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PVOID)arg5,
			(PVOID)arg6
		);

	}
	else if (NtSetContextThreadId != 0 && id == NtSetContextThreadId) {  // NtSetContextThread

		NtSetContextThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx     // PCONTEXT
		);
	}
	else if (id == NtAdjustPrivilegesTokenId) {  // NtAdjustPrivilegesToken

		NtAdjustPrivilegesTokenHandler(
			(HANDLE)trapFrame->Rcx,
			(BOOLEAN)trapFrame->Rdx,
			(PTOKEN_PRIVILEGES)trapFrame->R8,
			(ULONG)trapFrame->R9,
			(PTOKEN_PRIVILEGES)arg5,
			(PULONG)arg6
		);
	}
	else if (id == 0x0054) {	        // NtReadVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtReadVirtualMemory");

		NtReadVmHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(SIZE_T)trapFrame->R9,
			(PSIZE_T)arg5
		);
	}
	else if (id == 0x0008) {		// NtWriteFile

		PULONGLONG pArg7 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x38);
		PULONGLONG pArg8 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x40);
		PULONGLONG pArg9 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x48);

		ULONGLONG arg7 = 0;
		ULONGLONG arg8 = 0;
		ULONGLONG arg9 = 0;

		if (MmIsAddressValid(pArg7)) {
			arg7 = *pArg7;
		}
		else {
			return FALSE;
		}

		if (MmIsAddressValid(pArg8)) {
			arg8 = *pArg8;
		}
		else {
			return FALSE;
		}

		if (MmIsAddressValid(pArg9)) {
			arg9 = *pArg9;
		}
		else {
			return FALSE;
		}

		NtWriteFileHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx,
			(PIO_APC_ROUTINE)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PIO_STATUS_BLOCK)arg5,
			(PVOID)arg6,
			(ULONG)arg7,
			(PLARGE_INTEGER)arg8,
			(PULONG)arg9
		);
	}
	else if (id == NtOpenProcessId) {		// NtOpenProcess

		NtOpenProcessHandler(
			(HANDLE)trapFrame->Rcx,        // ProcessHandle*
			(ACCESS_MASK)trapFrame->Rdx,   // DesiredAccess
			(PVOID)trapFrame->R8,          // ObjectAttributes
			(PCLIENT_ID)trapFrame->R9      // ClientId
		);
	}
	else if (NtCreateThreadExId != 0 && id == NtCreateThreadExId) {  // NtCreateThreadEx

		PULONGLONG pArg7 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x38);
		ULONGLONG  arg7  = MmIsAddressValid(pArg7) ? *pArg7 : 0;

		NtCreateThreadExHandler(
			(PHANDLE)trapFrame->Rcx,       // ThreadHandle*
			(ACCESS_MASK)trapFrame->Rdx,   // DesiredAccess
			(PVOID)trapFrame->R8,          // ObjectAttributes
			(HANDLE)trapFrame->R9,         // ProcessHandle
			(PVOID)arg5,                   // StartRoutine
			(PVOID)arg6,                   // Argument
			(ULONG)arg7,                   // CreateFlags
			0, 0, 0, nullptr               // remaining args not inspected
		);
	}
	else if (NtSuspendThreadId != 0 && id == NtSuspendThreadId) {  // NtSuspendThread

		NtSuspendThreadHandler(
			(HANDLE)trapFrame->Rcx,   // ThreadHandle
			(PULONG)trapFrame->Rdx    // PreviousSuspendCount
		);
	}
	else if (NtCreateSectionId != 0 && id == NtCreateSectionId) {  // NtCreateSection

		PULONGLONG pArg7 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x38);
		ULONGLONG  arg7  = MmIsAddressValid(pArg7) ? *pArg7 : 0;

		NtCreateSectionHandler(
			(PHANDLE)trapFrame->Rcx,          // SectionHandle*
			(ACCESS_MASK)trapFrame->Rdx,      // DesiredAccess
			(PVOID)trapFrame->R8,             // ObjectAttributes
			(PLARGE_INTEGER)trapFrame->R9,    // MaximumSize
			(ULONG)arg5,                      // SectionPageProtection
			(ULONG)arg6,                      // AllocationAttributes
			(HANDLE)arg7                      // FileHandle
		);
	}
	else if (id == NtMapViewOfSectionId) {  // NtMapViewOfSection

		PULONGLONG pArg7  = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x38);
		PULONGLONG pArg8  = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x40);
		PULONGLONG pArg9  = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x48);
		PULONGLONG pArg10 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x50);
		ULONGLONG  arg7   = MmIsAddressValid(pArg7)  ? *pArg7  : 0;
		ULONGLONG  arg8   = MmIsAddressValid(pArg8)  ? *pArg8  : 0;
		ULONGLONG  arg9   = MmIsAddressValid(pArg9)  ? *pArg9  : 0;
		ULONGLONG  arg10  = MmIsAddressValid(pArg10) ? *pArg10 : 0;

		NtMapViewOfSectionHandler(
			(HANDLE)trapFrame->Rcx,       // SectionHandle
			(HANDLE)trapFrame->Rdx,       // ProcessHandle
			(PVOID*)trapFrame->R8,        // BaseAddress*
			(ULONG_PTR)trapFrame->R9,     // ZeroBits
			(SIZE_T)arg5,                 // CommitSize
			(PLARGE_INTEGER)arg6,         // SectionOffset
			(PSIZE_T)arg7,                // ViewSize
			(ULONG)arg8,                  // InheritDisposition
			(ULONG)arg9,                  // AllocationType
			(ULONG)arg10                  // Win32Protect
		);
	}
	else if (NtUnmapViewOfSectionId != 0 && id == NtUnmapViewOfSectionId) {  // NtUnmapViewOfSection

		NtUnmapViewOfSectionHandler(
			(HANDLE)trapFrame->Rcx,  // ProcessHandle
			(PVOID)trapFrame->Rdx    // BaseAddress
		);
	}
	else if (NtLoadDriverId != 0 && id == NtLoadDriverId) {  // NtLoadDriver — always suspicious

		NtLoadDriverHandler(
			(PUNICODE_STRING)trapFrame->Rcx  // DriverServiceName
		);
	}

	return TRUE;
}

BOOLEAN SyscallsUtils::isSyscallDirect(ULONG64 Rip, char* syscallName) 
{
	PEPROCESS curproc = IoGetCurrentProcess();

	PPS_PROTECTION procProtection = PsGetProcessProtection(curproc);

	if (procProtection->Level == 0x0) {

		KAPC_STATE apcState;

		KeStackAttachProcess(curproc, &apcState);

		BYTE op = *(BYTE*)Rip;

		BOOLEAN isWow64 = FALSE;
		BOOLEAN isAddressOutOfSystem32Ntdll = FALSE;
		BOOLEAN isAddressOutOfWow64Ntdll = FALSE;

		RTL_AVL_TREE* root = (RTL_AVL_TREE*)((PUCHAR)IoGetCurrentProcess() + OffsetsMgt::GetOffsets()->VadRoot);

		VadUtils::isAddressOutOfSpecificDll(
			(PRTL_BALANCED_NODE)root,
			(ULONG64)Rip,
			&isWow64,
			&isAddressOutOfSystem32Ntdll,
			&isAddressOutOfWow64Ntdll,
			L"\\Windows\\System32\\ntdll.dll",
			L"\\Windows\\SysWOW64\\ntdll.dll"
		);

		BOOL isSyscallDirect = FALSE;

		if (isWow64) {
			if (isAddressOutOfSystem32Ntdll ^ isAddressOutOfWow64Ntdll) {
				isSyscallDirect = TRUE;
			}
		}

		else {
			isSyscallDirect = isAddressOutOfSystem32Ntdll;
		}

		if (isSyscallDirect && op == 0xC3) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "NT Syscall did not came from Ntdll";

				SET_WARNING(*kernelNotif);
				SET_SYSCALL_CHECK(*kernelNotif);

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg) + 1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				} else {
					ExFreePool(kernelNotif);
				}
			}
		}

		KeUnstackDetachProcess(&apcState);
	}

	return FALSE;
}

VOID SyscallsUtils::UnInitAltSyscallHandler() {

	UNICODE_STRING usPsRegisterAltSystemCallHandler;
	RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
	pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

	ULONGLONG pPspAltSystemCallHandlers = LeakPspAltSystemCallHandlers((ULONGLONG)pPsRegisterAltSystemCallHandler);

	DbgPrint("[*] PspAltSystemCallHandlers: %llx\n", pPspAltSystemCallHandlers);

	LONGLONG* pAltSystemCallHandlers = (LONGLONG*)pPspAltSystemCallHandlers;

	if (pAltSystemCallHandlers[1] != 0x0) {
		pAltSystemCallHandlers[1] = 0x0000000000000000;
	}
}

BOOLEAN SyscallsUtils::InitAltSyscallHandler() {

	UNICODE_STRING usPsRegisterAltSystemCallHandler;
	RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
	
	pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

	UNICODE_STRING usZwSetInformationProcess;
	RtlInitUnicodeString(&usZwSetInformationProcess, L"ZwSetInformationProcess");

	pZwSetInformationProcess = (ZwSetInformationProcess)MmGetSystemRoutineAddress(&usZwSetInformationProcess);

	if (MmIsAddressValid(pPsRegisterAltSystemCallHandler)) {

		UNICODE_STRING usPsRegisterAltSystemCallHandler;
		RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");

		pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

		ULONGLONG pPspAltSystemCallHandlers = LeakPspAltSystemCallHandlers((ULONGLONG)pPsRegisterAltSystemCallHandler);

		LONGLONG* pAltSystemCallHandlers = (LONGLONG*)pPspAltSystemCallHandlers;
		if (pAltSystemCallHandlers[1] == 0) {

			NTSTATUS status = pPsRegisterAltSystemCallHandler((PVOID)SyscallsUtils::SyscallHandler, 1);

			if (NT_SUCCESS(status)) {

				this->enableTracing();
				DbgPrint("[+] Altsyscall handler registered !\n");
				return STATUS_SUCCESS;
			}
			else {
				DbgPrint("[-] Altsyscall handler already registered !\n");
			}
		}
	}
	else {
		DbgPrint("[-] Failed to get PsRegisterAltSystemCallHandler\n");
	}

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN SyscallsUtils::SetInformationAltSystemCall(HANDLE pid) {

	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	HANDLE hProcess;
	HANDLE qwPid;	

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = 0;
	hProcess = 0;

	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId))) {

		qwPid = (HANDLE)clientId.UniqueProcess;

		if (NT_SUCCESS(pZwSetInformationProcess(
			hProcess,
			0x64,
			&qwPid,
			1
		))) {

			ZwClose(hProcess);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN SyscallsUtils::UnsetInformationAltSystemCall(HANDLE pid) {

	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	HANDLE hProcess;
	HANDLE qwPid;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = 0;
	hProcess = 0;

	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId))) {

		qwPid = (HANDLE)clientId.UniqueProcess;

		if (NT_SUCCESS(pZwSetInformationProcess(
			hProcess,
			0x64,
			&qwPid,
			0
		))) {

			ZwClose(hProcess);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}


VOID SyscallsUtils::EnableAltSycallForThread(PETHREAD pEthread) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + OffsetsMgt::GetOffsets()->Header);
	header->DebugActive = 0x20;
}

VOID SyscallsUtils::DisableAltSycallForThread(PETHREAD pEthread) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + 
		OffsetsMgt::GetOffsets()->Header);
	header->DebugActive = 0x0;
}

UCHAR SyscallsUtils::GetAltSyscallStateForThread(PETHREAD pEthrad) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthrad + OffsetsMgt::GetOffsets()->Header);
	return header->DebugActive;
}

VOID SyscallsUtils::InitExportsMap(PFUNCTION_MAP map) {
	exportsMap = map;
}

VOID SyscallsUtils::InitSsdtTable(PSSDT_TABLE table) {
	ssdtTable = table;
}

VOID SyscallsUtils::InitIds() {

	UNICODE_STRING usNtAllocateVirtualMemory;
	RtlInitUnicodeString(&usNtAllocateVirtualMemory, L"NtAllocateVirtualMemory");
	ULONG ntAllocSsn = getSSNByName(ssdtTable, &usNtAllocateVirtualMemory, exportsMap);

	NtAllocId = ntAllocSsn;

	UNICODE_STRING usNtFreeVirtualMemory;
	RtlInitUnicodeString(&usNtFreeVirtualMemory, L"NtFreeVirtualMemory");
	ULONG ntFreeSsn = getSSNByName(ssdtTable, &usNtFreeVirtualMemory, exportsMap);
	NtFreeId = ntFreeSsn;

	// Resolve variable SSNs that change across Win10/11 builds
	UNICODE_STRING usNtMapViewOfSection;
	RtlInitUnicodeString(&usNtMapViewOfSection, L"NtMapViewOfSection");
	NtMapViewOfSectionId = getSSNByName(ssdtTable, &usNtMapViewOfSection, exportsMap);

	UNICODE_STRING usNtCreateThreadEx;
	RtlInitUnicodeString(&usNtCreateThreadEx, L"NtCreateThreadEx");
	NtCreateThreadExId = getSSNByName(ssdtTable, &usNtCreateThreadEx, exportsMap);

	UNICODE_STRING usNtSuspendThread;
	RtlInitUnicodeString(&usNtSuspendThread, L"NtSuspendThread");
	NtSuspendThreadId = getSSNByName(ssdtTable, &usNtSuspendThread, exportsMap);

	UNICODE_STRING usNtCreateSection;
	RtlInitUnicodeString(&usNtCreateSection, L"NtCreateSection");
	NtCreateSectionId = getSSNByName(ssdtTable, &usNtCreateSection, exportsMap);

	UNICODE_STRING usNtUnmapViewOfSection;
	RtlInitUnicodeString(&usNtUnmapViewOfSection, L"NtUnmapViewOfSection");
	NtUnmapViewOfSectionId = getSSNByName(ssdtTable, &usNtUnmapViewOfSection, exportsMap);

	UNICODE_STRING usNtLoadDriver;
	RtlInitUnicodeString(&usNtLoadDriver, L"NtLoadDriver");
	NtLoadDriverId = getSSNByName(ssdtTable, &usNtLoadDriver, exportsMap);

	// Resolve MmGetFileNameForSection for ntdll-remap detection in NtMapViewOfSectionHandler.
	// This is an ntoskrnl export (undocumented but stable; returns allocated OBJECT_NAME_INFORMATION
	// that caller must free with ExFreePool).
	UNICODE_STRING usMmGetFileName;
	RtlInitUnicodeString(&usMmGetFileName, L"MmGetFileNameForSection");
	g_MmGetFileNameForSection = (pfnMmGetFileNameForSection)
	    MmGetSystemRoutineAddress(&usMmGetFileName);
}

// Function pointer for MmGetFileNameForSection — resolved once in InitIds().
// Signature: returns allocated OBJECT_NAME_INFORMATION; caller frees with ExFreePool.
typedef NTSTATUS (*pfnMmGetFileNameForSection)(PVOID Section, POBJECT_NAME_INFORMATION* FileName);
static pfnMmGetFileNameForSection g_MmGetFileNameForSection = nullptr;

// ---------------------------------------------------------------------------
// Private helper — allocates and enqueues a KERNEL_STRUCTURED_NOTIFICATION
// for a syscall-level detection. Caller provides the scoped address, message,
// calling process, optional target process, and severity flag.
// ---------------------------------------------------------------------------
static VOID EmitSyscallNotif(
	ULONG64   scoopedAddr,
	const char* msg,
	PEPROCESS callerProcess,
	PEPROCESS targetProcess,   // may be nullptr
	BOOLEAN   critical
) {
	PKERNEL_STRUCTURED_NOTIFICATION n = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
	if (!n) return;

	RtlZeroMemory(n, sizeof(KERNEL_STRUCTURED_NOTIFICATION));

	if (critical) { SET_CRITICAL(*n); } else { SET_WARNING(*n); }
	SET_SYSCALL_CHECK(*n);

	n->isPath          = FALSE;
	n->pid             = PsGetProcessId(callerProcess);
	n->scoopedAddress  = scoopedAddr;
	RtlCopyMemory(n->procName, PsGetProcessImageFileName(callerProcess), 14);
	if (targetProcess)
		RtlCopyMemory(n->targetProcName, PsGetProcessImageFileName(targetProcess), 14);

	SIZE_T msgLen = strlen(msg) + 1;
	n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
	if (n->msg) {
		RtlCopyMemory(n->msg, msg, msgLen);
		if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
			ExFreePool(n->msg);
			ExFreePool(n);
		}
	} else {
		ExFreePool(n);
	}
}

// NtAllocateVirtualMemory — flag RWX allocations; cross-process is Critical.
VOID SyscallsUtils::NtAllocVmHandler(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
) {
	// PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
	if (Protect != 0x40 && Protect != 0x80) return;

	BOOLEAN remote = (ProcessHandle != (HANDLE)-1);
	const char* msg = remote
		? "NtAllocateVirtualMemory: remote RWX allocation (cross-process shellcode staging)"
		: "NtAllocateVirtualMemory: local RWX allocation";

	EmitSyscallNotif(
		BaseAddress && MmIsAddressValid(BaseAddress) ? (ULONG64)*BaseAddress : 0,
		msg,
		IoGetCurrentProcess(),
		nullptr,
		remote   // remote = Critical, local = Warning
	);
}

VOID SyscallsUtils::NtProtectVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
) {

	if (NewAccessProtection & PAGE_EXECUTE) {

		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, *NumberOfBytesToProtect, 'msg');

		if (buffer) {

			RtlCopyMemory(buffer, BaseAddress, *NumberOfBytesToProtect);

			// PE scan: check if the region being made executable contains a PE header
			PeScanner::CheckBufferForPeHeader(
				buffer,
				*NumberOfBytesToProtect,
				BaseAddress,
				PsGetProcessId(PsGetCurrentProcess()),
				PsGetProcessImageFileName(PsGetCurrentProcess()),
				CallbackObjects::GetNotifQueue()
			);

			RAW_BUFFER rawBuf;

			rawBuf.buffer = (BYTE*)buffer;
			rawBuf.size = *NumberOfBytesToProtect;
			rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
			RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

			if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
				ExFreePool(rawBuf.buffer);
			}
		}
	}
}

VOID SyscallsUtils::NtWriteVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
) {

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytesToWrite, 'msg');

	if (buffer) {

		RtlCopyMemory(buffer, Buffer, NumberOfBytesToWrite);

		// PE scan: flag cross-process writes that carry a PE header
		if (ProcessHandle != (HANDLE)-1) {
			PeScanner::CheckBufferForPeHeader(
				buffer,
				NumberOfBytesToWrite,
				BaseAddress,
				PsGetProcessId(PsGetCurrentProcess()),
				PsGetProcessImageFileName(PsGetCurrentProcess()),
				CallbackObjects::GetNotifQueue()
			);
		}

		RAW_BUFFER rawBuf;

		rawBuf.buffer = (BYTE*)buffer;
		rawBuf.size = NumberOfBytesToWrite;
		rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
		RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

		if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
			ExFreePool(rawBuf.buffer);
		}
	}
}

VOID SyscallsUtils::NtWriteFileHandler(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
) {

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Length, 'msg');

	if (buffer) {

		RtlCopyMemory(buffer, Buffer, Length);

		RAW_BUFFER rawBuf;

		rawBuf.buffer = (BYTE*)buffer;
		rawBuf.size = Length;
		rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
		RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

		if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
			ExFreePool(rawBuf.buffer);
		}
	}
}

// NtReadVirtualMemory — cross-process reads only; Critical if target is lsass.
VOID SyscallsUtils::NtReadVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
) {
	if (ProcessHandle == (HANDLE)-1) return; // self-read, not interesting

	PEPROCESS targetProcess = nullptr;
	NTSTATUS status = ObReferenceObjectByHandle(
		ProcessHandle, PROCESS_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetProcess, nullptr);
	if (!NT_SUCCESS(status)) return;

	PEPROCESS callerProcess = IoGetCurrentProcess();

	// Detect if the target is lsass for elevated severity
	char targetName[15] = {};
	RtlCopyMemory(targetName, PsGetProcessImageFileName(targetProcess), 14);

	BOOLEAN isSensitive = FALSE;
	char lower[15] = {};
	for (int i = 0; i < 14 && targetName[i]; i++)
		lower[i] = (targetName[i] >= 'A' && targetName[i] <= 'Z')
		          ? (char)(targetName[i] + 32) : targetName[i];
	if (RtlCompareMemory(lower, "lsass.exe", 9) == 9) isSensitive = TRUE;

	EmitSyscallNotif(
		(ULONG64)BaseAddress,
		isSensitive
			? "NtReadVirtualMemory: cross-process read from lsass (credential theft attempt)"
			: "NtReadVirtualMemory: cross-process memory read",
		callerProcess,
		targetProcess,
		isSensitive  // lsass read = Critical
	);

	// Deception: if the caller provided a kernel-accessible output buffer,
	// patch any NTLM-hash-like sequences with the canary hash.
	// This pre-call handler fires before the actual memory copy; for post-read
	// buffer corruption the HookDll's ReadProcessMemory hook is the primary path.
	// Here we handle the case where Buffer is already a kernel-mode address
	// (e.g., a kernel component reading LSASS on behalf of a user request).
	if (isSensitive && Buffer && NumberOfBytesToRead > 0) {
		if ((ULONG_PTR)Buffer > (ULONG_PTR)MmHighestUserAddress) {
			// Kernel-mode buffer — safe to write directly
			DeceptionEngine::PatchLsassReadBuffer(Buffer, NumberOfBytesToRead);
		}
		// User-mode buffer is handled post-read by HookDll's ReadProcessMemory hook.
	}

	ObDereferenceObject(targetProcess);
}

// NtQueueApcThread — flag cross-process APC injection.
VOID SyscallsUtils::NtQueueApcThreadHandler(
	HANDLE ThreadHandle,
	PPS_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3
) {
	if (!ApcRoutine) return;

	PETHREAD targetThread = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		ThreadHandle, THREAD_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetThread, nullptr))) return;

	PEPROCESS targetProcess  = IoThreadToProcess(targetThread);
	PEPROCESS callerProcess  = IoGetCurrentProcess();
	BOOLEAN   crossProcess   = (targetProcess != callerProcess);

	if (crossProcess) {
		EmitSyscallNotif(
			(ULONG64)ApcRoutine,
			"NtQueueApcThread: cross-process APC injection",
			callerProcess, targetProcess, TRUE);
	}

	ObDereferenceObject(targetThread);
}

// NtQueueApcThreadEx — same as above but with UserApcReserveHandle (Win8+).
VOID SyscallsUtils::NtQueueApcThreadExHandler(
	HANDLE ThreadHandle,
	HANDLE UserApcReserveHandle,
	PPS_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3
) {
	if (!ApcRoutine) return;

	PETHREAD targetThread = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		ThreadHandle, THREAD_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetThread, nullptr))) return;

	PEPROCESS targetProcess = IoThreadToProcess(targetThread);
	PEPROCESS callerProcess = IoGetCurrentProcess();

	if (targetProcess != callerProcess) {
		EmitSyscallNotif(
			(ULONG64)ApcRoutine,
			"NtQueueApcThreadEx: cross-process APC injection (extended)",
			callerProcess, targetProcess, TRUE);
	}

	ObDereferenceObject(targetThread);
}

// NtContinue — flag execution redirected into private executable memory.
// Typical attack: process hollowing / shellcode loader sets context then
// calls NtContinue to jump into injected code.
VOID SyscallsUtils::NtContinueHandler(
	PCONTEXT Context,
	BOOLEAN TestAlert
) {
	if (!Context || !MmIsAddressValid(Context)) return;

	ULONG64 rip = Context->Rip;
	// Only inspect user-mode addresses
	if (!rip || rip >= 0x00007FFFFFFFFFFF) return;

	// Skip protected processes — their pages aren't queryable this way
	PPS_PROTECTION prot = PsGetProcessProtection(IoGetCurrentProcess());
	if (prot->Level != 0x0) return;

	MEMORY_BASIC_INFORMATION mbi = {};
	SIZE_T retLen = 0;
	NTSTATUS status = ZwQueryVirtualMemory(
		NtCurrentProcess(),
		(PVOID)rip,
		MemoryBasicInformation,
		&mbi, sizeof(mbi), &retLen);
	if (!NT_SUCCESS(status)) return;

	// Private memory with an execute bit set = suspicious
	BOOLEAN isExec    = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
	                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	BOOLEAN isPrivate = (mbi.Type == 0x20000); // MEM_PRIVATE

	if (!isExec || !isPrivate) return;

	EmitSyscallNotif(
		rip,
		"NtContinue: execution redirected to private executable region (possible shellcode)",
		IoGetCurrentProcess(), nullptr, FALSE);
}

// NtResumeThread — flag cross-process thread resumption (process hollowing).
VOID SyscallsUtils::NtResumeThreadHandler(
	HANDLE ThreadHandle,
	PULONG SuspendCount
) {
	PETHREAD targetThread = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		ThreadHandle, THREAD_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetThread, nullptr))) return;

	PEPROCESS targetProcess = IoThreadToProcess(targetThread);
	PEPROCESS callerProcess = IoGetCurrentProcess();
	BOOLEAN   crossProcess  = (targetProcess != callerProcess);

	ObDereferenceObject(targetThread);

	if (!crossProcess) return;

	EmitSyscallNotif(
		0,
		"NtResumeThread: cross-process thread resumption (possible process hollowing)",
		callerProcess, targetProcess, FALSE);
}

// NtSetContextThread — flag cross-process thread context hijacking.
// scoopedAddress is the new RIP from the supplied CONTEXT.
VOID SyscallsUtils::NtSetContextThreadHandler(
	HANDLE ThreadHandle,
	PVOID  Context
) {
	if (!Context || !MmIsAddressValid(Context)) return;

	PETHREAD targetThread = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		ThreadHandle, THREAD_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetThread, nullptr))) return;

	PEPROCESS targetProcess = IoThreadToProcess(targetThread);
	PEPROCESS callerProcess = IoGetCurrentProcess();
	BOOLEAN   crossProcess  = (targetProcess != callerProcess);

	ULONG64 newRip   = 0;
	ULONG   ctxFlags = 0;
	ULONG64 dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0;

	__try {
		PCONTEXT ctx = (PCONTEXT)Context;
		ctxFlags = ctx->ContextFlags;
		if (crossProcess && (ctxFlags & CONTEXT_CONTROL))
			newRip = ctx->Rip;
		if (ctxFlags & CONTEXT_DEBUG_REGISTERS) {
			dr0 = ctx->Dr0; dr1 = ctx->Dr1;
			dr2 = ctx->Dr2; dr3 = ctx->Dr3;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	if (crossProcess) {
		EmitSyscallNotif(
			newRip,
			"NtSetContextThread: cross-process thread context hijack",
			callerProcess, targetProcess, TRUE);
	}

	// VEH hardware breakpoint bypass detection:
	// Setting hardware BPs (DR0-DR3) on hooked addresses causes EXCEPTION_SINGLE_STEP
	// to fire before the inline-hook JMP executes.  A registered VEH can then
	// redirect RIP past the hook — bypassing our detour entirely.
	if ((ctxFlags & CONTEXT_DEBUG_REGISTERS) && (dr0 || dr1 || dr2 || dr3)) {
		char msg[256];
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtSetContextThread: CONTEXT_DEBUG_REGISTERS Dr0=0x%llX Dr1=0x%llX "
			"Dr2=0x%llX Dr3=0x%llX — hardware BP may bypass inline hooks via VEH%s",
			(unsigned long long)dr0, (unsigned long long)dr1,
			(unsigned long long)dr2, (unsigned long long)dr3,
			crossProcess ? " (cross-process)" : "");
		EmitSyscallNotif(0, msg, callerProcess, crossProcess ? targetProcess : nullptr,
			crossProcess /* cross-process = Critical, same-process = Warning */);
	}

	ObDereferenceObject(targetThread);
}

// NtOpenProcess — flag injection-capable access flags on foreign processes.
// Critical if target is lsass; Warning otherwise.
VOID SyscallsUtils::NtOpenProcessHandler(
	HANDLE      ProcessHandle,
	ACCESS_MASK DesiredAccess,
	PVOID       ObjectAttributes,
	PCLIENT_ID  ClientId
) {
	// Flag any combination of VM or thread creation rights
	const ACCESS_MASK kInjectionMask =
		0x0002 |  // PROCESS_CREATE_THREAD
		0x0008 |  // PROCESS_VM_OPERATION
		0x0010 |  // PROCESS_VM_READ
		0x0020;   // PROCESS_VM_WRITE

	if (!(DesiredAccess & kInjectionMask)) return;

	PEPROCESS targetProcess = nullptr;
	HANDLE    targetPid     = nullptr;
	if (ClientId && MmIsAddressValid(ClientId)) {
		__try { targetPid = ClientId->UniqueProcess; } __except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	if (targetPid) {
		PsLookupProcessByProcessId(targetPid, &targetProcess);
	}

	BOOLEAN isSensitive = FALSE;
	if (targetProcess) {
		char lower[15] = {};
		char* name = PsGetProcessImageFileName(targetProcess);
		for (int i = 0; i < 14 && name[i]; i++)
			lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? (char)(name[i] + 32) : name[i];
		if (RtlCompareMemory(lower, "lsass.exe", 9) == 9) isSensitive = TRUE;
	}

	EmitSyscallNotif(
		(ULONG64)targetPid,
		isSensitive
			? "NtOpenProcess: injection-capable access to lsass (credential theft)"
			: "NtOpenProcess: injection-capable access to foreign process",
		IoGetCurrentProcess(),
		targetProcess,
		isSensitive
	);

	if (targetProcess) ObDereferenceObject(targetProcess);
}

// NtCreateThreadEx — flag remote thread creation (classic injection) and
// local thread creation via direct syscall (bypasses CreateThread telemetry).
VOID SyscallsUtils::NtCreateThreadExHandler(
	PHANDLE     ThreadHandle,
	ACCESS_MASK DesiredAccess,
	PVOID       ObjectAttributes,
	HANDLE      ProcessHandle,
	PVOID       StartRoutine,
	PVOID       Argument,
	ULONG       CreateFlags,
	SIZE_T      ZeroBits,
	SIZE_T      StackSize,
	SIZE_T      MaximumStackSize,
	PVOID       AttributeList
) {
	BOOLEAN crossProcess = (ProcessHandle != (HANDLE)-1);

	EmitSyscallNotif(
		(ULONG64)StartRoutine,
		crossProcess
			? "NtCreateThreadEx: remote thread creation (classic injection primitive)"
			: "NtCreateThreadEx: local thread via direct syscall (hook bypass)",
		IoGetCurrentProcess(),
		nullptr,
		crossProcess  // cross-process = Critical; local = Warning
	);
}

// NtSuspendThread — flag cross-process suspension (APC injection / hollowing step).
VOID SyscallsUtils::NtSuspendThreadHandler(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
) {
	PETHREAD targetThread = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		ThreadHandle, THREAD_QUERY_INFORMATION, nullptr,
		UserMode, (PVOID*)&targetThread, nullptr))) return;

	PEPROCESS targetProcess = IoThreadToProcess(targetThread);
	PEPROCESS callerProcess = IoGetCurrentProcess();
	BOOLEAN   crossProcess  = (targetProcess != callerProcess);

	ObDereferenceObject(targetThread);

	if (!crossProcess) return;

	EmitSyscallNotif(
		0,
		"NtSuspendThread: cross-process thread suspension (APC injection / hollowing step)",
		callerProcess, targetProcess, FALSE);
}

// NtCreateSection — flag SEC_IMAGE (module stomping) and executable file-backed sections.
VOID SyscallsUtils::NtCreateSectionHandler(
	PHANDLE        SectionHandle,
	ACCESS_MASK    DesiredAccess,
	PVOID          ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG          SectionPageProtection,
	ULONG          AllocationAttributes,
	HANDLE         FileHandle
) {
	// SEC_IMAGE = 0x1000000 — maps a PE as an image (module stomping indicator)
	BOOLEAN isStomp   = (AllocationAttributes & 0x1000000) != 0;
	// File-backed section with an execute protection = reflective/stomping variant
	BOOLEAN isExecMap = (FileHandle != nullptr) &&
		(SectionPageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
		                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

	if (!isStomp && !isExecMap) return;

	EmitSyscallNotif(
		0,
		isStomp
			? "NtCreateSection: SEC_IMAGE section created (module stomping indicator)"
			: "NtCreateSection: file-backed executable section (reflective load indicator)",
		IoGetCurrentProcess(), nullptr, isStomp);
}

// NtMapViewOfSection — flag cross-process mapping AND same-process ntdll remapping.
//
// Cross-process: Critical — classic section-based injection delivery.
//
// Same-process: check the section's backing file via MmGetFileNameForSection.
// If it is ntdll.dll, the attacker is loading a clean (unhooked) copy into the
// current process to get unhooked function pointers — a common EDR bypass.
// This is Critical because the technique directly undermines our user-mode hooks.
VOID SyscallsUtils::NtMapViewOfSectionHandler(
	HANDLE         SectionHandle,
	HANDLE         ProcessHandle,
	PVOID*         BaseAddress,
	ULONG_PTR      ZeroBits,
	SIZE_T         CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T        ViewSize,
	ULONG          InheritDisposition,
	ULONG          AllocationType,
	ULONG          Win32Protect
) {
	BOOLEAN crossProcess = (ProcessHandle != (HANDLE)-1);

	if (crossProcess) {
		EmitSyscallNotif(
			(BaseAddress && MmIsAddressValid(BaseAddress)) ? (ULONG64)*BaseAddress : 0,
			"NtMapViewOfSection: cross-process section mapping (shellcode/injection delivery)",
			IoGetCurrentProcess(), nullptr, TRUE);
		return;
	}

	// Same-process: resolve the section's backing file and check for ntdll.
	// Skip null/invalid handles and cases where the resolution API is unavailable.
	if (!SectionHandle || !g_MmGetFileNameForSection) return;

	PVOID sectionObject = nullptr;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		SectionHandle,
		0,                    // no specific access check — we're just reading for detection
		*MmSectionObjectType,
		UserMode,
		&sectionObject,
		nullptr))) return;

	POBJECT_NAME_INFORMATION nameInfo = nullptr;
	NTSTATUS status = g_MmGetFileNameForSection(sectionObject, &nameInfo);
	ObDereferenceObject(sectionObject);

	if (!NT_SUCCESS(status) || !nameInfo) return;

	// UnicodeStringContains does a case-insensitive substring search.
	// Matches "\Windows\System32\ntdll.dll" and "\KnownDlls\ntdll.dll".
	BOOLEAN isNtdll = UnicodeStringContains(&nameInfo->Name, L"ntdll.dll");
	ExFreePool(nameInfo);

	if (isNtdll) {
		EmitSyscallNotif(
			0,
			"NtMapViewOfSection: ntdll.dll remapped same-process (clean-copy hook bypass / unhooking)",
			IoGetCurrentProcess(), nullptr, TRUE);
	}
}

// NtUnmapViewOfSection — flag cross-process unmapping (hollowing / module stomp cleanup).
VOID SyscallsUtils::NtUnmapViewOfSectionHandler(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
) {
	BOOLEAN crossProcess = (ProcessHandle != (HANDLE)-1);
	if (!crossProcess) return;

	EmitSyscallNotif(
		(ULONG64)BaseAddress,
		"NtUnmapViewOfSection: cross-process unmap (process hollowing / module stomp cleanup)",
		IoGetCurrentProcess(), nullptr, TRUE);
}

// NtLoadDriver — always Critical; no legitimate user-mode software calls this directly.
// Malware uses it to load a kernel driver without going through SCM.
VOID SyscallsUtils::NtLoadDriverHandler(
	PUNICODE_STRING DriverServiceName
) {
	char msg[200] = "NtLoadDriver: direct kernel driver load -- service: ";
	SIZE_T prefixLen = strlen(msg);

	if (DriverServiceName && MmIsAddressValid(DriverServiceName)) {
		__try {
			if (DriverServiceName->Buffer && DriverServiceName->Length > 0) {
				ULONG copyLen = min(
					(ULONG)(DriverServiceName->Length / sizeof(WCHAR)),
					(ULONG)(sizeof(msg) - prefixLen - 2));
				for (ULONG i = 0; i < copyLen; i++) {
					WCHAR wc = DriverServiceName->Buffer[i];
					msg[prefixLen + i] = (wc < 128) ? (char)wc : '?';
				}
				msg[prefixLen + copyLen] = '\0';
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, TRUE);
}

VOID SyscallsUtils::DisableAltSyscallFromThreads2() {

	NTSTATUS status;
	ULONG bufferSize = 0x10000;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'prlc');

	if (!buffer) {
		DbgPrint("[-] Failed to allocate memory for process buffer\n");
		return;
	}

	do {
		status = ZwQuerySystemInformation(0x05, buffer, bufferSize, &bufferSize);

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(buffer);
			buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'proc');
			if (!buffer) {
				DbgPrint("[-] Failed to allocate memory for process buffer\n");
				return;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

		do {
			for (ULONG j = 0; j < processInfo->NumberOfThreads; j++) {

				PETHREAD eThread;
				status = PsLookupThreadByThreadId(processInfo->Threads[j].ClientId.UniqueThread, &eThread);

				if (!NT_SUCCESS(status)) {
					DbgPrint("[-] PsLookupThreadByThreadId failed for ThreadId: %d\n", processInfo->Threads[j].ClientId.UniqueThread);
					continue;
				}

				_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);

				if (header->DebugActive >= 0x20) {
					header->DebugActive = 0x0;
				}
			}

			UnsetInformationAltSystemCall(processInfo->UniqueProcessId);
			processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);

		} while (processInfo->NextEntryOffset);
	}
	else {
		DbgPrint("[-] ZwQuerySystemInformation failed with status: %x\n", status);
	}

	ExFreePool(buffer);
}

VOID SyscallsUtils::DisableAltSyscallFromThreads3() {

	__try {

		PEPROCESS currentProcess = PsInitialSystemProcess;
		PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)currentProcess + OffsetsMgt::GetOffsets()->ActiveProcessLinks);

		do
		{
			currentProcess = (PEPROCESS)((PUCHAR)listEntry - OffsetsMgt::GetOffsets()->ActiveProcessLinks);

			if (!currentProcess) {
				DbgPrint("[-] Failed to get current process\n");
				break;
			}

			HANDLE pid = PsGetProcessId(currentProcess);
			UnsetInformationAltSystemCall(pid);

			PLIST_ENTRY listEntryThreads = (PLIST_ENTRY)((PUCHAR)currentProcess + OffsetsMgt::GetOffsets()->ThreadListHead);
			PLIST_ENTRY threadListEntry = listEntryThreads->Flink;

			PULONG flags3 = (PULONG)((DWORD64)currentProcess + OffsetsMgt::GetOffsets()->Flags3);

			if (!flags3) {
				DbgPrint("[-] Failed to get flags3\n");
				break;
			}

			*flags3 = *flags3 & 0xFDFFFFFF;

			do {
				__try {

					PETHREAD eThread = (PETHREAD)((PUCHAR)threadListEntry - OffsetsMgt::GetOffsets()->ThreadListEntry);

					if (eThread) {	

						_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);
						
						if (!header || !MmIsAddressValid(header)) {
							break;
						}

						if (header->DebugActive >= 0x20) {

							header->DebugActive = 0x0;
						}

						threadListEntry = threadListEntry->Flink;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[-] Exception in DisableAltSyscallFromThreads3\n");
				}

			} while (threadListEntry != listEntryThreads);

			listEntry = listEntry->Flink;

		} while (listEntry != (PLIST_ENTRY)((PUCHAR)PsInitialSystemProcess + OffsetsMgt::GetOffsets()->ActiveProcessLinks));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[-] Exception in DisableAltSyscallFromThreads3\n");
	}
}

VOID SyscallsUtils::DestroyAltSyscallThreads() {

	NTSTATUS status;
	ULONG bufferSize = 0x10000;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'prlc');

	int numProcs = 0;
	int numThreads = 0;

	if (!buffer) {
		DbgPrint("[-] Failed to allocate memory for process buffer\n");
		return;
	}

	do {
		status = ZwQuerySystemInformation(0x05, buffer, bufferSize, &bufferSize);

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(buffer);
			buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'proc');
			if (!buffer) {
				DbgPrint("[-] Failed to allocate memory for process buffer\n");
				return;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

		do {
			++numProcs;

			for (ULONG j = 0; j < processInfo->NumberOfThreads; j++) {
				++numThreads;
				PETHREAD eThread;
				status = PsLookupThreadByThreadId(processInfo->Threads[j].ClientId.UniqueThread, &eThread);

				if (!NT_SUCCESS(status)) {
					DbgPrint("[-] PsLookupThreadByThreadId failed for ThreadId: %d\n", processInfo->Threads[j].ClientId.UniqueThread);
					continue;
				}

				_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);

				if (header->DebugActive >= 0x20) {
					
				}
			}

			UnsetInformationAltSystemCall(processInfo->UniqueProcessId);

			processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);

		} while (processInfo->NextEntryOffset);

	}
	else {
		DbgPrint("[-] ZwQuerySystemInformation failed with status: %x\n", status);
	}

	ExFreePool(buffer);

}

VOID SyscallsUtils::InitVadUtils() {

	vadUtils = (VadUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(VadUtils), 'vadu');
	if (!vadUtils) {
		DbgPrint("[-] Failed to allocate memory for VadUtils\n");
		return;
	}

}

// Privilege LUIDs (LowPart; HighPart is always 0 for well-known privileges).
static const struct { ULONG luid; const char* name; BOOLEAN critical; } kDangerousPrivileges[] = {
	{ 2,  "SeCreateTokenPrivilege",        TRUE  },
	{ 3,  "SeAssignPrimaryTokenPrivilege", FALSE },
	{ 7,  "SeTcbPrivilege",                TRUE  },
	{ 9,  "SeTakeOwnershipPrivilege",      FALSE },
	{ 10, "SeLoadDriverPrivilege",         FALSE },
	{ 20, "SeDebugPrivilege",              TRUE  },
	{ 29, "SeImpersonatePrivilege",        FALSE },
	{ 30, "SeCreateGlobalPrivilege",       FALSE },
};

VOID SyscallsUtils::NtAdjustPrivilegesTokenHandler(
	HANDLE TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	ULONG BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PULONG ReturnLength
) {
	UNREFERENCED_PARAMETER(TokenHandle);
	UNREFERENCED_PARAMETER(BufferLength);
	UNREFERENCED_PARAMETER(PreviousState);
	UNREFERENCED_PARAMETER(ReturnLength);

	// Only flag privilege enablement, not removal.
	if (DisableAllPrivileges || !NewState) return;

	__try {
		ProbeForRead(NewState, sizeof(ULONG), sizeof(ULONG));
		ULONG count = NewState->PrivilegeCount;

		if (count == 0 || count > 35) return;

		SIZE_T requiredSize = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges)
			+ (SIZE_T)count * sizeof(LUID_AND_ATTRIBUTES);
		ProbeForRead(NewState, requiredSize, sizeof(ULONG));

		for (ULONG i = 0; i < count; i++) {
			LUID_AND_ATTRIBUTES la = NewState->Privileges[i];

			// Only care about privileges being enabled.
			if (!(la.Attributes & SE_PRIVILEGE_ENABLED)) continue;
			if (la.Luid.HighPart != 0) continue;

			const char* privName = NULL;
			BOOLEAN isCritical = FALSE;
			for (int j = 0; j < ARRAYSIZE(kDangerousPrivileges); j++) {
				if (kDangerousPrivileges[j].luid == la.Luid.LowPart) {
					privName = kDangerousPrivileges[j].name;
					isCritical = kDangerousPrivileges[j].critical;
					break;
				}
			}
			if (!privName) continue;

			char msgBuf[96];
			RtlStringCbPrintfA(msgBuf, sizeof(msgBuf), "Token Privilege Enabled: %s", privName);
			ULONG msgLen = (ULONG)strnlen_s(msgBuf, sizeof(msgBuf)) + 1;

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
			if (!kernelNotif) continue;

			kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
			if (!kernelNotif->msg) {
				ExFreePool(kernelNotif);
				continue;
			}

			if (isCritical) {
				SET_CRITICAL(*kernelNotif);
			} else {
				SET_WARNING(*kernelNotif);
			}
			SET_SYSCALL_CHECK(*kernelNotif);

			kernelNotif->isPath = FALSE;
			kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
			kernelNotif->bufSize = msgLen;
			RtlCopyMemory(kernelNotif->procName,
				PsGetProcessImageFileName(IoGetCurrentProcess()), 15);
			RtlCopyMemory(kernelNotif->msg, msgBuf, msgLen);

			if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
				ExFreePool(kernelNotif->msg);
				ExFreePool(kernelNotif);
			}

			DbgPrint("[!] Token privilege escalation: %s by %s (PID %llu)\n",
				privName,
				PsGetProcessImageFileName(IoGetCurrentProcess()),
				(ULONG64)PsGetProcessId(IoGetCurrentProcess()));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[!] Exception in NtAdjustPrivilegesTokenHandler\n");
	}
}