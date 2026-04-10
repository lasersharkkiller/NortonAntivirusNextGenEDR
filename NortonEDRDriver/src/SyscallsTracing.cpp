#include "Globals.h"
#include "Deception.h"

// User-mode access masks not defined in kernel headers
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION  0x0040
#endif

// Process information classes
#define PROCESS_PROTECTION_LEVEL_CLASS  0x3Du   // ProcessProtectionLevel (61)

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
ULONG SyscallsUtils::NtProtectVirtualMemoryId = 0;
ULONG SyscallsUtils::NtCreateTransactionId = 0;
ULONG SyscallsUtils::NtRollbackTransactionId = 0;
ULONG SyscallsUtils::NtCreateProcessExId = 0;
ULONG SyscallsUtils::NtCreateProcessId = 0;
ULONG SyscallsUtils::NtQuerySystemInformationId = 0;
ULONG SyscallsUtils::NtSetInformationProcessId = 0;
ULONG SyscallsUtils::NtDuplicateObjectId = 0x003C;     // Stable across Win10 1507–Win11 24H2
ULONG SyscallsUtils::NtDebugActiveProcessId = 0;       // Resolve dynamically
ULONG SyscallsUtils::NtSetInformationThreadId = 0;     // Resolve dynamically
ULONG SyscallsUtils::NtTraceControlId = 0;             // Resolve dynamically
ULONG SyscallsUtils::NtCreateNamedPipeFileId = 0;      // Resolve dynamically
ULONG SyscallsUtils::NtOpenThreadId = 0;               // Resolve dynamically
ULONG SyscallsUtils::NtFlushInstructionCacheId = 0;    // Resolve dynamically
ULONG SyscallsUtils::NtCreateFileId = 0;              // Resolve dynamically — physical memory / raw device access detection
ULONG SyscallsUtils::NtAssignProcessToJobObjectId = 0; // Resolve dynamically — job object kill attack detection

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

// ---------------------------------------------------------------------------
// IdToName — map syscall SSN to human-readable name for alerts.
// ---------------------------------------------------------------------------
static const char* IdToName(ULONG id) {
	if (id == 0x0018) return "NtAllocateVirtualMemory";
	if (id == 0x003a) return "NtWriteVirtualMemory";
	if (id == 0x0050) return "NtProtectVirtualMemory";
	if (id == 0x0054) return "NtReadVirtualMemory";
	if (id == 0x0045) return "NtQueueApcThread";
	if (id == NtQueueApcThreadExId) return "NtQueueApcThreadEx";
	if (id == NtSetContextThreadId) return "NtSetContextThread";
	if (id == NtOpenProcessId) return "NtOpenProcess";
	if (id == NtMapViewOfSectionId) return "NtMapViewOfSection";
	if (id == NtDuplicateObjectId) return "NtDuplicateObject";
	if (id == NtDebugActiveProcessId) return "NtDebugActiveProcess";
	if (id == NtResumeThreadId) return "NtResumeThread";
	if (id == NtContinueId) return "NtContinue";
	if (id == NtCreateThreadExId) return "NtCreateThreadEx";
	if (id == NtOpenThreadId) return "NtOpenThread";
	return "Unknown";
}

BOOLEAN SyscallsUtils::SyscallHandler(PKTRAP_FRAME trapFrame) {

	PVOID spoofedAddr = NULL;

	ULONG id = (ULONG)trapFrame->Rax;

	if (lastNotifedCidStackCorrupt == PsGetCurrentProcessId()) {
		return FALSE;
	}

	// --- Pre-dispatch: unified call-origin and CET checks for attack-relevant syscalls ---
	// These syscalls are the primary injection/evasion attack surface: memory operations,
	// process/thread access, APC queuing, section/file operations, context manipulation.

	BOOLEAN isAttackRelevant =
		(id == NtAllocId                || id == NtWriteId               || id == NtProtectId           ||
		 id == 0x0054                   || id == 0x0045                  || id == NtQueueApcThreadExId  ||
		 id == NtSetContextThreadId     || id == NtOpenProcessId         || id == NtMapViewOfSectionId  ||
		 id == NtDuplicateObjectId      || id == NtDebugActiveProcessId  || id == NtResumeThreadId      ||
		 id == NtContinueId             || id == NtCreateThreadExId      || id == NtOpenThreadId);

	if (isAttackRelevant) {
		// CET shadow stack check — catches Type 2 indirect syscalls on CET-capable hardware
		if (id == NtAllocId || id == NtWriteId || id == NtProtectId) {
			if (stackUtils && stackUtils->isStackCorruptedRtlCET(&spoofedAddr)) {
				if (lastNotifedCidStackCorrupt != PsGetCurrentProcessId()) {
					lastNotifedCidStackCorrupt = PsGetCurrentProcessId();

					PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
						POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

					if (kernelNotif) {
						char* msg = "Corrupted Thread Call Stack";
						RtlZeroMemory(kernelNotif, sizeof(*kernelNotif));
						SET_WARNING(*kernelNotif);
						SET_SHADOW_STACK_CHECK(*kernelNotif);
						InjectionTaintTracker::MarkTainted(PsGetCurrentProcessId());
						kernelNotif->scoopedAddress = (ULONG64)spoofedAddr;
						kernelNotif->bufSize = sizeof(msg);
						kernelNotif->isPath = FALSE;
						kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
						RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 14);

						kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');
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
				return FALSE;
			}
		}

		// Call-origin check — catches Type 1 direct syscalls on all hardware
		isSyscallDirect(trapFrame->Rip, (char*)IdToName(id));

		// Indirect syscall check — catches Type 2 from shellcode (non-CET systems)
		isSyscallIndirect(trapFrame->Rsp);
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

		NtProtectVmHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(SIZE_T*)trapFrame->R8,
			(ULONG)trapFrame->R9,
			(PULONG)arg5
		);
	}
	else if (id == 0x003a) {			// NtWriteVirtualMemory | Win 10 -> Win11 24H2

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
	else if (NtProtectVirtualMemoryId != 0 && id == NtProtectVirtualMemoryId) {  // NtProtectVirtualMemory

		NtProtectVirtualMemoryHandler(
			(HANDLE)trapFrame->Rcx,    // ProcessHandle
			(PVOID*)trapFrame->Rdx,    // *BaseAddress
			(PSIZE_T)trapFrame->R8,    // *NumberOfBytesToProtect
			(ULONG)trapFrame->R9       // NewAccessProtection
		);
	}
	else if (NtCreateTransactionId != 0 && id == NtCreateTransactionId) {  // NtCreateTransaction
		NtCreateTransactionHandler();
	}
	else if (NtRollbackTransactionId != 0 && id == NtRollbackTransactionId) {  // NtRollbackTransaction
		NtRollbackTransactionHandler();
	}
	else if (NtCreateProcessExId != 0 && id == NtCreateProcessExId) {  // NtCreateProcessEx
		// NtCreateProcessEx(ProcessHandle*, Access, ObjAttr, ParentProcess, Flags, SectionHandle, ...)
		// ParentProcess = arg4 = R9
		// Flags  = arg5 = [RSP+0x28]
		// SectionHandle = arg6 = [RSP+0x30]
		NtCreateProcessExHandler((HANDLE)trapFrame->R9, (ULONG)arg5, (HANDLE)arg6);
	}
	else if (NtCreateProcessId != 0 && id == NtCreateProcessId) {  // NtCreateProcess (older, 8-arg)
		// NtCreateProcess(ProcessHandle*, Access, ObjAttr, ParentProcess, InheritObjTable, SectionHandle, ...)
		// ParentProcess = arg4 = R9
		// SectionHandle = arg6 = [RSP+0x30]
		NtCreateProcessHandler((HANDLE)trapFrame->R9, (HANDLE)arg6);
	}
	else if (NtQuerySystemInformationId != 0 && id == NtQuerySystemInformationId) {
		// NtQuerySystemInformation(SystemInformationClass, SystemInformation, Length, ReturnLength)
		// Class = RCX (arg1)
		NtQuerySystemInformationHandler((ULONG)trapFrame->Rcx);
	}
	else if (NtSetInformationProcessId != 0 && id == NtSetInformationProcessId) {
		// NtSetInformationProcess(ProcessHandle, ProcessInformationClass, Info, InfoLen)
		// RCX=handle  RDX=class  R8=info ptr  R9=len
		NtSetInformationProcessHandler(
			(HANDLE)trapFrame->Rcx,
			(ULONG)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(ULONG)trapFrame->R9);
	}
	else if (id == NtDuplicateObjectId) {
		// NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options)
		// RCX=srcProc  RDX=srcHandle  R8=tgtProc  R9=tgtHandle  [RSP+0x28]=access  [RSP+0x30]=attrs  [RSP+0x38]=opts
		PULONGLONG pAccess = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x28);
		ACCESS_MASK access = (ACCESS_MASK)(MmIsAddressValid(pAccess) ? *pAccess : 0);
		NtDuplicateObjectHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx,
			(HANDLE)trapFrame->R8,
			(PVOID)trapFrame->R9,
			access);
	}
	else if (NtDebugActiveProcessId != 0 && id == NtDebugActiveProcessId) {
		// NtDebugActiveProcess(ProcessHandle, DebugObjectHandle)
		// RCX=process  RDX=debugObject
		NtDebugActiveProcessHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx);
	}
	else if (NtSetInformationThreadId != 0 && id == NtSetInformationThreadId) {
		// NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength)
		// RCX=thread  RDX=class  R8=info  R9=len
		NtSetInformationThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(ULONG)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(ULONG)trapFrame->R9);
	}
	else if (NtTraceControlId != 0 && id == NtTraceControlId) {
		// NtTraceControl(TraceHandle, FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength)
		// RCX=handle  RDX=funcCode  R8=inBuf  R9=inLen  [RSP+0x28]=outBuf  [RSP+0x30]=outLen  [RSP+0x38]=retLen
		NtTraceControlHandler((ULONG)trapFrame->Rdx);
	}
	else if (NtCreateNamedPipeFileId != 0 && id == NtCreateNamedPipeFileId) {
		// NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeBits, ReadModeBits, CompletionMode, MaxInstances, InboundQuota, OutboundQuota, Timeout)
		// We care about the pipe name in ObjectAttributes->ObjectName
		PVOID objAttr = (PVOID)trapFrame->Rdx;
		NtCreateNamedPipeFileHandler(objAttr);
	}
	else if (NtOpenThreadId != 0 && id == NtOpenThreadId) {
		// NtOpenThread(ThreadHandle*, DesiredAccess, ObjectAttributes, ClientId)
		// RCX=handle ptr, RDX=access, R8=ObjAttr, R9=ClientId
		NtOpenThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(ACCESS_MASK)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(PCLIENT_ID)trapFrame->R9
		);
	}
	else if (NtFlushInstructionCacheId != 0 && id == NtFlushInstructionCacheId) {
		// NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
		// RCX=proc, RDX=base, R8=len
		NtFlushInstructionCacheHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(SIZE_T)trapFrame->R8
		);
	}
	else if (NtCreateFileId != 0 && id == NtCreateFileId) {
		// NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*, ...)
		// ObjectAttributes = arg3 = R8
		NtCreateFileHandler((PVOID)trapFrame->R8);
	}
	else if (NtAssignProcessToJobObjectId != 0 && id == NtAssignProcessToJobObjectId) {
		// NtAssignProcessToJobObject(JobHandle, ProcessHandle)
		// ProcessHandle = arg2 = RDX
		NtAssignProcessToJobObjectHandler((HANDLE)trapFrame->Rdx);
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

		if (isSyscallDirect) {
			// Tier 1 (WARNING): any direct syscall outside ntdll
			char msgBuf[200];
			RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
				"Direct syscall: '%s' return address 0x%llX outside ntdll — "
				"possible SysWhispers / Hell's Gate / manual stub",
				syscallName, Rip);

			PKERNEL_STRUCTURED_NOTIFICATION notif1 = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
				POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (notif1) {
				RtlZeroMemory(notif1, sizeof(*notif1));
				SET_WARNING(*notif1);
				SET_SYSCALL_CHECK(*notif1);
				notif1->pid = PsGetProcessId(IoGetCurrentProcess());
				notif1->isPath = FALSE;
				RtlCopyMemory(notif1->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 14);

				SIZE_T msgLen = strlen(msgBuf) + 1;
				notif1->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'msg');
				notif1->bufSize = (ULONG)msgLen;

				if (notif1->msg) {
					RtlCopyMemory(notif1->msg, msgBuf, msgLen);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(notif1)) {
						ExFreePool(notif1->msg);
						ExFreePool(notif1);
					}
				} else {
					ExFreePool(notif1);
				}
			}

			// Tier 2 (CRITICAL): SYSCALL;RET trampoline outside ntdll
			if (op == 0xC3) {
				char msgBuf2[200];
				RtlStringCbPrintfA(msgBuf2, sizeof(msgBuf2),
					"Direct syscall trampoline: '%s' SYSCALL;RET stub at 0x%llX "
					"outside ntdll — classic SysWhispers1 pattern",
					syscallName, Rip);

				PKERNEL_STRUCTURED_NOTIFICATION notif2 = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

				if (notif2) {
					RtlZeroMemory(notif2, sizeof(*notif2));
					SET_CRITICAL(*notif2);
					SET_SYSCALL_CHECK(*notif2);
					notif2->pid = PsGetProcessId(IoGetCurrentProcess());
					notif2->isPath = FALSE;
					RtlCopyMemory(notif2->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 14);

					SIZE_T msgLen2 = strlen(msgBuf2) + 1;
					notif2->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen2, 'msg');
					notif2->bufSize = (ULONG)msgLen2;

					if (notif2->msg) {
						RtlCopyMemory(notif2->msg, msgBuf2, msgLen2);
						if (!CallbackObjects::GetNotifQueue()->Enqueue(notif2)) {
							ExFreePool(notif2->msg);
							ExFreePool(notif2);
						}
					} else {
						ExFreePool(notif2);
					}
				}
			}
		}

		KeUnstackDetachProcess(&apcState);
	}

	return FALSE;
}

// ---------------------------------------------------------------------------
// isSyscallIndirect — detects shellcode-originated indirect syscalls.
//
// When RIP is inside ntdll, we inspect the return address at RSP. For a
// legitimate kernel32 → ntdll call, this address is inside a file-backed DLL.
// For SysWhispers3 / Tartarus Gate (JMP into ntdll's SYSCALL gadget), the
// return address is in a private executable VAD (attacker's shellcode).
//
// Only fires for processes without CET (CET shadow stack already catches Type 2).
// ---------------------------------------------------------------------------
BOOLEAN SyscallsUtils::isSyscallIndirect(ULONG64 Rsp)
{
	PEPROCESS curproc = IoGetCurrentProcess();
	PPS_PROTECTION prot = PsGetProcessProtection(curproc);
	if (prot && prot->Level != 0) return FALSE;

	// Skip if CET is active — shadow stack check already covers this case.
	if (stackUtils && stackUtils->isCETEnabled()) return FALSE;

	// Read the immediate return address at RSP.
	PVOID retAddr = nullptr;
	KAPC_STATE apcState;
	KeStackAttachProcess(curproc, &apcState);

	__try {
		PULONG_PTR pRsp = (PULONG_PTR)Rsp;
		if (MmIsAddressValid(pRsp)) {
			retAddr = (PVOID)*pRsp;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		retAddr = nullptr;
	}

	BOOLEAN result = FALSE;
	if (retAddr) {
		RTL_AVL_TREE* root = (RTL_AVL_TREE*)
			((PUCHAR)curproc + OffsetsMgt::GetOffsets()->VadRoot);

		result = VadUtils::IsAddressInPrivateExecVad(
			(PRTL_BALANCED_NODE)root, (ULONG64)retAddr);

		if (result) {
			InjectionTaintTracker::MarkTainted(PsGetProcessId(curproc));

			char msgBuf[200];
			RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
				"Indirect syscall: return address 0x%llX is in private executable "
				"region — shellcode jump-to-ntdll-syscall-gadget (SysWhispers3/Tartarus)",
				(ULONG64)retAddr);

			PKERNEL_STRUCTURED_NOTIFICATION notif =
				(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
					POOL_FLAG_NON_PAGED,
					sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'isci');

			if (notif) {
				RtlZeroMemory(notif, sizeof(*notif));
				SET_WARNING(*notif);
				SET_SYSCALL_CHECK(*notif);
				notif->pid    = PsGetProcessId(curproc);
				notif->isPath = FALSE;
				RtlCopyMemory(notif->procName, PsGetProcessImageFileName(curproc), 14);

				SIZE_T msgLen = strlen(msgBuf) + 1;
				notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'iscm');
				notif->bufSize = (ULONG)msgLen;

				if (notif->msg) {
					RtlCopyMemory(notif->msg, msgBuf, msgLen);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(notif)) {
						ExFreePool(notif->msg);
						ExFreePool(notif);
					}
				} else {
					ExFreePool(notif);
				}
			}
		}
	}

	KeUnstackDetachProcess(&apcState);
	return result;
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

	UNICODE_STRING usNtProtectVm;
	RtlInitUnicodeString(&usNtProtectVm, L"NtProtectVirtualMemory");
	NtProtectVirtualMemoryId = getSSNByName(ssdtTable, &usNtProtectVm, exportsMap);

	UNICODE_STRING usNtCreateTransaction;
	RtlInitUnicodeString(&usNtCreateTransaction, L"NtCreateTransaction");
	NtCreateTransactionId = getSSNByName(ssdtTable, &usNtCreateTransaction, exportsMap);

	UNICODE_STRING usNtRollbackTransaction;
	RtlInitUnicodeString(&usNtRollbackTransaction, L"NtRollbackTransaction");
	NtRollbackTransactionId = getSSNByName(ssdtTable, &usNtRollbackTransaction, exportsMap);

	UNICODE_STRING usNtCreateProcessEx;
	RtlInitUnicodeString(&usNtCreateProcessEx, L"NtCreateProcessEx");
	NtCreateProcessExId = getSSNByName(ssdtTable, &usNtCreateProcessEx, exportsMap);

	UNICODE_STRING usNtCreateProcess;
	RtlInitUnicodeString(&usNtCreateProcess, L"NtCreateProcess");
	NtCreateProcessId = getSSNByName(ssdtTable, &usNtCreateProcess, exportsMap);

	UNICODE_STRING usNtQuerySysInfo;
	RtlInitUnicodeString(&usNtQuerySysInfo, L"NtQuerySystemInformation");
	NtQuerySystemInformationId = getSSNByName(ssdtTable, &usNtQuerySysInfo, exportsMap);

	UNICODE_STRING usNtSetInfoProcess;
	RtlInitUnicodeString(&usNtSetInfoProcess, L"NtSetInformationProcess");
	NtSetInformationProcessId = getSSNByName(ssdtTable, &usNtSetInfoProcess, exportsMap);

	UNICODE_STRING usNtDebugActiveProcess;
	RtlInitUnicodeString(&usNtDebugActiveProcess, L"NtDebugActiveProcess");
	NtDebugActiveProcessId = getSSNByName(ssdtTable, &usNtDebugActiveProcess, exportsMap);

	UNICODE_STRING usNtSetInfoThread;
	RtlInitUnicodeString(&usNtSetInfoThread, L"NtSetInformationThread");
	NtSetInformationThreadId = getSSNByName(ssdtTable, &usNtSetInfoThread, exportsMap);

	UNICODE_STRING usNtTraceControl;
	RtlInitUnicodeString(&usNtTraceControl, L"NtTraceControl");
	NtTraceControlId = getSSNByName(ssdtTable, &usNtTraceControl, exportsMap);

	UNICODE_STRING usNtCreateNamedPipeFile;
	RtlInitUnicodeString(&usNtCreateNamedPipeFile, L"NtCreateNamedPipeFile");
	NtCreateNamedPipeFileId = getSSNByName(ssdtTable, &usNtCreateNamedPipeFile, exportsMap);

	UNICODE_STRING usNtOpenThread;
	RtlInitUnicodeString(&usNtOpenThread, L"NtOpenThread");
	NtOpenThreadId = getSSNByName(ssdtTable, &usNtOpenThread, exportsMap);

	UNICODE_STRING usNtFlushIC;
	RtlInitUnicodeString(&usNtFlushIC, L"NtFlushInstructionCache");
	NtFlushInstructionCacheId = getSSNByName(ssdtTable, &usNtFlushIC, exportsMap);

	UNICODE_STRING usNtCreateFile;
	RtlInitUnicodeString(&usNtCreateFile, L"NtCreateFile");
	NtCreateFileId = getSSNByName(ssdtTable, &usNtCreateFile, exportsMap);

	UNICODE_STRING usNtAssignJob;
	RtlInitUnicodeString(&usNtAssignJob, L"NtAssignProcessToJobObject");
	NtAssignProcessToJobObjectId = getSSNByName(ssdtTable, &usNtAssignJob, exportsMap);

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

	// Taint the target process so the C2 frequency tracker strips allowlist immunity.
	if (remote) {
		PEPROCESS targetProc = nullptr;
		if (NT_SUCCESS(ObReferenceObjectByHandle(
				ProcessHandle, 0, *PsProcessType, UserMode,
				(PVOID*)&targetProc, nullptr)) && targetProc) {
			InjectionTaintTracker::MarkTainted(PsGetProcessId(targetProc));
			ObDereferenceObject(targetProc);
		}
	}

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
	BOOLEAN isSelf = (ProcessHandle == NtCurrentProcess());

	// -----------------------------------------------------------------------
	// Argument-spoofing / PEB CommandLine tampering (Adam Chester technique).
	// Catches direct NtWriteVirtualMemory syscalls that bypass the user-mode
	// WriteProcessMemory hook in HookDll.
	//
	// For cross-process writes: attach to target and check whether the write
	// range overlaps PEB->ProcessParameters->CommandLine.
	// For same-process writes: check the current process's own PEB.
	// -----------------------------------------------------------------------
	if (BaseAddress && NumberOfBytesToWrite > 0) {
		PEPROCESS targetProcess = NULL;
		BOOLEAN   attached      = FALSE;
		KAPC_STATE apcState     = {};

		if (isSelf) {
			targetProcess = PsGetCurrentProcess();
		} else {
			ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			                         UserMode, (PVOID*)&targetProcess, NULL);
		}

		if (targetProcess) {
			PPEB peb = (PPEB)PsGetProcessPeb(targetProcess);
			if (peb) {
				if (!isSelf) {
					KeStackAttachProcess(targetProcess, &apcState);
					attached = TRUE;
				}
				BOOLEAN hit = FALSE;
				__try {
					if (MmIsAddressValid(peb)) {
						PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;
						if (params && MmIsAddressValid(params)) {
							PWSTR  cmdBuf    = params->CommandLine.Buffer;
							USHORT cmdMaxLen = params->CommandLine.MaximumLength;
							if (cmdBuf && cmdMaxLen > 0 && MmIsAddressValid(cmdBuf)) {
								BYTE* ws = (BYTE*)BaseAddress;
								BYTE* we = ws + NumberOfBytesToWrite;
								BYTE* cs = (BYTE*)cmdBuf;
								BYTE* ce = cs + cmdMaxLen;
								if (ws < ce && we > cs) hit = TRUE;
							}
						}
					}
				} __except (EXCEPTION_EXECUTE_HANDLER) {}

				if (attached) KeUnstackDetachProcess(&apcState);

				if (hit) {
					char spoofMsg[200];
					PEPROCESS caller = PsGetCurrentProcess();
					if (isSelf) {
						RtlStringCbPrintfA(spoofMsg, sizeof(spoofMsg),
							"PEB CommandLine self-modification (scanner evasion): "
							"dst=0x%llX size=0x%llX by '%s'",
							(ULONG64)BaseAddress, (ULONG64)NumberOfBytesToWrite,
							PsGetProcessImageFileName(caller));
					} else {
						RtlStringCbPrintfA(spoofMsg, sizeof(spoofMsg),
							"Argument Spoofing: NtWriteVirtualMemory targets PEB CommandLine "
							"of '%s' (pid=%llu) dst=0x%llX size=0x%llX by '%s'",
							PsGetProcessImageFileName(targetProcess),
							(ULONG64)PsGetProcessId(targetProcess),
							(ULONG64)BaseAddress, (ULONG64)NumberOfBytesToWrite,
							PsGetProcessImageFileName(caller));
					}
					SIZE_T msgLen = strlen(spoofMsg);
					PKERNEL_STRUCTURED_NOTIFICATION n =
						(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
							POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');
					if (n) {
						RtlZeroMemory(n, sizeof(*n));
						SET_CRITICAL(*n);
						SET_CALLING_PROC_PID_CHECK(*n);
						n->pid    = PsGetProcessId(caller);
						n->isPath = FALSE;
						RtlCopyMemory(n->procName, PsGetProcessImageFileName(caller), 14);
						n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen + 1, 'msg');
						if (n->msg) {
							RtlCopyMemory(n->msg, spoofMsg, msgLen + 1);
							n->bufSize = (ULONG)(msgLen + 1);
							if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
								ExFreePool(n->msg);
								ExFreePool(n);
							}
						} else { ExFreePool(n); }
					}
				}
			}
			// Fork-and-run correlation: mark this PID as written-to so that
			// a subsequent NtCreateThreadEx into it triggers a combined alert.
			if (!isSelf) {
				ForkRunTracker::MarkWritten(PsGetProcessId(targetProcess));
				InjectionTaintTracker::MarkTainted(PsGetProcessId(targetProcess));
			}

			if (!isSelf) ObDereferenceObject(targetProcess);
		}
	}

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytesToWrite, 'msg');

	if (buffer) {

		RtlCopyMemory(buffer, Buffer, NumberOfBytesToWrite);

		// PE scan: flag writes that carry a PE header (cross-process only)
		if (!isSelf) {
			PeScanner::CheckBufferForPeHeader(
				buffer,
				NumberOfBytesToWrite,
				BaseAddress,
				PsGetProcessId(PsGetCurrentProcess()),
				PsGetProcessImageFileName(PsGetCurrentProcess()),
				CallbackObjects::GetNotifQueue()
			);
		}

		// COFF/BOF scan: check all writes (self and cross-process) for raw COFF objects.
		// CS beacons write the BOF into their own process memory before executing it.
		PeScanner::CheckBufferForCoffHeader(
			buffer,
			NumberOfBytesToWrite,
			BaseAddress,
			PsGetProcessId(PsGetCurrentProcess()),
			PsGetProcessImageFileName(PsGetCurrentProcess()),
			CallbackObjects::GetNotifQueue()
		);

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

	// --- System binary replacement detection ---
	PFILE_OBJECT fileObject = nullptr;
	if (NT_SUCCESS(ObReferenceObjectByHandle(
			FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&fileObject, nullptr))
		&& fileObject)
	{
		if (MmIsAddressValid(&fileObject->FileName) &&
			fileObject->FileName.Buffer && fileObject->FileName.Length > 0)
		{
			BOOLEAN inSystem32 =
				UnicodeStringContains(&fileObject->FileName, L"\\Windows\\System32\\") ||
				UnicodeStringContains(&fileObject->FileName, L"\\Windows\\SysWOW64\\");

			if (inSystem32) {
				static const WCHAR* kAccessibilityExes[] = {
					L"sethc.exe", L"utilman.exe", L"osk.exe",
					L"narrator.exe", L"magnify.exe", L"displayswitch.exe", nullptr
				};
				BOOLEAN isSensitiveBinary = FALSE;
				for (int i = 0; kAccessibilityExes[i]; i++) {
					if (UnicodeStringContains(&fileObject->FileName, kAccessibilityExes[i])) {
						isSensitiveBinary = TRUE; break;
					}
				}

				char pathBuf[128] = {};
				USHORT copyLen = min(
					fileObject->FileName.Length / sizeof(WCHAR), (USHORT)(sizeof(pathBuf) - 1));
				for (USHORT i = 0; i < copyLen; i++) {
					WCHAR wc = fileObject->FileName.Buffer[i];
					pathBuf[i] = (wc < 128) ? (char)wc : '?';
				}

				char sysMsg[256];
				RtlStringCbPrintfA(sysMsg, sizeof(sysMsg),
					isSensitiveBinary
						? "NtWriteFile: write to protected system binary '%s' "
						  "(sticky keys / accessibility tool UAC bypass)"
						: "NtWriteFile: write to System32 path '%s' "
						  "(system binary replacement attempt)",
					pathBuf);
				EmitSyscallNotif(0, sysMsg, IoGetCurrentProcess(), nullptr, isSensitiveBinary);
			}
		}
		ObDereferenceObject(fileObject);
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

// ---------------------------------------------------------------------------
// ClassifyProcessAccessMask — heuristic-based access mask anomaly detection.
//
// Phase 1: excessive / structurally wrong masks (tool fingerprinting).
// Phase 2: known tool-specific patterns (signature-level IDs).
//
// Returns a description string when anomalous, nullptr when clean.
// *outCritical is set to TRUE for known tool patterns, FALSE for generic excess.
// ---------------------------------------------------------------------------

#define PROCESS_ALL_ACCESS_WIN10  0x1F0FFF
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

static const char* ClassifyProcessAccessMask(ACCESS_MASK mask, BOOLEAN* outCritical)
{
	*outCritical = FALSE;

	// --- Phase 1: Excessive / structurally anomalous ---

	// PROCESS_ALL_ACCESS: only legitimate for kernel/system callers.
	// Offensive tools frequently use this as a lazy "give me everything" shortcut.
	if ((mask & PROCESS_ALL_ACCESS_WIN10) == PROCESS_ALL_ACCESS_WIN10) {
		*outCritical = FALSE;
		return "PROCESS_ALL_ACCESS requested — offensive tools use this as a lazy "
		       "catch-all; minimal rights never require all bits set";
	}

	// VM_WRITE without VM_READ: write-only cross-process access is structurally odd.
	// Legitimate debuggers/profilers always pair write with read.
	if ((mask & 0x0020) && !(mask & 0x0010)) {  // VM_WRITE without VM_READ
		*outCritical = FALSE;
		return "PROCESS_VM_WRITE without PROCESS_VM_READ — structurally anomalous; "
		       "legitimate debuggers always pair write with read";
	}

	// Full manipulation combo: VM_WRITE + VM_OPERATION + SUSPEND_RESUME but no QUERY.
	// This is the exact set needed for shellcode injection with execution control.
	const ACCESS_MASK kInjectSuite =
		0x0008 |   // PROCESS_VM_OPERATION
		0x0020 |   // PROCESS_VM_WRITE
		0x0800;    // PROCESS_SUSPEND_RESUME
	if ((mask & kInjectSuite) == kInjectSuite &&
		!(mask & 0x0400) &&   // no PROCESS_QUERY_INFORMATION
		!(mask & 0x1000)) {   // no PROCESS_QUERY_LIMITED_INFORMATION
		*outCritical = FALSE;
		return "VM_OPERATION | VM_WRITE | SUSPEND_RESUME without any QUERY rights — "
		       "classic injection capability set; legitimate tools always include QUERY";
	}

	// --- Phase 2: Known tool signatures ---

	// Mimikatz sekurlsa::logonpasswords / sekurlsa::wdigest:
	// Opens lsass with exactly PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION.
	if (mask == (0x0010 | 0x1000)) {  // VM_READ | QUERY_LIMITED
		*outCritical = TRUE;
		return "Access mask matches Mimikatz sekurlsa pattern: "
		       "PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION";
	}

	// Meterpreter / common Metasploit migrate module:
	// Requests: VM_OPERATION | VM_WRITE | VM_READ | CREATE_THREAD | QUERY_INFORMATION
	if (mask == (0x0008 | 0x0020 | 0x0010 | 0x0002 | 0x0400)) {
		*outCritical = TRUE;
		return "Access mask matches Meterpreter process-migrate pattern: "
		       "CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | QUERY_INFORMATION";
	}

	return nullptr;  // nothing anomalous
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

	BOOLEAN isSensitive = targetProcess ? ObjectUtils::IsSensitiveProcess(targetProcess) : FALSE;
	BOOLEAN isLsass     = targetProcess ? ObjectUtils::IsLsass(targetProcess)            : FALSE;

	EmitSyscallNotif(
		(ULONG64)targetPid,
		isLsass     ? "NtOpenProcess: injection-capable access to lsass (credential theft)"   :
		isSensitive ? "NtOpenProcess: injection-capable access to sensitive OS process"        :
		              "NtOpenProcess: injection-capable access to foreign process",
		IoGetCurrentProcess(),
		targetProcess,
		isSensitive   // Critical for all 6 sensitive processes now, not just lsass
	);

	// Access mask anomaly check — fires a second, distinct alert characterizing the tool
	BOOLEAN maskCritical = FALSE;
	const char* maskTag = ClassifyProcessAccessMask(DesiredAccess, &maskCritical);
	if (maskTag) {
		char maskMsg[256];
		RtlStringCbPrintfA(maskMsg, sizeof(maskMsg),
			"NtOpenProcess access mask anomaly (0x%08lX) on %s: %s",
			DesiredAccess,
			isLsass     ? "lsass"     :
			isSensitive ? "sensitive OS process" :
			              "foreign process",
			maskTag);
		EmitSyscallNotif(
			(ULONG64)targetPid,
			maskMsg,
			IoGetCurrentProcess(),
			targetProcess,
			maskCritical || isSensitive);
	}

	if (targetProcess) ObDereferenceObject(targetProcess);
}

// NtCreateThreadEx — flag remote thread creation (classic injection), local
// direct-syscall thread creation (hook bypass), suspended-thread staging, and
// the final step of a fork-and-run sequence.
//
// THREAD_CREATE_FLAGS_CREATE_SUSPENDED (bit 0): attacker creates the thread
// suspended so they can set its context before it runs — two-phase injection.
//
// Fork-and-run: if the target PID was previously recorded as a known spawnto
// host that already received a cross-process write, this NtCreateThreadEx
// completes the three-step sequence and fires a combined Critical alert.
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

	// THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x1
	BOOLEAN createSuspended = (CreateFlags & 0x1) != 0;

	// Build the primary per-event alert message.
	char primaryMsg[200];
	if (crossProcess && createSuspended) {
		RtlStringCbPrintfA(primaryMsg, sizeof(primaryMsg),
			"NtCreateThreadEx: remote SUSPENDED thread in foreign process"
			" startAddr=0x%llX -- two-phase injection staging",
			(ULONG64)StartRoutine);
	} else if (crossProcess) {
		RtlStringCbPrintfA(primaryMsg, sizeof(primaryMsg),
			"NtCreateThreadEx: remote thread creation (classic injection primitive)"
			" startAddr=0x%llX",
			(ULONG64)StartRoutine);
	} else if (createSuspended) {
		RtlStringCbPrintfA(primaryMsg, sizeof(primaryMsg),
			"NtCreateThreadEx: local suspended thread via direct syscall"
			" startAddr=0x%llX -- staged self-injection",
			(ULONG64)StartRoutine);
	} else {
		RtlStringCbPrintfA(primaryMsg, sizeof(primaryMsg),
			"NtCreateThreadEx: local thread via direct syscall (hook bypass)"
			" startAddr=0x%llX",
			(ULONG64)StartRoutine);
	}

	EmitSyscallNotif(
		(ULONG64)StartRoutine,
		primaryMsg,
		IoGetCurrentProcess(),
		nullptr,
		crossProcess  // cross-process = Critical; local = Warning
	);

	// Fork-and-run correlation: resolve the target process PID and check
	// whether it has already been written to by this caller (step 2 of 3).
	if (crossProcess) {
		PEPROCESS targetProc = nullptr;
		if (NT_SUCCESS(ObReferenceObjectByHandle(
			ProcessHandle, 0, *PsProcessType, UserMode,
			(PVOID*)&targetProc, nullptr)) && targetProc) {

			HANDLE targetPid = PsGetProcessId(targetProc);
			char*  targetName = PsGetProcessImageFileName(targetProc);
			char*  callerName = PsGetProcessImageFileName(IoGetCurrentProcess());

			InjectionTaintTracker::MarkTainted(targetPid);

			if (ForkRunTracker::CheckForkRun(targetPid)) {
				// Sequence complete: spawn → write → thread.  Emit the combined alert.
				char forkMsg[280];
				RtlStringCbPrintfA(forkMsg, sizeof(forkMsg),
					"FORK-AND-RUN: '%s' (pid=%llu) spawned '%s' as sacrificial process,"
					" wrote shellcode, then created remote thread at 0x%llX"
					" -- Cobalt Strike fork-and-run / process injection pattern",
					callerName  ? callerName  : "?",
					(ULONG64)PsGetProcessId(IoGetCurrentProcess()),
					targetName  ? targetName  : "?",
					(ULONG64)StartRoutine);

				PKERNEL_STRUCTURED_NOTIFICATION n =
					(PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
						POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'frkr');
				if (n) {
					RtlZeroMemory(n, sizeof(*n));
					SET_CRITICAL(*n);
					SET_SYSCALL_CHECK(*n);
					n->scoopedAddress = (ULONG64)StartRoutine;
					n->pid            = PsGetProcessId(IoGetCurrentProcess());
					n->isPath         = FALSE;
					if (callerName) RtlCopyMemory(n->procName,       callerName, 14);
					if (targetName) RtlCopyMemory(n->targetProcName, targetName, 14);
					SIZE_T msgLen = strlen(forkMsg) + 1;
					n->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'fmsg');
					if (n->msg) {
						RtlCopyMemory(n->msg, forkMsg, msgLen);
						n->bufSize = (ULONG)msgLen;
						if (!CallbackObjects::GetNotifQueue()->Enqueue(n)) {
							ExFreePool(n->msg);
							ExFreePool(n);
						}
					} else { ExFreePool(n); }
				}
			}

			ObDereferenceObject(targetProc);
		}
	}
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

// NtCreateFile — detect raw physical memory and raw device access.
//
// Dangerous paths that indicate DMA / physical memory attacks:
//   \Device\PhysicalMemory   — maps physical RAM into virtual address space
//   \Device\Rawdisk*         — raw disk controller DMA bypass
//   \Device\Harddisk*\Partition0 — raw unpartitioned disk access (sector 0)
//
// MmMapIoSpace (kernel API) is not interceptable via SSDT; raw device opens
// are the usermode-accessible equivalent and equally dangerous.
VOID SyscallsUtils::NtCreateFileHandler(PVOID ObjectAttributes)
{
	if (!ObjectAttributes || !MmIsAddressValid(ObjectAttributes)) return;

	static const WCHAR* kDangerousPaths[] = {
		L"\\Device\\PhysicalMemory",
		L"\\Device\\Rawdisk",
		L"\\Device\\Harddisk",
		nullptr
	};
	// Severity: PhysicalMemory = CRITICAL; others = WARNING unless Partition0
	static const BOOLEAN kPathCritical[] = {
		TRUE,   // PhysicalMemory
		TRUE,   // Rawdisk
		FALSE,  // Harddisk (generic — escalate to CRITICAL if \Partition0)
	};

	__try {
		OBJECT_ATTRIBUTES* oa = (OBJECT_ATTRIBUTES*)ObjectAttributes;
		if (!oa->ObjectName || !MmIsAddressValid(oa->ObjectName)) return;
		UNICODE_STRING* name = (UNICODE_STRING*)oa->ObjectName;
		if (!name->Length || !name->Buffer || !MmIsAddressValid(name->Buffer)) return;

		for (int i = 0; kDangerousPaths[i]; i++) {
			if (!UnicodeStringContains(name, kDangerousPaths[i])) continue;

			// Escalate Harddisk to CRITICAL if targeting Partition0 (raw sector access)
			BOOLEAN critical = kPathCritical[i];
			if (!critical && UnicodeStringContains(name, L"\\Partition0"))
				critical = TRUE;

			// Convert path to narrow for alert message
			char pathBuf[128] = {};
			USHORT copyLen = min(name->Length / sizeof(WCHAR), (USHORT)(sizeof(pathBuf) - 1));
			for (USHORT j = 0; j < copyLen; j++) {
				WCHAR wc = name->Buffer[j];
				pathBuf[j] = (wc < 128) ? (char)wc : '?';
			}

			char msg[256];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"NtCreateFile: dangerous device path opened '%s' "
				"(physical memory / raw DMA access — IOMMU bypass indicator)",
				pathBuf);
			EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, critical);
			break;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// NtAssignProcessToJobObject — detect job object kill attacks.
//
// Attack: attacker creates a job object, assigns the EDR service (or any
// sensitive process) to it, then sets JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
// Closing the job handle terminates the victim process.
//
// NtAssignProcessToJobObject(JobHandle, ProcessHandle)
// ProcessHandle = arg2 (RDX on x64)
//
// We resolve the ProcessHandle to a PEPROCESS and check if it targets the
// EDR service or a sensitive OS process.  ObRegisterCallbacks already strips
// PROCESS_SET_QUOTA from handles to our service, but this provides defense-
// in-depth and alerting for any sensitive process assignment.
VOID SyscallsUtils::NtAssignProcessToJobObjectHandler(HANDLE ProcessHandle)
{
	if (!ProcessHandle) return;

	PEPROCESS targetProc = nullptr;
	NTSTATUS s = ObReferenceObjectByHandle(
		ProcessHandle, 0, *PsProcessType, UserMode, (PVOID*)&targetProc, nullptr);
	if (!NT_SUCCESS(s) || !targetProc) return;

	PEPROCESS callerProc = IoGetCurrentProcess();
	BOOLEAN isEdrService = FALSE;
	BOOLEAN isSensitive = FALSE;

	// Check if target is our EDR service
	ULONG targetPid = HandleToUlong(PsGetProcessId(targetProc));
	ULONG svcPid = (ULONG)InterlockedCompareExchange(
		&ObjectUtils::g_ServicePid, 0, 0);
	if (svcPid != 0 && targetPid == svcPid)
		isEdrService = TRUE;

	if (!isEdrService)
		isSensitive = ObjectUtils::IsSensitiveProcess(targetProc);

	if (isEdrService || isSensitive) {
		char* callerName = PsGetProcessImageFileName(callerProc);
		char* targetName = PsGetProcessImageFileName(targetProc);

		char msg[256];
		RtlStringCbPrintfA(msg, sizeof(msg),
			"Job object attack: '%s' assigning '%s' (pid=%lu) to a job object "
			"— potential KILL_ON_JOB_CLOSE / process limit attack%s",
			callerName ? callerName : "?",
			targetName ? targetName : "?",
			targetPid,
			isEdrService ? " targeting NortonEDR service" : "");

		EmitSyscallNotif(0, msg, callerProc, nullptr,
			isEdrService /* CRITICAL if targeting EDR, WARNING for other sensitive */);
	}

	ObDereferenceObject(targetProc);
}

// NtCreateSection — flag SEC_IMAGE (module stomping) and executable file-backed sections.
// Also tracks the FILE_OBJECT when SEC_IMAGE + a file handle are both present — this is the
// herpaderping pattern: malware creates an image section from a malicious file, then overwrites
// the file with benign content before the process starts, so on-disk != running image.
VOID SyscallsUtils::NtCreateSectionHandler(
	PHANDLE        SectionHandle,
	ACCESS_MASK    DesiredAccess,
	PVOID          ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG          SectionPageProtection,
	ULONG          AllocationAttributes,
	HANDLE         FileHandle
) {
	#define SEC_COMMIT 0x8000000

	// SEC_IMAGE = 0x1000000 — maps a PE as an image (module stomping indicator)
	BOOLEAN isStomp   = (AllocationAttributes & 0x1000000) != 0;
	// File-backed section with an execute protection = reflective/stomping variant
	BOOLEAN isExecMap = (FileHandle != nullptr) &&
		(SectionPageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
		                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	// Memory-backed section with no file handle: pagefile-backed section.
	// Used as an intermediate step in process cloning (NanoDump, LetMeowIn).
	BOOLEAN isMemBacked = (FileHandle == nullptr) &&
		((AllocationAttributes & SEC_COMMIT) != 0) &&
		!(AllocationAttributes & 0x1000000);  // exclude SEC_IMAGE (already handled)

	// Herpaderping: SEC_IMAGE from a file handle — track the FILE_OBJECT so FsFilter can
	// alert if the backing file is written to while this section remains open.
	if (isStomp && FileHandle != nullptr) {
		PVOID fileObject = nullptr;
		NTSTATUS status = ObReferenceObjectByHandle(
			FileHandle,
			0,                   // no specific access required — just need the pointer
			*IoFileObjectType,
			KernelMode,
			&fileObject,
			nullptr);
		if (NT_SUCCESS(status) && fileObject) {
			FsFilter::TrackImageSectionFile((PFILE_OBJECT)fileObject);
			ObDereferenceObject(fileObject);  // TrackImageSectionFile takes its own reference
		}
	}

	if (!isStomp && !isExecMap && !isMemBacked) return;

	EmitSyscallNotif(
		0,
		isStomp
			? "NtCreateSection: SEC_IMAGE section created (module stomping / herpaderping indicator)"
			: isMemBacked
				? "NtCreateSection: pagefile-backed memory section, no file handle "
				  "(process cloning / lsass clone intermediate step)"
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

// NtCreateTransaction — Process Doppelgänging step 1.
// Malware creates an NTFS transaction, writes a malicious PE into it, creates a section from
// the transacted file, then rolls back the transaction leaving no on-disk artifact.
// NtCreateTransaction is almost never called by legitimate user-mode software.
// Note: process creation from a transacted section is blocked on Win10 1803+ by the kernel,
// but telemetry of the attempt is still valuable.
VOID SyscallsUtils::NtCreateTransactionHandler() {
	char procName[16] = {};
	char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
	if (pn) RtlStringCbCopyA(procName, sizeof(procName), pn);

	char msg[160];
	RtlStringCbPrintfA(msg, sizeof(msg),
		"NtCreateTransaction: NTFS transaction created by '%s' -- "
		"Process Doppelganging / transacted section technique",
		procName);
	EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, FALSE);  // Warning: first step only
}

// NtRollbackTransaction — Process Doppelgänging step 3 (after SEC_IMAGE section created).
// Rolling back the transaction while an image section is open erases the on-disk PE —
// the canonical Doppelgänging cleanup step.
VOID SyscallsUtils::NtRollbackTransactionHandler() {
	char procName[16] = {};
	char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
	if (pn) RtlStringCbCopyA(procName, sizeof(procName), pn);

	char msg[160];
	RtlStringCbPrintfA(msg, sizeof(msg),
		"NtRollbackTransaction: transaction rolled back by '%s' -- "
		"Process Doppelganging cleanup step (erases on-disk PE)",
		procName);
	EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, TRUE);  // Critical: cleanup = committed
}

// NtCreateProcessEx — legacy process creation API that accepts an explicit SectionHandle.
//
// Modern CreateProcess calls NtCreateUserProcess. NtCreateProcessEx is used by:
//   - Process doppelgänging (create from transacted section)
//   - Direct section injection (create process from a manually crafted SEC_IMAGE section)
//   - Process cloning (lsass/sensitive parent) — offline dumps (LetMeowIn, NanoDump)
//   - Some debugger internals (ZwCreateProcessEx from kernel; not this path)
//
// Any user-mode NtCreateProcessEx call is highly suspicious. A non-null SectionHandle with
// PROCESS_CREATE_FLAGS_MINIMAL not set (bit 2 of Flags) creates a full non-minimal process
// from that section — the canonical injection technique.
VOID SyscallsUtils::NtCreateProcessExHandler(HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle) {
	// --- NEW: lsass / sensitive parent check (process cloning) ---
	if (ParentProcess && ParentProcess != NtCurrentProcess()) {
		PEPROCESS parentProc = nullptr;
		NTSTATUS st = ObReferenceObjectByHandle(
			ParentProcess,
			PROCESS_QUERY_INFORMATION,
			*PsProcessType,
			UserMode,
			(PVOID*)&parentProc,
			nullptr);
		if (NT_SUCCESS(st) && parentProc) {
			BOOLEAN parentIsLsass     = ObjectUtils::IsLsass(parentProc);
			BOOLEAN parentIsSensitive = ObjectUtils::IsSensitiveProcess(parentProc);
			if (parentIsLsass || parentIsSensitive) {
				char cloneMsg[240];
				char* parentName = PsGetProcessImageFileName(parentProc);
				RtlStringCbPrintfA(cloneMsg, sizeof(cloneMsg),
					"NtCreateProcessEx: cloning %s via ParentProcess handle "
					"(offline lsass clone / credential dump evasion)",
					parentName ? parentName : "sensitive process");
				EmitSyscallNotif(0, cloneMsg, IoGetCurrentProcess(), parentProc, TRUE);
			}
			ObDereferenceObject(parentProc);
		}
	}

	char procName[16] = {};
	char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
	if (pn) RtlStringCbCopyA(procName, sizeof(procName), pn);

	// PROCESS_CREATE_FLAGS_MINIMAL = 0x4 — minimal processes are used by pico providers (WSL, etc.)
	BOOLEAN isMinimal   = (Flags & 0x4) != 0;
	BOOLEAN hasSection  = (SectionHandle != nullptr && SectionHandle != (HANDLE)-1);

	char msg[200];
	if (hasSection && !isMinimal) {
		// Most suspicious: full non-minimal process created from an explicit image section —
		// classic process doppelgänging / section-based injection delivery.
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtCreateProcessEx: '%s' creating NON-MINIMAL process from explicit SectionHandle"
			" (Flags=0x%lx) -- process doppelganging / section injection",
			procName, Flags);
		EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, TRUE);  // Critical
	} else {
		// Still unusual: legacy API path even without an explicit section or with minimal flag.
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtCreateProcessEx: legacy process creation API called by '%s'"
			" (Flags=0x%lx, SectionHandle=%s) -- uncommon on modern Windows",
			procName, Flags, hasSection ? "set" : "null");
		EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, FALSE);  // Warning
	}
}

// NtCreateProcess — even older 8-argument variant (pre-Vista legacy).
// Same technique, no Flags field — SectionHandle is always arg6.
VOID SyscallsUtils::NtCreateProcessHandler(HANDLE ParentProcess, HANDLE SectionHandle) {
	// --- NEW: lsass / sensitive parent check ---
	if (ParentProcess && ParentProcess != NtCurrentProcess()) {
		PEPROCESS parentProc = nullptr;
		NTSTATUS st = ObReferenceObjectByHandle(
			ParentProcess,
			PROCESS_QUERY_INFORMATION,
			*PsProcessType,
			UserMode,
			(PVOID*)&parentProc,
			nullptr);
		if (NT_SUCCESS(st) && parentProc) {
			if (ObjectUtils::IsLsass(parentProc) || ObjectUtils::IsSensitiveProcess(parentProc)) {
				char cloneMsg[240];
				char* parentName = PsGetProcessImageFileName(parentProc);
				RtlStringCbPrintfA(cloneMsg, sizeof(cloneMsg),
					"NtCreateProcess: cloning %s via ParentProcess handle "
					"(offline lsass clone / credential dump evasion)",
					parentName ? parentName : "sensitive process");
				EmitSyscallNotif(0, cloneMsg, IoGetCurrentProcess(), parentProc, TRUE);
			}
			ObDereferenceObject(parentProc);
		}
	}

	char procName[16] = {};
	char* pn = PsGetProcessImageFileName(IoGetCurrentProcess());
	if (pn) RtlStringCbCopyA(procName, sizeof(procName), pn);

	BOOLEAN hasSection = (SectionHandle != nullptr && SectionHandle != (HANDLE)-1);
	char msg[200];
	RtlStringCbPrintfA(msg, sizeof(msg),
		"NtCreateProcess (legacy): called by '%s' with SectionHandle=%s"
		" -- direct section-based process creation bypasses NtCreateUserProcess",
		procName, hasSection ? "set" : "null");
	EmitSyscallNotif(0, msg, IoGetCurrentProcess(), nullptr, hasSection);  // Critical if section set
}

// NtQuerySystemInformation — intercept classes used by EDR-killer tools to recon the kernel.
//
// Class 57 = SystemObjectTypeInformation:
//   Used by EDRSandblast to enumerate all OBJECT_TYPE descriptors and locate the
//   CallbackList for PsProcessType/PsThreadType.  Iterating that list reveals our
//   ObRegisterCallbacks entries, which the attacker then unlinks.
//   No legitimate user-mode software queries this class — Critical.
//
// Class 11 = SystemModuleInformation:
//   Returns loaded kernel module names and base addresses.  Used by Terminator /
//   PPLdump / EDRSandblast to locate the EDR driver's kernel base for subsequent
//   patching.  Legitimate uses exist (sysinternals), but in a monitored process
//   context it is high-fidelity recon — Warning.
//
// Called only when the current process is opted into AltSyscall monitoring, so
// system processes and PPL callers do not trigger this path.
VOID SyscallsUtils::NtQuerySystemInformationHandler(ULONG SystemInformationClass)
{
	const char* msg      = nullptr;
	BOOLEAN     critical = FALSE;

	switch (SystemInformationClass) {
	case 16:   // SystemHandleInformation — enumerate all system handles
		msg      = "Handle recon: NtQuerySystemInformation(16=HandleInfo) "
		           "— enumerating all system handles (handle theft recon; handlekatz/Mimikatz)";
		critical = FALSE;
		break;

	case 64:   // SystemExtendedHandleInformation — extended handle enum with access masks
		msg      = "Handle recon: NtQuerySystemInformation(64=ExtendedHandleInfo) "
		           "— enumerating all handles with access mask details (modern handle theft recon)";
		critical = FALSE;
		break;

	case 57:   // SystemObjectTypeInformation — callback list enumeration
		msg      = "EDR recon: NtQuerySystemInformation(57=ObjectTypeInfo) "
		           "— mapping ObCallback lists (EDRSandblast/Terminator)";
		critical = TRUE;
		break;

	case 11:   // SystemModuleInformation — kernel module base recon
		msg      = "EDR recon: NtQuerySystemInformation(11=ModuleInfo) "
		           "— enumerating kernel module base addresses";
		critical = FALSE;
		break;

	default:
		return;
	}

	PEPROCESS proc = IoGetCurrentProcess();

	// Skip PPL / antimalware protected processes — they have legitimate recon needs.
	PPS_PROTECTION prot = PsGetProcessProtection(proc);
	if (prot && prot->Level != 0) return;

	EmitSyscallNotif(0, msg, proc, nullptr, critical);
}

// NtSetInformationProcess — detect PPL stripping attacks (Gabriel Landau / PPLdump).
//
// Attackers call NtSetInformationProcess(ProcessProtectionLevel=0x3D, ..., Level=0) to strip
// PPL from an unrelated process, silencing its EDR callbacks. This handler fires on any
// user-mode (non-PPL) caller attempting to modify ProcessProtectionLevel on any process.
VOID SyscallsUtils::NtSetInformationProcessHandler(
	HANDLE ProcessHandle,
	ULONG  ProcessInformationClass,
	PVOID  ProcessInformation,
	ULONG  ProcessInformationLength)
{
	UNREFERENCED_PARAMETER(ProcessInformation);
	UNREFERENCED_PARAMETER(ProcessInformationLength);

	// Only care about ProcessProtectionLevel (class 0x3D = 61)
	if (ProcessInformationClass != PROCESS_PROTECTION_LEVEL_CLASS)
		return;

	PEPROCESS caller = IoGetCurrentProcess();

	// Skip if caller is PPL or kernel — same guard used everywhere in the driver
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0)
		return;

	// Resolve target process from handle
	PEPROCESS target    = nullptr;
	BOOLEAN   ownedRef  = FALSE;

	if (ProcessHandle == NtCurrentProcess()) {
		target    = caller;
		ObReferenceObject(target);
		ownedRef  = TRUE;
	} else {
		NTSTATUS st = ObReferenceObjectByHandle(
			ProcessHandle,
			PROCESS_QUERY_INFORMATION,
			*PsProcessType,
			UserMode,
			(PVOID*)&target,
			nullptr);
		if (NT_SUCCESS(st)) ownedRef = TRUE;
	}

	char msg[128];
	if (target) {
		char targetName[15] = {};
		PUCHAR imgName = PsGetProcessImageFileName(target);
		if (imgName) RtlCopyMemory(targetName, imgName, min(strlen((char*)imgName), 14u));

		RtlStringCbPrintfA(msg, sizeof(msg),
			"ANTI-TAMPER: PPL-strip attempt via NtSetInformationProcess"
			"(ProcessProtectionLevel) on '%s' — Gabriel Landau / PPLdump technique",
			targetName);
	} else {
		RtlStringCbPrintfA(msg, sizeof(msg),
			"ANTI-TAMPER: PPL-strip attempt via NtSetInformationProcess"
			"(ProcessProtectionLevel) — target handle unresolvable");
	}

	EmitSyscallNotif(0, msg, caller, target, TRUE /* critical */);

	if (ownedRef && target) ObDereferenceObject(target);
}

// NtDuplicateObject — detect handle duplication with dangerous access masks.
//
// An attacker can call NtDuplicateObject to inherit dangerous access rights (PROCESS_VM_WRITE,
// PROCESS_VM_READ, PROCESS_CREATE_THREAD, etc.) from another process's handle table.
// This syscall-layer detection provides earlier alerting than the OB callback alone.
VOID SyscallsUtils::NtDuplicateObjectHandler(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PVOID  TargetHandle,
	ACCESS_MASK DesiredAccess)
{
	UNREFERENCED_PARAMETER(SourceHandle);
	UNREFERENCED_PARAMETER(TargetHandle);

	// Injection-capable access mask
	const ACCESS_MASK kInjectionMask =
		0x0002 |  // PROCESS_CREATE_THREAD
		0x0008 |  // PROCESS_VM_OPERATION
		0x0010 |  // PROCESS_VM_READ
		0x0020;   // PROCESS_VM_WRITE

	// If access mask has no dangerous bits, or is 0 (inherit all), skip
	BOOLEAN isSuspicious = (DesiredAccess & kInjectionMask) || (DesiredAccess == 0);
	if (!isSuspicious) return;

	PEPROCESS caller = IoGetCurrentProcess();

	// Skip PPL callers
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0) return;

	// Resolve target process
	PEPROCESS targetProcess = nullptr;
	BOOLEAN ownedRef = FALSE;

	if (TargetProcessHandle == NtCurrentProcess()) {
		targetProcess = caller;
		ObReferenceObject(targetProcess);
		ownedRef = TRUE;
	} else {
		NTSTATUS st = ObReferenceObjectByHandle(
			TargetProcessHandle,
			PROCESS_QUERY_INFORMATION,
			*PsProcessType,
			UserMode,
			(PVOID*)&targetProcess,
			nullptr);
		if (NT_SUCCESS(st)) ownedRef = TRUE;
	}

	char msg[128];
	BOOLEAN isSensitive = targetProcess ? ObjectUtils::IsSensitiveProcess(targetProcess) : FALSE;
	BOOLEAN isLsass = targetProcess ? ObjectUtils::IsLsass(targetProcess) : FALSE;

	if (DesiredAccess == 0) {
		// Duplication with "inherit all" access
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtDuplicateObject: duplicating handle with INHERIT_ALL access %s",
			isSensitive ? "(targeting sensitive process)" : "(dangerous access mask)");
	} else {
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtDuplicateObject: duplicating handle with injection-capable access (0x%X) %s",
			DesiredAccess, isSensitive ? "(sensitive process)" : "");
	}

	EmitSyscallNotif(0, msg, caller, targetProcess, isSensitive || isLsass);

	// Access mask anomaly check on duplication
	if (DesiredAccess != 0) {
		BOOLEAN dupMaskCritical = FALSE;
		const char* dupMaskTag = ClassifyProcessAccessMask(DesiredAccess, &dupMaskCritical);
		if (dupMaskTag) {
			char dupMsg[256];
			RtlStringCbPrintfA(dupMsg, sizeof(dupMsg),
				"NtDuplicateObject access mask anomaly (0x%08lX) %s: %s",
				DesiredAccess,
				isSensitive ? "(sensitive process)" : "",
				dupMaskTag);
			EmitSyscallNotif(0, dupMsg, caller, targetProcess,
				dupMaskCritical || isSensitive || isLsass);
		}
	}

	if (ownedRef && targetProcess) ObDereferenceObject(targetProcess);
}

// NtDebugActiveProcess — detect debug-attach credential dump bypass.
//
// Instead of calling NtOpenProcess with PROCESS_VM_READ (which triggers ObCallback stripping),
// an attacker can call NtDebugActiveProcess to attach a debug object to lsass and use
// NtReadVirtualMemory through the debug channel. This is the technique used by Mimikatz's
// sekurlsa::minidump and similar tools.
VOID SyscallsUtils::NtDebugActiveProcessHandler(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle)
{
	UNREFERENCED_PARAMETER(DebugObjectHandle);

	PEPROCESS caller = IoGetCurrentProcess();

	// Skip PPL callers
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0) return;

	// Resolve target process
	PEPROCESS targetProcess = nullptr;
	BOOLEAN ownedRef = FALSE;

	if (ProcessHandle == NtCurrentProcess()) {
		targetProcess = caller;
		ObReferenceObject(targetProcess);
		ownedRef = TRUE;
	} else {
		NTSTATUS st = ObReferenceObjectByHandle(
			ProcessHandle,
			PROCESS_QUERY_INFORMATION,
			*PsProcessType,
			UserMode,
			(PVOID*)&targetProcess,
			nullptr);
		if (NT_SUCCESS(st)) ownedRef = TRUE;
	}

	if (!targetProcess) return;

	// Check if target is lsass or any sensitive process
	BOOLEAN isLsass = ObjectUtils::IsLsass(targetProcess);
	BOOLEAN isSensitive = ObjectUtils::IsSensitiveProcess(targetProcess);

	char msg[128];
	if (isLsass) {
		RtlStringCbPrintfA(msg, sizeof(msg),
			"ANTI-TAMPER: NtDebugActiveProcess on lsass — debug-attach credential dump bypass");
	} else if (isSensitive) {
		RtlStringCbPrintfA(msg, sizeof(msg),
			"ANTI-TAMPER: NtDebugActiveProcess on sensitive OS process — potential code injection");
	} else {
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtDebugActiveProcess: attaching debugger to foreign process");
	}

	EmitSyscallNotif(0, msg, caller, targetProcess, isLsass || isSensitive);

	if (ownedRef && targetProcess) ObDereferenceObject(targetProcess);
}

// NtSetInformationThread(ThreadImpersonationToken) — detect token impersonation escalation.
//
// When an attacker steals a privileged token (SYSTEM, debug-capable, etc.) and assigns it
// to their own thread via NtSetInformationThread(ThreadImpersonationToken = 0x5), this syscall
// fires. TokenMonitor catches orphaned tokens post-session-teardown; this catches the
// impersonation act itself by checking token privilege level.
VOID SyscallsUtils::NtSetInformationThreadHandler(
	HANDLE ThreadHandle,
	ULONG  ThreadInformationClass,
	PVOID  ThreadInformation,
	ULONG  ThreadInformationLength)
{
	// Only interested in ThreadImpersonationToken (0x5)
	if (ThreadInformationClass != 0x5) return;

	PEPROCESS caller = IoGetCurrentProcess();

	// Skip PPL callers
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0) return;

	// Read the token handle from ThreadInformation safely
	if (!ThreadInformation || ThreadInformationLength < sizeof(HANDLE)) return;

	HANDLE tokenHandle = nullptr;
	__try {
		if (MmIsAddressValid(ThreadInformation)) {
			tokenHandle = *(PHANDLE)ThreadInformation;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return;
	}

	if (!tokenHandle) return;

	// Resolve token
	PVOID token = nullptr;
	NTSTATUS st = ObReferenceObjectByHandle(tokenHandle, TOKEN_QUERY, NULL, UserMode, &token, nullptr);
	if (!NT_SUCCESS(st) || !token) return;

	// Query token info — check for dangerous privileges
	// SeDebugPrivilege and SeTcbPrivilege are the highest-value escalations
	TOKEN_PRIVILEGES* privs = nullptr;
	ULONG privSize = 0;

	__try {
		st = SeQueryInformationToken(token, TokenPrivileges, &privs);
		if (NT_SUCCESS(st) && privs) {
			BOOLEAN hasDebugPriv = FALSE, hasTcbPriv = FALSE, hasImpersonatePriv = FALSE;

			for (ULONG i = 0; i < privs->PrivilegeCount; i++) {
				if (privs->Privileges[i].Luid.LowPart == SE_DEBUG_PRIVILEGE)
					hasDebugPriv = TRUE;
				else if (privs->Privileges[i].Luid.LowPart == SE_TCB_PRIVILEGE)
					hasTcbPriv = TRUE;
				else if (privs->Privileges[i].Luid.LowPart == SE_IMPERSONATE_PRIVILEGE)
					hasImpersonatePriv = TRUE;
			}

			char msg[128];
			BOOLEAN critical = hasDebugPriv || hasTcbPriv;

			if (hasDebugPriv || hasTcbPriv) {
				RtlStringCbPrintfA(msg, sizeof(msg),
					"CRITICAL: NtSetInformationThread(ThreadImpersonationToken) assigning %s token — privilege escalation",
					hasDebugPriv ? "SeDebugPrivilege" : "SeTcbPrivilege");
			} else if (hasImpersonatePriv) {
				RtlStringCbPrintfA(msg, sizeof(msg),
					"NtSetInformationThread(ThreadImpersonationToken) assigning SeImpersonatePrivilege token");
				critical = FALSE;
			} else {
				RtlStringCbPrintfA(msg, sizeof(msg),
					"NtSetInformationThread(ThreadImpersonationToken) — token impersonation");
				critical = FALSE;
			}

			EmitSyscallNotif(0, msg, caller, nullptr, critical);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	ObDereferenceObject(token);
}

// NtTraceControl — detect ETW provider/session manipulation.
//
// ETW can be disabled or manipulated via NtTraceControl without hooking any ETW functions.
// Dangerous function codes: 5 (update/enable trace), 31 (disable provider).
VOID SyscallsUtils::NtTraceControlHandler(ULONG FunctionCode)
{
	PEPROCESS caller = IoGetCurrentProcess();

	// Skip PPL/system callers
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0) return;

	// Flag update-trace and disable-provider operations
	if (FunctionCode == 5 || FunctionCode == 31) {
		const char* action = (FunctionCode == 5) ? "update/enable trace" : "disable provider";
		char msg[128];
		RtlStringCbPrintfA(msg, sizeof(msg),
			"NtTraceControl: user-mode process calling ETW %s — possible ETW bypass",
			action);
		EmitSyscallNotif(0, msg, caller, nullptr, FALSE); // WARNING
	}
}

// NtCreateNamedPipeFile — detect named pipe C2 / lateral movement.
//
// Cobalt Strike SMB beacons and PsExec lateral movement use named pipes as C2 transport.
// Alert on named pipe creation from non-system processes, especially pipes not in
// well-known system list.
VOID SyscallsUtils::NtCreateNamedPipeFileHandler(PVOID ObjectAttributes)
{
	// Static list of system-owned named pipes (legitimate)
	static const WCHAR* kSystemPipes[] = {
		L"\\Device\\NamedPipe\\lsass",
		L"\\Device\\NamedPipe\\winlogon",
		L"\\Device\\NamedPipe\\wininit",
		L"\\Device\\NamedPipe\\svcctl",
		L"\\Device\\NamedPipe\\samr",
		L"\\Device\\NamedPipe\\ntsvcs",
		L"\\Device\\NamedPipe\\protected_storage",
		nullptr
	};

	PEPROCESS caller = IoGetCurrentProcess();

	// Skip kernel/PPL callers
	PPS_PROTECTION callerProt = PsGetProcessProtection(caller);
	if (callerProt && callerProt->Level != 0) return;

	// Skip system/kernel processes
	char* name = PsGetProcessImageFileName(caller);
	if (!name) return;
	char lower[16] = {};
	for (int i = 0; i < 15 && name[i]; i++)
		lower[i] = (name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i];

	// Whitelist: services.exe, svchost.exe, lsass.exe, wininit.exe, csrss.exe, System
	if (strcmp(lower, "services.exe") == 0 || strcmp(lower, "svchost.exe") == 0 ||
		strcmp(lower, "lsass.exe") == 0 || strcmp(lower, "wininit.exe") == 0 ||
		strcmp(lower, "csrss.exe") == 0 || strcmp(lower, "system") == 0)
		return;

	// Extract pipe name from ObjectAttributes
	if (!ObjectAttributes || !MmIsAddressValid(ObjectAttributes)) return;

	OBJECT_ATTRIBUTES* objAttr = (OBJECT_ATTRIBUTES*)ObjectAttributes;
	if (!objAttr->ObjectName || !MmIsAddressValid(objAttr->ObjectName)) return;

	UNICODE_STRING* pipeName = (UNICODE_STRING*)objAttr->ObjectName;
	if (!pipeName->Length || !MmIsAddressValid(pipeName->Buffer)) return;

	// Check against system pipe list
	BOOLEAN isSystemPipe = FALSE;
	for (int i = 0; kSystemPipes[i]; i++) {
		UNICODE_STRING sysPipe;
		RtlInitUnicodeString(&sysPipe, kSystemPipes[i]);
		if (RtlEqualUnicodeString(pipeName, &sysPipe, TRUE)) {
			isSystemPipe = TRUE;
			break;
		}
	}

	if (!isSystemPipe) {
		// Check for known C2 framework named pipe patterns — escalate to CRITICAL
		static const WCHAR* kC2PipePatterns[] = {
			L"msagent_",       // Cobalt Strike default SMB beacon
			L"MSSE-",          // Cobalt Strike MSSE-*-server
			L"postex_",        // Cobalt Strike post-exploitation
			L"postex_ssh_",    // Cobalt Strike SSH
			L"status_",        // Cobalt Strike status pipe variant
			L"mojo.5688.8052", // Cobalt Strike named pipe stager
			L"win_svc",        // Cobalt Strike service pipe
			L"ntsvcs_",        // Cobalt Strike masquerading as ntsvcs
			L"scerpc_",        // Cobalt Strike masquerading as scerpc
			L"meterpreter",    // Metasploit Meterpreter
			L"PSEXESVC",       // PsExec service pipe
			L"RemCom",         // RemCom (open-source PsExec)
			L"csexec",         // CsExec lateral movement
			L"winsvc_",        // Generic malware service pipe
			nullptr
		};

		BOOLEAN isC2Pipe = FALSE;
		for (int i = 0; kC2PipePatterns[i]; i++) {
			// Case-insensitive substring match within the pipe name
			UNICODE_STRING pattern;
			RtlInitUnicodeString(&pattern, kC2PipePatterns[i]);
			if (pipeName->Length >= pattern.Length) {
				// Slide window over pipe name looking for substring
				USHORT maxOff = (pipeName->Length - pattern.Length) / sizeof(WCHAR);
				for (USHORT off = 0; off <= maxOff; off++) {
					UNICODE_STRING slice;
					slice.Buffer = pipeName->Buffer + off;
					slice.Length = pattern.Length;
					slice.MaximumLength = pattern.Length;
					if (RtlEqualUnicodeString(&slice, &pattern, TRUE)) {
						isC2Pipe = TRUE;
						break;
					}
				}
			}
			if (isC2Pipe) break;
		}

		if (isC2Pipe) {
			char msg[196];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"NtCreateNamedPipeFile: C2 framework pipe pattern detected "
				"(Cobalt Strike / Metasploit / PsExec)");
			EmitSyscallNotif(0, msg, caller, nullptr, TRUE); // CRITICAL
		} else {
			char msg[128];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"NtCreateNamedPipeFile: non-system process creating named pipe");
			EmitSyscallNotif(0, msg, caller, nullptr, FALSE); // WARNING
		}
	}
}

// ---------------------------------------------------------------------------
// ClassifyThreadAccessMask — thread-level access mask anomaly detection.
// ---------------------------------------------------------------------------

static const char* ClassifyThreadAccessMask(ACCESS_MASK mask, BOOLEAN* outCritical)
{
	*outCritical = FALSE;

	// THREAD_ALL_ACCESS: same lazy-spray pattern as PROCESS_ALL_ACCESS.
	// 0x1FFFFF on Win10/11
	if ((mask & 0x1FFFFF) == 0x1FFFFF) {
		return "THREAD_ALL_ACCESS requested — offensive tools spray this "
		       "instead of requesting minimal rights";
	}

	// SET_CONTEXT without GET_CONTEXT: write-only thread context is unusual.
	// Legitimate debuggers always read context before writing it back.
	if ((mask & THREAD_SET_CONTEXT) && !(mask & THREAD_GET_CONTEXT)) {
		return "THREAD_SET_CONTEXT without THREAD_GET_CONTEXT — anomalous; "
		       "legitimate debuggers read context before overwriting it";
	}

	// Known Mimikatz sekurlsa thread pattern:
	// Opens a thread in lsass with exactly THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
	if (mask == (THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME)) {
		*outCritical = TRUE;
		return "Access mask matches Mimikatz sekurlsa thread pattern: "
		       "THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME";
	}

	return nullptr;
}

// ---------------------------------------------------------------------------
// NtOpenThread — detect thread hijacking and context scraping.
//
// Attacker opens a handle to a thread in a sensitive process (lsass, csrss, etc.)
// with THREAD_SET_CONTEXT or THREAD_GET_CONTEXT to perform thread hijacking or
// credential scraping via context manipulation.
// ---------------------------------------------------------------------------

VOID SyscallsUtils::NtOpenThreadHandler(
	HANDLE      ThreadHandle,
	ACCESS_MASK DesiredAccess,
	PVOID       ObjectAttributes,
	PCLIENT_ID  ClientId)
{
	UNREFERENCED_PARAMETER(ThreadHandle);
	UNREFERENCED_PARAMETER(ObjectAttributes);

	PPS_PROTECTION prot = PsGetProcessProtection(IoGetCurrentProcess());
	if (prot && prot->Level != 0) return;

	// Rights that enable thread hijacking / context scraping
	const ACCESS_MASK kDangerMask =
		THREAD_SET_CONTEXT |
		THREAD_GET_CONTEXT |
		THREAD_SUSPEND_RESUME;

	if (!(DesiredAccess & kDangerMask)) return;

	// Resolve target thread's owning process
	PEPROCESS targetProc = nullptr;
	if (ClientId) {
		__try {
			HANDLE tid = ClientId->UniqueThread;
			PETHREAD th = nullptr;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &th))) {
				targetProc = IoThreadToProcess(th);
				ObReferenceObject(targetProc);
				ObDereferenceObject(th);
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	BOOLEAN isSensitive = targetProc ? ObjectUtils::IsSensitiveProcess(targetProc) : FALSE;
	BOOLEAN isLsass     = targetProc ? ObjectUtils::IsLsass(targetProc)            : FALSE;

	char msgBuf[220];
	RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
		"NtOpenThread: dangerous rights (0x%08lX) requested on %s thread — "
		"thread hijack / context scrape",
		DesiredAccess,
		isLsass     ? "lsass"     :
		isSensitive ? "sensitive OS process" :
		              "foreign process");

	EmitSyscallNotif(
		targetProc ? (ULONG64)PsGetProcessId(targetProc) : 0,
		msgBuf,
		IoGetCurrentProcess(),
		targetProc,
		isSensitive);

	// Thread access mask anomaly check
	BOOLEAN tMaskCritical = FALSE;
	const char* tMaskTag = ClassifyThreadAccessMask(DesiredAccess, &tMaskCritical);
	if (tMaskTag) {
		char tMaskMsg[256];
		RtlStringCbPrintfA(tMaskMsg, sizeof(tMaskMsg),
			"NtOpenThread access mask anomaly (0x%08lX) on %s thread: %s",
			DesiredAccess,
			isLsass     ? "lsass"     :
			isSensitive ? "sensitive OS process" :
			              "foreign process",
			tMaskTag);
		EmitSyscallNotif(
			targetProc ? (ULONG64)PsGetProcessId(targetProc) : 0,
			tMaskMsg,
			IoGetCurrentProcess(),
			targetProc,
			tMaskCritical || isSensitive);
	}

	if (targetProc) ObDereferenceObject(targetProc);
}

// ---------------------------------------------------------------------------
// NtFlushInstructionCache — detect post-injection cache flush.
//
// After injecting shellcode via NtWriteVirtualMemory, attackers call
// NtFlushInstructionCache to ensure the CPU instruction cache is updated.
// A cross-process flush is a strong post-injection indicator.
// ---------------------------------------------------------------------------

VOID SyscallsUtils::NtFlushInstructionCacheHandler(
	HANDLE ProcessHandle,
	PVOID  BaseAddress,
	SIZE_T Length)
{
	// Only flag cross-process flushes (NtCurrentProcess() == (HANDLE)-1)
	if (ProcessHandle == NtCurrentProcess()) return;
	if ((LONG_PTR)ProcessHandle == -1) return;

	PPS_PROTECTION prot = PsGetProcessProtection(IoGetCurrentProcess());
	if (prot && prot->Level != 0) return;

	PEPROCESS targetProc = nullptr;
	NTSTATUS  st = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION,
		                *PsProcessType, KernelMode, (PVOID*)&targetProc, nullptr);

	char msgBuf[220];
	if (NT_SUCCESS(st)) {
		BOOLEAN wholeProcFlush = (BaseAddress == nullptr && Length == 0);
		RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
			"NtFlushInstructionCache: cross-process flush on '%s' (pid=%llu) "
			"base=0x%llX len=0x%llX — post-injection indicator%s",
			PsGetProcessImageFileName(targetProc),
			(ULONG64)PsGetProcessId(targetProc),
			(ULONG64)BaseAddress, (ULONG64)Length,
			wholeProcFlush ? " [full process flush]" : "");
		ObDereferenceObject(targetProc);
	} else {
		RtlStringCbPrintfA(msgBuf, sizeof(msgBuf),
			"NtFlushInstructionCache: cross-process flush (handle resolution failed) "
			"base=0x%llX len=0x%llX — post-injection indicator",
			(ULONG64)BaseAddress, (ULONG64)Length);
	}

	EmitSyscallNotif(0, msgBuf, IoGetCurrentProcess(), nullptr, FALSE);
}

// NtProtectVirtualMemory — detect ntdll/DLL stomping and cross-process protection changes.
//
// Stomping technique: attacker maps a fresh ntdll.dll from disk (SEC_IMAGE or FILE_MAP_READ),
// calls NtProtectVirtualMemory(NtCurrentProcess, ntdll_text_base, ..., PAGE_READWRITE) to
// make the live hooked ntdll writable, then memcpy's clean bytes over it to remove our hooks.
// PAGE_READWRITE does NOT trigger the existing PAGE_EXECUTE_READWRITE guard in HookDll, so
// this is the kernel backstop for that bypass path.
VOID SyscallsUtils::NtProtectVirtualMemoryHandler(
	HANDLE  ProcessHandle,
	PVOID*  BaseAddress,
	PSIZE_T RegionSize,
	ULONG   NewProtect
) {
	// Pass through when write OR execute bits are being set — both are interesting.
	const ULONG kWriteMask = PAGE_READWRITE | PAGE_WRITECOPY |
	                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	const ULONG kExecMask  = PAGE_EXECUTE | PAGE_EXECUTE_READ |
	                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	if (!(NewProtect & kWriteMask) && !(NewProtect & kExecMask)) return;

	// Resolve target process
	PEPROCESS targetProcess = nullptr;
	BOOLEAN   pseudoHandle  = (ProcessHandle == (HANDLE)-1);
	if (pseudoHandle) {
		targetProcess = IoGetCurrentProcess();
		ObReferenceObject(targetProcess);
	} else {
		if (!NT_SUCCESS(ObReferenceObjectByHandle(
				ProcessHandle, PROCESS_VM_OPERATION, nullptr,
				UserMode, (PVOID*)&targetProcess, nullptr))) return;
	}

	PEPROCESS callerProcess = IoGetCurrentProcess();
	BOOLEAN   crossProcess  = (targetProcess != callerProcess);

	PVOID  base = nullptr;
	SIZE_T size = 0;
	if (BaseAddress && MmIsAddressValid(BaseAddress)) {
		__try { base = *BaseAddress; } __except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	if (RegionSize && MmIsAddressValid(RegionSize)) {
		__try { size = *RegionSize; } __except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	if (crossProcess) {
		// Any write grant on a foreign process is suspicious (process hollowing / injection staging)
		if (NewProtect & kWriteMask) {
			char msg[220];
			RtlStringCbPrintfA(msg, sizeof(msg),
				"NtProtectVirtualMemory: cross-process write permission granted "
				"addr=0x%llX size=0x%llX prot=0x%lX",
				(ULONG64)base, (ULONG64)size, NewProtect);
			EmitSyscallNotif((ULONG64)base, msg, callerProcess, targetProcess, TRUE);
		}
	} else if (base) {
		MEMORY_BASIC_INFORMATION mbi = {};
		SIZE_T retLen = 0;
		NTSTATUS s = ZwQueryVirtualMemory(
			NtCurrentProcess(), base,
			(MEMORY_INFORMATION_CLASS)0,  // MemoryBasicInformation
			&mbi, sizeof(mbi), &retLen);

		if (NT_SUCCESS(s)) {
			// ntdll/DLL stomp: write grant on image-backed memory
			if ((NewProtect & kWriteMask) && mbi.Type == 0x1000000 /* MEM_IMAGE */) {
				char msg[240];
				RtlStringCbPrintfA(msg, sizeof(msg),
					"NtProtectVirtualMemory: write permission on image-mapped region "
					"addr=0x%llX size=0x%llX prot=0x%lX — ntdll/DLL stomp attempt",
					(ULONG64)base, (ULONG64)size, NewProtect);
				EmitSyscallNotif((ULONG64)base, msg, callerProcess, nullptr, TRUE);
			}

			// W->X flip on private memory: shellcode/BOF staging pattern.
			// RW private alloc is written (BOF loaded), then flipped to RX for execution.
			// Only flag pure execute grants (not RWX — those are caught by the write check above).
			BOOLEAN newIsExecOnly = (NewProtect & kExecMask) && !(NewProtect & kWriteMask);
			BOOLEAN oldWasWritable = (mbi.Protect & kWriteMask) != 0;
			if (newIsExecOnly && oldWasWritable && mbi.Type == 0x20000 /* MEM_PRIVATE */) {
				char msg[280];
				RtlStringCbPrintfA(msg, sizeof(msg),
					"NtProtectVirtualMemory: W->X flip on private memory "
					"addr=0x%llX size=0x%llX oldProt=0x%lX newProt=0x%lX "
					"— shellcode/BOF execution staging",
					(ULONG64)base, (ULONG64)size, mbi.Protect, NewProtect);
				EmitSyscallNotif((ULONG64)base, msg, callerProcess, nullptr, TRUE);
			}
		}
	}

	ObDereferenceObject(targetProcess);
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