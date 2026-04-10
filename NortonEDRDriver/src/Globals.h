#pragma once
#include <ntifs.h>

#include <ndis.h>
#include <ndis/nbl.h>

#define INITGUID
#include <guiddef.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <fltKernel.h>

#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "Structs.h"
#include "Defs.h"
#include "Pe.h"
#include "Offsets.h"

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")
#pragma comment(lib, "fltMgr.lib")

#pragma warning(disable:4309)
#pragma warning(disable:4245)
#pragma warning(disable: 4244)
#pragma warning(disable:4100)  // unreferenced formal parameter
#pragma warning(disable:4101)  // unreferenced local variable
#pragma warning(disable:4189)  // local variable initialized but not referenced
#pragma warning(disable:4267)  // conversion from size_t to smaller type
#pragma warning(disable:4456)  // declaration hides previous local declaration
#pragma warning(disable:4458)  // declaration hides class member
#pragma warning(disable:4459)  // declaration hides global declaration

#define ALTITUDE L"300021"

#define MAX_BUFFER_COUNT 1024
#define HASH_TABLE_SIZE 256

#define NORTONAV_RETRIEVE_DATA_NOTIF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NORTONAV_RETRIEVE_DATA_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input: HOOKDLL_INJECT_CONFIG — configures kernel APC injection of HookDll.dll
#define NORTONAV_SET_INJECT_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input: NETWORK_FILTER_CONFIG — sets the WFP blocked-port list from user-mode
#define NORTONAV_SET_NETWORK_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define END_THAT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x216, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input: UINT32 PID — registers the caller as the EDR service process.
// The kernel will then strip PROCESS_TERMINATE / VM_WRITE from any handle
// opened to that PID (self-protection, like CrowdStrike's CSAgent protection).
#define NORTONAV_REGISTER_SERVICE_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input: UINT32 PID — HookDll confirms successful load + hook installation.
// Absence of confirmation within 5s triggers a WARNING alert.
#define NORTONAV_HOOKDLL_CONFIRM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Global device object — needed by IoAllocateWorkItem for deferred hash verification
// and injection timeout checking.
extern PDEVICE_OBJECT g_DeviceObject;

// Payload sent from user mode to configure DllInjector.
// LoadLibraryWAddress is the VA of LoadLibraryW in the NortonEDR process;
// it is valid in all processes because system DLLs are mapped at the same VA
// per boot (shared image section, boot-time ASLR only).
struct HOOKDLL_INJECT_CONFIG {
    PVOID  LoadLibraryWAddress; // user-mode VA of LoadLibraryW
    ULONG  PathByteLen;         // byte length of HookDllPath including null
    ULONG  OwnerPid;            // NortonEDR PID — excluded from injection
    WCHAR  HookDllPath[260];    // full path to HookDll.dll
};

// Payload sent from user mode to configure the WFP blocked-port list.
struct NETWORK_FILTER_CONFIG {
    UINT16 BlockedPorts[32];    // destination ports to block
    UINT32 NumBlockedPorts;     // number of valid entries in BlockedPorts
};

#define ProcessAltSystemCallInformation 0x64

#define SHA256_BLOCK_SIZE 32

#define FORMAT_ADDR(addr) \
	((addr) & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF)

DEFINE_GUID(NORTONAV_CALLOUT_GUID,
	0x0bf56436, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf4);
DEFINE_GUID(NORTONAV_SUBLAYER_GUID,
	0xe1d364e8, 0xcd84, 0x4a48, 0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xee);

BOOLEAN isCpuVTxEptSupported();

size_t SafeStringLength(
	const char*, 
	size_t
);

int contains_bytes_bitwise(
	UINT64, 
	const UINT8*, 
	size_t
);

int contains_signature(
	ULONGLONG, 
	size_t, 
	const UINT8*, 
	size_t
);

int starts_with_signature(
	ULONGLONG, 
	const UINT8*, 
	size_t
);

const char* GetProtectionString(
	ULONG
);

NTSTATUS getProcessBaseAddr(
	HANDLE,
	PVOID*,
	PSIZE_T
);

VOID InitializeFunctionMap(
	PFUNCTION_MAP
);

VOID AddFunctionToMap(
	PFUNCTION_MAP, 
	PVOID, 
	PUNICODE_STRING
);

UNICODE_STRING* GetFunctionNameFromMap(
	PFUNCTION_MAP, 
	PVOID
);

ULONG HashFunction(
	PVOID
);

VOID FreeFunctionMap(
	PFUNCTION_MAP
);

PSSDT_TABLE InitializeSsdtTable(
	ULONG
);

VOID PrintSsdtTable(
	PSSDT_TABLE
);

VOID FreeSsdtTable(
	PSSDT_TABLE
);

PVOID GetFunctionAddressBySSN(
	PSSDT_TABLE, 
	ULONG
);

ULONG getSSNByName(
	PSSDT_TABLE ssdtTable,
	UNICODE_STRING* functionName,
	PFUNCTION_MAP g_exportsMap
);

ULONG64 NullifyLastDigit(
	ULONG64
);

ULONG64 GetWow64UserModeAddressVpn(
	ULONG64
);

BOOLEAN FileIsExe(
	PUNICODE_STRING
);

BOOLEAN UnicodeStringContains(
	PUNICODE_STRING, 
	PCWSTR
);

const char* GetProtectionTypeString(
	UCHAR
);

const char* GetSignerTypeString(
	UCHAR
);

ULONG64 GetUserModeAddressVpn(
	ULONG64
);

NTSTATUS TerminateProcess(HANDLE);

char* FetchNtVersion(DWORD);

class OffsetsMgt {
	static KERNEL_STRUCTURES_OFFSET* offsets;

public:
	static BOOLEAN InitWinStructsOffsets();
	static KERNEL_STRUCTURES_OFFSET* GetOffsets() {
		return offsets;
	}
};

class SsdtUtils;
class ComUtils {

public:

	VOID invertedMsg();

};

class VadUtils {

	PEPROCESS process;
	RTL_AVL_TREE* root;
	VAD_RANGE ntdllVadRange;
	VAD_RANGE procVadRange;

public:
	
	VadUtils();

	VadUtils(
		PEPROCESS
	);

	//~VadUtils() {}

	VOID addressLookup();

	static BOOLEAN isAddressOutOfNtdll(
		RTL_BALANCED_NODE*, 
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);

	static BOOLEAN isAddressOutOfKernelBase(
		RTL_BALANCED_NODE*,
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);

	static BOOLEAN isAddressOutOfSpecificDll(
		RTL_BALANCED_NODE*,
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*,
		unsigned short*,
		unsigned short*
	);

	static BOOLEAN isAddressOutOfGdi32(
		RTL_BALANCED_NODE*,
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);
	

	VOID exploreVadTreeAndVerifyLdrIngtegrity(
		RTL_BALANCED_NODE*,
		UNICODE_STRING*,
		BOOLEAN*
	);

	BOOLEAN isVadImageAddrIdenticalToLdr(
		PEPROCESS,
		ULONG64
	);

	RTL_AVL_TREE* getVadRoot() {
		return root;
	}

	// Walk all SEC_IMAGE (VadImageMap) VAD nodes in the target process and alert on any
	// executable file-backed mapping that has no corresponding entry in the PEB LDR list.
	// Catches reflective/manual-map DLL injection. Must be called at PASSIVE_LEVEL.
	static VOID ScanForHiddenMappings(PEPROCESS process, BufferQueue* queue);

	// Check if an address falls in a private, executable VAD region (shellcode/RWX alloc).
	// Used to detect indirect syscalls originating from attacker code rather than DLLs.
	static BOOLEAN IsAddressInPrivateExecVad(PRTL_BALANCED_NODE root, ULONG64 address);

};

class StackUtils {

protected:
	PVOID stackBase;

public:

	ULONG64 getStackStartRtl();
	
	ULONG64 getSSP();

	BOOLEAN isCETEnabled();

	BOOLEAN isCETSupported();

	BOOLEAN isStackCorruptedRtlCET(
		PVOID*
	);

};


class ThreadTracker {

	THREAD_TRACKER g_ThreadTracker;

public:

	VOID InitializeThreadTracker();

	VOID AddThread(
		HANDLE, 
		HANDLE
	);
	
	VOID RemoveThread(
		HANDLE
	);
};


class WdfTcpipUtils {

	PDEVICE_OBJECT DeviceObject = NULL;
	HANDLE EngineHandle = NULL;
	UINT32 RegCalloutId = 0, AddCalloutId = 0;
	UINT64 FilterId = 0;

public:

	NTSTATUS InitWfp();
	NTSTATUS WfpAddSubLayer();
	NTSTATUS WfpAddFilter();
	NTSTATUS WfpRegisterCallout();
	VOID UnitializeWfp();
	NTSTATUS AddSubLayer();

	// Update the blocked-port list from user-mode (NORTONAV_SET_NETWORK_CONFIG).
	static VOID WfpSetBlocklist(const UINT16* ports, UINT32 count);
	
	static VOID TcpipFilteringCallback(
		const FWPS_INCOMING_VALUES*,
		const FWPS_INCOMING_METADATA_VALUES0*,
		PVOID,
		const void*,
		const FWPS_FILTER*,
		UINT64,
		FWPS_CLASSIFY_OUT*
	);
	
	static VOID TcpipFlowDeleteCallback(
		UINT16,
		UINT32,
		UINT64
	);

	static NTSTATUS TcpipNotifyCallback(
		FWPS_CALLOUT_NOTIFY_TYPE,
		const GUID*,
		const FWPS_FILTER*
	);

};

class SsdtUtils {

	FUNCTION_MAP exportsMap;

public:

	SsdtUtils() {}

	~SsdtUtils() {}

	FUNCTION_MAP getFunctionsMap() {
		return exportsMap;
	}
	
	VOID InitExportsMap();
	
	PVOID GetKernelBaseAddress();
	
	VOID VisitSSDT(
		PVOID, 
		ULONG
	);
	
	FUNCTION_MAP GetAndStoreKernelExports(
		PVOID
	);
	
	ULONGLONG LeakKeServiceDescriptorTableEptRvi();

	static ULONGLONG LeakKiSystemServiceUser();

	static ULONGLONG LeakKeServiceDescriptorTable(
		ULONGLONG
	);

};

class BytesQueue {
private:
	RAW_BUFFER* bufferArray;
	ULONG capacity;
	ULONG size;
	ULONG head;
	ULONG tail;
	KSPIN_LOCK spinLock;

public:
	BytesQueue() : bufferArray(nullptr), capacity(0), size(0), head(0), tail(0) {}

	VOID Init(ULONG maxBuf) {
		capacity = maxBuf;
		size = 0;
		head = 0;
		tail = 0;

		bufferArray = (RAW_BUFFER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RAW_BUFFER) * capacity, 'qBuf');
		if (!bufferArray) {
			DbgPrint("Failed to allocate buffer array\n");
			capacity = 0;
			return;
		}

		RtlZeroMemory(bufferArray, sizeof(RAW_BUFFER) * capacity);
		KeInitializeSpinLock(&spinLock);
	}

	BOOLEAN Enqueue(RAW_BUFFER rawBuffer) {
		if (!rawBuffer.buffer || rawBuffer.size == 0) {
			DbgPrint("Invalid RAW_BUFFER provided to Enqueue\n");
			return FALSE;
		}

		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == capacity) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return FALSE;  // Queue is full
		}

		bufferArray[tail] = rawBuffer;
		tail = (tail + 1) % capacity;
		size++;

		//if (size > 0) {
		//	DbgPrint("[Enqueue] Data added successfully\n");
		//}

		KeReleaseSpinLock(&spinLock, oldIrql);
		return TRUE;
	}

	RAW_BUFFER Dequeue() {
		RAW_BUFFER rawBuffer = { nullptr, 0 };

		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == 0) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return rawBuffer; // Queue is empty
		}

		rawBuffer = bufferArray[head];
		head = (head + 1) % capacity;
		size--;

		//if (size == 0) {
		//	DbgPrint("[Dequeue] Queue is empty now\n");
		//}

		KeReleaseSpinLock(&spinLock, oldIrql);
		return rawBuffer;
	}

	ULONG GetSize() {
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		ULONG currentSize = size;
		KeReleaseSpinLockFromDpcLevel(&spinLock);
		return currentSize;
	}

	VOID Cleanup() {
		if (bufferArray) {
			ExFreePool(bufferArray);
			bufferArray = nullptr;
		}
		capacity = 0;
		size = 0;
		head = 0;
		tail = 0;
	}

	VOID PrintSizes() {
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		for (ULONG i = 0; i < size; i++) {
			RAW_BUFFER rb = bufferArray[(head + i) % capacity];
			DbgPrint("\tSize %d: %lu\n", i, rb.size);
		}
		KeReleaseSpinLockFromDpcLevel(&spinLock);
	}

	//~BytesQueue() {
	//	Cleanup();
	//}
};



class BufferQueue {

private:

	PKERNEL_STRUCTURED_NOTIFICATION* bufferArray;
	ULONG capacity;
	ULONG size;
	ULONG head;
	ULONG tail;
	KSPIN_LOCK spinLock;

public:

	BufferQueue() {}

	VOID Init(ULONG maxBuf) {

		capacity = maxBuf;
		size = 0;
		head = 0;
		tail = 0;

		bufferArray = (PKERNEL_STRUCTURED_NOTIFICATION*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PKERNEL_STRUCTURED_NOTIFICATION) * capacity, 'qBuf');

		if (!bufferArray) {
			DbgPrint("Failed to allocate buffer array\n");
			capacity = 0;
		}

		KeInitializeSpinLock(&spinLock);
	}

	BOOLEAN Enqueue(PKERNEL_STRUCTURED_NOTIFICATION buffer) {
		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == capacity) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return FALSE;
		}

		bufferArray[tail] = buffer;
		tail = (tail + 1) % capacity;
		size++;

		KeReleaseSpinLock(&spinLock, oldIrql);
		return TRUE;
	}

	PKERNEL_STRUCTURED_NOTIFICATION Dequeue() {
		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (!bufferArray) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			DbgPrint("Buffer array is null\n");
			return nullptr;
		}

		if (size == 0) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return nullptr;
		}

		PKERNEL_STRUCTURED_NOTIFICATION buffer = bufferArray[head];
		head = (head + 1) % capacity;
		size--;

		KeReleaseSpinLock(&spinLock, oldIrql);
		return buffer;
	}

	ULONG GetSize() {
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		ULONG currentSize = size;
		KeReleaseSpinLockFromDpcLevel(&spinLock);
		return currentSize;
	}
};

class NotifQueue : public BufferQueue {

public:

	NotifQueue() : BufferQueue() {}

};

class RegionTracker {
private:
	LIST_ENTRY HashTable[HASH_TABLE_SIZE];

	ULONG HashFunction(HANDLE ProcessId) {
		return ((ULONG)(ULONG_PTR)ProcessId) % HASH_TABLE_SIZE;
	}

public:

	RegionTracker() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			InitializeListHead(&HashTable[i]);
		}
	}

	VOID Init() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			InitializeListHead(&HashTable[i]);
		}
	}

	~RegionTracker() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			PLIST_ENTRY listHead = &HashTable[i];
			PLIST_ENTRY currentEntry = listHead->Flink;

			while (currentEntry != listHead) {
				PHASH_ENTRY entry = CONTAINING_RECORD(currentEntry, HASH_ENTRY, ListEntry);
				currentEntry = currentEntry->Flink;
				ExFreePoolWithTag(entry, 'tag1');
			}
		}
	}

	VOID AddEntry(HANDLE ProcessId, PVOID address, ULONG size, ULONG Protect, BOOLEAN remote) {
		ULONG hashIndex = HashFunction(ProcessId);
		PHASH_ENTRY newEntry = (PHASH_ENTRY)ExAllocatePool2(NonPagedPool, sizeof(HASH_ENTRY), 'tag1');

		if (newEntry) {
			newEntry->ProcessId = ProcessId;
			newEntry->RegionInfo.address = address;
			newEntry->RegionInfo.size = size;
			newEntry->RegionInfo.Protect = Protect;
			newEntry->RegionInfo.remote = remote;
			InsertHeadList(&HashTable[hashIndex], &newEntry->ListEntry);
			DbgPrint("[+] Added entry for process %p\n", ProcessId);
		}
	}

	PHASH_ENTRY FindEntry(HANDLE ProcessId) {
		ULONG hashIndex = HashFunction(ProcessId);
		PLIST_ENTRY listHead = &HashTable[hashIndex];
		PLIST_ENTRY currentEntry = listHead->Flink;

		while (currentEntry != listHead) {
			PHASH_ENTRY entry = CONTAINING_RECORD(currentEntry, HASH_ENTRY, ListEntry);
			if (entry->ProcessId == ProcessId) {
				return entry;
			}
			currentEntry = currentEntry->Flink;
		}
		return NULL;
	}

	VOID RemoveEntry(HANDLE ProcessId) {
		PHASH_ENTRY entry = FindEntry(ProcessId);
		if (entry) {
			RemoveEntryList(&entry->ListEntry);
			ExFreePoolWithTag(entry, 'tag1');
		}
	}
};


class SyscallsUtils {

	UNICODE_STRING traced[5];
	BOOLEAN isTracingEnabled;

	PsRegisterAltSystemCallHandler pPsRegisterAltSystemCallHandler;

	static ZwSetInformationProcess pZwSetInformationProcess;

	static PFUNCTION_MAP exportsMap;
	static PSSDT_TABLE ssdtTable;

	static ULONG NtAllocId;
	static ULONG NtWriteId;
	static ULONG NtProtectId;
	static ULONG NtFreeId;
	static ULONG NtReadId;
	static ULONG NtWriteFileId;

	// For future use
	static ULONG NtQueueApcThreadId;
	static ULONG NtQueueApcThreadExId;
	static ULONG NtSetContextThreadId;
	static ULONG NtMapViewOfSectionId;
	static ULONG NtResumeThreadId;
	static ULONG NtContinueId;
	static ULONG NtContinueEx;
	static ULONG NtAdjustPrivilegesTokenId;

	// New IDs — cross-process injection, section mapping, driver load
	static ULONG NtOpenProcessId;        // Fixed: 0x0026 across all Win10/11
	static ULONG NtCreateThreadExId;     // Variable — resolved in InitIds()
	static ULONG NtSuspendThreadId;      // Variable — resolved in InitIds()
	static ULONG NtCreateSectionId;      // Variable — resolved in InitIds()
	static ULONG NtUnmapViewOfSectionId;        // Variable — resolved in InitIds()
	static ULONG NtLoadDriverId;               // Variable — resolved in InitIds()
	static ULONG NtProtectVirtualMemoryId;     // Variable — resolved in InitIds()
	static ULONG NtCreateTransactionId;        // Variable — doppelgänging telemetry
	static ULONG NtRollbackTransactionId;      // Variable — doppelgänging telemetry
	static ULONG NtCreateProcessExId;          // Variable — legacy section-based process creation
	static ULONG NtCreateProcessId;            // Variable — even older legacy API (same technique)
	static ULONG NtQuerySystemInformationId;   // Variable — EDR callback enumeration recon
	static ULONG NtSetInformationProcessId;    // Variable — PPL-strip detection (ProcessProtectionLevel = 0x3D)
	static ULONG NtDuplicateObjectId;         // Stable at 0x003C — handle duplication detection
	static ULONG NtDebugActiveProcessId;      // Variable — debug-attach credential dump detection
	static ULONG NtSetInformationThreadId;    // Variable — token impersonation detection
	static ULONG NtTraceControlId;            // Variable — ETW manipulation detection
	static ULONG NtCreateNamedPipeFileId;     // Variable — named pipe C2 detection
	static ULONG NtOpenThreadId;              // Variable — thread hijack / context scrape detection
	static ULONG NtFlushInstructionCacheId;   // Variable — post-injection cache flush detection
	static ULONG NtCreateFileId;             // Variable — physical memory / raw device access detection (IOMMU bypass)
	static ULONG NtAssignProcessToJobObjectId; // Variable — job object assignment attack detection

	static BufferQueue* bufQueue;
	static StackUtils* stackUtils;
	static RegionTracker* vmRegionTracker;

	VadUtils* vadUtils;
	
	static HANDLE lastNotifedCidStackCorrupt;

public:

	SyscallsUtils() {} /*: isTracingEnabled(FALSE) {}*/

	ULONGLONG LeakPspAltSystemCallHandlers(
		ULONGLONG
	);
	
	UCHAR GetAltSyscallStateForThread(
		PETHREAD
	);
	
	BOOLEAN InitAltSyscallHandler();

	VOID InitStackUtils();
	
	VOID UnInitAltSyscallHandler();
	
	BOOLEAN tracingEnabed();
	
	VOID enableTracing();
	
	VOID disableTracing();

	VOID DisableAltSyscallFromThreads2();

	VOID DisableAltSyscallFromThreads3();
	
	static BOOLEAN isSyscallDirect(
		ULONG64,
		char*
	);

	BOOLEAN isSyscallIndirect(
		ULONG64
	);

	VOID InitVadUtils();
	
	VOID InitQueue(BufferQueue* queue) {
		bufQueue = queue;
	}

	VadUtils* getVadutils() {
		return vadUtils;
	}

	VOID NtVersionPreCheck();


	static VOID NtAllocVmHandler(	// Ok
		HANDLE,
		PVOID*,
		ULONG_PTR,
		PSIZE_T,
		ULONG,
		ULONG
	);

	static VOID NtProtectVmHandler(		// Ok
		HANDLE,
		PVOID,
		SIZE_T*,
		ULONG,
		PULONG
	);

	static VOID NtWriteVmHandler(	// Ok
		HANDLE,
		PVOID,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static VOID NtReadVmHandler(	// Ok
		HANDLE,
		PVOID,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static VOID NtWriteFileHandler(		// Ok
		HANDLE,
		HANDLE,
		PIO_APC_ROUTINE,
		PVOID,
		PIO_STATUS_BLOCK,
		PVOID,
		ULONG,
		PLARGE_INTEGER,
		PULONG
	);

	static VOID NtQueueApcThreadHandler(
		HANDLE,
		PPS_APC_ROUTINE,
		PVOID,
		PVOID,
		PVOID
	);

	static VOID NtQueueApcThreadExHandler(
		HANDLE,
		HANDLE,
		PPS_APC_ROUTINE,
		PVOID,
		PVOID,
		PVOID
	);

	static VOID NtSetContextThreadHandler(
		HANDLE,
		PVOID
	);

	static VOID NtResumeThreadHandler(
		HANDLE,
		PULONG
	);

	static VOID NtContinueHandler(
		PCONTEXT,
		BOOLEAN
	);

	static VOID NtAdjustPrivilegesTokenHandler(
		HANDLE,
		BOOLEAN,
		PTOKEN_PRIVILEGES,
		ULONG,
		PTOKEN_PRIVILEGES,
		PULONG
	);

	static VOID NtOpenProcessHandler(
		HANDLE,       // ProcessHandle (out)
		ACCESS_MASK,  // DesiredAccess
		PVOID,        // ObjectAttributes
		PCLIENT_ID    // ClientId
	);

	static VOID NtCreateThreadExHandler(
		PHANDLE,      // ThreadHandle (out)
		ACCESS_MASK,  // DesiredAccess
		PVOID,        // ObjectAttributes
		HANDLE,       // ProcessHandle
		PVOID,        // StartRoutine
		PVOID,        // Argument
		ULONG,        // CreateFlags
		SIZE_T,       // ZeroBits
		SIZE_T,       // StackSize
		SIZE_T,       // MaximumStackSize
		PVOID         // AttributeList
	);

	static VOID NtSuspendThreadHandler(
		HANDLE,  // ThreadHandle
		PULONG   // PreviousSuspendCount
	);

	static VOID NtCreateSectionHandler(
		PHANDLE,         // SectionHandle (out)
		ACCESS_MASK,     // DesiredAccess
		PVOID,           // ObjectAttributes
		PLARGE_INTEGER,  // MaximumSize
		ULONG,           // SectionPageProtection
		ULONG,           // AllocationAttributes
		HANDLE           // FileHandle
	);

	static VOID NtMapViewOfSectionHandler(
		HANDLE,          // SectionHandle
		HANDLE,          // ProcessHandle
		PVOID*,          // BaseAddress (in/out)
		ULONG_PTR,       // ZeroBits
		SIZE_T,          // CommitSize
		PLARGE_INTEGER,  // SectionOffset
		PSIZE_T,         // ViewSize
		ULONG,           // InheritDisposition
		ULONG,           // AllocationType
		ULONG            // Win32Protect
	);

	static VOID NtUnmapViewOfSectionHandler(
		HANDLE,  // ProcessHandle
		PVOID    // BaseAddress
	);

	static VOID NtLoadDriverHandler(
		PUNICODE_STRING  // DriverServiceName
	);

	static VOID NtCreateTransactionHandler();   // doppelgänging telemetry
	static VOID NtRollbackTransactionHandler(); // doppelgänging telemetry
	// Legacy process creation from explicit image section (process injection / doppelgänging)
	// Also detects process cloning (lsass/sensitive parent process)
	static VOID NtCreateProcessExHandler(HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle);
	static VOID NtCreateProcessHandler(HANDLE ParentProcess, HANDLE SectionHandle);  // older 8-arg variant

	// EDR callback enumeration recon — suspicious SystemInformationClass values
	static VOID NtQuerySystemInformationHandler(ULONG SystemInformationClass);

	// PPL-strip detection (ProcessProtectionLevel = 0x3D)
	static VOID NtSetInformationProcessHandler(
		HANDLE ProcessHandle,
		ULONG  ProcessInformationClass,
		PVOID  ProcessInformation,
		ULONG  ProcessInformationLength
	);

	// Handle duplication with dangerous access masks
	static VOID NtDuplicateObjectHandler(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PVOID  TargetHandle,
		ACCESS_MASK DesiredAccess
	);

	// Debug-attach credential dump bypass (alternative to PROCESS_VM_READ)
	static VOID NtDebugActiveProcessHandler(
		HANDLE ProcessHandle,
		HANDLE DebugObjectHandle
	);

	// Token impersonation with privilege escalation
	static VOID NtSetInformationThreadHandler(
		HANDLE ThreadHandle,
		ULONG  ThreadInformationClass,
		PVOID  ThreadInformation,
		ULONG  ThreadInformationLength
	);

	// ETW provider/session manipulation bypass
	static VOID NtTraceControlHandler(
		ULONG FunctionCode
	);

	// Physical memory / raw device access detection (IOMMU bypass)
	static VOID NtCreateFileHandler(
		PVOID ObjectAttributes
	);

	// Job object assignment attack detection (KILL_ON_JOB_CLOSE)
	static VOID NtAssignProcessToJobObjectHandler(HANDLE ProcessHandle);

	// Named pipe C2 / lateral movement detection
	static VOID NtCreateNamedPipeFileHandler(
		PVOID ObjectAttributes
	);

	// Thread hijack / context scrape detection
	static VOID NtOpenThreadHandler(
		HANDLE      ThreadHandle,
		ACCESS_MASK DesiredAccess,
		PVOID       ObjectAttributes,
		PCLIENT_ID  ClientId
	);

	// Post-injection cache flush detection
	static VOID NtFlushInstructionCacheHandler(
		HANDLE ProcessHandle,
		PVOID  BaseAddress,
		SIZE_T Length
	);

	static VOID NtProtectVirtualMemoryHandler(
		HANDLE   ProcessHandle,
		PVOID*   BaseAddress,
		PSIZE_T  RegionSize,
		ULONG    NewProtect
	);

	static BOOLEAN SetInformationAltSystemCall(
		HANDLE
	);
	
	static BOOLEAN UnsetInformationAltSystemCall(
		HANDLE
	);
	
	static VOID EnableAltSycallForThread(
		PETHREAD
	);

	static VOID DisableAltSycallForThread(
		PETHREAD
	);

	static VOID DestroyAltSyscallThreads();

	static VOID InitExportsMap(
		PFUNCTION_MAP
	);

	static VOID InitSsdtTable(
		PSSDT_TABLE
	);
	
	static VOID InitIds();
	
	static BOOLEAN SyscallHandler(
		PKTRAP_FRAME
	);

	static PSSDT_TABLE GetSsdtTable() {
		return ssdtTable;
	}

	static PFUNCTION_MAP GetExportsMap() {
		return exportsMap;
	}

	static BufferQueue* getBufQueue() {
		return bufQueue;
	}

	static VOID InitVmRegionTracker() {

		vmRegionTracker = (RegionTracker*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(RegionTracker), 'vmrt');

		if (!vmRegionTracker) {
			DbgPrint("Failed to allocate memory for vmRegionTracker\n");
		}

		vmRegionTracker->Init();
	}

	static RegionTracker* getVmRegionTracker() {
		return vmRegionTracker;
	}

};

class ObjectUtils {

private:

	UNICODE_STRING altitude;

	PVOID regHandle1;
	PVOID regHandle2;

	OB_CALLBACK_REGISTRATION objOpCallbackRegistration1;
	OB_CALLBACK_REGISTRATION objOpCallbackRegistration2;

	OB_OPERATION_REGISTRATION regPreOpRegistration;
	OB_OPERATION_REGISTRATION regPreOpDupRegistration;
	OB_OPERATION_REGISTRATION threadPreOpRegistration;

	// PID of the NortonEDR user-mode service — set via NORTONAV_REGISTER_SERVICE_PID IOCTL.
	// Handles opened to this process have PROCESS_TERMINATE / VM_WRITE stripped (self-protection).
	static volatile LONG g_ServicePid;

public:

	VOID setObjectNotificationCallback();

	VOID unsetObjectNotificationCallback();

	// Called from DriverIoControl when NORTONAV_REGISTER_SERVICE_PID arrives.
	static VOID RegisterServicePid(ULONG pid) {
		InterlockedExchange(&g_ServicePid, (LONG)pid);
		DbgPrint("[+] ObjectUtils: EDR service PID registered: %lu\n", pid);
	}

	// Process-classification helpers — used by Objects.cpp and SyscallsTracing.cpp.
	static BOOLEAN IsSensitiveProcess(PEPROCESS proc);
	static BOOLEAN IsLsass(PEPROCESS proc);

	static OB_PREOP_CALLBACK_STATUS ProcessPreCallback(
		PVOID,
		POB_PRE_OPERATION_INFORMATION
	);

	static OB_PREOP_CALLBACK_STATUS ThreadPreCallback(
		PVOID,
		POB_PRE_OPERATION_INFORMATION
	);

	// Legacy names kept so existing call-sites compile unchanged
	static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
		PVOID ctx, POB_PRE_OPERATION_INFORMATION op) {
		return ProcessPreCallback(ctx, op);
	}

	static POB_POST_OPERATION_CALLBACK PostOperationCallback(
		PVOID,
		POB_POST_OPERATION_INFORMATION
	);

	static BOOLEAN isCredentialDumpAttempt(
		POB_PRE_OPERATION_INFORMATION
	);

	static BOOLEAN isRemoteContextMapipulation(
		POB_POST_OPERATION_INFORMATION
	);

};

class ProcessUtils {

private:

	PEPROCESS process;
	VadUtils vadUtils;

public:

	ProcessUtils(PEPROCESS pEprocess) : 
		process(pEprocess),
		vadUtils(process) {
	}

	BOOLEAN isProcessImageTampered();
	
	BOOLEAN isProcessParentPidSpoofed(
		PPS_CREATE_NOTIFY_INFO
	);
		
	BOOLEAN isProcessGhosted();

	VOID setProcessNotificationCallback();

	VOID unsetProcessNotificationCallback();

	VadUtils* getVadUtils() {
		return &vadUtils;
	}

	static VOID CreateProcessNotifyEx(
		PEPROCESS,
		HANDLE,
		PPS_CREATE_NOTIFY_INFO
	);
};

class FsFilter {
public:
    static NTSTATUS Init(PDRIVER_OBJECT DriverObject, NotifQueue* queue);
    static VOID     Cleanup();

    static FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

    static FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

    static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetInformation(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

    static FLT_PREOP_CALLBACK_STATUS FLTAPI PreDirControl(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

    static FLT_PREOP_CALLBACK_STATUS FLTAPI PreNetworkQueryOpen(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

    static NTSTATUS FLTAPI FilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags);

    // Herpaderping: track FILE_OBJECTs used to back active SEC_IMAGE sections.
    // Called from NtCreateSectionHandler when SEC_IMAGE + file handle are both present.
    static VOID TrackImageSectionFile(PFILE_OBJECT FileObject);
    static VOID UntrackImageSectionFile(PFILE_OBJECT FileObject);

    // Pointer to CreateProcessNotifyEx callback — exposed for Ps*Notify integrity check.
    static PVOID s_NotifyFn;
};

// ---------------------------------------------------------------------------
// Fork-and-run injection tracker.
//
// Cobalt Strike "fork and run" pattern:
//   1. CreateProcess(spawnto_host, CREATE_SUSPENDED)  — sacrificial process
//   2. NtWriteVirtualMemory → inject shellcode into child
//   3. NtCreateThreadEx / NtResumeThread → execute in child
//   4. Parent waits; child runs payload and exits
//
// Detection strategy: when a known spawnto host (rundll32, dllhost, WerFault,
// etc.) or a process with a suspiciously empty command line is spawned, add it
// to the tracker.  When a cross-process write into that PID is later seen, mark
// it.  When a remote thread is subsequently created in it, fire a combined
// Critical "fork-and-run" alert that links all three events.
//
// This is orthogonal to the individual NtWriteVm / NtCreateThreadEx alerts —
// those still fire for each event separately.  The combined alert is the
// high-confidence fork-and-run signal.
// ---------------------------------------------------------------------------
#define FORK_TRACK_MAX 64

struct FORK_TRACK_ENTRY {
    HANDLE  Pid;               // 0 = free slot
    BOOLEAN KnownHost;         // image is a classic spawnto binary
    BOOLEAN SuspiciousCmdLine; // cmdline missing or just the exe name
    BOOLEAN WrittenTo;         // cross-process NtWriteVm seen into this PID
    BOOLEAN Alerted;           // prevent duplicate combined alerts
};

class ForkRunTracker {
public:
    static VOID Init();

    // Called from CreateProcessNotifyEx (process creation path only).
    // Adds a slot if the process is a known spawnto host or has no/minimal args.
    static VOID TrackProcess(HANDLE pid, BOOLEAN knownHost, BOOLEAN suspiciousCmdLine);

    // Called from NtWriteVmHandler on any cross-process write.
    // Updates an existing slot — does NOT create one (avoids tracking all processes).
    static VOID MarkWritten(HANDLE targetPid);

    // Called from NtCreateThreadExHandler on cross-process thread creation.
    // Returns TRUE (and marks alerted) if WrittenTo is set for this PID,
    // completing the fork-and-run three-step.
    static BOOLEAN CheckForkRun(HANDLE targetPid);

    // Called from CreateProcessNotifyEx (process exit path) to free the slot.
    static VOID Remove(HANDLE pid);
};

// ---------------------------------------------------------------------------
// Injection taint tracker — cross-references injection detections with
// the C2 beaconing frequency detector.
//
// When any subsystem detects code injection into a process (VAD anomaly,
// PE header in cross-process write, remote RWX allocation, remote thread
// creation, CLR injection, shadow stack hit, etc.), it calls MarkTainted()
// with the target PID.  The WFP C2 frequency tracker then strips allowlist
// immunity for that PID — even if it's chrome.exe or svchost.exe.
//
// Table is fixed-size (256 entries), oldest entry evicted on overflow.
// Entries expire after 10 minutes to avoid permanent false tainting.
// ---------------------------------------------------------------------------
#define TAINT_TABLE_MAX     256
#define TAINT_EXPIRY_MS     (10LL * 60LL * 1000LL)  // 10 minutes

struct TaintEntry {
    ULONG    Pid;
    LONGLONG Timestamp;  // KeQueryInterruptTime() ticks (100ns units)
    BOOLEAN  Used;
};

class InjectionTaintTracker {
public:
    static VOID Init();

    // Mark a PID as injection-tainted.  Safe to call from any IRQL <= DISPATCH.
    static VOID MarkTainted(HANDLE pid);

    // Returns TRUE if the PID has been tainted and the entry hasn't expired.
    static BOOLEAN IsTainted(UINT64 pid);

    // Cleanup slot when process exits (optional — entries also expire).
    static VOID Remove(HANDLE pid);
};

class DllInjector {
public:
    static VOID Initialize();
    static VOID SetConfig(PVOID loadLibraryW, ULONG ownerPid, PCWSTR path, ULONG byteLen);
    // Must be called at PASSIVE_LEVEL while attached to `process` via KeStackAttachProcess.
    static VOID TryInject(PEPROCESS process, PUNICODE_STRING fullImageName);
    // APC execution confirmation — called from IOCTL when HookDll reports successful load.
    static VOID ConfirmInjection(ULONG pid);
    // Periodic check for HookDll injections that never confirmed (5s timeout).
    static VOID CheckPendingTimeouts();
    // Returns TRUE if a NormalRoutine address matches our configured LoadLibraryW
    // AND the target PID is one we injected.  Used by the APC queue scanner to
    // exclude our own queued APCs from detection.
    static BOOLEAN IsOurApc(PVOID normalRoutine, ULONG pid);
};

class ImageUtils {

private:

	static KMUTEX g_HashQueueMutex;

public:

	VOID InitNotifQueue(NotifQueue*);

	BOOLEAN isImageSignatureInvalid(
		PVOID
	);
	
	static VOID ImageLoadNotifyRoutine(
		PUNICODE_STRING,
		HANDLE,
		PIMAGE_INFO
	);

	VOID setImageNotificationCallback();

	VOID unsetImageNotificationCallback();

	VOID InitializeHashQueueMutex() {
		KeInitializeMutex(&g_HashQueueMutex, 0);
	}

	// Argument-spoofing discrepancy detection (Adam Chester / CS "argue" technique).
	// SaveKernelCmdLine: called at CreateProcessNotifyEx time to record the kernel's
	//   authentic copy before any parent can patch the child's PEB.
	// RemoveCmdLineRec:  called at process exit to free the table slot.
	// CheckCmdLineDiscrepancy: called from ImageLoadNotifyRoutine while already
	//   KeStackAttachProcess'd — reads the PEB copy and compares; emits Critical if they differ.
	static VOID SaveKernelCmdLine(ULONG pid, PCUNICODE_STRING cmd);
	static VOID RemoveCmdLineRec(ULONG pid);
	static VOID CheckCmdLineDiscrepancy(ULONG pid, PEPROCESS proc);

	// Pointer to ImageLoadNotifyRoutine callback — exposed for Ps*Notify integrity check.
	static PVOID s_NotifyFn;

	// Secondary ntdll mapping tracker — records base/size of second+ ntdll copies
	// so APC/thread handlers can detect LdrLoadDll resolved from a privately mapped
	// ntdll (bypasses ASLR since the image is in the current process address space).
	static VOID InitSecondaryNtdllTracker();
	static BOOLEAN IsAddressInSecondaryNtdll(ULONG pid, ULONG64 address);
	static VOID RemoveSecondaryNtdll(ULONG pid);

	// Periodic APC queue scanner — KeInsertQueueApc blind spot mitigation.
	// Walks user-mode APC queues of ALL user processes, detecting kernel-
	// originated APC injection that bypasses our NtQueueApcThread/Ex syscall
	// hooks.  Checks: (1) NormalRoutine in secondary ntdll mapping,
	// (2) NormalRoutine in private executable VAD (shellcode in allocated RWX).
	// Our own HookDll APCs are excluded via DllInjector::IsOurApc().
	static VOID ScanApcQueues();
};

class ThreadUtils : public ProcessUtils {

private:

	PETHREAD thread;
	StackUtils stackUtils;

public:

	ThreadUtils(): ProcessUtils(NULL), thread(NULL) {}

	ThreadUtils(
		PEPROCESS pEprocess, 
		PETHREAD pEthread) : ProcessUtils(pEprocess) {
		
		this->thread = pEthread;
	}

	BOOLEAN isThreadInjected(
		ULONG64*
	);
	
	BOOLEAN isThreadStackCorruptedCET(
		PETHREAD
	);
	
	BOOLEAN ForceProcessCET(
		PETHREAD
	);

	BOOLEAN isThreadRemotelyCreated(
		HANDLE
	);

	static VOID CreateThreadNotifyRoutine(
		HANDLE,
		HANDLE,
		BOOLEAN
	);

	VOID setThreadNotificationCallback();

	VOID unsetThreadNotificationCallback();

	// Pointer to CreateThreadNotifyRoutine callback — exposed for Ps*Notify integrity check.
	static PVOID s_NotifyFn;

};

class RegistryUtils {

private:
	
	static LARGE_INTEGER cookie;

public:
	
	VOID setRegistryNotificationCallback();

	VOID unsetRegistryNotificationCallback();

	static NTSTATUS RegOpNotifyCallback(
		PVOID,
		PVOID,
		PVOID
	);

	static BOOLEAN isRegistryPersistenceBehavior(
		PUNICODE_STRING
	);

};

class PeScanner {

public:

    // Walk the VAD tree of a target process and flag private executable
    // regions that contain an MZ/PE header (reflective injection) or are
    // anonymous RWX (shellcode staging). Must be called at PASSIVE_LEVEL.
    static VOID ScanProcessVad(
        PEPROCESS    process,
        BufferQueue* bufQueue
    );

    // Check a kernel-memory buffer (already copied from user space) for an
    // MZ/PE signature. Called from NtProtectVmHandler / NtWriteVmHandler.
    static VOID CheckBufferForPeHeader(
        PVOID        buffer,
        SIZE_T       size,
        PVOID        targetAddress,
        HANDLE       targetPid,
        char*        procName,
        BufferQueue* bufQueue
    );

    // Check a kernel-memory buffer for a raw COFF object file header.
    // BOFs (Beacon Object Files) are COFF .o files loaded and executed
    // in-process — they never have an MZ header so CheckBufferForPeHeader
    // misses them entirely.  A valid COFF object starts with a 2-byte machine
    // type (0x8664 or 0x014C), has NumberOfSections > 0, and SizeOfOptionalHeader == 0.
    static VOID CheckBufferForCoffHeader(
        PVOID        buffer,
        SIZE_T       size,
        PVOID        targetAddress,
        HANDLE       targetPid,
        char*        procName,
        BufferQueue* bufQueue
    );
};

class EtwProvider {

public:

    // Register the driver as an ETW provider at load time.
    static VOID Init();

    // Unregister at unload time.
    static VOID Cleanup();

    // Emit one ETW event for a detection notification.
    // Must be called at IRQL <= APC_LEVEL (call after releasing any spinlock).
    static VOID WriteDetectionEvent(PKERNEL_STRUCTURED_NOTIFICATION notif);
};

class AmsiDetector {

public:

    // Scan amsi.dll exports for known bypass patch patterns.
    // Must be called while attached to the target process (KeStackAttachProcess).
    static VOID ScanAmsiBypassPatterns(
        PVOID        imageBase,
        SIZE_T       imageSize,
        HANDLE       pid,
        char*        procName,
        BufferQueue* bufQueue
    );
};

// ---------------------------------------------------------------------------
// AntiTamper — periodic integrity re-verification and driver self-protection.
// Init() must be called once from DriverEntry after all other subsystems are up.
// Cleanup() must be called from UnloadDriver before any other teardown.
// ---------------------------------------------------------------------------
class AntiTamper {
public:
    static VOID Init(PDRIVER_OBJECT driverObject, BufferQueue* queue);
    static VOID Cleanup();
};

// Snapshot of one PreOperation pointer captured in a CallbackList at init time.
// Used to detect foreign callbacks registered after our driver loads.
#define OB_CALLBACK_SNAPSHOT_MAX 32

struct ObCallbackSnapshot {
    PVOID preOpPointers[OB_CALLBACK_SNAPSHOT_MAX];  // sorted array of known-good PreOp ptrs
    ULONG count;
};

// Snapshot of Ps*Notify callback arrays (PspCreateProcessNotifyRoutine[], etc).
// Locates the array via LEA scan of PsSet*NotifyRoutine* and records our callback pointer.
// Used to detect PsRemoveCreate*NotifyRoutine or direct memory patch attacks.
struct PsCallbackSnapshot {
    PVOID  arrayBase;    // base of PspCreate*NotifyRoutine[64]
    PVOID  ourCallback;  // our registered function pointer (what to look for)
    BOOLEAN valid;       // FALSE if LEA scan failed — check is skipped
};

// Snapshot of CmpCallBackVector[] — the EX_CALLBACK array backing CmRegisterCallback.
// Mirrors the PsNotify approach: locate via LEA scan of CmRegisterCallbackEx,
// snapshot all registered function pointers at init, detect additions/removals/hijacks.
// RegPhantom rootkit hijacks CmRegisterCallback entries as a C2 channel.
#define CM_CALLBACK_SNAPSHOT_MAX 64

struct CmCallbackSnapshot {
    PVOID  arrayBase;                               // base of CmpCallBackVector[]
    PVOID  callbacks[CM_CALLBACK_SNAPSHOT_MAX];      // known-good function pointers
    ULONG  count;                                    // entries populated
    PVOID  ourCallback;                              // our RegistryUtils::RegOpNotifyCallback
    BOOLEAN valid;                                   // FALSE if LEA scan failed
};

class HookDetector {

    static PSSDT_BASELINE_ENTRY ssdtBaseline;
    static ULONG                ssdtBaselineCount;
    static PVOID                cachedKiServiceTable;

    // Baseline snapshots of PsProcessType and PsThreadType CallbackLists.
    // Taken once at Init() after ObRegisterCallbacks.  Checked periodically
    // for new (foreign/rogue) entries appearing in the list.
    static ObCallbackSnapshot   s_ProcessCbSnapshot;
    static ObCallbackSnapshot   s_ThreadCbSnapshot;
    static BOOLEAN              s_CbSnapshotTaken;

    // Snapshots of PspCreate*NotifyRoutine[] arrays.  Locate via LEA scan, record our
    // callback pointers.  Checked periodically to detect removal/patching.
    static PsCallbackSnapshot   s_ProcNotifyCbSnap;
    static PsCallbackSnapshot   s_ThreadNotifyCbSnap;
    static PsCallbackSnapshot   s_ImageNotifyCbSnap;

    // CmpCallBackVector snapshot — CmRegisterCallback integrity (RegPhantom defense).
    static CmCallbackSnapshot   s_CmCbSnap;

    static UCHAR DetectInlineHookType(PVOID functionAddress);
    static PVOID ResolveHookTarget(PVOID functionAddress, UCHAR hookType);

public:

    static VOID  Init(BufferQueue* bufQueue);
    static VOID  Cleanup();

    static VOID  TakeSsdtBaseline(PVOID kiServiceTable, ULONG count);
    static ULONG CheckSsdtIntegrity(BufferQueue* bufQueue);

    static ULONG    ScanKernelInlineHooks(PFUNCTION_MAP exportsMap, BufferQueue* bufQueue);
    static ULONG    ScanKernelEatHooks(PVOID moduleBase, BufferQueue* bufQueue);
    static BOOLEAN  CheckEtwHooks(BufferQueue* bufQueue);
    static VOID     CheckAltSyscallHandlerIntegrity(BufferQueue* bufQueue);

    // Snapshot PsProcessType/PsThreadType CallbackLists immediately after
    // ObRegisterCallbacks.  Must be called once at init, before periodic checks.
    static VOID     TakeObCallbackSnapshot();

    // Verify our entries are still present AND no new foreign callbacks appeared
    // since the snapshot.  Catches both unlinking (EDRSandblast) and rogue
    // callback registration (offensive PreOp to strip rights from defenders).
    static VOID     CheckObCallbackIntegrity(BufferQueue* bufQueue);

    // Locate PspCreate*NotifyRoutine[] arrays via LEA scan of the Ps*Set* functions and
    // record our callback function pointers.  Call once after all Ps callbacks registered.
    static VOID     TakePsCallbackSnapshot();

    // Verify our process/thread/image callbacks are still present in the internal arrays.
    // Fires CRITICAL alert if any are missing.  Added to RunAllHookChecks().
    static VOID     CheckPsCallbackIntegrity(BufferQueue* bufQueue);

    // CmRegisterCallback (CmpCallBackVector) integrity — snapshot at init,
    // detect foreign registrations and callback hijacking (RegPhantom C2 channel).
    static VOID     TakeCmCallbackSnapshot();
    static VOID     CheckCmCallbackIntegrity(BufferQueue* bufQueue);

    // CI.dll code integrity — SHA256 baseline of executable section, periodic re-hash.
    // Detects g_CiOptions patching and inline hooks installed by BYOVD drivers.
    static VOID     TakeCiBaseline();
    static VOID     CheckCiIntegrity(BufferQueue* bufQueue);

    // EPROCESS protection level monitoring — snapshot PPL levels for sensitive processes,
    // alert on downgrade (BYOVD driver zeroing EPROCESS.Protection field).
    static VOID     TakeEprocessProtBaseline();
    static VOID     CheckEprocessProtection(BufferQueue* bufQueue);

    static VOID RunAllHookChecks(
        PFUNCTION_MAP exportsMap,
        PVOID         moduleBase,
        BufferQueue*  bufQueue
    );
};

// ---------------------------------------------------------------------------
// TokenMonitor — logon-session termination callback.
// Detects processes that retain a primary token for a dead logon session,
// which is the kernel-visible signature of pass-the-token / token theft.
// Init must be called at PASSIVE_LEVEL from DriverEntry.
// ---------------------------------------------------------------------------
class TokenMonitor {
public:
    static VOID Init(NotifQueue* queue);
    static VOID Cleanup();
};

// ---------------------------------------------------------------------------
// PnpMonitor — IoRegisterPlugPlayNotification for HID and removable disk.
// Alerts on BadUSB/HID-injection devices and suspicious USB mass storage.
// InitWithDriver must be called from DriverEntry (requires PDRIVER_OBJECT).
// ---------------------------------------------------------------------------
class PnpMonitor {
public:
    static VOID InitWithDriver(PDRIVER_OBJECT driverObject, NotifQueue* queue);
    static VOID Cleanup();
};

class CallbackObjects :

	public ThreadUtils,
	public RegistryUtils,
	public ImageUtils,
	public ObjectUtils

{

	static BufferQueue* bufferQueue;
	static NotifQueue* notifQueue;
	static BytesQueue* bytesQueue;

	static PVOID DriverObject;

public:

	CallbackObjects() {}

	CallbackObjects(
		PEPROCESS
	) {}

	static VOID InitDriverObject(PVOID drvObj) {
		DriverObject = drvObj;
	}

	static PVOID GetDriverObject() {
		return DriverObject;
	}

	static VOID InitBufferQueue(
		BufferQueue* bufQueue
	) {
		bufferQueue = bufQueue;
	}

	static VOID InitNotifQueue(
		NotifQueue* ntfQueue
	) {
		notifQueue = ntfQueue;
	}

	static VOID InitBytesQueue(
		BytesQueue* bytQueue
	) {
		bytesQueue = bytQueue;
	}

	static BufferQueue* GetBufferQueue() {
		return bufferQueue;
	}

	static NotifQueue* GetNotifQueue() {
		return notifQueue;
	}

	static BytesQueue* GetBytesQueue() {
		return bytesQueue;
	}

	VOID setupNotificationsGlobal();
	
	VOID unsetNotificationsGlobal();
};

