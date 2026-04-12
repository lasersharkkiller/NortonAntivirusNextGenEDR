/*
 _   _            _              _____ ____  ____
| \ | | ___  _ __| |_ ___  _ __ | ____|  _ \|  _ \
|  \| |/ _ \| '__| __/ _ \| '_ \|  _| | | | | |_) |
| |\  | (_) | |  | || (_) | | | | |___| |_| |  _ <
|_| \_|\___/|_|   \__\___/|_| |_|_____|____/|_| \_\

  Norton NextGen Antivirus  |  Kernel EDR Driver
*/


#include "Globals.h"
#include "Deception.h"
#include <wdf.h>
#include <wdmsec.h>    // IoCreateDeviceSecure, SDDL_DEVOBJ_SYS_ALL_ADM_ALL

PDEVICE_OBJECT DeviceObject = NULL;
PDEVICE_OBJECT g_DeviceObject = nullptr;  // exposed for IoAllocateWorkItem (phantom DLL, inject timer)

SyscallsUtils* g_syscallsUtils;
CallbackObjects* g_callbackObjects;
WdfTcpipUtils* g_wfpUtils;

BufferQueue* g_bufferQueue;
NotifQueue* g_hashQueue;
BytesQueue* g_bytesQueue;


void PrintAsciiTitle()
{
	DbgPrint(" _   _            _              _____ ____  ____  \n");
	DbgPrint("| \\ | | ___  _ __| |_ ___  _ __ | ____|  _ \\|  _ \\\n");
	DbgPrint("|  \\| |/ _ \\| '__| __/ _ \\| '_ \\|  _| | | | | |_) |\n");
	DbgPrint("| |\\  | (_) | |  | || (_) | | | | |___| |_| |  _ < \n");
	DbgPrint("|_| \\_|\\___/|_|   \\__\\___/|_| |_|_____|____/|_| \\_\\\n");
	DbgPrint("                                                     \n");
	DbgPrint("  Norton NextGen Antivirus  |  Kernel EDR  |  v3    \n\n");
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	//g_syscallsUtils->disableTracing();

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\NortonEDR");
	NTSTATUS status = STATUS_SUCCESS;

	g_callbackObjects->unsetNotificationsGlobal();

	AntiTamper::Cleanup();
	TokenMonitor::Cleanup();
	PnpMonitor::Cleanup();
	DeceptionEngine::Cleanup();
	FsFilter::Cleanup();
	EtwProvider::Cleanup();
	HookDetector::Cleanup();

	g_syscallsUtils->DisableAltSyscallFromThreads3();

	g_syscallsUtils->UnInitAltSyscallHandler();

	if (g_wfpUtils) {
		g_wfpUtils->UnitializeWfp();
		ExFreePool(g_wfpUtils);
		g_wfpUtils = nullptr;
	}

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

KSPIN_LOCK g_spinLock;

// Validate that the IOCTL caller is our registered service process.
// Returns TRUE if service PID is registered and caller matches, or if no
// service PID is registered yet (bootstrap: first call is REGISTER_SERVICE_PID).
static BOOLEAN IsCallerTrustedService() {
	ULONG svcPid = (ULONG)InterlockedCompareExchange(
		&ObjectUtils::g_ServicePid, 0, 0);
	if (svcPid == 0) return TRUE;  // not yet registered — bootstrap phase
	ULONG callerPid = HandleToUlong(PsGetProcessId(IoGetCurrentProcess()));
	return (callerPid == svcPid);
}

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	__try {

		KIRQL oldIrql;
		
		if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_RETRIEVE_DATA_NOTIF) {

			KeAcquireSpinLock(&g_spinLock, &oldIrql);

			if (!g_hashQueue) {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				DbgPrint("[-] HashQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (CallbackObjects::GetNotifQueue()->GetSize() > 0) {

				PKERNEL_STRUCTURED_NOTIFICATION resp = CallbackObjects::GetNotifQueue()->Dequeue();
				KeReleaseSpinLock(&g_spinLock, oldIrql);

				// Emit ETW event at PASSIVE_LEVEL (spinlock already released)
				EtwProvider::WriteDetectionEvent(resp);

				if (!resp || !MmIsAddressValid(resp)) {
					status = STATUS_NO_MORE_ENTRIES;
					__leave;
				}

				size_t respLen = 0;

				__try {
					respLen = SafeStringLength(resp->msg, 64) + 1;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[!] Invalid memory access while calculating resp length\n");
					status = STATUS_INVALID_PARAMETER;
					__leave;
				}

				if (stack->Parameters.DeviceIoControl.OutputBufferLength < respLen) {
					DbgPrint("[!] Output buffer is too small\n");
					status = STATUS_BUFFER_TOO_SMALL;
					__leave;
				}

				ULONG totalSize = sizeof(KERNEL_STRUCTURED_NOTIFICATION) + respLen;

				RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, totalSize);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, resp, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
				RtlCopyMemory((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(KERNEL_STRUCTURED_NOTIFICATION), resp->msg, respLen);

				Irp->IoStatus.Information = totalSize;
				status = STATUS_SUCCESS;

			}
			else {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				status = STATUS_NO_MORE_ENTRIES;
			}
		}

		else if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_RETRIEVE_DATA_BYTE) {

			KeAcquireSpinLockAtDpcLevel(&g_spinLock);

			if (!g_bytesQueue) {
				KeReleaseSpinLockFromDpcLevel(&g_spinLock);
				DbgPrint("[-] BytesQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (g_bytesQueue->GetSize() == 0) {
				KeReleaseSpinLockFromDpcLevel(&g_spinLock);
				status = STATUS_NO_MORE_ENTRIES;
				__leave;
			}

			RAW_BUFFER rawBuffer = CallbackObjects::GetBytesQueue()->Dequeue();
			KeReleaseSpinLockFromDpcLevel(&g_spinLock);

			BYTE* resp = rawBuffer.buffer;
			ULONG bytesBufSize = (ULONG)rawBuffer.size;

			// Validate the dequeued buffer before any use; resp must be freed on all
			// subsequent exit paths since ownership transferred out of the queue.
			if (!resp || bytesBufSize == 0 || !MmIsAddressValid(resp)) {
				DbgPrint("[!] Dequeued buffer is invalid.\n");
				if (resp) ExFreePool(resp);
				status = STATUS_NO_MORE_ENTRIES;
				__leave;
			}

			ULONG totalSize = sizeof(KERNEL_STRUCTURED_BUFFER) + bytesBufSize;

			if (stack->Parameters.DeviceIoControl.OutputBufferLength < totalSize) {
				DbgPrint("[!] Output buffer too small: need %lu, have %lu\n",
					totalSize, stack->Parameters.DeviceIoControl.OutputBufferLength);
				ExFreePool(resp);
				status = STATUS_BUFFER_TOO_SMALL;
				__leave;
			}

			// Build the header on the stack — no heap allocation needed.
			// The buffer pointer field is not used by the user-mode consumer;
			// it reads the raw bytes from immediately after the header.
			KERNEL_STRUCTURED_BUFFER ksbHeader = {};
			ksbHeader.bufSize = bytesBufSize;
			ksbHeader.pid = static_cast<UINT32>(reinterpret_cast<uintptr_t>(rawBuffer.pid));
			ksbHeader.buffer = nullptr;
			RtlCopyMemory(ksbHeader.procName, rawBuffer.procName, sizeof(ksbHeader.procName));

			__try {
				RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, totalSize);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &ksbHeader, sizeof(KERNEL_STRUCTURED_BUFFER));
				RtlCopyMemory(
					(BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(KERNEL_STRUCTURED_BUFFER),
					resp,
					bytesBufSize
				);
				Irp->IoStatus.Information = totalSize;
				status = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("[!] Exception during copy in NORTONAV_RETRIEVE_DATA_BYTE.\n");
				status = STATUS_UNSUCCESSFUL;
			}

			// Always free the dequeued buffer — ownership was transferred from the
			// queue and no other code path will release it.
			ExFreePool(resp);
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_SET_INJECT_CONFIG) {

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HOOKDLL_INJECT_CONFIG)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			HOOKDLL_INJECT_CONFIG* cfg = (HOOKDLL_INJECT_CONFIG*)Irp->AssociatedIrp.SystemBuffer;
			DllInjector::SetConfig(
				cfg->LoadLibraryWAddress,
				cfg->OwnerPid,
				cfg->HookDllPath,
				cfg->PathByteLen);
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_SET_NETWORK_CONFIG) {

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(NETWORK_FILTER_CONFIG)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			NETWORK_FILTER_CONFIG* cfg = (NETWORK_FILTER_CONFIG*)Irp->AssociatedIrp.SystemBuffer;
			WdfTcpipUtils::WfpSetBlocklist(cfg->BlockedPorts, cfg->NumBlockedPorts);
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == END_THAT_PROCESS) {

			// Only the registered NortonEDR service may terminate processes.
			if (!IsCallerTrustedService()) {
				DbgPrint("[!] END_THAT_PROCESS denied: caller pid=%lu is not service\n",
					HandleToUlong(PsGetProcessId(IoGetCurrentProcess())));
				status = STATUS_ACCESS_DENIED;
				__leave;
			}

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT32)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			NTSTATUS termStatus = TerminateProcess((HANDLE) * (UINT32*)Irp->AssociatedIrp.SystemBuffer);

			if (!NT_SUCCESS(termStatus)) {
				status = STATUS_UNSUCCESSFUL;
			}
			else {
				status = STATUS_SUCCESS;
			}
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_REGISTER_SERVICE_PID) {

			// Only allow registration if no PID is registered yet (bootstrap),
			// or the caller is the currently registered service (re-registration).
			if (!IsCallerTrustedService()) {
				DbgPrint("[!] REGISTER_SERVICE_PID denied: caller pid=%lu is not service\n",
					HandleToUlong(PsGetProcessId(IoGetCurrentProcess())));
				status = STATUS_ACCESS_DENIED;
				__leave;
			}

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT32)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			UINT32 svcPid = *(UINT32*)Irp->AssociatedIrp.SystemBuffer;
			ObjectUtils::RegisterServicePid(svcPid);
			status = STATUS_SUCCESS;
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == NORTONAV_HOOKDLL_CONFIRM) {

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT32)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			UINT32 confirmPid = *(UINT32*)Irp->AssociatedIrp.SystemBuffer;
			DllInjector::ConfirmInjection(confirmPid);
			status = STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[!] Exception occurred in DriverIoControl\n");
		status = STATUS_UNSUCCESSFUL;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	PrintAsciiTitle();

	if (!OffsetsMgt::InitWinStructsOffsets()) {
		DbgPrint("[-] Failed to initialize Win Kernel Structs offsets\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("[+] Win Kernel Structs offsets initialized\n");

	UNREFERENCED_PARAMETER(RegistryPath);

	g_bufferQueue = (BufferQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BufferQueue), 'bufq');

	if (!g_bufferQueue) {

		DbgPrint("[-] Failed to allocate memory for Buffer Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bufferQueue->Init(MAX_BUFFER_COUNT);

	DllInjector::Initialize();

	g_hashQueue = (NotifQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(NotifQueue), 'hshq');

	if (!g_hashQueue) {

		DbgPrint("[-] Failed to allocate memory for Hash Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_hashQueue->Init(MAX_BUFFER_COUNT);

	g_bytesQueue = (BytesQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BytesQueue), 'bytq');

	if (!g_bytesQueue) {

		DbgPrint("[-] Failed to allocate memory for Bytes Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bytesQueue->Init(MAX_BUFFER_COUNT);

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	// Snapshot the dispatch table immediately after assignment — used by the
	// periodic integrity check to detect BYOVD patching of our IOCTL handler.
	HookDetector::TakeMajorFunctionBaseline(DriverObject);

	g_syscallsUtils = (SyscallsUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(SyscallsUtils), 'sysc');
	if (!g_syscallsUtils) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ForkRunTracker::Init();
	InjectionTaintTracker::Init();

	g_syscallsUtils->NtVersionPreCheck();
	g_syscallsUtils->InitIds();
	g_syscallsUtils->InitAltSyscallHandler();
	g_syscallsUtils->InitQueue(g_bufferQueue);
	g_syscallsUtils->InitVadUtils();
	g_syscallsUtils->InitStackUtils();

	g_callbackObjects = (CallbackObjects*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(CallbackObjects), 'cbob');

	if (!g_callbackObjects) {

		DbgPrint("[-] Failed to allocate memory for CallbackObjects\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_callbackObjects->InitDriverObject(DriverObject);
	g_callbackObjects->InitializeHashQueueMutex();
	g_callbackObjects->InitNotifQueue(g_hashQueue);
	g_callbackObjects->InitBytesQueue(g_bytesQueue);
	g_callbackObjects->InitBufferQueue(g_bufferQueue);

	g_callbackObjects->setupNotificationsGlobal();

	// Snapshot the ObCallback lists immediately after our ObRegisterCallbacks calls.
	// Must happen before HookDetector::RunAllHookChecks or AntiTamper starts, so
	// that the periodic check has a valid whitelist of known-good PreOp pointers.
	HookDetector::TakeObCallbackSnapshot();

	// Snapshot PspCreate*NotifyRoutine[] arrays immediately after our Ps* callbacks
	// are registered (inside setupNotificationsGlobal() above).
	HookDetector::TakePsCallbackSnapshot();

	// Snapshot CmpCallBackVector[] immediately after CmRegisterCallbackEx
	// (called from setupNotificationsGlobal → setRegistryNotificationCallback).
	// Detects RegPhantom-style rogue CmCallback registration and callback hijacking.
	HookDetector::TakeCmCallbackSnapshot();

	EtwProvider::Init();

	// Take SSDT baseline snapshot and run full hook scan
	HookDetector::Init(g_hashQueue);

	// CI.dll code integrity baseline — SHA256 hash of the executable section
	HookDetector::TakeCiBaseline();

	// SeCiCallbacks baseline — snapshot CI validation callback pointers in ntoskrnl.
	// Detects callback table overwrite that redirects SeValidateImageHeader to attacker stub.
	HookDetector::TakeSeCiCallbackBaseline();

	// EPROCESS protection level baseline — snapshot PPL levels for lsass, csrss, etc.
	HookDetector::TakeEprocessProtBaseline();

	// Initialize Skeleton Key detection lock (lsass auth DLL baselines are
	// populated lazily from ImageLoadNotifyRoutine as auth DLLs load into lsass).
	HookDetector::InitLsassAuthLock();

	// Callback prologue baseline — snapshot first 16 bytes of each registered
	// callback function (Ob/Ps/Cm/IOCTL).  Detects inline hooks patched by BYOVD
	// onto our callback entry points to silently neuter the EDR.
	HookDetector::TakeCallbackPrologueBaseline();

	// PspNotifyEnableMask baseline — single byte that globally enables/disables
	// all Ps*Notify callbacks.  If cleared by BYOVD, all callback arrays stop
	// being invoked even though the entries are intact.
	HookDetector::TakePspNotifyEnableMaskBaseline();

	SsdtUtils ssdtUtils;
	PVOID moduleBase = ssdtUtils.GetKernelBaseAddress();
	if (moduleBase) {
		FUNCTION_MAP kExports = ssdtUtils.GetAndStoreKernelExports(moduleBase);
		HookDetector::RunAllHookChecks(&kExports, moduleBase, g_hashQueue);
	}

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\NortonEDR");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\NortonEDR");

	// SDDL: SYSTEM (full), Administrators (full), SERVICE (read+write).
	// Prevents unprivileged users from opening the device and sending IOCTLs
	// like END_THAT_PROCESS or REGISTER_SERVICE_PID.
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(
		L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;SU)");
	NTSTATUS status = IoCreateDeviceSecure(
		DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	g_DeviceObject = DeviceObject;

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
		return status;
	}

	g_wfpUtils = (WdfTcpipUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(WdfTcpipUtils), 'wfpu');
	if (g_wfpUtils) {
		NTSTATUS wfpStatus = g_wfpUtils->InitWfp();
		if (!NT_SUCCESS(wfpStatus)) {
			DbgPrint("[-] WFP initialization failed: 0x%x — network telemetry disabled\n", wfpStatus);
			ExFreePool(g_wfpUtils);
			g_wfpUtils = nullptr;
		}
	} else {
		DbgPrint("[-] Failed to allocate WdfTcpipUtils\n");
	}

	// Anti-tamper: bump driver refcount and start periodic integrity re-checks.
	// Must be initialized after HookDetector (which establishes the SSDT baseline)
	// so the first periodic check has a valid snapshot to compare against.
	AntiTamper::Init(DriverObject, g_hashQueue);

	// Token theft detection: fire on every logon-session teardown and alert
	// on any process that still holds a token tied to the dead session.
	TokenMonitor::Init(g_hashQueue);

	// PnP monitoring: alert on BadUSB/HID-injection devices and removable disks.
	PnpMonitor::InitWithDriver(DriverObject, g_hashQueue);

	// Initialize deception engine — honeypot registry keys and file traps.
	// Non-fatal: the driver functions normally if SECURITY hive is inaccessible.
	DeceptionEngine::Init(g_hashQueue);

	// Register filesystem minifilter — non-fatal if it fails (e.g. Filter Manager not present)
	NTSTATUS fsStatus = FsFilter::Init(DriverObject, g_hashQueue);
	if (!NT_SUCCESS(fsStatus)) {
		DbgPrint("[-] FsFilter::Init failed: 0x%x — filesystem monitoring disabled\n", fsStatus);
	}

	// Periodic HookDll injection-confirmation timeout check (every 5s).
	// DPC fires at DISPATCH_LEVEL → queues a work item to PASSIVE_LEVEL.
	{
		static KTIMER       s_InjectTimer;
		static KDPC         s_InjectDpc;
		static PIO_WORKITEM s_InjectWorkItem;

		s_InjectWorkItem = IoAllocateWorkItem(DeviceObject);
		if (s_InjectWorkItem) {
			KeInitializeTimer(&s_InjectTimer);
			KeInitializeDpc(&s_InjectDpc,
				[](PKDPC, PVOID Ctx, PVOID, PVOID) {
					if (Ctx) IoQueueWorkItem((PIO_WORKITEM)Ctx,
						[](PDEVICE_OBJECT, PVOID) {
							DllInjector::CheckPendingTimeouts();
							ImageUtils::ScanApcQueues();
						},
						DelayedWorkQueue, nullptr);
				}, s_InjectWorkItem);

			LARGE_INTEGER due;
			due.QuadPart = -50000000LL;  // 5 seconds initial delay
			KeSetTimerEx(&s_InjectTimer, due, 5000 /*5s period*/, &s_InjectDpc);
			DbgPrint("[+] Periodic timer started (injection confirmation + APC queue scan)\n");
		}
	}

	DbgPrint("[+] Driver loaded\n");

	return STATUS_SUCCESS;
}