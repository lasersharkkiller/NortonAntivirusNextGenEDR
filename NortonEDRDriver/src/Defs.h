#include <ntifs.h>

typedef VOID(NTAPI* PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

typedef NTSTATUS(NTAPI* PsRegisterAltSystemCallHandler)(PVOID HandlerFunction, LONG HandlerIndex);

typedef NTSTATUS(*ZwSetInformationProcess)(
	HANDLE, 
	ULONG, 
	PVOID, 
	ULONG);

extern "C" ULONGLONG __readmsr(ULONG);

extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;

extern "C" NTKERNELAPI PEPROCESS PsInitialSystemProcess;

extern "C" NTKERNELAPI PVOID NTAPI MmGetSystemRoutineAddress(
    _In_ PUNICODE_STRING SystemRoutineName
);

extern "C" NTKERNELAPI char* NTAPI PsGetProcessImageFileName(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS PsSuspendProcess(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS PsResumeProcess(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

extern "C" PVOID PsGetProcessWow64Process(
	PEPROCESS Process
);

extern "C" PVOID PsGetProcessPeb(
	PEPROCESS Process
);

extern "C" NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

extern "C" NTSTATUS ZwOpenThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

extern "C" NTSTATUS PsGetContextThread(
	PETHREAD Thread,
	PCONTEXT ThreadContext,
	KPROCESSOR_MODE PreviousMode
);

extern "C" PPS_PROTECTION PsGetProcessProtection(
	PEPROCESS Process
);

extern "C" HANDLE PsGetProcessInheritedFromUniqueProcessId(
	PEPROCESS Process
);

extern "C" PVOID PsGetThreadWin32StartAddress(
	PETHREAD Thread
);

extern "C" NTKERNELAPI POBJECT_TYPE MmSectionObjectType;

// ---------------------------------------------------------------------------
// Token / logon-session APIs (used by TokenMonitor)
// ---------------------------------------------------------------------------

// Windows Process Access Rights (from winnt.h, needed in kernel mode)
// Note: PROCESS_TERMINATE and PROCESS_VM_READ are defined in Offsets.h
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#endif

// PE/Image Constants from winnt.h (needed in kernel mode)
#ifndef IMAGE_DIRECTORY_ENTRY_SECURITY
#define IMAGE_DIRECTORY_ENTRY_SECURITY     4
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_SCN_MEM_READ                 0x40000000
#define IMAGE_SCN_MEM_WRITE                0x80000000
#endif

// Opaque logon session identifier passed to SeRegisterLogonSessionTerminatedRoutine.
typedef LUID* PLUID;

typedef NTSTATUS (NTAPI* PSE_LOGON_SESSION_TERMINATED_ROUTINE)(
    _In_ PLUID LogonId);

#pragma warning(push)
#pragma warning(disable:4273)  // inconsistent dll linkage
extern "C" NTSTATUS SeRegisterLogonSessionTerminatedRoutine(
    _In_ PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine);

extern "C" NTSTATUS SeUnregisterLogonSessionTerminatedRoutine(
    _In_ PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine);

// Returns (and references) the primary token of a process.
// Caller must call PsDereferencePrimaryToken when done.
extern "C" PACCESS_TOKEN PsReferencePrimaryToken(_In_ PEPROCESS Process);

// Token logon LUID — the session the token was issued for.
// Returns STATUS_SUCCESS; LogonId is filled in the TOKEN_STATISTICS structure
// obtained via SeQueryInformationToken(TokenStatistics).
typedef enum _TOKEN_INFORMATION_CLASS2 {
    TokenStatistics2 = 10,   // avoid clash with WDK's TOKEN_INFORMATION_CLASS
} TOKEN_INFORMATION_CLASS2;

// SeQueryInformationToken is exported by ntoskrnl.
extern "C" NTSTATUS SeQueryInformationToken(
    _In_  PACCESS_TOKEN     Token,
    _In_  TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_ PVOID*            TokenInformation);
#pragma warning(pop)

// ---------------------------------------------------------------------------
// PnP notification types (used by PnpMonitor)
// ---------------------------------------------------------------------------

// GUID_DEVINTERFACE_HID  — Human Interface Devices (keyboard, mouse, gamepad)
// {4D1E55B2-F16F-11CF-88CB-001111000030}
DEFINE_GUID(GUID_DEVINTERFACE_HID_LOCAL,
    0x4D1E55B2, 0xF16F, 0x11CF,
    0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30);

// GUID_DEVINTERFACE_USB_DEVICE — raw USB device arrival
// {A5DCBF10-6530-11D2-901F-00C04FB951ED}
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE_LOCAL,
    0xA5DCBF10, 0x6530, 0x11D2,
    0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);

// GUID_DEVINTERFACE_DISK — mass storage (thumb drives, external drives)
// {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
DEFINE_GUID(GUID_DEVINTERFACE_DISK_LOCAL,
    0x53F56307, 0xB6BF, 0x11D0,
    0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B);

// GUID_DEVINTERFACE_1394 — FireWire (IEEE 1394) controller
// DMA by design via OHCI spec; classic hardware DMA attack vector
// {6BDD1FC1-810F-11D0-BEC7-08002BE2092F}
DEFINE_GUID(GUID_DEVINTERFACE_1394_LOCAL,
    0x6BDD1FC1, 0x810F, 0x11D0,
    0xBE, 0xC7, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F);