// Regular Stack / Shadow Stack
#define MSR_IA32_PL3_SSP			0x000006A7U
#define MAX_STACK_FRAMES 512
#define RTL_WALK_KERNEL_MODE_STACK		0x00000000
#define RTL_WALK_USER_MODE_STACK 0x00000001

#define EPROCESS_SE_AUDIT_PROCESS_CREATION_INFO_IMAGE_FILE_NAME_OFFSET 0x0

typedef struct _KERNEL_STRUCTURES_OFFSETS {

	// E/KPROCESS
	ULONG ActiveProcessLinks;
	ULONG SeAuditProcessCreationInfo;
	ULONG VadRoot;
	ULONG MitigationFlags2Values;
	ULONG ThreadListHead;
	ULONG Flags3;
	ULONG Flags2;               // contains PicoCreated (bit 10)
	ULONG ImageFilePointer;     // Ptr64 FILE_OBJECT — null for file-less images

	// E/KTHREAD
	ULONG Header;
	ULONG ThreadListEntry;
	ULONG TrapFrame;

	// VAD
	ULONG Protection;		// not used
	ULONG Subsection;
	ULONG ControlArea;
	ULONG Segment;
	ULONG FilePointer;
	ULONG EntryPoint;		// not used

} KERNEL_STRUCTURES_OFFSET, *PKERNEL_STRUCTURES_OFFSET;


// VM
#define PROCESS_VM_READ 0x0010

#define MM_ZERO_ACCESS         0x0  
#define MM_READONLY            0x1  
#define MM_EXECUTE             0x2  
#define MM_EXECUTE_READ        0x3  
#define MM_READWRITE           0x4  
#define MM_WRITECOPY           0x5  
#define MM_EXECUTE_READWRITE   0x6  
#define MM_EXECUTE_WRITECOPY   0x7  
#define MM_NOACCESS            0x8  
#define MM_GUARD_PAGE          0x9 
#define MM_NOCACHE             0xA 
#define MM_WRITECOMBINE        0xB 
#define MM_EXECUTE_NOCACHE     0xC  
#define MM_EXECUTE_WRITECOMBINE 0xD 
#define MM_EXECUTE_GUARD_PAGE  0xE 
#define MM_EXECUTE_NOACCESS    0xF 

// EPROCESS signature enforcement offsets — stable across Win10 19041 – Win11 22632 (x64).
// Used by DllInjector to temporarily clear ProcessSignaturePolicy when injecting
// HookDll into processes with BLOCK_NON_MICROSOFT_BINARIES (Adam Chester blockdlls).
#define EPROCESS_MITIGATION_FLAGS_OFFSET     0x9d0  // MitigationFlags (ULONG) — 4 bytes before MitigationFlags2
#define EPROCESS_SIGNATURE_LEVEL             0x878  // SignatureLevel (UCHAR) — image signature level
#define EPROCESS_SECTION_SIGNATURE_LEVEL     0x879  // SectionSignatureLevel (UCHAR) — min sig level for DLL loads
#define MITIGATION_SIGNATURE_OPT_IN_BIT      23     // SignatureMitigationOptIn in MitigationFlags

// KTHREAD APC queue offsets — stable across Win10 19041 – Win11 22632 (x64).
// Used by the periodic APC queue scanner to detect KeInsertQueueApc bypass.
#define KTHREAD_APCSTATE_OFFSET       0x098  // KAPC_STATE embedded in KTHREAD
#define KAPCSTATE_USERLIST_OFFSET     0x010  // ApcListHead[UserMode] within KAPC_STATE
// Combined: user-mode APC list head = KTHREAD + 0x0A8

// KAPC structure offsets (x64)
#define KAPC_APCLISTENTRY_OFFSET      0x010  // LIST_ENTRY linking into APC list
#define KAPC_NORMALROUTINE_OFFSET     0x030  // user-mode routine pointer (LdrLoadDll target)

// Others
#define PROCESS_TERMINATE 0x0001
