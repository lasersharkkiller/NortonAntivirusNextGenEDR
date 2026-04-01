#pragma once
#include <ntddk.h>
#include <intrin.h>

// ---------------------------------------------------------------------------
// Sizes and limits
// ---------------------------------------------------------------------------
#define VMX_REGION_SIZE     4096
#define HOST_STACK_SIZE     (8 * PAGE_SIZE)   // 32 KB per vCPU
#define MAX_EPT_PDPT_ENTRIES 512              // covers 512 GB physical memory
#define HV_POOL_TAG         'NHyp'

// ---------------------------------------------------------------------------
// MSR numbers
// ---------------------------------------------------------------------------
#define IA32_FEATURE_CONTROL        0x3A
#define IA32_SYSENTER_CS            0x174
#define IA32_SYSENTER_ESP           0x175
#define IA32_SYSENTER_EIP           0x176
#define IA32_DEBUGCTL               0x1D9
#define IA32_PAT                    0x277
#define IA32_VMX_BASIC              0x480
#define IA32_VMX_PINBASED_CTLS      0x481
#define IA32_VMX_PROCBASED_CTLS     0x482
#define IA32_VMX_EXIT_CTLS          0x483
#define IA32_VMX_ENTRY_CTLS         0x484
#define IA32_VMX_CR0_FIXED0         0x486
#define IA32_VMX_CR0_FIXED1         0x487
#define IA32_VMX_CR4_FIXED0         0x488
#define IA32_VMX_CR4_FIXED1         0x489
#define IA32_VMX_EPT_VPID_CAP       0x48C
#define IA32_VMX_PROCBASED_CTLS2    0x48B
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS     0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS    0x490
#define IA32_FS_BASE                0xC0000100
#define IA32_GS_BASE                0xC0000101
#define IA32_KERNEL_GS_BASE         0xC0000102
#define IA32_EFER                   0xC0000080
#define IA32_STAR                   0xC0000081
#define IA32_LSTAR                  0xC0000082   // SYSCALL target (x64)
#define IA32_CSTAR                  0xC0000083
#define IA32_FMASK                  0xC0000084

// IA32_FEATURE_CONTROL bits
#define FEATURE_CONTROL_LOCKED              (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE_SMX   (1ULL << 2)

// ---------------------------------------------------------------------------
// VMCS field encodings  (Intel SDM Vol. 3C, Appendix B)
// ---------------------------------------------------------------------------

// 16-bit control fields
#define VMCS_CTRL_VPID                      0x0000
// 16-bit guest state
#define VMCS_GUEST_ES_SEL                   0x0800
#define VMCS_GUEST_CS_SEL                   0x0802
#define VMCS_GUEST_SS_SEL                   0x0804
#define VMCS_GUEST_DS_SEL                   0x0806
#define VMCS_GUEST_FS_SEL                   0x0808
#define VMCS_GUEST_GS_SEL                   0x080A
#define VMCS_GUEST_LDTR_SEL                 0x080C
#define VMCS_GUEST_TR_SEL                   0x080E
// 16-bit host state
#define VMCS_HOST_ES_SEL                    0x0C00
#define VMCS_HOST_CS_SEL                    0x0C02
#define VMCS_HOST_SS_SEL                    0x0C04
#define VMCS_HOST_DS_SEL                    0x0C06
#define VMCS_HOST_FS_SEL                    0x0C08
#define VMCS_HOST_GS_SEL                    0x0C0A
#define VMCS_HOST_TR_SEL                    0x0C0C

// 64-bit control fields
#define VMCS_CTRL_IO_BITMAP_A               0x2000
#define VMCS_CTRL_IO_BITMAP_B               0x2002
#define VMCS_CTRL_MSR_BITMAP                0x2004
#define VMCS_CTRL_TSC_OFFSET                0x2010
#define VMCS_CTRL_EPT_POINTER               0x201A
// 64-bit guest state
#define VMCS_GUEST_VMCS_LINK_PTR            0x2800
#define VMCS_GUEST_DEBUGCTL                 0x2802
#define VMCS_GUEST_PAT                      0x2804
#define VMCS_GUEST_EFER                     0x2806
// 64-bit host state
#define VMCS_HOST_PAT                       0x2C00
#define VMCS_HOST_EFER                      0x2C02

// 32-bit control fields
#define VMCS_CTRL_PIN_EXEC                  0x4000
#define VMCS_CTRL_PROC_EXEC                 0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP          0x4004
#define VMCS_CTRL_PF_EC_MASK                0x4006
#define VMCS_CTRL_PF_EC_MATCH               0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT          0x400A
#define VMCS_CTRL_VMEXIT                    0x400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT    0x400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT     0x4010
#define VMCS_CTRL_VMENTRY                   0x4012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT    0x4014
#define VMCS_CTRL_VMENTRY_INTR_INFO         0x4016
#define VMCS_CTRL_VMENTRY_EXC_EC            0x4018
#define VMCS_CTRL_VMENTRY_INSTR_LEN         0x401A
#define VMCS_CTRL_PROC_EXEC2                0x401E
// 32-bit read-only fields
#define VMCS_RO_VM_INSTR_ERROR              0x4400
#define VMCS_RO_EXIT_REASON                 0x4402
#define VMCS_RO_EXIT_INTR_INFO              0x4404
#define VMCS_RO_EXIT_INTR_EC                0x4406
#define VMCS_RO_IDT_VECT_INFO               0x4408
#define VMCS_RO_IDT_VECT_EC                 0x440A
#define VMCS_RO_EXIT_INSTR_LEN              0x440C
#define VMCS_RO_EXIT_INSTR_INFO             0x440E
// 32-bit guest state
#define VMCS_GUEST_ES_LIMIT                 0x4800
#define VMCS_GUEST_CS_LIMIT                 0x4802
#define VMCS_GUEST_SS_LIMIT                 0x4804
#define VMCS_GUEST_DS_LIMIT                 0x4806
#define VMCS_GUEST_FS_LIMIT                 0x4808
#define VMCS_GUEST_GS_LIMIT                 0x480A
#define VMCS_GUEST_LDTR_LIMIT               0x480C
#define VMCS_GUEST_TR_LIMIT                 0x480E
#define VMCS_GUEST_GDTR_LIMIT               0x4810
#define VMCS_GUEST_IDTR_LIMIT               0x4812
#define VMCS_GUEST_ES_AR                    0x4814
#define VMCS_GUEST_CS_AR                    0x4816
#define VMCS_GUEST_SS_AR                    0x4818
#define VMCS_GUEST_DS_AR                    0x481A
#define VMCS_GUEST_FS_AR                    0x481C
#define VMCS_GUEST_GS_AR                    0x481E
#define VMCS_GUEST_LDTR_AR                  0x4820
#define VMCS_GUEST_TR_AR                    0x4822
#define VMCS_GUEST_INTERRUPTIBILITY         0x4824
#define VMCS_GUEST_ACTIVITY_STATE           0x4826
#define VMCS_GUEST_SYSENTER_CS              0x482A
// 32-bit host state
#define VMCS_HOST_SYSENTER_CS               0x4C00

// Natural-width control fields
#define VMCS_CTRL_CR0_MASK                  0x6000
#define VMCS_CTRL_CR4_MASK                  0x6002
#define VMCS_CTRL_CR0_SHADOW                0x6004
#define VMCS_CTRL_CR4_SHADOW                0x6006
// Natural-width read-only fields
#define VMCS_RO_EXIT_QUAL                   0x6400
#define VMCS_RO_GUEST_LIN_ADDR              0x640A
// 64-bit read-only
#define VMCS_RO_GUEST_PHYS_ADDR             0x2400
// Natural-width guest state
#define VMCS_GUEST_CR0                      0x6800
#define VMCS_GUEST_CR3                      0x6802
#define VMCS_GUEST_CR4                      0x6804
#define VMCS_GUEST_ES_BASE                  0x6806
#define VMCS_GUEST_CS_BASE                  0x6808
#define VMCS_GUEST_SS_BASE                  0x680A
#define VMCS_GUEST_DS_BASE                  0x680C
#define VMCS_GUEST_FS_BASE                  0x680E
#define VMCS_GUEST_GS_BASE                  0x6810
#define VMCS_GUEST_LDTR_BASE                0x6812
#define VMCS_GUEST_TR_BASE                  0x6814
#define VMCS_GUEST_GDTR_BASE                0x6816
#define VMCS_GUEST_IDTR_BASE                0x6818
#define VMCS_GUEST_DR7                      0x681A
#define VMCS_GUEST_RSP                      0x681C
#define VMCS_GUEST_RIP                      0x681E
#define VMCS_GUEST_RFLAGS                   0x6820
#define VMCS_GUEST_SYSENTER_ESP             0x6824
#define VMCS_GUEST_SYSENTER_EIP             0x6826
// Natural-width host state
#define VMCS_HOST_CR0                       0x6C00
#define VMCS_HOST_CR3                       0x6C02
#define VMCS_HOST_CR4                       0x6C04
#define VMCS_HOST_FS_BASE                   0x6C06
#define VMCS_HOST_GS_BASE                   0x6C08
#define VMCS_HOST_TR_BASE                   0x6C0A
#define VMCS_HOST_GDTR_BASE                 0x6C0C
#define VMCS_HOST_IDTR_BASE                 0x6C0E
#define VMCS_HOST_SYSENTER_ESP              0x6C10
#define VMCS_HOST_SYSENTER_EIP              0x6C12
#define VMCS_HOST_RSP                       0x6C14
#define VMCS_HOST_RIP                       0x6C16

// ---------------------------------------------------------------------------
// VM execution control bits
// ---------------------------------------------------------------------------

// Pin-based
#define PIN_EXT_INTR_EXIT           (1u << 0)
#define PIN_NMI_EXITING             (1u << 3)

// Primary processor-based
#define PROC_CR3_LOAD_EXIT          (1u << 15)   // CR3-write → VM exit
#define PROC_CR3_STORE_EXIT         (1u << 16)
#define PROC_CR8_LOAD_EXIT          (1u << 19)
#define PROC_USE_MSR_BITMAPS        (1u << 28)   // enable MSR bitmap
#define PROC_ACTIVATE_SECONDARY     (1u << 31)   // enable secondary controls

// Secondary processor-based
#define PROC2_ENABLE_EPT            (1u << 1)    // Extended Page Tables
#define PROC2_RDTSCP                (1u << 3)
#define PROC2_UNRESTRICTED_GUEST    (1u << 7)
#define PROC2_ENABLE_INVPCID        (1u << 12)
#define PROC2_XSAVES                (1u << 20)

// VM-exit controls
#define VMEXIT_HOST_ADDR64          (1u << 9)    // 64-bit host
#define VMEXIT_SAVE_IA32_PAT        (1u << 18)
#define VMEXIT_LOAD_IA32_PAT        (1u << 19)
#define VMEXIT_SAVE_IA32_EFER       (1u << 20)
#define VMEXIT_LOAD_IA32_EFER       (1u << 21)

// VM-entry controls
#define VMENTRY_IA32E_GUEST         (1u << 9)    // 64-bit guest
#define VMENTRY_LOAD_IA32_PAT       (1u << 14)
#define VMENTRY_LOAD_IA32_EFER      (1u << 15)

// Segment unusable flag (bit 16 of access rights)
#define SEG_AR_UNUSABLE             (1u << 16)

// ---------------------------------------------------------------------------
// VM exit reasons  (Intel SDM Vol. 3C, Table C-1)
// ---------------------------------------------------------------------------
#define EXIT_REASON_EXCEPTION           0
#define EXIT_REASON_EXT_INTERRUPT       1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_CPUID              10
#define EXIT_REASON_HLT                12
#define EXIT_REASON_INVD               13
#define EXIT_REASON_VMCALL             18
#define EXIT_REASON_CR_ACCESS          28
#define EXIT_REASON_DR_ACCESS          29
#define EXIT_REASON_MSR_READ           31
#define EXIT_REASON_MSR_WRITE          32
#define EXIT_REASON_INVALID_STATE      33
#define EXIT_REASON_EPT_VIOLATION      48
#define EXIT_REASON_EPT_MISCONFIG      49
#define EXIT_REASON_XSETBV             55

// ---------------------------------------------------------------------------
// EPT definitions
// ---------------------------------------------------------------------------
#define EPT_READ            (1ULL << 0)
#define EPT_WRITE           (1ULL << 1)
#define EPT_EXECUTE         (1ULL << 2)
#define EPT_RWX             (EPT_READ | EPT_WRITE | EPT_EXECUTE)
#define EPT_MEMORY_WB       (6ULL << 3)    // write-back memory type
#define EPT_LARGE_PAGE      (1ULL << 7)    // 2 MB large page in PD
#define EPT_WALK_4          (3ULL << 3)    // 4-level walk, encoded as (4-1)

// EPT violation exit qualification bits
#define EPT_VIOL_READ       (1u << 0)
#define EPT_VIOL_WRITE      (1u << 1)
#define EPT_VIOL_EXEC       (1u << 2)
#define EPT_VIOL_READABLE   (1u << 3)
#define EPT_VIOL_WRITABLE   (1u << 4)
#define EPT_VIOL_EXECUTABLE (1u << 5)
#define EPT_VIOL_GVA_VALID  (1u << 7)

// ---------------------------------------------------------------------------
// Hypercall codes (VMCALL from guest)
// ---------------------------------------------------------------------------
#define HV_CALL_PING                0x4E484F00   // "NHO\0"
#define HV_CALL_GET_STATS           0x4E484F01
#define HV_CALL_PROTECT_PAGE        0x4E484F02   // make page EPT read-only
#define HV_CALL_UNPROTECT_PAGE      0x4E484F03

// ---------------------------------------------------------------------------
// CR exit qualification helpers
// ---------------------------------------------------------------------------
#define CR_ACCESS_CR_NUM(q)     ((q) & 0xF)
#define CR_ACCESS_TYPE(q)       (((q) >> 4) & 0x3)  // 0=LMSW/MOV to CR, 1=MOV from CR
#define CR_ACCESS_REG(q)        (((q) >> 8) & 0xF)   // general register index
#define CR_ACCESS_TYPE_MOV_TO   0
#define CR_ACCESS_TYPE_MOV_FROM 1
#define CR_ACCESS_TYPE_CLTS     2
#define CR_ACCESS_TYPE_LMSW     3

// ---------------------------------------------------------------------------
// Descriptor table register
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _PSEUDO_DESCRIPTOR {
    USHORT  Limit;
    ULONG64 Base;
} PSEUDO_DESCRIPTOR;
#pragma pack(pop)

// GDT segment descriptor (8-byte normal descriptor)
#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR {
    USHORT LimitLow;
    USHORT BaseLow;
    UCHAR  BaseMid;
    UCHAR  Flags1;      // Type, S, DPL, P
    UCHAR  Flags2;      // Limit[19:16], AVL, L, D/B, G
    UCHAR  BaseHigh;
} SEGMENT_DESCRIPTOR;
#pragma pack(pop)

// 16-byte system segment descriptor (used for TSS/LDT in 64-bit mode)
#pragma pack(push, 1)
typedef struct _SYSTEM_DESCRIPTOR {
    SEGMENT_DESCRIPTOR Desc;
    ULONG  BaseUpper;
    ULONG  Reserved;
} SYSTEM_DESCRIPTOR;
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Per-vCPU general-purpose register save area
// Layout MUST match the push order in HvAsm.asm HvVmExitStub.
// ---------------------------------------------------------------------------
typedef struct _GUEST_REGISTERS {
    ULONG_PTR RAX;
    ULONG_PTR RCX;
    ULONG_PTR RDX;
    ULONG_PTR RBX;
    ULONG_PTR RBP;
    ULONG_PTR RSI;
    ULONG_PTR RDI;
    ULONG_PTR R8;
    ULONG_PTR R9;
    ULONG_PTR R10;
    ULONG_PTR R11;
    ULONG_PTR R12;
    ULONG_PTR R13;
    ULONG_PTR R14;
    ULONG_PTR R15;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

// ---------------------------------------------------------------------------
// EPT page table entry (all levels share the same bit layout at the low end)
// ---------------------------------------------------------------------------
typedef ULONG64 EPT_ENTRY;

typedef struct _EPT_PML4 {
    EPT_ENTRY Entries[512];
} EPT_PML4, *PEPT_PML4;

typedef struct _EPT_PDPT {
    EPT_ENTRY Entries[512];
} EPT_PDPT, *PEPT_PDPT;

typedef struct _EPT_PD {
    EPT_ENTRY Entries[512];
} EPT_PD, *PEPT_PD;

typedef struct _EPT_PT {
    EPT_ENTRY Entries[512];
} EPT_PT, *PEPT_PT;

// ---------------------------------------------------------------------------
// Per-vCPU state
// ---------------------------------------------------------------------------
typedef struct _VCPU {
    // VMX regions — each must be 4 KB aligned; first DWORD = VMCS revision ID
    PVOID             VmxonRegion;
    PHYSICAL_ADDRESS  VmxonPhys;
    PVOID             VmcsRegion;
    PHYSICAL_ADDRESS  VmcsPhys;

    // MSR bitmap — 4 KB, controls which MSR accesses cause VM exits
    PVOID             MsrBitmap;
    PHYSICAL_ADDRESS  MsrBitmapPhys;

    // EPT PML4 root — 4 KB aligned, one per vCPU (shared identity map is fine for a lab)
    PEPT_PML4         EptPml4;
    PHYSICAL_ADDRESS  EptPml4Phys;
    ULONG64           EptPointer;    // preformatted EPTP value for VMCS

    // Host stack (separate from guest stack; grows down)
    PVOID             HostStack;
    ULONG_PTR         HostStackTop;  // HOST_RSP value (16-byte aligned)

    // Per-exit register snapshot (filled by HvVmExitStub before calling C handler)
    GUEST_REGISTERS   GuestRegs;

    // State
    ULONG             ProcessorIndex;
    BOOLEAN           VmxLaunched;

    // Statistics
    ULONG64           ExitCount;
    ULONG64           EptViolationCount;
    ULONG64           MsrInterceptCount;
    ULONG64           CpuidCount;
    ULONG64           CrAccessCount;
    ULONG64           VmcallCount;
} VCPU, *PVCPU;

// ---------------------------------------------------------------------------
// Assembly stubs (defined in HvAsm.asm, called from C)
// ---------------------------------------------------------------------------
extern "C" {
    NTSTATUS HvVmxOn(_In_ PHYSICAL_ADDRESS* physAddr);
    VOID     HvVmxOff();
    NTSTATUS HvVmClear(_In_ PHYSICAL_ADDRESS* physAddr);
    NTSTATUS HvVmPtrLd(_In_ PHYSICAL_ADDRESS* physAddr);
    ULONG_PTR HvVmRead(_In_ ULONG_PTR encoding);
    VOID     HvVmWrite(_In_ ULONG_PTR encoding, _In_ ULONG_PTR value);
    BOOLEAN  HvLaunchVm(_In_ PVCPU vcpu);
    VOID     HvVmExitStub();        // HOST_RIP — never called from C directly
    VOID     HvInvEpt(_In_ ULONG type, _In_ PVOID descriptor);
    ULONG_PTR HvVmCall(_In_ ULONG_PTR code, _In_ ULONG_PTR arg1, _In_ ULONG_PTR arg2);
}

// ---------------------------------------------------------------------------
// Inline helpers used across translation units
// ---------------------------------------------------------------------------

// Adjust VMX control value to satisfy capability MSR constraints:
// Low DWORD = bits that must be 1; High DWORD = bits that may be 1.
static inline ULONG HvAdjustControls(ULONG requested, ULONG msr)
{
    LARGE_INTEGER cap;
    cap.QuadPart = __readmsr(msr);
    requested |= cap.LowPart;    // force required-1 bits
    requested &= cap.HighPart;   // clear disallowed-1 bits
    return requested;
}

// Decode a GDT segment descriptor into its base address.
static inline ULONG_PTR HvGetSegmentBase(ULONG_PTR gdtBase, USHORT selector)
{
    if (selector == 0) return 0;

    const SEGMENT_DESCRIPTOR* desc =
        (const SEGMENT_DESCRIPTOR*)(gdtBase + (selector & ~7u));

    ULONG_PTR base =
        ((ULONG_PTR)desc->BaseLow)  |
        ((ULONG_PTR)desc->BaseMid  << 16) |
        ((ULONG_PTR)desc->BaseHigh << 24);

    // For 64-bit system descriptors (TSS/LDT), the upper 32 bits of the base
    // are in the following 4 bytes.
    if ((desc->Flags1 & 0x10) == 0) {  // S=0 → system descriptor (16 bytes wide)
        const SYSTEM_DESCRIPTOR* sys = (const SYSTEM_DESCRIPTOR*)desc;
        base |= ((ULONG_PTR)sys->BaseUpper << 32);
    }
    return base;
}

// Decode a GDT segment descriptor into its access rights (VMCS format).
static inline ULONG HvGetAccessRights(ULONG_PTR gdtBase, USHORT selector)
{
    if (selector == 0) return SEG_AR_UNUSABLE;

    const SEGMENT_DESCRIPTOR* desc =
        (const SEGMENT_DESCRIPTOR*)(gdtBase + (selector & ~7u));

    // VMCS access-rights format:
    //   bits  7:0  = Flags1 (Type[3:0], S, DPL[1:0], P)
    //   bits 11:8  = reserved (0)
    //   bits 15:12 = Flags2[3:0] (AVL, L, D/B, G)  — upper nibble of byte 6
    ULONG ar = 0;
    ar |= (ULONG)(desc->Flags1);
    ar |= (ULONG)(desc->Flags2 & 0xF0) << 8;   // shift nibble to bits 15:12
    return ar;
}

// Decode a GDT segment descriptor into its limit (in bytes or pages).
static inline ULONG HvGetSegmentLimit(ULONG_PTR gdtBase, USHORT selector)
{
    if (selector == 0) return 0;
    const SEGMENT_DESCRIPTOR* desc =
        (const SEGMENT_DESCRIPTOR*)(gdtBase + (selector & ~7u));
    ULONG limit = (ULONG)desc->LimitLow | (((ULONG)desc->Flags2 & 0x0F) << 16);
    if (desc->Flags2 & 0x80) limit = (limit << 12) | 0xFFF; // G bit: page granularity
    return limit;
}
