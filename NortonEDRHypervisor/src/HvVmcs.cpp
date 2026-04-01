/*
  HvVmcs.cpp — VMCS field setup and VM exit handler dispatch

  Two responsibilities:
    1. HvSetupVmcs() — writes all required VMCS fields for a single vCPU before
       the first VMLAUNCH.  The guest state mirrors the current CPU state exactly
       so the OS continues without disruption.

    2. HvHandleVmExit() — the C-level entry point called from HvVmExitStub
       (MASM) on every VM exit.  Dispatches to per-reason handlers and issues
       VMRESUME to return control to the guest.

  Exit reasons handled:
    EXIT_REASON_CPUID       — hide VMX presence; expose custom HV leaf
    EXIT_REASON_CR_ACCESS   — monitor CR3 writes (process switches) and
                               CR0/CR4 changes that weaken security
    EXIT_REASON_MSR_READ    — log intercepted MSR reads (IA32_LSTAR, etc.)
    EXIT_REASON_MSR_WRITE   — detect writes to IA32_LSTAR (syscall hook)
    EXIT_REASON_VMCALL      — hypercall interface (guest ↔ hypervisor)
    EXIT_REASON_EPT_VIOLATION — delegate to HvEpt.cpp handler
    EXIT_REASON_INVD        — emulate to avoid cache corruption
    EXIT_REASON_XSETBV      — pass through XCR0 changes, log them
*/

#include "HvDefs.h"

// Forward declarations from HvEpt.cpp
extern VOID HvEptHandleViolation(_In_ PVCPU vcpu);

// Forward declarations from HvDeception.cpp
extern BOOLEAN HvDeceptionHandleEptReadViolation(_In_ PVCPU vcpu, _In_ ULONG64 gpa);
extern VOID    HvDeceptionHandleMtfExit(_In_ PVCPU vcpu);

// ---------------------------------------------------------------------------
// MSR bitmap helpers
// ---------------------------------------------------------------------------
// The MSR bitmap is a 4 KB region divided into four 1 KB sub-maps:
//   [+0x000] read-bitmap  for MSRs 0x00000000 – 0x00001FFF
//   [+0x400] write-bitmap for MSRs 0x00000000 – 0x00001FFF
//   [+0x800] read-bitmap  for MSRs 0xC0000000 – 0xC0001FFF
//   [+0xC00] write-bitmap for MSRs 0xC0000000 – 0xC0001FFF
// A set bit causes a VM exit; a clear bit passes the MSR access through.

static void MsrBitmapSetBit(PVOID bitmap, ULONG msr, BOOLEAN isWrite)
{
    BYTE* map = (BYTE*)bitmap;
    ULONG bitIndex;
    ULONG byteOffset;

    if (msr <= 0x1FFF) {
        // Low MSR range
        bitIndex = msr;
        byteOffset = isWrite ? 0x400 : 0x000;
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        // High MSR range
        bitIndex = msr - 0xC0000000;
        byteOffset = isWrite ? 0xC00 : 0x800;
    } else {
        return;  // MSR not coverable by bitmap
    }

    map[byteOffset + bitIndex / 8] |= (1u << (bitIndex % 8));
}

static void HvSetupMsrBitmap(PVCPU vcpu)
{
    // Intercept writes to IA32_LSTAR — the SYSCALL target MSR.
    // Any write here is a potential syscall hook installation.
    MsrBitmapSetBit(vcpu->MsrBitmap, IA32_LSTAR,       TRUE);

    // Intercept reads of IA32_LSTAR so the guest always sees the unpatched value.
    MsrBitmapSetBit(vcpu->MsrBitmap, IA32_LSTAR,       FALSE);

    // Intercept SYSENTER target writes (32-bit legacy syscall path)
    MsrBitmapSetBit(vcpu->MsrBitmap, IA32_SYSENTER_EIP, TRUE);

    // IA32_DEBUGCTL writes — flag attempt to enable/disable branch tracing
    MsrBitmapSetBit(vcpu->MsrBitmap, IA32_DEBUGCTL,    TRUE);

    // Intercept EFER writes — NX disable is a critical security regression
    MsrBitmapSetBit(vcpu->MsrBitmap, IA32_EFER,        TRUE);
}

// ---------------------------------------------------------------------------
// HvSetupVmcs — configure all VMCS fields for one vCPU
// ---------------------------------------------------------------------------

// Convenience wrappers to avoid repetitive casting
static inline VOID W(ULONG_PTR field, ULONG_PTR value) { HvVmWrite(field, value); }

NTSTATUS HvSetupVmcs(_In_ PVCPU vcpu)
{
    // -- VMCLEAR + VMPTRLD to make this VMCS current and active ---------------
    NTSTATUS s = HvVmClear(&vcpu->VmcsPhys);
    if (!NT_SUCCESS(s)) return s;
    s = HvVmPtrLd(&vcpu->VmcsPhys);
    if (!NT_SUCCESS(s)) return s;

    // =========================================================================
    // Guest state — mirrors the current CPU state so the OS runs unmodified
    // =========================================================================

    // Read GDT / IDT
    PSEUDO_DESCRIPTOR gdtr = {}, idtr = {};
    __sgdt(&gdtr);
    __sidt(&idtr);
    ULONG_PTR gdtBase = gdtr.Base;

    // Segment selectors
    USHORT cs = (USHORT)__readcs();
    USHORT ss = (USHORT)__readss();
    USHORT ds = (USHORT)__readds();
    USHORT es = (USHORT)__reades();
    USHORT fs = (USHORT)__readfs();
    USHORT gs = (USHORT)__readgs();
    USHORT tr = (USHORT)__readtr();
    USHORT ldtr = (USHORT)__readldtr();

    W(VMCS_GUEST_CS_SEL,   cs);
    W(VMCS_GUEST_SS_SEL,   ss);
    W(VMCS_GUEST_DS_SEL,   ds);
    W(VMCS_GUEST_ES_SEL,   es);
    W(VMCS_GUEST_FS_SEL,   fs);
    W(VMCS_GUEST_GS_SEL,   gs);
    W(VMCS_GUEST_TR_SEL,   tr);
    W(VMCS_GUEST_LDTR_SEL, ldtr);

    // Segment limits
    W(VMCS_GUEST_CS_LIMIT,   HvGetSegmentLimit(gdtBase, cs));
    W(VMCS_GUEST_SS_LIMIT,   HvGetSegmentLimit(gdtBase, ss));
    W(VMCS_GUEST_DS_LIMIT,   HvGetSegmentLimit(gdtBase, ds));
    W(VMCS_GUEST_ES_LIMIT,   HvGetSegmentLimit(gdtBase, es));
    W(VMCS_GUEST_FS_LIMIT,   HvGetSegmentLimit(gdtBase, fs));
    W(VMCS_GUEST_GS_LIMIT,   HvGetSegmentLimit(gdtBase, gs));
    W(VMCS_GUEST_TR_LIMIT,   HvGetSegmentLimit(gdtBase, tr));
    W(VMCS_GUEST_LDTR_LIMIT, HvGetSegmentLimit(gdtBase, ldtr));
    W(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    W(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    // Segment access rights
    W(VMCS_GUEST_CS_AR,   HvGetAccessRights(gdtBase, cs));
    W(VMCS_GUEST_SS_AR,   HvGetAccessRights(gdtBase, ss));
    W(VMCS_GUEST_DS_AR,   HvGetAccessRights(gdtBase, ds));
    W(VMCS_GUEST_ES_AR,   HvGetAccessRights(gdtBase, es));
    W(VMCS_GUEST_FS_AR,   HvGetAccessRights(gdtBase, fs));
    W(VMCS_GUEST_GS_AR,   HvGetAccessRights(gdtBase, gs));
    W(VMCS_GUEST_TR_AR,   HvGetAccessRights(gdtBase, tr));
    W(VMCS_GUEST_LDTR_AR, (ldtr == 0) ? SEG_AR_UNUSABLE : HvGetAccessRights(gdtBase, ldtr));

    // Segment bases
    // In 64-bit mode, CS/DS/ES/SS bases are architecturally 0; only FS/GS have non-zero bases
    W(VMCS_GUEST_CS_BASE,   0);
    W(VMCS_GUEST_SS_BASE,   0);
    W(VMCS_GUEST_DS_BASE,   0);
    W(VMCS_GUEST_ES_BASE,   0);
    W(VMCS_GUEST_FS_BASE,   __readmsr(IA32_FS_BASE));
    W(VMCS_GUEST_GS_BASE,   __readmsr(IA32_GS_BASE));
    W(VMCS_GUEST_TR_BASE,   HvGetSegmentBase(gdtBase, tr));
    W(VMCS_GUEST_LDTR_BASE, HvGetSegmentBase(gdtBase, ldtr));
    W(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    W(VMCS_GUEST_IDTR_BASE, idtr.Base);

    // Control registers
    W(VMCS_GUEST_CR0, __readcr0());
    W(VMCS_GUEST_CR3, __readcr3());
    W(VMCS_GUEST_CR4, __readcr4());
    W(VMCS_GUEST_DR7, __readdr(7));

    // RFLAGS (start with IF set so the guest can receive interrupts)
    W(VMCS_GUEST_RFLAGS, __readeflags());

    // MSRs
    W(VMCS_GUEST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    W(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    W(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    W(VMCS_GUEST_DEBUGCTL,     __readmsr(IA32_DEBUGCTL));
    W(VMCS_GUEST_PAT,          __readmsr(IA32_PAT));
    W(VMCS_GUEST_EFER,         __readmsr(IA32_EFER));

    // VMCS link pointer (no VMCS shadowing — set to -1)
    W(VMCS_GUEST_VMCS_LINK_PTR, ~0ULL);

    // Activity state: active (0 = normal)
    W(VMCS_GUEST_ACTIVITY_STATE, 0);
    W(VMCS_GUEST_INTERRUPTIBILITY, 0);

    // GUEST_RIP and GUEST_RSP are written by HvLaunchVm (assembly) immediately
    // before VMLAUNCH using the live RSP/RIP at that moment.

    // =========================================================================
    // Host state — what the processor restores on every VM exit
    // =========================================================================

    W(VMCS_HOST_CS_SEL, cs & ~7u);     // RPL=0, TI=0 (host always ring 0)
    W(VMCS_HOST_SS_SEL, ss & ~7u);
    W(VMCS_HOST_DS_SEL, ds & ~7u);
    W(VMCS_HOST_ES_SEL, es & ~7u);
    W(VMCS_HOST_FS_SEL, fs & ~7u);
    W(VMCS_HOST_GS_SEL, gs & ~7u);
    W(VMCS_HOST_TR_SEL, tr & ~7u);

    // CR0/CR4 must satisfy VMX fixed-bit requirements
    W(VMCS_HOST_CR0, __readcr0());
    W(VMCS_HOST_CR3, __readcr3());
    W(VMCS_HOST_CR4, __readcr4());

    W(VMCS_HOST_FS_BASE,   __readmsr(IA32_FS_BASE));
    W(VMCS_HOST_GS_BASE,   __readmsr(IA32_GS_BASE));
    W(VMCS_HOST_TR_BASE,   HvGetSegmentBase(gdtBase, tr));
    W(VMCS_HOST_GDTR_BASE, gdtr.Base);
    W(VMCS_HOST_IDTR_BASE, idtr.Base);

    W(VMCS_HOST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    W(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    W(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    W(VMCS_HOST_PAT,           __readmsr(IA32_PAT));
    W(VMCS_HOST_EFER,          __readmsr(IA32_EFER));

    // Host stack and VM exit entry point
    W(VMCS_HOST_RSP, vcpu->HostStackTop);
    W(VMCS_HOST_RIP, (ULONG_PTR)HvVmExitStub);

    // =========================================================================
    // VM execution controls
    // =========================================================================

    // Detect whether TRUE-control MSRs are supported (IA32_VMX_BASIC bit 55)
    ULONG64 vmxBasic = __readmsr(IA32_VMX_BASIC);
    BOOLEAN hasTrueCtls = (vmxBasic >> 55) & 1;

    ULONG pinMsr  = hasTrueCtls ? IA32_VMX_TRUE_PINBASED_CTLS  : IA32_VMX_PINBASED_CTLS;
    ULONG procMsr = hasTrueCtls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;
    ULONG exitMsr = hasTrueCtls ? IA32_VMX_TRUE_EXIT_CTLS       : IA32_VMX_EXIT_CTLS;
    ULONG entMsr  = hasTrueCtls ? IA32_VMX_TRUE_ENTRY_CTLS      : IA32_VMX_ENTRY_CTLS;

    // Pin-based: no external-interrupt exiting (let the guest handle its own IRQs)
    W(VMCS_CTRL_PIN_EXEC, HvAdjustControls(0, pinMsr));

    // Primary proc-based:
    //   CR3_LOAD_EXIT  — track process switches (every CR3 write → VM exit)
    //   USE_MSR_BITMAPS — only selected MSRs cause exits (see HvSetupMsrBitmap)
    //   ACTIVATE_SECONDARY — enable secondary controls (required for EPT)
    ULONG proc = PROC_CR3_LOAD_EXIT | PROC_USE_MSR_BITMAPS | PROC_ACTIVATE_SECONDARY;
    W(VMCS_CTRL_PROC_EXEC, HvAdjustControls(proc, procMsr));

    // Secondary proc-based: EPT enabled
    ULONG proc2 = PROC2_ENABLE_EPT | PROC2_RDTSCP;
    W(VMCS_CTRL_PROC_EXEC2, HvAdjustControls(proc2, IA32_VMX_PROCBASED_CTLS2));

    // Exception bitmap — intercept #GP (29) to trap guest VMX instruction attempts
    //   Bit 13 = General-Protection Fault (#GP)
    W(VMCS_CTRL_EXCEPTION_BITMAP, (1u << 13));

    // CR0 / CR4 guest-host mask + shadow:
    //   Bits in the mask that we want to monitor (guest writes these → VM exit).
    //   We watch bit 16 of CR0 (WP = Write Protect) and bit 5 of CR4 (PAE).
    //   The shadow is what the guest sees when it reads the register.
    W(VMCS_CTRL_CR0_MASK,   (1u << 16));      // WP bit
    W(VMCS_CTRL_CR0_SHADOW, (ULONG)__readcr0());
    W(VMCS_CTRL_CR4_MASK,   0);               // let all CR4 bits pass through initially
    W(VMCS_CTRL_CR4_SHADOW, (ULONG)__readcr4());

    // MSR bitmap
    W(VMCS_CTRL_MSR_BITMAP, vcpu->MsrBitmapPhys.QuadPart);

    // EPT pointer
    W(VMCS_CTRL_EPT_POINTER, vcpu->EptPointer);

    // VM-exit controls: 64-bit host, save/load PAT and EFER
    ULONG exitCtls = VMEXIT_HOST_ADDR64 | VMEXIT_SAVE_IA32_PAT |
                     VMEXIT_LOAD_IA32_PAT | VMEXIT_SAVE_IA32_EFER | VMEXIT_LOAD_IA32_EFER;
    W(VMCS_CTRL_VMEXIT, HvAdjustControls(exitCtls, exitMsr));
    W(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    W(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    // VM-entry controls: 64-bit guest, load PAT and EFER
    ULONG entryCtls = VMENTRY_IA32E_GUEST | VMENTRY_LOAD_IA32_PAT | VMENTRY_LOAD_IA32_EFER;
    W(VMCS_CTRL_VMENTRY, HvAdjustControls(entryCtls, entMsr));
    W(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    W(VMCS_CTRL_VMENTRY_INTR_INFO, 0);

    // CR3 target count — 0 means every CR3 MOV causes a VM exit
    W(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Individual exit handlers
// ---------------------------------------------------------------------------

static VOID HandleCpuid(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    vcpu->CpuidCount++;
    int leaf = (int)regs->RAX;
    int subleaf = (int)regs->RCX;

    int info[4] = {};
    __cpuidex(info, leaf, subleaf);

    // Hide VMX capability from the guest (bit 5 of ECX for leaf 1)
    if (leaf == 1) {
        info[2] &= ~(1 << 5);   // clear CPUID.1:ECX.VMX (bit 5)
        info[2] |=  (1 << 31);  // set hypervisor-present bit (bit 31)
    }

    // Expose a custom hypervisor leaf at 0x40000000 (standard HV leaf)
    if (leaf == 0x40000000) {
        info[0] = 0x40000001;                   // max HV leaf
        info[1] = 'troN';                        // "NortonEDR HV" signature
        info[2] = 'EDRn';
        info[3] = 0x20565820;                   // " HV"
    }

    regs->RAX = (ULONG_PTR)info[0];
    regs->RBX = (ULONG_PTR)info[1];
    regs->RCX = (ULONG_PTR)info[2];
    regs->RDX = (ULONG_PTR)info[3];

    // Advance guest RIP past the CPUID instruction (2 bytes: 0F A2)
    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleCrAccess(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    vcpu->CrAccessCount++;
    ULONG_PTR qual = HvVmRead(VMCS_RO_EXIT_QUAL);
    ULONG crNum  = (ULONG)CR_ACCESS_CR_NUM(qual);
    ULONG accType = (ULONG)CR_ACCESS_TYPE(qual);
    ULONG regIdx  = (ULONG)CR_ACCESS_REG(qual);

    // Get the value from the guest register referenced in the instruction
    ULONG_PTR* gprPtr = nullptr;
    switch (regIdx) {
        case 0:  gprPtr = &regs->RAX; break;
        case 1:  gprPtr = &regs->RCX; break;
        case 2:  gprPtr = &regs->RDX; break;
        case 3:  gprPtr = &regs->RBX; break;
        case 4: { ULONG_PTR rsp = HvVmRead(VMCS_GUEST_RSP); gprPtr = &rsp; break; }
        case 5:  gprPtr = &regs->RBP; break;
        case 6:  gprPtr = &regs->RSI; break;
        case 7:  gprPtr = &regs->RDI; break;
        case 8:  gprPtr = &regs->R8;  break;
        case 9:  gprPtr = &regs->R9;  break;
        case 10: gprPtr = &regs->R10; break;
        case 11: gprPtr = &regs->R11; break;
        case 12: gprPtr = &regs->R12; break;
        case 13: gprPtr = &regs->R13; break;
        case 14: gprPtr = &regs->R14; break;
        case 15: gprPtr = &regs->R15; break;
    }

    if (accType == CR_ACCESS_TYPE_MOV_TO && crNum == 3 && gprPtr) {
        // CR3 write = process switch.  Update the VMCS guest CR3 with the
        // new value and log the transition.
        ULONG_PTR newCr3 = *gprPtr;
        W(VMCS_GUEST_CR3, newCr3);

        DbgPrint("[NortonHV] CR3 write: 0x%llx → 0x%llx (CPU %u, RIP=0x%llx)\n",
                 HvVmRead(VMCS_GUEST_CR3), newCr3, vcpu->ProcessorIndex,
                 HvVmRead(VMCS_GUEST_RIP));

    } else if (accType == CR_ACCESS_TYPE_MOV_TO && crNum == 0 && gprPtr) {
        // CR0 write — check if WP (Write Protect) bit is being cleared
        ULONG_PTR newCr0 = *gprPtr;
        if (!(newCr0 & (1u << 16))) {
            DbgPrint("[NortonHV] WARNING: CR0.WP cleared by guest at RIP=0x%llx "
                     "(CPU %u) — kernel write protection disabled\n",
                     HvVmRead(VMCS_GUEST_RIP), vcpu->ProcessorIndex);
        }
        __writecr0(newCr0);
        W(VMCS_GUEST_CR0, newCr0);
        W(VMCS_CTRL_CR0_SHADOW, newCr0);
    }

    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleMsrRead(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    vcpu->MsrInterceptCount++;
    ULONG msr = (ULONG)regs->RCX;

    // Read the actual MSR value and return it to the guest
    LARGE_INTEGER val;
    val.QuadPart = (LONGLONG)__readmsr(msr);
    regs->RAX = (ULONG_PTR)(ULONG)val.LowPart;
    regs->RDX = (ULONG_PTR)(ULONG)val.HighPart;

    DbgPrint("[NortonHV] MSR read: MSR=0x%08x value=0x%016llx (CPU %u)\n",
             msr, (ULONG64)val.QuadPart, vcpu->ProcessorIndex);

    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleMsrWrite(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    vcpu->MsrInterceptCount++;
    ULONG msr = (ULONG)regs->RCX;
    ULONG64 value = ((ULONG64)(ULONG)regs->RDX << 32) | (ULONG)regs->RAX;

    if (msr == IA32_LSTAR) {
        DbgPrint("[NortonHV] CRITICAL: IA32_LSTAR write detected (CPU %u) "
                 "old=0x%llx new=0x%llx RIP=0x%llx — potential syscall hook\n",
                 vcpu->ProcessorIndex, __readmsr(IA32_LSTAR), value,
                 HvVmRead(VMCS_GUEST_RIP));
        // Allow the write to proceed (monitoring mode — production EDR could block)
    }

    if (msr == IA32_EFER) {
        // If the guest tries to clear the NXE (No-Execute Enable) bit, warn
        if (!(value & (1ULL << 11))) {
            DbgPrint("[NortonHV] WARNING: IA32_EFER.NXE cleared by guest (CPU %u) "
                     "— NX protection disabled\n", vcpu->ProcessorIndex);
        }
    }

    if (msr == IA32_DEBUGCTL) {
        DbgPrint("[NortonHV] IA32_DEBUGCTL write: 0x%llx (CPU %u, RIP=0x%llx)\n",
                 value, vcpu->ProcessorIndex, HvVmRead(VMCS_GUEST_RIP));
    }

    __writemsr(msr, value);

    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleVmcall(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    vcpu->VmcallCount++;
    ULONG_PTR code = regs->RCX;
    ULONG_PTR arg1 = regs->RDX;
    ULONG_PTR arg2 = regs->R8;

    switch (code) {
    case HV_CALL_PING:
        DbgPrint("[NortonHV] Hypercall PING from guest (CPU %u)\n",
                 vcpu->ProcessorIndex);
        regs->RAX = 0;  // STATUS_SUCCESS
        break;

    case HV_CALL_GET_STATS:
        // Return vCPU statistics to guest caller
        regs->RAX = vcpu->ExitCount;
        regs->RDX = vcpu->EptViolationCount;
        regs->R8  = vcpu->MsrInterceptCount;
        DbgPrint("[NortonHV] Hypercall GET_STATS: exits=%llu ept=%llu msr=%llu\n",
                 vcpu->ExitCount, vcpu->EptViolationCount, vcpu->MsrInterceptCount);
        break;

    case HV_CALL_PROTECT_PAGE: {
        // arg1 = guest virtual address; make the corresponding physical page
        // non-writable in EPT (anti-tampering for protected regions)
        PHYSICAL_ADDRESS gpa = MmGetPhysicalAddress((PVOID)arg1);
        if (gpa.QuadPart) {
            HvEptSetPagePermissions(vcpu, (ULONG64)gpa.QuadPart, EPT_READ | EPT_EXECUTE);
            DbgPrint("[NortonHV] Hypercall PROTECT_PAGE: GVA=0x%llx GPA=0x%llx\n",
                     arg1, (ULONG64)gpa.QuadPart);
        }
        regs->RAX = 0;
        break;
    }

    case HV_CALL_UNPROTECT_PAGE: {
        PHYSICAL_ADDRESS gpa = MmGetPhysicalAddress((PVOID)arg1);
        if (gpa.QuadPart) {
            HvEptSetPagePermissions(vcpu, (ULONG64)gpa.QuadPart, EPT_RWX);
        }
        regs->RAX = 0;
        break;
    }

    default:
        DbgPrint("[NortonHV] Unknown hypercall code=0x%llx (CPU %u)\n",
                 code, vcpu->ProcessorIndex);
        regs->RAX = (ULONG_PTR)STATUS_NOT_IMPLEMENTED;
        break;
    }

    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleInvd(_In_ PVCPU vcpu)
{
    (void)vcpu;
    // The INVD instruction flushes caches without writing back dirty lines —
    // catastrophic if executed in kernel mode.  Emulate it as WBINVD instead.
    __wbinvd();
    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

static VOID HandleXsetbv(_In_ PVCPU vcpu, _In_ PGUEST_REGISTERS regs)
{
    // XCR0 write — validate and forward to hardware
    ULONG  xcr  = (ULONG)regs->RCX;
    ULONG64 val = ((ULONG64)(ULONG)regs->RDX << 32) | (ULONG)regs->RAX;

    DbgPrint("[NortonHV] XSETBV: XCR%u = 0x%llx (CPU %u)\n",
             xcr, val, vcpu->ProcessorIndex);

    _xsetbv(xcr, val);

    ULONG len = (ULONG)HvVmRead(VMCS_RO_EXIT_INSTR_LEN);
    W(VMCS_GUEST_RIP, HvVmRead(VMCS_GUEST_RIP) + len);
}

// ---------------------------------------------------------------------------
// HvHandleVmExit — main C-level VM exit dispatcher
// Called from HvVmExitStub (MASM) with a pointer to the guest register save area.
// Returns void; the MASM stub issues VMRESUME after this returns.
// ---------------------------------------------------------------------------
extern "C" VOID HvHandleVmExit(_In_ PGUEST_REGISTERS regs)
{
    // Identify the vCPU for the current logical processor
    ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);

    // g_VcpuArray is declared in HvEntry.cpp
    extern PVCPU g_VcpuArray;
    PVCPU vcpu = &g_VcpuArray[cpu];
    vcpu->ExitCount++;

    // Copy saved registers into the VCPU struct so handlers can access them
    // without worrying about pointer lifetime (the stack-based copy is valid
    // only inside this call, but VCPU-level copy persists for diagnostics)
    vcpu->GuestRegs = *regs;

    ULONG exitReason = (ULONG)(HvVmRead(VMCS_RO_EXIT_REASON) & 0xFFFF);

    switch (exitReason) {
    case EXIT_REASON_CPUID:
        HandleCpuid(vcpu, regs);
        break;

    case EXIT_REASON_CR_ACCESS:
        HandleCrAccess(vcpu, regs);
        break;

    case EXIT_REASON_MSR_READ:
        HandleMsrRead(vcpu, regs);
        break;

    case EXIT_REASON_MSR_WRITE:
        HandleMsrWrite(vcpu, regs);
        break;

    case EXIT_REASON_VMCALL:
        HandleVmcall(vcpu, regs);
        break;

    case EXIT_REASON_EPT_VIOLATION: {
        // Check shadow-protected pages first — if this is a read on a decoy
        // page, HvDeceptionHandleEptReadViolation maps the decoy and enables MTF.
        // It returns TRUE and we must NOT call the general handler (which would
        // advance RIP or restore permissions prematurely).
        ULONG64 gpa  = HvVmRead(VMCS_RO_GUEST_PHYS_ADDR);
        ULONG64 qual = HvVmRead(VMCS_RO_EXIT_QUAL);
        if ((qual & EPT_VIOL_READ) && HvDeceptionHandleEptReadViolation(vcpu, gpa)) {
            break;  // decoy served; MTF will restore real mapping after one instruction
        }
        HvEptHandleViolation(vcpu);
        // RIP is NOT advanced — the guest retries the faulting instruction
        // after EPT permissions are restored in HvEptHandleViolation.
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG:
        HvDeceptionHandleMtfExit(vcpu);
        // RIP is already at the next instruction (MTF fires after the instruction completes)
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        DbgPrint("[NortonHV] EPT misconfiguration at GPA=0x%llx (CPU %u) — "
                 "check EPT entry format\n",
                 HvVmRead(VMCS_RO_GUEST_PHYS_ADDR), vcpu->ProcessorIndex);
        // Fatal misconfiguration — halt the guest (set activity state to HLT)
        W(VMCS_GUEST_ACTIVITY_STATE, 2);  // 2 = HLT
        break;

    case EXIT_REASON_INVD:
        HandleInvd(vcpu);
        break;

    case EXIT_REASON_XSETBV:
        HandleXsetbv(vcpu, regs);
        break;

    case EXIT_REASON_EXCEPTION: {
        // #GP triggered by guest VMX instructions (VMXON, VMLAUNCH, etc.)
        // Pass it through to the guest as a normal #GP.
        ULONG intrInfo = (ULONG)HvVmRead(VMCS_RO_EXIT_INTR_INFO);
        DbgPrint("[NortonHV] Exception exit: intr_info=0x%08x (CPU %u, RIP=0x%llx)\n",
                 intrInfo, vcpu->ProcessorIndex, HvVmRead(VMCS_GUEST_RIP));
        // Re-inject the exception
        W(VMCS_CTRL_VMENTRY_INTR_INFO,    intrInfo | (1u << 31));
        W(VMCS_CTRL_VMENTRY_INSTR_LEN,    HvVmRead(VMCS_RO_EXIT_INSTR_LEN));
        ULONG ec = (ULONG)HvVmRead(VMCS_RO_EXIT_INTR_EC);
        if (intrInfo & (1u << 11)) W(VMCS_CTRL_VMENTRY_EXC_EC, ec);
        break;
    }

    case EXIT_REASON_TRIPLE_FAULT:
        DbgPrint("[NortonHV] Triple fault (CPU %u, RIP=0x%llx) — guest crashed\n",
                 vcpu->ProcessorIndex, HvVmRead(VMCS_GUEST_RIP));
        break;

    default:
        // Unexpected exit — log and continue (advance RIP by instruction length
        // for instruction-based exits; for others, just VMRESUME)
        DbgPrint("[NortonHV] Unhandled exit reason %u (CPU %u, RIP=0x%llx)\n",
                 exitReason, vcpu->ProcessorIndex, HvVmRead(VMCS_GUEST_RIP));
        break;
    }

    // Write the (possibly modified) registers back for VMRESUME
    // (RAX/RCX/RDX/etc. are written back by the MASM stub directly from regs[])
    *regs = vcpu->GuestRegs;
}
