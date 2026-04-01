/*
  HvEntry.cpp — hypervisor driver entry, per-CPU VMX initialization, and unload

  Initialization sequence (per logical processor, broadcast via IPI):
    1. Check CPUID for VMX support (leaf 1, ECX bit 5).
    2. Verify IA32_FEATURE_CONTROL is locked with VMXON-outside-SMX enabled.
    3. Adjust CR0 and CR4 to satisfy IA32_VMX_CR*_FIXED0/1 requirements.
    4. Allocate and initialize VMXON region, VMCS region, MSR bitmap, EPT, host stack.
    5. VMXON — enter VMX root operation on this CPU.
    6. HvSetupVmcs() — populate all VMCS fields.
    7. HvLaunchVm() (assembly) — write GUEST_RSP/RIP from live CPU state, VMLAUNCH.
       On success: guest (the existing OS) runs in VMX non-root mode.
       On failure: VMXOFF and free resources.

  Unload sequence:
    IPI broadcast → per-CPU: VMCALL HV_CALL_PING (self-test), VMXOFF, free allocations.
    Because the driver is in the guest after launch, it must hypercall into the
    hypervisor to request VMXOFF — directly executing VMXOFF from guest mode would
    cause a #UD or #GP depending on CPL.

  Notes:
    • This driver targets Intel VT-x only.  AMD-V (SVM) uses different MSRs and
      an entirely different instruction set; a CPUID vendor check guards against
      running on AMD hardware.
    • Nested virtualization must be enabled on the test VM (Hyper-V: "Expose
      virtualization extensions"; VMware: vmx.vhv.enable = TRUE; VirtualBox:
      "Enable Nested VT-x/AMD-V").
    • Only tested on Windows 10 20H1–22H2 x64 in TESTSIGNING mode.
*/

#include "HvDefs.h"

// ---------------------------------------------------------------------------
// Forward declarations from other translation units
// ---------------------------------------------------------------------------
extern NTSTATUS HvSetupVmcs(_In_ PVCPU vcpu);
extern NTSTATUS HvEptSetup(_Inout_ PVCPU vcpu);
extern VOID     HvEptFree(_In_ PVCPU vcpu);
extern VOID     HvDeceptionInit();
extern VOID     HvDeceptionCleanup();

// ---------------------------------------------------------------------------
// Global per-CPU array — one VCPU structure per logical processor
// ---------------------------------------------------------------------------
PVCPU g_VcpuArray = nullptr;
ULONG g_ProcessorCount = 0;

// ---------------------------------------------------------------------------
// CheckVmxSupport — verify Intel VT-x availability
// ---------------------------------------------------------------------------
static BOOLEAN CheckVmxSupport()
{
    // CPU vendor must be "GenuineIntel"
    int regs[4];
    __cpuid(regs, 0);
    // EBX="Genu", EDX="ineI", ECX="ntel"
    if (regs[1] != 0x756E6547 || regs[3] != 0x49656E69 || regs[2] != 0x6C65746E) {
        DbgPrint("[NortonHV] Not running on Intel hardware — hypervisor not supported\n");
        return FALSE;
    }

    // CPUID.1:ECX.VMX (bit 5) must be set
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 5))) {
        DbgPrint("[NortonHV] VMX not supported by this CPU\n");
        return FALSE;
    }

    // IA32_FEATURE_CONTROL must be locked with VMXON-outside-SMX bit set
    ULONG64 fc = __readmsr(IA32_FEATURE_CONTROL);
    if (!(fc & FEATURE_CONTROL_LOCKED)) {
        // Not locked — attempt to set and lock (requires ring 0; will succeed
        // on a bare-metal lab machine, may fail on some hypervisors)
        fc |= FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
        __writemsr(IA32_FEATURE_CONTROL, fc);
        fc = __readmsr(IA32_FEATURE_CONTROL);
    }
    if (!(fc & FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) {
        DbgPrint("[NortonHV] IA32_FEATURE_CONTROL does not allow VMXON outside SMX\n");
        return FALSE;
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// AdjustCr0Cr4ForVmx — set VMX-required fixed bits in CR0 and CR4
// ---------------------------------------------------------------------------
static VOID AdjustCr0Cr4ForVmx()
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |=  (ULONG_PTR)__readmsr(IA32_VMX_CR0_FIXED0);
    cr0 &= (ULONG_PTR)__readmsr(IA32_VMX_CR0_FIXED1);
    __writecr0(cr0);

    ULONG_PTR cr4 = __readcr4();
    cr4 |= (ULONG_PTR)__readmsr(IA32_VMX_CR4_FIXED0);
    cr4 &= (ULONG_PTR)__readmsr(IA32_VMX_CR4_FIXED1);
    cr4 |= (1u << 13);   // CR4.VMXE — required before VMXON
    __writecr4(cr4);
}

// ---------------------------------------------------------------------------
// AllocVcpuRegions — allocate all VMX/EPT memory for one VCPU
// ---------------------------------------------------------------------------
static NTSTATUS AllocVcpuRegions(_Inout_ PVCPU vcpu)
{
    // Read the VMCS revision identifier from IA32_VMX_BASIC [30:0]
    ULONG revId = (ULONG)(__readmsr(IA32_VMX_BASIC) & 0x7FFFFFFF);

    // VMXON region
    vcpu->VmxonRegion = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION, PAGE_SIZE, HV_POOL_TAG);
    if (!vcpu->VmxonRegion) return STATUS_INSUFFICIENT_RESOURCES;
    *(ULONG*)vcpu->VmxonRegion = revId;  // write revision ID at offset 0
    vcpu->VmxonPhys = MmGetPhysicalAddress(vcpu->VmxonRegion);

    // VMCS region
    vcpu->VmcsRegion = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION, PAGE_SIZE, HV_POOL_TAG);
    if (!vcpu->VmcsRegion) return STATUS_INSUFFICIENT_RESOURCES;
    *(ULONG*)vcpu->VmcsRegion = revId;
    vcpu->VmcsPhys = MmGetPhysicalAddress(vcpu->VmcsRegion);

    // MSR bitmap (4 KB, zero = no interception by default)
    vcpu->MsrBitmap = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION, PAGE_SIZE, HV_POOL_TAG);
    if (!vcpu->MsrBitmap) return STATUS_INSUFFICIENT_RESOURCES;
    vcpu->MsrBitmapPhys = MmGetPhysicalAddress(vcpu->MsrBitmap);

    // Host stack — grows downward; HOST_RSP = top of the allocation
    vcpu->HostStack = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION, HOST_STACK_SIZE, HV_POOL_TAG);
    if (!vcpu->HostStack) return STATUS_INSUFFICIENT_RESOURCES;

    // Align HOST_RSP to 16 bytes at the top of the stack
    vcpu->HostStackTop = ((ULONG_PTR)vcpu->HostStack + HOST_STACK_SIZE) & ~0xFull;

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// FreeVcpuRegions — release all allocations for one VCPU
// ---------------------------------------------------------------------------
static VOID FreeVcpuRegions(_In_ PVCPU vcpu)
{
    if (vcpu->VmxonRegion) { ExFreePool(vcpu->VmxonRegion); vcpu->VmxonRegion = nullptr; }
    if (vcpu->VmcsRegion)  { ExFreePool(vcpu->VmcsRegion);  vcpu->VmcsRegion  = nullptr; }
    if (vcpu->MsrBitmap)   { ExFreePool(vcpu->MsrBitmap);   vcpu->MsrBitmap   = nullptr; }
    if (vcpu->HostStack)   { ExFreePool(vcpu->HostStack);   vcpu->HostStack   = nullptr; }
    HvEptFree(vcpu);
}

// ---------------------------------------------------------------------------
// HvInitOnProcessor — per-CPU initialization; called via IPI
// ---------------------------------------------------------------------------
static ULONG_PTR HvInitOnProcessor(ULONG_PTR /*context*/)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);
    PVCPU vcpu = &g_VcpuArray[cpu];
    vcpu->ProcessorIndex = cpu;

    // 1. Adjust CR0/CR4 for VMX requirements
    AdjustCr0Cr4ForVmx();

    // 2. Allocate VMX regions (already done in DriverEntry; they must be per-CPU)
    //    If already allocated, skip — DriverEntry pre-allocated everything.
    if (!vcpu->VmxonRegion) {
        DbgPrint("[NortonHV] CPU %u: VCPU regions not pre-allocated\n", cpu);
        return 0;
    }

    // 3. VMXON — enter VMX root operation
    NTSTATUS s = HvVmxOn(&vcpu->VmxonPhys);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[NortonHV] CPU %u: VMXON failed 0x%x\n", cpu, s);
        return 0;
    }

    // 4. Set up MSR bitmap (before VMCS setup which writes the bitmap address)
    // HvSetupMsrBitmap is inlined into HvSetupVmcs via the same TU; call here
    // via the VMCS setup path.

    // 5. Configure VMCS fields
    s = HvSetupVmcs(vcpu);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[NortonHV] CPU %u: HvSetupVmcs failed 0x%x\n", cpu, s);
        HvVmxOff();
        return 0;
    }

    // 6. VMLAUNCH — the CPU transitions to VMX non-root (guest) mode.
    //    If this returns TRUE, the OS is now virtualized.
    //    If it returns FALSE, VMLAUNCH failed (check VM-instruction error field).
    BOOLEAN launched = HvLaunchVm(vcpu);
    if (!launched) {
        ULONG err = (ULONG)HvVmRead(VMCS_RO_VM_INSTR_ERROR);
        DbgPrint("[NortonHV] CPU %u: VMLAUNCH failed, VM-instruction error=%u\n", cpu, err);
        HvVmxOff();
        return 0;
    }

    // If we reach here, the OS is running as a guest and this code runs in
    // guest mode (VMX non-root).  Mark the vCPU as active.
    vcpu->VmxLaunched = TRUE;
    DbgPrint("[NortonHV] CPU %u: virtualized successfully\n", cpu);
    return 1;
}

// ---------------------------------------------------------------------------
// HvDeinitOnProcessor — per-CPU teardown via VMCALL → VMXOFF
// ---------------------------------------------------------------------------
static ULONG_PTR HvDeinitOnProcessor(ULONG_PTR /*context*/)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);
    PVCPU vcpu = &g_VcpuArray[cpu];

    if (!vcpu->VmxLaunched) return 0;

    // Issue a hypercall that signals the hypervisor to exit VMX operation on
    // this CPU.  The exit handler for VMCALL HV_CALL_PING is modified at
    // unload time to execute VMXOFF and return to guest mode.
    //
    // Simpler approach for a lab: set a per-CPU "shutdown" flag in the VCPU
    // and issue any VMCALL — the exit handler checks the flag, executes VMXOFF,
    // and returns to the guest in root mode.
    //
    // Here we use the VMCALL approach: after VMXOFF in the handler, execution
    // returns to the instruction after VMCALL in the guest (which is this code).

    // Signal shutdown
    extern volatile BOOLEAN g_HvShutdown;
    g_HvShutdown = TRUE;

    // The VMCALL will cause an exit; the handler detects g_HvShutdown and
    // calls VMXOFF before returning.  The guest resumes in VMX root operation.
    HvVmCall(HV_CALL_PING, 0, 0);

    vcpu->VmxLaunched = FALSE;
    DbgPrint("[NortonHV] CPU %u: VMXOFF complete; exits=%llu ept=%llu msr=%llu\n",
             cpu, vcpu->ExitCount, vcpu->EptViolationCount, vcpu->MsrInterceptCount);

    return 1;
}

// Shutdown flag checked in HvHandleVmExit for the VMCALL exit
volatile BOOLEAN g_HvShutdown = FALSE;

// ---------------------------------------------------------------------------
// HvUnload
// ---------------------------------------------------------------------------
static VOID HvUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[NortonHV] Unloading — deactivating all vCPUs\n");

    if (g_VcpuArray) {
        KeIpiGenericCall(HvDeinitOnProcessor, 0);

        HvDeceptionCleanup();

        for (ULONG i = 0; i < g_ProcessorCount; i++) {
            FreeVcpuRegions(&g_VcpuArray[i]);
        }

        ExFreePool(g_VcpuArray);
        g_VcpuArray = nullptr;
    }

    DbgPrint("[NortonHV] Unloaded\n");
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[NortonHV] DriverEntry — NortonEDR Hypervisor v1\n");
    DriverObject->DriverUnload = HvUnload;

    // 1. Verify VMX support on the boot CPU (representative check)
    if (!CheckVmxSupport()) return STATUS_NOT_SUPPORTED;

    // 2. Determine logical processor count
    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    DbgPrint("[NortonHV] %u logical processors\n", g_ProcessorCount);

    // 3. Allocate the per-CPU VCPU array
    g_VcpuArray = (PVCPU)ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION,
        sizeof(VCPU) * g_ProcessorCount,
        HV_POOL_TAG);
    if (!g_VcpuArray) return STATUS_INSUFFICIENT_RESOURCES;

    // 4. Pre-allocate per-CPU regions (must happen before the IPI broadcast
    //    because ExAllocatePool2 may not be callable at the elevated IRQL
    //    used inside KeIpiGenericCall on some Windows builds)
    for (ULONG i = 0; i < g_ProcessorCount; i++) {
        NTSTATUS s = AllocVcpuRegions(&g_VcpuArray[i]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[NortonHV] AllocVcpuRegions failed for CPU %u: 0x%x\n", i, s);
            // Free all previously allocated regions
            for (ULONG j = 0; j < i; j++) FreeVcpuRegions(&g_VcpuArray[j]);
            ExFreePool(g_VcpuArray);
            g_VcpuArray = nullptr;
            return s;
        }

        // Build the EPT identity map for this vCPU
        s = HvEptSetup(&g_VcpuArray[i]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[NortonHV] HvEptSetup failed for CPU %u: 0x%x\n", i, s);
            for (ULONG j = 0; j <= i; j++) FreeVcpuRegions(&g_VcpuArray[j]);
            ExFreePool(g_VcpuArray);
            g_VcpuArray = nullptr;
            return s;
        }
    }

    // 5. Initialize the shadow-page deception subsystem (before guests launch).
    //    Non-fatal: deception is best-effort on top of core hypervisor function.
    HvDeceptionInit();

    // 6. Broadcast IPI to virtualize all logical processors simultaneously.
    //    KeIpiGenericCall raises IRQL to IPI_LEVEL, calls the routine on every
    //    CPU, and waits for all to complete before returning.
    DbgPrint("[NortonHV] Broadcasting VMXON + VMLAUNCH to all CPUs...\n");
    ULONG_PTR result = KeIpiGenericCall(HvInitOnProcessor, 0);

    (void)result;   // result is from the current CPU only; individual CPUs log success

    DbgPrint("[NortonHV] Hypervisor active on %u CPU(s)\n", g_ProcessorCount);

    return STATUS_SUCCESS;
}
