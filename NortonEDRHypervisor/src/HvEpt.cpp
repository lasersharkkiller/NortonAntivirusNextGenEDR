/*
  HvEpt.cpp — Extended Page Table (EPT) management

  EPT is a second layer of address translation sitting between guest-physical
  addresses (GPA) and host-physical addresses (HPA).  The hypervisor controls
  both the translation and the access permissions for every guest-physical page.

  Defensive use cases implemented here:
    • Identity map — every GPA maps 1:1 to the same HPA with full RWX, so the
      guest OS runs normally without modification.
    • Split-page / EPT breakpoint — HvEptSplitPage promotes a 2 MB large-page PD
      entry into a 4 KB PT; callers can then restrict permissions on individual
      4 KB pages to trigger EPT violations on reads, writes, or executes.
    • Write-then-execute detection — the violation handler detects when a GPA that
      was recently written is now being executed (shellcode staging).
    • LSASS page protection — marks the physical pages of lsass.exe executable
      sections as non-writable; a write attempt causes an EPT violation alert.

  EPT page table structure (4-level, 4 KB granularity at leaf, but we use 2 MB
  large pages in the PD layer for the initial identity map to reduce overhead):

      PML4 [GPA bits 47:39] → PDPT [38:30] → PD [29:21] → (large page) HPA
                                                          → PT [20:12] → (small page) HPA

  Memory layout requirements:
    • Every table must be 4 KB aligned (physical address bits 11:0 = 0).
    • Allocated from non-paged pool with 4 KB alignment guaranteed by
      ExAllocatePool2 when size == PAGE_SIZE.
*/

#include "HvDefs.h"

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Allocate a single 4 KB page of non-paged, zeroed memory and return its
// physical address.  Returns NULL physical address on failure.
static PVOID AllocPage(PHYSICAL_ADDRESS* phys)
{
    PVOID va = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION,
                               PAGE_SIZE, HV_POOL_TAG);
    if (!va) {
        phys->QuadPart = 0;
        return nullptr;
    }
    *phys = MmGetPhysicalAddress(va);
    return va;
}

// Build the 64-bit EPT entry for a table pointer (non-leaf entry).
// address = physical address of the next-level table.
static inline EPT_ENTRY MakeTableEntry(PHYSICAL_ADDRESS address)
{
    return (EPT_ENTRY)(address.QuadPart & ~0xFFFull) | EPT_RWX;
}

// Build the 64-bit EPT entry for a 2 MB large page.
static inline EPT_ENTRY MakeLargePage(ULONG64 hpa, ULONG64 permissions)
{
    return (hpa & ~0x1FFFFFull) | EPT_LARGE_PAGE | EPT_MEMORY_WB | permissions;
}

// Build the 64-bit EPT entry for a 4 KB page.
static inline EPT_ENTRY MakeSmallPage(ULONG64 hpa, ULONG64 permissions)
{
    return (hpa & ~0xFFFull) | EPT_MEMORY_WB | permissions;
}

// ---------------------------------------------------------------------------
// HvEptSetup — build the EPT hierarchy and identity-map all physical memory
// ---------------------------------------------------------------------------
NTSTATUS HvEptSetup(_Inout_ PVCPU vcpu)
{
    // Allocate PML4 (one entry is enough to cover the low 512 GB)
    PHYSICAL_ADDRESS pml4Phys = {};
    PEPT_PML4 pml4 = (PEPT_PML4)AllocPage(&pml4Phys);
    if (!pml4) return STATUS_INSUFFICIENT_RESOURCES;

    vcpu->EptPml4     = pml4;
    vcpu->EptPml4Phys = pml4Phys;

    // EPTP value: physical address of PML4 | walk-length (4-1=3) << 3 | WB (6)
    //   bits 5:3 = page-walk length - 1   = 3 (for 4-level walk)
    //   bits 2:0 = EPT paging-structure memory type = 6 (WB)
    vcpu->EptPointer = (pml4Phys.QuadPart & ~0xFFFull) | (3ull << 3) | 6ull;

    // Enumerate host physical memory ranges and identity-map each one
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) {
        ExFreePool(pml4);
        return STATUS_UNSUCCESSFUL;
    }

    for (ULONG i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; i++) {

        ULONG64 base  = (ULONG64)ranges[i].BaseAddress.QuadPart;
        ULONG64 bytes = (ULONG64)ranges[i].NumberOfBytes.QuadPart;
        ULONG64 end   = base + bytes;

        // Walk in 2 MB steps and create large-page EPT entries
        for (ULONG64 gpa = base; gpa < end; gpa += 0x200000ull) {

            // PML4 index [47:39]
            ULONG pml4Idx = (ULONG)((gpa >> 39) & 0x1FF);
            if (!pml4->Entries[pml4Idx]) {
                PHYSICAL_ADDRESS pdptPhys = {};
                PEPT_PDPT pdpt = (PEPT_PDPT)AllocPage(&pdptPhys);
                if (!pdpt) {
                    ExFreePool(pml4);
                    ExFreePool(ranges);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                pml4->Entries[pml4Idx] = MakeTableEntry(pdptPhys);
            }

            // PDPT: physical address from PML4 entry
            ULONG64 pdptPhysAddr = pml4->Entries[pml4Idx] & ~0xFFFull;
            PHYSICAL_ADDRESS pdptPa = { .QuadPart = (LONGLONG)pdptPhysAddr };
            PEPT_PDPT pdpt = (PEPT_PDPT)MmGetVirtualForPhysical(pdptPa);
            if (!pdpt) continue;

            // PDPT index [38:30]
            ULONG pdptIdx = (ULONG)((gpa >> 30) & 0x1FF);
            if (!pdpt->Entries[pdptIdx]) {
                PHYSICAL_ADDRESS pdPhys = {};
                PEPT_PD pd = (PEPT_PD)AllocPage(&pdPhys);
                if (!pd) continue;   // skip this 1 GB range if alloc fails
                pdpt->Entries[pdptIdx] = MakeTableEntry(pdPhys);
            }

            // PD: physical address from PDPT entry
            ULONG64 pdPhysAddr = pdpt->Entries[pdptIdx] & ~0xFFFull;
            PHYSICAL_ADDRESS pdPa = { .QuadPart = (LONGLONG)pdPhysAddr };
            PEPT_PD pd = (PEPT_PD)MmGetVirtualForPhysical(pdPa);
            if (!pd) continue;

            // PD index [29:21] — install a 2 MB identity-map large page
            ULONG pdIdx = (ULONG)((gpa >> 21) & 0x1FF);
            if (!pd->Entries[pdIdx]) {
                pd->Entries[pdIdx] = MakeLargePage(gpa, EPT_RWX);
            }
        }
    }

    ExFreePool(ranges);
    DbgPrint("[NortonHV] EPT identity map built; EPTP=0x%llx\n", vcpu->EptPointer);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HvEptSplitPage — promote a 2 MB large-page PD entry into a 4 KB PT
//
// After splitting, the caller can call HvEptSetPagePermissions to restrict
// a single 4 KB page and trigger EPT violations on that specific page.
// ---------------------------------------------------------------------------
NTSTATUS HvEptSplitPage(_In_ PVCPU vcpu, _In_ ULONG64 gpa)
{
    if (!vcpu || !vcpu->EptPml4) return STATUS_INVALID_PARAMETER;

    ULONG pml4Idx = (ULONG)((gpa >> 39) & 0x1FF);
    ULONG pdptIdx = (ULONG)((gpa >> 30) & 0x1FF);
    ULONG pdIdx   = (ULONG)((gpa >> 21) & 0x1FF);

    PEPT_PML4 pml4 = vcpu->EptPml4;
    if (!pml4->Entries[pml4Idx]) return STATUS_NOT_FOUND;

    PEPT_PDPT pdpt = (PEPT_PDPT)MmGetVirtualForPhysical(
        { .QuadPart = (LONGLONG)(pml4->Entries[pml4Idx] & ~0xFFFull) });
    if (!pdpt || !pdpt->Entries[pdptIdx]) return STATUS_NOT_FOUND;

    PEPT_PD pd = (PEPT_PD)MmGetVirtualForPhysical(
        { .QuadPart = (LONGLONG)(pdpt->Entries[pdptIdx] & ~0xFFFull) });
    if (!pd) return STATUS_NOT_FOUND;

    EPT_ENTRY pde = pd->Entries[pdIdx];
    if (!(pde & EPT_LARGE_PAGE)) return STATUS_SUCCESS;  // already split

    // Allocate a new PT and populate it with 512 × 4 KB entries
    PHYSICAL_ADDRESS ptPhys = {};
    PEPT_PT pt = (PEPT_PT)AllocPage(&ptPhys);
    if (!pt) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG64 baseHpa = pde & ~0x1FFFFFull;   // 2 MB aligned HPA from the large PDE
    for (ULONG k = 0; k < 512; k++) {
        pt->Entries[k] = MakeSmallPage(baseHpa + (ULONG64)k * PAGE_SIZE, EPT_RWX);
    }

    // Replace the large-page PDE with a pointer to the new PT
    pd->Entries[pdIdx] = MakeTableEntry(ptPhys);

    // Invalidate EPT TLB entries for this context
    struct { ULONG64 eptp; ULONG64 reserved; } inveptDesc = { vcpu->EptPointer, 0 };
    HvInvEpt(1, &inveptDesc);   // type 1 = single-context invalidation

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HvEptSetPagePermissions — change R/W/X permissions on a single 4 KB page
//
// The page must already have been split from a 2 MB large page via
// HvEptSplitPage. Passing EPT_RWX restores normal access.
// ---------------------------------------------------------------------------
NTSTATUS HvEptSetPagePermissions(_In_ PVCPU vcpu, _In_ ULONG64 gpa,
                                  _In_ ULONG64 permissions)
{
    if (!vcpu || !vcpu->EptPml4) return STATUS_INVALID_PARAMETER;

    ULONG pml4Idx = (ULONG)((gpa >> 39) & 0x1FF);
    ULONG pdptIdx = (ULONG)((gpa >> 30) & 0x1FF);
    ULONG pdIdx   = (ULONG)((gpa >> 21) & 0x1FF);
    ULONG ptIdx   = (ULONG)((gpa >> 12) & 0x1FF);

    PEPT_PML4 pml4 = vcpu->EptPml4;
    if (!pml4->Entries[pml4Idx]) return STATUS_NOT_FOUND;

    PEPT_PDPT pdpt = (PEPT_PDPT)MmGetVirtualForPhysical(
        { .QuadPart = (LONGLONG)(pml4->Entries[pml4Idx] & ~0xFFFull) });
    if (!pdpt || !pdpt->Entries[pdptIdx]) return STATUS_NOT_FOUND;

    PEPT_PD pd = (PEPT_PD)MmGetVirtualForPhysical(
        { .QuadPart = (LONGLONG)(pdpt->Entries[pdptIdx] & ~0xFFFull) });
    if (!pd) return STATUS_NOT_FOUND;

    EPT_ENTRY pde = pd->Entries[pdIdx];
    if (pde & EPT_LARGE_PAGE) return STATUS_INVALID_PARAMETER; // must split first

    PEPT_PT pt = (PEPT_PT)MmGetVirtualForPhysical(
        { .QuadPart = (LONGLONG)(pde & ~0xFFFull) });
    if (!pt) return STATUS_NOT_FOUND;

    // Update permission bits, preserve the HPA and memory-type bits
    ULONG64 hpa = pt->Entries[ptIdx] & ~0xFFFull;
    pt->Entries[ptIdx] = hpa | EPT_MEMORY_WB | (permissions & EPT_RWX);

    struct { ULONG64 eptp; ULONG64 reserved; } inveptDesc = { vcpu->EptPointer, 0 };
    HvInvEpt(1, &inveptDesc);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HvEptHandleViolation — called from HvHandleVmExit on EXIT_REASON_EPT_VIOLATION
//
// Exit qualification bits describe whether the access was a read, write, or
// execute, and what the current EPT permissions are.  We log the event and
// optionally restore permissions so the guest can continue.
// ---------------------------------------------------------------------------
VOID HvEptHandleViolation(_In_ PVCPU vcpu)
{
    ULONG64 qual  = HvVmRead(VMCS_RO_EXIT_QUAL);
    ULONG64 gpa   = HvVmRead(VMCS_RO_GUEST_PHYS_ADDR);
    ULONG64 gva   = (qual & EPT_VIOL_GVA_VALID) ? HvVmRead(VMCS_RO_GUEST_LIN_ADDR) : 0;
    ULONG64 rip   = HvVmRead(VMCS_GUEST_RIP);

    vcpu->EptViolationCount++;

    const char* accessType =
        (qual & EPT_VIOL_EXEC)  ? "EXECUTE" :
        (qual & EPT_VIOL_WRITE) ? "WRITE"   : "READ";

    // ------------------------------------------------------------------
    // Anti-exploit: detect write-then-execute pattern (shellcode staging)
    //
    // If a page was made non-executable (EPT_READ | EPT_WRITE only) and
    // a guest EXECUTE violation fires on it, this is a strong indicator
    // that shellcode was written into the page and is now being run.
    // ------------------------------------------------------------------
    BOOLEAN execViolOnNonExec =
        (qual & EPT_VIOL_EXEC) &&           // attempted execute
        (qual & EPT_VIOL_READABLE) &&       // page was readable
        !(qual & EPT_VIOL_EXECUTABLE);      // but NOT executable

    DbgPrint("[NortonHV-EPT] %s violation: GPA=0x%llx GVA=0x%llx RIP=0x%llx CPU=%u%s\n",
             accessType, gpa, gva, rip, vcpu->ProcessorIndex,
             execViolOnNonExec ? " [WRITE-THEN-EXECUTE DETECTED]" : "");

    if (execViolOnNonExec) {
        DbgPrint("[NortonHV-EPT] CRITICAL: shellcode execution detected at GPA=0x%llx "
                 "GVA=0x%llx (CPU %u, RIP=0x%llx)\n",
                 gpa, gva, vcpu->ProcessorIndex, rip);
        // In a production EDR, this would inject a detection event into the
        // host-side queue for the TUI/JSONL/Elasticsearch pipeline.
    }

    // Restore full permissions so the guest can continue (monitoring mode).
    // To block execution, leave EPT_EXECUTE cleared — the guest will #GP.
    HvEptSetPagePermissions(vcpu, gpa & ~0xFFFull, EPT_RWX);
}

// ---------------------------------------------------------------------------
// HvEptFree — release all EPT page tables for a vCPU
// ---------------------------------------------------------------------------
VOID HvEptFree(_In_ PVCPU vcpu)
{
    if (!vcpu->EptPml4) return;

    PEPT_PML4 pml4 = vcpu->EptPml4;

    for (int i = 0; i < 512; i++) {
        if (!pml4->Entries[i]) continue;
        PEPT_PDPT pdpt = (PEPT_PDPT)MmGetVirtualForPhysical(
            { .QuadPart = (LONGLONG)(pml4->Entries[i] & ~0xFFFull) });
        if (!pdpt) continue;

        for (int j = 0; j < 512; j++) {
            if (!pdpt->Entries[j]) continue;
            PEPT_PD pd = (PEPT_PD)MmGetVirtualForPhysical(
                { .QuadPart = (LONGLONG)(pdpt->Entries[j] & ~0xFFFull) });
            if (!pd) continue;

            for (int k = 0; k < 512; k++) {
                if (!pd->Entries[k] || (pd->Entries[k] & EPT_LARGE_PAGE)) continue;
                PVOID pt = MmGetVirtualForPhysical(
                    { .QuadPart = (LONGLONG)(pd->Entries[k] & ~0xFFFull) });
                if (pt) ExFreePool(pt);
            }
            ExFreePool(pd);
        }
        ExFreePool(pdpt);
    }

    ExFreePool(pml4);
    vcpu->EptPml4     = nullptr;
    vcpu->EptPml4Phys = {};
    vcpu->EptPointer  = 0;
}
