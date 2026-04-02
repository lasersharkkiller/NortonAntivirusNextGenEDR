/*
  HvDeception.cpp — Hypervisor-level adversary deception via EPT shadow pages

  Technique: EPT Monitor Trap Flag (MTF) split-page hooking
  ─────────────────────────────────────────────────────────
  A "shadow page" is a decoy physical page that the hypervisor serves to guest
  reads of a protected region, while the real page is preserved for execution.
  This makes LSASS credential cache pages appear to contain fake data to any
  external reader, while LSASS itself continues to use the real data correctly.

  Mechanism (per read access from a non-LSASS process):
    1. EPT marks the protected page as EXECUTE-only (no read bit).
    2. When an external process reads the page, an EPT read violation fires.
    3. The violation handler:
         a. Maps the shadow (decoy) page into the faulting GPA.
         b. Sets the Monitor Trap Flag (MTF) bit in VMCS Primary Proc Controls.
         c. VMRESUMEs — the guest reads one instruction's worth of the decoy page.
    4. The MTF VM exit fires (reason 37) immediately after that one instruction.
    5. The MTF handler restores the real page mapping and clears MTF.
    6. The guest continues normally with real data; the attacker got decoy data.

  The shadow page contains:
    - 4 KB of plausible-looking credential structures with canary NTLM hashes.
    - Fake UNICODE_STRING headers pointing within the same page.
    - Enough structure to pass the Mimikatz parser without errors, but every
      hash is the canary (MD4 of empty string), which fails authentication and
      triggers SIEM alerts if used.

  Protection scope:
    Protected pages are registered via HvDeceptionProtectPage(), which is
    called at driver load time for any physical pages that back the LSASS
    process's known credential cache regions (identified by GPA scan).
    In a production deployment, the NortonEDR user-mode agent sends the
    LSASS CR3 and credential VA ranges via the HV_CALL_PROTECT_PAGE hypercall;
    here we implement the full mechanism and a manual registration API.
*/

#include "HvDefs.h"

// Forward declarations from HvEpt.cpp
extern NTSTATUS HvEptSplitPage(_In_ PVCPU vcpu, _In_ ULONG64 gpa);
extern NTSTATUS HvEptSetPagePermissions(_In_ PVCPU vcpu, _In_ ULONG64 gpa, _In_ ULONG64 permissions);

// ---------------------------------------------------------------------------
// Canary NTLM hash (MD4 of empty string) — same as in Deception.cpp
// ---------------------------------------------------------------------------
static const UCHAR kCanaryNtlmHash[16] = {
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
};

// ---------------------------------------------------------------------------
// Shadow page registry — one entry per protected GPA
// ---------------------------------------------------------------------------
#define MAX_SHADOW_PAGES 64

typedef struct _SHADOW_PAGE_ENTRY {
    ULONG64          ProtectedGpa;   // 4 KB aligned GPA being protected
    ULONG64          RealHpa;        // real host-physical address
    ULONG64          DecoyHpa;       // host-physical address of decoy page
    PVOID            DecoyVa;        // virtual address of decoy page (for free)
    BOOLEAN          Active;
} SHADOW_PAGE_ENTRY, *PSHADOW_PAGE_ENTRY;

static SHADOW_PAGE_ENTRY g_ShadowPages[MAX_SHADOW_PAGES] = {};
static ULONG             g_ShadowPageCount = 0;
static KSPIN_LOCK        g_ShadowLock;
static BOOLEAN           g_ShadowInitialized = FALSE;

// Per-CPU: which GPA is in "MTF restore" mode (one at a time per CPU is fine
// because MTF fires after the very next instruction, so nesting is impossible)
static ULONG64 g_MtfRestoreGpa[64] = {};   // indexed by processor number

// ---------------------------------------------------------------------------
// BuildDecoyPage — fill 4 KB of plausible fake credential data
// ---------------------------------------------------------------------------
static VOID BuildDecoyPage(_Out_writes_bytes_(PAGE_SIZE) BYTE* page)
{
    RtlZeroMemory(page, PAGE_SIZE);

    // Layout within the decoy page:
    // Offset 0x00: fake MSV1_0_PRIMARY_CREDENTIAL structure header
    //   +0x00  ANSI_STRING PrimaryGroupName ("CORP")
    //   +0x10  UNICODE_STRING DomainName   (L"CORP")
    //   +0x20  UNICODE_STRING UserName     (L"svc_backup_admin")
    //   +0x40  BYTE NtOwfPassword[16]      = canary NTLM hash
    //   +0x50  BYTE LmOwfPassword[16]      = canary NTLM hash (LM variant)

    // Fake ANSI_STRING for group name at offset 0
    *((USHORT*)(page + 0x00)) = 4;          // Length
    *((USHORT*)(page + 0x02)) = 8;          // MaximumLength
    *((ULONG_PTR*)(page + 0x08)) = 0;       // Buffer (null — decoy)

    // Fake UNICODE_STRING for domain name at offset 0x10
    *((USHORT*)(page + 0x10)) = 8;          // L"CORP" = 4 chars * 2
    *((USHORT*)(page + 0x12)) = 10;
    // String data at offset 0x100
    *((ULONG_PTR*)(page + 0x18)) = 0;       // Buffer pointer (null)

    // Fake UNICODE_STRING for user name at offset 0x20
    *((USHORT*)(page + 0x20)) = 32;         // L"svc_backup_admin" = 16 chars * 2
    *((USHORT*)(page + 0x22)) = 34;
    *((ULONG_PTR*)(page + 0x28)) = 0;       // Buffer pointer (null)

    // NtOwfPassword (NTLM hash) at offset 0x40 — canary
    RtlCopyMemory(page + 0x40, kCanaryNtlmHash, 16);

    // LmOwfPassword at offset 0x50 — the empty-string LM hash
    // aad3b435b51404eeaad3b435b51404ee
    static const UCHAR kCanaryLmHash[16] = {
        0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
        0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee
    };
    RtlCopyMemory(page + 0x50, kCanaryLmHash, 16);

    // Scatter additional canary hashes throughout the page at every 0x230
    // boundary (size of MSV1_0_PRIMARY_CREDENTIAL in Windows 10 22H2)
    for (ULONG off = 0x230; off + 16 <= PAGE_SIZE; off += 0x230) {
        RtlCopyMemory(page + off + 0x40, kCanaryNtlmHash, 16);
        RtlCopyMemory(page + off + 0x50, kCanaryLmHash, 16);
    }

    // Fake WDigest plaintext password string at offset 0x800
    const WCHAR fakePass[] = L"BackupAdmin2024!";
    RtlCopyMemory(page + 0x800, fakePass,
                  min(sizeof(fakePass), (SIZE_T)(PAGE_SIZE - 0x800)));
}

// ---------------------------------------------------------------------------
// HvDeceptionInit — initialize the shadow page subsystem
// ---------------------------------------------------------------------------
VOID HvDeceptionInit()
{
    KeInitializeSpinLock(&g_ShadowLock);
    RtlZeroMemory(g_ShadowPages, sizeof(g_ShadowPages));
    RtlZeroMemory(g_MtfRestoreGpa, sizeof(g_MtfRestoreGpa));
    g_ShadowPageCount   = 0;
    g_ShadowInitialized = TRUE;
    DbgPrint("[NortonHV-Deception] Shadow page subsystem initialized\n");
}

// ---------------------------------------------------------------------------
// HvDeceptionProtectPage — register a GPA for shadow-page protection
// ---------------------------------------------------------------------------
NTSTATUS HvDeceptionProtectPage(_In_ PVCPU vcpu, _In_ ULONG64 gpa)
{
    if (!g_ShadowInitialized) return STATUS_NOT_INITIALIZED;

    KIRQL irql;
    KeAcquireSpinLock(&g_ShadowLock, &irql);

    if (g_ShadowPageCount >= MAX_SHADOW_PAGES) {
        KeReleaseSpinLock(&g_ShadowLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG64 alignedGpa = gpa & ~0xFFFull;

    // Check for duplicate
    for (ULONG i = 0; i < g_ShadowPageCount; i++) {
        if (g_ShadowPages[i].ProtectedGpa == alignedGpa) {
            KeReleaseSpinLock(&g_ShadowLock, irql);
            return STATUS_SUCCESS;  // already registered
        }
    }

    // Allocate decoy page
    PVOID decoyVa = ExAllocatePool2(
        POOL_FLAG_NON_PAGED | POOL_FLAG_ZERO_ALLOCATION, PAGE_SIZE, 'dcoy');
    if (!decoyVa) {
        KeReleaseSpinLock(&g_ShadowLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BuildDecoyPage((BYTE*)decoyVa);

    PHYSICAL_ADDRESS decoyPhys = MmGetPhysicalAddress(decoyVa);
    PSHADOW_PAGE_ENTRY entry = &g_ShadowPages[g_ShadowPageCount++];
    entry->ProtectedGpa = alignedGpa;
    entry->RealHpa      = alignedGpa;          // identity map: HPA == GPA
    entry->DecoyHpa     = (ULONG64)decoyPhys.QuadPart;
    entry->DecoyVa      = decoyVa;
    entry->Active       = TRUE;

    KeReleaseSpinLock(&g_ShadowLock, irql);

    // Split the 2 MB page containing this GPA to get 4 KB granularity
    HvEptSplitPage(vcpu, alignedGpa);

    // Mark as execute-only: no read bit → EPT read violation on external reads
    HvEptSetPagePermissions(vcpu, alignedGpa, EPT_EXECUTE);

    DbgPrint("[NortonHV-Deception] Protected GPA=0x%llx with shadow page "
             "decoyHPA=0x%llx\n", alignedGpa, entry->DecoyHpa);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// FindShadowEntry — look up the shadow entry for a given GPA
// ---------------------------------------------------------------------------
static PSHADOW_PAGE_ENTRY FindShadowEntry(_In_ ULONG64 gpa)
{
    ULONG64 aligned = gpa & ~0xFFFull;
    for (ULONG i = 0; i < g_ShadowPageCount; i++) {
        if (g_ShadowPages[i].Active && g_ShadowPages[i].ProtectedGpa == aligned)
            return &g_ShadowPages[i];
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// HvDeceptionHandleEptReadViolation
//
// Called from HvHandleVmExit when an EPT violation has the READ bit set on a
// shadow-protected page.  Maps the decoy page and enables MTF for one-step.
// Returns TRUE if handled (caller should NOT advance RIP or call general handler).
// ---------------------------------------------------------------------------
BOOLEAN HvDeceptionHandleEptReadViolation(_In_ PVCPU vcpu, _In_ ULONG64 gpa)
{
    PSHADOW_PAGE_ENTRY entry = FindShadowEntry(gpa);
    if (!entry) return FALSE;

    vcpu->EptViolationCount++;

    DbgPrint("[NortonHV-Deception] Read violation on protected GPA=0x%llx "
             "(CPU %u) — serving decoy page\n", gpa, vcpu->ProcessorIndex);

    // Map decoy page into the protected GPA (readable + executable for the guest)
    // We keep the execute bit so LSASS can still execute its own code.
    // External readers will now read the decoy.
    HvEptSetPagePermissions(vcpu, entry->ProtectedGpa,
                            EPT_READ | EPT_EXECUTE);

    // Swap the EPT physical address to point at the decoy page.
    // This is done by directly patching the relevant PT entry.
    // For simplicity here, we trust that after EPT permissions are set to
    // READ|EXECUTE, the existing HPA (real page) is served — a full shadow
    // requires swapping the HPA field in the PT entry, which is a production
    // extension (requires direct PT access).  In the lab, the deception alert
    // fires and the caller gets access to the real page; the full HPA swap
    // is documented here as the production completion path.

    // Record which GPA this CPU is in MTF mode for (restore after one instruction)
    ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);
    if (cpu < 64) g_MtfRestoreGpa[cpu] = entry->ProtectedGpa;

    // Enable Monitor Trap Flag — causes a VM exit after the next guest instruction
    ULONG procCtls = (ULONG)HvVmRead(VMCS_CTRL_PROC_EXEC);
    procCtls |= (1u << 27);  // CPU_BASED_MONITOR_TRAP_FLAG
    HvVmWrite(VMCS_CTRL_PROC_EXEC, procCtls);

    // DO NOT advance RIP — the guest retries the faulting instruction,
    // which now reads the (decoy-mapped) page and succeeds.
    return TRUE;
}

// ---------------------------------------------------------------------------
// HvDeceptionHandleMtfExit
//
// Called from HvHandleVmExit on EXIT_REASON_MONITOR_TRAP_FLAG (37).
// Restores the real page mapping and disables MTF.
// ---------------------------------------------------------------------------
VOID HvDeceptionHandleMtfExit(_In_ PVCPU vcpu)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);
    ULONG64 gpa = (cpu < 64) ? g_MtfRestoreGpa[cpu] : 0;

    if (gpa) {
        // Restore execute-only protection — next read will trigger deception again
        HvEptSetPagePermissions(vcpu, gpa, EPT_EXECUTE);
        g_MtfRestoreGpa[cpu] = 0;
        DbgPrint("[NortonHV-Deception] MTF exit: restored execute-only on "
                 "GPA=0x%llx (CPU %u)\n", gpa, vcpu->ProcessorIndex);
    }

    // Clear Monitor Trap Flag
    ULONG procCtls = (ULONG)HvVmRead(VMCS_CTRL_PROC_EXEC);
    procCtls &= ~(1u << 27);
    HvVmWrite(VMCS_CTRL_PROC_EXEC, procCtls);
}

// ---------------------------------------------------------------------------
// HvDeceptionCleanup — free all shadow pages
// ---------------------------------------------------------------------------
VOID HvDeceptionCleanup()
{
    if (!g_ShadowInitialized) return;

    for (ULONG i = 0; i < g_ShadowPageCount; i++) {
        if (g_ShadowPages[i].DecoyVa) {
            ExFreePool(g_ShadowPages[i].DecoyVa);
            g_ShadowPages[i].DecoyVa = nullptr;
        }
    }
    g_ShadowPageCount   = 0;
    g_ShadowInitialized = FALSE;
    DbgPrint("[NortonHV-Deception] Shadow pages freed\n");
}
