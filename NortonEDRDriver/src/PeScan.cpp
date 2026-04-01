#include "Globals.h"

// ---------------------------------------------------------------------------
// PeScanner: detects injected PE images and suspicious executable regions.
//
// Detection methods:
//   1. VAD walk — private RWX regions containing an MZ/PE header
//                 → reflective DLL injection
//   2. Buffer check — MZ/PE header in a captured write or protect buffer
//                 → cross-process PE injection in progress
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static BOOLEAN IsExecutableVadProt(ULONG prot) {
    return (prot == MM_EXECUTE          ||
            prot == MM_EXECUTE_READ     ||
            prot == MM_EXECUTE_READWRITE ||
            prot == MM_EXECUTE_WRITECOPY);
}

static VOID SendPeScanAlert(
    BufferQueue* bufQueue,
    ULONG64      address,
    HANDLE       pid,
    char*        procName,
    BOOLEAN      isCritical,
    const char*  message
) {
    if (!bufQueue || !message) return;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KERNEL_STRUCTURED_NOTIFICATION),
            'pesc'
        );
    if (!notif) return;

    RtlZeroMemory(notif, sizeof(KERNEL_STRUCTURED_NOTIFICATION));

    if (isCritical) SET_CRITICAL(*notif);
    else            SET_WARNING(*notif);

    SET_PESCAN_CHECK(*notif);
    notif->scoopedAddress = address;
    notif->pid            = pid;

    if (procName) {
        RtlCopyMemory(notif->procName, procName, 14);
        notif->procName[14] = '\0';
    }

    SIZE_T msgLen = SafeStringLength(message, 63) + 1;
    notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'psmg');
    if (notif->msg)
        RtlCopyMemory(notif->msg, message, msgLen);

    if (!bufQueue->Enqueue(notif)) {
        if (notif->msg) ExFreePool(notif->msg);
        ExFreePool(notif);
    }
}

// ---------------------------------------------------------------------------
// VAD tree walker — called while attached to the target process.
// Flags private executable regions that contain an MZ header (reflective
// injection) or are marked RWX with no file backing (shellcode staging).
// ---------------------------------------------------------------------------

static VOID WalkVadForPeScan(
    RTL_BALANCED_NODE* node,
    PEPROCESS          process,
    BufferQueue*       bufQueue,
    ULONG*             alertCount
) {
    if (!node || !MmIsAddressValid(node)) return;

    // Cap total alerts per scan to avoid flooding the queue
    if (*alertCount >= 16) return;

    __try {
        PMMVAD  vad  = (PMMVAD)node;
        ULONG   prot = vad->u.VadFlags.Protection;
        BOOLEAN priv = (BOOLEAN)vad->u.VadFlags.PrivateMemory;

        if (priv && IsExecutableVadProt(prot)) {

            ULONG64 startVa = (ULONG64)vad->StartingVpn << 12;
            ULONG64 endVa   = ((ULONG64)vad->EndingVpn + 1) << 12;
            SIZE_T  size    = (SIZE_T)(endVa - startVa);

            // Skip zero-size or unreasonably large regions
            if (size == 0 || size > 0x4000000) goto recurse;

            PVOID startPtr = (PVOID)startVa;

            __try {
                ProbeForRead(startPtr, sizeof(WORD), sizeof(BYTE));
                WORD magic = *(PWORD)startPtr;

                if (magic == IMAGE_DOS_SIGNATURE) {

                    // Confirm NT signature if the buffer is large enough
                    BOOLEAN validPe = FALSE;
                    __try {
                        ProbeForRead(startPtr, sizeof(IMAGE_DOS_HEADER), sizeof(BYTE));
                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)startPtr;
                        LONG e_lfanew = dos->e_lfanew;
                        if (e_lfanew > 0 && e_lfanew < 0x1000 &&
                            (SIZE_T)e_lfanew + sizeof(DWORD) <= size) {
                            PVOID ntHdr = (PVOID)((PUCHAR)startPtr + e_lfanew);
                            ProbeForRead(ntHdr, sizeof(DWORD), sizeof(BYTE));
                            validPe = (*(PDWORD)ntHdr == IMAGE_NT_SIGNATURE);
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}

                    DbgPrint("[!] PeScan: %s PE in private exec region %p size=0x%llX (pid=%llu)\n",
                        validPe ? "Valid" : "MZ-only",
                        startPtr, (ULONG64)size,
                        (ULONG64)PsGetProcessId(process));

                    char msg[64];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "%sPE priv-exec %p sz=0x%llX",
                        validPe ? "Valid" : "MZ",
                        startPtr, (ULONG64)size);

                    (*alertCount)++;
                    SendPeScanAlert(bufQueue,
                        startVa, PsGetProcessId(process),
                        PsGetProcessImageFileName(process),
                        TRUE, msg);
                }

                // Separately flag anonymous RWX even without an MZ header
                else if (prot == MM_EXECUTE_READWRITE) {

                    DbgPrint("[!] PeScan: anonymous RWX region %p size=0x%llX (pid=%llu)\n",
                        startPtr, (ULONG64)size,
                        (ULONG64)PsGetProcessId(process));

                    char msg[64];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "AnonRWX %p sz=0x%llX", startPtr, (ULONG64)size);

                    (*alertCount)++;
                    SendPeScanAlert(bufQueue,
                        startVa, PsGetProcessId(process),
                        PsGetProcessImageFileName(process),
                        FALSE, msg);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

recurse:
    WalkVadForPeScan(node->Left,  process, bufQueue, alertCount);
    WalkVadForPeScan(node->Right, process, bufQueue, alertCount);
}

// ---------------------------------------------------------------------------
// ScanProcessVad — attach to the target process, walk its VAD tree, and
// report suspicious private executable regions.
// Must be called at PASSIVE_LEVEL.
// ---------------------------------------------------------------------------

VOID PeScanner::ScanProcessVad(PEPROCESS process, BufferQueue* bufQueue) {

    if (!process || !bufQueue) return;

    RTL_AVL_TREE* vadRoot =
        (RTL_AVL_TREE*)((PUCHAR)process + OffsetsMgt::GetOffsets()->VadRoot);

    if (!MmIsAddressValid(vadRoot)) return;

    RTL_BALANCED_NODE* root = vadRoot->BalancedRoot;
    if (!root || !MmIsAddressValid(root)) return;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    ULONG alertCount = 0;
    WalkVadForPeScan(root, process, bufQueue, &alertCount);

    KeUnstackDetachProcess(&apcState);

    DbgPrint("[*] PeScan: pid=%llu alerts=%lu\n",
        (ULONG64)PsGetProcessId(process), alertCount);
}

// ---------------------------------------------------------------------------
// CheckBufferForPeHeader — inspect a kernel-memory buffer (already copied
// from user space by NtProtectVmHandler / NtWriteVmHandler) for an MZ/PE
// signature.  No process attachment required.
// ---------------------------------------------------------------------------

VOID PeScanner::CheckBufferForPeHeader(
    PVOID        buffer,
    SIZE_T       size,
    PVOID        targetAddress,
    HANDLE       targetPid,
    char*        procName,
    BufferQueue* bufQueue
) {
    if (!buffer || size < sizeof(WORD) || !bufQueue) return;

    __try {
        if (*(PWORD)buffer != IMAGE_DOS_SIGNATURE) return;

        // Attempt to confirm the NT signature
        BOOLEAN validPe = FALSE;
        if (size >= sizeof(IMAGE_DOS_HEADER)) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
            LONG e_lfanew = dos->e_lfanew;
            if (e_lfanew > 0 && e_lfanew < 0x1000 &&
                (SIZE_T)e_lfanew + sizeof(DWORD) <= size) {
                PDWORD ntSig = (PDWORD)((PUCHAR)buffer + e_lfanew);
                validPe = (*ntSig == IMAGE_NT_SIGNATURE);
            }
        }

        DbgPrint("[!] PeScan: %s PE header in captured buffer target=%p pid=%llu\n",
            validPe ? "Valid" : "MZ-only",
            targetAddress, (ULONG64)targetPid);

        char msg[64];
        RtlStringCbPrintfA(msg, sizeof(msg),
            "%sPE in buf target=%p sz=0x%llX",
            validPe ? "Valid" : "MZ",
            targetAddress, (ULONG64)size);

        SendPeScanAlert(bufQueue,
            (ULONG64)targetAddress, targetPid,
            procName, TRUE, msg);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
