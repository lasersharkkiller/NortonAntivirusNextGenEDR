#include "Globals.h"

static VOID SendPeScanAlert(BufferQueue* bufQueue, ULONG64 address, HANDLE pid,
    char* procName, BOOLEAN isCritical, const char* message);

// ---------------------------------------------------------------------------
// Static PE analysis helpers — entropy, section anomalies, TLS callbacks.
// All operate on kernel-memory buffers already validated to contain MZ+NT.
// ---------------------------------------------------------------------------

// Shannon entropy of a byte range, returned as fixed-point (value * 100).
// A packed/encrypted section typically scores >= 700 (7.0 bits/byte).
static ULONG ByteEntropyFixed(const BYTE* data, SIZE_T size) {
    if (!data || size == 0) return 0;

    ULONG freq[256] = {};
    for (SIZE_T i = 0; i < size; i++) freq[data[i]]++;

    // Compute H = -sum(p * log2(p)) using integer approximation.
    // log2(p) ~ log2_approx via repeated halving; scaled by 1000.
    ULONG entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        // p = freq[i] / size  (numerator * 1000 for fixed-point)
        ULONG p1000 = (ULONG)((freq[i] * 1000ULL) / size);
        if (p1000 == 0) continue;

        // Integer log2 via leading-zero count approximation
        ULONG v = (ULONG)((freq[i] * 1024ULL) / size); // p * 1024
        ULONG log2_approx = 0;
        ULONG tmp = v;
        while (tmp > 1) { tmp >>= 1; log2_approx++; }  // floor(log2(v))
        // log2(p) = log2(v) - log2(1024) = log2_approx - 10
        if (log2_approx <= 10) continue;                // p effectively 0
        ULONG log2_bits = log2_approx - 10;             // positive bits

        entropy += p1000 * log2_bits;
    }
    // Result is H * 1000; normalise to H * 100 (two decimal places of bits)
    return entropy / 10;
}

#define IMAGE_DIRECTORY_ENTRY_TLS      9
#define IMAGE_SCN_MEM_EXECUTE          0x20000000
#define IMAGE_SCN_MEM_WRITE            0x80000000

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;   // VA of PIMAGE_TLS_CALLBACK array
    ULONG     SizeOfZeroFill;
    ULONG     Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

// Analyse sections and optional TLS directory of a mapped PE buffer.
// Emits alerts for: high-entropy sections, writable+executable sections,
// raw-size < virtual-size anomalies, TLS callbacks present.
static VOID AnalysePeSections(
    PVOID        base,
    SIZE_T       bufSize,
    HANDLE       pid,
    char*        procName,
    BufferQueue* bufQueue
) {
    __try {
        PIMAGE_DOS_HEADER  dos  = (PIMAGE_DOS_HEADER)base;
        PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dos->e_lfanew);

        WORD  nSections = nth->FileHeader.NumberOfSections;
        if (nSections == 0 || nSections > 96) return;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

        for (WORD i = 0; i < nSections; i++) {
            // Bounds-check section header itself
            if ((PUCHAR)&sec[i] + sizeof(IMAGE_SECTION_HEADER) >
                (PUCHAR)base + bufSize) break;

            ULONG va      = sec[i].VirtualAddress;
            ULONG rawSize = sec[i].SizeOfRawData;
            ULONG rawPtr  = sec[i].PointerToRawData;
            ULONG chars   = sec[i].Characteristics;

            // --- W+X anomaly ---
            BOOLEAN isExec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            BOOLEAN isWrite = (chars & IMAGE_SCN_MEM_WRITE)   != 0;
            if (isExec && isWrite) {
                char msg[64];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "PE section W+X: %.8s (va=0x%lX)",
                    sec[i].Name, va);
                SendPeScanAlert(bufQueue, (ULONG64)base + va, pid, procName, FALSE, msg);
            }

            // --- Raw < Virtual (decompression stub / BSS anomaly) ---
            ULONG virtSize = sec[i].Misc; // Misc.VirtualSize
            if (virtSize > 0 && rawSize > 0 && rawSize < virtSize / 2) {
                char msg[64];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "PE section raw<virt: %.8s raw=0x%lX virt=0x%lX",
                    sec[i].Name, rawSize, virtSize);
                SendPeScanAlert(bufQueue, (ULONG64)base + va, pid, procName, FALSE, msg);
            }

            // --- Entropy of section raw data ---
            if (rawPtr > 0 && rawSize > 64 &&
                (SIZE_T)rawPtr + rawSize <= bufSize) {
                PUCHAR sectionData = (PUCHAR)base + rawPtr;
                ULONG  ent100 = ByteEntropyFixed(sectionData, rawSize);
                // Alert at >= 7.2 bits/byte (720 in our fixed-point scale)
                if (ent100 >= 720) {
                    char msg[64];
                    RtlStringCbPrintfA(msg, sizeof(msg),
                        "High-entropy section %.8s: %lu.%02lu bits/byte",
                        sec[i].Name, ent100 / 100, ent100 % 100);
                    SendPeScanAlert(bufQueue, (ULONG64)base + va, pid, procName, FALSE, msg);
                }
            }
        }

        // --- TLS callbacks ---
        if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            IMAGE_DATA_DIRECTORY tlsDir =
                nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tlsDir.VirtualAddress != 0 && tlsDir.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
                SIZE_T tlsOff = (SIZE_T)tlsDir.VirtualAddress;
                if (tlsOff + sizeof(IMAGE_TLS_DIRECTORY64) <= bufSize) {
                    PIMAGE_TLS_DIRECTORY64 tls =
                        (PIMAGE_TLS_DIRECTORY64)((PUCHAR)base + tlsOff);
                    if (tls->AddressOfCallBacks != 0) {
                        char msg[64];
                        RtlStringCbPrintfA(msg, sizeof(msg),
                            "PE TLS callbacks present (cbArray=0x%llX)",
                            tls->AddressOfCallBacks);
                        SendPeScanAlert(bufQueue, tls->AddressOfCallBacks,
                            pid, procName, FALSE, msg);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

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

                    if (validPe)
                        AnalysePeSections(startPtr, size,
                            PsGetProcessId(process),
                            PsGetProcessImageFileName(process),
                            bufQueue);
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

        if (validPe)
            AnalysePeSections(buffer, size, targetPid, procName, bufQueue);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
