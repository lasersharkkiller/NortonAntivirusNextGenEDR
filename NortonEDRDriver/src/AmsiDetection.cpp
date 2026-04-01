#include "Globals.h"

// ---------------------------------------------------------------------------
// AmsiDetector: detects AMSI bypass patches in amsi.dll at image load time.
//
// Called from ImageLoadNotifyRoutine when amsi.dll is mapped into a process.
// The caller must already be attached to the target process via
// KeStackAttachProcess so that ImageBase is accessible.
//
// Detected bypass patterns (in the first 8 bytes of each export prologue):
//   XOR EAX,EAX; RET          (33 C0 C3 / 31 C0 C3)  — always-clean patch
//   XOR RAX,RAX; RET          (48 31 C0 C3)           — 64-bit zero-return
//   MOV EAX,0x80070057; RET   (B8 57 00 07 80 C3)     — E_INVALIDARG patch
//   JMP near trampoline        (E9 xx xx xx xx)        — redirect hook
//   JMP far indirect           (FF 25 xx xx xx xx)     — indirect redirect
// ---------------------------------------------------------------------------

static const char* const kAmsiExports[] = {
    "AmsiScanBuffer",
    "AmsiOpenSession",
    "AmsiInitialize",
    "AmsiScanString",
    nullptr
};

static const char* IdentifyBypassPattern(const UCHAR* bytes, SIZE_T avail) {
    if (avail >= 3) {
        if (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
            return "XOR EAX,EAX;RET";
        if (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
            return "XOR EAX,EAX;RET(alt)";
    }
    if (avail >= 4) {
        if (bytes[0] == 0x48 && bytes[1] == 0x31 && bytes[2] == 0xC0 && bytes[3] == 0xC3)
            return "XOR RAX,RAX;RET";
        if (bytes[0] == 0x48 && bytes[1] == 0x33 && bytes[2] == 0xC0 && bytes[3] == 0xC3)
            return "XOR RAX,RAX;RET(alt)";
    }
    if (avail >= 6) {
        if (bytes[0] == 0xB8 && bytes[1] == 0x57 && bytes[2] == 0x00 &&
            bytes[3] == 0x07 && bytes[4] == 0x80 && bytes[5] == 0xC3)
            return "MOV EAX,0x80070057;RET";
    }
    if (avail >= 5 && bytes[0] == 0xE9) return "JMP-near trampoline";
    if (avail >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25) return "JMP-far indirect";
    return nullptr;
}

// ---------------------------------------------------------------------------
// FindExportByName — resolve a named export from a user-mode PE image.
// Must be called while attached to the target process.
// ---------------------------------------------------------------------------
static PUCHAR FindExportByName(PVOID imageBase, SIZE_T imageSize, const char* name) {
    if (!imageBase || imageSize < sizeof(IMAGE_DOS_HEADER) || !name) return nullptr;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        ProbeForRead(dos, sizeof(IMAGE_DOS_HEADER), 1);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        LONG e_lfanew = dos->e_lfanew;
        if (e_lfanew <= 0 || (SIZE_T)e_lfanew + sizeof(IMAGE_NT_HEADERS64) > imageSize)
            return nullptr;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)imageBase + e_lfanew);
        ProbeForRead(nt, sizeof(IMAGE_NT_HEADERS64), 1);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        IMAGE_DATA_DIRECTORY expDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress || !expDir.Size) return nullptr;
        if ((SIZE_T)expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > imageSize)
            return nullptr;

        PIMAGE_EXPORT_DIRECTORY exports =
            (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + expDir.VirtualAddress);
        ProbeForRead(exports, sizeof(IMAGE_EXPORT_DIRECTORY), 1);

        ULONG numNames = exports->NumberOfNames;
        if (!numNames || numNames > 8192) return nullptr;
        if (!exports->AddressOfNames || !exports->AddressOfNameOrdinals ||
            !exports->AddressOfFunctions) return nullptr;

        PULONG  nameRvas  = (PULONG) ((PUCHAR)imageBase + exports->AddressOfNames);
        PUSHORT ordinals  = (PUSHORT)((PUCHAR)imageBase + exports->AddressOfNameOrdinals);
        PULONG  funcRvas  = (PULONG) ((PUCHAR)imageBase + exports->AddressOfFunctions);

        ProbeForRead(nameRvas, sizeof(ULONG)  * numNames, 1);
        ProbeForRead(ordinals, sizeof(USHORT) * numNames, 1);

        SIZE_T nameLen = SafeStringLength(name, 127);

        for (ULONG i = 0; i < numNames; i++) {
            if (!nameRvas[i] || (SIZE_T)nameRvas[i] >= imageSize) continue;

            PCHAR expName = (PCHAR)((PUCHAR)imageBase + nameRvas[i]);

            // Byte-by-byte comparison (safe because we're in the target process)
            BOOLEAN match = TRUE;
            for (SIZE_T j = 0; j < nameLen; j++) {
                if (expName[j] != name[j]) { match = FALSE; break; }
            }
            if (!match || expName[nameLen] != '\0') continue;

            USHORT ord = ordinals[i];
            if (ord >= exports->NumberOfFunctions) continue;

            ULONG funcRva = funcRvas[ord];
            if (!funcRva || (SIZE_T)funcRva >= imageSize) continue;

            return (PUCHAR)imageBase + funcRva;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return nullptr;
}

// ---------------------------------------------------------------------------
// AmsiDetector::ScanAmsiBypassPatterns
// ---------------------------------------------------------------------------
VOID AmsiDetector::ScanAmsiBypassPatterns(
    PVOID        imageBase,
    SIZE_T       imageSize,
    HANDLE       pid,
    char*        procName,
    BufferQueue* bufQueue
) {
    if (!imageBase || !bufQueue || imageSize == 0) return;

    for (int i = 0; kAmsiExports[i] != nullptr; i++) {

        PUCHAR funcAddr = FindExportByName(imageBase, imageSize, kAmsiExports[i]);
        if (!funcAddr) continue;

        __try {
            ProbeForRead(funcAddr, 8, 1);
            const char* pattern = IdentifyBypassPattern(funcAddr, 8);
            if (!pattern) continue;

            DbgPrint("[!] AmsiDetector: bypass in %-20s pid=%llu — %s @ %p\n",
                kAmsiExports[i], (ULONG64)pid, pattern, funcAddr);

            char msg[64];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "AMSI bypass: %s [%s]", kAmsiExports[i], pattern);

            PKERNEL_STRUCTURED_NOTIFICATION notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'amsi');
            if (!notif) continue;

            RtlZeroMemory(notif, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
            SET_CRITICAL(*notif);
            SET_AMSI_BYPASS_CHECK(*notif);
            notif->scoopedAddress = (ULONG64)funcAddr;
            notif->pid            = pid;
            notif->isPath         = FALSE;

            if (procName) {
                SIZE_T pnLen = SafeStringLength(procName, 14);
                RtlCopyMemory(notif->procName, procName, pnLen);
                notif->procName[pnLen] = '\0';
            }

            SIZE_T msgLen = SafeStringLength(msg, 63) + 1;
            notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'amsg');
            if (notif->msg)
                RtlCopyMemory(notif->msg, msg, msgLen);

            if (!bufQueue->Enqueue(notif)) {
                if (notif->msg) ExFreePool(notif->msg);
                ExFreePool(notif);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}
