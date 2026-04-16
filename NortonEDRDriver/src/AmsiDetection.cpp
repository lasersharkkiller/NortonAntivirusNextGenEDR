#include "Globals.h"

// ---------------------------------------------------------------------------
// Per-process amsi.dll image base tracking.
//
// When amsi.dll loads into a process we record its base and size.  The
// NtSetContextThread / NtContinue syscall handlers query this table to
// detect hardware breakpoints targeting AMSI functions — the core of
// the Ceri Coburn (@_EthicalChaos_) bypass technique.
//
// Table size is bounded (MAX_AMSI_ENTRIES).  On overflow the oldest entry
// is evicted.  Process termination cleans up entries via
// RemoveAmsiImageBase() called from ProcessNotifyRoutine.
// ---------------------------------------------------------------------------
#define MAX_AMSI_ENTRIES 256

struct AmsiImageEntry {
    HANDLE pid;
    ULONG64 base;
    SIZE_T  size;
};

static AmsiImageEntry g_AmsiTable[MAX_AMSI_ENTRIES] = {};
static ULONG          g_AmsiTableCount = 0;
static KSPIN_LOCK     g_AmsiTableLock;
static BOOLEAN        g_AmsiTableInit = FALSE;

static void EnsureAmsiTableInit() {
    if (!g_AmsiTableInit) {
        KeInitializeSpinLock(&g_AmsiTableLock);
        g_AmsiTableInit = TRUE;
    }
}

VOID AmsiDetector::RecordAmsiImageBase(HANDLE pid, PVOID imageBase, SIZE_T imageSize) {
    EnsureAmsiTableInit();
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_AmsiTableLock, &oldIrql);

    // Check if PID already has an entry (amsi.dll re-load after unhook)
    for (ULONG i = 0; i < g_AmsiTableCount; i++) {
        if (g_AmsiTable[i].pid == pid) {
            g_AmsiTable[i].base = (ULONG64)imageBase;
            g_AmsiTable[i].size = imageSize;
            KeReleaseSpinLock(&g_AmsiTableLock, oldIrql);
            return;
        }
    }

    // Add new entry
    if (g_AmsiTableCount < MAX_AMSI_ENTRIES) {
        g_AmsiTable[g_AmsiTableCount].pid  = pid;
        g_AmsiTable[g_AmsiTableCount].base = (ULONG64)imageBase;
        g_AmsiTable[g_AmsiTableCount].size = imageSize;
        g_AmsiTableCount++;
    } else {
        // Evict oldest (index 0) and shift
        RtlMoveMemory(&g_AmsiTable[0], &g_AmsiTable[1],
                       (MAX_AMSI_ENTRIES - 1) * sizeof(AmsiImageEntry));
        g_AmsiTable[MAX_AMSI_ENTRIES - 1].pid  = pid;
        g_AmsiTable[MAX_AMSI_ENTRIES - 1].base = (ULONG64)imageBase;
        g_AmsiTable[MAX_AMSI_ENTRIES - 1].size = imageSize;
    }

    KeReleaseSpinLock(&g_AmsiTableLock, oldIrql);
}

VOID AmsiDetector::RemoveAmsiImageBase(HANDLE pid) {
    EnsureAmsiTableInit();
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_AmsiTableLock, &oldIrql);

    for (ULONG i = 0; i < g_AmsiTableCount; i++) {
        if (g_AmsiTable[i].pid == pid) {
            if (i < g_AmsiTableCount - 1) {
                RtlMoveMemory(&g_AmsiTable[i], &g_AmsiTable[i + 1],
                               (g_AmsiTableCount - i - 1) * sizeof(AmsiImageEntry));
            }
            g_AmsiTableCount--;
            break;
        }
    }

    KeReleaseSpinLock(&g_AmsiTableLock, oldIrql);
}

BOOLEAN AmsiDetector::IsAddressInAmsiDll(HANDLE pid, ULONG64 address) {
    if (!address) return FALSE;
    EnsureAmsiTableInit();

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_AmsiTableLock, &oldIrql);

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_AmsiTableCount; i++) {
        if (g_AmsiTable[i].pid == pid &&
            address >= g_AmsiTable[i].base &&
            address < g_AmsiTable[i].base + g_AmsiTable[i].size)
        {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_AmsiTableLock, oldIrql);
    return found;
}

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
    "AmsiCloseSession",       // less monitored — attackers patch this as alternate target
    "AmsiUacScan",            // undocumented export; if present, verify prologue integrity
    nullptr
};

// ---------------------------------------------------------------------------
// Lightweight x86-64 prologue semantic analyzer.
//
// Rather than matching individual byte sequences (which attackers trivially
// evade by choosing alternate instruction encodings), we track the abstract
// *effect* of the first N instructions.  Any instruction sequence that
// reaches RET within the first ~24 bytes with EAX set to a suspicious value
// (0, 1, 0x80070057, etc.) is a bypass — regardless of how the value was
// constructed (MOV, XOR, PUSH/POP, SUB, LEA, XCHG, NOT+AND, split
// MOV+OR, ...).
//
// This catches:
//   B8 57 00 07 80 C3            MOV EAX,0x80070057; RET
//   68 57 00 07 80 58 C3         PUSH 0x80070057; POP EAX; RET
//   33 C0 0D 57 00 07 80 C3     XOR EAX,EAX; OR EAX,0x80070057; RET
//   B8 00 00 07 80 83 C8 57 C3  MOV EAX,0x80070000; OR EAX,0x57; RET
//   2D A9 FF F8 7F F7 D0 C3     SUB EAX,0x7FF8FFA9; NOT EAX; RET
//   91 33 C0 C3                  XCHG ECX,EAX; XOR EAX,EAX; RET
//   ...and any other creative encoding that produces the same result.
//
// State tracked: EAX value (known/unknown), a stack slot for PUSH/POP,
// and instruction count / byte offset limits to avoid false positives on
// legitimate function prologues.
// ---------------------------------------------------------------------------

// Suspicious return values: if EAX == any of these at RET, it's a bypass
static const ULONG kSuspiciousReturnValues[] = {
    0x00000000, // S_OK / AMSI_RESULT_CLEAN
    0x00000001, // AMSI_RESULT_NOT_DETECTED
    0x80070057, // E_INVALIDARG
};
static const ULONG kNumSuspiciousValues = 3;

static BOOLEAN IsSuspiciousReturn(ULONG val) {
    for (ULONG i = 0; i < kNumSuspiciousValues; i++) {
        if (val == kSuspiciousReturnValues[i]) return TRUE;
    }
    return FALSE;
}

static const char* ClassifySuspiciousReturn(ULONG val) {
    switch (val) {
        case 0x00000000: return "EAX=0(S_OK/CLEAN)";
        case 0x00000001: return "EAX=1(NOT_DETECTED)";
        case 0x80070057: return "EAX=0x80070057(E_INVALIDARG)";
        default:         return "EAX=suspicious";
    }
}

// Emulator state for one register (EAX) and one stack slot
struct PrologueState {
    ULONG  eax;
    BOOLEAN eaxKnown;
    ULONG  stackTop;      // for PUSH/POP tracking
    BOOLEAN stackValid;
    ULONG  insCount;      // instruction count
};

// ---------------------------------------------------------------------------
// EmulateProlog — walk up to 24 bytes / 10 instructions of the prologue,
// tracking EAX state.  Returns a description string if a bypass is found,
// or nullptr if the prologue looks legitimate.
//
// This is intentionally conservative: we only track EAX and a single stack
// slot, and bail on any instruction we don't understand. This means zero
// false positives on real function prologues (which use SUB RSP, MOV RBP,
// LEA with memory operands, etc. — none of which target EAX in the first
// few bytes).
// ---------------------------------------------------------------------------
static const char* EmulateProlog(const UCHAR* b, SIZE_T avail) {
    PrologueState st = {};
    st.eaxKnown = FALSE;
    st.stackValid = FALSE;
    st.insCount = 0;

    SIZE_T off = 0;
    const SIZE_T maxBytes = (avail < 24) ? avail : 24;
    const ULONG  maxIns   = 10;

    while (off < maxBytes && st.insCount < maxIns) {
        UCHAR op = b[off];
        st.insCount++;

        // ----- RET (C3) -----
        if (op == 0xC3) {
            if (st.insCount == 1) return "RET(immediate)";
            if (st.eaxKnown && IsSuspiciousReturn(st.eax))
                return ClassifySuspiciousReturn(st.eax);
            return nullptr; // RET with unknown/non-suspicious EAX
        }

        // ----- RET imm16 (C2 xx xx) -----
        if (op == 0xC2 && off + 2 < maxBytes) {
            if (st.insCount == 1) return "RET-imm16(stack-cleanup)";
            if (st.eaxKnown && IsSuspiciousReturn(st.eax))
                return ClassifySuspiciousReturn(st.eax);
            return nullptr;
        }

        // ----- NOP (90) -----
        if (op == 0x90) {
            // Count consecutive NOPs
            SIZE_T nopStart = off;
            while (off < maxBytes && b[off] == 0x90) off++;
            if (off - nopStart >= 5)
                return "NOP-slide";
            continue; // single NOP, keep going
        }

        // ----- INT3 (CC) -----
        if (op == 0xCC) {
            return "INT3(breakpoint)";
        }

        // ----- MOV EAX, imm32 (B8 xx xx xx xx) -----
        if (op == 0xB8 && off + 4 < maxBytes) {
            st.eax = *(ULONG*)(b + off + 1);
            st.eaxKnown = TRUE;
            off += 5;
            continue;
        }

        // ----- MOV EAX, ECX (89 C8 or 8B C1) -----
        //       MOV EAX, EDX (89 D0 or 8B C2)
        //       — register moves make EAX unknown
        if ((op == 0x89 || op == 0x8B) && off + 1 < maxBytes) {
            UCHAR modrm = b[off + 1];
            UCHAR mod = modrm >> 6;
            UCHAR regDst = (op == 0x8B) ? ((modrm >> 3) & 7) : (modrm & 7);
            if (mod == 3 && regDst == 0) { // EAX is destination
                UCHAR regSrc = (op == 0x8B) ? (modrm & 7) : ((modrm >> 3) & 7);
                if (regSrc == 0) {
                    // MOV EAX, EAX — no-op, keep state
                } else {
                    st.eaxKnown = FALSE; // unknown register source
                }
                off += 2;
                continue;
            }
            // Not targeting EAX — instruction doesn't affect our tracking
            // but we can't easily determine its length, so bail
            break;
        }

        // ----- XOR EAX, EAX (31 C0 or 33 C0) -----
        if ((op == 0x31 || op == 0x33) && off + 1 < maxBytes && b[off + 1] == 0xC0) {
            st.eax = 0;
            st.eaxKnown = TRUE;
            off += 2;
            continue;
        }

        // ----- REX.W prefix (48) + XOR RAX,RAX or XOR EAX,EAX -----
        if (op == 0x48 && off + 2 < maxBytes) {
            if ((b[off + 1] == 0x31 || b[off + 1] == 0x33) && b[off + 2] == 0xC0) {
                st.eax = 0;
                st.eaxKnown = TRUE;
                off += 3;
                continue;
            }
            // Other REX.W prefixed instructions — bail
            break;
        }

        // ----- SUB EAX, EAX (29 C0 or 2B C0) -----
        if ((op == 0x29 || op == 0x2B) && off + 1 < maxBytes && b[off + 1] == 0xC0) {
            st.eax = 0;
            st.eaxKnown = TRUE;
            off += 2;
            continue;
        }

        // ----- SUB EAX, imm32 (2D xx xx xx xx) -----
        if (op == 0x2D && off + 4 < maxBytes && st.eaxKnown) {
            st.eax -= *(ULONG*)(b + off + 1);
            off += 5;
            continue;
        }

        // ----- ADD EAX, imm32 (05 xx xx xx xx) -----
        if (op == 0x05 && off + 4 < maxBytes && st.eaxKnown) {
            st.eax += *(ULONG*)(b + off + 1);
            off += 5;
            continue;
        }

        // ----- OR EAX, imm32 (0D xx xx xx xx) -----
        if (op == 0x0D && off + 4 < maxBytes && st.eaxKnown) {
            st.eax |= *(ULONG*)(b + off + 1);
            off += 5;
            continue;
        }

        // ----- AND EAX, imm32 (25 xx xx xx xx) -----
        if (op == 0x25 && off + 4 < maxBytes && st.eaxKnown) {
            st.eax &= *(ULONG*)(b + off + 1);
            off += 5;
            continue;
        }

        // ----- XOR EAX, imm32 (35 xx xx xx xx) -----
        if (op == 0x35 && off + 4 < maxBytes && st.eaxKnown) {
            st.eax ^= *(ULONG*)(b + off + 1);
            off += 5;
            continue;
        }

        // ----- NOT EAX (F7 D0) -----
        if (op == 0xF7 && off + 1 < maxBytes && b[off + 1] == 0xD0 && st.eaxKnown) {
            st.eax = ~st.eax;
            off += 2;
            continue;
        }

        // ----- NEG EAX (F7 D8) -----
        if (op == 0xF7 && off + 1 < maxBytes && b[off + 1] == 0xD8 && st.eaxKnown) {
            st.eax = (ULONG)(-(LONG)st.eax);
            off += 2;
            continue;
        }

        // ----- INC EAX (FF C0) -----
        if (op == 0xFF && off + 1 < maxBytes && b[off + 1] == 0xC0 && st.eaxKnown) {
            st.eax++;
            off += 2;
            continue;
        }

        // ----- DEC EAX (FF C8) -----
        if (op == 0xFF && off + 1 < maxBytes && b[off + 1] == 0xC8 && st.eaxKnown) {
            st.eax--;
            off += 2;
            continue;
        }

        // ----- PUSH imm32 (68 xx xx xx xx) -----
        if (op == 0x68 && off + 4 < maxBytes) {
            st.stackTop = *(ULONG*)(b + off + 1);
            st.stackValid = TRUE;
            off += 5;
            continue;
        }

        // ----- PUSH imm8 (6A xx) -----
        if (op == 0x6A && off + 1 < maxBytes) {
            st.stackTop = (ULONG)(LONG)(signed char)b[off + 1];
            st.stackValid = TRUE;
            off += 2;
            continue;
        }

        // ----- POP EAX (58) -----
        if (op == 0x58) {
            if (st.stackValid) {
                st.eax = st.stackTop;
                st.eaxKnown = TRUE;
                st.stackValid = FALSE;
            } else {
                st.eaxKnown = FALSE;
            }
            off += 1;
            continue;
        }

        // ----- XCHG EAX, reg (90+rd, but 90=NOP handled above) -----
        //       91=XCHG ECX,EAX  92=XCHG EDX,EAX  etc.
        if (op >= 0x91 && op <= 0x97) {
            st.eaxKnown = FALSE; // unknown source register
            off += 1;
            continue;
        }

        // ----- BSWAP EAX (0F C8) -----
        if (op == 0x0F && off + 1 < maxBytes && b[off + 1] == 0xC8 && st.eaxKnown) {
            st.eax = ((st.eax >> 24) & 0xFF) |
                     ((st.eax >> 8)  & 0xFF00) |
                     ((st.eax << 8)  & 0xFF0000) |
                     ((st.eax << 24) & 0xFF000000);
            off += 2;
            continue;
        }

        // ----- SHL/SHR EAX, imm8 (C1 E0 xx / C1 E8 xx) -----
        if (op == 0xC1 && off + 2 < maxBytes && st.eaxKnown) {
            UCHAR modrm = b[off + 1];
            UCHAR shift = b[off + 2];
            if (modrm == 0xE0) { st.eax <<= (shift & 31); off += 3; continue; }  // SHL
            if (modrm == 0xE8) { st.eax >>= (shift & 31); off += 3; continue; }  // SHR
            break; // other C1 ModR/M — bail
        }

        // ----- OR EAX, imm8 (83 C8 xx) -----
        if (op == 0x83 && off + 2 < maxBytes && b[off + 1] == 0xC8 && st.eaxKnown) {
            st.eax |= (ULONG)(LONG)(signed char)b[off + 2];
            off += 3;
            continue;
        }

        // ----- AND EAX, imm8 (83 E0 xx) -----
        if (op == 0x83 && off + 2 < maxBytes && b[off + 1] == 0xE0 && st.eaxKnown) {
            st.eax &= (ULONG)(LONG)(signed char)b[off + 2];
            off += 3;
            continue;
        }

        // ----- ADD EAX, imm8 (83 C0 xx) -----
        if (op == 0x83 && off + 2 < maxBytes && b[off + 1] == 0xC0 && st.eaxKnown) {
            st.eax += (ULONG)(LONG)(signed char)b[off + 2];
            off += 3;
            continue;
        }

        // ----- SUB EAX, imm8 (83 E8 xx) -----
        if (op == 0x83 && off + 2 < maxBytes && b[off + 1] == 0xE8 && st.eaxKnown) {
            st.eax -= (ULONG)(LONG)(signed char)b[off + 2];
            off += 3;
            continue;
        }

        // ----- XOR EAX, imm8 (83 F0 xx) -----
        if (op == 0x83 && off + 2 < maxBytes && b[off + 1] == 0xF0 && st.eaxKnown) {
            st.eax ^= (ULONG)(LONG)(signed char)b[off + 2];
            off += 3;
            continue;
        }

        // ----- MOV AL, imm8 (B0 xx) -----
        if (op == 0xB0 && off + 1 < maxBytes) {
            if (st.eaxKnown) {
                st.eax = (st.eax & 0xFFFFFF00) | b[off + 1];
            } else {
                // Only low byte known, but common pattern is XOR EAX,EAX + MOV AL
                // If we don't know EAX yet, skip
            }
            off += 2;
            continue;
        }

        // ----- MOV AH, imm8 (B4 xx) -----
        if (op == 0xB4 && off + 1 < maxBytes && st.eaxKnown) {
            st.eax = (st.eax & 0xFFFF00FF) | ((ULONG)b[off + 1] << 8);
            off += 2;
            continue;
        }

        // ----- MOV AX, imm16 (66 B8 xx xx) -----
        if (op == 0x66 && off + 3 < maxBytes && b[off + 1] == 0xB8 && st.eaxKnown) {
            USHORT val = *(USHORT*)(b + off + 2);
            st.eax = (st.eax & 0xFFFF0000) | val;
            off += 4;
            continue;
        }

        // ----- JMP detours (not a return-value bypass, but still a patch) -----
        if (op == 0xE9 && off + 4 < maxBytes) return "JMP-near trampoline";
        if (op == 0xEB) return "JMP-short trampoline";
        if (op == 0xFF && off + 1 < maxBytes && b[off + 1] == 0x25)
            return "JMP-far indirect";

        // ----- MOV R10,imm64; JMP R10 (10-byte far detour) -----
        if (op == 0x49 && off + 11 < maxBytes && b[off + 1] == 0xBA &&
            b[off + 10] == 0x41 && b[off + 11] == 0xFF)
            return "MOV R10,imm64;JMP R10(far-detour)";

        // ----- Unknown instruction — bail (legitimate prologue) -----
        break;
    }

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
// ---------------------------------------------------------------------------
// ScanAmsiContextSignature — amsi.dll keeps a global HAMSICONTEXT whose first
// DWORD is the ASCII magic 'AMSI' (0x49534D41). Attackers corrupt this field
// so AmsiScanBuffer fails its context validation and early-returns
// AMSI_RESULT_CLEAN without invoking any provider. The export prologue is
// untouched in this bypass, so the prologue scanner misses it.
//
// We locate the global context by resolving amsi.dll's `g_amsiContext`
// export (present on Win10+ debug PDBs; on stripped builds we fall back to
// scanning the .data section for the 'AMSI' magic pattern within 256KB of
// amsi.dll base).
// ---------------------------------------------------------------------------
static VOID ScanAmsiContextSignature(
    PVOID        imageBase,
    SIZE_T       imageSize,
    HANDLE       pid,
    char*        procName,
    BufferQueue* bufQueue
) {
    if (!imageBase || imageSize < 0x1000 || !bufQueue) return;

    __try {
        // Walk the image in 4-byte steps searching for the 'AMSI' magic
        // (0x49534D41) within the first 512KB — the g_amsiContext global
        // lives in amsi.dll's .data segment, well before end-of-image.
        SIZE_T scanMax = imageSize > 0x80000 ? 0x80000 : imageSize;
        PUCHAR base = (PUCHAR)imageBase;
        ULONG  magic = 0x49534D41; // 'AMSI'

        // Heuristic: intact install always has at least one literal 'AMSI'
        // DWORD in .data. Absence (with amsi.dll loaded) implies corruption.
        BOOLEAN found = FALSE;
        for (SIZE_T off = 0; off + 4 <= scanMax; off += 4) {
            ProbeForRead(base + off, 4, 1);
            if (*(ULONG*)(base + off) == magic) { found = TRUE; break; }
        }
        if (found) return;

        DbgPrint("[!] AmsiDetector: amsi.dll context signature corrupted pid=%llu\n",
            (ULONG64)pid);

        PKERNEL_STRUCTURED_NOTIFICATION notif =
            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'amsc');
        if (!notif) return;
        RtlZeroMemory(notif, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
        SET_CRITICAL(*notif);
        SET_AMSI_BYPASS_CHECK(*notif);
        notif->scoopedAddress = (ULONG64)imageBase;
        notif->pid = pid;
        notif->isPath = FALSE;
        if (procName) {
            SIZE_T pnLen = SafeStringLength(procName, 14);
            RtlCopyMemory(notif->procName, procName, pnLen);
            notif->procName[pnLen] = '\0';
        }
        const char* msg = "AMSI bypass: g_amsiContext signature corrupted";
        SIZE_T mlen = SafeStringLength(msg, 63) + 1;
        notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, mlen, 'amcg');
        if (notif->msg) RtlCopyMemory(notif->msg, msg, mlen);
        if (!bufQueue->Enqueue(notif)) {
            if (notif->msg) ExFreePool(notif->msg);
            ExFreePool(notif);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ---------------------------------------------------------------------------
// ScanInternalMethodPrologues — find and check internal COM virtual methods
// that are not exported but are targeted by advanced AMSI bypass techniques.
//
// CAmsiAntimalware::Scan() is the internal method that AmsiScanBuffer calls
// to iterate registered providers. Attackers can leave all exported functions
// intact and patch this method instead — evading export-prologue scanners.
//
// Approach: We scan amsi.dll's .text section for the CAmsiAntimalware::Scan
// method signature. The method is a COM __stdcall with a distinctive prologue
// that takes (this, IAmsiStream*, AMSI_RESULT*) and references the provider
// list. We locate candidate internal functions by finding CALL targets from
// AmsiScanBuffer's body, then check each for bypass patches.
// ---------------------------------------------------------------------------
static VOID ScanInternalMethodPrologues(
    PVOID        imageBase,
    SIZE_T       imageSize,
    HANDLE       pid,
    char*        procName,
    BufferQueue* bufQueue
) {
    if (!imageBase || !bufQueue || imageSize < 0x2000) return;

    // Find AmsiScanBuffer — we'll walk its body to find CALL targets
    PUCHAR asbAddr = FindExportByName(imageBase, imageSize, "AmsiScanBuffer");
    if (!asbAddr) return;

    __try {
        // Scan AmsiScanBuffer's body (up to 512 bytes) for E8 (CALL rel32)
        // instructions. Each CALL target that falls within amsi.dll is a
        // candidate internal method. Check each for bypass patches.
        SIZE_T scanLen = 512;
        if ((SIZE_T)(asbAddr - (PUCHAR)imageBase) + scanLen > imageSize)
            scanLen = imageSize - (SIZE_T)(asbAddr - (PUCHAR)imageBase);

        ProbeForRead(asbAddr, scanLen, 1);

        for (SIZE_T off = 0; off + 5 <= scanLen; off++) {
            if (asbAddr[off] != 0xE8) continue;  // CALL rel32

            // Decode relative call target
            LONG rel = *(LONG*)(asbAddr + off + 1);
            PUCHAR target = asbAddr + off + 5 + rel;

            // Verify target is within amsi.dll bounds
            if (target < (PUCHAR)imageBase ||
                target >= (PUCHAR)imageBase + imageSize ||
                target == asbAddr)  // skip self-reference
                continue;

            // Check this internal function's prologue for bypass patches
            ProbeForRead(target, 24, 1);
            const char* pattern = EmulateProlog(target, 24);
            if (!pattern) continue;

            // Found a patched internal method — likely CAmsiAntimalware::Scan
            DbgPrint("[!] AmsiDetector: internal method patch pid=%llu — %s @ %p "
                     "(CALL target from AmsiScanBuffer+0x%llX)\n",
                     (ULONG64)pid, pattern, target, (ULONG64)off);

            char msg[96];
            RtlStringCbPrintfA(msg, sizeof(msg),
                "AMSI bypass: CAmsiAntimalware::Scan (internal) [%s]", pattern);

            PKERNEL_STRUCTURED_NOTIFICATION notif =
                (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'amci');
            if (!notif) continue;

            RtlZeroMemory(notif, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
            SET_CRITICAL(*notif);
            SET_AMSI_BYPASS_CHECK(*notif);
            notif->scoopedAddress = (ULONG64)target;
            notif->pid            = pid;
            notif->isPath         = FALSE;

            if (procName) {
                SIZE_T pnLen = SafeStringLength(procName, 14);
                RtlCopyMemory(notif->procName, procName, pnLen);
                notif->procName[pnLen] = '\0';
            }

            SIZE_T msgLen = SafeStringLength(msg, 95) + 1;
            notif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, msgLen, 'amcm');
            if (notif->msg)
                RtlCopyMemory(notif->msg, msg, msgLen);

            if (!bufQueue->Enqueue(notif)) {
                if (notif->msg) ExFreePool(notif->msg);
                ExFreePool(notif);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}


VOID AmsiDetector::ScanAmsiBypassPatterns(
    PVOID        imageBase,
    SIZE_T       imageSize,
    HANDLE       pid,
    char*        procName,
    BufferQueue* bufQueue
) {
    if (!imageBase || !bufQueue || imageSize == 0) return;

    ScanAmsiContextSignature(imageBase, imageSize, pid, procName, bufQueue);
    ScanInternalMethodPrologues(imageBase, imageSize, pid, procName, bufQueue);

    for (int i = 0; kAmsiExports[i] != nullptr; i++) {

        PUCHAR funcAddr = FindExportByName(imageBase, imageSize, kAmsiExports[i]);
        if (!funcAddr) continue;

        __try {
            ProbeForRead(funcAddr, 24, 1);
            const char* pattern = EmulateProlog(funcAddr, 24);
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
