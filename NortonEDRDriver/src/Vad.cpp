#include "Globals.h"

VadUtils::VadUtils() {

	process = NULL;
	root = NULL;
}

VadUtils::VadUtils(PEPROCESS pEprocess) {
	
	process = pEprocess;
	
	root = (PRTL_AVL_TREE)((PUCHAR)pEprocess + OffsetsMgt::GetOffsets()->VadRoot);

	if (!MmIsAddressValid(root)) {

		DbgPrint("[!] Invalid VadRoot address: %p\n", root);
	}
}

BOOLEAN VadUtils::isAddressOutOfNtdll(
	RTL_BALANCED_NODE* node,
	ULONG64 targetAddress,
	BOOLEAN* isWow64,
	BOOLEAN* isOutOfSys32Ntdll,
	BOOLEAN* isOutOfWow64Ntdll
) {

	if (node == NULL) {
		return FALSE;
	}

	PMMVAD Vad = (PMMVAD)node;
	if (Vad == NULL || !MmIsAddressValid(Vad))
	{
		return FALSE;
	}

	__try {
		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + OffsetsMgt::GetOffsets()->Subsection);

		if (MmIsAddressValid(subsectionAddr)) {
			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + OffsetsMgt::GetOffsets()->ControlArea));

			if (MmIsAddressValid(ControlAreaAddr))
			{
				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->Segment));

				if (MmIsAddressValid(segmentAddr)) {

					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->FilePointer);
					PVOID fileObjectPointer = *(PVOID*)filePointer;

					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);

					if (MmIsAddressValid(fileObject)) {

						if (!*isWow64 && UnicodeStringContains(&fileObject->FileName, L"\\Windows\\System32\\ntdll.dll")) {

							ULONG64 targetVpn = GetUserModeAddressVpn(targetAddress);
							ULONG64 vadStartingVpn = Vad->StartingVpn;
							ULONG64 vadEndingVpn = Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfSys32Ntdll = TRUE;
							}

						}
						else if (*isWow64 && UnicodeStringContains(&fileObject->FileName, L"\\Windows\\SysWOW64\\ntdll.dll")) {

							ULONG32 targetVpn = (ULONG32)GetWow64UserModeAddressVpn(targetAddress);
							ULONG32 vadStartingVpn = (ULONG32)Vad->StartingVpn;
							ULONG32 vadEndingVpn = (ULONG32)Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfWow64Ntdll = TRUE;
							}
						}
					}
				}
			}
		}

		if (*isOutOfSys32Ntdll && *isOutOfWow64Ntdll) {
			return TRUE;
		}

		isAddressOutOfNtdll(
			node->Left,
			targetAddress,
			isWow64,
			isOutOfSys32Ntdll,
			isOutOfWow64Ntdll
		);

		isAddressOutOfNtdll(
			node->Right,
			targetAddress,
			isWow64,
			isOutOfSys32Ntdll,
			isOutOfWow64Ntdll
		);

		return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[Exception] isAddressOutOfNtdll\n");
		//DbgBreakPoint();
	}

	return FALSE;
}

BOOLEAN VadUtils::isAddressOutOfSpecificDll(
	RTL_BALANCED_NODE* node,
	ULONG64 targetAddress,
	BOOLEAN* isWow64,
	BOOLEAN* isOutOfSys32Dll,
	BOOLEAN* isOutOfWow64Dll,
	unsigned short* sys32DllPath,
	unsigned short* wow64DllPath
) {
	if (node == NULL) {
		return FALSE;
	}

	PMMVAD Vad = (PMMVAD)node;
	if (Vad == NULL || !MmIsAddressValid(Vad))
	{
		return FALSE;
	}

	__try {
		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + OffsetsMgt::GetOffsets()->Subsection);

		if (MmIsAddressValid(subsectionAddr)) {
			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + OffsetsMgt::GetOffsets()->ControlArea));

			if (MmIsAddressValid(ControlAreaAddr))
			{
				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->Segment));

				if (MmIsAddressValid(segmentAddr)) {

					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->FilePointer);
					PVOID fileObjectPointer = *(PVOID*)filePointer;

					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);

					if (MmIsAddressValid(fileObject)) {

						if (!*isWow64 && UnicodeStringContains(&fileObject->FileName, sys32DllPath)) {

							ULONG64 targetVpn = GetUserModeAddressVpn(targetAddress);
							ULONG64 vadStartingVpn = Vad->StartingVpn;
							ULONG64 vadEndingVpn = Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfSys32Dll = TRUE;
							}

						}
						else if (*isWow64 && UnicodeStringContains(&fileObject->FileName, wow64DllPath)) {

							ULONG32 targetVpn = (ULONG32)GetWow64UserModeAddressVpn(targetAddress);
							ULONG32 vadStartingVpn = (ULONG32)Vad->StartingVpn;
							ULONG32 vadEndingVpn = (ULONG32)Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfWow64Dll = TRUE;
							}
						}
					}
				}
			}
		}

		if (*isOutOfSys32Dll && *isOutOfWow64Dll) {
			return TRUE;
		}

		isAddressOutOfSpecificDll(
			node->Left,
			targetAddress,
			isWow64,
			isOutOfSys32Dll,
			isOutOfWow64Dll,
			sys32DllPath,
			wow64DllPath
		);

		isAddressOutOfSpecificDll(
			node->Right,
			targetAddress,
			isWow64,
			isOutOfSys32Dll,
			isOutOfWow64Dll,
			sys32DllPath,
			wow64DllPath
		);

		return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[Exception] isAddressOutOfNtdll\n");
		//DbgBreakPoint();
	}

	return FALSE;
}

BOOLEAN VadUtils::isVadImageAddrIdenticalToLdr(PEPROCESS eProcess, ULONG64 vpnStart) {
	
	KAPC_STATE ApcState;
	NTSTATUS Status;

	PVOID PebAddress = NULL;
	PVOID LdrAddress = NULL;

	KeStackAttachProcess(eProcess, &ApcState);

	__try {
		PebAddress = PsGetProcessPeb(eProcess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		return FALSE;
	}

	__try {
		RtlCopyMemory(&LdrAddress, (PVOID)((PUCHAR)PebAddress + 0x018), sizeof(PVOID));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		DbgPrint("Exception occurred while reading Ldr: %08x\n", Status);
		return FALSE;
	}

	PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)LdrAddress;
	if (!MmIsAddressValid(Ldr))
	{
		KeUnstackDetachProcess(&ApcState);
		return FALSE;
	}

	LIST_ENTRY* head = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* current = head->Flink;

	PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	if (vpnStart != GetUserModeAddressVpn((ULONG64)entry->DllBase)) {
		return TRUE;
	}

	KeUnstackDetachProcess(&ApcState);

	return FALSE;
}

VOID VadUtils::exploreVadTreeAndVerifyLdrIngtegrity(
	RTL_BALANCED_NODE* node,
	UNICODE_STRING* searchStr,
	BOOLEAN* isTampered
) {
	if (PsGetCurrentProcess()) {
		if (node == NULL || isTampered == NULL || *isTampered) {
		return;
	}

	PMMVAD Vad = (PMMVAD)node;

	if (!MmIsAddressValid(Vad)) {
		return;
	}

	__try {
		_SUBSECTION* subsectionAddr = NULL;
		PVOID ControlAreaAddr = NULL;
		_SEGMENT* segmentAddr = NULL;
		FILE_OBJECT* fileObject = NULL;

		subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + OffsetsMgt::GetOffsets()->Subsection);

		if (subsectionAddr != 0x0) {

			if (MmIsAddressValid(subsectionAddr)) {
				ControlAreaAddr = *(PVOID*)((PUCHAR)subsectionAddr + OffsetsMgt::GetOffsets()->ControlArea);

				if (MmIsAddressValid(ControlAreaAddr)) {
					segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->Segment));

					if (MmIsAddressValid(segmentAddr)) {
						PVOID filePointer = *(PVOID*)((PUCHAR)ControlAreaAddr + OffsetsMgt::GetOffsets()->FilePointer);

						if (filePointer && MmIsAddressValid(filePointer)) {
							fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)filePointer);

							if (MmIsAddressValid(fileObject) &&
								UnicodeStringContains(&fileObject->FileName, searchStr->Buffer) &&
								FileIsExe(&fileObject->FileName)) {
								*isTampered = isVadImageAddrIdenticalToLdr(PsGetCurrentProcess(), (ULONG64)Vad->StartingVpn);
							}
						}
					}
				}
			}

		}

		if (!*isTampered) {
			exploreVadTreeAndVerifyLdrIngtegrity(node->Left, searchStr, isTampered);
			exploreVadTreeAndVerifyLdrIngtegrity(node->Right, searchStr, isTampered);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Exception in exploreVadTreeAndVerifyLdrIngtegrity\n");
	}
	}


}

// ---------------------------------------------------------------------------
// Hidden mapped section detection — find SEC_IMAGE VAD entries with no LDR match.
//
// Reflective loaders and manual-map injectors call NtMapViewOfSection to place
// a PE image into the target process without going through the Windows loader.
// The result is a VadType==VadImageMap (file-backed SEC_IMAGE) VAD node whose
// StartingVpn is absent from the PEB LDR InMemoryOrderModuleList.
//
// Algorithm:
//   1. Walk all VAD nodes; filter to VadType==2 (VadImageMap) + executable prot.
//   2. For each, walk the LDR list looking for a DllBase match.
//   3. If not found and LDR is initialised with ≥3 entries → Critical alert.
//
// Called after cross-process thread injection is detected (CreateThreadNotify)
// to scan the target process. LDR-readiness guard prevents false positives at
// early process startup.
// ---------------------------------------------------------------------------

#define VAD_TYPE_IMAGE_MAP 2  // MMVAD_FLAGS.VadType == 2 → SEC_IMAGE (VadImageMap)

// Returns TRUE if the internal VAD protection value is executable.
static BOOLEAN IsVadExec(ULONG prot) {
    return (prot == MM_EXECUTE          ||
            prot == MM_EXECUTE_READ     ||
            prot == MM_EXECUTE_READWRITE ||
            prot == MM_EXECUTE_WRITECOPY);
}

// Must be called while attached to the process.
// Returns TRUE if baseVa is in the InMemoryOrderModuleList (= has an LDR entry).
// Returns TRUE on any read failure (conservative: prefer no false positives).
static BOOLEAN IsBaseInLdr(PEPROCESS process, ULONG64 baseVa) {
    __try {
        PVOID peb = PsGetProcessPeb(process);
        if (!peb || !MmIsAddressValid(peb)) return TRUE;

        PVOID ldrPtr = nullptr;
        ProbeForRead((PUCHAR)peb + 0x18, sizeof(PVOID), sizeof(BYTE));
        RtlCopyMemory(&ldrPtr, (PUCHAR)peb + 0x18, sizeof(PVOID));
        if (!ldrPtr || !MmIsAddressValid(ldrPtr)) return TRUE;

        PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)ldrPtr;
        if (!ldr->Initialized) return TRUE;  // loader not yet running

        LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY* cur  = head->Flink;

        for (int limit = 512; cur != head && limit > 0; limit--) {
            if (!MmIsAddressValid(cur)) return TRUE;  // corrupt list — bail safe
            PLDR_DATA_TABLE_ENTRY entry =
                CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (MmIsAddressValid(entry) && (ULONG64)entry->DllBase == baseVa)
                return TRUE;
            cur = cur->Flink;
        }
        return FALSE;  // walked all entries — not found
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;  // read fault — skip this address
    }
}

// VAD tree walker for hidden mappings.  Must be called while attached.
static VOID WalkVadHiddenMappings(
    RTL_BALANCED_NODE* node,
    PEPROCESS          process,
    BufferQueue*       queue,
    ULONG*             alertCount
) {
    if (!node || !MmIsAddressValid(node) || *alertCount >= 8) return;

    __try {
        PMMVAD vad  = (PMMVAD)node;
        ULONG  vt   = vad->u.VadFlags.VadType;
        ULONG  prot = vad->u.VadFlags.Protection;

        if (vt == VAD_TYPE_IMAGE_MAP && IsVadExec(prot)) {
            ULONG64 baseVa = (ULONG64)vad->StartingVpn << 12;

            // Skip null/sub-page and kernel addresses
            if (baseVa < 0x10000 || baseVa >= 0x7FFF00000000ULL) goto recurse;

            if (!IsBaseInLdr(process, baseVa)) {

                // Extract backing file name from Subsection → ControlArea → FILE_OBJECT
                char fileName[128] = "<no file>";
                __try {
                    _SUBSECTION* sub =
                        (_SUBSECTION*)*(PVOID*)((PUCHAR)vad + OffsetsMgt::GetOffsets()->Subsection);
                    if (sub && MmIsAddressValid(sub)) {
                        PVOID ctrl = *(PVOID*)((PUCHAR)sub + OffsetsMgt::GetOffsets()->ControlArea);
                        if (ctrl && MmIsAddressValid(ctrl)) {
                            PVOID rawFp = *(PVOID*)((PUCHAR)ctrl + OffsetsMgt::GetOffsets()->FilePointer);
                            FILE_OBJECT* fo =
                                (FILE_OBJECT*)NullifyLastDigit((ULONG64)rawFp);
                            if (fo && MmIsAddressValid(fo) &&
                                fo->FileName.Buffer && fo->FileName.Length > 0) {
                                USHORT cc = min(
                                    (USHORT)(fo->FileName.Length / sizeof(WCHAR)),
                                    (USHORT)(sizeof(fileName) - 1));
                                for (USHORT i = 0; i < cc; i++) {
                                    WCHAR wc = fo->FileName.Buffer[i];
                                    fileName[i] = (wc < 128) ? (char)wc : '?';
                                }
                                fileName[cc] = '\0';
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                (*alertCount)++;
                char msg[256];
                RtlStringCbPrintfA(msg, sizeof(msg),
                    "Hidden mapped section: SEC_IMAGE at 0x%llX not in LDR"
                    " -- reflective/manual-map injection; file: %s",
                    baseVa, fileName);

                char* pn = PsGetProcessImageFileName(process);

                PKERNEL_STRUCTURED_NOTIFICATION notif =
                    (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'vadh');
                if (notif) {
                    RtlZeroMemory(notif, sizeof(*notif));
                    SET_CRITICAL(*notif);
                    SET_PROC_VAD_CHECK(*notif);
                    InjectionTaintTracker::MarkTainted(PsGetProcessId(process));
                    notif->scoopedAddress = baseVa;
                    notif->pid            = PsGetProcessId(process);
                    notif->isPath         = FALSE;
                    if (pn) RtlCopyMemory(notif->procName, pn, 14);
                    SIZE_T msgLen = strlen(msg) + 1;
                    notif->msg = (char*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, msgLen, 'vadm');
                    if (notif->msg) {
                        RtlCopyMemory(notif->msg, msg, msgLen);
                        notif->bufSize = (ULONG)msgLen;
                        if (!queue->Enqueue(notif)) {
                            ExFreePool(notif->msg);
                            ExFreePool(notif);
                        }
                    } else { ExFreePool(notif); }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

recurse:
    WalkVadHiddenMappings(node->Left,  process, queue, alertCount);
    WalkVadHiddenMappings(node->Right, process, queue, alertCount);
}

// Public entry point.
VOID VadUtils::ScanForHiddenMappings(PEPROCESS process, BufferQueue* queue) {
    if (!process || !queue) return;

    RTL_AVL_TREE* vadRoot =
        (RTL_AVL_TREE*)((PUCHAR)process + OffsetsMgt::GetOffsets()->VadRoot);
    if (!MmIsAddressValid(vadRoot)) return;

    RTL_BALANCED_NODE* root = vadRoot->BalancedRoot;
    if (!root || !MmIsAddressValid(root)) return;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    // Guard: skip if LDR is not yet initialised or has fewer than 3 entries.
    // At fewer than 3 entries the loader hasn't finished its normal startup
    // sequence — any missing-LDR result would be a false positive.
    BOOLEAN ready = FALSE;
    __try {
        PVOID peb = PsGetProcessPeb(process);
        if (peb && MmIsAddressValid(peb)) {
            PVOID ldrPtr = nullptr;
            RtlCopyMemory(&ldrPtr, (PUCHAR)peb + 0x18, sizeof(PVOID));
            if (ldrPtr && MmIsAddressValid(ldrPtr)) {
                PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)ldrPtr;
                if (ldr->Initialized) {
                    int count = 0;
                    LIST_ENTRY* h = &ldr->InMemoryOrderModuleList;
                    LIST_ENTRY* c = h->Flink;
                    while (c != h && MmIsAddressValid(c) && count < 4) {
                        c = c->Flink;
                        count++;
                    }
                    if (count >= 3) ready = TRUE;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (ready) {
        ULONG alertCount = 0;
        WalkVadHiddenMappings(root, process, queue, &alertCount);
    }

    KeUnstackDetachProcess(&apc);
}

// ---------------------------------------------------------------------------
// IsAddressInPrivateExecVad — detect if an address falls in a private,
// executable VAD region (shellcode).  Used to identify indirect syscalls
// originating from attacker-controlled memory rather than loaded DLLs.
// ---------------------------------------------------------------------------

static BOOLEAN WalkVadForPrivateExec(RTL_BALANCED_NODE* node, ULONG64 address)
{
    if (!node || !MmIsAddressValid(node)) return FALSE;

    __try {
        PMMVAD vad  = (PMMVAD)node;
        ULONG64 startVa = (ULONG64)vad->StartingVpn << 12;
        ULONG64 endVa   = ((ULONG64)vad->EndingVpn << 12) | 0xFFF;

        if (address >= startVa && address <= endVa) {
            return vad->u.VadFlags.PrivateMemory &&
                   (vad->u.VadFlags.Protection == MM_EXECUTE          ||
                    vad->u.VadFlags.Protection == MM_EXECUTE_READ     ||
                    vad->u.VadFlags.Protection == MM_EXECUTE_READWRITE ||
                    vad->u.VadFlags.Protection == MM_EXECUTE_WRITECOPY);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    // Not in this node — recurse left and right
    if (WalkVadForPrivateExec(((PMMVAD)node)->LeftChild ?
            (RTL_BALANCED_NODE*)((PMMVAD)node)->LeftChild : nullptr, address))
        return TRUE;

    return WalkVadForPrivateExec(((PMMVAD)node)->RightChild ?
            (RTL_BALANCED_NODE*)((PMMVAD)node)->RightChild : nullptr, address);
}

BOOLEAN VadUtils::IsAddressInPrivateExecVad(PRTL_BALANCED_NODE root, ULONG64 address)
{
    if (!root || address < 0x10000 || address >= 0x7FFF00000000ULL) return FALSE;
    return WalkVadForPrivateExec(root, address);
}

//VOID VadUtils::exploreVadTreeAndVerifyLdrIngtegrity(
//	RTL_BALANCED_NODE* node,
//	UNICODE_STRING* searchStr,
//	BOOLEAN* isTampered
//) {
//
//	if (node == NULL) {
//		return;
//	}
//
//	PMMVAD Vad = (PMMVAD)node;
//	if (Vad == NULL || !MmIsAddressValid(Vad))
//	{
//		return;
//	}
//
//	__try {
//
//		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + VAD_SUBSECTION_OFFSET);
//
//		if (MmIsAddressValid(subsectionAddr)) {
//			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + VAD_CONTROL_AREA_OFFSET));
//
//			if (MmIsAddressValid(ControlAreaAddr))
//			{
//				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + VAD_SEGMENT_OFFSET));
//
//				if (MmIsAddressValid(segmentAddr)) {
//
//					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + VAD_FILE_POINTER_OFFSET);
//					PVOID fileObjectPointer = *(PVOID*)filePointer;
//
//					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);
//
//					if (MmIsAddressValid(fileObject)) {
//
//						if (UnicodeStringContains(&fileObject->FileName, searchStr->Buffer) && FileIsExe(&fileObject->FileName)) {
//
//							*isTampered = isVadImageAddrIdenticalToLdr(PsGetCurrentProcess(), (ULONG64)Vad->StartingVpn);
//						}
//					}
//				}
//			}
//		}
//
//		if (!*isTampered) {
//			exploreVadTreeAndVerifyLdrIngtegrity(node->Left, searchStr, isTampered);
//			exploreVadTreeAndVerifyLdrIngtegrity(node->Right, searchStr, isTampered);
//		}
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		DbgPrint("Exception in exploreVadTreeAndVerifyLdrIngtegrity\n");
//		//DbgBreakPoint();
//	}
//
//}