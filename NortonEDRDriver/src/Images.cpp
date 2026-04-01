#include "Globals.h"
#include "sha256utils.h"

KMUTEX ImageUtils::g_HashQueueMutex;

VOID ImageUtils::ImageLoadNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL) {
        DbgPrint("[-] Invalid parameters\n");
        return;
    }

    if (ImageInfo->ImageSize == 0) {
        DbgPrint("[-] Image size is zero\n");
        return;
    }

    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;

    __try {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProcess))) {
            DbgPrint("[-] PsLookupProcessByProcessId failed\n");
            return;
        }

        KeStackAttachProcess(targetProcess, &apcState);
        attached = TRUE;
    
        __try {

                if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
                    ULONG charBufferSize = FullImageName->Length / sizeof(WCHAR) + 1;
                    char* charBuffer = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, charBufferSize, 'jedb');

                    if (charBuffer) {
                        UNICODE_STRING unicodeString;
                        ANSI_STRING ansiString;

                        RtlInitUnicodeString(&unicodeString, FullImageName->Buffer);
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, TRUE))) {

                            RtlCopyMemory(charBuffer, ansiString.Buffer, ansiString.Length);
                            charBuffer[ansiString.Length] = '\0';

							PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

                            if (kernelNotif) {

                                SET_INFO(*kernelNotif);

                                kernelNotif->pid = PsGetProcessId(targetProcess);
                                kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ansiString.Length + 1, 'msg');
								kernelNotif->bufSize = ansiString.Length + 1;

                                if (kernelNotif->msg) {

                                    RtlCopyMemory(kernelNotif->msg, charBuffer, ansiString.Length + 1);
                                    kernelNotif->isPath = TRUE;

                                    if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
                                        ExFreePool(kernelNotif->msg);
                                        ExFreePool(kernelNotif);
                                    }
                                }
                                else {
                                    ExFreePool(kernelNotif);
                                }
                            }
                           
                            RtlFreeAnsiString(&ansiString);

                            // Detect amsi.dll load and scan exports for bypass patches.
                            // We are still attached to the target process here.
                            if (ImageInfo->ImageBase != NULL && ImageInfo->ImageSize > 0) {
                                SIZE_T cbLen = SafeStringLength(charBuffer, charBufferSize - 1);
                                BOOLEAN isAmsiDll = FALSE;
                                for (SIZE_T k = 0; k + 8 <= cbLen; k++) {
                                    if (((charBuffer[k]   | 0x20) == 'a') &&
                                        ((charBuffer[k+1] | 0x20) == 'm') &&
                                        ((charBuffer[k+2] | 0x20) == 's') &&
                                        ((charBuffer[k+3] | 0x20) == 'i') &&
                                         (charBuffer[k+4]         == '.') &&
                                        ((charBuffer[k+5] | 0x20) == 'd') &&
                                        ((charBuffer[k+6] | 0x20) == 'l') &&
                                        ((charBuffer[k+7] | 0x20) == 'l')) {
                                        isAmsiDll = TRUE;
                                        break;
                                    }
                                }
                                if (isAmsiDll) {
                                    AmsiDetector::ScanAmsiBypassPatterns(
                                        ImageInfo->ImageBase,
                                        ImageInfo->ImageSize,
                                        ProcessId,
                                        PsGetProcessImageFileName(targetProcess),
                                        CallbackObjects::GetNotifQueue()
                                    );
                                }
                            }

                            ExFreePool(charBuffer);
                        }
                        else {
                            ExFreePool(charBuffer);
                        }
                    }
                
            }
            else {
                DbgPrint("[-] Failed to allocate memory for section data\n");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception in ImageLoadNotifyRoutine\n");
        }

        KeUnstackDetachProcess(&apcState);
        attached = FALSE;
    }
    __finally {
        if (attached) {
            KeUnstackDetachProcess(&apcState);
        }
        if (targetProcess) {
            ObDereferenceObject(targetProcess);
        }
    }
}

VOID ImageUtils::setImageNotificationCallback() {

	NTSTATUS status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsSetLoadImageNotifyRoutine failed\n");
    }
    else {
		DbgPrint("[+] PsSetLoadImageNotifyRoutine success\n");

    }

}

VOID ImageUtils::unsetImageNotificationCallback() {

	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsRemoveLoadImageNotifyRoutine failed\n");
    }
    else {
		DbgPrint("[+] PsRemoveLoadImageNotifyRoutine success\n");
    }

}