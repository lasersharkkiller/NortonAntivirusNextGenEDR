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

                                // Detect unmanaged PowerShell hosting:
                                // System.Management.Automation.dll loading into any process
                                // that is not a known legitimate PowerShell host is a strong
                                // indicator of the "spawn email client + host PS runtime" evasion
                                // technique (and reflective PS injection in general).
                                BOOLEAN isSMADll = FALSE;
                                for (SIZE_T k = 0; k + 28 <= cbLen; k++) {
                                    if (((charBuffer[k]    | 0x20) == 's') &&
                                        ((charBuffer[k+1]  | 0x20) == 'y') &&
                                        ((charBuffer[k+2]  | 0x20) == 's') &&
                                        ((charBuffer[k+3]  | 0x20) == 't') &&
                                        ((charBuffer[k+4]  | 0x20) == 'e') &&
                                        ((charBuffer[k+5]  | 0x20) == 'm') &&
                                         (charBuffer[k+6]           == '.') &&
                                        ((charBuffer[k+7]  | 0x20) == 'm') &&
                                        ((charBuffer[k+8]  | 0x20) == 'a') &&
                                        ((charBuffer[k+9]  | 0x20) == 'n') &&
                                        ((charBuffer[k+10] | 0x20) == 'a') &&
                                        ((charBuffer[k+11] | 0x20) == 'g') &&
                                        ((charBuffer[k+12] | 0x20) == 'e') &&
                                        ((charBuffer[k+13] | 0x20) == 'm') &&
                                        ((charBuffer[k+14] | 0x20) == 'e') &&
                                        ((charBuffer[k+15] | 0x20) == 'n') &&
                                        ((charBuffer[k+16] | 0x20) == 't') &&
                                         (charBuffer[k+17]          == '.') &&
                                        ((charBuffer[k+18] | 0x20) == 'a') &&
                                        ((charBuffer[k+19] | 0x20) == 'u') &&
                                        ((charBuffer[k+20] | 0x20) == 't') &&
                                        ((charBuffer[k+21] | 0x20) == 'o') &&
                                        ((charBuffer[k+22] | 0x20) == 'm') &&
                                        ((charBuffer[k+23] | 0x20) == 'a') &&
                                        ((charBuffer[k+24] | 0x20) == 't') &&
                                        ((charBuffer[k+25] | 0x20) == 'i') &&
                                        ((charBuffer[k+26] | 0x20) == 'o') &&
                                        ((charBuffer[k+27] | 0x20) == 'n')) {
                                        isSMADll = TRUE;
                                        break;
                                    }
                                }

                                if (isSMADll) {
                                    char* hostName = PsGetProcessImageFileName(targetProcess);
                                    if (hostName != NULL &&
                                        strcmp(hostName, "powershell.exe")   != 0 &&
                                        strcmp(hostName, "pwsh.exe")         != 0 &&
                                        strcmp(hostName, "wsmprovhost.exe")  != 0 &&
                                        strcmp(hostName, "powershell_ise")   != 0) {

                                        const char* smaMsg = "Unmanaged PowerShell hosting: System.Management.Automation.dll in unexpected process";
                                        SIZE_T smaMsgLen = 84;

                                        PKERNEL_STRUCTURED_NOTIFICATION smaNotif =
                                            (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

                                        if (smaNotif) {
                                            SET_CRITICAL(*smaNotif);
                                            SET_IMAGE_LOAD_PATH_CHECK(*smaNotif);
                                            SET_CALLING_PROC_PID_CHECK(*smaNotif);

                                            smaNotif->pid    = PsGetProcessId(targetProcess);
                                            smaNotif->isPath = FALSE;

                                            RtlStringCbCopyA(smaNotif->procName,
                                                             sizeof(smaNotif->procName),
                                                             hostName);

                                            char* msgBuf = (char*)ExAllocatePool2(
                                                POOL_FLAG_NON_PAGED, smaMsgLen + 1, 'msg');

                                            if (msgBuf) {
                                                RtlCopyMemory(msgBuf, smaMsg, smaMsgLen);
                                                msgBuf[smaMsgLen] = '\0';
                                                smaNotif->msg     = msgBuf;
                                                smaNotif->bufSize = (ULONG)(smaMsgLen + 1);

                                                if (!CallbackObjects::GetNotifQueue()->Enqueue(smaNotif)) {
                                                    ExFreePool(smaNotif->msg);
                                                    ExFreePool(smaNotif);
                                                }
                                            } else {
                                                ExFreePool(smaNotif);
                                            }
                                        }
                                    }
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

        // Queue HookDll APC while still attached — allocates path buffer in target process.
        DllInjector::TryInject(targetProcess, FullImageName);

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