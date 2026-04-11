/*
  Deception.cpp — Adversary Deception Engine (kernel side)

  The fundamental principle: never let the adversary know they have been
  detected.  Instead, allow operations to "succeed" while returning data
  that is false in a controlled way.  The attacker chases credentials that
  do not exist, injects shellcode into a process that is not what they think,
  and dumps memory that contains nothing real — all while the EDR collects
  complete telemetry of their technique.

  Deception surfaces implemented here:

  1. Honeypot registry keys
     Created under HKLM\SECURITY\Policy\Secrets (LSA secrets area),
     HKLM\SAM, and HKLM\SYSTEM service password paths.  These keys contain
     plausible fake credential data.  No legitimate software reads LSA secrets
     at the raw registry level — any access is a high-confidence indicator of
     a credential-hunting tool (Mimikatz lsadump::secrets, secretsdump.py, etc.).

  2. Honeypot file access detection
     FsFilter's PreCreate callback routes through IsHoneypotFilePath().  When
     a decoy file (fake SAM backup, .env.credentials, credentials.xml) is
     opened, a Critical alert fires before the file handle is granted.

  3. LSASS memory buffer deception
     When NtReadVmHandler detects a cross-process read from lsass.exe and the
     caller's buffer is accessible, PatchLsassReadBuffer() walks the buffer
     looking for 16-byte sequences that have the entropy profile of an NTLM
     hash (non-null, non-printable, uniform-ish byte distribution) and replaces
     them with the canary hash.  The canary is the NTLM hash of the empty
     password — universally flagged by SIEMs and domain controllers as a
     known-bad credential if attempted in pass-the-hash.

  4. Process image name deception (NtQuerySystemInformation)
     The kernel-level hook patches SystemProcessInformation output to:
       a) Remove EDR process entries (attacker sees no defender running)
       b) Inject a single fake "svchost_vuln.exe" decoy entry that looks like
          an unprotected, injectable SYSTEM process — a honeypot for process
          injection attempts.
*/

#include "Deception.h"

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------
HANDLE          DeceptionEngine::g_HoneypotSecretHandle  = nullptr;
HANDLE          DeceptionEngine::g_HoneypotServiceHandle = nullptr;
KSPIN_LOCK      DeceptionEngine::g_Lock;
NotifQueue*     DeceptionEngine::g_NotifQueue            = nullptr;
UNICODE_STRING  DeceptionEngine::g_CanaryPaths[CANARY_MAX_FILES] = {};
ULONG           DeceptionEngine::g_CanaryCount                   = 0;

// ---------------------------------------------------------------------------
// Internal: create or open a registry key and set a value
// ---------------------------------------------------------------------------
NTSTATUS DeceptionEngine::CreateHoneypotRegistryKey(
    _In_ PCWSTR  absolutePath,
    _In_ PCWSTR  valueName,
    _In_ PVOID   valueData,
    _In_ ULONG   valueDataLen,
    _In_ ULONG   valueType,
    _Out_opt_ HANDLE* outHandle)
{
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, absolutePath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE hKey = nullptr;
    ULONG disposition = 0;
    NTSTATUS s = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, nullptr,
                              REG_OPTION_VOLATILE, &disposition);
    if (!NT_SUCCESS(s)) return s;

    if (valueName && valueData && valueDataLen) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, valueName);
        ZwSetValueKey(hKey, &valName, 0, valueType, valueData, valueDataLen);
    }

    if (outHandle) {
        *outHandle = hKey;
    } else {
        ZwClose(hKey);
    }
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Internal: emit a deception detection alert into the NotifQueue pipeline
// ---------------------------------------------------------------------------
VOID DeceptionEngine::EmitDeceptionAlert(
    _In_ const char* msg,
    _In_ const char* method,
    _In_ ULONG       pid)
{
    if (!g_NotifQueue) return;

    SIZE_T msgLen = strlen(msg) + 1;
    SIZE_T totalSize = sizeof(KERNEL_STRUCTURED_NOTIFICATION) + msgLen;

    PKERNEL_STRUCTURED_NOTIFICATION notif =
        (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            totalSize, 'dcpt');
    if (!notif) return;
    RtlZeroMemory(notif, totalSize);

    notif->pid = (HANDLE)(ULONG_PTR)pid;
    notif->method = 0;
    notif->method2 = 0;
    notif->method3 = 0;
    SET_CRITICAL(*notif);  // deception events are always Critical severity

    // Tag as a deception event (using NetworkCheck bit as generic "detection" bit
    // for deception category — maps cleanly to existing TUI rendering)
    notif->method3 |= 0x04;   // bit 2 = DeceptionCheck (see Structs.h)

    RtlStringCbCopyA(notif->procName, sizeof(notif->procName), method);
    RtlCopyMemory(notif->msg, msg, msgLen);

    if (!g_NotifQueue->Enqueue(notif)) ExFreePool(notif);
}

// ---------------------------------------------------------------------------
// Canary file deployment — create bait documents in user directories
// ---------------------------------------------------------------------------

// Create a single canary file at directoryPath\fileName with realistic content.
// The file is created with FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM to keep
// it out of casual Explorer views while still visible to ransomware enumeration
// (ransomware calls FindFirstFile with no attribute filter — they see everything).
NTSTATUS DeceptionEngine::CreateSingleCanary(
    _In_ PCWSTR directoryPath,
    _In_ PCWSTR fileName)
{
    if (g_CanaryCount >= CANARY_MAX_FILES) return STATUS_INSUFFICIENT_RESOURCES;

    // Build full path: directoryPath + "\" + fileName
    WCHAR fullPath[512];
    NTSTATUS s = RtlStringCbPrintfW(fullPath, sizeof(fullPath),
        L"%s\\%s", directoryPath, fileName);
    if (!NT_SUCCESS(s)) return s;

    UNICODE_STRING uniPath;
    RtlInitUnicodeString(&uniPath, fullPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uniPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = nullptr;

    s = ZwCreateFile(
        &hFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        nullptr,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY,
        FILE_SHARE_READ,
        FILE_OPEN_IF,          // create if not exists, open if already there
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr, 0);

    if (!NT_SUCCESS(s)) {
        // Directory may not exist — try creating it first
        // Build the directory path
        UNICODE_STRING dirUni;
        RtlInitUnicodeString(&dirUni, directoryPath);
        OBJECT_ATTRIBUTES dirOa;
        InitializeObjectAttributes(&dirOa, &dirUni,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE hDir = nullptr;
        IO_STATUS_BLOCK dirIosb;
        NTSTATUS dirSt = ZwCreateFile(
            &hDir,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &dirOa, &dirIosb, nullptr,
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            nullptr, 0);
        if (NT_SUCCESS(dirSt) && hDir) ZwClose(hDir);

        // Retry file creation
        s = ZwCreateFile(
            &hFile, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, nullptr,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY,
            FILE_SHARE_READ, FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr, 0);
        if (!NT_SUCCESS(s)) return s;
    }

    // Write realistic-looking content — a plausible document header followed by
    // padding.  The content doesn't need to be a valid OOXML/PDF — it just needs
    // to be non-zero bytes so ransomware doesn't skip it as an empty file.
    // We use a recognizable ASCII header that also helps us identify canaries
    // if we ever need to verify the file.
    UCHAR canaryContent[CANARY_FILE_SIZE];
    RtlFillMemory(canaryContent, sizeof(canaryContent), 0x20);  // spaces

    // Embed a canary signature at the start (not the file extension magic —
    // we want ransomware to treat this as a real document worth encrypting)
    static const char kCanaryHeader[] =
        "PERSONAL FINANCIAL RECORDS - CONFIDENTIAL\r\n"
        "Account: 4532-XXXX-XXXX-7891\r\n"
        "Tax ID: XXX-XX-4821\r\n"
        "This document contains sensitive information.\r\n"
        "\r\n"
        "NortonEDR-Canary-v1\r\n";  // our hidden tag at the end of the header

    RtlCopyMemory(canaryContent, kCanaryHeader,
        min(sizeof(kCanaryHeader) - 1, sizeof(canaryContent)));

    ZwWriteFile(hFile, nullptr, nullptr, nullptr, &iosb,
        canaryContent, sizeof(canaryContent), nullptr, nullptr);
    ZwClose(hFile);

    // Store the full NT path for runtime matching
    USHORT pathBytes = uniPath.Length;
    PWCH pathBuf = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, pathBytes + sizeof(WCHAR), 'cnry');
    if (pathBuf) {
        RtlCopyMemory(pathBuf, uniPath.Buffer, pathBytes);
        pathBuf[pathBytes / sizeof(WCHAR)] = L'\0';
        g_CanaryPaths[g_CanaryCount].Buffer        = pathBuf;
        g_CanaryPaths[g_CanaryCount].Length         = pathBytes;
        g_CanaryPaths[g_CanaryCount].MaximumLength  = pathBytes + sizeof(WCHAR);
        g_CanaryCount++;
        DbgPrint("[NortonEDR-Deception] Canary deployed: %wZ\n", &g_CanaryPaths[g_CanaryCount - 1]);
    }

    return STATUS_SUCCESS;
}

// Deploy canary files across user profile directories.
// We enumerate user profiles from HKLM\SOFTWARE\Microsoft\Windows NT\
// CurrentVersion\ProfileList and plant canaries in each user's Documents,
// Desktop, and deep subdirectories.
NTSTATUS DeceptionEngine::DeployCanaryFiles()
{
    g_CanaryCount = 0;

    // Open the ProfileList key to enumerate user profile directories
    UNICODE_STRING profileListPath;
    RtlInitUnicodeString(&profileListPath,
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &profileListPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE hProfileList = nullptr;
    NTSTATUS s = ZwOpenKey(&hProfileList, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[NortonEDR-Deception] Cannot open ProfileList: 0x%x\n", s);
        return s;
    }

    // Enumerate subkeys (each is a user SID)
    ULONG index = 0;
    UCHAR keyInfoBuf[512];
    ULONG resultLen = 0;

    while (NT_SUCCESS(ZwEnumerateKey(hProfileList, index++,
        KeyBasicInformation, keyInfoBuf, sizeof(keyInfoBuf), &resultLen)))
    {
        KEY_BASIC_INFORMATION* keyInfo = (KEY_BASIC_INFORMATION*)keyInfoBuf;

        // Skip short SIDs (built-in accounts like S-1-5-18, S-1-5-19, S-1-5-20)
        if (keyInfo->NameLength < 20 * sizeof(WCHAR)) continue;

        // Open this profile subkey to read ProfileImagePath
        UNICODE_STRING subKeyName;
        subKeyName.Buffer        = keyInfo->Name;
        subKeyName.Length        = (USHORT)keyInfo->NameLength;
        subKeyName.MaximumLength = (USHORT)keyInfo->NameLength;

        OBJECT_ATTRIBUTES subOa;
        InitializeObjectAttributes(&subOa, &subKeyName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hProfileList, nullptr);

        HANDLE hProfile = nullptr;
        if (!NT_SUCCESS(ZwOpenKey(&hProfile, KEY_READ, &subOa))) continue;

        // Read ProfileImagePath value (e.g., "C:\Users\JohnDoe")
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, L"ProfileImagePath");

        UCHAR valBuf[600];
        ULONG valResultLen = 0;
        NTSTATUS valSt = ZwQueryValueKey(hProfile, &valName,
            KeyValuePartialInformation, valBuf, sizeof(valBuf), &valResultLen);
        ZwClose(hProfile);

        if (!NT_SUCCESS(valSt)) continue;

        KEY_VALUE_PARTIAL_INFORMATION* valInfo = (KEY_VALUE_PARTIAL_INFORMATION*)valBuf;
        if (valInfo->Type != REG_EXPAND_SZ && valInfo->Type != REG_SZ) continue;
        if (valInfo->DataLength < 10) continue;

        // Convert the profile path to an NT path (prefix with \??\)
        WCHAR profilePath[260];
        ULONG profileChars = valInfo->DataLength / sizeof(WCHAR);
        // Remove trailing null if present
        if (profileChars > 0 && ((WCHAR*)valInfo->Data)[profileChars - 1] == L'\0')
            profileChars--;

        s = RtlStringCbPrintfW(profilePath, sizeof(profilePath),
            L"\\??\\%.*s", profileChars, (WCHAR*)valInfo->Data);
        if (!NT_SUCCESS(s)) continue;

        // Plant canaries in each subdirectory for each filename
        for (ULONG di = 0; di < ARRAYSIZE(g_CanarySubDirs); di++) {
            WCHAR targetDir[400];
            s = RtlStringCbPrintfW(targetDir, sizeof(targetDir),
                L"%s%s", profilePath, g_CanarySubDirs[di]);
            if (!NT_SUCCESS(s)) continue;

            for (ULONG fi = 0; fi < CANARY_NAME_COUNT; fi++) {
                if (g_CanaryCount >= CANARY_MAX_FILES) goto done;
                CreateSingleCanary(targetDir, g_CanaryFileNames[fi]);
            }
        }
    }

done:
    ZwClose(hProfileList);
    DbgPrint("[NortonEDR-Deception] Deployed %lu canary files across user profiles\n", g_CanaryCount);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Init — create honeypot registry keys with plausible fake credential data
// ---------------------------------------------------------------------------
NTSTATUS DeceptionEngine::Init(_In_ NotifQueue* queue)
{
    KeInitializeSpinLock(&g_Lock);
    g_NotifQueue = queue;

    // -----------------------------------------------------------------
    // Honeypot 1: LSA secret that looks like a stored service credential.
    // Mimikatz lsadump::secrets and secretsdump.py parse these.
    // The "secret" value contains our canary NTLM hash embedded in a
    // plausible binary blob (LSA_SECRET_OBJECT structure prefix + hash).
    // -----------------------------------------------------------------
    UCHAR lsaSecretBlob[48] = {};
    // Fake LSA secret header (version=1, encrypted=0 in our simplified blob)
    lsaSecretBlob[0] = 0x01;  // version
    lsaSecretBlob[1] = 0x00;
    lsaSecretBlob[2] = 0x00;
    lsaSecretBlob[3] = 0x00;
    // Embed canary NTLM hash at offset 8 (where the secret data typically starts)
    RtlCopyMemory(&lsaSecretBlob[8], g_CanaryNtlmHash, 16);
    // Embed a fake plaintext password hint as UTF-16 at offset 24
    const WCHAR* fakePass = DECOY_PASSWORD_HINT;
    ULONG fakePassBytes = (ULONG)(wcslen(fakePass) * sizeof(WCHAR));
    if (fakePassBytes <= 24) {
        RtlCopyMemory(&lsaSecretBlob[24], fakePass, fakePassBytes);
    }

    NTSTATUS s = CreateHoneypotRegistryKey(
        HONEYPOT_LSA_SECRET_KEY,
        L"$MACHINE.ACC",
        lsaSecretBlob, sizeof(lsaSecretBlob),
        REG_BINARY,
        &g_HoneypotSecretHandle);

    if (!NT_SUCCESS(s)) {
        DbgPrint("[NortonEDR-Deception] LSA secret honeypot creation failed: 0x%x "
                 "(SECURITY hive may require SYSTEM context)\n", s);
        // Non-fatal — honeypot 2 and 3 may still succeed
    } else {
        DbgPrint("[NortonEDR-Deception] LSA secret honeypot created\n");
    }

    // -----------------------------------------------------------------
    // Honeypot 2: Fake service password in HKLM\SYSTEM\...Services\...
    // Tools like Mimikatz lsadump::lsa /patch and impacket read these.
    // -----------------------------------------------------------------
    WCHAR fakeServicePass[] = DECOY_PASSWORD_HINT;
    s = CreateHoneypotRegistryKey(
        HONEYPOT_SERVICE_KEY,
        L"ServicePassword",
        fakeServicePass,
        (ULONG)(wcslen(fakeServicePass) + 1) * sizeof(WCHAR),
        REG_SZ,
        &g_HoneypotServiceHandle);

    if (NT_SUCCESS(s)) {
        DbgPrint("[NortonEDR-Deception] Service password honeypot created\n");
    }

    // -----------------------------------------------------------------
    // Honeypot 3: SAM-like user entry with canary NT hash.
    // SAM hash format: F value = 40-byte blob with hash at offset 0x18.
    // -----------------------------------------------------------------
    UCHAR samFBlob[64] = {};
    samFBlob[0] = 0x03;   // SAM revision
    RtlCopyMemory(&samFBlob[0x18], g_CanaryNtlmHash, 16);
    CreateHoneypotRegistryKey(
        HONEYPOT_SAM_KEY,
        L"F",
        samFBlob, sizeof(samFBlob),
        REG_BINARY,
        nullptr);

    // -----------------------------------------------------------------
    // Canary files: anti-ransomware tripwires deployed in user directories
    // -----------------------------------------------------------------
    DeployCanaryFiles();

    DbgPrint("[NortonEDR-Deception] Deception engine initialized — "
             "honeypots: LSA secret, service password, SAM user, file paths, "
             "%lu canary files\n", g_CanaryCount);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Cleanup — close honeypot key handles (keys themselves are volatile and
// disappear at reboot; we also delete them explicitly on unload)
// ---------------------------------------------------------------------------
VOID DeceptionEngine::Cleanup()
{
    if (g_HoneypotSecretHandle) {
        ZwDeleteKey(g_HoneypotSecretHandle);
        ZwClose(g_HoneypotSecretHandle);
        g_HoneypotSecretHandle = nullptr;
    }
    if (g_HoneypotServiceHandle) {
        ZwDeleteKey(g_HoneypotServiceHandle);
        ZwClose(g_HoneypotServiceHandle);
        g_HoneypotServiceHandle = nullptr;
    }
    // Clean up canary file path tracking (files are left on disk intentionally —
    // removing them on unload would create a window where ransomware could run
    // undetected; they are tiny and hidden, so leaving them is harmless)
    for (ULONG i = 0; i < g_CanaryCount; i++) {
        if (g_CanaryPaths[i].Buffer) {
            ExFreePool(g_CanaryPaths[i].Buffer);
            g_CanaryPaths[i].Buffer = nullptr;
        }
    }
    g_CanaryCount = 0;

    g_NotifQueue = nullptr;
    DbgPrint("[NortonEDR-Deception] Deception engine cleaned up\n");
}

// ---------------------------------------------------------------------------
// IsHoneypotRegistryAccess — called from RegOpNotifyCallback
// ---------------------------------------------------------------------------
BOOLEAN DeceptionEngine::IsHoneypotRegistryAccess(_In_ PCUNICODE_STRING keyPath)
{
    if (!keyPath || !keyPath->Buffer) return FALSE;

    // Check for any of our honeypot key paths as a substring
    static const WCHAR* honeypotPaths[] = {
        L"_NortonEDRHoneypot",
        L"FakeSvcPassword",
        L"HoneypotUser",
    };

    for (int i = 0; i < 3; i++) {
        UNICODE_STRING needle;
        RtlInitUnicodeString(&needle, honeypotPaths[i]);
        if (RtlFindUnicodePrefix(nullptr, keyPath, 0) ||  // fast path
            // fallback: substring search
            (keyPath->Length >= needle.Length &&
             RtlCompareUnicodeString(keyPath, &needle, TRUE) == 0)) {
            return TRUE;
        }
        // Manual substring check (RtlFindUnicodePrefix is for prefix trees)
        ULONG hLen = keyPath->Length / sizeof(WCHAR);
        ULONG nLen = needle.Length / sizeof(WCHAR);
        for (ULONG j = 0; j + nLen <= hLen; j++) {
            if (RtlCompareMemory(
                    keyPath->Buffer + j,
                    needle.Buffer,
                    needle.Length) == needle.Length) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// HandleHoneypotRegistryAccess — emit Critical alert, let access proceed
// ---------------------------------------------------------------------------
VOID DeceptionEngine::HandleHoneypotRegistryAccess(
    _In_ PCUNICODE_STRING keyPath,
    _In_ HANDLE           callerPid,
    _In_ BOOLEAN          isWrite)
{
    UNREFERENCED_PARAMETER(keyPath);

    char msg[256];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "HONEYPOT registry %s: PID=%llu accessed fake credential key — "
        "credential hunting confirmed; canary hash will be returned",
        isWrite ? "WRITE" : "READ",
        (ULONG64)(ULONG_PTR)callerPid);

    DbgPrint("[NortonEDR-Deception] %s\n", msg);
    EmitDeceptionAlert(msg, "Method: Deception (HoneypotRegistry)", (ULONG)(ULONG_PTR)callerPid);

    // Access is ALLOWED — caller proceeds with the fake data.
    // We do not modify REG_CALLBACK_CLASS to block; the return value of
    // RegOpNotifyCallback is STATUS_SUCCESS, letting the access complete.
}

// ---------------------------------------------------------------------------
// IsHoneypotFilePath — called from FsFilter::PreCreate
// ---------------------------------------------------------------------------
BOOLEAN DeceptionEngine::IsHoneypotFilePath(_In_ PCUNICODE_STRING filePath)
{
    if (!filePath || !filePath->Buffer) return FALSE;

    static const WCHAR* honeypotFiles[] = {
        HONEYPOT_SAM_PATH,    // L"\\sam_backup.bak"
        HONEYPOT_ENV_PATH,    // L"\\.env.credentials"
        HONEYPOT_CRED_PATH,   // L"\\credentials.xml"
        L"\\ntds_backup.dit",
        L"\\lsass.dmp",       // already monitored by FsFilter cred check, but add deception alert
    };

    for (int i = 0; i < 5; i++) {
        UNICODE_STRING needle;
        RtlInitUnicodeString(&needle, honeypotFiles[i]);

        ULONG hLen = filePath->Length / sizeof(WCHAR);
        ULONG nLen = needle.Length / sizeof(WCHAR);
        if (nLen == 0) continue;

        for (ULONG j = 0; j + nLen <= hLen; j++) {
            if (_wcsnicmp(filePath->Buffer + j, needle.Buffer, nLen) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// HandleHoneypotFileAccess — emit Critical alert when a decoy file is opened
// ---------------------------------------------------------------------------
VOID DeceptionEngine::HandleHoneypotFileAccess(
    _In_ PCUNICODE_STRING filePath,
    _In_ HANDLE           callerPid)
{
    ANSI_STRING ansiPath = {};
    RtlUnicodeStringToAnsiString(&ansiPath, filePath, TRUE);

    char msg[256];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "HONEYPOT file opened: '%s' by PID=%llu — "
        "attacker is targeting credential backup files",
        ansiPath.Buffer ? ansiPath.Buffer : "(unknown)",
        (ULONG64)(ULONG_PTR)callerPid);

    if (ansiPath.Buffer) RtlFreeAnsiString(&ansiPath);

    DbgPrint("[NortonEDR-Deception] %s\n", msg);
    EmitDeceptionAlert(msg, "Method: Deception (HoneypotFile)", (ULONG)(ULONG_PTR)callerPid);

    // File open is ALLOWED — attacker sees the file and reads it.
    // For full deception, a post-operation callback could replace the content
    // with a decoy (fake SAM/NTDS) — left as a production extension point.
}

// ---------------------------------------------------------------------------
// IsCanaryFile — called from FsFilter PreCreate / PreSetInformation
//
// Checks if the normalized file path matches any deployed canary file.
// Uses case-insensitive suffix matching against the stored canary paths.
// ---------------------------------------------------------------------------
BOOLEAN DeceptionEngine::IsCanaryFile(_In_ PCUNICODE_STRING filePath)
{
    if (!filePath || !filePath->Buffer || g_CanaryCount == 0) return FALSE;

    for (ULONG i = 0; i < g_CanaryCount; i++) {
        if (g_CanaryPaths[i].Buffer == nullptr) continue;

        // Case-insensitive comparison — canary paths are full NT paths,
        // filePath from FltGetFileNameInformation is also a full NT path.
        // Use suffix match: filePath may have volume device prefix while
        // canary has \??\ prefix, so compare just the filename portions.
        // However, both should normalize similarly. Try exact match first.
        if (RtlEqualUnicodeString(filePath, &g_CanaryPaths[i], TRUE))
            return TRUE;

        // Fallback: check if filePath ends with the canary filename portion.
        // Extract filename from canary path (after last backslash).
        USHORT canaryChars = g_CanaryPaths[i].Length / sizeof(WCHAR);
        USHORT nameStart = canaryChars;
        for (USHORT j = canaryChars; j > 0; j--) {
            if (g_CanaryPaths[i].Buffer[j - 1] == L'\\') {
                nameStart = j;
                break;
            }
        }
        USHORT canaryNameLen = canaryChars - nameStart;
        if (canaryNameLen == 0) continue;

        USHORT fileChars = filePath->Length / sizeof(WCHAR);
        if (fileChars < canaryNameLen) continue;

        // Compare the filename portion (case-insensitive)
        USHORT fileNameStart = fileChars;
        for (USHORT j = fileChars; j > 0; j--) {
            if (filePath->Buffer[j - 1] == L'\\') {
                fileNameStart = j;
                break;
            }
        }
        USHORT fileNameLen = fileChars - fileNameStart;
        if (fileNameLen != canaryNameLen) continue;

        BOOLEAN match = TRUE;
        for (USHORT k = 0; k < canaryNameLen; k++) {
            WCHAR a = filePath->Buffer[fileNameStart + k];
            WCHAR b = g_CanaryPaths[i].Buffer[nameStart + k];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { match = FALSE; break; }
        }

        // Also verify the parent directory contains one of our canary subdirs
        // to avoid false positives from identically named files elsewhere
        if (match) {
            for (ULONG di = 0; di < ARRAYSIZE(g_CanarySubDirs); di++) {
                UNICODE_STRING subDir;
                RtlInitUnicodeString(&subDir, g_CanarySubDirs[di]);
                ULONG sdLen = subDir.Length / sizeof(WCHAR);
                if (fileNameStart >= sdLen) {
                    BOOLEAN dirMatch = TRUE;
                    for (ULONG ci = 0; ci < sdLen; ci++) {
                        WCHAR fa = filePath->Buffer[fileNameStart - sdLen + ci];
                        WCHAR fb = subDir.Buffer[ci];
                        if (fa >= L'A' && fa <= L'Z') fa += 32;
                        if (fb >= L'A' && fb <= L'Z') fb += 32;
                        if (fa != fb) { dirMatch = FALSE; break; }
                    }
                    if (dirMatch) return TRUE;
                }
            }
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// HandleCanaryFileAccess — CRITICAL ransomware alert on canary tripwire
//
// This fires on the very first file the ransomware touches — no need for
// burst counting, rename-extension heuristics, or behavioral thresholds.
// Any write/rename/delete of a canary is a confirmed ransomware indicator.
// ---------------------------------------------------------------------------
VOID DeceptionEngine::HandleCanaryFileAccess(
    _In_ PCUNICODE_STRING filePath,
    _In_ HANDLE           callerPid,
    _In_ const char*      operation)
{
    ANSI_STRING ansiPath = {};
    RtlUnicodeStringToAnsiString(&ansiPath, filePath, TRUE);

    char msg[320];
    RtlStringCbPrintfA(msg, sizeof(msg),
        "RANSOMWARE CANARY TRIPWIRE: %s on canary file '%s' by PID=%llu — "
        "CONFIRMED RANSOMWARE ACTIVITY — immediate response required",
        operation,
        ansiPath.Buffer ? ansiPath.Buffer : "(unknown)",
        (ULONG64)(ULONG_PTR)callerPid);

    if (ansiPath.Buffer) RtlFreeAnsiString(&ansiPath);

    DbgPrint("[NortonEDR-Deception] *** %s ***\n", msg);
    EmitDeceptionAlert(msg, "Method: Deception (RansomwareCanary)", (ULONG)(ULONG_PTR)callerPid);
}

// ---------------------------------------------------------------------------
// PatchLsassReadBuffer — corrupt candiates NTLM hashes in-place
//
// Called from NtReadVmHandler immediately after the syscall succeeds when
// the target process is lsass.exe and the buffer is a kernel-mode copy.
//
// Algorithm:
//   Walk every 8-byte-aligned 16-byte window in the output buffer.
//   A "likely NTLM hash" window has:
//     - At least 1 non-zero byte (not a padding region)
//     - At least 6 bytes in the 0x80–0xFF range (non-ASCII, high entropy)
//     - No more than 4 consecutive identical bytes (rules out patterns)
//   Windows that match are replaced with the canary NTLM hash.
//   The canary (empty-string NTLM) is a sentinel that:
//     - Fails authentication on any hardened domain
//     - Triggers SIEM alerts if used in pass-the-hash
//     - Looks indistinguishable from a real hash to offline tooling
// ---------------------------------------------------------------------------
VOID DeceptionEngine::PatchLsassReadBuffer(
    _Inout_ PVOID  buffer,
    _In_    SIZE_T size)
{
    if (!buffer || size < 16) return;

    BYTE* buf = (BYTE*)buffer;
    ULONG patchCount = 0;

    for (SIZE_T offset = 0; offset + 16 <= size; offset += 8) {
        BYTE* candidate = buf + offset;

        ULONG nonZero    = 0;
        ULONG highByte   = 0;   // 0x80–0xFF range
        ULONG consecutive = 0;  // max run of same byte
        ULONG maxRun     = 0;
        BYTE  lastByte   = ~candidate[0];

        for (int i = 0; i < 16; i++) {
            if (candidate[i] != 0) nonZero++;
            if (candidate[i] >= 0x80) highByte++;
            if (candidate[i] == lastByte) {
                consecutive++;
                if (consecutive > maxRun) maxRun = consecutive;
            } else {
                consecutive = 1;
                lastByte = candidate[i];
            }
        }

        // Heuristic: looks like an NTLM hash
        if (nonZero >= 8 && highByte >= 5 && maxRun <= 4) {
            RtlCopyMemory(candidate, g_CanaryNtlmHash, 16);
            patchCount++;
            offset += 8;  // skip ahead — hashes are typically non-overlapping
        }
    }

    if (patchCount > 0) {
        DbgPrint("[NortonEDR-Deception] Patched %lu potential NTLM hash(es) in "
                 "LSASS read buffer with canary\n", patchCount);
    }
}
