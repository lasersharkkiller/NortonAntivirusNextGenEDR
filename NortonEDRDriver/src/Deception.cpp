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
HANDLE       DeceptionEngine::g_HoneypotSecretHandle  = nullptr;
HANDLE       DeceptionEngine::g_HoneypotServiceHandle = nullptr;
KSPIN_LOCK   DeceptionEngine::g_Lock;
NotifQueue*  DeceptionEngine::g_NotifQueue            = nullptr;

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

    DbgPrint("[NortonEDR-Deception] Deception engine initialized — "
             "honeypots: LSA secret, service password, SAM user, file paths\n");

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
