#pragma once
#include "Globals.h"

// ---------------------------------------------------------------------------
// Adversary Deception Engine
//
// Philosophy: instead of blocking malicious operations (which reveals that
// defenses are active), allow them to appear to succeed while returning
// falsified data.  The attacker wastes time debugging their tooling and
// pursuing credentials that do not work, while the EDR collects telemetry.
//
// Deception layers implemented here (kernel side):
//   1. Honeypot registry keys — fake LSA secrets / service credentials.
//      Any access is a high-confidence indicator of credential hunting.
//   2. Honeypot files — decoy SAM / NTDS.dit / .env files deployed in
//      monitored paths; any read triggers a Critical alert.
//   3. Fake process information — NtQuerySystemInformation output patched
//      to hide EDR processes and inject a decoy "vulnerable" process entry.
//   4. LSASS read deception — coordinated with HookDll's ReadProcessMemory
//      hook (user-mode) to return canary NTLM hashes that alert if used.
//
// The hypervisor layer (EPT MTF shadow pages) is in HvDeception.cpp.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Canary NTLM hash — returned to credential-dumping tools instead of real
// hashes.  This is the NTLM hash of the empty string, a universally known
// sentinel that triggers alerts in every SIEM and authentication system if
// used in a pass-the-hash or Kerberos attack.
// NT hash: 31d6cfe0d16ae931b73c59d7e0c089c0
// ---------------------------------------------------------------------------
static const UCHAR g_CanaryNtlmHash[16] = {
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
};

// Fake account name embedded in honeypot credential data
#define DECOY_ACCOUNT_NAME  L"svc_backup_admin"
#define DECOY_DOMAIN_NAME   L"CORP"
#define DECOY_PASSWORD_HINT L"BackupAdmin2024!"   // appears as WDigest plaintext

// Honeypot registry paths (under HKLM\SECURITY — inaccessible to user mode,
// so only kernel or SYSTEM-level attackers with SeBackupPrivilege will touch them)
#define HONEYPOT_LSA_SECRET_KEY  L"\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\_NortonEDRHoneypot"
#define HONEYPOT_SERVICE_KEY     L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\FakeSvcPassword\\Parameters"
#define HONEYPOT_SAM_KEY         L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\HoneypotUser"

// Honeypot file paths — FsFilter PreCreate will alert on any open of these
#define HONEYPOT_SAM_PATH   L"\\sam_backup.bak"        // in %SystemRoot%
#define HONEYPOT_ENV_PATH   L"\\.env.credentials"       // in root paths
#define HONEYPOT_CRED_PATH  L"\\credentials.xml"        // in common drop paths

// ---------------------------------------------------------------------------
// Deception Engine
// ---------------------------------------------------------------------------
class DeceptionEngine {

    // Tracks registry key handles we created for honeypots (for cleanup)
    static HANDLE g_HoneypotSecretHandle;
    static HANDLE g_HoneypotServiceHandle;

    // Spinlock protecting the deception state
    static KSPIN_LOCK g_Lock;

    // NotifQueue for emitting deception events into the detection pipeline
    static NotifQueue* g_NotifQueue;

    // Internal helpers
    static NTSTATUS CreateHoneypotRegistryKey(
        _In_ PCWSTR absolutePath,
        _In_ PCWSTR valueName,
        _In_ PVOID  valueData,
        _In_ ULONG  valueDataLen,
        _In_ ULONG  valueType,
        _Out_opt_ HANDLE* outHandle);

    static VOID EmitDeceptionAlert(
        _In_ const char* msg,
        _In_ const char* method,
        _In_ ULONG       pid);

public:

    // Called from DriverEntry after the NotifQueue is initialized.
    static NTSTATUS Init(_In_ NotifQueue* queue);

    // Called from UnloadDriver before queue teardown.
    static VOID Cleanup();

    // Called from RegistryUtils::RegOpNotifyCallback — returns TRUE if the
    // key/value being accessed is a honeypot (caller should emit the alert
    // and still let the access succeed so the attacker is not tipped off).
    static BOOLEAN IsHoneypotRegistryAccess(_In_ PCUNICODE_STRING keyPath);

    // Called from FsFilter::PreCreate — returns TRUE if the file path contains
    // a honeypot indicator.
    static BOOLEAN IsHoneypotFilePath(_In_ PCUNICODE_STRING filePath);

    // Called from FsFilter::PreCreate when a honeypot file is accessed.
    static VOID HandleHoneypotFileAccess(
        _In_ PCUNICODE_STRING filePath,
        _In_ HANDLE           callerPid);

    // Called from RegistryUtils::RegOpNotifyCallback for honeypot key access.
    static VOID HandleHoneypotRegistryAccess(
        _In_ PCUNICODE_STRING keyPath,
        _In_ HANDLE           callerPid,
        _In_ BOOLEAN          isWrite);

    // Patch a user-mode buffer that was just read from an LSASS handle:
    // scan for NTLM-hash-like 16-byte sequences and replace them with canary.
    // Safe to call from NtReadVmHandler (kernel mode, buffer is kernel copy).
    static VOID PatchLsassReadBuffer(
        _Inout_ PVOID  buffer,
        _In_    SIZE_T size);
};
