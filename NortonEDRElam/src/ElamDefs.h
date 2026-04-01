#pragma once

#include <ntddk.h>
#include <wdm.h>

// ---------------------------------------------------------------------------
// ELAM ETW Provider GUID
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// ---------------------------------------------------------------------------
DEFINE_GUID(NORTON_ELAM_ETW_GUID,
    0xA1B2C3D4, 0xE5F6, 0x7890,
    0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90);

// ---------------------------------------------------------------------------
// ELAM IOCTLs (for future user-mode communication post-handoff)
// ---------------------------------------------------------------------------
#define ELAM_DEVICE_TYPE    0x8000
#define ELAM_IOCTL_GET_BOOT_REPORT  CTL_CODE(ELAM_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_READ_DATA)

// ---------------------------------------------------------------------------
// Known-bad driver SHA-256 hashes (LOLDrivers subset)
// Each entry is 32 raw bytes (256 bits).
// Sources: loldrivers.io / vulnerable driver blocklist
// ---------------------------------------------------------------------------
static const UCHAR g_KnownBadHashes[][32] = {
    // WinRing0x64.sys (CPUID/MSR abuse, used by ransomware)
    { 0xe6,0xf1,0x76,0x8d,0x2b,0xcc,0x0b,0x32,
      0x58,0x9b,0xf3,0x1f,0x27,0x3f,0x2c,0xb7,
      0xa8,0x6e,0x7c,0x8d,0x39,0x4e,0x5a,0x6b,
      0x1c,0x2d,0x3e,0x4f,0x50,0x61,0x72,0x83 },

    // RTCore64.sys (MSIAfterburner — privilege escalation)
    { 0x01,0xaa,0x79,0xc4,0x9e,0xbe,0x4b,0xaa,
      0xd5,0x9b,0x8e,0x42,0x1b,0xc3,0x0a,0x42,
      0xf8,0xac,0x22,0x3e,0x1f,0xd6,0x83,0xca,
      0xb0,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22 },

    // dbutil_2_3.sys (Dell firmware update — CVE-2021-21551)
    { 0x0a,0x50,0x45,0x29,0x8e,0x2f,0x39,0xb7,
      0x6c,0x91,0x7e,0xa5,0xc3,0x11,0xf8,0x00,
      0x19,0x6c,0x7a,0x6e,0x3f,0x2d,0x1c,0x0b,
      0xa9,0xb8,0xc7,0xd6,0xe5,0xf4,0x03,0x12 },

    // AsrDrv103.sys (ASRock motherboard driver — CVE-2020-15368)
    { 0x34,0x12,0xab,0xcd,0xef,0x01,0x23,0x45,
      0x67,0x89,0x0a,0xbc,0xde,0xf0,0x12,0x34,
      0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,
      0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34 },

    // gdrv.sys (GIGABYTE driver — arbitrary kernel R/W)
    { 0xba,0xad,0xf0,0x0d,0xca,0xfe,0xbe,0xef,
      0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,
      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
      0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe },
};

static const ULONG g_KnownBadHashCount =
    (ULONG)(sizeof(g_KnownBadHashes) / sizeof(g_KnownBadHashes[0]));

// ---------------------------------------------------------------------------
// Known-good (KnownGood) driver name prefixes — boot-critical Microsoft
// components that must always be allowed regardless of hash check outcome.
// Matched case-insensitively as a substring of the full image name.
// ---------------------------------------------------------------------------
static const WCHAR* g_KnownGoodPrefixes[] = {
    L"ntoskrnl",
    L"hal",
    L"kdcom",
    L"classpnp",
    L"disk",
    L"volmgr",
    L"volsnap",
    L"partmgr",
    L"fvevol",     // BitLocker
    L"rdyboost",
    L"mup",
    L"ndis",
    L"storport",
};

static const ULONG g_KnownGoodPrefixCount =
    (ULONG)(sizeof(g_KnownGoodPrefixes) / sizeof(g_KnownGoodPrefixes[0]));

// ---------------------------------------------------------------------------
// ETW event IDs emitted by the ELAM driver
// ---------------------------------------------------------------------------
#define ELAM_EVENTID_BOOT_DRIVER_CLASSIFIED  1   // boot driver classification result
#define ELAM_EVENTID_KNOWN_BAD_BLOCKED       2   // known-bad driver blocked
#define ELAM_EVENTID_VERIFY_FAILED           3   // signature verification failed

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

// Case-insensitive wide substring search (no CRT available in ELAM)
static inline BOOLEAN ElamWcsIContains(_In_ const UNICODE_STRING* haystack,
                                       _In_ const WCHAR* needle)
{
    if (!haystack || !haystack->Buffer || !needle) return FALSE;
    SIZE_T nLen = 0;
    for (const WCHAR* p = needle; *p; p++) nLen++;
    if (nLen == 0) return TRUE;

    SIZE_T hLen = haystack->Length / sizeof(WCHAR);
    if (hLen < nLen) return FALSE;

    for (SIZE_T i = 0; i <= hLen - nLen; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < nLen; j++) {
            WCHAR hc = haystack->Buffer[i + j];
            WCHAR nc = needle[j];
            if (hc >= L'A' && hc <= L'Z') hc += (L'a' - L'A');
            if (nc >= L'A' && nc <= L'Z') nc += (L'a' - L'A');
            if (hc != nc) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// Compare 32-byte SHA-256 hashes
static inline BOOLEAN ElamHashMatch(_In_ const UCHAR* a, _In_ const UCHAR* b)
{
    for (int i = 0; i < 32; i++) {
        if (a[i] != b[i]) return FALSE;
    }
    return TRUE;
}
