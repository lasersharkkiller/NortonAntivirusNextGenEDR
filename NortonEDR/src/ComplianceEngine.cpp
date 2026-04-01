/*
  ComplianceEngine.cpp — evaluate system configuration against six compliance
  standards and optionally apply registry-level hardening.

  Standards supported:
    NIST SP 800-53 Rev 5   — federal information systems baseline
    NIST SP 800-171 Rev 2  — protecting Controlled Unclassified Information
    CIS Benchmark Level 1  — basic cyber hygiene, minimal operational impact
    CIS Benchmark Level 2  — defense-in-depth, higher operational cost
    CMMC Level 1           — basic safeguarding (FAR 52.204-21, 17 practices)
    CMMC Level 2           — advanced (110 practices from NIST 800-171)

  All checks are read-only unless --harden is specified.  Hardening modifies
  HKLM registry keys and requires elevation; a UAC prompt will appear if the
  process is not already running as Administrator.

  Note: some controls (Credential Guard, BitLocker, Audit Policy) require a
  reboot or Group Policy refresh after the registry values are written.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include <ntsecapi.h>
#include "ComplianceEngine.h"
#include <cstdio>
#include <iostream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// ANSI colour codes — enabled via ENABLE_VIRTUAL_TERMINAL_PROCESSING
// ---------------------------------------------------------------------------
#define C_RESET  "\033[0m"
#define C_RED    "\033[91m"
#define C_GREEN  "\033[92m"
#define C_YELLOW "\033[93m"
#define C_CYAN   "\033[96m"
#define C_BOLD   "\033[1m"
#define C_DIM    "\033[2m"
#define C_WHITE  "\033[97m"

static void EnableAnsiColors() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------
static bool RegReadDword(HKEY root, const char* sub, const char* val, DWORD& out) {
    HKEY hk;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    DWORD type = REG_DWORD, size = sizeof(DWORD);
    bool ok = (RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)&out, &size) == ERROR_SUCCESS
               && type == REG_DWORD);
    RegCloseKey(hk);
    return ok;
}

static bool RegReadString(HKEY root, const char* sub, const char* val, std::string& out) {
    HKEY hk;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    char buf[256] = {};
    DWORD size = sizeof(buf), type;
    bool ok = (RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS);
    if (ok) out = buf;
    RegCloseKey(hk);
    return ok;
}

static bool RegKeyExists(HKEY root, const char* sub) {
    HKEY hk;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    RegCloseKey(hk);
    return true;
}

static bool RegWriteDword(HKEY root, const char* sub, const char* val, DWORD data) {
    HKEY hk; DWORD disp;
    if (RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, nullptr, &hk, &disp) != ERROR_SUCCESS) return false;
    bool ok = (RegSetValueExA(hk, val, 0, REG_DWORD, (LPBYTE)&data, sizeof(data)) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

static bool RegWriteString(HKEY root, const char* sub, const char* val, const char* data) {
    HKEY hk; DWORD disp;
    if (RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, nullptr, &hk, &disp) != ERROR_SUCCESS) return false;
    bool ok = (RegSetValueExA(hk, val, 0, REG_SZ,
               (LPBYTE)data, (DWORD)(strlen(data) + 1)) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

// ---------------------------------------------------------------------------
// Per-check data table
// ---------------------------------------------------------------------------
struct CheckDef {
    std::string  id;
    std::string  title;
    uint32_t     standards;       // bitmask of applicable standards
    ControlRef   refs;
    std::function<ComplianceFinding()> evaluate;
    std::function<bool()>              harden;   // nullptr = manual only
};

// Shorthand for building a failing finding
static ComplianceFinding Fail(const CheckDef& c, const std::string& cur,
                               const std::string& req, bool canH,
                               const std::string& note = "") {
    return { c.id, c.title, {}, CheckResult::Fail, cur, req, canH, note };
}
static ComplianceFinding Pass(const CheckDef& c, const std::string& cur) {
    return { c.id, c.title, {}, CheckResult::Pass, cur, cur, false, {} };
}
static ComplianceFinding Warn(const CheckDef& c, const std::string& cur,
                               const std::string& req, bool canH,
                               const std::string& note = "") {
    return { c.id, c.title, {}, CheckResult::Warning, cur, req, canH, note };
}
static ComplianceFinding Manual(const CheckDef& c, const std::string& note) {
    return { c.id, c.title, {}, CheckResult::ManualCheck, {}, {}, false, note };
}

// ---------------------------------------------------------------------------
// Build the complete check table
// ---------------------------------------------------------------------------
static std::vector<CheckDef> BuildChecks() {
    using CR = CheckResult;
    std::vector<CheckDef> t;

    // ------------------------------------------------------------------
    // 1. LSA Protection (RunAsPPL)
    // ------------------------------------------------------------------
    t.push_back({
        "LSA-RPL",
        "LSA Protection (RunAsPPL) — prevents LSASS credential dumping",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-28(1)", "3.13.16", nullptr, "18.3.1", nullptr, "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", v);
            if (!found || v < 1) return Fail({"LSA-RPL","LSA Protection (RunAsPPL)"}, {},
                found ? std::to_string(v) : "not set", "1", true);
            return Pass({"LSA-RPL","LSA Protection (RunAsPPL)"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", 1); }
    });

    // ------------------------------------------------------------------
    // 2. WDigest plaintext credential caching disabled
    // ------------------------------------------------------------------
    t.push_back({
        "WDIG-000",
        "WDigest plaintext credential caching disabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(13)", "3.5.10", "18.3.2", "18.3.2", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            DWORD v = 1;  // default is 1 (enabled) on older OS
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                "UseLogonCredential", v);
            if (v != 0) return Fail({"WDIG-000","WDigest disabled"}, {},
                std::to_string(v), "0", true);
            return Pass({"WDIG-000","WDigest disabled"}, "0");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                "UseLogonCredential", 0); }
    });

    // ------------------------------------------------------------------
    // 3. SMBv1 disabled
    // ------------------------------------------------------------------
    t.push_back({
        "SMB-V1",
        "SMBv1 protocol disabled (EternalBlue / WannaCry vector)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "CM-7", "3.4.6", "18.3.3", "18.3.3", "CM.1.074", "CM.2.061" },
        []() -> ComplianceFinding {
            DWORD v = 1;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "SMB1", v);
            if (v != 0) return Fail({"SMB-V1","SMBv1 disabled"}, {},
                std::to_string(v), "0", true);
            return Pass({"SMB-V1","SMBv1 disabled"}, "0");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "SMB1", 0); }
    });

    // ------------------------------------------------------------------
    // 4. SMB signing required — server
    // ------------------------------------------------------------------
    t.push_back({
        "SMB-SGS",
        "SMB packet signing required (server) — prevents relay attacks",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-8", "3.13.8", "2.3.9.2", "2.3.9.2", nullptr, "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "RequireSecuritySignature", v);
            if (v < 1) return Fail({"SMB-SGS","SMB signing (server)"}, {},
                std::to_string(v), "1", true);
            return Pass({"SMB-SGS","SMB signing (server)"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "RequireSecuritySignature", 1); }
    });

    // ------------------------------------------------------------------
    // 5. SMB signing required — client
    // ------------------------------------------------------------------
    t.push_back({
        "SMB-SGC",
        "SMB packet signing required (client)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-8", "3.13.8", "2.3.9.1", "2.3.9.1", nullptr, "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                "RequireSecuritySignature", v);
            if (v < 1) return Fail({"SMB-SGC","SMB signing (client)"}, {},
                std::to_string(v), "1", true);
            return Pass({"SMB-SGC","SMB signing (client)"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                "RequireSecuritySignature", 1); }
    });

    // ------------------------------------------------------------------
    // 6. UAC enabled
    // ------------------------------------------------------------------
    t.push_back({
        "UAC-ENA",
        "User Account Control (UAC) enabled",
        STD_ALL,
        { "AC-6(1)", "3.1.6", "2.3.17.1", "2.3.17.1", "AC.1.002", "AC.2.005" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "EnableLUA", v);
            if (v < 1) return Fail({"UAC-ENA","UAC enabled"}, {},
                std::to_string(v), "1", true);
            return Pass({"UAC-ENA","UAC enabled"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "EnableLUA", 1); }
    });

    // ------------------------------------------------------------------
    // 7. UAC admin elevation prompt (not silent auto-elevate)
    // ------------------------------------------------------------------
    t.push_back({
        "UAC-ADM",
        "UAC admin consent prompt behavior — must not be silent (0)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-6(1)", "3.1.6", "2.3.17.2", "2.3.17.2", nullptr, "AC.2.005" },
        []() -> ComplianceFinding {
            DWORD v = 5;  // Windows default = 5 (prompt for consent)
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "ConsentPromptBehaviorAdmin", v);
            // 0 = elevate without prompt (insecure); any other value is acceptable
            if (v == 0) return Fail({"UAC-ADM","UAC admin prompt"}, {},
                "0 (no prompt)", ">= 1", true,
                "Setting to 2 (prompt for credentials on secure desktop)");
            if (v < 2) return Warn({"UAC-ADM","UAC admin prompt"}, {},
                std::to_string(v), "2 (secure desktop)", true);
            return Pass({"UAC-ADM","UAC admin prompt"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "ConsentPromptBehaviorAdmin", 2); }
    });

    // ------------------------------------------------------------------
    // 8. AutoPlay / AutoRun disabled
    // ------------------------------------------------------------------
    t.push_back({
        "AUTO-RUN",
        "AutoPlay/AutoRun disabled for all drive types",
        STD_ALL,
        { "CM-7", "3.4.6", "18.9.8.1", "18.9.8.1", "CM.1.074", "CM.2.061" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "NoDriveTypeAutoRun", v);
            if (!found || v != 255) return Fail({"AUTO-RUN","AutoPlay disabled"}, {},
                found ? std::to_string(v) : "not set", "255", true);
            return Pass({"AUTO-RUN","AutoPlay disabled"}, "255");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "NoDriveTypeAutoRun", 255); }
    });

    // ------------------------------------------------------------------
    // 9. PowerShell Script Block Logging enabled
    // ------------------------------------------------------------------
    t.push_back({
        "PS-SBL",
        "PowerShell Script Block Logging enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-2", "3.3.1", nullptr, "18.9.102.1.1", nullptr, "AU.3.045" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                "EnableScriptBlockLogging", v);
            if (v < 1) return Fail({"PS-SBL","PS ScriptBlock Logging"}, {},
                std::to_string(v), "1", true);
            return Pass({"PS-SBL","PS ScriptBlock Logging"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                "EnableScriptBlockLogging", 1); }
    });

    // ------------------------------------------------------------------
    // 10. PowerShell Transcription enabled
    // ------------------------------------------------------------------
    t.push_back({
        "PS-TRN",
        "PowerShell Transcription logging enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-3", "3.3.1", nullptr, "18.9.102.2.1", nullptr, "AU.3.045" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
                "EnableTranscripting", v);
            if (v < 1) return Fail({"PS-TRN","PS Transcription"}, {},
                std::to_string(v), "1", true);
            return Pass({"PS-TRN","PS Transcription"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
                "EnableTranscripting", 1); }
    });

    // ------------------------------------------------------------------
    // 11–13. Windows Firewall — Domain / Private / Public profiles
    // ------------------------------------------------------------------
    const struct { const char* profile; const char* regKey; const char* id; } fwProfiles[] = {
        { "Domain",  "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",   "FW-DOM" },
        { "Private", "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", "FW-PRI" },
        { "Public",  "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",   "FW-PUB" },
    };
    for (auto& fp : fwProfiles) {
        std::string id = fp.id, key = fp.regKey, profile = fp.profile;
        std::string title = "Windows Firewall enabled — " + profile + " profile";
        t.push_back({
            id, title,
            STD_ALL,
            { "SC-7", "3.13.1", "9.1.1", "9.1.1", "SC.1.175", "SC.3.177" },
            [id, title, key]() -> ComplianceFinding {
                DWORD v = 0;
                RegReadDword(HKEY_LOCAL_MACHINE, key.c_str(), "EnableFirewall", v);
                if (v < 1) return Fail({id, title}, {}, std::to_string(v), "1", true);
                return Pass({id, title}, "1");
            },
            [key]{ return RegWriteDword(HKEY_LOCAL_MACHINE, key.c_str(), "EnableFirewall", 1); }
        });
    }

    // ------------------------------------------------------------------
    // 14. Network Level Authentication (NLA) for Remote Desktop
    // ------------------------------------------------------------------
    t.push_back({
        "RDP-NLA",
        "Network Level Authentication required for RDP",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-17", "3.1.12", "18.10.28.2", "18.10.28.2", nullptr, "AC.2.006" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                "UserAuthentication", v);
            if (v < 1) return Fail({"RDP-NLA","NLA for RDP"}, {},
                std::to_string(v), "1", true);
            return Pass({"RDP-NLA","NLA for RDP"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                "UserAuthentication", 1); }
    });

    // ------------------------------------------------------------------
    // 15–16. NTLM minimum security — client and server
    //   0x20080000 = NTLMv2 session security + 128-bit encryption
    // ------------------------------------------------------------------
    const struct { const char* id; const char* label; const char* val; } ntlmPairs[] = {
        { "NTLM-CLI", "NTLM minimum security (client)", "NTLMMinClientSec" },
        { "NTLM-SRV", "NTLM minimum security (server)", "NTLMMinServerSec" },
    };
    for (auto& np : ntlmPairs) {
        std::string id = np.id, title = np.label, regVal = np.val;
        t.push_back({
            id, title,
            STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
            { "IA-5(1)", "3.5.10", "2.3.11.7", "2.3.11.7", nullptr, "IA.3.083" },
            [id, title, regVal]() -> ComplianceFinding {
                DWORD v = 0;
                RegReadDword(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", regVal.c_str(), v);
                const DWORD required = 0x20080000;
                if ((v & required) != required)
                    return Fail({id, title}, {}, "0x" + [v]{ std::ostringstream ss; ss << std::hex << v; return ss.str(); }(),
                        "0x20080000", true);
                return Pass({id, title}, "0x20080000");
            },
            [regVal]{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", regVal.c_str(), 0x20080000); }
        });
    }

    // ------------------------------------------------------------------
    // 17. Credential Guard enabled
    // ------------------------------------------------------------------
    t.push_back({
        "CRED-GRD",
        "Credential Guard (VBS) enabled — isolates LSA secrets from kernel",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-28(1)", "3.13.16", nullptr, "18.8.5.1", nullptr, "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD vbs = 0, lsa = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                "EnableVirtualizationBasedSecurity", vbs);
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                "LsaCfgFlags", lsa);
            if (vbs < 1 || lsa < 1)
                return Fail({"CRED-GRD","Credential Guard"}, {},
                    "VBS=" + std::to_string(vbs) + " LsaCfg=" + std::to_string(lsa),
                    "VBS=1 LsaCfg=1", true,
                    "Requires Secure Boot, TPM 2.0, UEFI firmware, and a reboot to activate");
            return Pass({"CRED-GRD","Credential Guard"}, "VBS=1 LsaCfg=1");
        },
        []() -> bool {
            bool a = RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                "EnableVirtualizationBasedSecurity", 1);
            bool b = RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                "LsaCfgFlags", 1);
            bool c = RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                "RequirePlatformSecurityFeatures", 3);
            return a && b && c;
        }
    });

    // ------------------------------------------------------------------
    // 18. Guest account disabled
    // ------------------------------------------------------------------
    t.push_back({
        "ACCT-GST",
        "Built-in Guest account disabled",
        STD_ALL,
        { "AC-2", "3.1.1", "2.3.1.5", "2.3.1.5", "AC.1.001", "AC.2.005" },
        []() -> ComplianceFinding {
            USER_INFO_1* info = nullptr;
            NET_API_STATUS r = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&info);
            if (r != NERR_Success || !info)
                return Manual({"ACCT-GST","Guest account disabled"},
                    "Run: net user Guest /active:no");
            bool disabled = (info->usri1_flags & UF_ACCOUNTDISABLE) != 0;
            NetApiBufferFree(info);
            if (!disabled) return Fail({"ACCT-GST","Guest account disabled"}, {},
                "active", "disabled", true);
            return Pass({"ACCT-GST","Guest account disabled"}, "disabled");
        },
        []() -> bool {
            USER_INFO_1008 info;
            USER_INFO_1* cur = nullptr;
            if (NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&cur) != NERR_Success) return false;
            info.usri1008_flags = cur->usri1_flags | UF_ACCOUNTDISABLE;
            NetApiBufferFree(cur);
            DWORD err;
            return NetUserSetInfo(nullptr, L"Guest", 1008, (LPBYTE)&info, &err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // 19. Anonymous SAM enumeration restricted
    // ------------------------------------------------------------------
    t.push_back({
        "LSA-ANO",
        "Anonymous enumeration of SAM accounts restricted",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-3", "3.1.3", "2.3.10.3", "2.3.10.3", nullptr, "AC.2.006" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "RestrictAnonymousSAM", v);
            if (v < 1) return Fail({"LSA-ANO","Anonymous SAM restriction"}, {},
                std::to_string(v), "1", true);
            return Pass({"LSA-ANO","Anonymous SAM restriction"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "RestrictAnonymousSAM", 1); }
    });

    // ------------------------------------------------------------------
    // 20. Cached domain logon count (limit credential exposure offline)
    // ------------------------------------------------------------------
    t.push_back({
        "AUTH-CAC",
        "Cached domain logon credentials limited (CachedLogonsCount <= 4)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5", "3.5.4", nullptr, "2.3.11.1", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            std::string v;
            RegReadString(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "CachedLogonsCount", v);
            int count = v.empty() ? 10 : std::stoi(v);  // Windows default = 10
            if (count > 4) return Fail({"AUTH-CAC","Cached logon count"}, {},
                v.empty() ? "10 (default)" : v, "<= 4", true);
            return Pass({"AUTH-CAC","Cached logon count"}, v.empty() ? "10" : v);
        },
        []{ return RegWriteString(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "CachedLogonsCount", "2"); }
    });

    // ------------------------------------------------------------------
    // 21. Audit logon events (success + failure)
    // ------------------------------------------------------------------
    t.push_back({
        "AUD-LOG",
        "Audit Logon events enabled (Success + Failure)",
        STD_ALL,
        { "AU-2", "3.3.1", "17.5.1", "17.5.1", "AU.1.010", "AU.2.041" },
        []() -> ComplianceFinding {
            // Query via AuditQuerySubcategoryPolicy
            // GUID for "Logon" subcategory: {0CCE9216-69AE-11D9-BED3-505054503030}
            GUID logonGuid = { 0x0CCE9216, 0x69AE, 0x11D9,
                               {0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30} };
            PAUDIT_POLICY_INFORMATION pInfo = nullptr;
            if (!AuditQuerySubcategoryPolicy(&logonGuid, &pInfo) || !pInfo)
                return Manual({"AUD-LOG","Audit Logon events"},
                    "Run: auditpol /get /subcategory:Logon   (requires admin)");
            DWORD info = pInfo->AuditingInformation;
            AuditFree(pInfo);
            bool hasSuccess = (info & POLICY_AUDIT_EVENT_SUCCESS) != 0;
            bool hasFailure = (info & POLICY_AUDIT_EVENT_FAILURE) != 0;
            if (!hasSuccess || !hasFailure)
                return Fail({"AUD-LOG","Audit Logon events"}, {},
                    std::string(hasSuccess ? "Success" : "") + (hasFailure ? "+Failure" : ""),
                    "Success+Failure", false,
                    "Run: auditpol /set /subcategory:Logon /success:enable /failure:enable");
            return Pass({"AUD-LOG","Audit Logon events"}, "Success+Failure");
        },
        nullptr   // manual: auditpol command required
    });

    // ------------------------------------------------------------------
    // 22. BitLocker (volume encryption) — CIS L2 / CMMC L2 / NIST
    // ------------------------------------------------------------------
    t.push_back({
        "BL-ENC",
        "BitLocker drive encryption enabled on OS volume",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-28", "3.13.16", nullptr, "18.10.10", nullptr, "SC.3.177" },
        []() -> ComplianceFinding {
            // Check via registry key written by BitLocker provider
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\FVE", "EnableBDEWithNoTPM", v);
            // A simple presence check: look for BitLocker-related key
            bool blKey = RegKeyExists(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\BitLocker");
            if (!blKey && !found)
                return Manual({"BL-ENC","BitLocker encryption"},
                    "Verify via: manage-bde -status C:   |   Required for CIS L2 / CMMC L2");
            return Manual({"BL-ENC","BitLocker encryption"},
                "Check manage-bde -status C: — cannot fully verify from registry alone");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // 23. PowerShell v2 disabled (eliminates AMSI/CLM bypass vector)
    // ------------------------------------------------------------------
    t.push_back({
        "PS-V2",
        "PowerShell v2 disabled (removes AMSI/constrained-language bypass)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-7", "3.4.6", "18.9.102.3", "18.9.102.3", nullptr, "CM.2.061" },
        []() -> ComplianceFinding {
            // PS v2 is a Windows Optional Feature; check via DISM registry key
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine",
                "PSCompatibleVersion", v);
            // Simpler: check if MicrosoftWindowsPowerShellV2Root feature is present
            return Manual({"PS-V2","PowerShell v2 disabled"},
                "Disable via: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root");
        },
        nullptr
    });

    return t;
}

// ---------------------------------------------------------------------------
// Standard helpers
// ---------------------------------------------------------------------------
uint32_t ComplianceEngine::StandardMask(ComplianceStandard s) {
    switch (s) {
    case ComplianceStandard::NIST_800_53:  return STD_NIST_80053;
    case ComplianceStandard::NIST_800_171: return STD_NIST_800171;
    case ComplianceStandard::CIS_Level1:   return STD_CIS_L1;
    case ComplianceStandard::CIS_Level2:   return STD_CIS_L1 | STD_CIS_L2;  // L2 includes L1
    case ComplianceStandard::CMMC_Level1:  return STD_CMMC_L1;
    case ComplianceStandard::CMMC_Level2:  return STD_CMMC_L1 | STD_CMMC_L2; // L2 includes L1
    default: return 0;
    }
}

std::string ComplianceEngine::StandardName(ComplianceStandard s) {
    switch (s) {
    case ComplianceStandard::NIST_800_53:  return "NIST SP 800-53 Rev 5";
    case ComplianceStandard::NIST_800_171: return "NIST SP 800-171 Rev 2";
    case ComplianceStandard::CIS_Level1:   return "CIS Benchmark Level 1";
    case ComplianceStandard::CIS_Level2:   return "CIS Benchmark Level 2";
    case ComplianceStandard::CMMC_Level1:  return "CMMC Level 1";
    case ComplianceStandard::CMMC_Level2:  return "CMMC Level 2";
    default: return "Unknown";
    }
}

const char* ComplianceEngine::ResolveRef(const ControlRef& r, ComplianceStandard s) {
    switch (s) {
    case ComplianceStandard::NIST_800_53:  return r.nist80053  ? r.nist80053  : "—";
    case ComplianceStandard::NIST_800_171: return r.nist800171 ? r.nist800171 : "—";
    case ComplianceStandard::CIS_Level1:   return r.cisL1      ? r.cisL1      : "—";
    case ComplianceStandard::CIS_Level2:   return r.cisL2      ? r.cisL2      : r.cisL1 ? r.cisL1 : "—";
    case ComplianceStandard::CMMC_Level1:  return r.cmmcL1     ? r.cmmcL1     : "—";
    case ComplianceStandard::CMMC_Level2:  return r.cmmcL2     ? r.cmmcL2     : r.cmmcL1 ? r.cmmcL1 : "—";
    default: return "—";
    }
}

// ---------------------------------------------------------------------------
// Evaluate — run all checks applicable to the given standard
// ---------------------------------------------------------------------------
std::vector<ComplianceFinding> ComplianceEngine::Evaluate(ComplianceStandard s) {
    uint32_t mask = StandardMask(s);
    auto checks   = BuildChecks();
    std::vector<ComplianceFinding> findings;

    for (auto& c : checks) {
        if (!(c.standards & mask)) continue;   // not applicable to this standard
        ComplianceFinding f = c.evaluate();
        f.id         = c.id;
        f.title      = c.title;
        f.controlRef = ResolveRef(c.refs, s);
        f.canHarden  = f.canHarden && (c.harden != nullptr);
        findings.push_back(std::move(f));
    }
    return findings;
}

// ---------------------------------------------------------------------------
// PrintReport
// ---------------------------------------------------------------------------
void ComplianceEngine::PrintReport(const std::vector<ComplianceFinding>& findings,
                                    const std::string& name) {
    int pass = 0, fail = 0, warn = 0, manual = 0;
    for (auto& f : findings) {
        switch (f.result) {
        case CheckResult::Pass:        pass++;   break;
        case CheckResult::Fail:        fail++;   break;
        case CheckResult::Warning:     warn++;   break;
        case CheckResult::ManualCheck: manual++; break;
        }
    }
    int total = pass + fail + warn + manual;

    printf("\n");
    printf(C_BOLD C_WHITE "═══════════════════════════════════════════════════════════════\n" C_RESET);
    printf(C_BOLD C_WHITE "  NortonEDR Compliance Evaluation — %s\n" C_RESET, name.c_str());
    printf(C_BOLD C_WHITE "═══════════════════════════════════════════════════════════════\n" C_RESET);
    printf("\n");

    for (auto& f : findings) {
        const char* badge  = "";
        const char* col    = "";
        switch (f.result) {
        case CheckResult::Pass:        badge = "PASS"; col = C_GREEN;  break;
        case CheckResult::Fail:        badge = "FAIL"; col = C_RED;    break;
        case CheckResult::Warning:     badge = "WARN"; col = C_YELLOW; break;
        case CheckResult::ManualCheck: badge = "INFO"; col = C_CYAN;   break;
        }

        printf("%s[%s]%s  [%s] %s\n", col, badge, C_RESET,
               f.controlRef.c_str(), f.title.c_str());

        if (f.result != CheckResult::Pass && f.result != CheckResult::ManualCheck) {
            printf("       %sCurrent:%s  %s\n", C_DIM, C_RESET, f.currentValue.c_str());
            printf("       %sRequired:%s %s\n", C_DIM, C_RESET, f.requiredValue.c_str());
            if (f.canHarden)
                printf("       %s→ Can be auto-hardened%s\n", C_CYAN, C_RESET);
        }
        if (!f.hardenNote.empty())
            printf("       %s⚠  %s%s\n", C_YELLOW, f.hardenNote.c_str(), C_RESET);
        printf("\n");
    }

    printf(C_BOLD C_WHITE "───────────────────────────────────────────────────────────────\n" C_RESET);
    printf(C_BOLD "  Results: " C_RESET);
    printf(C_GREEN  "%d PASS" C_RESET "  ", pass);
    printf(C_RED    "%d FAIL" C_RESET "  ", fail);
    printf(C_YELLOW "%d WARN" C_RESET "  ", warn);
    printf(C_CYAN   "%d INFO" C_RESET "  ", manual);
    printf("/ %d total\n", total);

    int score = (total > 0) ? (int)((pass * 100.0) / total) : 0;
    const char* scoreCol = score >= 80 ? C_GREEN : (score >= 60 ? C_YELLOW : C_RED);
    printf(C_BOLD   "  Compliance score: %s%d%%\n" C_RESET, scoreCol, score);
    printf(C_BOLD C_WHITE "═══════════════════════════════════════════════════════════════\n\n" C_RESET);
}

// ---------------------------------------------------------------------------
// ApplyHardening
// ---------------------------------------------------------------------------
void ComplianceEngine::ApplyHardening(const std::vector<ComplianceFinding>& findings,
                                       ComplianceStandard s) {
    auto checks = BuildChecks();
    int applied = 0, skipped = 0;

    printf(C_BOLD "\n  Applying hardening...\n\n" C_RESET);

    for (auto& f : findings) {
        if (f.result == CheckResult::Pass || f.result == CheckResult::ManualCheck) continue;
        if (!f.canHarden) {
            if (!f.hardenNote.empty())
                printf("  " C_YELLOW "[SKIP]" C_RESET " %s — %s\n", f.title.c_str(), f.hardenNote.c_str());
            else
                printf("  " C_YELLOW "[SKIP]" C_RESET " %s — manual remediation required\n", f.title.c_str());
            skipped++;
            continue;
        }

        // Find the matching CheckDef to get the harden function
        for (auto& c : checks) {
            if (c.id == f.id && c.harden) {
                bool ok = c.harden();
                if (ok) {
                    printf("  " C_GREEN "[DONE]" C_RESET " %s\n", f.title.c_str());
                    applied++;
                } else {
                    printf("  " C_RED "[FAIL]" C_RESET " %s — access denied or write error\n", f.title.c_str());
                    skipped++;
                }
                break;
            }
        }
    }

    printf("\n");
    printf(C_BOLD "  Hardening complete: %s%d applied" C_RESET ", %d skipped.\n",
           applied > 0 ? C_GREEN : C_YELLOW, applied, skipped);
    if (applied > 0)
        printf(C_YELLOW "  ⚠  Some changes (Credential Guard, audit policy) require a reboot.\n" C_RESET);
    printf("\n");
}

// ---------------------------------------------------------------------------
// RunEvaluation — entry point
// ---------------------------------------------------------------------------
int ComplianceEngine::RunEvaluation(ComplianceStandard standard, bool autoHarden) {
    EnableAnsiColors();

    std::string name = StandardName(standard);
    printf(C_DIM "\n  Running compliance evaluation against: " C_RESET C_BOLD "%s\n" C_RESET, name.c_str());

    auto findings = Evaluate(standard);
    PrintReport(findings, name);

    bool anyFail = false;
    for (auto& f : findings)
        if (f.result == CheckResult::Fail || f.result == CheckResult::Warning) { anyFail = true; break; }

    if (!anyFail) {
        printf(C_GREEN "  All automated checks passed. No hardening required.\n\n" C_RESET);
        return 0;
    }

    if (autoHarden) {
        ApplyHardening(findings, standard);
    } else {
        printf("  Apply hardening for failed controls? [y/N] ");
        fflush(stdout);
        char c = '\0';
        std::cin >> c;
        if (c == 'y' || c == 'Y')
            ApplyHardening(findings, standard);
        else
            printf(C_DIM "\n  Hardening skipped.\n\n" C_RESET);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// ParseStandard
// ---------------------------------------------------------------------------
bool ComplianceEngine::ParseStandard(const std::string& name, ComplianceStandard& out) {
    std::string n = name;
    for (auto& c : n) c = (char)tolower((unsigned char)c);

    if (n == "nist800-53"  || n == "nist-800-53"  || n == "800-53")  { out = ComplianceStandard::NIST_800_53;  return true; }
    if (n == "nist800-171" || n == "nist-800-171" || n == "800-171") { out = ComplianceStandard::NIST_800_171; return true; }
    if (n == "cis-l1"      || n == "cis1"         || n == "cisl1")   { out = ComplianceStandard::CIS_Level1;   return true; }
    if (n == "cis-l2"      || n == "cis2"         || n == "cisl2")   { out = ComplianceStandard::CIS_Level2;   return true; }
    if (n == "cmmc-l1"     || n == "cmmc1"        || n == "cmmcl1")  { out = ComplianceStandard::CMMC_Level1;  return true; }
    if (n == "cmmc-l2"     || n == "cmmc2"        || n == "cmmcl2")  { out = ComplianceStandard::CMMC_Level2;  return true; }
    return false;
}
