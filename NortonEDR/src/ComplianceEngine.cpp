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
// Service start type helper (returns 4 = SERVICE_DISABLED; -1 = not found)
// ---------------------------------------------------------------------------
static DWORD SvcStartType(const char* name) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return (DWORD)-1;
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_CONFIG);
    if (!svc) { CloseServiceHandle(scm); return (DWORD)-1; }
    DWORD needed = 0;
    QueryServiceConfigA(svc, nullptr, 0, &needed);
    LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LMEM_FIXED, needed);
    DWORD st = SERVICE_DISABLED;
    if (cfg && QueryServiceConfigA(svc, cfg, needed, &needed)) st = cfg->dwStartType;
    LocalFree(cfg);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return st;
}

// ---------------------------------------------------------------------------
// Audit subcategory helper — checks success/failure bits via AuditQuerySystemPolicy
// ---------------------------------------------------------------------------
static ComplianceFinding CheckAuditSub(const CheckDef& c, const GUID& guid,
                                        bool needSuccess, bool needFailure,
                                        const char* subcatName) {
    PAUDIT_POLICY_INFORMATION pInfo = nullptr;
    if (!AuditQuerySystemPolicy(&guid, 1, &pInfo) || !pInfo) {
        char note[320];
        sprintf_s(note, sizeof(note),
            "auditpol /get /subcategory:\"%s\"  (requires admin)", subcatName);
        return Manual(c, note);
    }
    DWORD info = pInfo->AuditingInformation;
    AuditFree(pInfo);
    bool hasS = (info & POLICY_AUDIT_EVENT_SUCCESS) != 0;
    bool hasF = (info & POLICY_AUDIT_EVENT_FAILURE) != 0;
    auto statusStr = [&]() -> std::string {
        if (!hasS && !hasF) return "None";
        return std::string(hasS ? "Success" : "") + (hasF ? (hasS ? "+Failure" : "Failure") : "");
    };
    bool ok = (!needSuccess || hasS) && (!needFailure || hasF);
    if (!ok) {
        std::string req = std::string(needSuccess ? "Success" : "") +
                          (needFailure ? (needSuccess ? "+Failure" : "Failure") : "");
        char cmd[400];
        sprintf_s(cmd, sizeof(cmd),
            "auditpol /set /subcategory:\"%s\" /success:%s /failure:%s",
            subcatName, needSuccess ? "enable" : "disable", needFailure ? "enable" : "disable");
        return Fail(c, statusStr(), req, false, cmd);
    }
    return Pass(c, statusStr());
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
            if (!found || v < 1) return Fail({"LSA-RPL","LSA Protection (RunAsPPL)"},
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
            if (v != 0) return Fail({"WDIG-000","WDigest disabled"},
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
            if (v != 0) return Fail({"SMB-V1","SMBv1 disabled"},
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
            if (v < 1) return Fail({"SMB-SGS","SMB signing (server)"},
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
            if (v < 1) return Fail({"SMB-SGC","SMB signing (client)"},
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
            if (v < 1) return Fail({"UAC-ENA","UAC enabled"},
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
            if (v == 0) return Fail({"UAC-ADM","UAC admin prompt"},
                "0 (no prompt)", ">= 1", true,
                "Setting to 2 (prompt for credentials on secure desktop)");
            if (v < 2) return Warn({"UAC-ADM","UAC admin prompt"},
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
            if (!found || v != 255) return Fail({"AUTO-RUN","AutoPlay disabled"},
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
            if (v < 1) return Fail({"PS-SBL","PS ScriptBlock Logging"},
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
            if (v < 1) return Fail({"PS-TRN","PS Transcription"},
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
                if (v < 1) return Fail({id, title}, std::to_string(v), "1", true);
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
            if (v < 1) return Fail({"RDP-NLA","NLA for RDP"},
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
                    return Fail({id, title}, "0x" + [v]{ std::ostringstream ss; ss << std::hex << v; return ss.str(); }(),
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
                return Fail({"CRED-GRD","Credential Guard"},
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
            if (!disabled) return Fail({"ACCT-GST","Guest account disabled"},
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
            if (v < 1) return Fail({"LSA-ANO","Anonymous SAM restriction"},
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
            if (count > 4) return Fail({"AUTH-CAC","Cached logon count"},
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
            if (!AuditQuerySystemPolicy(&logonGuid, 1, &pInfo) || !pInfo)
                return Manual({"AUD-LOG","Audit Logon events"},
                    "Run: auditpol /get /subcategory:Logon   (requires admin)");
            DWORD info = pInfo->AuditingInformation;
            AuditFree(pInfo);
            bool hasSuccess = (info & POLICY_AUDIT_EVENT_SUCCESS) != 0;
            bool hasFailure = (info & POLICY_AUDIT_EVENT_FAILURE) != 0;
            if (!hasSuccess || !hasFailure)
                return Fail({"AUD-LOG","Audit Logon events"},
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

    // ==================================================================
    // AC — Access Control additions
    // ==================================================================

    // ------------------------------------------------------------------
    // ACLOCK-THR: Account lockout threshold <= 5
    // ------------------------------------------------------------------
    t.push_back({
        "ACLOCK-THR",
        "Account lockout threshold <= 5 invalid attempts",
        STD_ALL,
        { "AC-7", "3.1.8", "1.2.1", "1.2.1", "AC.1.001", "AC.2.009" },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_3* m3 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 3, (LPBYTE*)&m3);
            if (r != NERR_Success || !m3)
                return Manual({"ACLOCK-THR","Account lockout threshold"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD thresh = m3->usrmod3_lockout_threshold;
            NetApiBufferFree(m3);
            if (thresh == 0)
                return Fail({"ACLOCK-THR","Account lockout threshold"},
                    "0 (never locks out)", "1-5", true, "");
            if (thresh > 5)
                return Fail({"ACLOCK-THR","Account lockout threshold"},
                    std::to_string(thresh), "<= 5", true, "");
            return Pass({"ACLOCK-THR","Account lockout threshold"}, std::to_string(thresh));
        },
        []() -> bool {
            USER_MODALS_INFO_3* cur = nullptr;
            if (NetUserModalsGet(nullptr, 3, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_3 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod3_lockout_threshold   = 5;
            upd.usrmod3_lockout_duration    = 30;
            upd.usrmod3_lockout_observation_window = 30;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 3, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // ACLOCK-DUR: Account lockout duration >= 15 min (or TIMEQ_FOREVER)
    // ------------------------------------------------------------------
    t.push_back({
        "ACLOCK-DUR",
        "Account lockout duration >= 15 minutes (or never auto-unlock)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-7", "3.1.8", "1.2.2", "1.2.2", nullptr, "AC.2.009" },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_3* m3 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 3, (LPBYTE*)&m3);
            if (r != NERR_Success || !m3)
                return Manual({"ACLOCK-DUR","Account lockout duration"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD dur = m3->usrmod3_lockout_duration;
            NetApiBufferFree(m3);
            // TIMEQ_FOREVER = 0xFFFFFFFF => never auto-unlock => pass
            if (dur == TIMEQ_FOREVER)
                return Pass({"ACLOCK-DUR","Account lockout duration"}, "never (TIMEQ_FOREVER)");
            // duration in 30-second units; 30 units = 15 min
            if (dur < 30)
                return Fail({"ACLOCK-DUR","Account lockout duration"},
                    std::to_string(dur) + " units (" + std::to_string(dur / 2) + " min)",
                    ">= 30 units (15 min)", true, "");
            return Pass({"ACLOCK-DUR","Account lockout duration"},
                std::to_string(dur) + " units");
        },
        []() -> bool {
            USER_MODALS_INFO_3* cur = nullptr;
            if (NetUserModalsGet(nullptr, 3, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_3 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod3_lockout_duration = 30;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 3, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // ACLOCK-RST: Lockout observation window >= 15 min
    // ------------------------------------------------------------------
    t.push_back({
        "ACLOCK-RST",
        "Account lockout observation window >= 15 minutes",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-7", "3.1.8", "1.2.3", "1.2.3", nullptr, "AC.2.009" },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_3* m3 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 3, (LPBYTE*)&m3);
            if (r != NERR_Success || !m3)
                return Manual({"ACLOCK-RST","Lockout observation window"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD win = m3->usrmod3_lockout_observation_window;
            NetApiBufferFree(m3);
            if (win < 30)
                return Fail({"ACLOCK-RST","Lockout observation window"},
                    std::to_string(win) + " units (" + std::to_string(win / 2) + " min)",
                    ">= 30 units (15 min)", true, "");
            return Pass({"ACLOCK-RST","Lockout observation window"},
                std::to_string(win) + " units");
        },
        []() -> bool {
            USER_MODALS_INFO_3* cur = nullptr;
            if (NetUserModalsGet(nullptr, 3, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_3 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod3_lockout_observation_window = 30;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 3, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // SESS-LOCK: Machine inactivity lock timeout <= 900 s
    // ------------------------------------------------------------------
    t.push_back({
        "SESS-LOCK",
        "Machine inactivity lock timeout <= 900 seconds",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-11", "3.1.10", "2.3.7.3", "2.3.7.3", nullptr, "AC.2.013" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "InactivityTimeoutSecs", v);
            if (!found || v == 0)
                return Fail({"SESS-LOCK","Machine inactivity lock"},
                    found ? "0 (disabled)" : "not set (disabled)", "<= 900", true, "");
            if (v > 900)
                return Fail({"SESS-LOCK","Machine inactivity lock"},
                    std::to_string(v) + "s", "<= 900s", true, "");
            return Pass({"SESS-LOCK","Machine inactivity lock"}, std::to_string(v) + "s");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "InactivityTimeoutSecs", 900); }
    });

    // ------------------------------------------------------------------
    // DISP-LAST: Don't display last username at logon
    // ------------------------------------------------------------------
    t.push_back({
        "DISP-LAST",
        "Last logged-on username not displayed at logon screen",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-9", nullptr, "2.3.7.1", "2.3.7.1", nullptr, "AC.2.006" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "DontDisplayLastUserName", v);
            if (!found || v < 1)
                return Fail({"DISP-LAST","Hide last username"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"DISP-LAST","Hide last username"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "DontDisplayLastUserName", 1); }
    });

    // ------------------------------------------------------------------
    // NULL-SESS: Null session / anonymous network access restricted
    // ------------------------------------------------------------------
    t.push_back({
        "NULL-SESS",
        "Null session access to named pipes and shares restricted",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-3", "3.1.3", "2.3.10.2", "2.3.10.2", nullptr, "AC.2.006" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "RestrictNullSessAccess", v);
            if (!found || v < 1)
                return Fail({"NULL-SESS","Null session restriction"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"NULL-SESS","Null session restriction"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "RestrictNullSessAccess", 1); }
    });

    // ------------------------------------------------------------------
    // ANON-RST: Anonymous access to network resources restricted
    // ------------------------------------------------------------------
    t.push_back({
        "ANON-RST",
        "Anonymous access to network resources restricted (RestrictAnonymous=1)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AC-3", "3.1.3", "2.3.10.1", "2.3.10.1", nullptr, "AC.2.006" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "RestrictAnonymous", v);
            if (!found || v < 1)
                return Fail({"ANON-RST","Restrict anonymous access"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"ANON-RST","Restrict anonymous access"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "RestrictAnonymous", 1); }
    });

    // ------------------------------------------------------------------
    // USB-DENY: Removable storage write access denied via policy
    // ------------------------------------------------------------------
    t.push_back({
        "USB-DENY",
        "Removable storage (USB) write access denied via policy",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "MP-7", "3.8.7", nullptr, "18.9.97.2.1", nullptr, "MP.2.120" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\"
                "{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}",
                "Deny_Write", v);
            if (!found || v < 1)
                return Fail({"USB-DENY","USB write denied"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"USB-DENY","USB write denied"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\"
                "{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}",
                "Deny_Write", 1); }
    });

    // ==================================================================
    // IA — Identification & Authentication additions
    // ==================================================================

    // ------------------------------------------------------------------
    // PWD-LEN: Password minimum length >= 14 (warn if 8-13, fail if < 8)
    // ------------------------------------------------------------------
    t.push_back({
        "PWD-LEN",
        "Password minimum length >= 14 characters",
        STD_ALL,
        { "IA-5(1)", "3.5.7", "1.1.4", "1.1.4", "IA.1.076", nullptr },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_0* m0 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 0, (LPBYTE*)&m0);
            if (r != NERR_Success || !m0)
                return Manual({"PWD-LEN","Password minimum length"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD len = m0->usrmod0_min_passwd_len;
            NetApiBufferFree(m0);
            if (len < 8)
                return Fail({"PWD-LEN","Password minimum length"},
                    std::to_string(len), ">= 14", true, "");
            if (len < 14)
                return Warn({"PWD-LEN","Password minimum length"},
                    std::to_string(len), ">= 14 (CIS L1/L2, CMMC L2); >= 8 (CMMC L1)", true, "");
            return Pass({"PWD-LEN","Password minimum length"}, std::to_string(len));
        },
        []() -> bool {
            USER_MODALS_INFO_0* cur = nullptr;
            if (NetUserModalsGet(nullptr, 0, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_0 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod0_min_passwd_len = 14;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 0, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // PWD-MAXAGE: Password maximum age <= 90 days
    // ------------------------------------------------------------------
    t.push_back({
        "PWD-MAXAGE",
        "Password maximum age <= 90 days (passwords must expire)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(1)", "3.5.8", "1.1.2", "1.1.2", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_0* m0 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 0, (LPBYTE*)&m0);
            if (r != NERR_Success || !m0)
                return Manual({"PWD-MAXAGE","Password maximum age"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD age = m0->usrmod0_max_passwd_age;
            NetApiBufferFree(m0);
            if (age == TIMEQ_FOREVER)
                return Fail({"PWD-MAXAGE","Password maximum age"},
                    "never expires (TIMEQ_FOREVER)", "<= 90 days", true, "");
            // age in seconds; 90 days = 7776000
            if (age > 7776000)
                return Fail({"PWD-MAXAGE","Password maximum age"},
                    std::to_string(age / 86400) + " days", "<= 90 days", true, "");
            return Pass({"PWD-MAXAGE","Password maximum age"},
                std::to_string(age / 86400) + " days");
        },
        []() -> bool {
            USER_MODALS_INFO_0* cur = nullptr;
            if (NetUserModalsGet(nullptr, 0, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_0 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod0_max_passwd_age = 7776000;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 0, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // PWD-MINAGE: Password minimum age >= 1 day
    // ------------------------------------------------------------------
    t.push_back({
        "PWD-MINAGE",
        "Password minimum age >= 1 day (prevents immediate re-use)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(1)", nullptr, "1.1.3", "1.1.3", nullptr, nullptr },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_0* m0 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 0, (LPBYTE*)&m0);
            if (r != NERR_Success || !m0)
                return Manual({"PWD-MINAGE","Password minimum age"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD age = m0->usrmod0_min_passwd_age;
            NetApiBufferFree(m0);
            if (age < 86400)
                return Fail({"PWD-MINAGE","Password minimum age"},
                    age == 0 ? "0 (can change immediately)" : std::to_string(age) + "s",
                    ">= 1 day (86400s)", true, "");
            return Pass({"PWD-MINAGE","Password minimum age"},
                std::to_string(age / 86400) + " day(s)");
        },
        []() -> bool {
            USER_MODALS_INFO_0* cur = nullptr;
            if (NetUserModalsGet(nullptr, 0, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_0 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod0_min_passwd_age = 86400;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 0, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // PWD-HIST: Password history >= 24
    // ------------------------------------------------------------------
    t.push_back({
        "PWD-HIST",
        "Password history >= 24 passwords remembered",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(1)", "3.5.8", "1.1.1", "1.1.1", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            USER_MODALS_INFO_0* m0 = nullptr;
            NET_API_STATUS r = NetUserModalsGet(nullptr, 0, (LPBYTE*)&m0);
            if (r != NERR_Success || !m0)
                return Manual({"PWD-HIST","Password history"},
                    "NetUserModalsGet failed — requires admin or domain context");
            DWORD hist = m0->usrmod0_password_hist_len;
            NetApiBufferFree(m0);
            if (hist < 24)
                return Fail({"PWD-HIST","Password history"},
                    std::to_string(hist), ">= 24", true, "");
            return Pass({"PWD-HIST","Password history"}, std::to_string(hist));
        },
        []() -> bool {
            USER_MODALS_INFO_0* cur = nullptr;
            if (NetUserModalsGet(nullptr, 0, (LPBYTE*)&cur) != NERR_Success || !cur) return false;
            USER_MODALS_INFO_0 upd = *cur;
            NetApiBufferFree(cur);
            upd.usrmod0_password_hist_len = 24;
            DWORD parm_err = 0;
            return NetUserSetModalInfo(nullptr, 0, (LPBYTE)&upd, &parm_err) == NERR_Success;
        }
    });

    // ------------------------------------------------------------------
    // PWD-CPX: Password complexity — manual check
    // ------------------------------------------------------------------
    t.push_back({
        "PWD-CPX",
        "Password complexity requirements enabled",
        STD_ALL,
        { "IA-5(1)", nullptr, "1.1.5", "1.1.5", "IA.1.076", nullptr },
        []() -> ComplianceFinding {
            return Manual({"PWD-CPX","Password complexity"},
                "secedit /export /cfg \"%temp%\\sec.cfg\"  "
                "then verify: PasswordComplexity = 1");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // LM-HASH: LM hash storage disabled
    // ------------------------------------------------------------------
    t.push_back({
        "LM-HASH",
        "LM hash storage disabled (NoLMHash=1)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(1)", "3.5.10", "2.3.11.6", "2.3.11.6", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa", "NoLMHash", v);
            if (!found || v < 1)
                return Fail({"LM-HASH","LM hash disabled"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"LM-HASH","LM hash disabled"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa", "NoLMHash", 1); }
    });

    // ------------------------------------------------------------------
    // LM-COMPAT: LAN Manager authentication level = 5 (NTLMv2 only)
    // ------------------------------------------------------------------
    t.push_back({
        "LM-COMPAT",
        "LAN Manager authentication level = 5 (NTLMv2 only, refuse LM/NTLM)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "IA-5(1)", "3.5.10", "2.3.11.7", "2.3.11.7", nullptr, "IA.3.083" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "LmCompatibilityLevel", v);
            if (!found || v < 5)
                return Fail({"LM-COMPAT","LM compatibility level"},
                    found ? std::to_string(v) : "not set (default 0)", "5", true, "");
            return Pass({"LM-COMPAT","LM compatibility level"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "LmCompatibilityLevel", 5); }
    });

    // ==================================================================
    // CM — Configuration Management additions
    // ==================================================================

    // ------------------------------------------------------------------
    // DEF-RT: Windows Defender real-time protection enabled
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-RT",
        "Windows Defender real-time protection enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SI-3", "3.14.2", "5.1", "5.1", "SI.1.210", "SI.1.210" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            // Policy path overrides product path; value=1 means disabled
            bool policyFound = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableRealtimeMonitoring", v);
            if (!policyFound)
                RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                    "DisableRealtimeMonitoring", v);
            if (v == 1)
                return Fail({"DEF-RT","Defender real-time protection"},
                    "1 (disabled)", "0 (enabled)", true, "");
            return Pass({"DEF-RT","Defender real-time protection"}, "0 (enabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableRealtimeMonitoring", 0); }
    });

    // ------------------------------------------------------------------
    // DEF-CLD: Windows Defender cloud-delivered protection
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-CLD",
        "Windows Defender cloud-delivered protection enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-3", nullptr, "5.1.2", "5.1.2", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
                "SpynetReporting", v);
            if (!found)
                found = RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender\\Spynet",
                    "SpynetReporting", v);
            if (!found || v == 0)
                return Fail({"DEF-CLD","Defender cloud protection"},
                    found ? "0 (disabled)" : "not set", ">= 1 (enabled)", true, "");
            return Pass({"DEF-CLD","Defender cloud protection"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
                "SpynetReporting", 2); }
    });

    // ------------------------------------------------------------------
    // DEF-PUA: Windows Defender PUA protection enabled
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-PUA",
        "Windows Defender PUA (Potentially Unwanted Application) protection enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-3", nullptr, "5.1.4", "5.1.4", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "PUAProtection", v);
            if (!found)
                found = RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender",
                    "PUAProtection", v);
            if (!found || v == 0)
                return Fail({"DEF-PUA","Defender PUA protection"},
                    found ? "0 (disabled)" : "not set", ">= 1 (enabled)", true, "");
            return Pass({"DEF-PUA","Defender PUA protection"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "PUAProtection", 1); }
    });

    // ------------------------------------------------------------------
    // DEF-TMP: Windows Defender Tamper Protection enabled
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-TMP",
        "Windows Defender Tamper Protection enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-7", nullptr, nullptr, "5.1.5", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows Defender\\Features",
                "TamperProtection", v);
            if (!found || v != 5)
                return Fail({"DEF-TMP","Defender Tamper Protection"},
                    found ? std::to_string(v) : "not set", "5 (enabled)", false,
                    "Tamper Protection can only be enabled via Windows Security UI or Intune, "
                    "not via registry when managed");
            return Pass({"DEF-TMP","Defender Tamper Protection"}, "5");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // DEF-CFA: Controlled Folder Access enabled
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-CFA",
        "Controlled Folder Access (ransomware protection) enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-3", "3.14.2", nullptr, nullptr, nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
                "Windows Defender Exploit Guard\\Controlled Folder Access",
                "EnableControlledFolderAccess", v);
            if (!found)
                found = RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender\\"
                    "Windows Defender Exploit Guard\\Controlled Folder Access",
                    "EnableControlledFolderAccess", v);
            if (!found || v < 1)
                return Fail({"DEF-CFA","Controlled Folder Access"},
                    found ? std::to_string(v) : "not set", "1 (enabled)", true, "");
            return Pass({"DEF-CFA","Controlled Folder Access"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
                "Windows Defender Exploit Guard\\Controlled Folder Access",
                "EnableControlledFolderAccess", 1); }
    });

    // ------------------------------------------------------------------
    // DEF-NP: Network Protection enabled
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-NP",
        "Windows Defender Network Protection enabled (block malicious connections)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-7", "3.13.1", nullptr, nullptr, nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
                "Windows Defender Exploit Guard\\Network Protection",
                "EnableNetworkProtection", v);
            if (!found)
                found = RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender\\"
                    "Windows Defender Exploit Guard\\Network Protection",
                    "EnableNetworkProtection", v);
            if (!found || v < 1)
                return Fail({"DEF-NP","Network Protection"},
                    found ? std::to_string(v) : "not set", "1 (block mode)", true, "");
            return Pass({"DEF-NP","Network Protection"}, std::to_string(v));
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
                "Windows Defender Exploit Guard\\Network Protection",
                "EnableNetworkProtection", 1); }
    });

    // ------------------------------------------------------------------
    // ASR-CFG: Attack Surface Reduction rules configured
    // ------------------------------------------------------------------
    t.push_back({
        "ASR-CFG",
        "Attack Surface Reduction (ASR) rules configured",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-3", nullptr, nullptr, "18.10.43.6.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            const char* keyPath =
                "SOFTWARE\\Microsoft\\Windows Defender\\"
                "Windows Defender Exploit Guard\\ASR\\Rules";
            HKEY hk;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hk) != ERROR_SUCCESS)
                return Fail({"ASR-CFG","ASR rules configured"},
                    "key not found", "at least one rule enabled", false,
                    "Enable ASR rules via: Set-MpPreference -AttackSurfaceReductionRules_Ids "
                    "<GUID> -AttackSurfaceReductionRules_Actions Enabled");
            DWORD numValues = 0;
            RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &numValues, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hk);
            if (numValues == 0)
                return Fail({"ASR-CFG","ASR rules configured"},
                    "key exists but no rules set", "at least one rule enabled", false,
                    "Enable ASR rules via: Set-MpPreference -AttackSurfaceReductionRules_Ids "
                    "<GUID> -AttackSurfaceReductionRules_Actions Enabled");
            return Pass({"ASR-CFG","ASR rules configured"},
                std::to_string(numValues) + " rule(s) configured");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // SVC-RREG: Remote Registry service disabled
    // ------------------------------------------------------------------
    t.push_back({
        "SVC-RREG",
        "Remote Registry service disabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-7", nullptr, "5.26", "5.26", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD st = SvcStartType("RemoteRegistry");
            if (st != SERVICE_DISABLED)
                return Fail({"SVC-RREG","Remote Registry disabled"},
                    st == (DWORD)-1 ? "not found" : "start type=" + std::to_string(st),
                    "4 (disabled)", true, "");
            return Pass({"SVC-RREG","Remote Registry disabled"}, "4 (disabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
                "Start", 4); }
    });

    // ------------------------------------------------------------------
    // SVC-TELNET: Telnet service disabled (or not installed)
    // ------------------------------------------------------------------
    t.push_back({
        "SVC-TELNET",
        "Telnet service disabled or not installed",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "CM-7", nullptr, "5.5", "5.5", "CM.1.074", "CM.2.061" },
        []() -> ComplianceFinding {
            DWORD st = SvcStartType("TlntSvr");
            if (st == (DWORD)-1)
                return Pass({"SVC-TELNET","Telnet service disabled"}, "not installed");
            if (st != SERVICE_DISABLED)
                return Fail({"SVC-TELNET","Telnet service disabled"},
                    "start type=" + std::to_string(st), "4 (disabled)", true, "");
            return Pass({"SVC-TELNET","Telnet service disabled"}, "4 (disabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\TlntSvr",
                "Start", 4); }
    });

    // ------------------------------------------------------------------
    // SVC-SNMP: SNMP service disabled (or not installed)
    // ------------------------------------------------------------------
    t.push_back({
        "SVC-SNMP",
        "SNMP service disabled or not installed (community strings in cleartext)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-7", nullptr, nullptr, "5.26", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD st = SvcStartType("SNMP");
            if (st == (DWORD)-1)
                return Pass({"SVC-SNMP","SNMP service disabled"}, "not installed");
            if (st != SERVICE_DISABLED)
                return Fail({"SVC-SNMP","SNMP service disabled"},
                    "start type=" + std::to_string(st), "4 (disabled)", true, "");
            return Pass({"SVC-SNMP","SNMP service disabled"}, "4 (disabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SNMP",
                "Start", 4); }
    });

    // ------------------------------------------------------------------
    // WSH-DIS: Windows Script Host disabled
    // ------------------------------------------------------------------
    t.push_back({
        "WSH-DIS",
        "Windows Script Host disabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-7", nullptr, "18.9.101", "18.9.101", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 1;  // default = enabled when key absent
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
                "Enabled", v);
            if (!found || v != 0)
                return Fail({"WSH-DIS","Windows Script Host disabled"},
                    found ? std::to_string(v) : "not set (enabled)", "0 (disabled)", true, "");
            return Pass({"WSH-DIS","Windows Script Host disabled"}, "0 (disabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
                "Enabled", 0); }
    });

    // ------------------------------------------------------------------
    // MSI-ELEV: AlwaysInstallElevated disabled
    // ------------------------------------------------------------------
    t.push_back({
        "MSI-ELEV",
        "Windows Installer AlwaysInstallElevated disabled (privilege escalation vector)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-7", nullptr, "18.9.85.2", "18.9.85.2", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                "AlwaysInstallElevated", v);
            if (found && v == 1)
                return Fail({"MSI-ELEV","AlwaysInstallElevated disabled"},
                    "1 (enabled — privilege escalation risk)", "0 or not set", true, "");
            return Pass({"MSI-ELEV","AlwaysInstallElevated disabled"},
                found ? std::to_string(v) : "not set (safe)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                "AlwaysInstallElevated", 0); }
    });

    // ==================================================================
    // AU — Audit and Accountability additions
    // ==================================================================

    // ------------------------------------------------------------------
    // LOG-SEC: Security event log minimum size >= 196608 KB
    // ------------------------------------------------------------------
    t.push_back({
        "LOG-SEC",
        "Security event log minimum size >= 196608 KB (192 MB)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-11", nullptr, "17.1.1", "17.1.1", nullptr, "AU.3.045" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            // Policy path stores value in KB
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
                "MaxSize", v);
            if (found) {
                if (v < 196608)
                    return Fail({"LOG-SEC","Security log size"},
                        std::to_string(v) + " KB", ">= 196608 KB", true, "");
                return Pass({"LOG-SEC","Security log size"}, std::to_string(v) + " KB");
            }
            // Fallback: service path stores value in bytes
            bool foundB = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
                "MaxSize", v);
            if (foundB) {
                if (v < 201326592)  // 196608 KB in bytes
                    return Fail({"LOG-SEC","Security log size"},
                        std::to_string(v / 1024) + " KB", ">= 196608 KB", true, "");
                return Pass({"LOG-SEC","Security log size"}, std::to_string(v / 1024) + " KB");
            }
            return Fail({"LOG-SEC","Security log size"}, "not configured", ">= 196608 KB", true, "");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
                "MaxSize", 196608); }
    });

    // ------------------------------------------------------------------
    // LOG-APP: Application event log minimum size >= 32768 KB
    // ------------------------------------------------------------------
    t.push_back({
        "LOG-APP",
        "Application event log minimum size >= 32768 KB (32 MB)",
        STD_NIST_80053 | STD_CIS_L1 | STD_CIS_L2,
        { "AU-11", nullptr, "17.9.1", "17.9.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application",
                "MaxSize", v);
            if (found) {
                if (v < 32768)
                    return Fail({"LOG-APP","Application log size"},
                        std::to_string(v) + " KB", ">= 32768 KB", true, "");
                return Pass({"LOG-APP","Application log size"}, std::to_string(v) + " KB");
            }
            bool foundB = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application",
                "MaxSize", v);
            if (foundB) {
                if (v < 33554432)  // 32768 KB in bytes
                    return Fail({"LOG-APP","Application log size"},
                        std::to_string(v / 1024) + " KB", ">= 32768 KB", true, "");
                return Pass({"LOG-APP","Application log size"}, std::to_string(v / 1024) + " KB");
            }
            return Fail({"LOG-APP","Application log size"}, "not configured", ">= 32768 KB", true, "");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application",
                "MaxSize", 32768); }
    });

    // ------------------------------------------------------------------
    // LOG-SYS: System event log minimum size >= 32768 KB
    // ------------------------------------------------------------------
    t.push_back({
        "LOG-SYS",
        "System event log minimum size >= 32768 KB (32 MB)",
        STD_NIST_80053 | STD_CIS_L1 | STD_CIS_L2,
        { "AU-11", nullptr, "17.9.5", "17.9.5", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System",
                "MaxSize", v);
            if (found) {
                if (v < 32768)
                    return Fail({"LOG-SYS","System log size"},
                        std::to_string(v) + " KB", ">= 32768 KB", true, "");
                return Pass({"LOG-SYS","System log size"}, std::to_string(v) + " KB");
            }
            bool foundB = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\EventLog\\System",
                "MaxSize", v);
            if (foundB) {
                if (v < 33554432)
                    return Fail({"LOG-SYS","System log size"},
                        std::to_string(v / 1024) + " KB", ">= 32768 KB", true, "");
                return Pass({"LOG-SYS","System log size"}, std::to_string(v / 1024) + " KB");
            }
            return Fail({"LOG-SYS","System log size"}, "not configured", ">= 32768 KB", true, "");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System",
                "MaxSize", 32768); }
    });

    // ------------------------------------------------------------------
    // AUD-ACMGMT: Audit user account management (success + failure)
    // GUID: {0CCE9236-69AE-11D9-BED3-505054503030}
    // ------------------------------------------------------------------
    t.push_back({
        "AUD-ACMGMT",
        "Audit User Account Management events enabled (Success + Failure)",
        STD_ALL,
        { "AU-2", nullptr, "17.2.1", "17.2.1", "AU.1.010", nullptr },
        []() -> ComplianceFinding {
            GUID g = { 0x0CCE9236, 0x69AE, 0x11D9,
                       {0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30} };
            CheckDef cd{ "AUD-ACMGMT",
                         "Audit User Account Management events enabled (Success + Failure)",
                         0, {}, {}, {} };
            return CheckAuditSub(cd, g, true, true, "User Account Management");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // AUD-PROC: Audit process creation (success)
    // GUID: {0CCE922B-69AE-11D9-BED3-505054503030}
    // ------------------------------------------------------------------
    t.push_back({
        "AUD-PROC",
        "Audit Process Creation events enabled (Success)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-12", "3.3.1", "17.8.1", "17.8.1", nullptr, "AU.2.041" },
        []() -> ComplianceFinding {
            GUID g = { 0x0CCE922B, 0x69AE, 0x11D9,
                       {0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30} };
            CheckDef cd{ "AUD-PROC", "Audit Process Creation events enabled (Success)",
                         0, {}, {}, {} };
            return CheckAuditSub(cd, g, true, false, "Process Creation");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // AUD-PRIV: Audit sensitive privilege use (success + failure)
    // GUID: {0CCE9228-69AE-11D9-BED3-505054503030}
    // ------------------------------------------------------------------
    t.push_back({
        "AUD-PRIV",
        "Audit Sensitive Privilege Use events enabled (Success + Failure)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-2", "3.3.1", nullptr, "17.7.1", nullptr, "AU.2.041" },
        []() -> ComplianceFinding {
            GUID g = { 0x0CCE9228, 0x69AE, 0x11D9,
                       {0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30} };
            CheckDef cd{ "AUD-PRIV",
                         "Audit Sensitive Privilege Use events enabled (Success + Failure)",
                         0, {}, {}, {} };
            return CheckAuditSub(cd, g, true, true, "Sensitive Privilege Use");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // AUD-POLCHG: Audit policy change (success)
    // GUID: {0CCE922F-69AE-11D9-BED3-505054503030}
    // ------------------------------------------------------------------
    t.push_back({
        "AUD-POLCHG",
        "Audit Policy Change events enabled (Success)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "AU-2", nullptr, "17.7.4", "17.7.4", nullptr, nullptr },
        []() -> ComplianceFinding {
            GUID g = { 0x0CCE922F, 0x69AE, 0x11D9,
                       {0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30} };
            CheckDef cd{ "AUD-POLCHG", "Audit Policy Change events enabled (Success)",
                         0, {}, {}, {} };
            return CheckAuditSub(cd, g, true, false, "Audit Policy Change");
        },
        nullptr
    });

    // ==================================================================
    // SC — System & Communications additions
    // ==================================================================

    // ------------------------------------------------------------------
    // DEP-POL: Data Execution Prevention policy
    // ------------------------------------------------------------------
    t.push_back({
        "DEP-POL",
        "Data Execution Prevention (DEP) policy enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-16", nullptr, "18.8.3.1", "18.8.3.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            DEP_SYSTEM_POLICY_TYPE pol = GetSystemDEPPolicy();
            // 0=AlwaysOff, 1=AlwaysOn, 2=OptIn, 3=OptOut
            if (pol == DEPPolicyAlwaysOff)
                return Fail({"DEP-POL","DEP policy"},
                    "AlwaysOff (0)", ">= OptIn (2)", false,
                    "Enable via: bcdedit /set {current} nx AlwaysOn  (requires reboot)");
            const char* names[] = { "AlwaysOff", "AlwaysOn", "OptIn", "OptOut" };
            std::string cur = (pol >= 0 && pol <= 3) ? names[pol] : std::to_string((int)pol);
            return Pass({"DEP-POL","DEP policy"}, cur);
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // ASLR-SYS: System-wide ASLR not disabled
    // ------------------------------------------------------------------
    t.push_back({
        "ASLR-SYS",
        "System-wide ASLR not disabled (MoveImages != 0)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-16", nullptr, nullptr, "18.8.3.2", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                "MoveImages", v);
            if (!found)
                return Pass({"ASLR-SYS","System ASLR"}, "not set (default ASLR enabled)");
            if (v == 0)
                return Fail({"ASLR-SYS","System ASLR"},
                    "0 (ASLR disabled)", "0xFFFFFFFF (force ASLR) or not set", true,
                    "Requires reboot to take effect");
            return Pass({"ASLR-SYS","System ASLR"}, "0x" + [v]{
                std::ostringstream ss; ss << std::hex << v; return ss.str(); }());
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                "MoveImages", 0xFFFFFFFF); }
    });

    // ------------------------------------------------------------------
    // SEHOP: Structured Exception Handling Overwrite Protection enabled
    // ------------------------------------------------------------------
    t.push_back({
        "SEHOP",
        "SEHOP (Structured Exception Handling Overwrite Protection) enabled",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-16", nullptr, nullptr, "18.8.3.3", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
                "DisableExceptionChainValidation", v);
            // Not set or 0 = SEHOP enabled (pass); 1 = disabled (fail)
            if (found && v == 1)
                return Fail({"SEHOP","SEHOP enabled"},
                    "1 (disabled)", "0 (enabled)", true, "");
            return Pass({"SEHOP","SEHOP enabled"}, found ? "0 (enabled)" : "not set (enabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
                "DisableExceptionChainValidation", 0); }
    });

    // ------------------------------------------------------------------
    // FW-BLK-DOM: Firewall Domain profile default inbound action = block
    // ------------------------------------------------------------------
    t.push_back({
        "FW-BLK-DOM",
        "Firewall Domain profile default inbound action = block",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SC-7", "3.13.1", "9.1.2", "9.1.2", "SC.1.175", "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\DomainProfile",
                "DefaultInboundAction", v);
            if (!found || v != 1)
                return Fail({"FW-BLK-DOM","FW Domain inbound block"},
                    found ? std::to_string(v) : "not set", "1 (block)", true, "");
            return Pass({"FW-BLK-DOM","FW Domain inbound block"}, "1 (block)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\DomainProfile",
                "DefaultInboundAction", 1); }
    });

    // ------------------------------------------------------------------
    // FW-BLK-PRI: Firewall Private profile default inbound action = block
    // ------------------------------------------------------------------
    t.push_back({
        "FW-BLK-PRI",
        "Firewall Private profile default inbound action = block",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SC-7", "3.13.1", "9.2.2", "9.2.2", "SC.1.175", "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\StandardProfile",
                "DefaultInboundAction", v);
            if (!found || v != 1)
                return Fail({"FW-BLK-PRI","FW Private inbound block"},
                    found ? std::to_string(v) : "not set", "1 (block)", true, "");
            return Pass({"FW-BLK-PRI","FW Private inbound block"}, "1 (block)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\StandardProfile",
                "DefaultInboundAction", 1); }
    });

    // ------------------------------------------------------------------
    // FW-BLK-PUB: Firewall Public profile default inbound action = block
    // ------------------------------------------------------------------
    t.push_back({
        "FW-BLK-PUB",
        "Firewall Public profile default inbound action = block",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SC-7", "3.13.1", "9.3.2", "9.3.2", "SC.1.175", "SC.3.177" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\PublicProfile",
                "DefaultInboundAction", v);
            if (!found || v != 1)
                return Fail({"FW-BLK-PUB","FW Public inbound block"},
                    found ? std::to_string(v) : "not set", "1 (block)", true, "");
            return Pass({"FW-BLK-PUB","FW Public inbound block"}, "1 (block)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
                "FirewallPolicy\\PublicProfile",
                "DefaultInboundAction", 1); }
    });

    // ------------------------------------------------------------------
    // SAFE-DLL: Safe DLL search mode enabled
    // ------------------------------------------------------------------
    t.push_back({
        "SAFE-DLL",
        "Safe DLL search mode enabled (SafeDllSearchMode=1)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "CM-6", nullptr, "18.4.1", "18.4.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 1;  // default when key absent = 1 (safe mode enabled)
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                "SafeDllSearchMode", v);
            if (found && v == 0)
                return Fail({"SAFE-DLL","Safe DLL search mode"},
                    "0 (disabled)", "1 (enabled)", true, "");
            return Pass({"SAFE-DLL","Safe DLL search mode"},
                found ? std::to_string(v) : "not set (default 1, enabled)");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                "SafeDllSearchMode", 1); }
    });

    // ------------------------------------------------------------------
    // NLOG-SIGN: Netlogon secure channel signing required
    // ------------------------------------------------------------------
    t.push_back({
        "NLOG-SIGN",
        "Netlogon secure channel data signing required",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-8", nullptr, "2.3.6.1", "2.3.6.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                "RequireSignOrSeal", v);
            if (!found || v < 1)
                return Fail({"NLOG-SIGN","Netlogon signing required"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"NLOG-SIGN","Netlogon signing required"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                "RequireSignOrSeal", 1); }
    });

    // ------------------------------------------------------------------
    // NLOG-SEAL: Netlogon secure channel encryption required
    // ------------------------------------------------------------------
    t.push_back({
        "NLOG-SEAL",
        "Netlogon secure channel data encryption required",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SC-8", nullptr, "2.3.6.2", "2.3.6.2", nullptr, nullptr },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                "SealSecureChannel", v);
            if (!found || v < 1)
                return Fail({"NLOG-SEAL","Netlogon encryption required"},
                    found ? std::to_string(v) : "not set", "1", true, "");
            return Pass({"NLOG-SEAL","Netlogon encryption required"}, "1");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                "SealSecureChannel", 1); }
    });

    // ==================================================================
    // SI — System & Information Integrity additions
    // ==================================================================

    // ------------------------------------------------------------------
    // WIN-UPD: Windows Update automatic download enabled
    // ------------------------------------------------------------------
    t.push_back({
        "WIN-UPD",
        "Windows Update automatic download enabled (NoAutoUpdate=0)",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SI-2", "3.14.1", "18.9.108", "18.9.108", "SI.1.210", "SI.1.210" },
        []() -> ComplianceFinding {
            DWORD noAuto = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                "NoAutoUpdate", noAuto);
            if (found && noAuto == 1)
                return Fail({"WIN-UPD","Windows Update auto-download"},
                    "1 (automatic updates disabled)", "0 (enabled)", true, "");
            return Pass({"WIN-UPD","Windows Update auto-download"},
                found ? std::to_string(noAuto) : "not set (enabled by default)");
        },
        []() -> bool {
            bool a = RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                "NoAutoUpdate", 0);
            bool b = RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
                "AUOptions", 4);
            return a && b;
        }
    });

    // ------------------------------------------------------------------
    // DEF-DEFS: Windows Defender signature update interval
    // ------------------------------------------------------------------
    t.push_back({
        "DEF-DEFS",
        "Windows Defender signature updates automatic",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L1 | STD_CMMC_L2,
        { "SI-3", "3.14.2", "5.1.3", "5.1.3", "SI.1.210", "SI.1.210" },
        []() -> ComplianceFinding {
            DWORD v = 0;
            bool found = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
                "SignatureUpdateInterval", v);
            if (!found)
                found = RegReadDword(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
                    "SignatureUpdateInterval", v);
            // If not configured or 0, Windows manages updates automatically (pass via manual)
            if (!found || v == 0)
                return Manual({"DEF-DEFS","Defender signature updates"},
                    "Windows Defender updates signatures automatically by default; "
                    "verify via: Get-MpComputerStatus | Select AntivirusSignatureAge");
            return Pass({"DEF-DEFS","Defender signature updates"},
                "interval=" + std::to_string(v) + "h");
        },
        nullptr
    });

    // ------------------------------------------------------------------
    // SMRT-SCR: Windows SmartScreen enabled
    // ------------------------------------------------------------------
    t.push_back({
        "SMRT-SCR",
        "Windows SmartScreen enabled for apps and files",
        STD_NIST_80053 | STD_NIST_800171 | STD_CIS_L1 | STD_CIS_L2 | STD_CMMC_L2,
        { "SI-3", nullptr, "18.9.85.1.1", "18.9.85.1.1", nullptr, nullptr },
        []() -> ComplianceFinding {
            // Check policy key first
            DWORD v = 0;
            bool policyFound = RegReadDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "EnableSmartScreen", v);
            if (policyFound) {
                if (v == 0)
                    return Fail({"SMRT-SCR","SmartScreen enabled"},
                        "0 (disabled by policy)", "1 (enabled)", true, "");
                return Pass({"SMRT-SCR","SmartScreen enabled"}, std::to_string(v));
            }
            // Fallback: Explorer key uses string value
            std::string sv;
            bool explorerFound = RegReadString(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                "SmartScreenEnabled", sv);
            if (explorerFound) {
                if (sv == "Off" || sv == "off")
                    return Fail({"SMRT-SCR","SmartScreen enabled"},
                        "Off", "On", true, "");
                return Pass({"SMRT-SCR","SmartScreen enabled"}, sv);
            }
            return Warn({"SMRT-SCR","SmartScreen enabled"},
                "not configured", "1 (enabled via policy)", true,
                "SmartScreen may be managed by Windows Security Center");
        },
        []{ return RegWriteDword(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "EnableSmartScreen", 1); }
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
