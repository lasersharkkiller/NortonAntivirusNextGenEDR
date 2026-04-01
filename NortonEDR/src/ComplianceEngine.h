#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

// ---------------------------------------------------------------------------
// Per-standard bitmask — a single check may be required by multiple standards.
// CIS L2 includes all L1 controls; CMMC L2 includes all CMMC L1 controls.
// ---------------------------------------------------------------------------
constexpr uint32_t STD_NIST_80053  = 0x01;
constexpr uint32_t STD_NIST_800171 = 0x02;
constexpr uint32_t STD_CIS_L1      = 0x04;
constexpr uint32_t STD_CIS_L2      = 0x08;
constexpr uint32_t STD_CMMC_L1     = 0x10;
constexpr uint32_t STD_CMMC_L2     = 0x20;
constexpr uint32_t STD_ALL         = 0x3F;

enum class ComplianceStandard {
    NIST_800_53,
    NIST_800_171,
    CIS_Level1,
    CIS_Level2,
    CMMC_Level1,
    CMMC_Level2,
};

enum class CheckResult {
    Pass,
    Fail,
    Warning,
    ManualCheck,   // cannot be determined automatically
};

// Cross-standard control reference numbers for a single check
struct ControlRef {
    const char* nist80053;   // e.g. "SC-28(1)"    or nullptr
    const char* nist800171;  // e.g. "3.13.16"     or nullptr
    const char* cisL1;       // CIS Benchmark L1 ref, nullptr if not a L1 control
    const char* cisL2;       // CIS Benchmark L2 ref, nullptr if not a L2 control
    const char* cmmcL1;      // CMMC L1 practice,   nullptr if not applicable
    const char* cmmcL2;      // CMMC L2 practice,   nullptr if not applicable
};

struct ComplianceFinding {
    std::string  id;             // short check identifier, e.g. "LSA-RPL"
    std::string  title;          // human-readable title
    std::string  controlRef;     // resolved control ID for the evaluated standard
    CheckResult  result;
    std::string  currentValue;
    std::string  requiredValue;
    bool         canHarden = false;
    std::string  hardenNote;     // shown when hardening is not automatic
};

class ComplianceEngine {
public:
    // Parse "nist800-53", "nist800-171", "cis-l1", "cis-l2",
    //        "cmmc-l1", "cmmc-l2" → enum.  Returns false if unknown.
    static bool ParseStandard(const std::string& name, ComplianceStandard& out);

    // Run evaluation for the selected standard, print the report,
    // then optionally apply hardening (autoHarden skips the interactive prompt).
    // Returns 0 on success, 1 on fatal error.
    static int RunEvaluation(ComplianceStandard standard, bool autoHarden);

private:
    static uint32_t    StandardMask(ComplianceStandard s);
    static std::string StandardName(ComplianceStandard s);
    static const char* ResolveRef(const ControlRef& refs, ComplianceStandard s);

    static std::vector<ComplianceFinding> Evaluate(ComplianceStandard s);
    static void PrintReport(const std::vector<ComplianceFinding>& f,
                            const std::string& standardName);
    static void ApplyHardening(const std::vector<ComplianceFinding>& findings,
                               ComplianceStandard s);
};
