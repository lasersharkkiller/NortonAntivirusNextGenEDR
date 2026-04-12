#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>

#include "Utils.h"
#include "ComplianceEngine.h"

#pragma comment(lib, "ftxui-component.lib")
#pragma comment(lib, "ftxui-dom.lib")
#pragma comment(lib, "ftxui-screen.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libyara.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")

#include <winevt.h>
#include <aclapi.h>
#include <sddl.h>
#include <evntrace.h>
#include <evntcons.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <winioctl.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wintrust.lib")

#include <wintrust.h>
#include <softpub.h>

using namespace ftxui;
using namespace std;

#define NORTONAV_RETRIEVE_DATA_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NORTONAV_RETRIEVE_DATA_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NORTONAV_RETRIEVE_DATA_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define END_THAT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x216, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NORTONAV_SET_INJECT_CONFIG  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NORTONAV_SET_NETWORK_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct HOOKDLL_INJECT_CONFIG {
    void*   LoadLibraryWAddress;
    ULONG   PathByteLen;
    ULONG   OwnerPid;
    wchar_t HookDllPath[260];
};

struct NETWORK_FILTER_CONFIG {
    UINT16 BlockedPorts[32];
    UINT32 NumBlockedPorts;
};

UINT32 curPid;

YR_COMPILER* compiler;
YR_RULES* rules;
YR_SCANNER* scanner = nullptr;
int yara_rules_count = 0;

std::queue<char*> g_bytesEvents;
std::queue<char*> g_fileEvents;

HANDLE hNortonDevice;

std::mutex security_event_mutex;
std::atomic<bool> should_update(false);

std::vector<std::string> tab_values{
    "Detection Events (0) | Score: 100 (SECURE)",
    "Processes",
    "About"
};
int tab_selected = 0;
auto tab_toggle = Toggle(&tab_values, &tab_selected);

std::vector<std::string> tab_1_menu_items{};
// Parallel to tab_1_menu_items — severity label per entry for color-coding.
// Written under security_event_mutex; read-only in the render thread (no lock
// needed: vector only grows and reads are color hints, not safety-critical).
std::vector<std::string> g_eventSeverityLabels;

auto screen = ScreenInteractive::Fullscreen();

int tab_1_selected = 0;

MenuOption g_detectionMenuOption = [] {
    MenuOption opt;
    opt.entries_option.transform = [](const EntryState& state) -> Element {
        Color itemColor = Color::Default;
        if (state.index < static_cast<int>(g_eventSeverityLabels.size())) {
            const std::string& sev = g_eventSeverityLabels[state.index];
            if      (sev == "critical") itemColor = Color::Red;
            else if (sev == "high")     itemColor = Color::RedLight;
            else if (sev == "medium")   itemColor = Color::Yellow;
            else if (sev == "low")      itemColor = Color::Cyan;
        }
        auto elem = text(state.label) | color(itemColor);
        if (state.focused) elem = elem | inverted;
        return elem;
    };
    return opt;
}();

auto tab_1_menu = Menu(&tab_1_menu_items, &tab_1_selected, g_detectionMenuOption);

std::unordered_set<std::string> benignFSPaths;
std::unordered_set<std::string> loadedYaraRulePaths;
std::unordered_set<std::string> lolDriverNames;
std::unordered_set<std::string> lolDriverHashes;   // lowercase hex SHA256
std::unordered_set<std::string> detectedLolDriverPaths;

const std::string kLoadedPotatoYaraRulesDir = R"(D:\Loaded-Potato\detections\yara)";
const std::string kLoadedPotatoLolDriversCachePath = R"(D:\Loaded-Potato\detections\loldrivers\loldrivers_cache.json)";
const std::string kLoadedPotatoSigmaRulesDir = R"(D:\Loaded-Potato\detections\sigma)";
const std::string kDefaultEventsLogPath = R"(C:\ProgramData\NortonEDR\events.jsonl)";
const std::string kCapaExePath          = "capa.exe"; // must be on PATH or same dir as the binary

enum class DetectionSeverity : int {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

struct CorrelationEvent {
    time_t timestamp;
    std::string method;
    DetectionSeverity severity;
};

struct SigmaLiteSelector {
    std::vector<std::string> containsAny;
    std::vector<std::string> containsAll;
    std::vector<std::string> startsWithAny;
    std::vector<std::string> endsWithAny;
};

struct SigmaLiteRule {
    std::string title;
    std::string level;
    std::string condition;
    std::unordered_map<std::string, SigmaLiteSelector> selectors;
};

std::unordered_map<UINT32, std::deque<CorrelationEvent>> g_recentEventsByPid;
std::unordered_map<UINT32, time_t> g_lastCorrelationAlertByPid;
std::array<int, 5> g_severityCounters = { 0, 0, 0, 0, 0 };
std::vector<SigmaLiteRule> g_sigmaRules;
std::unordered_set<std::string> g_sigmaMatchDedup;
struct DetectionEvent {
    std::string timestamp;
    std::string severity;
    UINT32 pid;
    std::string method;
    std::string summary;
    std::string details;
};

std::vector<DetectionEvent> g_detectionEvents; // structured store for API consumers
std::mutex events_log_mutex;

// Forward declarations
static std::string BuildEcsDocument(const std::string& severity, UINT32 pid,
    const std::string& method, const std::string& summary, const std::string& details);

// ---------------------------------------------------------------------------
// Sysmon event subscription
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_sysmonSubscription = nullptr;
static std::atomic<bool> g_sysmonStop(false);

// ---------------------------------------------------------------------------
// Security-log (SACL audit) subscription
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_saclSubscription = nullptr;
static std::atomic<bool> g_saclStop(false);
static bool              g_saclReady = false;

// ---------------------------------------------------------------------------
// ETW-TI (Microsoft-Windows-Threat-Intelligence) real-time session
// ---------------------------------------------------------------------------
static TRACEHANDLE       g_tiSessionHandle  = 0;
static TRACEHANDLE       g_tiTraceHandle    = INVALID_PROCESSTRACE_HANDLE;
static std::atomic<bool> g_tiStop(false);

// ---------------------------------------------------------------------------
// Microsoft-Windows-Kernel-Process ETW session (PPID spoofing detection)
// ---------------------------------------------------------------------------
static TRACEHANDLE       g_kpSessionHandle  = 0;
static TRACEHANDLE       g_kpTraceHandle    = INVALID_PROCESSTRACE_HANDLE;

// ---------------------------------------------------------------------------
// PowerShell script-block logging subscription
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_psSubscription = nullptr;
static std::atomic<bool> g_psStop(false);

// ---------------------------------------------------------------------------
// DNS-Client query subscription
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_dnsSubscription = nullptr;
static std::atomic<bool> g_dnsStop(false);

// ---------------------------------------------------------------------------
// WinRM operational subscription
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_winrmSubscription = nullptr;
static std::atomic<bool> g_winrmStop(false);

// ---------------------------------------------------------------------------
// Security event log — logon, privilege, process, service, task
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_secExtSubscription = nullptr;
static std::atomic<bool> g_secExtStop(false);

// ---------------------------------------------------------------------------
// Task Scheduler
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_taskSubscription = nullptr;
static std::atomic<bool> g_taskStop(false);

// ---------------------------------------------------------------------------
// Windows Defender
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_defenderSubscription = nullptr;
static std::atomic<bool> g_defenderStop(false);

// ---------------------------------------------------------------------------
// Print Spooler (PrintNightmare)
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_spoolerSubscription = nullptr;
static std::atomic<bool> g_spoolerStop(false);

// ---------------------------------------------------------------------------
// RDP — Terminal Services Remote Connection Manager
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_rdpSubscription = nullptr;
static std::atomic<bool> g_rdpStop(false);

// ---------------------------------------------------------------------------
// BITS Client
// ---------------------------------------------------------------------------
static EVT_HANDLE        g_bitsSubscription = nullptr;
static std::atomic<bool> g_bitsStop(false);

// ---------------------------------------------------------------------------
// Minifilter altitude registry audit
// ---------------------------------------------------------------------------
static std::atomic<bool> g_altitudeAuditStop(false);

struct TraceRuntimeConfig {
    std::vector<std::string> targetProcessNamesLower;
    bool includeChildren = false;
};

struct ProcessContext {
    UINT32 pid = 0;
    UINT32 parentPid = 0;
    std::string processName;
    std::string imagePath;
    std::string commandLine;
    time_t firstSeen = 0;
    time_t lastSeen = 0;
    bool observed = true;
};

struct ProcessSnapshotData {
    bool found = false;
    UINT32 parentPid = 0;
    std::string processName;
    std::string imagePath;
    std::string commandLine;
};

TraceRuntimeConfig g_traceConfig;
std::unordered_map<UINT32, ProcessContext> g_processCache;
std::mutex process_cache_mutex;
std::atomic<bool> g_apiServerStop(false);
int g_apiPort = 8091;
size_t g_apiEventLimit = 200;

// ---------------------------------------------------------------------------
// YARA async scan queue
// The kernel event polling threads enqueue work here so they are never
// blocked by a slow YARA scan.  A single dedicated worker drains the queue.
// ---------------------------------------------------------------------------
enum class YaraScanType { ByteStream, File };

struct YaraScanWork {
    YaraScanType type;
    // ByteStream fields
    std::vector<BYTE> bytes;
    KERNEL_STRUCTURED_BUFFER ksbHeader;
    // File fields
    std::string filePath;
    KERNEL_STRUCTURED_NOTIFICATION notifHeader;
};

static std::queue<YaraScanWork>   g_yaraScanQueue;
static std::mutex                  g_yaraScanMutex;
static std::condition_variable     g_yaraScanCv;
static std::atomic<bool>           g_yaraScanStop(false);
static const size_t                kYaraScanQueueMax = 512;

static std::queue<std::pair<std::string, UINT32>> g_capaQueue;
static std::mutex                                  g_capaMutex;
static std::condition_variable                     g_capaCv;
static std::atomic<bool>                           g_capaStop(false);
static std::unordered_set<std::string>             g_capaScanned;
static constexpr size_t                            kCapaQueueMax = 32;

// ---------------------------------------------------------------------------
// HookDll named-pipe server
// Receives telemetry lines from injected HookDll instances.
// Line format: SEVERITY\tCALLER_PID\tAPI_NAME\tTARGET_PID\tDETAIL\n
// ---------------------------------------------------------------------------
static std::atomic<bool> g_hookPipeStop(false);
static constexpr const char* kHookPipeName = "\\\\.\\pipe\\NortonEDR_HookDll";

// ---------------------------------------------------------------------------
// Elasticsearch shipper
// Events are enqueued from PushUiDetectionEvent and flushed in batches by
// ElasticShipperThread via WinHTTP POST to /<index>/_bulk.
// ---------------------------------------------------------------------------
struct ElasticConfig {
    std::string host;       // e.g. "https://localhost:9200"
    std::string index;      // e.g. "nortonav-events"
    std::string apiKey;     // base64 API key (Authorization: ApiKey <key>)
    std::string username;   // for Basic auth (alternative to apiKey)
    std::string password;
    bool        enabled   = false;
    bool        tlsVerify = true;   // set false with --elastic-no-verify
};
static ElasticConfig           g_elasticConfig;
static std::queue<std::string> g_elasticQueue;   // ECS JSON documents (one per event)
static std::mutex              g_elasticMutex;
static std::condition_variable g_elasticCv;
static std::atomic<bool>       g_elasticStop(false);
static constexpr size_t        kElasticQueueMax  = 1000;
static constexpr size_t        kElasticBatchSize = 50;
static constexpr int           kElasticFlushMs   = 5000;
static std::string             g_hostname;        // cached at startup

std::string startupAsciiTitle = R"(

   _   _            _              _____ ____  ____
  | \ | | ___  _ __| |_ ___  _ __ | ____|  _ \|  _ \
  |  \| |/ _ \| '__| __/ _ \| '_ \|  _| | | | | |_) |
  | |\  | (_) | |  | || (_) | | | | |___| |_| |  _ <
  |_| \_|\___/|_|   \__\___/|_| |_|_____|____/|_| \_\

       Norton NextGen Antivirus  |  Kernel EDR  |  v3

)";

std::vector<std::string> detectEventsDetails;

std::vector<std::string> SplitLines(const std::string& str) {
    std::stringstream ss(str);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(ss, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::wstring GetFullPath(const std::wstring& relativePath) {
    WCHAR fullPath[MAX_PATH];

    DWORD result = GetFullPathNameW(relativePath.c_str(), MAX_PATH, fullPath, nullptr);
    if (result == 0) {
        std::wcerr << L"Failed to get full path. Error: " << GetLastError() << std::endl;
        return L"";
    }

    return std::wstring(fullPath);
}

std::string QueryDosDevicePath(const std::string& devicePath) {
    char driveLetter = 'A';
    char deviceName[256];
    char targetPath[1024];
    DWORD result;

    for (driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter) {
        std::string drive = std::string(1, driveLetter) + ":";
        result = QueryDosDeviceA(drive.c_str(), deviceName, 256);
        if (result != 0) {
            if (devicePath.find(deviceName) == 0) {
                std::string fullPath = drive + devicePath.substr(strlen(deviceName));
                return fullPath;
            }
        }
    }
    return "";
}

std::string ToLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
        });

    return value;
}

std::string BuildTimestamp() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char date_time[80];
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(date_time);
}

// ---------------------------------------------------------------------------
// Event-log XML helpers (used by Sysmon and SACL subscribers)
// ---------------------------------------------------------------------------

// Render an EVT_HANDLE event to raw XML. Caller must free() the result.
static LPWSTR RenderEventXml(EVT_HANDLE hEvent) {
    DWORD bufferUsed = 0, propertyCount = 0;
    EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr,
              &bufferUsed, &propertyCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return nullptr;
    LPWSTR buf = static_cast<LPWSTR>(malloc(bufferUsed));
    if (!buf) return nullptr;
    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferUsed, buf,
                   &bufferUsed, &propertyCount)) {
        free(buf);
        return nullptr;
    }
    return buf;
}

// Extract first <Data Name='fieldName'>value</Data> from event XML.
static std::string XmlFieldValue(const std::wstring& xml, const std::wstring& fieldName) {
    std::wstring prefix = L"Name='" + fieldName + L"'>";
    auto pos = xml.find(prefix);
    if (pos == std::wstring::npos) {
        prefix = L"Name=\"" + fieldName + L"\">";
        pos = xml.find(prefix);
        if (pos == std::wstring::npos) return "";
    }
    pos += prefix.size();
    auto end = xml.find(L'<', pos);
    if (end == std::wstring::npos) return "";
    std::wstring wval = xml.substr(pos, end - pos);
    return std::string(wval.begin(), wval.end());
}

// Extract first <Element>value</Element> from event XML.
static std::string XmlElementValue(const std::wstring& xml, const std::wstring& element) {
    std::wstring open = L"<" + element + L">";
    auto pos = xml.find(open);
    if (pos == std::wstring::npos) return "";
    pos += open.size();
    auto end = xml.find(L"</" + element + L">", pos);
    if (end == std::wstring::npos) return "";
    std::wstring wval = xml.substr(pos, end - pos);
    return std::string(wval.begin(), wval.end());
}

// Render event XML and return as narrow string (lossy for non-ASCII, acceptable for field parsing).
static std::string RenderEventXmlStr(EVT_HANDLE hEvent) {
    LPWSTR buf = RenderEventXml(hEvent);
    if (!buf) return {};
    std::wstring ws(buf);
    free(buf);
    return std::string(ws.begin(), ws.end());
}

// Extract a named field from narrow event XML — tries Data Name='X' and <X> element formats.
static std::string GetXmlField(const std::string& xml, const std::string& fieldName) {
    std::string prefix = "Name='" + fieldName + "'>";
    auto pos = xml.find(prefix);
    if (pos == std::string::npos) {
        prefix = "Name=\"" + fieldName + "\">";
        pos = xml.find(prefix);
    }
    if (pos != std::string::npos) {
        pos += prefix.size();
        auto end = xml.find('<', pos);
        if (end != std::string::npos) return xml.substr(pos, end - pos);
    }
    std::string open = "<" + fieldName + ">";
    pos = xml.find(open);
    if (pos != std::string::npos) {
        pos += open.size();
        auto end = xml.find("</" + fieldName + ">", pos);
        if (end != std::string::npos) return xml.substr(pos, end - pos);
    }
    return {};
}

// Enable a named privilege in the current process token.
static bool EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
                                   nullptr, nullptr) != 0 &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(hToken);
    return ok;
}

std::string TrimCopy(const std::string& input) {
    size_t start = input.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }

    size_t end = input.find_last_not_of(" \t\r\n");
    return input.substr(start, end - start + 1);
}

std::string StripOuterQuotes(const std::string& input) {
    if (input.size() >= 2) {
        if ((input.front() == '"' && input.back() == '"') ||
            (input.front() == '\'' && input.back() == '\'')) {
            return input.substr(1, input.size() - 2);
        }
    }

    return input;
}

std::string RemoveYamlInlineComment(const std::string& input) {
    bool inSingleQuote = false;
    bool inDoubleQuote = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == '\'' && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
        }
        else if (c == '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
        }
        else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
            if (i == 0 || std::isspace(static_cast<unsigned char>(input[i - 1]))) {
                return TrimCopy(input.substr(0, i));
            }
        }
    }

    return TrimCopy(input);
}

std::string NormalizeSigmaValue(const std::string& rawValue) {
    std::string value = RemoveYamlInlineComment(TrimCopy(rawValue));
    value = StripOuterQuotes(value);
    value = TrimCopy(value);
    return ToLowerCopy(value);
}

bool EndsWith(const std::string& text, const std::string& suffix) {
    if (suffix.size() > text.size()) {
        return false;
    }

    return std::equal(suffix.rbegin(), suffix.rend(), text.rbegin());
}

bool StartsWith(const std::string& text, const std::string& prefix) {
    if (prefix.size() > text.size()) {
        return false;
    }

    return std::equal(prefix.begin(), prefix.end(), text.begin());
}

std::string JsonEscape(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (char c : input) {
        switch (c) {
        case '\\': output += "\\\\"; break;
        case '"': output += "\\\""; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default: output += c; break;
        }
    }

    return output;
}

std::string SeverityToLabel(DetectionSeverity severity) {
    switch (severity) {
    case DetectionSeverity::Critical: return "critical";
    case DetectionSeverity::High: return "high";
    case DetectionSeverity::Medium: return "medium";
    case DetectionSeverity::Low: return "low";
    case DetectionSeverity::Info:
    default:
        return "info";
    }
}

int SeverityPenalty(DetectionSeverity severity) {
    switch (severity) {
    case DetectionSeverity::Critical: return 25;
    case DetectionSeverity::High: return 15;
    case DetectionSeverity::Medium: return 8;
    case DetectionSeverity::Low: return 3;
    case DetectionSeverity::Info:
    default:
        return 1;
    }
}

int ComputeSecurityScoreLocked() {
    int penalty = 0;

    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Critical)] * SeverityPenalty(DetectionSeverity::Critical);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::High)] * SeverityPenalty(DetectionSeverity::High);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Medium)] * SeverityPenalty(DetectionSeverity::Medium);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Low)] * SeverityPenalty(DetectionSeverity::Low);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Info)] * SeverityPenalty(DetectionSeverity::Info);

    return std::max(0, 100 - penalty);
}

std::string SecurityLabelFromScore(int score) {
    if (score >= 90) {
        return "SECURE";
    }
    if (score >= 70) {
        return "FAIR";
    }
    if (score >= 50) {
        return "AT RISK";
    }
    if (score >= 25) {
        return "POOR";
    }

    return "CRITICAL";
}

std::string WideToUtf8(const std::wstring& input) {
    if (input.empty()) {
        return "";
    }

    int requiredSize = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (requiredSize <= 0) {
        return "";
    }

    std::string output(static_cast<size_t>(requiredSize), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, output.data(), requiredSize, nullptr, nullptr);
    if (!output.empty() && output.back() == '\0') {
        output.pop_back();
    }
    return output;
}

std::string SafeFixedBufferString(const char* buffer, size_t capacity) {
    if (buffer == nullptr || capacity == 0) {
        return "";
    }

    size_t safeLen = strnlen_s(buffer, capacity);
    return std::string(buffer, safeLen);
}

std::string NormalizeProcessTokenLower(const std::string& input) {
    return ToLowerCopy(StripOuterQuotes(TrimCopy(input)));
}

std::string BaseNameLower(const std::string& path) {
    std::string normalizedPath = StripOuterQuotes(TrimCopy(path));
    if (normalizedPath.empty()) {
        return "";
    }

    size_t slashPos = normalizedPath.find_last_of("\\/");
    if (slashPos == std::string::npos) {
        return ToLowerCopy(normalizedPath);
    }

    return ToLowerCopy(normalizedPath.substr(slashPos + 1));
}

void AppendCsvValues(const std::string& csv, std::vector<std::string>& output) {
    std::stringstream ss(csv);
    std::string value;
    while (std::getline(ss, value, ',')) {
        std::string normalized = NormalizeProcessTokenLower(value);
        if (!normalized.empty()) {
            output.push_back(normalized);
        }
    }
}

// Read the command line of a running process via PEB walk.
// Requires hProcess to be opened with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
// x64-only (fixed offsets: PEB+0x20 → ProcessParameters, +0x70 → CommandLine).
std::string QueryProcessCommandLine(HANDLE hProcess) {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto pfnNtQIP = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!pfnNtQIP) return "";

    // ProcessBasicInformation (0) → gives us PebBaseAddress
    struct { PVOID r1; PVOID PebBaseAddress; PVOID r2[2]; ULONG_PTR UniqueProcessId; PVOID r3; } pbi{};
    ULONG returnLen = 0;
    if (pfnNtQIP(hProcess, 0, &pbi, sizeof(pbi), &returnLen) != 0) return "";
    if (!pbi.PebBaseAddress) return "";

    // PEB+0x20 → ProcessParameters pointer
    PVOID processParameters = nullptr;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
                           &processParameters, sizeof(PVOID), &bytesRead)) return "";
    if (!processParameters) return "";

    // RTL_USER_PROCESS_PARAMETERS+0x70 → CommandLine (UNICODE_STRING: Length, MaxLength, Buffer)
    struct { USHORT Length; USHORT MaxLength; PWSTR Buffer; } cmdLine{};
    if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(processParameters) + 0x70,
                           &cmdLine, sizeof(cmdLine), &bytesRead)) return "";
    if (!cmdLine.Buffer || cmdLine.Length == 0) return "";

    std::vector<WCHAR> wbuf(cmdLine.Length / sizeof(WCHAR) + 1, L'\0');
    if (!ReadProcessMemory(hProcess, cmdLine.Buffer, wbuf.data(), cmdLine.Length, &bytesRead)) return "";
    return WideToUtf8(std::wstring(wbuf.data(), cmdLine.Length / sizeof(WCHAR)));
}

ProcessSnapshotData CollectProcessSnapshot(UINT32 pid) {
    ProcessSnapshotData snapshot;
    if (pid == 0) {
        return snapshot;
    }

    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshotHandle, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == pid) {
                    snapshot.found = true;
                    snapshot.parentPid = processEntry.th32ParentProcessID;
                    snapshot.processName = WideToUtf8(processEntry.szExeFile);
                    break;
                }
            } while (Process32NextW(snapshotHandle, &processEntry));
        }

        CloseHandle(snapshotHandle);
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (processHandle != nullptr) {
        char fullPath[MAX_PATH * 4] = { 0 };
        DWORD fullPathSize = static_cast<DWORD>(sizeof(fullPath));
        if (QueryFullProcessImageNameA(processHandle, 0, fullPath, &fullPathSize)) {
            snapshot.imagePath = std::string(fullPath, fullPathSize);
            if (snapshot.processName.empty()) {
                snapshot.processName = BaseNameLower(snapshot.imagePath);
            }
        }
        snapshot.commandLine = QueryProcessCommandLine(processHandle);
        CloseHandle(processHandle);
    }

    return snapshot;
}

bool MatchesTraceTargetNameLocked(const ProcessContext& context) {
    if (g_traceConfig.targetProcessNamesLower.empty()) {
        return true;
    }

    std::vector<std::string> candidates = {
        NormalizeProcessTokenLower(context.processName),
        BaseNameLower(context.processName),
        NormalizeProcessTokenLower(context.imagePath),
        BaseNameLower(context.imagePath)
    };

    for (const auto& target : g_traceConfig.targetProcessNamesLower) {
        if (target.empty()) {
            continue;
        }

        bool targetHasExeSuffix = EndsWith(target, ".exe");
        for (const auto& candidate : candidates) {
            if (candidate.empty()) {
                continue;
            }

            if (candidate == target || EndsWith(candidate, "\\" + target)) {
                return true;
            }

            if (!targetHasExeSuffix) {
                const std::string targetExe = target + ".exe";
                if (candidate == targetExe || EndsWith(candidate, "\\" + targetExe)) {
                    return true;
                }
            }
        }
    }

    return false;
}

void RecomputeObservedProcessesLocked() {
    if (g_traceConfig.targetProcessNamesLower.empty()) {
        for (auto& [pid, context] : g_processCache) {
            context.observed = true;
        }
        return;
    }

    for (auto& [pid, context] : g_processCache) {
        context.observed = MatchesTraceTargetNameLocked(context);
    }

    if (!g_traceConfig.includeChildren) {
        return;
    }

    bool changed = false;
    do {
        changed = false;
        for (auto& [pid, context] : g_processCache) {
            if (context.observed || context.parentPid == 0) {
                continue;
            }

            auto parentIt = g_processCache.find(context.parentPid);
            if (parentIt != g_processCache.end() && parentIt->second.observed) {
                context.observed = true;
                changed = true;
            }
        }
    } while (changed);
}

static std::atomic<time_t> g_lastCacheEviction{ 0 };
static const time_t kCacheEvictionIntervalSec = 60;

// Must be called with process_cache_mutex held.
void PruneProcessCacheLocked() {
    std::vector<UINT32> toRemove;
    for (const auto& [pid, context] : g_processCache) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) {
            toRemove.push_back(pid);
            continue;
        }
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(h, &exitCode);
        CloseHandle(h);
        if (exitCode != STILL_ACTIVE) {
            toRemove.push_back(pid);
        }
    }
    for (UINT32 deadPid : toRemove) {
        g_processCache.erase(deadPid);
    }
}

void UpsertProcessContext(UINT32 pid, const std::string& processNameHint) {
    if (pid == 0) {
        return;
    }

    ProcessSnapshotData snapshot = CollectProcessSnapshot(pid);
    time_t now = time(0);

    std::lock_guard<std::mutex> lock(process_cache_mutex);

    // Periodically evict terminated processes to bound cache growth.
    time_t lastEviction = g_lastCacheEviction.load(std::memory_order_relaxed);
    if (now - lastEviction >= kCacheEvictionIntervalSec) {
        g_lastCacheEviction.store(now, std::memory_order_relaxed);
        PruneProcessCacheLocked();
    }

    ProcessContext& context = g_processCache[pid];
    if (context.pid == 0) {
        context.pid = pid;
        context.firstSeen = now;
    }

    context.lastSeen = now;

    if (!processNameHint.empty()) {
        context.processName = processNameHint;
    }

    if (context.processName.empty() && !snapshot.processName.empty()) {
        context.processName = snapshot.processName;
    }

    if (context.parentPid == 0 && snapshot.parentPid != 0) {
        context.parentPid = snapshot.parentPid;
    }

    if (context.imagePath.empty() && !snapshot.imagePath.empty()) {
        context.imagePath = snapshot.imagePath;
    }

    if (context.commandLine.empty() && !snapshot.commandLine.empty()) {
        context.commandLine = snapshot.commandLine;
    }

    if (g_traceConfig.targetProcessNamesLower.empty()) {
        context.observed = true;
    }
    else if (!g_traceConfig.includeChildren) {
        context.observed = MatchesTraceTargetNameLocked(context);
    }
    else {
        RecomputeObservedProcessesLocked();
    }
}

bool ShouldHandlePidEvent(UINT32 pid, const std::string& processNameHint) {
    if (pid == 0 || pid == curPid) {
        return false;
    }

    UpsertProcessContext(pid, processNameHint);

    std::lock_guard<std::mutex> lock(process_cache_mutex);
    if (g_traceConfig.targetProcessNamesLower.empty()) {
        return true;
    }

    auto it = g_processCache.find(pid);
    if (it == g_processCache.end()) {
        return false;
    }

    return it->second.observed;
}

std::string GetProcessCommandLineCached(UINT32 pid) {
    if (pid == 0) return "";
    std::lock_guard<std::mutex> lock(process_cache_mutex);
    auto it = g_processCache.find(pid);
    if (it == g_processCache.end()) return "";
    return it->second.commandLine;
}

std::string GetProcessEnrichment(UINT32 pid) {
    if (pid == 0) {
        return "";
    }

    std::lock_guard<std::mutex> lock(process_cache_mutex);
    auto it = g_processCache.find(pid);
    if (it == g_processCache.end()) {
        return "";
    }

    const ProcessContext& context = it->second;
    std::string enrichment;
    if (context.parentPid != 0) {
        enrichment += " | Parent PID: " + std::to_string(context.parentPid);
    }
    if (!context.imagePath.empty()) {
        enrichment += " | Image: " + context.imagePath;
    }
    if (!context.commandLine.empty()) {
        enrichment += " | CmdLine: " + context.commandLine;
    }

    return enrichment;
}

std::string BuildTraceTargetsJsonArray() {
    std::lock_guard<std::mutex> lock(process_cache_mutex);
    std::string out = "[";
    for (size_t i = 0; i < g_traceConfig.targetProcessNamesLower.size(); ++i) {
        out += "\"" + JsonEscape(g_traceConfig.targetProcessNamesLower[i]) + "\"";
        if (i + 1 < g_traceConfig.targetProcessNamesLower.size()) {
            out += ",";
        }
    }
    out += "]";
    return out;
}

void ResetDetectionState() {
    {
        std::lock_guard<std::mutex> lock(security_event_mutex);
        tab_1_menu_items.clear();
        detectEventsDetails.clear();
        g_eventSeverityLabels.clear();
        g_detectionEvents.clear();
        tab_1_selected = 0;
        g_recentEventsByPid.clear();
        g_lastCorrelationAlertByPid.clear();
        g_sigmaMatchDedup.clear();
        detectedLolDriverPaths.clear();
        g_severityCounters = { 0, 0, 0, 0, 0 };
        tab_values[0] = "Detection Events (0) | Score: 100 (SECURE)";
        should_update = true;
    }

    screen.PostEvent(Event::Custom);
}

std::string BuildApiStatsJson() {
    size_t eventsCount = 0;
    int score = 100;
    int infoCount = 0;
    int lowCount = 0;
    int mediumCount = 0;
    int highCount = 0;
    int criticalCount = 0;

    {
        std::lock_guard<std::mutex> lock(security_event_mutex);
        eventsCount = tab_1_menu_items.size();
        score = ComputeSecurityScoreLocked();
        infoCount = g_severityCounters[static_cast<int>(DetectionSeverity::Info)];
        lowCount = g_severityCounters[static_cast<int>(DetectionSeverity::Low)];
        mediumCount = g_severityCounters[static_cast<int>(DetectionSeverity::Medium)];
        highCount = g_severityCounters[static_cast<int>(DetectionSeverity::High)];
        criticalCount = g_severityCounters[static_cast<int>(DetectionSeverity::Critical)];
    }

    size_t processCount = 0;
    size_t observedProcessCount = 0;
    bool includeChildren = false;

    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        processCount = g_processCache.size();
        includeChildren = g_traceConfig.includeChildren;
        for (const auto& [pid, context] : g_processCache) {
            if (context.observed) {
                observedProcessCount += 1;
            }
        }
    }

    std::string json = "{";
    json += "\"events_count\":" + std::to_string(eventsCount) + ",";
    json += "\"security_score\":" + std::to_string(score) + ",";
    json += "\"security_label\":\"" + SecurityLabelFromScore(score) + "\",";
    json += "\"severity\":{";
    json += "\"critical\":" + std::to_string(criticalCount) + ",";
    json += "\"high\":" + std::to_string(highCount) + ",";
    json += "\"medium\":" + std::to_string(mediumCount) + ",";
    json += "\"low\":" + std::to_string(lowCount) + ",";
    json += "\"info\":" + std::to_string(infoCount);
    json += "},";
    json += "\"process_cache_count\":" + std::to_string(processCount) + ",";
    json += "\"observed_process_count\":" + std::to_string(observedProcessCount) + ",";
    json += "\"trace_children\":" + std::string(includeChildren ? "true" : "false") + ",";
    json += "\"trace_targets\":" + BuildTraceTargetsJsonArray();
    json += "}";
    return json;
}

std::string BuildApiEventsJson(size_t limit) {
    std::vector<DetectionEvent> snapshot;
    {
        std::lock_guard<std::mutex> lock(security_event_mutex);
        snapshot = g_detectionEvents;
    }

    if (limit == 0) limit = 1;
    size_t start = snapshot.size() > limit ? snapshot.size() - limit : 0;

    std::string json = "[";
    for (size_t i = start; i < snapshot.size(); ++i) {
        const DetectionEvent& e = snapshot[i];
        json += "{";
        json += "\"index\":" + std::to_string(i) + ",";
        json += "\"timestamp\":\"" + JsonEscape(e.timestamp) + "\",";
        json += "\"severity\":\"" + e.severity + "\",";
        json += "\"pid\":" + std::to_string(e.pid) + ",";
        json += "\"method\":\"" + JsonEscape(e.method) + "\",";
        json += "\"summary\":\"" + JsonEscape(e.summary) + "\",";
        json += "\"details\":\"" + JsonEscape(e.details) + "\"";
        json += "}";
        if (i + 1 < snapshot.size()) json += ",";
    }
    json += "]";
    return json;
}

std::string BuildApiProcessesJson() {
    std::vector<ProcessContext> processes;
    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        processes.reserve(g_processCache.size());
        for (const auto& [pid, context] : g_processCache) {
            processes.push_back(context);
        }
    }

    std::string json = "[";
    for (size_t i = 0; i < processes.size(); ++i) {
        const ProcessContext& context = processes[i];
        json += "{";
        json += "\"pid\":" + std::to_string(context.pid) + ",";
        json += "\"parent_pid\":" + std::to_string(context.parentPid) + ",";
        json += "\"process_name\":\"" + JsonEscape(context.processName) + "\",";
        json += "\"image_path\":\"" + JsonEscape(context.imagePath) + "\",";
        json += "\"observed\":" + std::string(context.observed ? "true" : "false") + ",";
        json += "\"first_seen\":" + std::to_string(static_cast<long long>(context.firstSeen)) + ",";
        json += "\"last_seen\":" + std::to_string(static_cast<long long>(context.lastSeen)) + ",";
        json += "\"command_line\":\"" + JsonEscape(context.commandLine) + "\"";
        json += "}";
        if (i + 1 < processes.size()) {
            json += ",";
        }
    }
    json += "]";
    return json;
}

std::string HttpStatusText(int statusCode) {
    switch (statusCode) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default: return "Internal Server Error";
    }
}

void SendHttpResponse(SOCKET clientSocket, int statusCode, const std::string& body, const std::string& contentType = "application/json") {
    std::string response =
        "HTTP/1.1 " + std::to_string(statusCode) + " " + HttpStatusText(statusCode) + "\r\n" +
        "Content-Type: " + contentType + "\r\n" +
        "Connection: close\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" +
        body;

    send(clientSocket, response.c_str(), static_cast<int>(response.size()), 0);
}

size_t ParseEventsLimitFromPath(const std::string& path) {
    size_t queryPos = path.find('?');
    if (queryPos == std::string::npos) {
        return g_apiEventLimit;
    }

    std::string query = path.substr(queryPos + 1);
    const std::string key = "limit=";
    size_t limitPos = query.find(key);
    if (limitPos == std::string::npos) {
        return g_apiEventLimit;
    }

    std::string rawLimit = query.substr(limitPos + key.size());
    size_t ampPos = rawLimit.find('&');
    if (ampPos != std::string::npos) {
        rawLimit = rawLimit.substr(0, ampPos);
    }

    try {
        size_t parsed = static_cast<size_t>(std::stoul(rawLimit));
        return std::max<size_t>(1, std::min<size_t>(parsed, 5000));
    }
    catch (...) {
        return g_apiEventLimit;
    }
}

std::string StripQuery(const std::string& path) {
    size_t queryPos = path.find('?');
    if (queryPos == std::string::npos) {
        return path;
    }

    return path.substr(0, queryPos);
}

void HandleApiRequest(const std::string& method, const std::string& path, SOCKET clientSocket) {
    std::string cleanPath = StripQuery(path);

    if (cleanPath == "/api/stats" && method == "GET") {
        SendHttpResponse(clientSocket, 200, BuildApiStatsJson());
        return;
    }

    if (cleanPath == "/api/events" && method == "GET") {
        SendHttpResponse(clientSocket, 200, BuildApiEventsJson(ParseEventsLimitFromPath(path)));
        return;
    }

    if (cleanPath == "/api/processes" && method == "GET") {
        SendHttpResponse(clientSocket, 200, BuildApiProcessesJson());
        return;
    }

    if (cleanPath == "/api/reset") {
        if (method != "POST" && method != "GET") {
            SendHttpResponse(clientSocket, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }

        ResetDetectionState();
        SendHttpResponse(clientSocket, 200, "{\"status\":\"ok\"}");
        return;
    }

    SendHttpResponse(clientSocket, 404, "{\"error\":\"not_found\"}");
}

void RunLocalApiServer() {
    if (g_apiPort <= 0) {
        return;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[*] API: WSAStartup failed.\n";
        return;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[*] API: socket creation failed.\n";
        WSACleanup();
        return;
    }

    sockaddr_in serviceAddr{};
    serviceAddr.sin_family = AF_INET;
    serviceAddr.sin_port = htons(static_cast<u_short>(g_apiPort));
    inet_pton(AF_INET, "127.0.0.1", &serviceAddr.sin_addr);

    if (::bind(listenSocket, reinterpret_cast<SOCKADDR*>(&serviceAddr), sizeof(serviceAddr)) == SOCKET_ERROR) {
        std::cerr << "[*] API: bind failed on 127.0.0.1:" << g_apiPort << "\n";
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[*] API: listen failed.\n";
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    std::cout << "[*] API: listening on http://127.0.0.1:" << g_apiPort << "\n";

    while (!g_apiServerStop.load()) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listenSocket, &readSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
        if (selectResult <= 0) {
            continue;
        }

        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }

        char requestBuffer[8192] = { 0 };
        int received = recv(clientSocket, requestBuffer, static_cast<int>(sizeof(requestBuffer) - 1), 0);
        if (received > 0) {
            std::string request(requestBuffer, received);
            std::istringstream requestStream(request);
            std::string method;
            std::string path;
            std::string version;
            requestStream >> method >> path >> version;

            if (method.empty() || path.empty()) {
                SendHttpResponse(clientSocket, 400, "{\"error\":\"bad_request\"}");
            }
            else {
                HandleApiRequest(method, path, clientSocket);
            }
        }
        else {
            SendHttpResponse(clientSocket, 400, "{\"error\":\"bad_request\"}");
        }

        closesocket(clientSocket);
    }

    closesocket(listenSocket);
    WSACleanup();
}

void PushUniqueValue(std::vector<std::string>& target, const std::string& value) {
    std::string normalized = NormalizeSigmaValue(value);
    if (normalized.empty()) {
        return;
    }

    if (std::find(target.begin(), target.end(), normalized) == target.end()) {
        target.push_back(normalized);
    }
}

std::string ValueAfterColon(const std::string& line) {
    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos || colonPos + 1 >= line.size()) {
        return "";
    }

    return TrimCopy(line.substr(colonPos + 1));
}

bool ParseSigmaRuleFile(const std::filesystem::path& filePath, SigmaLiteRule& outRule) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    enum class SigmaParseMode {
        None,
        ContainsAny,
        ContainsAll,
        StartsWithAny,
        EndsWithAny
    };

    auto updateSelectorModeFromLine = [](
        const std::string& trimmedLine,
        SigmaLiteSelector& selector,
        SigmaParseMode& currentMode
        ) -> bool {
            if (trimmedLine.find("|contains|all:") != std::string::npos) {
                currentMode = SigmaParseMode::ContainsAll;
                PushUniqueValue(selector.containsAll, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|contains:") != std::string::npos) {
                currentMode = SigmaParseMode::ContainsAny;
                PushUniqueValue(selector.containsAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|startswith:") != std::string::npos) {
                currentMode = SigmaParseMode::StartsWithAny;
                PushUniqueValue(selector.startsWithAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|endswith:") != std::string::npos) {
                currentMode = SigmaParseMode::EndsWithAny;
                PushUniqueValue(selector.endsWithAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.rfind("keywords:", 0) == 0) {
                currentMode = SigmaParseMode::ContainsAny;
                PushUniqueValue(selector.containsAny, ValueAfterColon(trimmedLine));
                return true;
            }

            return false;
        };

    auto lineIndent = [](const std::string& lineValue) -> int {
        int count = 0;
        for (char c : lineValue) {
            if (c == ' ') {
                count += 1;
            }
            else if (c == '\t') {
                count += 4;
            }
            else {
                break;
            }
        }
        return count;
        };

    SigmaParseMode currentMode = SigmaParseMode::None;
    bool inDetection = false;
    int detectionIndent = -1;
    int detectionChildIndent = -1;
    std::string currentSelectorName;
    std::string line;

    while (std::getline(file, line)) {
        std::string trimmed = TrimCopy(line);
        if (trimmed.empty()) {
            continue;
        }

        if (trimmed.rfind("title:", 0) == 0) {
            outRule.title = TrimCopy(StripOuterQuotes(ValueAfterColon(trimmed)));
            continue;
        }
        if (trimmed.rfind("level:", 0) == 0) {
            outRule.level = ToLowerCopy(TrimCopy(StripOuterQuotes(ValueAfterColon(trimmed))));
            continue;
        }
        if (trimmed.rfind("detection:", 0) == 0) {
            inDetection = true;
            detectionIndent = lineIndent(line);
            detectionChildIndent = -1;
            currentMode = SigmaParseMode::None;
            currentSelectorName.clear();
            continue;
        }

        if (!inDetection) {
            continue;
        }

        int indent = lineIndent(line);
        if (indent <= detectionIndent && trimmed.find(':') != std::string::npos) {
            break;
        }

        if (detectionChildIndent == -1) {
            detectionChildIndent = indent;
        }

        if (indent == detectionChildIndent && trimmed.find(':') != std::string::npos) {
            std::string selectorKey = ToLowerCopy(TrimCopy(line.substr(0, line.find(':'))));
            std::string selectorValue = ValueAfterColon(trimmed);

            if (selectorKey == "condition") {
                outRule.condition = ToLowerCopy(TrimCopy(StripOuterQuotes(selectorValue)));
                currentSelectorName.clear();
                currentMode = SigmaParseMode::None;
                continue;
            }

            currentSelectorName = selectorKey;
            SigmaLiteSelector& selector = outRule.selectors[currentSelectorName];
            currentMode = SigmaParseMode::None;

            if (currentSelectorName == "keywords") {
                currentMode = SigmaParseMode::ContainsAny;
            }

            if (updateSelectorModeFromLine(trimmed, selector, currentMode)) {
                continue;
            }

            if (!selectorValue.empty()) {
                if (currentMode == SigmaParseMode::None) {
                    currentMode = SigmaParseMode::ContainsAny;
                }
                PushUniqueValue(selector.containsAny, selectorValue);
            }

            continue;
        }

        if (currentSelectorName.empty()) {
            continue;
        }

        SigmaLiteSelector& currentSelector = outRule.selectors[currentSelectorName];

        if (updateSelectorModeFromLine(trimmed, currentSelector, currentMode)) {
            continue;
        }

        if (trimmed.rfind("-", 0) == 0) {
            std::string listValue = TrimCopy(trimmed.substr(1));
            if (listValue.empty()) {
                continue;
            }

            if (updateSelectorModeFromLine(listValue, currentSelector, currentMode)) {
                continue;
            }

            switch (currentMode) {
            case SigmaParseMode::ContainsAny:
                PushUniqueValue(currentSelector.containsAny, listValue);
                break;
            case SigmaParseMode::ContainsAll:
                PushUniqueValue(currentSelector.containsAll, listValue);
                break;
            case SigmaParseMode::StartsWithAny:
                PushUniqueValue(currentSelector.startsWithAny, listValue);
                break;
            case SigmaParseMode::EndsWithAny:
                PushUniqueValue(currentSelector.endsWithAny, listValue);
                break;
            case SigmaParseMode::None:
            default:
                break;
            }
        }
        else {
            std::string inlineValue = ValueAfterColon(trimmed);
            if (!inlineValue.empty()) {
                if (currentMode == SigmaParseMode::None) {
                    currentMode = SigmaParseMode::ContainsAny;
                }
                PushUniqueValue(currentSelector.containsAny, inlineValue);
            }
        }
    }

    if (outRule.title.empty()) {
        outRule.title = filePath.stem().string();
    }
    if (outRule.level.empty()) {
        outRule.level = "medium";
    }
    if (outRule.condition.empty()) {
        outRule.condition = "1 of them";
    }

    return !outRule.selectors.empty();
}

void LoadSigmaRules(const std::string& sigmaDirectory) {
    std::error_code existsError;
    if (!std::filesystem::exists(sigmaDirectory, existsError)) {
        std::cerr << "[*] Sigma directory not found: " << sigmaDirectory << "\n";
        return;
    }

    size_t previousRuleCount = g_sigmaRules.size();
    std::error_code iterError;
    std::filesystem::recursive_directory_iterator it(
        sigmaDirectory,
        std::filesystem::directory_options::skip_permission_denied,
        iterError
    );
    std::filesystem::recursive_directory_iterator end;

    if (iterError) {
        std::cerr << "[*] Failed to iterate Sigma directory: " << sigmaDirectory
            << " (" << iterError.message() << ")\n";
        return;
    }

    for (; it != end; it.increment(iterError)) {
        if (iterError) {
            iterError.clear();
            continue;
        }

        const auto& entry = *it;
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string extension = ToLowerCopy(entry.path().extension().string());
        if (extension != ".yml" && extension != ".yaml") {
            continue;
        }

        SigmaLiteRule parsedRule;
        if (ParseSigmaRuleFile(entry.path(), parsedRule)) {
            g_sigmaRules.push_back(std::move(parsedRule));
        }
    }

    std::cout << "[*] " << (g_sigmaRules.size() - previousRuleCount)
        << " Sigma-Lite rules loaded from " << sigmaDirectory << "\n";
}

bool PatternFoundInFields(const std::vector<std::string>& fields, const std::string& pattern) {
    for (const auto& field : fields) {
        if (field.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool SelectorMatchesSigmaLite(const SigmaLiteSelector& selector, const std::vector<std::string>& fieldsLower) {
    bool hasOptional = !selector.containsAny.empty() || !selector.startsWithAny.empty() || !selector.endsWithAny.empty();
    bool optionalMatched = false;

    for (const auto& pattern : selector.containsAny) {
        if (PatternFoundInFields(fieldsLower, pattern)) {
            optionalMatched = true;
            break;
        }
    }

    if (!optionalMatched) {
        for (const auto& pattern : selector.startsWithAny) {
            for (const auto& field : fieldsLower) {
                if (StartsWith(field, pattern)) {
                    optionalMatched = true;
                    break;
                }
            }
            if (optionalMatched) {
                break;
            }
        }
    }

    if (!optionalMatched) {
        for (const auto& pattern : selector.endsWithAny) {
            for (const auto& field : fieldsLower) {
                if (EndsWith(field, pattern)) {
                    optionalMatched = true;
                    break;
                }
            }
            if (optionalMatched) {
                break;
            }
        }
    }

    bool requiredMatched = true;
    for (const auto& requiredPattern : selector.containsAll) {
        if (!PatternFoundInFields(fieldsLower, requiredPattern)) {
            requiredMatched = false;
            break;
        }
    }

    if (!requiredMatched) {
        return false;
    }

    if (hasOptional) {
        return optionalMatched;
    }

    return requiredMatched;
}

bool WildcardMatch(const std::string& pattern, const std::string& text) {
    size_t p = 0;
    size_t t = 0;
    size_t star = std::string::npos;
    size_t match = 0;

    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == text[t])) {
            p += 1;
            t += 1;
        }
        else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            match = t;
        }
        else if (star != std::string::npos) {
            p = star + 1;
            t = ++match;
        }
        else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == '*') {
        p += 1;
    }

    return p == pattern.size();
}

std::vector<std::string> ExpandSelectorPattern(
    const SigmaLiteRule& rule,
    const std::string& rawPattern
) {
    std::string pattern = ToLowerCopy(TrimCopy(rawPattern));
    std::vector<std::string> matchedSelectors;

    if (pattern == "them") {
        for (const auto& [selectorName, _] : rule.selectors) {
            matchedSelectors.push_back(selectorName);
        }
        return matchedSelectors;
    }

    const bool hasWildcard = pattern.find('*') != std::string::npos;
    for (const auto& [selectorName, _] : rule.selectors) {
        if (hasWildcard) {
            if (WildcardMatch(pattern, selectorName)) {
                matchedSelectors.push_back(selectorName);
            }
        }
        else if (selectorName == pattern) {
            matchedSelectors.push_back(selectorName);
        }
    }

    return matchedSelectors;
}

std::vector<std::string> TokenizeCondition(const std::string& condition) {
    std::vector<std::string> tokens;
    std::string current;

    for (char c : condition) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!current.empty()) {
                tokens.push_back(ToLowerCopy(current));
                current.clear();
            }
            continue;
        }

        if (c == '(' || c == ')') {
            if (!current.empty()) {
                tokens.push_back(ToLowerCopy(current));
                current.clear();
            }
            tokens.push_back(std::string(1, c));
            continue;
        }

        current.push_back(c);
    }

    if (!current.empty()) {
        tokens.push_back(ToLowerCopy(current));
    }

    return tokens;
}

bool EvaluateConditionExpression(
    const SigmaLiteRule& rule,
    const std::unordered_map<std::string, bool>& selectorMatches
) {
    std::vector<std::string> tokens = TokenizeCondition(rule.condition);
    if (tokens.empty()) {
        return false;
    }

    size_t index = 0;

    std::function<bool(const std::string&, const std::string&)> evalQuantifier =
        [&](const std::string& quantifier, const std::string& pattern) -> bool {
            std::vector<std::string> selectors = ExpandSelectorPattern(rule, pattern);
            if (selectors.empty()) {
                return false;
            }

            if (quantifier == "1") {
                for (const auto& selectorName : selectors) {
                    auto it = selectorMatches.find(selectorName);
                    if (it != selectorMatches.end() && it->second) {
                        return true;
                    }
                }
                return false;
            }

            if (quantifier == "all") {
                for (const auto& selectorName : selectors) {
                    auto it = selectorMatches.find(selectorName);
                    if (it == selectorMatches.end() || !it->second) {
                        return false;
                    }
                }
                return true;
            }

            return false;
        };

    std::function<bool()> parseExpression;
    std::function<bool()> parseAnd;
    std::function<bool()> parseFactor;
    std::function<bool()> parseAtom;

    parseAtom = [&]() -> bool {
        if (index >= tokens.size()) {
            return false;
        }

        const std::string token = tokens[index];
        if (token == "(") {
            index += 1;
            bool innerResult = parseExpression();
            if (index < tokens.size() && tokens[index] == ")") {
                index += 1;
            }
            return innerResult;
        }

        if ((token == "1" || token == "all") &&
            (index + 2) < tokens.size() &&
            tokens[index + 1] == "of") {
            std::string quantifier = token;
            std::string pattern = tokens[index + 2];
            index += 3;
            return evalQuantifier(quantifier, pattern);
        }

        index += 1;
        auto matchIt = selectorMatches.find(token);
        return matchIt != selectorMatches.end() && matchIt->second;
    };

    parseFactor = [&]() -> bool {
        if (index < tokens.size() && tokens[index] == "not") {
            index += 1;
            return !parseFactor();
        }

        return parseAtom();
    };

    parseAnd = [&]() -> bool {
        bool result = parseFactor();
        while (index < tokens.size() && tokens[index] == "and") {
            index += 1;
            result = result && parseFactor();
        }
        return result;
    };

    parseExpression = [&]() -> bool {
        bool result = parseAnd();
        while (index < tokens.size() && tokens[index] == "or") {
            index += 1;
            result = result || parseAnd();
        }
        return result;
    };

    return parseExpression();
}

bool RuleMatchesSigmaLite(const SigmaLiteRule& rule, const std::vector<std::string>& fieldsLower) {
    std::unordered_map<std::string, bool> selectorMatches;

    for (const auto& [selectorName, selector] : rule.selectors) {
        selectorMatches[selectorName] = SelectorMatchesSigmaLite(selector, fieldsLower);
    }

    return EvaluateConditionExpression(rule, selectorMatches);
}

DetectionSeverity SigmaLevelToSeverity(const std::string& sigmaLevel) {
    const std::string normalizedLevel = ToLowerCopy(sigmaLevel);

    if (normalizedLevel == "critical") {
        return DetectionSeverity::Critical;
    }
    if (normalizedLevel == "high") {
        return DetectionSeverity::High;
    }
    if (normalizedLevel == "medium") {
        return DetectionSeverity::Medium;
    }
    if (normalizedLevel == "low") {
        return DetectionSeverity::Low;
    }

    return DetectionSeverity::Info;
}

void PersistDetectionEvent(
    const std::string& timestamp,
    DetectionSeverity severity,
    UINT32 pid,
    const std::string& method,
    const std::string& message,
    const std::string& details,
    int securityScore
) {
    std::lock_guard<std::mutex> logLock(events_log_mutex);

    std::ofstream outFile(kDefaultEventsLogPath, std::ios::app);
    if (!outFile.is_open()) {
        return;
    }

    outFile
        << "{"
        << "\"timestamp\":\"" << JsonEscape(timestamp) << "\","
        << "\"severity\":\"" << SeverityToLabel(severity) << "\","
        << "\"pid\":" << pid << ","
        << "\"method\":\"" << JsonEscape(method) << "\","
        << "\"security_score\":" << securityScore << ","
        << "\"message\":\"" << JsonEscape(message) << "\","
        << "\"details\":\"" << JsonEscape(details) << "\""
        << "}"
        << "\n";
}

bool ShouldEmitCorrelationAlertLocked(
    UINT32 pid,
    const std::string& method,
    DetectionSeverity severity,
    std::string& outSummary,
    std::string& outDetails
) {
    if (pid == 0 || pid == curPid) {
        return false;
    }

    const time_t now = time(0);
    auto& history = g_recentEventsByPid[pid];
    history.push_back({ now, method, severity });

    const time_t correlationWindowSeconds = 120;
    while (!history.empty() && (now - history.front().timestamp) > correlationWindowSeconds) {
        history.pop_front();
    }

    if (history.size() < 2) {
        return false;
    }

    std::unordered_set<std::string> uniqueMethods;
    bool hasHighOrCritical = false;

    for (const auto& event : history) {
        uniqueMethods.insert(event.method);
        if (event.severity == DetectionSeverity::High || event.severity == DetectionSeverity::Critical) {
            hasHighOrCritical = true;
        }
    }

    if (uniqueMethods.size() < 2 || !hasHighOrCritical) {
        return false;
    }

    const time_t alertCooldownSeconds = 300;
    auto lastAlertIt = g_lastCorrelationAlertByPid.find(pid);
    if (lastAlertIt != g_lastCorrelationAlertByPid.end() && (now - lastAlertIt->second) < alertCooldownSeconds) {
        return false;
    }

    g_lastCorrelationAlertByPid[pid] = now;

    std::string date_time_str = BuildTimestamp();
    outSummary = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Alert] | " + date_time_str +
        " | Method: Correlation Engine" +
        " | Multi-method detection chain on PID " + std::to_string(pid);

    outDetails = "Date & Time: " + date_time_str +
        " | PID: " + std::to_string(pid) +
        " | Method: Correlation Engine" +
        " | Trigger: multiple detection methods observed within 120 seconds.";

    return true;
}

void PushUiDetectionEvent(
    const std::string& message,
    const std::string& details,
    const std::string& method,
    UINT32 pid,
    DetectionSeverity severity,
    bool allowCorrelation = true
) {
    std::string timestamp = BuildTimestamp();
    std::string enrichedDetails = details + GetProcessEnrichment(pid);
    int securityScore = 100;
    bool emitCorrelationAlert = false;
    std::string correlationSummary;
    std::string correlationDetails;

    {
        std::lock_guard<std::mutex> lock(security_event_mutex);

        tab_1_menu_items.push_back(message);
        detectEventsDetails.push_back(enrichedDetails);
        g_eventSeverityLabels.push_back(SeverityToLabel(severity));
        g_severityCounters[static_cast<int>(severity)] += 1;
        g_detectionEvents.push_back({ timestamp, SeverityToLabel(severity), pid, method, message, enrichedDetails });

        securityScore = ComputeSecurityScoreLocked();
        tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ") | Score: " +
            std::to_string(securityScore) + " (" + SecurityLabelFromScore(securityScore) + ")";
        should_update = true;

        if (allowCorrelation) {
            emitCorrelationAlert = ShouldEmitCorrelationAlertLocked(
                pid,
                method,
                severity,
                correlationSummary,
                correlationDetails
            );
        }

        auto tab_toggle = Toggle(&tab_values, &tab_selected);
        screen.PostEvent(Event::Custom);
    }

    PersistDetectionEvent(timestamp, severity, pid, method, message, enrichedDetails, securityScore);

    if (g_elasticConfig.enabled) {
        std::string doc = BuildEcsDocument(SeverityToLabel(severity), pid, method, message, enrichedDetails);
        {
            std::lock_guard<std::mutex> eLock(g_elasticMutex);
            if (g_elasticQueue.size() < kElasticQueueMax)
                g_elasticQueue.push(std::move(doc));
        }
        g_elasticCv.notify_one();
    }

    if (emitCorrelationAlert) {
        PushUiDetectionEvent(
            correlationSummary,
            correlationDetails,
            "Method: Correlation Engine",
            pid,
            DetectionSeverity::Critical,
            false
        );
    }
}

void NotifySigmaMatches(
    UINT32 pid,
    const std::string& procName,
    const std::vector<std::string>& candidateFields,
    const std::string& sourceContext
) {
    if (g_sigmaRules.empty() || !ShouldHandlePidEvent(pid, procName) || candidateFields.empty()) {
        return;
    }

    std::vector<std::string> fieldsLower;
    fieldsLower.reserve(candidateFields.size());
    for (const auto& field : candidateFields) {
        std::string normalizedField = ToLowerCopy(TrimCopy(field));
        if (!normalizedField.empty()) {
            fieldsLower.push_back(std::move(normalizedField));
        }
    }

    if (fieldsLower.empty()) {
        return;
    }

    const std::string contextKey = ToLowerCopy(sourceContext) + "|" + fieldsLower.front();
    int emittedMatches = 0;
    const int maxMatchesPerEvent = 2;

    for (const auto& rule : g_sigmaRules) {
        if (!RuleMatchesSigmaLite(rule, fieldsLower)) {
            continue;
        }

        const std::string dedupKey = rule.title + "|" + std::to_string(pid) + "|" + contextKey;
        if (g_sigmaMatchDedup.find(dedupKey) != g_sigmaMatchDedup.end()) {
            continue;
        }
        g_sigmaMatchDedup.insert(dedupKey);

        const std::string dateTime = BuildTimestamp();
        const std::string message = std::to_string(tab_1_menu_items.size()) +
            " - [!] [Alert] | " + dateTime +
            " | " + procName +
            " | Method: Sigma-Lite Rule Matching" +
            " | Rule: " + rule.title;

        const std::string details = "Date & Time: " + dateTime +
            " | " + procName +
            " | PID: " + std::to_string(pid) +
            " | Method: Sigma-Lite Rule Matching" +
            " | Rule: " + rule.title +
            " | Level: " + rule.level +
            " | Source Context: " + sourceContext;

        PushUiDetectionEvent(
            message,
            details,
            "Method: Sigma-Lite Rule Matching",
            pid,
            SigmaLevelToSeverity(rule.level)
        );

        emittedMatches += 1;
        if (emittedMatches >= maxMatchesPerEvent) {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// SHA256 file hash — returns lowercase hex string, empty on failure.
// ---------------------------------------------------------------------------
static std::string Sha256File(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES,
                               CRYPT_VERIFYCONTEXT)) goto cleanup;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;

    {
        BYTE buf[65536];
        DWORD read;
        while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0)
            if (!CryptHashData(hHash, buf, read, 0)) goto cleanup;
    }

    {
        BYTE digest[32];
        DWORD digestLen = sizeof(digest);
        if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0)) {
            char hex[65] = {};
            for (int i = 0; i < 32; i++)
                sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
            result = hex;
        }
    }

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

// RVA → file offset (free function — no C++ objects, safe for SEH callers).
static DWORD ImphashRvaToOff(const IMAGE_NT_HEADERS64* nth, DWORD rva) {
    WORD n = nth->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER* sec =
        (const IMAGE_SECTION_HEADER*)((const BYTE*)&nth->OptionalHeader
        + nth->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < n; i++)
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    return 0;
}

// SEH-safe import walker. Writes "mod.fn,mod.fn,..." (null-terminated) into buf.
// No C++ objects in this frame. Returns bytes written, 0 on AV or empty table.
static DWORD CollectImportFlat(PVOID base, char* buf, DWORD cap) {
    struct ImpDesc { DWORD OFT, TS, FC, Name, FT; };
    DWORD w = 0;
    __try {
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != 0x5A4D) __leave;
        const IMAGE_NT_HEADERS64* nth =
            (const IMAGE_NT_HEADERS64*)((const BYTE*)base + dos->e_lfanew);
        if (nth->Signature != 0x00004550) __leave;
        DWORD impRva = nth->OptionalHeader.DataDirectory[1].VirtualAddress;
        if (!impRva) __leave;
        DWORD impOff = ImphashRvaToOff(nth, impRva);
        if (!impOff) __leave;

        const ImpDesc* desc = (const ImpDesc*)((const BYTE*)base + impOff);
        for (; desc->Name; desc++) {
            DWORD nameOff = ImphashRvaToOff(nth, desc->Name);
            if (!nameOff) continue;

            char mod[256]; int modLen = 0;
            const char* p = (const char*)base + nameOff;
            while (*p && modLen < 255) {
                char c = *p++;
                mod[modLen++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
            }
            for (int i = modLen - 1; i >= 0; i--)
                if (mod[i] == '.') { modLen = i; break; }
            mod[modLen] = '\0';

            DWORD thunkRva = desc->OFT ? desc->OFT : desc->FT;
            DWORD thunkOff = ImphashRvaToOff(nth, thunkRva);
            if (!thunkOff) continue;

            const ULONGLONG* thunk = (const ULONGLONG*)((const BYTE*)base + thunkOff);
            for (; *thunk; thunk++) {
                char fn[256]; int fnLen = 0;
                if (*thunk & (1ULL << 63)) {
                    char tmp[8]; _itoa_s((int)(*thunk & 0xFFFF), tmp, 10);
                    fn[fnLen++] = '#';
                    for (const char* q = tmp; *q; q++) fn[fnLen++] = *q;
                } else {
                    DWORD hOff = ImphashRvaToOff(nth, (DWORD)(*thunk & 0xFFFFFFFF));
                    if (!hOff) continue;
                    const char* r = (const char*)base + hOff + 2;
                    while (*r && fnLen < 255) {
                        char c = *r++;
                        fn[fnLen++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
                    }
                }
                fn[fnLen] = '\0';
                DWORD need = (DWORD)(modLen + 1 + fnLen);
                if (w + need + 2 > cap) __leave;
                if (w) buf[w++] = ',';
                memcpy(buf + w, mod, modLen); w += modLen;
                buf[w++] = '.';
                memcpy(buf + w, fn, fnLen);   w += fnLen;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { w = 0; }
    buf[w] = '\0';
    return w;
}

// ---------------------------------------------------------------------------
// Import hash (imphash) — MD5 of "module.funcname,..." pairs, matching
// the convention used by pefile/VirusTotal for threat-intel correlation.
// Returns lowercase hex string, empty if the PE has no import table.
// ---------------------------------------------------------------------------
static std::string ComputeImphash(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return {};

    PVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!base) return {};

    // Heap-allocate the flat buffer so __try is in a separate frame (no C++ objects there)
    std::vector<char> flatBuf(131072, 0);
    DWORD flatLen = CollectImportFlat(base, flatBuf.data(), (DWORD)flatBuf.size() - 1);
    UnmapViewOfFile(base);
    if (!flatLen) return {};

    // MD5 the concatenated string (all C++ objects outside any __try)
    std::string result;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)flatBuf.data(), flatLen, 0);
            BYTE dig[16]; DWORD dlen = 16;
            if (CryptGetHashParam(hHash, HP_HASHVAL, dig, &dlen, 0)) {
                char hex[33] = {};
                for (int i = 0; i < 16; i++)
                    sprintf_s(hex + i * 2, 3, "%02x", dig[i]);
                result = hex;
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

void NotifyLolDriverMatch(PKERNEL_STRUCTURED_NOTIFICATION notif, const std::string& fullPath) {
    if (lolDriverNames.empty() || fullPath.empty()) {
        return;
    }

    std::filesystem::path fsPath(fullPath);
    const std::string fileName = ToLowerCopy(fsPath.filename().string());
    const std::string extension = ToLowerCopy(fsPath.extension().string());

    if (extension != ".sys") {
        return;
    }

    // Name-based match
    bool nameMatch = lolDriverNames.find(fileName) != lolDriverNames.end();

    // Hash-based match (always compute for .sys files — catches renames)
    std::string fileHash = Sha256File(fullPath);
    bool hashMatch = !fileHash.empty() &&
                     !lolDriverHashes.empty() &&
                     lolDriverHashes.find(fileHash) != lolDriverHashes.end();

    if (!nameMatch && !hashMatch) return;

    const std::string normalizedPath = ToLowerCopy(fsPath.lexically_normal().string());
    if (detectedLolDriverPaths.find(normalizedPath) != detectedLolDriverPaths.end()) {
        return;
    }

    detectedLolDriverPaths.insert(normalizedPath);

    const std::string date_time_str = BuildTimestamp();
    const UINT32 pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(notif->pid));
    const std::string procName = SafeFixedBufferString(notif->procName, sizeof(notif->procName));

    std::string matchType = nameMatch && hashMatch ? "name+hash"
                          : nameMatch              ? "name"
                                                   : "hash";

    const std::string message = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Warning] | " + date_time_str +
        " | " + procName +
        " | Method: LOLDrivers Lookup (" + matchType + ")" +
        " | Flagged driver file: " + fileName;

    const std::string details = "Date & Time: " + date_time_str +
        " | " + procName +
        " | PID: " + std::to_string(pid) +
        " | Method: LOLDrivers Lookup (" + matchType + ")" +
        " | Driver: " + fileName +
        " | Path: " + fullPath +
        (fileHash.empty() ? "" : " | SHA256: " + fileHash);

    PushUiDetectionEvent(
        message,
        details,
        "Method: LOLDrivers Lookup",
        pid,
        DetectionSeverity::Medium
    );
}

bool LoadLolDriversCache(const std::string& cachePath) {
    std::ifstream cacheFile(cachePath);
    if (!cacheFile.is_open()) {
        std::cerr << "[*] LOLDrivers cache not found at: " << cachePath << "\n";
        return false;
    }

    std::string rawJson(
        (std::istreambuf_iterator<char>(cacheFile)),
        std::istreambuf_iterator<char>()
    );

    std::regex fileNameRegex(R"re("n"\s*:\s*"([^"]+)")re");
    std::regex hashRegex(R"re("sha256"\s*:\s*"([0-9a-fA-F]{64})")re");

    size_t beforeNames  = lolDriverNames.size();
    size_t beforeHashes = lolDriverHashes.size();

    std::sregex_iterator it(rawJson.begin(), rawJson.end(), fileNameRegex);
    std::sregex_iterator end;
    for (; it != end; ++it)
        if (it->size() > 1) {
            std::string n = ToLowerCopy((*it)[1].str());
            if (!n.empty()) lolDriverNames.insert(n);
        }

    std::sregex_iterator hit(rawJson.begin(), rawJson.end(), hashRegex);
    for (; hit != end; ++hit)
        if (hit->size() > 1) {
            std::string h = ToLowerCopy((*hit)[1].str());
            if (h.size() == 64) lolDriverHashes.insert(h);
        }

    std::cout << "[*] LOLDrivers: " << (lolDriverNames.size() - beforeNames)
              << " names, " << (lolDriverHashes.size() - beforeHashes)
              << " hashes loaded from " << cachePath << "\n";

    return !lolDriverNames.empty() || !lolDriverHashes.empty();
}


int yr_callback_function_file(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        KERNEL_STRUCTURED_NOTIFICATION* notif = (PKERNEL_STRUCTURED_NOTIFICATION)user_data;
        UINT32 pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(notif->pid));
        std::string procName = SafeFixedBufferString(notif->procName, sizeof(notif->procName));

        if (!ShouldHandlePidEvent(pid, procName)) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hNortonDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string method = "Method: In-Memory Loaded Image Analysis";

        std::string msgCatch;
        std::string details;

        if (endRes) {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | " + method + " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) + " | Process was terminated";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | Process was terminated successfully.";
        }
        else {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | Memory Mapped Image | Identified: " + std::string(((YR_RULE*)message_data)->identifier) + " | (!) Failed to kill process";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | (!) Process termination failed.";
        }

        PushUiDetectionEvent(
            msgCatch,
            details,
            "Method: In-Memory Loaded Image Analysis",
            pid,
            DetectionSeverity::Critical
        );

        return 1;

    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        char* fileName = (char*)user_data;

        if (benignFSPaths.find(fileName) == benignFSPaths.end()) {

            //printf("[+] Adding to benignFSPaths: %s\n", fileName);
            benignFSPaths.insert(fileName);

            return CALLBACK_CONTINUE;
        }
    }

    return CALLBACK_CONTINUE;
}

int yr_callback_function_byte_stream(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {

        PKERNEL_STRUCTURED_BUFFER structBuffer = (PKERNEL_STRUCTURED_BUFFER)user_data;

        UINT32 pid = (UINT32)structBuffer->pid;
        std::string procName = SafeFixedBufferString(structBuffer->procName, sizeof(structBuffer->procName));

        if (!ShouldHandlePidEvent(pid, procName)) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hNortonDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string msgCatch;
        std::string details;

        std::string rule_identifier = std::string(((YR_RULE*)message_data)->identifier);

        if (endRes) {

            msgCatch = std::to_string(tab_1_menu_items.size()) +
                " - [!] [Alert] | " + date_time_str +
                " | " + procName +
                " | Byte Stream Analysis | Identified: " + rule_identifier +
                "\n\n | Process with PID " + std::to_string(pid) + " has been terminated.";

            details = "Date & Time: " + date_time_str +
                " | " + procName +
                " | PID: " + std::to_string(pid) +
                " | Method: Byte Stream Analysis" +
                " | YARA rule Identifier: " + rule_identifier +
                " | Process was terminated successfully.";
        }
        else {

            msgCatch = std::to_string(tab_1_menu_items.size()) +
                " - [!] [Alert] | " + date_time_str +
                " | " + procName +
                " | Byte Stream Analysis | Identified: " + rule_identifier +
                "\n\n | (!) Failed to terminate process with PID " + std::to_string(pid);

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | " + procName +
                " | Method: Byte Stream Analysis" +
                " | YARA rule Identifier: " + rule_identifier +
                " | (!) Process termination failed.";
        }

        PushUiDetectionEvent(
            msgCatch,
            details,
            "Method: Byte Stream Analysis",
            pid,
            DetectionSeverity::Critical
        );
    }

    return CALLBACK_CONTINUE;
}

UINT lastNotifiedStackSpoofPid = 0;

// ---------------------------------------------------------------------------
// WinVerifyTrust revocation check for driver certificates.
//
// Called from the notification handler when the kernel reports a suspect signer
// or expired certificate.  Extracts the NT-namespace driver path from the alert
// message, converts to a Win32 path, and calls WinVerifyTrust with online
// revocation checking (OCSP + CRL).
//
// Returns: "REVOKED", "EXPIRED", "UNTRUSTED", "VALID", or "ERROR: <reason>".
// ---------------------------------------------------------------------------

static std::string VerifyDriverSignatureRevocation(const std::string& ntPath)
{
    std::string win32Path = QueryDosDevicePath(ntPath);
    if (win32Path.empty()) return "ERROR: path conversion failed";

    std::wstring wPath(win32Path.begin(), win32Path.end());

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wPath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtd = {};
    wtd.cbStruct            = sizeof(wtd);
    wtd.pPolicyCallbackData = NULL;
    wtd.pSIPClientData      = NULL;
    wtd.dwUIChoice          = WTD_UI_NONE;
    // Enable online revocation checking (CRL + OCSP)
    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wtd.dwUnionChoice       = WTD_CHOICE_FILE;
    wtd.pFile               = &fileInfo;
    wtd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData       = NULL;
    wtd.pwszURLReference    = NULL;
    // Revocation + lifetime checking
    wtd.dwProvFlags         = WTD_REVOCATION_CHECK_CHAIN |
                              WTD_CACHE_ONLY_URL_RETRIEVAL;

    // First try with cached CRLs (fast, no network)
    LONG status = WinVerifyTrust(NULL, &actionGuid, &wtd);

    if (status == CERT_E_REVOKED)
        return "REVOKED";
    if (status == CERT_E_EXPIRED)
        return "EXPIRED";

    // If cache-only didn't find revocation info, retry with network access
    if (status != ERROR_SUCCESS) {
        wtd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;
        // Close previous state
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionGuid, &wtd);

        // Re-verify with network
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        wtd.hWVTStateData = NULL;
        status = WinVerifyTrust(NULL, &actionGuid, &wtd);
    }

    // Close state
    WINTRUST_DATA wtdClose = wtd;
    wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &wtdClose);

    switch (status) {
    case ERROR_SUCCESS:
        return "VALID";
    case TRUST_E_NOSIGNATURE:
        return "UNSIGNED";
    case CERT_E_REVOKED:
        return "REVOKED";
    case CERT_E_EXPIRED:
        return "EXPIRED";
    case CERT_E_UNTRUSTEDROOT:
    case TRUST_E_EXPLICIT_DISTRUST:
        return "UNTRUSTED";
    case CERT_E_CHAINING:
        return "CHAIN_ERROR";
    default:
        return "UNTRUSTED (0x" + std::to_string(status) + ")";
    }
}

// Extract the NT-namespace path from a kernel alert message.
// Our kernel alerts format paths as: "... kernel driver '\Device\...\foo.sys' ..."
static std::string ExtractDriverPathFromAlert(const char* msg)
{
    if (!msg) return "";
    const char* start = strchr(msg, '\'');
    if (!start) return "";
    start++;  // skip the opening quote
    const char* end = strchr(start, '\'');
    if (!end || end <= start) return "";
    return std::string(start, end - start);
}

int Notify(PKERNEL_STRUCTURED_NOTIFICATION notif, char* msg) {

    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char date_time[80];
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

    UINT32 pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(notif->pid));
    std::string procName = SafeFixedBufferString(notif->procName, sizeof(notif->procName));
    std::string targetProcName = SafeFixedBufferString(notif->targetProcName, sizeof(notif->targetProcName));

    if (!ShouldHandlePidEvent(pid, procName)) {
        return 0;
    }

    std::string date_time_str = date_time;
    std::string msgCatch;
    std::string details;
    std::string targetedProc = "";
    std::string method;

    if (notif->ProcVadCheck) {
        method = "Method: Process VAD Tree Inspection";
    }
    else if (notif->StackBaseVadCheck) {
        method = "Method: Stack Base + VAD Inspection";
    }
    else if (notif->CallingProcPidCheck) {
        method = "Method: Calling Process PID Inspection";
    }
    else if (notif->SeAuditInfoCheck) {
        method = "Method: Process Audit Info Inspection";
    }
    else if (notif->ImageLoadPathCheck) {
        method = "Method: Image Load Path Inspection";
    }
    else if (notif->ObjectCheck) {
        method = "Method: Object Operation Inspection";
        targetedProc = " -> " + targetProcName + " ";
    }
    else if (notif->RegCheck) {
        method = "Method: Registry Operation Inspection";
    }
    else if (notif->SyscallCheck) {
        method = "Method: Syscall Integrity Inspection";
    }
    else if (notif->ShadowStackCheck) {

        if (lastNotifiedStackSpoofPid == pid) {
            return 0;
        }

        lastNotifiedStackSpoofPid = pid;
        method = "Method: Shadow Stack Inspection";
    }
    else if (notif->SsdtHookCheck) {
        method = "Method: SSDT Integrity Check";
    }
    else if (notif->InlineHookCheck) {
        method = "Method: Inline Hook Detection";
    }
    else if (notif->EatHookCheck) {
        method = "Method: EAT Hook Detection";
    }
    else if (notif->EtwHookCheck) {
        method = "Method: ETW Hook Detection";
    }
    else if (notif->AltSyscallHandlerCheck) {
        method = "Method: Alt Syscall Handler Integrity";
    }
    else if (notif->PeScanCheck) {
        method = "Method: PE / VAD Scan";
    }
    else if (notif->AmsiBypassCheck) {
        method = "Method: AMSI Bypass Detection";
    }
    else if (notif->NetworkCheck) {
        method = "Method: Network Traffic Inspection";
    }
    else if (notif->FsFilterCheck) {
        method = "Method: Filesystem Activity Monitor";
    }
    else if (notif->TokenCheck) {
        method = "Method: Token / Logon Session Monitor";
    }
    else if (notif->PnpCheck) {
        method = "Method: PnP Device Monitor";
    }
    else if (notif->ObCallbackCheck) {
        method = "Method: ObCallback Integrity Check";
    }
    else if (notif->PsNotifyCallbackCheck) {
        method = "Method: PsNotify Callback Integrity";
    }
    else if (notif->CiIntegrityCheck) {
        method = "Method: CI.dll Code Integrity Check";
    }
    else if (notif->EprocessProtCheck) {
        method = "Method: EPROCESS Protection Monitor";
    }
    else if (notif->DkomCheck) {
        method = "Method: DKOM Process Hiding Detection";
    }
    else if (notif->DseBypassCheck) {
        method = "Method: DSE Bypass Detection";
    }
    else if (notif->UnsignedModuleCheck) {
        method = "Method: Unsigned Kernel Module Detection";
    }
    else if (notif->CmCallbackCheck) {
        method = "Method: CmCallback Integrity Check";
    }
    else if (notif->SuspectSignerCheck) {
        method = "Method: Driver Certificate Signer Analysis";
    }

    // --- Usermode WinVerifyTrust revocation check ---
    // When the kernel flags a suspect/expired/unsigned driver cert, extract the
    // driver path from the alert and verify via WinVerifyTrust with CRL/OCSP.
    // If the cert is revoked, escalate to CRITICAL regardless of kernel severity.
    if (notif->SuspectSignerCheck || notif->UnsignedModuleCheck) {
        std::string drvPath = ExtractDriverPathFromAlert(msg);
        if (!drvPath.empty()) {
            std::string revStatus = VerifyDriverSignatureRevocation(drvPath);
            std::string revDetail = " [WinVerifyTrust: " + revStatus + "]";

            // Append revocation status to the message for UI display
            SIZE_T origLen = strlen(msg);
            SIZE_T extraLen = revDetail.size();
            if (origLen + extraLen < 1024) {
                // msg points into the IOCTL buffer — safe to append within 1MB buffer
                memcpy(msg + origLen, revDetail.c_str(), extraLen + 1);
            }

            if (revStatus == "REVOKED" || revStatus == "UNTRUSTED") {
                // Escalate: override to CRITICAL and append escalation note
                notif->Critical = 1;
                notif->Warning  = 0;

                std::string escalation =
                    " ** REVOKED/UNTRUSTED certificate detected by WinVerifyTrust — "
                    "this driver was signed with a certificate that has been explicitly "
                    "revoked or distrusted. High-confidence malicious driver.";
                SIZE_T curLen = strlen(msg);
                SIZE_T escLen = escalation.size();
                if (curLen + escLen < 1024) {
                    memcpy(msg + curLen, escalation.c_str(), escLen + 1);
                }

                PushUiDetectionEvent(
                    "[!!] REVOKED CERT: " + drvPath,
                    "Driver signed with revoked/untrusted certificate.\n"
                    "WinVerifyTrust result: " + revStatus + "\n"
                    "Kernel alert: " + std::string(msg),
                    "Method: Certificate Revocation Check (WinVerifyTrust)",
                    pid,
                    DetectionSeverity::Critical
                );
            }
        }
    }

    if (notif->Critical) {

        try {
            DWORD bytesReturned;
            BOOL endRes = DeviceIoControl(
                hNortonDevice,
                END_THAT_PROCESS,
                &pid,
                sizeof(pid),
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );

            if (endRes) {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + procName +
                    " | " + method +
                    " | " + (char*)msg;

                msgCatch += " | Process with PID " + std::to_string(pid) + " has been terminated.";

                details = "Date & Time: " + date_time_str +
                    " | " + procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | PID: " + std::to_string(pid);

                details += " | Process was terminated.";
            }
            else {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | (!) Failed to terminate process with PID " + std::to_string(pid);

                details = "Date & Time: " + date_time_str +
                    " | " + procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | PID: " + std::to_string(pid) +
                    " | (!) Process termination failed.";
            }

            PushUiDetectionEvent(
                msgCatch,
                details,
                method,
                pid,
                DetectionSeverity::Critical
            );
        }
        catch (std::exception& e) {
            std::cerr << "[!] Exception caught: " << e.what() << std::endl;
        }

    }
    else if (notif->Warning) {

        msgCatch = std::to_string(tab_1_menu_items.size()) +
            " - [*] [Warning] | " + date_time_str +
            " | " + method +
            " | " + procName +
            " | " + (char*)msg;

        details = "Date & Time: " + date_time_str +
            " | " + procName +
            " | " + method +
            " | " + (char*)msg +
            " | PID: " + std::to_string(pid);

        PushUiDetectionEvent(
            msgCatch,
            details,
            method,
            pid,
            DetectionSeverity::Medium
        );

    }
    else if (notif->Info) {
        msgCatch = std::to_string(tab_1_menu_items.size()) +
            " - [i] [Info] | " + date_time_str +
            " | " + method +
            " | " + procName +
            " | " + (char*)msg;

        details = "Date & Time: " + date_time_str +
            " | " + procName +
            " | " + method +
            " | " + (char*)msg +
            " | PID: " + std::to_string(pid);

        PushUiDetectionEvent(
            msgCatch,
            details,
            method,
            pid,
            DetectionSeverity::Info
        );
    }

    return 0;
}

void setConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void AddYaraRulesFromDirectory(const std::string& rulesDirectory) {
    std::error_code existsError;
    if (!std::filesystem::exists(rulesDirectory, existsError)) {
        std::cerr << "[*] YARA directory not found: " << rulesDirectory << "\n";
        return;
    }

    std::error_code iterError;
    std::filesystem::recursive_directory_iterator iter(
        rulesDirectory,
        std::filesystem::directory_options::skip_permission_denied,
        iterError
    );
    std::filesystem::recursive_directory_iterator end;

    if (iterError) {
        std::cerr << "[*] Failed to iterate YARA directory: " << rulesDirectory
            << " (" << iterError.message() << ")\n";
        return;
    }

    for (; iter != end; iter.increment(iterError)) {
        if (iterError) {
            iterError.clear();
            continue;
        }

        const auto& entry = *iter;
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string extension = ToLowerCopy(entry.path().extension().string());
        if (extension != ".yar" && extension != ".yara") {
            continue;
        }

        std::string normalizedRulePath = ToLowerCopy(entry.path().lexically_normal().string());
        if (loadedYaraRulePaths.find(normalizedRulePath) != loadedYaraRulePaths.end()) {
            continue;
        }

        FILE* rule_file;
        if (fopen_s(&rule_file, entry.path().string().c_str(), "r") != 0 || rule_file == NULL) {
            std::cerr << "Failed to open Yara rule: " << entry.path().string() << "\n";
            continue;
        }

        if (yr_compiler_add_file(compiler, rule_file, NULL, entry.path().string().c_str()) != ERROR_SUCCESS) {
            std::cerr << "Failed to add Yara rule: " << entry.path().string() << "\n";
            fclose(rule_file);
            continue;
        }

        fclose(rule_file);
        loadedYaraRulePaths.insert(normalizedRulePath);
        yara_rules_count += 1;

        setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        printf("\t [+] Adding Yara rule: %s\n", entry.path().string().c_str());
        setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

VOID InitYara(const std::vector<std::string>& yaraRulesDirectories) {

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara\n";
        system("pause");
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler\n";
        system("pause");
        return;
    }

    for (const auto& directory : yaraRulesDirectories) {
        AddYaraRulesFromDirectory(directory);
    }

    int result = yr_compiler_get_rules(compiler, &rules);

    if (result != 0) {
        std::cerr << "Error retrieving compiled rules" << std::endl;
        system("pause");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    int scan_res = yr_scanner_create(rules, &scanner);

    if (scan_res != 0 || scanner == nullptr) {
        std::cerr << "Error while creating a scanner" << std::endl;
        system("pause");
        return;
    }
}

auto detail_panel_content = [&]() {

    if (!detectEventsDetails.empty()) {
        return paragraph(detectEventsDetails.at(tab_1_selected));
    }

    return paragraph(" ") | center;

    };

auto tab_1_container = Container::Vertical({
    Renderer(tab_1_menu, [&] {

        auto main_panel = vbox({
            text("Detection Events:") | bold | color(Color::Red),
            tab_1_menu->Render() | frame | border | size(HEIGHT, EQUAL, 60),
        });

        auto details_panel = vbox({
            text("Details:") | bold | color(Color::Yellow),
            detail_panel_content() | border | size(HEIGHT, EQUAL, 10),
            });

        return vbox({
            main_panel | flex,
            details_panel,
        }) | border;

        /*return tab_1_menu->Render() |
               size(HEIGHT, GREATER_THAN, 10) |
               frame | vscroll_indicator | focus | color(Color::Red);*/
    })
    });

void EnqueueYaraByteStreamScan(const KERNEL_STRUCTURED_BUFFER* ksbHeader, const BYTE* data, ULONG dataSize) {
    if (!rules || !ksbHeader || !data || dataSize == 0) return;

    YaraScanWork work;
    work.type = YaraScanType::ByteStream;
    work.ksbHeader = *ksbHeader;
    work.bytes.assign(data, data + dataSize);

    std::lock_guard<std::mutex> lock(g_yaraScanMutex);
    if (g_yaraScanQueue.size() >= kYaraScanQueueMax) return; // drop rather than block
    g_yaraScanQueue.push(std::move(work));
    g_yaraScanCv.notify_one();
}

void EnqueueYaraFileScan(const KERNEL_STRUCTURED_NOTIFICATION* notifHeader, const std::string& filePath) {
    if (!rules || !notifHeader || filePath.empty()) return;

    YaraScanWork work;
    work.type = YaraScanType::File;
    work.notifHeader = *notifHeader;
    work.filePath = filePath;

    std::lock_guard<std::mutex> lock(g_yaraScanMutex);
    if (g_yaraScanQueue.size() >= kYaraScanQueueMax) return;
    g_yaraScanQueue.push(std::move(work));
    g_yaraScanCv.notify_one();
}

void YaraScanWorker() {
    while (true) {
        YaraScanWork work;
        {
            std::unique_lock<std::mutex> lock(g_yaraScanMutex);
            g_yaraScanCv.wait(lock, [] {
                return !g_yaraScanQueue.empty() || g_yaraScanStop.load();
            });
            if (g_yaraScanStop.load() && g_yaraScanQueue.empty()) break;
            work = std::move(g_yaraScanQueue.front());
            g_yaraScanQueue.pop();
        }

        if (!rules) continue;

        if (work.type == YaraScanType::ByteStream) {
            KERNEL_STRUCTURED_BUFFER ksbCopy = work.ksbHeader;
            yr_rules_scan_mem(
                rules,
                work.bytes.data(),
                work.bytes.size(),
                0,
                (YR_CALLBACK_FUNC)yr_callback_function_byte_stream,
                (void*)&ksbCopy,
                0
            );
        } else {
            KERNEL_STRUCTURED_NOTIFICATION notifCopy = work.notifHeader;
            yr_rules_scan_file(
                rules,
                work.filePath.c_str(),
                0,
                (YR_CALLBACK_FUNC)yr_callback_function_file,
                (void*)&notifCopy,
                0
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Capa capabilities scanning
// ---------------------------------------------------------------------------

// Parse the top-level rule names from capa's --json output.
// Tracks brace depth so only direct children of the "rules" object are returned.
static std::vector<std::string> ParseCapaRuleNames(const std::string& json) {
    std::vector<std::string> names;

    size_t rulesPos = json.find("\"rules\":");
    if (rulesPos == std::string::npos) return names;
    size_t braceStart = json.find('{', rulesPos + 8);
    if (braceStart == std::string::npos) return names;

    int    depth    = 0;
    bool   inString = false;
    size_t pos      = braceStart;

    while (pos < json.size()) {
        char c = json[pos];

        if (inString) {
            if (c == '\\') { pos += 2; continue; }
            if (c == '"')  inString = false;
            ++pos; continue;
        }

        if      (c == '{') { ++depth; ++pos; continue; }
        else if (c == '}') {
            if (--depth == 0) break;
            ++pos; continue;
        }
        else if (c == '"') {
            if (depth == 1) {
                // Candidate rule-name key at the top level of the rules object
                size_t nameStart = pos + 1;
                size_t nameEnd   = json.find('"', nameStart);
                if (nameEnd == std::string::npos) break;
                std::string key = json.substr(nameStart, nameEnd - nameStart);

                // Verify it is followed by ': {' (possibly with whitespace)
                size_t chk = nameEnd + 1;
                while (chk < json.size() && std::isspace((unsigned char)json[chk])) ++chk;
                if (chk < json.size() && json[chk] == ':') {
                    ++chk;
                    while (chk < json.size() && std::isspace((unsigned char)json[chk])) ++chk;
                    if (chk < json.size() && json[chk] == '{')
                        names.push_back(std::move(key));
                }
                pos = nameEnd + 1; continue;
            }
            inString = true;
        }
        ++pos;
    }
    return names;
}

// Run capa on a PE file, parse the JSON output, and surface every matched
// capability as a High-severity detection event.
static void RunCapaScan(const std::string& path, UINT32 pid) {
    std::string cmd = "\"" + kCapaExePath + "\" --json \"" + path + "\"";

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = INVALID_HANDLE_VALUE, hWrite = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    std::vector<char> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back('\0');

    if (!CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return;
    }
    CloseHandle(hWrite);

    std::string output;
    char   buf[4096];
    DWORD  bytesRead;
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        output += buf;
    }
    CloseHandle(hRead);

    // 60-second timeout — terminate capa if it stalls
    if (WaitForSingleObject(pi.hProcess, 60000) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (output.empty()) return;

    std::vector<std::string> caps = ParseCapaRuleNames(output);
    if (caps.empty()) return;

    std::string baseName = BaseNameLower(path);
    std::string details  = "File: " + path + "\nCapabilities (" + std::to_string(caps.size()) + "):\n";
    for (const auto& cap : caps)
        details += "  - " + cap + "\n";

    PushUiDetectionEvent(
        "capa: " + std::to_string(caps.size()) + " capabilities in " + baseName,
        details,
        "Capa: Capabilities Scan",
        pid,
        DetectionSeverity::High
    );
}

static void EnqueueCapaScan(const std::string& path, UINT32 pid) {
    if (path.empty()) return;
    std::lock_guard<std::mutex> lock(g_capaMutex);
    if (g_capaScanned.count(path)) return;          // deduplicate
    if (g_capaQueue.size() >= kCapaQueueMax) return; // drop rather than block
    g_capaScanned.insert(path);
    g_capaQueue.push({ path, pid });
    g_capaCv.notify_one();
}

void CapaScanWorker() {
    while (true) {
        std::pair<std::string, UINT32> work;
        {
            std::unique_lock<std::mutex> lock(g_capaMutex);
            g_capaCv.wait(lock, [] {
                return !g_capaQueue.empty() || g_capaStop.load();
            });
            if (g_capaStop.load() && g_capaQueue.empty()) break;
            work = std::move(g_capaQueue.front());
            g_capaQueue.pop();
        }
        RunCapaScan(work.first, work.second);
    }
}

void ConsumeIOCTLData(LPCWSTR deviceName, DWORD ioctlCode, int sleepDurationMs) {

    hNortonDevice = CreateFileW(
        deviceName,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hNortonDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device: " << GetLastError() << std::endl;
        exit(-1);
        ;
    }

    DWORD bufferSize = 1024 * 1024;
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        std::cerr << "Failed to allocate buffer" << std::endl;
        CloseHandle(hNortonDevice);
        return;
    }

    const int maxRetries = 1000000000;
    int retryCount = 0;

    while (retryCount < maxRetries) {

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hNortonDevice,
            ioctlCode,
            nullptr,
            0,
            buffer,
            bufferSize,
            &bytesReturned,
            nullptr
        );

        if (result) {

            if (ioctlCode == NORTONAV_RETRIEVE_DATA_BYTE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_BUFFER)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                KERNEL_STRUCTURED_BUFFER* structuredBuffer = (PKERNEL_STRUCTURED_BUFFER)buffer;
                BYTE* bufferData = (BYTE*)(buffer + sizeof(KERNEL_STRUCTURED_BUFFER));

                EnqueueYaraByteStreamScan(structuredBuffer, bufferData, structuredBuffer->bufSize);

            }
            else if (ioctlCode == NORTONAV_RETRIEVE_DATA_BUFFER) {

                std::cout << "Buffer" << std::endl;

            }
            else if (ioctlCode == NORTONAV_RETRIEVE_DATA_FILE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_NOTIFICATION)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                if (buffer && bufferSize > 0) {

                    PKERNEL_STRUCTURED_NOTIFICATION notif = (PKERNEL_STRUCTURED_NOTIFICATION)buffer;
                    char* msg = (char*)(buffer + sizeof(KERNEL_STRUCTURED_NOTIFICATION));

                    if (msg != NULL) {
                        UINT32 notifPid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(notif->pid));
                        std::string notifProcName = SafeFixedBufferString(notif->procName, sizeof(notif->procName));
                        if (!ShouldHandlePidEvent(notifPid, notifProcName)) {
                            continue;
                        }

                        std::string cachedCmdLine = GetProcessCommandLineCached(notifPid);

                        if (notif->isPath) {

                            std::string litFileName = msg;
                            std::string fullPath = QueryDosDevicePath(litFileName);
                            if (fullPath.empty()) {
                                fullPath = litFileName;
                            }

                            NotifyLolDriverMatch(notif, fullPath);

                            std::vector<std::string> sigmaFields = { fullPath, litFileName, notifProcName };
                            if (!cachedCmdLine.empty()) sigmaFields.push_back(cachedCmdLine);
                            NotifySigmaMatches(notifPid, notifProcName, sigmaFields, "file_path_notification");

                            if (benignFSPaths.find(fullPath) != benignFSPaths.end()) {
                                continue;
                            }

                            EnqueueYaraFileScan(notif, fullPath);
                            EnqueueCapaScan(fullPath, notifPid);

                            // Compute and surface imphash for threat-intel correlation
                            {
                                std::string ih = ComputeImphash(fullPath);
                                if (!ih.empty()) {
                                    std::string sha = Sha256File(fullPath);
                                    std::string details = "File: " + fullPath +
                                        "\nImphash: " + ih +
                                        (sha.empty() ? "" : "\nSHA256:  " + sha);
                                    PushUiDetectionEvent(
                                        "PE fingerprint: " + BaseNameLower(fullPath),
                                        details,
                                        "Static: Import Hash",
                                        notifPid,
                                        DetectionSeverity::Info
                                    );
                                }
                            }
                        }
                        else {
                            std::vector<std::string> sigmaFields = { std::string(msg), notifProcName };
                            if (!cachedCmdLine.empty()) sigmaFields.push_back(cachedCmdLine);
                            NotifySigmaMatches(notifPid, notifProcName, sigmaFields, "generic_notification");

                            Notify(notif, msg);

                            // Resolve the process image path and queue a capa scan
                            if (notifPid > 0) {
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, notifPid);
                                if (hProc) {
                                    char imagePath[MAX_PATH * 4] = {};
                                    DWORD imgSize = sizeof(imagePath);
                                    if (QueryFullProcessImageNameA(hProc, 0, imagePath, &imgSize))
                                        EnqueueCapaScan(std::string(imagePath, imgSize), notifPid);
                                    CloseHandle(hProc);
                                }
                            }
                        }
                    }
                }
            }
        }

        Sleep(sleepDurationMs);
    }

    free(buffer);
    CloseHandle(hNortonDevice);
}

std::string GetLastErrorAsString() {
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    LocalFree(messageBuffer);

    return message;
}

SC_HANDLE hService;
SC_HANDLE hSCManager;

void UninstallNortonEDRDriver() {
    if (hService) {
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            std::wcout << L"Service stopped successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to stop service. Error: " << GetLastError() << std::endl;
        }

        if (DeleteService(hService)) {
            std::wcout << L"Service deleted successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to delete service. Error: " << GetLastError() << std::endl;
        }

        CloseServiceHandle(hService);
        hService = nullptr;
    }

    if (hSCManager) {
        CloseServiceHandle(hSCManager);
        hSCManager = nullptr;
    }
}


bool InstallNortonEDRDriver(
    const std::wstring& drvName,
    const std::wstring& drvPath
) {

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!hSCManager) {
        std::wcout << L"Failed to open service control manager. Error: " << GetLastError() << std::endl;
        return false;
    }

    hService = CreateServiceW(
        hSCManager,
        drvName.c_str(),
        drvName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        drvPath.c_str(),
        L"FSFilter Anti-Virus",     // LoadOrderGroup — must match INF and altitude range
        NULL,
        L"FltMgr\0",               // Dependencies — Filter Manager must load first
        NULL,
        NULL
    );


    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            std::wcout << L"Service already exists, opening existing service..." << std::endl;
            hService = OpenService(hSCManager, drvName.c_str(), SERVICE_START);
            if (!hService) {
                std::wcerr << L"Failed to open existing service. Error: " << GetLastError() << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else {
            std::wcerr << L"Failed to create service. Error: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    // Write minifilter altitude registry keys so the Filter Manager can find the driver.
    // These must exist before the driver is started.
    {
        wchar_t instRoot[300], instKey[356];
        swprintf_s(instRoot, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances", drvName.c_str());
        swprintf_s(instKey,  L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\NortonEDRDrvInstance", drvName.c_str());

        HKEY hk = nullptr;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, instRoot, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
            const wchar_t* defInst = L"NortonEDRDrvInstance";
            RegSetValueExW(hk, L"DefaultInstance", 0, REG_SZ,
                           (const BYTE*)defInst, (DWORD)((wcslen(defInst) + 1) * sizeof(wchar_t)));
            RegCloseKey(hk);
        }
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, instKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
            const wchar_t* altitude = L"320021";
            RegSetValueExW(hk, L"Altitude", 0, REG_SZ,
                           (const BYTE*)altitude, (DWORD)((wcslen(altitude) + 1) * sizeof(wchar_t)));
            DWORD flags = 0;
            RegSetValueExW(hk, L"Flags", 0, REG_DWORD, (const BYTE*)&flags, sizeof(DWORD));
            RegCloseKey(hk);
        }
    }

    if (!StartService(hService, 0, nullptr)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"Failed to start service. Error: " << GetLastError() << std::endl;
            std::cerr << GetLastErrorAsString() << std::endl;

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    std::wcout << L"Driver installed and started successfully!" << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;

}

void SignalHandler(int signal) {
    if (signal == SIGINT) {
        std::wcout << L"Ctrl+C detected. Uninstalling driver..." << std::endl;
        UninstallNortonEDRDriver();
        exit(0);
    }
}

// ---------------------------------------------------------------------------
// Sysmon integration
// ---------------------------------------------------------------------------

static DWORD WINAPI SysmonEventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                         PVOID /*ctx*/, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    LPWSTR xmlBuf = RenderEventXml(hEvent);
    if (!xmlBuf) return ERROR_SUCCESS;
    std::wstring xml(xmlBuf);
    free(xmlBuf);

    std::string eventIdStr = XmlElementValue(xml, L"EventID");
    int eid = 0;
    try { eid = std::stoi(eventIdStr); } catch (...) { return ERROR_SUCCESS; }

    if (eid == 1) {
        // Process Create
        std::string image   = XmlFieldValue(xml, L"Image");
        std::string cmdLine = XmlFieldValue(xml, L"CommandLine");
        std::string parent  = XmlFieldValue(xml, L"ParentImage");
        std::string pidStr  = XmlFieldValue(xml, L"ProcessId");
        UINT32 pid = 0;
        try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}

        std::string imgLow = ToLowerCopy(image);
        std::string cmdLow = ToLowerCopy(cmdLine);
        DetectionSeverity sev = DetectionSeverity::Info;
        std::string reason;

        if (cmdLow.find("mimikatz") != std::string::npos ||
            cmdLow.find("sekurlsa") != std::string::npos ||
            cmdLow.find("lsadump") != std::string::npos) {
            sev = DetectionSeverity::Critical;
            reason = "Credential-tool keyword in command line";
        } else if (imgLow.find("powershell") != std::string::npos &&
                   (cmdLow.find("-enc") != std::string::npos ||
                    cmdLow.find("-encodedcommand") != std::string::npos)) {
            sev = DetectionSeverity::High;
            reason = "Encoded PowerShell execution";
        } else if ((imgLow.find("wscript") != std::string::npos ||
                    imgLow.find("cscript") != std::string::npos) &&
                   (cmdLow.find(".vbs") != std::string::npos ||
                    cmdLow.find(".js") != std::string::npos)) {
            sev = DetectionSeverity::Medium;
            reason = "Script host launching script file";
        } else {
            return ERROR_SUCCESS; // not interesting
        }

        std::string ts  = BuildTimestamp();
        std::string img = image.substr(image.rfind('\\') + 1);
        std::string msg = std::to_string(tab_1_menu_items.size()) +
            " - [Sysmon EID 1] | " + ts + " | " + img + " | " + reason;
        std::string det = "Date & Time: " + ts +
            " | PID: " + pidStr +
            " | Image: " + image +
            " | Parent: " + parent +
            " | CmdLine: " + cmdLine.substr(0, 256);

        PushUiDetectionEvent(msg, det, "Method: Sysmon EID 1 (Process Create)", pid, sev);
    }
    else if (eid == 3) {
        // Network Connect — flag known C2 staging ports
        std::string image   = XmlFieldValue(xml, L"Image");
        std::string dstIp   = XmlFieldValue(xml, L"DestinationIp");
        std::string dstPort = XmlFieldValue(xml, L"DestinationPort");
        std::string pidStr  = XmlFieldValue(xml, L"ProcessId");
        UINT32 pid = 0;
        try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}
        int port = 0;
        try { port = std::stoi(dstPort); } catch (...) {}

        static const int kSuspiciousPorts[] = { 1234, 4444, 4445, 5555, 6666, 8888, 9001 };
        bool suspicious = false;
        for (int p : kSuspiciousPorts) if (port == p) { suspicious = true; break; }
        if (!suspicious) return ERROR_SUCCESS;

        std::string ts  = BuildTimestamp();
        std::string img = image.substr(image.rfind('\\') + 1);
        std::string msg = std::to_string(tab_1_menu_items.size()) +
            " - [Sysmon EID 3] | " + ts + " | " + img +
            " -> " + dstIp + ":" + dstPort;
        std::string det = "Date & Time: " + ts +
            " | PID: " + pidStr +
            " | Image: " + image +
            " | Dst: " + dstIp + ":" + dstPort + " (suspicious port)";

        PushUiDetectionEvent(msg, det, "Method: Sysmon EID 3 (Network Connect - Suspicious Port)",
                             pid, DetectionSeverity::Medium);
    }
    else if (eid == 7) {
        // Image Load — unsigned DLL from temp/appdata
        std::string image   = XmlFieldValue(xml, L"Image");
        std::string loaded  = XmlFieldValue(xml, L"ImageLoaded");
        std::string signedS = XmlFieldValue(xml, L"Signed");
        std::string pidStr  = XmlFieldValue(xml, L"ProcessId");
        UINT32 pid = 0;
        try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}

        std::string loadLow = ToLowerCopy(loaded);
        bool fromTemp    = loadLow.find("\\temp\\")    != std::string::npos ||
                           loadLow.find("\\appdata\\") != std::string::npos;
        bool isUnsigned  = ToLowerCopy(signedS) == "false";
        if (!fromTemp && !isUnsigned) return ERROR_SUCCESS;

        DetectionSeverity sev = (isUnsigned && fromTemp) ?
            DetectionSeverity::High : DetectionSeverity::Medium;
        std::string reason = isUnsigned ? "unsigned" : "";
        if (fromTemp) reason += std::string(reason.empty() ? "" : " + ") + "loaded from user-writable path";

        std::string ts  = BuildTimestamp();
        std::string dll = loaded.substr(loaded.rfind('\\') + 1);
        std::string msg = std::to_string(tab_1_menu_items.size()) +
            " - [Sysmon EID 7] | " + ts + " | " + dll + " | " + reason;
        std::string det = "Date & Time: " + ts +
            " | PID: " + pidStr +
            " | Loader: " + image +
            " | DLL: " + loaded +
            " | Signed: " + signedS;

        PushUiDetectionEvent(msg, det, "Method: Sysmon EID 7 (Suspicious Image Load)",
                             pid, sev);
    }
    else if (eid == 10) {
        // Process Access — anything touching lsass
        std::string srcImage = XmlFieldValue(xml, L"SourceImage");
        std::string tgtImage = XmlFieldValue(xml, L"TargetImage");
        std::string access   = XmlFieldValue(xml, L"GrantedAccess");
        std::string pidStr   = XmlFieldValue(xml, L"SourceProcessId");
        UINT32 pid = 0;
        try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}

        if (ToLowerCopy(tgtImage).find("lsass.exe") == std::string::npos)
            return ERROR_SUCCESS;

        std::string ts  = BuildTimestamp();
        std::string src = srcImage.substr(srcImage.rfind('\\') + 1);
        std::string msg = std::to_string(tab_1_menu_items.size()) +
            " - [Sysmon EID 10] | " + ts + " | " + src +
            " -> lsass.exe [access: " + access + "]";
        std::string det = "Date & Time: " + ts +
            " | PID: " + pidStr +
            " | Source: " + srcImage +
            " | Target: " + tgtImage +
            " | GrantedAccess: " + access;

        PushUiDetectionEvent(msg, det, "Method: Sysmon EID 10 (LSASS Process Access)",
                             pid, DetectionSeverity::Critical);
    }
    else if (eid == 22) {
        // DNS Query — flag suspiciously long first labels (DGA heuristic)
        std::string image  = XmlFieldValue(xml, L"Image");
        std::string query  = XmlFieldValue(xml, L"QueryName");
        std::string pidStr = XmlFieldValue(xml, L"ProcessId");
        UINT32 pid = 0;
        try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}

        std::string firstLabel = query.substr(0, query.find('.'));
        if (firstLabel.size() <= 20) return ERROR_SUCCESS;

        std::string ts  = BuildTimestamp();
        std::string img = image.substr(image.rfind('\\') + 1);
        std::string msg = std::to_string(tab_1_menu_items.size()) +
            " - [Sysmon EID 22] | " + ts + " | " + img +
            " queried: " + query;
        std::string det = "Date & Time: " + ts +
            " | PID: " + pidStr +
            " | Image: " + image +
            " | DNS query: " + query + " (long label - possible DGA)";

        PushUiDetectionEvent(msg, det, "Method: Sysmon EID 22 (Suspicious DNS Query)",
                             pid, DetectionSeverity::Low);
    }

    return ERROR_SUCCESS;
}

static void SysmonSubscriberThread() {
    g_sysmonSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-Sysmon/Operational",
        L"*",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(SysmonEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_sysmonSubscription) {
        std::cerr << "[Sysmon] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    while (!g_sysmonStop.load()) Sleep(500);

    EvtClose(g_sysmonSubscription);
    g_sysmonSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// SACL-based auditing
// ---------------------------------------------------------------------------

static bool ApplyLsassSACL() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD lsassPid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                lsassPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (!lsassPid) {
        std::cerr << "[SACL] lsass.exe not found\n";
        return false;
    }

    // ACCESS_SYSTEM_SECURITY needed to write SACL on a kernel object
    HANDLE hLsass = OpenProcess(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, lsassPid);
    if (!hLsass) {
        std::cerr << "[SACL] OpenProcess(lsass) failed: " << GetLastError() << "\n";
        return false;
    }

    // SDDL: success+failure audit of PROCESS_VM_READ(0x10)|VM_WRITE(0x20)|DUP_HANDLE(0x40)
    // for Everyone (WD).
    PSECURITY_DESCRIPTOR pSd = nullptr;
    BOOL ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"S:(AU;SAFA;0x0070;;;WD)", SDDL_REVISION_1, &pSd, nullptr);
    if (!ok) { CloseHandle(hLsass); return false; }

    BOOL hasSacl = FALSE, saclDef = FALSE;
    PACL pSacl = nullptr;
    GetSecurityDescriptorSacl(pSd, &hasSacl, &pSacl, &saclDef);

    DWORD err = ERROR_SUCCESS;
    if (hasSacl && pSacl) {
        err = SetSecurityInfo(hLsass, SE_KERNEL_OBJECT,
                              SACL_SECURITY_INFORMATION,
                              nullptr, nullptr, nullptr, pSacl);
    }
    LocalFree(pSd);
    CloseHandle(hLsass);

    if (err != ERROR_SUCCESS)
        std::cerr << "[SACL] SetSecurityInfo(lsass) failed: " << err << "\n";
    return err == ERROR_SUCCESS;
}

static bool ApplyRegistryKeySACL(LPCWSTR keyPath) {
    PSECURITY_DESCRIPTOR pSd = nullptr;
    BOOL ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"S:(AU;SAFA;KR;;;WD)", SDDL_REVISION_1, &pSd, nullptr);
    if (!ok) return false;

    BOOL hasSacl = FALSE, saclDef = FALSE;
    PACL pSacl = nullptr;
    GetSecurityDescriptorSacl(pSd, &hasSacl, &pSacl, &saclDef);

    DWORD err = ERROR_SUCCESS;
    if (hasSacl && pSacl) {
        std::wstring fullPath = std::wstring(L"MACHINE\\") + keyPath;
        err = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(fullPath.c_str()),
            SE_REGISTRY_KEY,
            SACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, pSacl);
    }
    LocalFree(pSd);

    if (err != ERROR_SUCCESS)
        std::wcerr << L"[SACL] SetNamedSecurityInfoW(" << keyPath
                   << L") failed: " << err << L"\n";
    return err == ERROR_SUCCESS;
}

static void SetupAuditSACLs() {
    if (!EnablePrivilege(SE_SECURITY_NAME)) {
        std::cerr << "[SACL] SeSecurityPrivilege unavailable — SACL auditing skipped\n";
        return;
    }

    bool ok = true;
    ok &= ApplyLsassSACL();
    ok &= ApplyRegistryKeySACL(L"SECURITY\\SAM");
    ok &= ApplyRegistryKeySACL(L"SECURITY\\Policy\\Secrets");

    g_saclReady = ok;
    std::cerr << (ok ? "[SACL] Audit SACLs applied\n"
                     : "[SACL] Partial SACL coverage (some failed)\n");
}

static DWORD WINAPI SecurityAuditEventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                                PVOID /*ctx*/, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    LPWSTR xmlBuf = RenderEventXml(hEvent);
    if (!xmlBuf) return ERROR_SUCCESS;
    std::wstring xml(xmlBuf);
    free(xmlBuf);

    std::string eventIdStr = XmlElementValue(xml, L"EventID");
    int eid = 0;
    try { eid = std::stoi(eventIdStr); } catch (...) { return ERROR_SUCCESS; }
    if (eid != 4656 && eid != 4663) return ERROR_SUCCESS;

    std::string objectName  = XmlFieldValue(xml, L"ObjectName");
    std::string processName = XmlFieldValue(xml, L"ProcessName");
    std::string subject     = XmlFieldValue(xml, L"SubjectUserName");
    std::string accessMask  = XmlFieldValue(xml, L"AccessMask");
    std::string pidStr      = XmlFieldValue(xml, L"ProcessId");
    UINT32 pid = 0;
    try { pid = static_cast<UINT32>(std::stoul(pidStr)); } catch (...) {}

    std::string objLow  = ToLowerCopy(objectName);
    std::string procLow = ToLowerCopy(processName);

    bool isLsass   = objLow.find("lsass")   != std::string::npos;
    bool isSam     = objLow.find("\\sam")   != std::string::npos;
    bool isSecrets = objLow.find("secrets") != std::string::npos;

    if (!isLsass && !isSam && !isSecrets) return ERROR_SUCCESS;
    // Suppress self-reads
    if (pid == curPid) return ERROR_SUCCESS;
    if (isLsass && procLow.find("lsass.exe") != std::string::npos)
        return ERROR_SUCCESS;

    DetectionSeverity sev;
    std::string targetDesc;
    if (isLsass)        { sev = DetectionSeverity::Critical; targetDesc = "LSASS process"; }
    else if (isSecrets) { sev = DetectionSeverity::High;     targetDesc = "LSA Secrets registry key"; }
    else                { sev = DetectionSeverity::High;     targetDesc = "SAM registry key"; }

    std::string ts    = BuildTimestamp();
    std::string proc  = processName.substr(processName.rfind('\\') + 1);
    std::string eidLbl = (eid == 4656) ? "4656 (Handle)" : "4663 (Access)";

    std::string msg = std::to_string(tab_1_menu_items.size()) +
        " - [Security EID " + eidLbl + "] | " + ts +
        " | " + proc + " accessed " + targetDesc;
    std::string det = "Date & Time: " + ts +
        " | PID: " + pidStr +
        " | Process: " + processName +
        " | User: " + subject +
        " | Object: " + objectName +
        " | AccessMask: " + accessMask;

    PushUiDetectionEvent(msg, det,
        "Method: SACL Audit (Security EID " + std::to_string(eid) + ")",
        pid, sev);

    return ERROR_SUCCESS;
}

static void SecurityAuditSubscriberThread() {
    if (!g_saclReady) {
        std::cerr << "[SACL] Subscriber not starting (SACLs not applied)\n";
        return;
    }

    g_saclSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Security",
        L"*[System[(EventID=4656 or EventID=4663)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(SecurityAuditEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_saclSubscription) {
        std::cerr << "[SACL] EvtSubscribe(Security) failed: " << GetLastError() << "\n";
        return;
    }

    while (!g_saclStop.load()) Sleep(500);

    EvtClose(g_saclSubscription);
    g_saclSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// ETW-TI real-time consumer
// Provider: Microsoft-Windows-Threat-Intelligence
// GUID:     {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
//
// Requires SeSystemEnvironmentPrivilege + SeDebugPrivilege, or a PPL process.
// Falls back gracefully if access is denied (non-PPL user-mode process).
//
// Remote task IDs surfaced as injection indicators:
//   2  ProtectVM-Remote      4  MapView-Remote
//   5  QueueUserAPC-Remote   6  SetThreadContext-Remote
//   8  AllocVM-Remote       10  ReadVM-Remote   12  WriteVM-Remote
// ---------------------------------------------------------------------------

static const GUID kTiProviderGuid = {
    0xF4E1897C, 0xBB5D, 0x5668,
    {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}
};

static const wchar_t* TiTaskName(USHORT task) {
    switch (task) {
    case  2: return L"ProtectVM-Remote";
    case  4: return L"MapView-Remote";
    case  5: return L"QueueUserAPC-Remote";
    case  6: return L"SetThreadContext-Remote";
    case  8: return L"AllocVM-Remote";
    case 10: return L"ReadVM-Remote";
    case 12: return L"WriteVM-Remote";
    default: return nullptr;
    }
}

static void WINAPI TiEventCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, kTiProviderGuid)) return;

    USHORT task = pEvent->EventHeader.EventDescriptor.Task;
    const wchar_t* taskNameW = TiTaskName(task);
    if (!taskNameW) return; // local ops or unrecognised — skip

    UINT32 callerPid = pEvent->EventHeader.ProcessId;
    if (callerPid == 0 || callerPid == curPid) return;

    // Extract TargetProcessId from UserData when present (first UINT32 after
    // two FILETIME fields = 8 bytes header + 8 bytes CallerCreateTime = offset 12).
    // Layout: CallerPid(4) CallerCreateTime(8) TargetPid(4) ...
    UINT32 targetPid = 0;
    if (pEvent->UserDataLength >= 16) {
        const BYTE* d = static_cast<const BYTE*>(pEvent->UserData);
        memcpy(&targetPid, d + 12, sizeof(targetPid));
    }

    std::string taskName(taskNameW, taskNameW + wcslen(taskNameW));
    std::string ts = BuildTimestamp();

    std::string procName;
    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        auto it = g_processCache.find(callerPid);
        if (it != g_processCache.end()) procName = it->second.processName;
    }
    if (procName.empty()) procName = std::to_string(callerPid);

    std::string msg = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Alert] | " + ts +
        " | " + procName +
        " | Method: ETW-TI" +
        " | " + taskName +
        (targetPid ? " -> PID " + std::to_string(targetPid) : "");

    std::string det = "Date & Time: " + ts +
        " | " + procName +
        " | PID: " + std::to_string(callerPid) +
        " | Method: ETW Threat-Intelligence" +
        " | Operation: " + taskName +
        (targetPid ? " | Target PID: " + std::to_string(targetPid) : "");

    PushUiDetectionEvent(msg, det, "Method: ETW Threat-Intelligence",
                         callerPid, DetectionSeverity::High);
}


static void EtwTiSubscriberThread() {
    // Attempt privilege escalation required for ETW-TI
    EnablePrivilege(SE_SYSTEM_ENVIRONMENT_NAME);
    EnablePrivilege(SE_DEBUG_NAME);

    const wchar_t* kSessionName = L"NortonEDR-TI";

    // Allocate EVENT_TRACE_PROPERTIES (name goes immediately after the struct)
    const size_t nameBufBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
    const size_t propBufSize  = sizeof(EVENT_TRACE_PROPERTIES) + nameBufBytes;
    auto* props = static_cast<PEVENT_TRACE_PROPERTIES>(malloc(propBufSize));
    if (!props) return;

    auto buildProps = [&]() {
        ZeroMemory(props, propBufSize);
        props->Wnode.BufferSize    = static_cast<ULONG>(propBufSize);
        props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s(reinterpret_cast<wchar_t*>(
            reinterpret_cast<BYTE*>(props) + props->LoggerNameOffset),
            wcslen(kSessionName) + 1, kSessionName);
    };

    buildProps();
    ULONG status = StartTraceW(&g_tiSessionHandle, kSessionName, props);
    if (status == ERROR_ALREADY_EXISTS) {
        buildProps();
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        buildProps();
        status = StartTraceW(&g_tiSessionHandle, kSessionName, props);
    }
    free(props);

    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW-TI] StartTrace failed: " << status
                  << " (access denied without PPL — skipping)\n";
        return;
    }

    // Enable the TI provider on this session
    ENABLE_TRACE_PARAMETERS etp{};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        g_tiSessionHandle, &kTiProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFFULL, 0, 0, &etp);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW-TI] EnableTraceEx2 failed: " << status << "\n";
        EVENT_TRACE_PROPERTIES stopProps{};
        stopProps.Wnode.BufferSize = sizeof(stopProps);
        ControlTraceW(g_tiSessionHandle, nullptr, &stopProps,
                      EVENT_TRACE_CONTROL_STOP);
        g_tiSessionHandle = 0;
        return;
    }

    std::cout << "[ETW-TI] Session started — consuming threat-intelligence events\n";

    // Open the real-time trace
    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName       = const_cast<LPWSTR>(kSessionName);
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = TiEventCallback;

    g_tiTraceHandle = OpenTraceW(&logFile);
    if (g_tiTraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW-TI] OpenTrace failed: " << GetLastError() << "\n";
        return;
    }

    // ProcessTrace blocks until CloseTrace is called from another thread
    ProcessTrace(&g_tiTraceHandle, 1, nullptr, nullptr);
    g_tiTraceHandle = INVALID_PROCESSTRACE_HANDLE;
}

static void StopEtwTiSession() {
    if (g_tiTraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_tiTraceHandle);
        g_tiTraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_tiSessionHandle) {
        EVENT_TRACE_PROPERTIES stopProps{};
        stopProps.Wnode.BufferSize = sizeof(stopProps);
        ControlTraceW(g_tiSessionHandle, nullptr, &stopProps,
                      EVENT_TRACE_CONTROL_STOP);
        g_tiSessionHandle = 0;
    }
}

// ---------------------------------------------------------------------------
// Microsoft-Windows-Kernel-Process ETW consumer
// Provider GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
//
// Implements the F-Secure "Detecting Parent PID Spoofing" technique:
//   ProcessStart (event ID 1) carries both:
//     ParentProcessID  — the claimed parent (spoofable via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
//     EventHeader.ProcessId — the actual creating process (kernel-populated, unforgeable)
//   A mismatch is PPID spoofing.
//
// This is an independent telemetry channel from the kernel driver callback —
// it fires from the OS's own process accounting, providing a second opinion
// that remains valid even if the driver is temporarily unloaded.
//
// No special privileges required (unlike ETW-TI).
// ---------------------------------------------------------------------------
static const GUID kKernelProcessProviderGuid = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

static void WINAPI KernelProcessEventCallback(PEVENT_RECORD pEvent)
{
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, kKernelProcessProviderGuid)) return;
    if (pEvent->EventHeader.EventDescriptor.Id != 1) return;  // ProcessStart only
    if (pEvent->UserDataLength < 8) return;

    const BYTE* d = static_cast<const BYTE*>(pEvent->UserData);
    UINT32 newPid    = 0;
    UINT32 parentPid = 0;
    memcpy(&newPid,    d + 0, 4);
    memcpy(&parentPid, d + 4, 4);

    // EventHeader.ProcessId = the actual creating process (kernel-populated)
    UINT32 creatorPid = pEvent->EventHeader.ProcessId;

    // Skip kernel/system (PID 0/4) and self
    if (creatorPid == 0 || creatorPid == 4 || newPid == 0) return;
    if (creatorPid == curPid) return;
    if (parentPid == creatorPid) return;  // no spoofing

    // ImageName: null-terminated UTF-16 at offset 8
    std::string imageName;
    if (pEvent->UserDataLength > 8) {
        const wchar_t* wname = reinterpret_cast<const wchar_t*>(d + 8);
        size_t remaining = (pEvent->UserDataLength - 8) / sizeof(wchar_t);
        size_t nameLen = 0;
        while (nameLen < remaining && wname[nameLen] != L'\0') nameLen++;
        if (nameLen > 0 && nameLen < 260) {
            imageName.resize(nameLen);
            for (size_t i = 0; i < nameLen; i++)
                imageName[i] = (wname[i] < 128) ? static_cast<char>(wname[i]) : '?';
        }
    }
    if (imageName.empty()) imageName = "pid=" + std::to_string(newPid);

    std::string creatorName, parentName;
    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        auto it = g_processCache.find(creatorPid);
        if (it != g_processCache.end()) creatorName = it->second.processName;
        it = g_processCache.find(parentPid);
        if (it != g_processCache.end()) parentName = it->second.processName;
    }
    if (creatorName.empty()) creatorName = std::to_string(creatorPid);
    if (parentName.empty())  parentName  = std::to_string(parentPid);

    std::string ts = BuildTimestamp();
    std::string det = "Date & Time: " + ts +
        " | Method: ETW Kernel-Process" +
        " | PPID Spoofing detected" +
        " | child: " + imageName + " (pid=" + std::to_string(newPid) + ")" +
        " | real_creator: " + creatorName + " (pid=" + std::to_string(creatorPid) + ")" +
        " | spoofed_parent: " + parentName + " (pid=" + std::to_string(parentPid) + ")";

    std::string msg = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Alert] | " + ts +
        " | " + creatorName +
        " | Method: ETW Kernel-Process" +
        " | PPID Spoofing: child=" + imageName +
        " spoofed_parent=" + parentName + " (pid=" + std::to_string(parentPid) + ")";

    PushUiDetectionEvent(msg, det, "Method: ETW Kernel-Process | PPID Spoofing",
                         creatorPid, DetectionSeverity::Critical);
}

static void KernelProcessSubscriberThread()
{
    const wchar_t* kSessionName = L"NortonEDR-KernelProcess";
    const size_t nameBufBytes   = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
    const size_t propBufSize    = sizeof(EVENT_TRACE_PROPERTIES) + nameBufBytes;
    auto* props = static_cast<PEVENT_TRACE_PROPERTIES>(malloc(propBufSize));
    if (!props) return;

    auto buildProps = [&]() {
        ZeroMemory(props, propBufSize);
        props->Wnode.BufferSize   = static_cast<ULONG>(propBufSize);
        props->Wnode.Flags        = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s(reinterpret_cast<wchar_t*>(
            reinterpret_cast<BYTE*>(props) + props->LoggerNameOffset),
            wcslen(kSessionName) + 1, kSessionName);
    };

    buildProps();
    ULONG status = StartTraceW(&g_kpSessionHandle, kSessionName, props);
    if (status == ERROR_ALREADY_EXISTS) {
        buildProps();
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        buildProps();
        status = StartTraceW(&g_kpSessionHandle, kSessionName, props);
    }
    free(props);

    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW-KP] StartTrace failed: " << status << "\n";
        return;
    }

    ENABLE_TRACE_PARAMETERS etp{};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        g_kpSessionHandle, &kKernelProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFFULL, 0, 0, &etp);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW-KP] EnableTraceEx2 failed: " << status << "\n";
        EVENT_TRACE_PROPERTIES stopProps{};
        stopProps.Wnode.BufferSize = sizeof(stopProps);
        ControlTraceW(g_kpSessionHandle, nullptr, &stopProps, EVENT_TRACE_CONTROL_STOP);
        g_kpSessionHandle = 0;
        return;
    }

    std::cout << "[ETW-KP] Session started — consuming Microsoft-Windows-Kernel-Process events\n";

    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName          = const_cast<LPWSTR>(kSessionName);
    logFile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = KernelProcessEventCallback;

    g_kpTraceHandle = OpenTraceW(&logFile);
    if (g_kpTraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW-KP] OpenTrace failed: " << GetLastError() << "\n";
        return;
    }

    ProcessTrace(&g_kpTraceHandle, 1, nullptr, nullptr);
    g_kpTraceHandle = INVALID_PROCESSTRACE_HANDLE;
}

static void StopKernelProcessSession()
{
    if (g_kpTraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_kpTraceHandle);
        g_kpTraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_kpSessionHandle) {
        EVENT_TRACE_PROPERTIES stopProps{};
        stopProps.Wnode.BufferSize = sizeof(stopProps);
        ControlTraceW(g_kpSessionHandle, nullptr, &stopProps, EVENT_TRACE_CONTROL_STOP);
        g_kpSessionHandle = 0;
    }
}

// ---------------------------------------------------------------------------
// PowerShell script-block logging (EID 4104)
// Channel: Microsoft-Windows-PowerShell/Operational
// ---------------------------------------------------------------------------

static DWORD WINAPI PowerShellEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string scriptBlock = GetXmlField(xml, "ScriptBlockText");
    if (scriptBlock.empty()) return ERROR_SUCCESS;

    std::string ts    = BuildTimestamp();
    UINT32      pid   = 0;

    std::string pidStr = GetXmlField(xml, "ProcessID");
    if (!pidStr.empty()) {
        try { pid = static_cast<UINT32>(std::stoul(pidStr, nullptr, 0)); }
        catch (...) {}
    }

    // Trim for display
    std::string preview = scriptBlock.size() > 120
        ? scriptBlock.substr(0, 120) + "..."
        : scriptBlock;

    // Run Sigma rules against the script block content (same pipeline as Sysmon)
    std::string procName = "powershell";
    NotifySigmaMatches(pid, procName, { scriptBlock }, "PowerShell/4104");

    // Always surface script block loads as Info; Sigma can escalate
    std::string msg = std::to_string(tab_1_menu_items.size()) +
        " - [i] [Info] | " + ts +
        " | powershell | Method: PS Script-Block Logging | " + preview;

    std::string det = "Date & Time: " + ts +
        " | powershell | PID: " + std::to_string(pid) +
        " | Method: PowerShell Script-Block Logging (EID 4104)" +
        " | Script: " + scriptBlock.substr(0, 512);

    PushUiDetectionEvent(msg, det, "Method: PowerShell Script-Block Logging",
                         pid, DetectionSeverity::Info);
    return ERROR_SUCCESS;
}

static void PowerShellSubscriberThread() {
    g_psSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-PowerShell/Operational",
        L"*[System[(EventID=4104)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(PowerShellEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_psSubscription) {
        std::cerr << "[PS] EvtSubscribe failed: " << GetLastError()
                  << " (enable PS script-block logging via GPO)\n";
        return;
    }

    std::cout << "[PS] Script-block logging subscriber active\n";
    while (!g_psStop.load()) Sleep(500);
    EvtClose(g_psSubscription);
    g_psSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// DNS-Client query logging (EID 3006)
// Channel: Microsoft-Windows-DNS-Client/Operational
// ---------------------------------------------------------------------------

static DWORD WINAPI DnsEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string queryName = GetXmlField(xml, "QueryName");
    if (queryName.empty()) return ERROR_SUCCESS;

    UINT32 pid = 0;
    std::string pidStr = GetXmlField(xml, "ProcessID");
    if (!pidStr.empty()) {
        try { pid = static_cast<UINT32>(std::stoul(pidStr, nullptr, 0)); }
        catch (...) {}
    }

    // Reuse the existing Sysmon EID-22 DGA heuristic (long label detection)
    // by routing through Sigma matching on the query name
    NotifySigmaMatches(pid, "dns-client", { queryName }, "DNS/3006");

    return ERROR_SUCCESS;
}

static void DnsSubscriberThread() {
    g_dnsSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-DNS-Client/Operational",
        L"*[System[(EventID=3006)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(DnsEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_dnsSubscription) {
        std::cerr << "[DNS] EvtSubscribe failed: " << GetLastError()
                  << " (DNS-Client operational channel may be unavailable)\n";
        return;
    }

    std::cout << "[DNS] Client query subscriber active\n";
    while (!g_dnsStop.load()) Sleep(500);
    EvtClose(g_dnsSubscription);
    g_dnsSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// WinRM lateral-movement detection (EIDs 6, 8, 91)
// Channel: Microsoft-Windows-WinRM/Operational
// ---------------------------------------------------------------------------

static DWORD WINAPI WinRmEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string eidStr = GetXmlField(xml, "EventID");
    int eid = 0;
    try { eid = std::stoi(eidStr); } catch (...) { return ERROR_SUCCESS; }

    std::string ts = BuildTimestamp();

    const char* description = nullptr;
    DetectionSeverity sev = DetectionSeverity::Medium;
    switch (eid) {
    case   6: description = "WSMan client session created";       break;
    case   8: description = "WSMan client request sent";          break;
    case  91: description = "WSMan session creation initiated";   break;
    case 132: description = "WSMan HTTP request"; sev = DetectionSeverity::Low; break;
    default: return ERROR_SUCCESS;
    }

    UINT32 pid = 0;
    std::string pidStr = GetXmlField(xml, "ProcessID");
    if (!pidStr.empty()) {
        try { pid = static_cast<UINT32>(std::stoul(pidStr, nullptr, 0)); }
        catch (...) {}
    }

    std::string procName;
    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        auto it = g_processCache.find(pid);
        if (it != g_processCache.end()) procName = it->second.processName;
    }
    if (procName.empty()) procName = "winrm-client";

    std::string msg = std::to_string(tab_1_menu_items.size()) +
        " - [*] [Warning] | " + ts +
        " | " + procName +
        " | Method: WinRM Lateral Movement Detection"
        " | EID " + std::to_string(eid) + ": " + description;

    std::string det = "Date & Time: " + ts +
        " | " + procName +
        " | PID: " + std::to_string(pid) +
        " | Method: WinRM Lateral Movement Detection" +
        " | EventID: " + std::to_string(eid) +
        " | " + description;

    PushUiDetectionEvent(msg, det, "Method: WinRM Lateral Movement Detection",
                         pid, sev);
    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Elasticsearch helpers
// ---------------------------------------------------------------------------

static std::string GetIso8601Timestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::string JsonEscapeStr(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c >= 0x20) out += (char)c;
        }
    }
    return out;
}

static std::string Base64Encode(const std::string& input) {
    DWORD outLen = 0;
    CryptBinaryToStringA(
        (const BYTE*)input.data(), (DWORD)input.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA(
        (const BYTE*)input.data(), (DWORD)input.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// Map severity label to ECS numeric severity (higher = more severe)
static int SeverityToEcsInt(const std::string& label) {
    if (label == "critical") return 100;
    if (label == "high")     return 75;
    if (label == "medium")   return 50;
    if (label == "low")      return 25;
    return 10; // info
}

// Build a single ECS-aligned JSON document for the bulk body (no newline appended).
static std::string BuildEcsDocument(
    const std::string& severity,
    UINT32 pid,
    const std::string& method,
    const std::string& summary,
    const std::string& details)
{
    std::string det = details.size() > 512 ? details.substr(0, 512) + "..." : details;

    std::string doc = "{";
    doc += "\"@timestamp\":\"" + GetIso8601Timestamp() + "\",";
    doc += "\"agent\":{\"name\":\"NortonEDR\",\"type\":\"endpoint\"},";
    doc += "\"host\":{\"name\":\"" + JsonEscapeStr(g_hostname) + "\"},";
    doc += "\"event\":{";
    doc +=   "\"kind\":\"alert\",";
    doc +=   "\"category\":[\"intrusion_detection\"],";
    doc +=   "\"type\":[\"info\"],";
    doc +=   "\"severity\":" + std::to_string(SeverityToEcsInt(severity)) + ",";
    doc +=   "\"action\":\"" + JsonEscapeStr(method) + "\"";
    doc += "},";
    doc += "\"process\":{\"pid\":" + std::to_string(pid) + "},";
    doc += "\"rule\":{\"name\":\"" + JsonEscapeStr(summary) + "\"},";
    doc += "\"message\":\"" + JsonEscapeStr(summary) + "\",";
    doc += "\"nortonav\":{";
    doc +=   "\"details\":\"" + JsonEscapeStr(det) + "\",";
    doc +=   "\"severity_label\":\"" + severity + "\"";
    doc += "}";
    doc += "}";
    return doc;
}

static bool ParseElasticUrl(
    const std::string& url,
    bool& outHttps,
    std::wstring& outHost,
    INTERNET_PORT& outPort,
    std::wstring& outPathPrefix)
{
    std::string rest;
    if (url.rfind("https://", 0) == 0) { outHttps = true;  rest = url.substr(8); }
    else if (url.rfind("http://", 0) == 0) { outHttps = false; rest = url.substr(7); }
    else return false;

    size_t pathPos = rest.find('/');
    std::string hostPort = (pathPos != std::string::npos) ? rest.substr(0, pathPos) : rest;
    outPathPrefix = (pathPos != std::string::npos)
        ? std::wstring(rest.begin() + (int)pathPos, rest.end())
        : L"";

    size_t colon = hostPort.rfind(':');
    if (colon != std::string::npos) {
        outHost = std::wstring(hostPort.begin(), hostPort.begin() + (int)colon);
        outPort = (INTERNET_PORT)std::stoi(hostPort.substr(colon + 1));
    } else {
        outHost = std::wstring(hostPort.begin(), hostPort.end());
        outPort = outHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }
    return !outHost.empty();
}

static void ShipBatch(const std::vector<std::string>& docs) {
    if (!g_elasticConfig.enabled || docs.empty()) return;

    // Build NDJSON body: action + document per event
    std::string body;
    body.reserve(docs.size() * 512);
    for (const auto& doc : docs) {
        body += "{\"index\":{}}\n";
        body += doc;
        body += "\n";
    }

    bool isHttps = true;
    std::wstring host, pathPrefix;
    INTERNET_PORT port = 9200;
    if (!ParseElasticUrl(g_elasticConfig.host, isHttps, host, port, pathPrefix)) {
        std::cerr << "[Elastic] Invalid host URL: " << g_elasticConfig.host << "\n";
        return;
    }

    std::wstring indexW(g_elasticConfig.index.begin(), g_elasticConfig.index.end());
    std::wstring bulkPath = pathPrefix + L"/" + indexW + L"/_bulk";

    HINTERNET hSession = WinHttpOpen(L"NortonEDR/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    DWORD timeout = 5000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT,  &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT,     &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT,  &timeout, sizeof(timeout));

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", bulkPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (isHttps && !g_elasticConfig.tlsVerify) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA       |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID  |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // Authorization header
    std::wstring headers = L"Content-Type: application/x-ndjson\r\n";
    if (!g_elasticConfig.apiKey.empty()) {
        std::wstring keyW(g_elasticConfig.apiKey.begin(), g_elasticConfig.apiKey.end());
        headers += L"Authorization: ApiKey " + keyW + L"\r\n";
    } else if (!g_elasticConfig.username.empty()) {
        std::string b64 = Base64Encode(g_elasticConfig.username + ":" + g_elasticConfig.password);
        headers += L"Authorization: Basic " +
                   std::wstring(b64.begin(), b64.end()) + L"\r\n";
    }
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)headers.size(),
                             WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, nullptr);

    if (ok) {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status < 200 || status >= 300)
            std::cerr << "[Elastic] Bulk POST HTTP " << status
                      << " — " << docs.size() << " event(s) dropped\n";
    } else {
        std::cerr << "[Elastic] WinHTTP failed (err=" << GetLastError()
                  << ") — " << docs.size() << " event(s) dropped\n";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

static void ElasticShipperThread() {
    while (!g_elasticStop.load()) {
        std::vector<std::string> batch;
        {
            std::unique_lock<std::mutex> lock(g_elasticMutex);
            g_elasticCv.wait_for(lock,
                std::chrono::milliseconds(kElasticFlushMs),
                [&] {
                    return g_elasticStop.load() ||
                           g_elasticQueue.size() >= kElasticBatchSize;
                });
            while (!g_elasticQueue.empty() && batch.size() < kElasticBatchSize) {
                batch.push_back(std::move(g_elasticQueue.front()));
                g_elasticQueue.pop();
            }
        }
        if (!batch.empty()) ShipBatch(batch);
    }
    // Flush remaining events on shutdown
    std::vector<std::string> tail;
    {
        std::lock_guard<std::mutex> lock(g_elasticMutex);
        while (!g_elasticQueue.empty()) {
            tail.push_back(std::move(g_elasticQueue.front()));
            g_elasticQueue.pop();
        }
    }
    if (!tail.empty()) ShipBatch(tail);
}

static DetectionSeverity SeverityFromLabel(const char* s) {
    if (!s) return DetectionSeverity::Info;
    if (_stricmp(s, "critical") == 0) return DetectionSeverity::Critical;
    if (_stricmp(s, "high")     == 0) return DetectionSeverity::High;
    if (_stricmp(s, "warning")  == 0) return DetectionSeverity::Medium;
    if (_stricmp(s, "medium")   == 0) return DetectionSeverity::Medium;
    if (_stricmp(s, "low")      == 0) return DetectionSeverity::Low;
    return DetectionSeverity::Info;
}

// Called on a per-client thread; reads lines until the pipe client disconnects.
static void HandleHookPipeClient(HANDLE hPipe) {
    char buf[4096];
    DWORD total = 0;

    while (true) {
        DWORD read = 0;
        BOOL  ok   = ReadFile(hPipe, buf + total,
                              (DWORD)(sizeof(buf) - total - 1), &read, nullptr);
        if (!ok || read == 0) break;
        total += read;

        // Process all complete lines in the buffer
        char* lineStart = buf;
        buf[total] = '\0';

        char* newline;
        while ((newline = strchr(lineStart, '\n')) != nullptr) {
            *newline = '\0';

            // Parse: SEVERITY\tCALLER_PID\tAPI_NAME\tTARGET_PID\tDETAIL
            char   severityBuf[16]  = {};
            DWORD  callerPid        = 0;
            char   apiName[64]      = {};
            DWORD  targetPid        = 0;
            char   detail[512]      = {};

            // sscanf with tab delimiters
            int fields = sscanf_s(lineStart,
                "%15[^\t]\t%lu\t%63[^\t]\t%lu\t%511[^\r]",
                severityBuf, (unsigned)sizeof(severityBuf),
                &callerPid,
                apiName,     (unsigned)sizeof(apiName),
                &targetPid,
                detail,      (unsigned)sizeof(detail));

            if (fields >= 3) {
                std::string msg = std::string("HookDll: ") + apiName;
                std::string det = std::string(detail);
                if (targetPid)
                    det += "\nTarget PID: " + std::to_string(targetPid);
                det += "\nCaller PID: " + std::to_string(callerPid);

                PushUiDetectionEvent(msg, det,
                    "Method: User-Mode API Hook",
                    callerPid,
                    SeverityFromLabel(severityBuf));
            }

            lineStart = newline + 1;
        }

        // Shift remaining partial line to the front
        DWORD remaining = (DWORD)(buf + total - lineStart);
        if (remaining > 0 && lineStart != buf)
            memmove(buf, lineStart, remaining);
        total = remaining;
    }
}

static void HookPipeServerThread() {
    while (!g_hookPipeStop.load()) {
        HANDLE hPipe = CreateNamedPipeA(
            kHookPipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 4096, 0, nullptr
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Block until a client connects (or we're stopping)
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        // Service this client on a detached thread so we can accept the next
        std::thread([hPipe]() {
            HandleHookPipeClient(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }).detach();
    }
}

static void WinRmSubscriberThread() {
    g_winrmSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-WinRM/Operational",
        L"*[System[(EventID=6 or EventID=8 or EventID=91 or EventID=132)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(WinRmEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_winrmSubscription) {
        std::cerr << "[WinRM] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[WinRM] Operational subscriber active\n";
    while (!g_winrmStop.load()) Sleep(500);
    EvtClose(g_winrmSubscription);
    g_winrmSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// Security event log — extended (logon, explicit logon, process create,
// service install, scheduled task, privilege assignment)
// EIDs: 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4726, 4732, 4733
// ---------------------------------------------------------------------------
static DWORD WINAPI SecExtEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string eidStr = GetXmlField(xml, "EventID");
    int eid = 0;
    try { eid = std::stoi(eidStr); } catch (...) { return ERROR_SUCCESS; }

    std::string ts = BuildTimestamp();
    UINT32 pid = 0;
    std::string pidStr = GetXmlField(xml, "ProcessID");
    if (!pidStr.empty()) try { pid = static_cast<UINT32>(std::stoul(pidStr, nullptr, 0)); } catch (...) {}

    switch (eid) {

    case 4624: {
        // Successful logon — flag non-interactive remote types (3=network, 10=remoteinteractive)
        std::string logonType = GetXmlField(xml, "LogonType");
        std::string subjectUser = GetXmlField(xml, "SubjectUserName");
        std::string targetUser  = GetXmlField(xml, "TargetUserName");
        std::string workstation = GetXmlField(xml, "WorkstationName");
        std::string ipAddr      = GetXmlField(xml, "IpAddress");
        int lt = 0;
        try { lt = std::stoi(logonType); } catch (...) {}
        if (lt != 3 && lt != 10) return ERROR_SUCCESS;
        std::string ltLabel = (lt == 3) ? "Network" : "RemoteInteractive";
        std::string msg = "[Sec 4624] " + ts + " | Logon (" + ltLabel + ") " +
            targetUser + " from " + (ipAddr.empty() ? workstation : ipAddr);
        std::string det = "Date & Time: " + ts + " | EID 4624 Successful Logon" +
            " | Type: " + ltLabel + " | User: " + targetUser +
            " | Subject: " + subjectUser + " | Source: " + ipAddr;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Logon)", pid,
            lt == 10 ? DetectionSeverity::Medium : DetectionSeverity::Low);
        break;
    }

    case 4625: {
        // Failed logon
        std::string targetUser  = GetXmlField(xml, "TargetUserName");
        std::string ipAddr      = GetXmlField(xml, "IpAddress");
        std::string failureCode = GetXmlField(xml, "SubStatus");
        std::string msg = "[Sec 4625] " + ts + " | Failed logon: " + targetUser +
            " from " + (ipAddr.empty() ? "?" : ipAddr) + " (" + failureCode + ")";
        std::string det = "Date & Time: " + ts + " | EID 4625 Failed Logon" +
            " | User: " + targetUser + " | Source: " + ipAddr +
            " | Code: " + failureCode;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Failed Logon)", pid,
            DetectionSeverity::Low);
        break;
    }

    case 4648: {
        // Explicit credentials logon (runas / pass-the-hash)
        std::string subjectUser = GetXmlField(xml, "SubjectUserName");
        std::string targetUser  = GetXmlField(xml, "TargetUserName");
        std::string targetServer= GetXmlField(xml, "TargetServerName");
        std::string processName = GetXmlField(xml, "ProcessName");
        std::string msg = "[Sec 4648] " + ts + " | Explicit cred logon: " +
            subjectUser + " -> " + targetUser + "@" + targetServer;
        std::string det = "Date & Time: " + ts + " | EID 4648 Explicit Credential Logon" +
            " | Subject: " + subjectUser + " | Target: " + targetUser +
            " | Server: " + targetServer + " | Process: " + processName;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Explicit Credential Logon)",
            pid, DetectionSeverity::Medium);
        break;
    }

    case 4672: {
        // Special privileges assigned to new logon (admin/debug rights)
        std::string user   = GetXmlField(xml, "SubjectUserName");
        std::string privs  = GetXmlField(xml, "PrivilegeList");
        // Only alert if SeDebugPrivilege or SeTcbPrivilege is assigned
        if (privs.find("SeDebugPrivilege") == std::string::npos &&
            privs.find("SeTcbPrivilege")   == std::string::npos) return ERROR_SUCCESS;
        std::string msg = "[Sec 4672] " + ts + " | Sensitive privileges assigned: " +
            user + " | " + privs.substr(0, 80);
        std::string det = "Date & Time: " + ts + " | EID 4672 Special Privileges" +
            " | User: " + user + " | Privs: " + privs.substr(0, 256);
        PushUiDetectionEvent(msg, det, "Method: Security Log (Privilege Assignment)",
            pid, DetectionSeverity::Medium);
        break;
    }

    case 4688: {
        // Process creation with command line (requires audit policy)
        std::string newProcess  = GetXmlField(xml, "NewProcessName");
        std::string cmdLine     = GetXmlField(xml, "CommandLine");
        std::string creator     = GetXmlField(xml, "ParentProcessName");
        std::string newPidStr   = GetXmlField(xml, "NewProcessId");
        UINT32 newPid = 0;
        try { newPid = static_cast<UINT32>(std::stoul(newPidStr, nullptr, 0)); } catch (...) {}
        std::string cmdLow = ToLowerCopy(cmdLine);
        std::string procLow = ToLowerCopy(newProcess);
        // Only surface suspicious launches
        bool suspicious =
            cmdLow.find("mimikatz") != std::string::npos ||
            cmdLow.find("-enc") != std::string::npos ||
            cmdLow.find("invoke-") != std::string::npos ||
            cmdLow.find("downloadstring") != std::string::npos ||
            cmdLow.find("iex(") != std::string::npos ||
            cmdLow.find("iex (") != std::string::npos ||
            (procLow.find("cmd.exe") != std::string::npos && cmdLow.find("whoami") != std::string::npos) ||
            procLow.find("certutil") != std::string::npos ||
            procLow.find("mshta") != std::string::npos ||
            procLow.find("regsvr32") != std::string::npos ||
            procLow.find("rundll32") != std::string::npos;
        if (!suspicious) return ERROR_SUCCESS;
        std::string proc = newProcess.substr(newProcess.rfind('\\') + 1);
        std::string msg = "[Sec 4688] " + ts + " | " + proc + " | " +
            cmdLine.substr(0, 100);
        std::string det = "Date & Time: " + ts + " | EID 4688 Process Create" +
            " | Process: " + newProcess + " | PID: " + newPidStr +
            " | Parent: " + creator + " | CmdLine: " + cmdLine.substr(0, 512);
        PushUiDetectionEvent(msg, det, "Method: Security Log (Process Creation)",
            newPid, DetectionSeverity::High);
        break;
    }

    case 4697: {
        // Service installed
        std::string serviceName = GetXmlField(xml, "ServiceName");
        std::string serviceFile = GetXmlField(xml, "ServiceFileName");
        std::string user        = GetXmlField(xml, "SubjectUserName");
        std::string msg = "[Sec 4697] " + ts + " | Service installed: " +
            serviceName + " -> " + serviceFile.substr(serviceFile.rfind('\\') + 1);
        std::string det = "Date & Time: " + ts + " | EID 4697 Service Installed" +
            " | Name: " + serviceName + " | Binary: " + serviceFile +
            " | By: " + user;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Service Installation)",
            pid, DetectionSeverity::High);
        break;
    }

    case 4698:
    case 4702: {
        // Scheduled task created or updated
        std::string taskName    = GetXmlField(xml, "TaskName");
        std::string subjectUser = GetXmlField(xml, "SubjectUserName");
        std::string label = (eid == 4698) ? "created" : "updated";
        std::string msg = "[Sec " + eidStr + "] " + ts + " | Scheduled task " +
            label + ": " + taskName;
        std::string det = "Date & Time: " + ts + " | EID " + eidStr +
            " Scheduled Task " + label + " | Task: " + taskName +
            " | By: " + subjectUser;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Scheduled Task)", pid,
            DetectionSeverity::Medium);
        break;
    }

    case 4720: {
        std::string newUser = GetXmlField(xml, "TargetUserName");
        std::string byUser  = GetXmlField(xml, "SubjectUserName");
        std::string msg = "[Sec 4720] " + ts + " | Account created: " + newUser + " by " + byUser;
        std::string det = "Date & Time: " + ts + " | EID 4720 Account Created" +
            " | New: " + newUser + " | By: " + byUser;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Account Created)",
            pid, DetectionSeverity::Medium);
        break;
    }

    case 4726: {
        std::string delUser = GetXmlField(xml, "TargetUserName");
        std::string byUser  = GetXmlField(xml, "SubjectUserName");
        std::string msg = "[Sec 4726] " + ts + " | Account deleted: " + delUser + " by " + byUser;
        std::string det = "Date & Time: " + ts + " | EID 4726 Account Deleted" +
            " | User: " + delUser + " | By: " + byUser;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Account Deleted)",
            pid, DetectionSeverity::Medium);
        break;
    }

    case 4732:
    case 4733: {
        std::string member = GetXmlField(xml, "MemberName");
        std::string group  = GetXmlField(xml, "TargetUserName");
        std::string byUser = GetXmlField(xml, "SubjectUserName");
        // Only alert on admin-tier groups
        std::string groupLow = ToLowerCopy(group);
        if (groupLow.find("admin") == std::string::npos &&
            groupLow.find("domain admins") == std::string::npos &&
            groupLow.find("remote desktop") == std::string::npos) return ERROR_SUCCESS;
        std::string action = (eid == 4732) ? "added to" : "removed from";
        std::string msg = "[Sec " + eidStr + "] " + ts + " | " +
            member + " " + action + " " + group;
        std::string det = "Date & Time: " + ts + " | EID " + eidStr +
            " Group Membership | Member: " + member +
            " | Group: " + group + " | By: " + byUser;
        PushUiDetectionEvent(msg, det, "Method: Security Log (Group Membership)",
            pid, DetectionSeverity::High);
        break;
    }

    default: break;
    }

    return ERROR_SUCCESS;
}

static void SecExtSubscriberThread() {
    // EID filter covers all events we handle above
    const wchar_t* query =
        L"*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672"
        L" or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4702"
        L" or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4733)]]";

    g_secExtSubscription = EvtSubscribe(
        nullptr, nullptr, L"Security", query,
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(SecExtEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_secExtSubscription) {
        std::cerr << "[SecExt] EvtSubscribe failed: " << GetLastError()
                  << " (run as administrator with audit policy enabled)\n";
        return;
    }

    std::cout << "[SecExt] Security event log subscriber active\n";
    while (!g_secExtStop.load()) Sleep(500);
    EvtClose(g_secExtSubscription);
    g_secExtSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// Task Scheduler — persistence via scheduled tasks
// EIDs: 106 (registered), 129 (launched), 140 (updated), 141 (deleted)
// ---------------------------------------------------------------------------
static DWORD WINAPI TaskEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string eidStr   = GetXmlField(xml, "EventID");
    std::string taskName = GetXmlField(xml, "TaskName");
    if (taskName.empty()) taskName = GetXmlField(xml, "Path");
    std::string ts = BuildTimestamp();
    int eid = 0;
    try { eid = std::stoi(eidStr); } catch (...) { return ERROR_SUCCESS; }

    const char* action_label = nullptr;
    DetectionSeverity sev = DetectionSeverity::Medium;
    switch (eid) {
    case 106: action_label = "registered";         sev = DetectionSeverity::High;   break;
    case 129: action_label = "launched";           sev = DetectionSeverity::Low;    break;
    case 140: action_label = "updated";            sev = DetectionSeverity::Medium; break;
    case 141: action_label = "deleted";            sev = DetectionSeverity::Low;    break;
    default:  return ERROR_SUCCESS;
    }

    std::string msg = "[Task " + eidStr + "] " + ts + " | Task " +
        action_label + ": " + taskName;
    std::string det = "Date & Time: " + ts + " | EID " + eidStr +
        " Task Scheduler | Task: " + taskName + " | Action: " + action_label;
    PushUiDetectionEvent(msg, det, "Method: Task Scheduler Event", 0, sev);
    return ERROR_SUCCESS;
}

static void TaskSubscriberThread() {
    g_taskSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-TaskScheduler/Operational",
        L"*[System[(EventID=106 or EventID=129 or EventID=140 or EventID=141)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(TaskEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_taskSubscription) {
        std::cerr << "[Task] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[Task] Scheduler subscriber active\n";
    while (!g_taskStop.load()) Sleep(500);
    EvtClose(g_taskSubscription);
    g_taskSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// Windows Defender — detections and tamper events
// EIDs: 1116 (detected), 1117 (action taken), 5001 (real-time protection disabled)
// ---------------------------------------------------------------------------
static DWORD WINAPI DefenderEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string eidStr = GetXmlField(xml, "EventID");
    std::string ts = BuildTimestamp();
    int eid = 0;
    try { eid = std::stoi(eidStr); } catch (...) { return ERROR_SUCCESS; }

    if (eid == 5001) {
        std::string msg = "[Defender 5001] " + ts + " | Real-time protection DISABLED";
        std::string det = "Date & Time: " + ts +
            " | EID 5001 Defender Tamper: Real-time protection disabled";
        PushUiDetectionEvent(msg, det, "Method: Windows Defender (Tamper)",
            0, DetectionSeverity::Critical);
        return ERROR_SUCCESS;
    }

    std::string threatName = GetXmlField(xml, "Threat Name");
    if (threatName.empty()) threatName = GetXmlField(xml, "ThreatName");
    std::string path       = GetXmlField(xml, "Path");
    std::string actionTaken= GetXmlField(xml, "Action");

    if (eid == 1116) {
        std::string msg = "[Defender 1116] " + ts + " | Detection: " + threatName +
            " | " + path.substr(path.rfind('\\') + 1);
        std::string det = "Date & Time: " + ts + " | EID 1116 Defender Detection" +
            " | Threat: " + threatName + " | Path: " + path;
        PushUiDetectionEvent(msg, det, "Method: Windows Defender (Detection)",
            0, DetectionSeverity::High);
    } else if (eid == 1117) {
        std::string msg = "[Defender 1117] " + ts + " | Action taken: " +
            actionTaken + " on " + threatName;
        std::string det = "Date & Time: " + ts + " | EID 1117 Defender Action" +
            " | Threat: " + threatName + " | Action: " + actionTaken +
            " | Path: " + path;
        PushUiDetectionEvent(msg, det, "Method: Windows Defender (Action)",
            0, DetectionSeverity::Medium);
    }

    return ERROR_SUCCESS;
}

static void DefenderSubscriberThread() {
    g_defenderSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-Windows Defender/Operational",
        L"*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(DefenderEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_defenderSubscription) {
        std::cerr << "[Defender] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[Defender] Operational subscriber active\n";
    while (!g_defenderStop.load()) Sleep(500);
    EvtClose(g_defenderSubscription);
    g_defenderSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// Print Spooler — driver installation (PrintNightmare / EID 316)
// ---------------------------------------------------------------------------
static DWORD WINAPI SpoolerEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string ts         = BuildTimestamp();
    std::string driverName = GetXmlField(xml, "param3");   // driver name field in EID 316
    std::string driverPath = GetXmlField(xml, "param4");
    std::string user       = GetXmlField(xml, "param7");

    std::string msg = "[Spooler 316] " + ts + " | Printer driver installed: " + driverName;
    std::string det = "Date & Time: " + ts + " | EID 316 Printer Driver Install" +
        " | Driver: " + driverName + " | Path: " + driverPath +
        " | By: " + user;
    PushUiDetectionEvent(msg, det, "Method: Print Spooler (Driver Install / PrintNightmare)",
        0, DetectionSeverity::High);
    return ERROR_SUCCESS;
}

static void SpoolerSubscriberThread() {
    g_spoolerSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-PrintSpooler/Operational",
        L"*[System[(EventID=316)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(SpoolerEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_spoolerSubscription) {
        std::cerr << "[Spooler] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[Spooler] Print Spooler subscriber active\n";
    while (!g_spoolerStop.load()) Sleep(500);
    EvtClose(g_spoolerSubscription);
    g_spoolerSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// RDP — Terminal Services Remote Connection Manager
// EID 1149: Remote Desktop Services: User authentication succeeded
// ---------------------------------------------------------------------------
static DWORD WINAPI RdpEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string ts      = BuildTimestamp();
    std::string user    = GetXmlField(xml, "Param1");
    std::string domain  = GetXmlField(xml, "Param2");
    std::string srcAddr = GetXmlField(xml, "Param3");

    std::string msg = "[RDP 1149] " + ts + " | RDP logon: " +
        (domain.empty() ? "" : domain + "\\") + user +
        " from " + (srcAddr.empty() ? "?" : srcAddr);
    std::string det = "Date & Time: " + ts +
        " | EID 1149 RDP Authentication Success" +
        " | User: " + domain + "\\" + user +
        " | Source IP: " + srcAddr;
    PushUiDetectionEvent(msg, det, "Method: RDP Logon (Lateral Movement)",
        0, DetectionSeverity::Medium);
    return ERROR_SUCCESS;
}

static void RdpSubscriberThread() {
    g_rdpSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        L"*[System[(EventID=1149)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(RdpEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_rdpSubscription) {
        std::cerr << "[RDP] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[RDP] TerminalServices subscriber active\n";
    while (!g_rdpStop.load()) Sleep(500);
    EvtClose(g_rdpSubscription);
    g_rdpSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// BITS Client — background transfer jobs (T1197 persistence / exfiltration)
// EIDs: 3 (job created), 59 (transfer started), 60 (transfer completed)
// ---------------------------------------------------------------------------
static DWORD WINAPI BitsEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID /*ctx*/, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = RenderEventXmlStr(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    std::string eidStr  = GetXmlField(xml, "EventID");
    std::string ts      = BuildTimestamp();
    std::string jobName = GetXmlField(xml, "jobTitle");
    if (jobName.empty()) jobName = GetXmlField(xml, "jobId");
    std::string url     = GetXmlField(xml, "url");
    std::string user    = GetXmlField(xml, "user");
    std::string proc    = GetXmlField(xml, "processPath");
    int eid = 0;
    try { eid = std::stoi(eidStr); } catch (...) { return ERROR_SUCCESS; }

    const char* action_label = nullptr;
    DetectionSeverity sev = DetectionSeverity::Medium;
    switch (eid) {
    case  3: action_label = "created";   sev = DetectionSeverity::Medium; break;
    case 59: action_label = "started";   sev = DetectionSeverity::Low;    break;
    case 60: action_label = "completed"; sev = DetectionSeverity::Medium; break;
    default: return ERROR_SUCCESS;
    }

    std::string msg = "[BITS " + eidStr + "] " + ts + " | BITS job " +
        action_label + ": " + jobName + (url.empty() ? "" : " | " + url.substr(0, 80));
    std::string det = "Date & Time: " + ts + " | EID " + eidStr + " BITS Job " + action_label +
        " | Job: " + jobName + " | URL: " + url + " | User: " + user +
        " | Process: " + proc;
    PushUiDetectionEvent(msg, det, "Method: BITS Client (T1197)", 0, sev);
    return ERROR_SUCCESS;
}

static void BitsSubscriberThread() {
    g_bitsSubscription = EvtSubscribe(
        nullptr, nullptr,
        L"Microsoft-Windows-Bits-Client/Operational",
        L"*[System[(EventID=3 or EventID=59 or EventID=60)]]",
        nullptr, nullptr,
        reinterpret_cast<EVT_SUBSCRIBE_CALLBACK>(BitsEventCallback),
        EvtSubscribeToFutureEvents
    );

    if (!g_bitsSubscription) {
        std::cerr << "[BITS] EvtSubscribe failed: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[BITS] Client subscriber active\n";
    while (!g_bitsStop.load()) Sleep(500);
    EvtClose(g_bitsSubscription);
    g_bitsSubscription = nullptr;
}

// ---------------------------------------------------------------------------
// AltitudeAuditThread — periodic registry scan for minifilter altitude theft.
//
// Every 30 seconds, this thread:
//   1) Verifies our own altitude registry key hasn't been tampered with
//   2) Scans all other services for altitude squatting (same altitude as ours)
//   3) Checks for suspicious near-altitude registrations (sandwiching)
//
// Attackers may:
//   - Overwrite our altitude key to a value where no EDR listens
//   - Register their own driver at our altitude so we fail to attach on reboot
//   - Plant a filter just above us to intercept I/O before we see it
// ---------------------------------------------------------------------------
void AltitudeAuditThread()
{
    const wchar_t* kExpectedAltitude = L"320021";
    const ULONG    kOurAltNum        = 320021;
    const ULONG    kAvRangeTop       = 329999;  // FSFilter Anti-Virus range ceiling

    std::cout << "[AltitudeAudit] Minifilter altitude integrity monitor active\n";

    while (!g_altitudeAuditStop.load()) {
        // --- Check 1: Verify our own altitude key ---
        {
            HKEY hk = nullptr;
            // The installer writes: Services\NortonEDRDriver\Instances\NortonEDRDrvInstance
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\NortonEDRDriver\\Instances\\NortonEDRDrvInstance",
                    0, KEY_READ, &hk) == ERROR_SUCCESS)
            {
                wchar_t altBuf[64] = {};
                DWORD   altSize = sizeof(altBuf);
                DWORD   altType = 0;
                if (RegQueryValueExW(hk, L"Altitude", nullptr, &altType,
                        (LPBYTE)altBuf, &altSize) == ERROR_SUCCESS)
                {
                    if (altType != REG_SZ || wcscmp(altBuf, kExpectedAltitude) != 0) {
                        std::string tampered = "Altitude registry key TAMPERED: expected '320021', found '";
                        char narrowBuf[64] = {};
                        WideCharToMultiByte(CP_UTF8, 0, altBuf, -1, narrowBuf, sizeof(narrowBuf), nullptr, nullptr);
                        tampered += narrowBuf;
                        tampered += "' — attacker may have redirected our minifilter to a dead altitude";

                        PushUiDetectionEvent(
                            "Minifilter altitude registry tampered",
                            tampered,
                            "altitude_tamper",
                            0,
                            DetectionSeverity::Critical
                        );
                    }
                }
                else {
                    // Altitude value missing entirely
                    PushUiDetectionEvent(
                        "Minifilter altitude registry key MISSING",
                        "The Altitude value under NortonEDRDrvInstance has been deleted — "
                        "minifilter will fail to attach on next boot",
                        "altitude_tamper",
                        0,
                        DetectionSeverity::Critical
                    );
                }
                RegCloseKey(hk);
            }
            else {
                // Entire instance key missing
                PushUiDetectionEvent(
                    "Minifilter instance registry key MISSING",
                    "The NortonEDRDrvInstance key has been deleted — "
                    "minifilter will fail to attach on next boot",
                    "altitude_tamper",
                    0,
                    DetectionSeverity::Critical
                );
            }
        }

        // --- Check 2: Scan all services for altitude squatting / sandwiching ---
        {
            HKEY hkServices = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services",
                    0, KEY_ENUMERATE_SUB_KEYS, &hkServices) == ERROR_SUCCESS)
            {
                wchar_t svcName[256];
                DWORD   svcIdx = 0;
                DWORD   svcNameLen;

                while (true) {
                    svcNameLen = ARRAYSIZE(svcName);
                    if (RegEnumKeyExW(hkServices, svcIdx++, svcName, &svcNameLen,
                            nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                        break;

                    // Skip our own service
                    if (_wcsicmp(svcName, L"NortonEDRDriver") == 0) continue;

                    // Check if this service has an Instances subkey
                    std::wstring instPath = std::wstring(svcName) + L"\\Instances";
                    HKEY hkInst = nullptr;
                    if (RegOpenKeyExW(hkServices, instPath.c_str(), 0,
                            KEY_ENUMERATE_SUB_KEYS, &hkInst) != ERROR_SUCCESS)
                        continue;

                    wchar_t instName[256];
                    DWORD   instIdx2 = 0;
                    DWORD   instNameLen;

                    while (true) {
                        instNameLen = ARRAYSIZE(instName);
                        if (RegEnumKeyExW(hkInst, instIdx2++, instName, &instNameLen,
                                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                            break;

                        HKEY hkInstance = nullptr;
                        if (RegOpenKeyExW(hkInst, instName, 0, KEY_READ,
                                &hkInstance) != ERROR_SUCCESS)
                            continue;

                        wchar_t altBuf[64] = {};
                        DWORD   altSize = sizeof(altBuf);
                        DWORD   altType = 0;
                        if (RegQueryValueExW(hkInstance, L"Altitude", nullptr,
                                &altType, (LPBYTE)altBuf, &altSize) == ERROR_SUCCESS &&
                            altType == REG_SZ)
                        {
                            // Parse altitude to numeric
                            ULONG foreignAlt = (ULONG)_wtol(altBuf);

                            char narrowSvc[128] = {};
                            WideCharToMultiByte(CP_UTF8, 0, svcName, -1,
                                narrowSvc, sizeof(narrowSvc), nullptr, nullptr);

                            if (foreignAlt == kOurAltNum) {
                                std::string detail = "Service '";
                                detail += narrowSvc;
                                detail += "' has registered a minifilter at our exact altitude 320021 — "
                                          "on next boot our minifilter may be displaced (altitude squatting)";

                                PushUiDetectionEvent(
                                    "Minifilter altitude SQUATTING detected",
                                    detail,
                                    "altitude_squat",
                                    0,
                                    DetectionSeverity::Critical
                                );
                            }
                            else if (foreignAlt > kOurAltNum &&
                                     foreignAlt <= kAvRangeTop)
                            {
                                std::string detail = "Service '";
                                detail += narrowSvc;
                                detail += "' registered at altitude ";
                                detail += std::to_string(foreignAlt);
                                detail += " (ours is 320021) — positioned to intercept I/O "
                                          "before our EDR minifilter (sandwiching attack)";

                                PushUiDetectionEvent(
                                    "Minifilter altitude SANDWICHING detected",
                                    detail,
                                    "altitude_sandwich",
                                    0,
                                    DetectionSeverity::Critical
                                );
                            }
                        }
                        RegCloseKey(hkInstance);
                    }
                    RegCloseKey(hkInst);
                }
                RegCloseKey(hkServices);
            }
        }

        // Sleep in 500ms increments so we can respond to stop signal quickly
        for (int s = 0; s < 60 && !g_altitudeAuditStop.load(); s++)
            Sleep(500);
    }

    std::cout << "[AltitudeAudit] Thread stopped\n";
}

VOID ShowUI() {

    auto processesRenderer = Renderer([&] {
        std::vector<ProcessContext> snapshot;
        {
            std::lock_guard<std::mutex> lock(process_cache_mutex);
            snapshot.reserve(g_processCache.size());
            for (const auto& [pid, ctx] : g_processCache) {
                snapshot.push_back(ctx);
            }
        }
        std::sort(snapshot.begin(), snapshot.end(), [](const ProcessContext& a, const ProcessContext& b) {
            return a.pid < b.pid;
        });

        std::vector<Element> rows;
        rows.push_back(hbox({
            text("PID    ") | bold | color(Color::Blue),
            text("PPID   ") | bold | color(Color::Blue),
            text("Name                     ") | bold | color(Color::Blue),
            text("Command Line") | bold | color(Color::Blue) | flex,
        }));
        rows.push_back(separator());

        for (const auto& ctx : snapshot) {
            std::string name = ctx.processName.size() > 24
                ? ctx.processName.substr(0, 21) + "..."
                : ctx.processName;
            std::string cmdLine = ctx.commandLine.size() > 60
                ? ctx.commandLine.substr(0, 57) + "..."
                : ctx.commandLine;
            Color rowColor = ctx.observed ? Color(Color::Palette1::Default) : Color(Color::Palette16::GrayDark);
            rows.push_back(hbox({
                text(std::to_string(ctx.pid)) | size(WIDTH, EQUAL, 7) | color(rowColor),
                text(std::to_string(ctx.parentPid)) | size(WIDTH, EQUAL, 7) | color(rowColor),
                text(name) | size(WIDTH, EQUAL, 25) | color(rowColor),
                text(cmdLine) | flex | color(rowColor),
            }));
        }

        if (snapshot.empty()) {
            rows.push_back(text(" No processes observed yet.") | color(Color::GrayDark));
        }

        return vbox({
            text("Observed processes: " + std::to_string(snapshot.size())) | bold,
            vbox(rows) | frame | vscroll_indicator | border | size(HEIGHT, EQUAL, 48),
        });
    });

    auto tab_container = Container::Tab(
        {
            tab_1_container,
            processesRenderer,
            Renderer([&] {
                if (tab_values[tab_selected] == "About") {
                    auto lines = SplitLines(startupAsciiTitle);
                    std::vector<Element> ascii_elements;
                    for (const auto& line : lines) {
                        ascii_elements.push_back(text(line));
                    }
                    return vbox(ascii_elements) | center | xflex | yflex;
                }
                return text("");
            }),
        },
        &tab_selected);


    auto container = Container::Vertical({
    tab_toggle,
    tab_container,
        });

    auto renderer = Renderer(container, [&] {
        return vbox({
                   tab_toggle->Render(),
                   separator(),
                   tab_container->Render() | size(HEIGHT, LESS_THAN, 40),
            }) |
            border;
        });

    if (g_apiPort > 0) {
        g_apiServerStop = false;
        std::thread(RunLocalApiServer).detach();
    }

    g_yaraScanStop = false;
    std::thread yaraWorker(YaraScanWorker);

    std::thread threadByte([]() {
        ConsumeIOCTLData(L"\\\\.\\NortonEDR", NORTONAV_RETRIEVE_DATA_BYTE, 5);
        });

    std::thread threadFile([]() {
        ConsumeIOCTLData(L"\\\\.\\NortonEDR", NORTONAV_RETRIEVE_DATA_FILE, 5);
        });

    // Sysmon, SACL, ETW-TI, PowerShell, DNS, WinRM and extended ETW subscribers
    SetupAuditSACLs();
    g_sysmonStop    = false;
    g_saclStop      = false;
    g_tiStop        = false;
    g_psStop        = false;
    g_dnsStop       = false;
    g_winrmStop     = false;
    g_secExtStop    = false;
    g_taskStop      = false;
    g_defenderStop  = false;
    g_spoolerStop   = false;
    g_rdpStop       = false;
    g_bitsStop      = false;
    std::thread sysmonThread(SysmonSubscriberThread);
    std::thread saclThread(SecurityAuditSubscriberThread);
    std::thread tiThread(EtwTiSubscriberThread);
    std::thread kpThread(KernelProcessSubscriberThread);
    std::thread psThread(PowerShellSubscriberThread);
    std::thread dnsThread(DnsSubscriberThread);
    std::thread winrmThread(WinRmSubscriberThread);
    std::thread secExtThread(SecExtSubscriberThread);
    std::thread taskThread(TaskSubscriberThread);
    std::thread defenderThread(DefenderSubscriberThread);
    std::thread spoolerThread(SpoolerSubscriberThread);
    std::thread rdpThread(RdpSubscriberThread);
    std::thread bitsThread(BitsSubscriberThread);

    g_capaStop = false;
    std::thread capaWorker(CapaScanWorker);

    g_hookPipeStop = false;
    std::thread hookPipeThread(HookPipeServerThread);

    g_elasticStop = false;
    std::thread elasticThread(ElasticShipperThread);

    g_altitudeAuditStop = false;
    std::thread altitudeAuditThread(AltitudeAuditThread);

    try {
        screen.Loop(renderer);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception caught: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[!] Unknown exception caught" << std::endl;
    }

    g_yaraScanStop = true;
    g_yaraScanCv.notify_all();
    yaraWorker.join();

    threadByte.join();
    threadFile.join();

    g_sysmonStop   = true;
    g_saclStop     = true;
    g_psStop       = true;
    g_dnsStop      = true;
    g_winrmStop    = true;
    g_secExtStop   = true;
    g_taskStop     = true;
    g_defenderStop = true;
    g_spoolerStop  = true;
    g_rdpStop      = true;
    g_bitsStop     = true;
    sysmonThread.join();
    saclThread.join();
    psThread.join();
    dnsThread.join();
    winrmThread.join();
    secExtThread.join();
    taskThread.join();
    defenderThread.join();
    spoolerThread.join();
    rdpThread.join();
    bitsThread.join();

    // ETW-TI: unblock ProcessTrace then join
    StopEtwTiSession();
    tiThread.join();

    // ETW Kernel-Process: unblock ProcessTrace then join
    StopKernelProcessSession();
    kpThread.join();

    g_capaStop = true;
    g_capaCv.notify_all();
    capaWorker.join();

    g_hookPipeStop = true;
    // Unblock ConnectNamedPipe by opening a dummy client connection
    HANDLE dummy = CreateFileA(kHookPipeName, GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (dummy != INVALID_HANDLE_VALUE) CloseHandle(dummy);
    hookPipeThread.join();

    g_elasticStop = true;
    g_elasticCv.notify_all();
    elasticThread.join();

    g_altitudeAuditStop = true;
    altitudeAuditThread.join();
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, SignalHandler);

    std::vector<std::string> positionalArgs;
    std::vector<std::string> traceTargetRawValues;
    std::string              blockPortsRaw;
    bool includeTraceChildren = false;
    std::string              complianceArg;   // --compliance <standard>
    bool                     hardenMode = false; // --harden (skip interactive prompt)

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--trace") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --trace\n";
                return 1;
            }
            traceTargetRawValues.push_back(argv[++i]);
            continue;
        }

        if (arg.rfind("--trace=", 0) == 0) {
            traceTargetRawValues.push_back(arg.substr(8));
            continue;
        }

        if (arg == "--trace-child" || arg == "--trace-children") {
            includeTraceChildren = true;
            continue;
        }

        if (arg == "--api-port") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --api-port\n";
                return 1;
            }

            try {
                g_apiPort = std::stoi(argv[++i]);
            }
            catch (...) {
                std::cerr << "Invalid --api-port value\n";
                return 1;
            }
            continue;
        }

        if (arg.rfind("--api-port=", 0) == 0) {
            try {
                g_apiPort = std::stoi(arg.substr(11));
            }
            catch (...) {
                std::cerr << "Invalid --api-port value\n";
                return 1;
            }
            continue;
        }

        if (arg == "--api-events-limit") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --api-events-limit\n";
                return 1;
            }

            try {
                g_apiEventLimit = static_cast<size_t>(std::stoul(argv[++i]));
            }
            catch (...) {
                std::cerr << "Invalid --api-events-limit value\n";
                return 1;
            }
            continue;
        }

        if (arg.rfind("--api-events-limit=", 0) == 0) {
            try {
                g_apiEventLimit = static_cast<size_t>(std::stoul(arg.substr(19)));
            }
            catch (...) {
                std::cerr << "Invalid --api-events-limit value\n";
                return 1;
            }
            continue;
        }

        if (arg == "--elastic-host") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --elastic-host\n"; return 1; }
            g_elasticConfig.host    = argv[++i];
            g_elasticConfig.enabled = true;
            continue;
        }
        if (arg.rfind("--elastic-host=", 0) == 0) {
            g_elasticConfig.host    = arg.substr(15);
            g_elasticConfig.enabled = true;
            continue;
        }

        if (arg == "--elastic-index") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --elastic-index\n"; return 1; }
            g_elasticConfig.index = argv[++i];
            continue;
        }
        if (arg.rfind("--elastic-index=", 0) == 0) {
            g_elasticConfig.index = arg.substr(16);
            continue;
        }

        if (arg == "--elastic-api-key") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --elastic-api-key\n"; return 1; }
            g_elasticConfig.apiKey = argv[++i];
            continue;
        }
        if (arg.rfind("--elastic-api-key=", 0) == 0) {
            g_elasticConfig.apiKey = arg.substr(18);
            continue;
        }

        if (arg == "--elastic-user") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --elastic-user\n"; return 1; }
            g_elasticConfig.username = argv[++i];
            continue;
        }
        if (arg.rfind("--elastic-user=", 0) == 0) {
            g_elasticConfig.username = arg.substr(15);
            continue;
        }

        if (arg == "--elastic-pass") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --elastic-pass\n"; return 1; }
            g_elasticConfig.password = argv[++i];
            continue;
        }
        if (arg.rfind("--elastic-pass=", 0) == 0) {
            g_elasticConfig.password = arg.substr(15);
            continue;
        }

        if (arg == "--elastic-no-verify") {
            g_elasticConfig.tlsVerify = false;
            continue;
        }

        if (arg == "--block-ports") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --block-ports\n"; return 1; }
            blockPortsRaw = argv[++i];
            continue;
        }
        if (arg.rfind("--block-ports=", 0) == 0) {
            blockPortsRaw = arg.substr(14);
            continue;
        }

        if (arg == "--compliance") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --compliance\n"; return 1; }
            complianceArg = argv[++i];
            continue;
        }
        if (arg.rfind("--compliance=", 0) == 0) {
            complianceArg = arg.substr(13);
            continue;
        }

        if (arg == "--harden") {
            hardenMode = true;
            continue;
        }

        positionalArgs.push_back(arg);
    }

    if (g_apiPort < 0 || g_apiPort > 65535) {
        std::cerr << "--api-port must be between 0 and 65535\n";
        return 1;
    }

    if (g_apiEventLimit == 0) {
        g_apiEventLimit = 1;
    }

    if (g_elasticConfig.enabled && g_elasticConfig.index.empty()) {
        g_elasticConfig.index = "nortonav-edr";
    }

    {
        WCHAR buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(buf, &sz)) {
            int needed = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (needed > 0) {
                g_hostname.resize(needed - 1);
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, &g_hostname[0], needed, nullptr, nullptr);
            }
        }
        if (g_hostname.empty()) g_hostname = "unknown";
    }

    // Ensure log directory exists before the first PersistDetectionEvent write.
    std::filesystem::create_directories(R"(C:\ProgramData\NortonEDR)");

    // ------------------------------------------------------------------
    // Compliance evaluation mode — runs standalone, no driver required.
    // Usage: NortonEDR.exe --compliance <standard> [--harden]
    //   standards: nist800-53  nist800-171  cis-l1  cis-l2  cmmc-l1  cmmc-l2
    // ------------------------------------------------------------------
    if (!complianceArg.empty()) {
        ComplianceStandard std;
        if (!ComplianceEngine::ParseStandard(complianceArg, std)) {
            std::cerr << "Unknown compliance standard: \"" << complianceArg << "\"\n"
                      << "Valid values: nist800-53  nist800-171  cis-l1  cis-l2  cmmc-l1  cmmc-l2\n";
            return 1;
        }
        return ComplianceEngine::RunEvaluation(std, hardenMode);
    }

    if (positionalArgs.empty()) {
        std::cerr << "Usage: " << argv[0]
            << " <path to driver> [path to YARA rules directory] [path to LOLDrivers cache] [path to Sigma rules directory]"
            << " [--trace <proc1,proc2>] [--trace-children] [--api-port <port>] [--api-events-limit <n>]"
            << " [--elastic-host <https://host:port>] [--elastic-index <index>]"
            << " [--elastic-api-key <key> | --elastic-user <u> --elastic-pass <p>]"
            << " [--elastic-no-verify]"
            << " [--block-ports <port1,port2,...>]"
            << " [--compliance <standard>] [--harden]\n";
        return 1;
    }

    std::wstring driverPath = std::wstring(positionalArgs[0].begin(), positionalArgs[0].end());
    std::wstring driverName = L"NortonEDRDrv";
    std::vector<std::string> yaraRulesDirectories;

    if (positionalArgs.size() >= 2 && !positionalArgs[1].empty()) {
        yaraRulesDirectories.push_back(positionalArgs[1]);
    }

    yaraRulesDirectories.push_back(kLoadedPotatoYaraRulesDir);

    std::string lolDriversCachePath = kLoadedPotatoLolDriversCachePath;
    if (positionalArgs.size() >= 3 && !positionalArgs[2].empty()) {
        lolDriversCachePath = positionalArgs[2];
    }

    std::string sigmaRulesDirectory = kLoadedPotatoSigmaRulesDir;
    if (positionalArgs.size() >= 4 && !positionalArgs[3].empty()) {
        sigmaRulesDirectory = positionalArgs[3];
    }

    std::vector<std::string> parsedTraceTargets;
    for (const auto& rawValue : traceTargetRawValues) {
        AppendCsvValues(rawValue, parsedTraceTargets);
    }

    {
        std::lock_guard<std::mutex> lock(process_cache_mutex);
        g_traceConfig.targetProcessNamesLower.clear();
        g_traceConfig.includeChildren = includeTraceChildren;

        for (const auto& target : parsedTraceTargets) {
            if (std::find(
                g_traceConfig.targetProcessNamesLower.begin(),
                g_traceConfig.targetProcessNamesLower.end(),
                target
            ) == g_traceConfig.targetProcessNamesLower.end()) {
                g_traceConfig.targetProcessNamesLower.push_back(target);
            }
        }

        RecomputeObservedProcessesLocked();
    }

    std::wstring fullPath = GetFullPath(driverPath);

    if (!InstallNortonEDRDriver(driverName, fullPath)) {
        std::wcerr << L"Failed to install driver." << std::endl;
        std::cerr << GetLastErrorAsString() << std::endl;
        return 1;
    }

    curPid = static_cast<UINT32>(GetCurrentProcessId());

    if (!parsedTraceTargets.empty()) {
        std::cout << "[*] Trace mode enabled for targets: ";
        for (size_t i = 0; i < parsedTraceTargets.size(); ++i) {
            std::cout << parsedTraceTargets[i];
            if (i + 1 < parsedTraceTargets.size()) {
                std::cout << ", ";
            }
        }
        std::cout << "\n";
        std::cout << "[*] Trace children: " << (includeTraceChildren ? "enabled" : "disabled") << "\n";
    }

    if (g_apiPort > 0) {
        std::cout << "[*] Local API enabled on http://127.0.0.1:" << g_apiPort << "\n";
    }
    else {
        std::cout << "[*] Local API disabled (--api-port 0)\n";
    }

    std::cout << "[*] Loading LOLDrivers cache...\n";
    LoadLolDriversCache(lolDriversCachePath);
    std::cout << "[*] Loading Sigma rules...\n";
    LoadSigmaRules(sigmaRulesDirectory);

    printf("[*] Loading YARA rules...\n");

    InitYara(yaraRulesDirectories);

    printf("[*] %d Yara Rules Loaded & Compiled\n", yara_rules_count);
    system("pause");

    // Send HookDll injection config to the kernel driver.
    // LoadLibraryW is at the same VA in all processes (shared section, boot ASLR only).
    {
        HANDLE hDev = CreateFileW(L"\\\\.\\NortonEDR",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDev != INVALID_HANDLE_VALUE) {
            HOOKDLL_INJECT_CONFIG cfg = {};
            cfg.LoadLibraryWAddress =
                (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
            cfg.OwnerPid = GetCurrentProcessId();

            // Build HookDll.dll path from NortonEDR.exe directory
            wchar_t exePath[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            wchar_t* lastSlash = wcsrchr(exePath, L'\\');
            if (lastSlash)
                wcscpy_s(lastSlash + 1,
                         MAX_PATH - (DWORD)(lastSlash + 1 - exePath),
                         L"HookDll.dll");
            wcscpy_s(cfg.HookDllPath, exePath);
            cfg.PathByteLen = (ULONG)((wcslen(cfg.HookDllPath) + 1) * sizeof(wchar_t));

            DWORD returned = 0;
            DeviceIoControl(hDev, NORTONAV_SET_INJECT_CONFIG,
                            &cfg, sizeof(cfg), nullptr, 0, &returned, nullptr);
            CloseHandle(hDev);
        }
    }

    // Send WFP blocked-port list to the kernel driver.
    if (!blockPortsRaw.empty()) {
        NETWORK_FILTER_CONFIG netCfg = {};
        std::istringstream ss(blockPortsRaw);
        std::string token;
        while (std::getline(ss, token, ',') && netCfg.NumBlockedPorts < 32) {
            try {
                int p = std::stoi(token);
                if (p > 0 && p <= 65535)
                    netCfg.BlockedPorts[netCfg.NumBlockedPorts++] = static_cast<UINT16>(p);
            } catch (...) {}
        }
        if (netCfg.NumBlockedPorts > 0) {
            HANDLE hDev = CreateFileW(L"\\\\.\\NortonEDR",
                GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDev != INVALID_HANDLE_VALUE) {
                DWORD returned = 0;
                DeviceIoControl(hDev, NORTONAV_SET_NETWORK_CONFIG,
                                &netCfg, sizeof(netCfg), nullptr, 0, &returned, nullptr);
                CloseHandle(hDev);
                std::cout << "[*] WFP blocking " << netCfg.NumBlockedPorts << " port(s)\n";
            }
        }
    }

    ShowUI();

    return 0;
}

