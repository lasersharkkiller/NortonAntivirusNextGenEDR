#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>    // COM types: LPUNKNOWN, LPCOLESTR, IID, etc.
#include <ole2.h>       // OLE2 functions
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winreg.h>
// wincrypt.h types used in CRYPT32 hooks — defined as opaque pointers to avoid
// WIN32_LEAN_AND_MEAN / include-order conflicts with the full wincrypt.h header.
typedef void*       HCERTSTORE_OPAQUE;
typedef const void* PCCERT_CONTEXT_OPAQUE;
// evntprov.h REGHANDLE — avoid full header pull-in under WIN32_LEAN_AND_MEAN
#ifndef _EVNTPROV_H_
typedef ULONGLONG REGHANDLE;
#endif
// evntprov.h EVENT_DESCRIPTOR fwd — we only need the pointer type
struct _EVENT_DESCRIPTOR_FWD;
struct _EVENT_DATA_DESCRIPTOR_FWD;
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")

#define HOOKDLL_EXPORTS
#include "HookDll.h"

// ---------------------------------------------------------------------------
// Pipe IPC — sends telemetry lines to the NortonEDR pipe server.
// Line format: SEVERITY\tCALLER_PID\tAPI_NAME\tTARGET_PID\tDETAIL\n
// ---------------------------------------------------------------------------

static HANDLE           g_pipe     = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeLock;
static DWORD            g_selfPid  = 0;
static bool             g_lockInit = false;

// Forward declaration for function defined later in file
static bool IsAddressInKnownModule(const void* addr);

static void ConnectToPipe() {
    if (!WaitNamedPipeA("\\\\.\\pipe\\NortonEDR_HookDll", 2000)) return;
    g_pipe = CreateFileA("\\\\.\\pipe\\NortonEDR_HookDll",
        GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_pipe == INVALID_HANDLE_VALUE) g_pipe = INVALID_HANDLE_VALUE;
}

static void SendHookEvent(
    const char* severity, const char* apiName,
    DWORD targetPid, const char* detail)
{
    if (g_pipe == INVALID_HANDLE_VALUE || !g_lockInit) return;
    char buf[512];
    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%s\t%lu\t%s\t%lu\t%s\n",
        severity, g_selfPid, apiName, targetPid, detail);
    if (len <= 0) return;
    EnterCriticalSection(&g_pipeLock);
    DWORD written = 0;
    WriteFile(g_pipe, buf, (DWORD)len, &written, nullptr);
    LeaveCriticalSection(&g_pipeLock);
}

// ---------------------------------------------------------------------------
// Hook table
// ---------------------------------------------------------------------------

enum HookIdx : int {
    IDX_VIRTUALALLOC          = 0,
    IDX_VIRTUALALLOCEX        = 1,
    IDX_WRITEPROCESSMEMORY    = 2,
    IDX_CREATEREMOTETHREAD    = 3,
    IDX_CREATEREMOTETHREADEX  = 4,
    IDX_LOADLIBRARYA          = 5,
    IDX_LOADLIBRARYW          = 6,
    IDX_LOADLIBRARYEXA        = 7,
    IDX_LOADLIBRARYEXW        = 8,
    IDX_RESUMETHREAD          = 9,
    IDX_SETTHREADCONTEXT      = 10,
    IDX_REGSETVALUEEX_A       = 11,
    IDX_REGSETVALUEEX_W       = 12,
    IDX_READPROCESSMEMORY     = 13,  // deception: post-read LSASS buffer patching
    IDX_NTQUERYSYSTEMINFO     = 14,  // deception: hide EDR, inject decoy process
    // --- Evasion-path execution triggers ---
    IDX_CREATETHREAD          = 15,  // local thread with non-module start address
    IDX_MAPVIEWOFFILE         = 16,  // file-backed section mapped executable
    IDX_REGISTERCLASSEXA      = 17,  // WndProc shellcode dispatch (window message)
    IDX_REGISTERCLASSEXW      = 18,
    IDX_ENUMSYSTEMLOCALESA    = 19,  // callback abuse
    IDX_ENUMSYSLANGGRPA       = 20,  // callback abuse — rarity score 100 in malware set
    IDX_ENUMWINDOWS           = 21,  // callback abuse
    IDX_ENUMCHILDWINDOWS      = 22,  // callback abuse
    IDX_SETTIMER              = 23,  // timer callback execution
    IDX_SETWAITABLETIMER      = 24,  // timer callback execution
    IDX_CREATETIMERQUEUETIMER  = 25,  // timer callback execution
    // --- Category 1 additions from differential analysis ---
    IDX_OPENPROCESS            = 26,  // injection precursor — log target PID
    IDX_VIRTUALPROTECT         = 27,  // RWX page marking (shellcode staging)
    IDX_CREATEFILEMAPPINGW     = 28,  // section creation for module stomping
    IDX_CREATEFILEMAPPINGA     = 29,
    IDX_ENUMSYSTEMLOCALESW     = 30,  // W variant callback abuse
    IDX_CALLWINDOWPROCA        = 31,  // WndProc dispatch callback abuse
    IDX_CALLWINDOWPROCW        = 32,
    IDX_ENUMTHREADWINDOWS      = 33,  // callback abuse
    IDX_CONVERTTHREADTOFIBER   = 34,  // fiber-based shellcode execution
    IDX_CREATEFIBER            = 35,
    IDX_SWITCHTOFIBER          = 36,
    IDX_RTLCREATEUSERTHREAD    = 37,  // direct user-mode thread (ntdll, bypasses CreateThread)
    IDX_CREATEWAITABLETIMEREXW  = 38,  // timer variant missed in first pass
    // --- Gap closure: window WndProc hijack + CRYPT32 callback abuse ---
    IDX_SETWINDOWLONGPTRA       = 39,  // post-creation WndProc replacement (Path B window msgs)
    IDX_SETWINDOWLONGPTRW       = 40,
    IDX_CERTENUMCERTIFICATES    = 41,  // CRYPT32 callback abuse (score 94, mal 27)
    IDX_CERTFINDCERTIFICATE     = 42,  // CRYPT32 callback abuse (score 94, mal 24)
    // --- VEH hooking bypass: shellcode registered as vectored exception handler ---
    IDX_ADDVECTOREDEXCEPTIONHANDLER   = 43,  // kernel32.dll (thunks to ntdll)
    IDX_ADDVECTOREDCONTINUEHANDLER    = 44,  // kernel32.dll
    IDX_RTLADDVECTOREDEXCEPTIONHANDLER = 45, // ntdll.dll — direct call path
    IDX_RTLADDVECTOREDCONTINUEHANDLER  = 46, // ntdll.dll — direct call path
    // --- Authentication downgrade detection: SSPI hooks ---
    IDX_INITIALIZESECURITYCONTEXTW     = 47, // sspicli.dll — Negotiate→NTLM fallback
    IDX_ACQUIRECREDENTIALSHANDLEW      = 48, // sspicli.dll — explicit NTLM/WDigest credential acquisition
    // --- Sleep obfuscation detection ---
    IDX_SYSTEMFUNCTION032              = 49, // advapi32.dll — RC4 encrypt used by Ekko/Foliage
    // --- DPAPI credential harvesting ---
    IDX_CRYPTUNPROTECTDATA             = 50, // crypt32.dll — DPAPI decryption
    // --- Process Ghosting / Transacted Hollowing ---
    IDX_NTSETINFORMATIONFILE           = 51, // ntdll.dll — FileDispositionInformation (delete-pending)
    IDX_NTCREATETRANSACTION            = 52, // ntdll.dll — TxF for transacted hollowing
    // --- WFP manipulation detection (fwpuclnt.dll) ---
    IDX_FWPMFILTERADD0                 = 53, // fwpuclnt.dll — rogue filter injection
    IDX_FWPMFILTERDELETEBYID0          = 54, // fwpuclnt.dll — filter deletion
    IDX_FWPMCALLOUTADD0                = 55, // fwpuclnt.dll — rogue callout injection
    IDX_FWPMSUBLAYERADD0               = 56, // fwpuclnt.dll — rogue sublayer injection
    IDX_FWPMSUBLAYERDELETEBYKEY0       = 57, // fwpuclnt.dll — sublayer deletion
    IDX_FWPMENGINECLOSE0               = 58, // fwpuclnt.dll — engine handle closure
    // --- WFP enumeration/recon detection (fwpuclnt.dll) ---
    IDX_FWPMFILTERENUM0                = 59, // fwpuclnt.dll — filter enumeration (recon)
    IDX_FWPMCALLOUTENUM0               = 60, // fwpuclnt.dll — callout enumeration (recon)
    IDX_FWPMSUBLAYERENUM0              = 61, // fwpuclnt.dll — sublayer enumeration (recon)
    IDX_FWPMPROVIDERENUM0              = 62, // fwpuclnt.dll — provider enumeration (recon)
    IDX_FWPMENGINEGETSECINFOBYKEY0     = 63, // fwpuclnt.dll — engine security descriptor query
    IDX_FWPMFILTERGETSECINFOBYKEY0     = 64, // fwpuclnt.dll — filter security descriptor query
    // --- Weaver Ant: JScript/VBScript script engine instantiation ---
    IDX_COCREATEINSTANCE               = 65, // ole32.dll — COM object creation (script engines)
    IDX_COCREATEINSTANCEEX             = 66, // ole32.dll — DCOM remote COM instantiation
    IDX_CLSIDFROMPROGID                = 67, // ole32.dll — ProgID → CLSID resolution
    // --- ETW filter descriptor attack detection ---
    IDX_ENABLETRACEEX2                 = 68, // advapi32/sechost — filter descriptor injection
    // --- REGHANDLE nulling detection (T1562.002) ---
    IDX_ETWEVENTWRITE                  = 69, // ntdll — catches RegHandle==0 writes
    // --- Session security descriptor / rogue consumer detection ---
    IDX_EVENTACCESSCONTROL             = 70, // advapi32 — session SD rewrites
    IDX_OPENTRACEW                     = 71, // advapi32 — rogue real-time consumer attach
    // --- Dylan Hall user-mode _ETW_REG_ENTRY tampering detection ---
    IDX_ETWEVENTREGISTER               = 72, // ntdll — capture REGHANDLEs for baselining
    HOOK_COUNT                  = 73
};

struct ApiHook {
    const char* modName;    // lowercase, e.g. "kernel32.dll"
    const char* funcName;
    FARPROC     hookFn;

    // IAT patching
    FARPROC     original;   // original IAT slot value

    // Inline hook + trampoline
    BYTE*       inlineTarget;   // address of the patched function prologue
    BYTE        savedBytes[16]; // copy of overwritten prologue bytes
    FARPROC     trampoline;     // executable stub: savedBytes + JMP back
    bool        inlinePatched;
};

// Forward declarations of hook stubs
static LPVOID  WINAPI Hook_VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
static LPVOID  WINAPI Hook_VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static BOOL    WINAPI Hook_WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
static HANDLE  WINAPI Hook_CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static HANDLE  WINAPI Hook_CreateRemoteThreadEx(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                 LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                                 LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR);
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR);
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR, HANDLE, DWORD);
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
static DWORD   WINAPI Hook_ResumeThread(HANDLE);
static BOOL    WINAPI Hook_SetThreadContext(HANDLE, const CONTEXT*);
static LONG    WINAPI Hook_RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
static LONG    WINAPI Hook_RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static BOOL    WINAPI Hook_ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
static BOOL    WINAPI Hook_NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
static HANDLE  WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static LPVOID  WINAPI Hook_MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static ATOM    WINAPI Hook_RegisterClassExA(const WNDCLASSEXA*);
static ATOM    WINAPI Hook_RegisterClassExW(const WNDCLASSEXW*);
static BOOL    WINAPI Hook_EnumSystemLocalesA(LOCALE_ENUMPROCA, DWORD);
static BOOL    WINAPI Hook_EnumSystemLanguageGroupsA(LANGUAGEGROUP_ENUMPROCA, DWORD, LONG_PTR);
static BOOL    WINAPI Hook_EnumWindows(WNDENUMPROC, LPARAM);
static BOOL    WINAPI Hook_EnumChildWindows(HWND, WNDENUMPROC, LPARAM);
static UINT_PTR WINAPI Hook_SetTimer(HWND, UINT_PTR, UINT, TIMERPROC);
static BOOL    WINAPI Hook_SetWaitableTimer(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, PVOID, BOOL);
static BOOL    WINAPI Hook_CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
static HANDLE  WINAPI Hook_OpenProcess(DWORD, BOOL, DWORD);
static BOOL    WINAPI Hook_VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
static HANDLE  WINAPI Hook_CreateFileMappingW(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
static HANDLE  WINAPI Hook_CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
static BOOL    WINAPI Hook_EnumSystemLocalesW(LOCALE_ENUMPROCW, DWORD);
static LRESULT WINAPI Hook_CallWindowProcA(WNDPROC, HWND, UINT, WPARAM, LPARAM);
static LRESULT WINAPI Hook_CallWindowProcW(WNDPROC, HWND, UINT, WPARAM, LPARAM);
static BOOL    WINAPI Hook_EnumThreadWindows(DWORD, WNDENUMPROC, LPARAM);
static LPVOID  WINAPI Hook_ConvertThreadToFiber(LPVOID);
static LPVOID  WINAPI Hook_CreateFiber(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
static VOID    WINAPI Hook_SwitchToFiber(LPVOID);
static NTSTATUS NTAPI Hook_RtlCreateUserThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
                                               SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);
static HANDLE  WINAPI Hook_CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
static LONG_PTR WINAPI Hook_SetWindowLongPtrA(HWND, int, LONG_PTR);
static LONG_PTR WINAPI Hook_SetWindowLongPtrW(HWND, int, LONG_PTR);
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertFindCertificateInStore(HCERTSTORE_OPAQUE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT_OPAQUE);
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertEnumCertificatesInStore(HCERTSTORE_OPAQUE, PCCERT_CONTEXT_OPAQUE);
static PVOID   WINAPI Hook_AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   WINAPI Hook_AddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   NTAPI  Hook_RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID   NTAPI  Hook_RtlAddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
// SSPI authentication downgrade hooks
typedef void* PCtxtHandle;
typedef void* PCredHandle;
typedef void* PSecBufferDesc;
// DPAPI hook — CryptUnprotectData uses DATA_BLOB structures
typedef struct { DWORD cbData; BYTE* pbData; } HOOK_DATA_BLOB;
// SystemFunction032 — RC4 encryption (sleep obfuscation)
typedef struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } USTRING;
static LONG  WINAPI Hook_InitializeSecurityContextW(
    PCredHandle, PCtxtHandle, wchar_t*, ULONG, ULONG, ULONG,
    PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, ULONG*, PLARGE_INTEGER);
static LONG  WINAPI Hook_AcquireCredentialsHandleW(
    wchar_t*, wchar_t*, ULONG, PVOID, PVOID, PVOID, PVOID, PCredHandle, PLARGE_INTEGER);
// Sleep obfuscation
static NTSTATUS WINAPI Hook_SystemFunction032(USTRING* data, USTRING* key);
// DPAPI credential harvesting
static BOOL WINAPI Hook_CryptUnprotectData(
    HOOK_DATA_BLOB*, wchar_t**, HOOK_DATA_BLOB*, PVOID, PVOID, DWORD, HOOK_DATA_BLOB*);
// Process Ghosting / Transacted Hollowing
static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE, PVOID, PVOID, ULONG, ULONG);
static NTSTATUS NTAPI Hook_NtCreateTransaction(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PVOID);
// WFP manipulation detection (fwpuclnt.dll)
// These typedefs match the WFP user-mode API signatures.
// We use DWORD/PVOID for opaque WFP structures to avoid pulling in fwpmu.h.
typedef DWORD (WINAPI *FnFwpmFilterAdd0)(HANDLE, const PVOID, PVOID, UINT64*);
typedef DWORD (WINAPI *FnFwpmFilterDeleteById0)(HANDLE, UINT64);
typedef DWORD (WINAPI *FnFwpmCalloutAdd0)(HANDLE, const PVOID, PVOID, UINT32*);
typedef DWORD (WINAPI *FnFwpmSubLayerAdd0)(HANDLE, const PVOID, PVOID);
typedef DWORD (WINAPI *FnFwpmSubLayerDeleteByKey0)(HANDLE, const GUID*);
typedef DWORD (WINAPI *FnFwpmEngineClose0)(HANDLE);
// WFP enumeration/recon typedefs
typedef DWORD (WINAPI *FnFwpmFilterEnum0)(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
typedef DWORD (WINAPI *FnFwpmCalloutEnum0)(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
typedef DWORD (WINAPI *FnFwpmSubLayerEnum0)(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
typedef DWORD (WINAPI *FnFwpmProviderEnum0)(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
typedef DWORD (WINAPI *FnFwpmEngineGetSecurityInfo0)(HANDLE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
typedef DWORD (WINAPI *FnFwpmFilterGetSecurityInfoByKey0)(HANDLE, const GUID*, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
static DWORD  WINAPI Hook_FwpmFilterAdd0(HANDLE, const PVOID, PVOID, UINT64*);
static DWORD  WINAPI Hook_FwpmFilterDeleteById0(HANDLE, UINT64);
static DWORD  WINAPI Hook_FwpmCalloutAdd0(HANDLE, const PVOID, PVOID, UINT32*);
static DWORD  WINAPI Hook_FwpmSubLayerAdd0(HANDLE, const PVOID, PVOID);
static DWORD  WINAPI Hook_FwpmSubLayerDeleteByKey0(HANDLE, const GUID*);
static DWORD  WINAPI Hook_FwpmEngineClose0(HANDLE);
static DWORD  WINAPI Hook_FwpmFilterEnum0(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
static DWORD  WINAPI Hook_FwpmCalloutEnum0(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
static DWORD  WINAPI Hook_FwpmSubLayerEnum0(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
static DWORD  WINAPI Hook_FwpmProviderEnum0(HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
static DWORD  WINAPI Hook_FwpmEngineGetSecurityInfo0(HANDLE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
static DWORD  WINAPI Hook_FwpmFilterGetSecurityInfoByKey0(HANDLE, const GUID*, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
// Weaver Ant: JScript/VBScript script engine COM instantiation detection
typedef HRESULT (WINAPI *FnCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
static HRESULT WINAPI Hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, REFIID riid, LPVOID* ppv);
// DCOM remote instantiation — attackers use CoCreateInstanceEx for remote COM
// (MMC20.Application, ShellWindows, etc.) lateral movement.
typedef struct { CLSID* pClsid; LPUNKNOWN punkOuter; DWORD dwFlags; } MULTI_QI_STUB;
typedef HRESULT (WINAPI *FnCoCreateInstanceEx)(REFCLSID, LPUNKNOWN, DWORD, PVOID, DWORD, PVOID);
static HRESULT WINAPI Hook_CoCreateInstanceEx(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, PVOID pServerInfo, DWORD dwCount, PVOID pResults);
// CLSIDFromProgID — attackers resolve "JScript", "VBScript", "WScript.Shell"
// ProgIDs to avoid hardcoding CLSIDs.
typedef HRESULT (WINAPI *FnCLSIDFromProgID)(LPCOLESTR, LPCLSID);
static HRESULT WINAPI Hook_CLSIDFromProgID(LPCOLESTR lpszProgID, LPCLSID lpclsid);
// EnableTraceEx2 — ETW filter descriptor injection detection
// ENABLE_TRACE_PARAMETERS contains FilterDescCount + EnableFilterDesc array.
// Attackers attach EVENT_FILTER_TYPE_PAYLOAD / EVENT_ID / EVENT_NAME filters
// to silently drop specific events without disabling the provider.
typedef struct _ENABLE_TRACE_PARAMETERS_HOOK {
    ULONG  Version;
    ULONG  EnableProperty;
    ULONG  ControlFlags;
    GUID   SourceId;
    /* PEVENT_FILTER_DESCRIPTOR */ PVOID EnableFilterDesc;
    ULONG  FilterDescCount;
} ENABLE_TRACE_PARAMETERS_HOOK;
typedef ULONG (WINAPI *FnEnableTraceEx2)(
    ULONG_PTR TraceHandle, const GUID* ProviderId, ULONG ControlCode,
    UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    ULONG Timeout, ENABLE_TRACE_PARAMETERS_HOOK* EnableParameters);
static ULONG WINAPI Hook_EnableTraceEx2(
    ULONG_PTR TraceHandle, const GUID* ProviderId, ULONG ControlCode,
    UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    ULONG Timeout, ENABLE_TRACE_PARAMETERS_HOOK* EnableParameters);

// REGHANDLE-nulling detection — fires if EventWrite is called with handle=0
typedef ULONG (NTAPI *FnEtwEventWrite)(
    REGHANDLE RegHandle, PVOID EventDescriptor,
    ULONG UserDataCount, PVOID UserData);
static ULONG NTAPI Hook_EtwEventWrite(
    REGHANDLE RegHandle, PVOID EventDescriptor,
    ULONG UserDataCount, PVOID UserData);

// Session security descriptor rewrite — EventAccessControl tweaks SD on a
// provider GUID, granting non-admin callers session-modification rights.
typedef ULONG (WINAPI *FnEventAccessControl)(
    LPGUID Guid, ULONG Operation, PSID Sid, ULONG Rights, BOOLEAN AllowOrDeny);
static ULONG WINAPI Hook_EventAccessControl(
    LPGUID Guid, ULONG Operation, PSID Sid, ULONG Rights, BOOLEAN AllowOrDeny);

// Rogue real-time consumer — OpenTraceW with EVENT_TRACE_REAL_TIME_MODE
// attaches a consumer to a live session, intercepting events before any
// file write.  Trusted consumers are few (EventViewer, logman, Sysmon, us).
typedef ULONG_PTR (WINAPI *FnOpenTraceW)(PVOID Logfile);
static ULONG_PTR WINAPI Hook_OpenTraceW(PVOID Logfile);

// Dylan Hall "Universally Evading Sysmon and ETW" — capture REGHANDLEs
// so we can baseline and diff user-mode _ETW_REG_ENTRY structs each tick.
typedef ULONG (NTAPI *FnEtwEventRegister)(
    LPCGUID ProviderId, PVOID EnableCallback, PVOID CallbackContext,
    REGHANDLE* RegHandle);
static ULONG NTAPI Hook_EtwEventRegister(
    LPCGUID ProviderId, PVOID EnableCallback, PVOID CallbackContext,
    REGHANDLE* RegHandle);

static ApiHook g_hooks[HOOK_COUNT] = {
    { "kernel32.dll", "VirtualAlloc",         (FARPROC)Hook_VirtualAlloc,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "VirtualAllocEx",       (FARPROC)Hook_VirtualAllocEx,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "WriteProcessMemory",   (FARPROC)Hook_WriteProcessMemory,  nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateRemoteThread",   (FARPROC)Hook_CreateRemoteThread,  nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateRemoteThreadEx", (FARPROC)Hook_CreateRemoteThreadEx,nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryA",         (FARPROC)Hook_LoadLibraryA,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryW",         (FARPROC)Hook_LoadLibraryW,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryExA",       (FARPROC)Hook_LoadLibraryExA,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "LoadLibraryExW",       (FARPROC)Hook_LoadLibraryExW,      nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ResumeThread",         (FARPROC)Hook_ResumeThread,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SetThreadContext",     (FARPROC)Hook_SetThreadContext,     nullptr, nullptr, {}, nullptr, false },
    { "advapi32.dll", "RegSetValueExA",       (FARPROC)Hook_RegSetValueExA,       nullptr, nullptr, {}, nullptr, false },
    { "advapi32.dll", "RegSetValueExW",       (FARPROC)Hook_RegSetValueExW,       nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ReadProcessMemory",    (FARPROC)Hook_ReadProcessMemory,    nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "NtQuerySystemInformation",    (FARPROC)Hook_NtQuerySystemInformation,    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateThread",               (FARPROC)Hook_CreateThread,                nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "MapViewOfFile",              (FARPROC)Hook_MapViewOfFile,               nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "RegisterClassExA",           (FARPROC)Hook_RegisterClassExA,            nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "RegisterClassExW",           (FARPROC)Hook_RegisterClassExW,            nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLocalesA",         (FARPROC)Hook_EnumSystemLocalesA,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLanguageGroupsA",  (FARPROC)Hook_EnumSystemLanguageGroupsA,   nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumWindows",                (FARPROC)Hook_EnumWindows,                 nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumChildWindows",           (FARPROC)Hook_EnumChildWindows,            nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetTimer",                   (FARPROC)Hook_SetTimer,                    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SetWaitableTimer",           (FARPROC)Hook_SetWaitableTimer,            nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateTimerQueueTimer",      (FARPROC)Hook_CreateTimerQueueTimer,       nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "OpenProcess",               (FARPROC)Hook_OpenProcess,                 nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "VirtualProtect",            (FARPROC)Hook_VirtualProtect,              nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFileMappingW",        (FARPROC)Hook_CreateFileMappingW,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFileMappingA",        (FARPROC)Hook_CreateFileMappingA,          nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "EnumSystemLocalesW",        (FARPROC)Hook_EnumSystemLocalesW,          nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "CallWindowProcA",           (FARPROC)Hook_CallWindowProcA,             nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "CallWindowProcW",           (FARPROC)Hook_CallWindowProcW,             nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "EnumThreadWindows",         (FARPROC)Hook_EnumThreadWindows,           nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "ConvertThreadToFiber",      (FARPROC)Hook_ConvertThreadToFiber,        nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateFiber",               (FARPROC)Hook_CreateFiber,                 nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "SwitchToFiber",             (FARPROC)Hook_SwitchToFiber,               nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlCreateUserThread",       (FARPROC)Hook_RtlCreateUserThread,         nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "CreateWaitableTimerExW",    (FARPROC)Hook_CreateWaitableTimerExW,      nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetWindowLongPtrA",         (FARPROC)Hook_SetWindowLongPtrA,           nullptr, nullptr, {}, nullptr, false },
    { "user32.dll",   "SetWindowLongPtrW",         (FARPROC)Hook_SetWindowLongPtrW,           nullptr, nullptr, {}, nullptr, false },
    { "crypt32.dll",  "CertFindCertificateInStore",(FARPROC)Hook_CertFindCertificateInStore,   nullptr, nullptr, {}, nullptr, false },
    { "crypt32.dll",  "CertEnumCertificatesInStore",(FARPROC)Hook_CertEnumCertificatesInStore, nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "AddVectoredExceptionHandler",   (FARPROC)Hook_AddVectoredExceptionHandler,    nullptr, nullptr, {}, nullptr, false },
    { "kernel32.dll", "AddVectoredContinueHandler",    (FARPROC)Hook_AddVectoredContinueHandler,     nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlAddVectoredExceptionHandler",(FARPROC)Hook_RtlAddVectoredExceptionHandler, nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "RtlAddVectoredContinueHandler", (FARPROC)Hook_RtlAddVectoredContinueHandler,  nullptr, nullptr, {}, nullptr, false },
    // SSPI authentication downgrade detection
    { "sspicli.dll",  "InitializeSecurityContextW",    (FARPROC)Hook_InitializeSecurityContextW,      nullptr, nullptr, {}, nullptr, false },
    { "sspicli.dll",  "AcquireCredentialsHandleW",     (FARPROC)Hook_AcquireCredentialsHandleW,      nullptr, nullptr, {}, nullptr, false },
    // Sleep obfuscation detection (Ekko/Foliage use SystemFunction032 = RC4)
    { "advapi32.dll", "SystemFunction032",             (FARPROC)Hook_SystemFunction032,               nullptr, nullptr, {}, nullptr, false },
    // DPAPI browser credential harvesting
    { "crypt32.dll",  "CryptUnprotectData",            (FARPROC)Hook_CryptUnprotectData,              nullptr, nullptr, {}, nullptr, false },
    // Process Ghosting (delete-before-map) and Transacted Hollowing
    { "ntdll.dll",    "NtSetInformationFile",          (FARPROC)Hook_NtSetInformationFile,            nullptr, nullptr, {}, nullptr, false },
    { "ntdll.dll",    "NtCreateTransaction",           (FARPROC)Hook_NtCreateTransaction,             nullptr, nullptr, {}, nullptr, false },
    // WFP manipulation detection — fwpuclnt.dll (loaded on-demand by attackers)
    { "fwpuclnt.dll", "FwpmFilterAdd0",                (FARPROC)Hook_FwpmFilterAdd0,                  nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmFilterDeleteById0",         (FARPROC)Hook_FwpmFilterDeleteById0,           nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmCalloutAdd0",               (FARPROC)Hook_FwpmCalloutAdd0,                 nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmSubLayerAdd0",              (FARPROC)Hook_FwpmSubLayerAdd0,                nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmSubLayerDeleteByKey0",      (FARPROC)Hook_FwpmSubLayerDeleteByKey0,        nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmEngineClose0",              (FARPROC)Hook_FwpmEngineClose0,                nullptr, nullptr, {}, nullptr, false },
    // --- WFP enumeration/recon hooks ---
    { "fwpuclnt.dll", "FwpmFilterEnum0",              (FARPROC)Hook_FwpmFilterEnum0,                 nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmCalloutEnum0",             (FARPROC)Hook_FwpmCalloutEnum0,                nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmSubLayerEnum0",            (FARPROC)Hook_FwpmSubLayerEnum0,               nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmProviderEnum0",            (FARPROC)Hook_FwpmProviderEnum0,               nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmEngineGetSecurityInfo0",   (FARPROC)Hook_FwpmEngineGetSecurityInfo0,       nullptr, nullptr, {}, nullptr, false },
    { "fwpuclnt.dll", "FwpmFilterGetSecurityInfoByKey0", (FARPROC)Hook_FwpmFilterGetSecurityInfoByKey0, nullptr, nullptr, {}, nullptr, false },
    // Weaver Ant: script engine COM instantiation + DCOM lateral movement
    { "ole32.dll",    "CoCreateInstance",               (FARPROC)Hook_CoCreateInstance,              nullptr, nullptr, {}, nullptr, false },
    { "ole32.dll",    "CoCreateInstanceEx",             (FARPROC)Hook_CoCreateInstanceEx,            nullptr, nullptr, {}, nullptr, false },
    { "ole32.dll",    "CLSIDFromProgID",                (FARPROC)Hook_CLSIDFromProgID,               nullptr, nullptr, {}, nullptr, false },
    // ETW filter descriptor attack — EnableTraceEx2 interception
    { "advapi32.dll", "EnableTraceEx2",                  (FARPROC)Hook_EnableTraceEx2,                nullptr, nullptr, {}, nullptr, false },
    // REGHANDLE nulling — EtwEventWrite called with handle=0 means caller's
    // REGHANDLE variable was zeroed, silently dropping events (T1562.002)
    { "ntdll.dll",    "EtwEventWrite",                   (FARPROC)Hook_EtwEventWrite,                 nullptr, nullptr, {}, nullptr, false },
    // Session security descriptor rewrite detection
    { "advapi32.dll", "EventAccessControl",              (FARPROC)Hook_EventAccessControl,            nullptr, nullptr, {}, nullptr, false },
    // Rogue real-time consumer attach detection
    { "advapi32.dll", "OpenTraceW",                      (FARPROC)Hook_OpenTraceW,                    nullptr, nullptr, {}, nullptr, false },
    // Dylan Hall user-mode _ETW_REG_ENTRY tampering — capture REGHANDLEs
    { "ntdll.dll",    "EtwEventRegister",                (FARPROC)Hook_EtwEventRegister,              nullptr, nullptr, {}, nullptr, false },
};

// Returns the correct call-through address.
// When both hook types are active, IAT stubs MUST call the trampoline — calling
// .original directly would re-enter the inline hook (the prologue is now our JMP).
static inline FARPROC GetCallThrough(int idx) {
    return g_hooks[idx].inlinePatched
           ? g_hooks[idx].trampoline
           : g_hooks[idx].original;
}

// ---------------------------------------------------------------------------
// IAT patching engine
// ---------------------------------------------------------------------------

static void ToLower(const char* src, char* dst, int dstLen) {
    int i = 0;
    for (; i < dstLen - 1 && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static void PatchModuleIAT(HMODULE hMod, bool restore) {
    __try {
        auto base = (BYTE*)hMod;
        auto dos  = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto nth  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE) return;

        IMAGE_DATA_DIRECTORY& impDir =
            nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!impDir.VirtualAddress || !impDir.Size) return;

        auto desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);
        for (; desc->Name; desc++) {
            char lowerName[64];
            ToLower((const char*)(base + desc->Name), lowerName, sizeof(lowerName));

            for (int hi = 0; hi < HOOK_COUNT; hi++) {
                if (strcmp(lowerName, g_hooks[hi].modName) != 0) continue;

                auto orig  = desc->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA64*)(base + desc->OriginalFirstThunk) : nullptr;
                auto first = (IMAGE_THUNK_DATA64*)(base + desc->FirstThunk);

                for (DWORD ti = 0; first[ti].u1.Function; ti++) {
                    if (!orig || (orig[ti].u1.Ordinal & IMAGE_ORDINAL_FLAG64)) continue;
                    auto ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig[ti].u1.AddressOfData);
                    if (_stricmp(ibn->Name, g_hooks[hi].funcName) != 0) continue;

                    auto slot = (FARPROC*)&first[ti].u1.Function;
                    if (!restore && g_hooks[hi].original == nullptr)
                        g_hooks[hi].original = *slot;
                    if (g_hooks[hi].original == nullptr) continue;

                    DWORD old = 0;
                    if (VirtualProtect(slot, sizeof(FARPROC), PAGE_READWRITE, &old)) {
                        *slot = restore ? g_hooks[hi].original : g_hooks[hi].hookFn;
                        VirtualProtect(slot, sizeof(FARPROC), old, &old);
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void PatchAllModules(bool restore) {
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    for (DWORD i = 0, n = needed / sizeof(HMODULE); i < n; i++)
        if (mods[i]) PatchModuleIAT(mods[i], restore);
}

// ---------------------------------------------------------------------------
// Inline hook + trampoline engine
//
// Patch layout (written at function prologue, kPatchBytes = 14):
//   FF 25 00 00 00 00        JMP QWORD PTR [RIP+0]   — 6 bytes
//   XX XX XX XX XX XX XX XX  absolute address of hook stub — 8 bytes
//
// Trampoline layout (kTrampolineSize = 32 bytes, PAGE_EXECUTE_READWRITE):
//   [ 0 .. 13] original prologue bytes (14 bytes saved before patching)
//   [14 .. 27] FF 25 00 00 00 00 + 8-byte address of (target + 14)
//   [28 .. 31] padding
//
// The hook stub calls GetCallThrough() which returns the trampoline address,
// ensuring the call-through re-executes the displaced bytes then falls through
// to the rest of the original function (target + 14).
//
// Limitation (by design, no disassembler): if a relative branch or RIP-relative
// memory operand falls in the first 14 bytes, IsSafeToCopy() rejects the function
// and the inline hook is silently skipped (IAT hook still applies).
// ---------------------------------------------------------------------------

static constexpr int kPatchBytes    = 14; // 6-byte indirect JMP + 8-byte address
static constexpr int kTrampolineSize = 32;

static BYTE* g_trampolinePool = nullptr;

// Saved before any hooking so VerifyHooks() can VirtualProtect without re-entering
// our own Hook_VirtualProtect stub.
static BOOL (WINAPI *g_vpOriginal)(LPVOID, SIZE_T, DWORD, PDWORD) = nullptr;

// Hook-integrity watch thread handles.
static HANDLE g_watchStop   = nullptr;  // auto-reset event — signals thread to exit
static HANDLE g_watchThread = nullptr;

// Returns false if the first `len` bytes contain instructions that would produce
// wrong results when copied to a different address (RIP-relative operands or
// relative branches).
static bool IsSafeToCopy(const BYTE* fn, int len) {
    __try {
        for (int i = 0; i < len; i++) {
            BYTE b = fn[i];

            // Relative CALL / near JMP / short JMP
            if (b == 0xE8 || b == 0xE9 || b == 0xEB) return false;

            // Conditional near jumps: 0F 80..8F
            if (b == 0x0F && i + 1 < len && (fn[i + 1] & 0xF0) == 0x80) return false;

            // RIP-relative memory operand: ModRM mod=00 rm=101.
            // Cover the most common cases in prologues:
            //   REX.W (48..4F) + MOV r,rm (8B) or LEA r,m (8D) with RIP-rel ModRM
            if ((b >= 0x48 && b <= 0x4F) && i + 2 < len) {
                BYTE opc   = fn[i + 1];
                BYTE modrm = fn[i + 2];
                if ((opc == 0x8B || opc == 0x8D) &&
                    (modrm >> 6) == 0 && (modrm & 7) == 5)
                    return false;
            }

            // Indirect CALL/JMP through RIP-relative pointer: FF 15 / FF 25 disp32
            if (b == 0xFF && i + 1 < len) {
                BYTE modrm = fn[i + 1];
                BYTE reg   = (modrm >> 3) & 7;  // reg field selects CALL(2)/JMP(4)
                if ((reg == 2 || reg == 4) &&
                    (modrm >> 6) == 0 && (modrm & 7) == 5)
                    return false;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}

static void InstallInlineHook(ApiHook& h, BYTE* trampolineSlot) {
    HMODULE hMod = GetModuleHandleA(h.modName);
    if (!hMod) return;

    // GetProcAddress resolves forwarder chains (e.g. kernel32→KernelBase)
    BYTE* target = (BYTE*)GetProcAddress(hMod, h.funcName);
    if (!target) return;

    if (!IsSafeToCopy(target, kPatchBytes)) return;

    // --- Build trampoline ---
    // Bytes 0..13: displaced prologue
    memcpy(trampolineSlot, target, kPatchBytes);
    // Bytes 14..27: absolute JMP back to target+14
    BYTE* jmpBack = trampolineSlot + kPatchBytes;
    ULONG64 returnAddr = (ULONG64)(target + kPatchBytes);
    jmpBack[0] = 0xFF; jmpBack[1] = 0x25;
    jmpBack[2] = jmpBack[3] = jmpBack[4] = jmpBack[5] = 0x00; // [RIP+0]
    memcpy(jmpBack + 6, &returnAddr, sizeof(ULONG64));

    // --- Record for restore ---
    memcpy(h.savedBytes, target, kPatchBytes);
    h.inlineTarget = target;
    h.trampoline   = (FARPROC)trampolineSlot;

    // --- Write the 14-byte prologue patch ---
    BYTE patch[kPatchBytes];
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0x00; // [RIP+0]
    ULONG64 hookAddr = (ULONG64)h.hookFn;
    memcpy(patch + 6, &hookAddr, sizeof(ULONG64));

    DWORD old = 0;
    if (VirtualProtect(target, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(target, patch, kPatchBytes);
        VirtualProtect(target, kPatchBytes, old, &old);
        h.inlinePatched = true;
    }
}

static void RemoveInlineHook(ApiHook& h) {
    if (!h.inlinePatched || !h.inlineTarget) return;
    DWORD old = 0;
    if (VirtualProtect(h.inlineTarget, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(h.inlineTarget, h.savedBytes, kPatchBytes);
        VirtualProtect(h.inlineTarget, kPatchBytes, old, &old);
    }
    h.inlinePatched = false;
    h.inlineTarget  = nullptr;
    h.trampoline    = nullptr;
}

// ---------------------------------------------------------------------------
// Hook self-integrity
//
// VerifyHooks() walks every installed inline hook and checks that the first
// two bytes of the patched prologue are still 0xFF 0x25 (our indirect JMP).
// If another tool (Detours, manual unhooking) has overwritten the patch, we:
//   1. Send a Critical event naming the affected API.
//   2. Re-apply the 14-byte patch using the saved hookFn address.
//
// WatchThreadProc runs in a background thread started at DLL_PROCESS_ATTACH
// and calls VerifyHooks() every 2 seconds until signalled to stop.
// ---------------------------------------------------------------------------

static void VerifyHooks() {
    if (!g_vpOriginal) return;

    for (int i = 0; i < HOOK_COUNT; i++) {
        ApiHook& h = g_hooks[i];
        if (!h.inlinePatched || !h.inlineTarget) continue;

        // Check that our patch signature (FF 25) is still in place.
        bool tampered = false;
        __try {
            tampered = (h.inlineTarget[0] != 0xFF || h.inlineTarget[1] != 0x25);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!tampered) continue;

        // Report the tampering — another hooking layer removed our patch.
        char det[192];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "inline hook removed/overwritten: %s!%s at %p — bytes now %02X %02X",
            h.modName, h.funcName, (void*)h.inlineTarget,
            (unsigned)h.inlineTarget[0], (unsigned)h.inlineTarget[1]);
        SendHookEvent("Critical", "HookIntegrityViolation", 0, det);

        // Re-apply the 14-byte patch via the raw VirtualProtect pointer so we
        // don't re-enter Hook_VirtualProtect and generate a spurious alert.
        BYTE patch[kPatchBytes];
        patch[0] = 0xFF; patch[1] = 0x25;
        patch[2] = patch[3] = patch[4] = patch[5] = 0x00;
        ULONG64 hookAddr = (ULONG64)h.hookFn;
        memcpy(patch + 6, &hookAddr, sizeof(ULONG64));

        DWORD old = 0;
        if (g_vpOriginal(h.inlineTarget, kPatchBytes, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(h.inlineTarget, patch, kPatchBytes);
            g_vpOriginal(h.inlineTarget, kPatchBytes, old, &old);
        }
    }
}

// ---------------------------------------------------------------------------
// ETW / AMSI critical function integrity monitoring (XPN "Hiding Your .NET")
//
// Attackers patch ntdll!EtwEventWrite or amsi!AmsiScanBuffer prologues with
// a `ret` (0xC3) to blind ETW telemetry or AMSI scanning.  The prerequisite
// VirtualProtect on image memory is caught by the kernel driver, but we add
// a user-mode integrity check here as defense-in-depth.
//
// On first call, we snapshot the first 16 bytes of each function.
// On each subsequent check, we compare and alert + restore if tampered.
// ---------------------------------------------------------------------------
struct CriticalFuncGuard {
    const char* modName;
    const char* funcName;
    BYTE* addr;            // resolved address
    BYTE  baseline[64];    // 64 bytes catches deep trampoline splices past typical prologues
    bool  valid;           // baseline captured
};

static CriticalFuncGuard g_etwGuards[] = {
    { "ntdll.dll",  "EtwEventWrite",     nullptr, {}, false },
    { "ntdll.dll",  "EtwEventWriteFull", nullptr, {}, false },
    { "ntdll.dll",  "NtTraceEvent",      nullptr, {}, false },
    // advapi32 user-mode ETW wrappers — distinct code path from ntdll ETW
    { "advapi32.dll", "EventWrite",         nullptr, {}, false },
    { "advapi32.dll", "EventWriteTransfer", nullptr, {}, false },
    { "advapi32.dll", "EventRegister",      nullptr, {}, false },
    // Classic Windows Event Log API — patching silences legacy event reporting
    { "advapi32.dll", "ReportEventW",       nullptr, {}, false },
    { "advapi32.dll", "ReportEventA",       nullptr, {}, false },
    { "amsi.dll",   "AmsiScanBuffer",    nullptr, {}, false },
    { "amsi.dll",   "AmsiOpenSession",   nullptr, {}, false },
    // Provider-specific EventRegister call-site protection (FindETWProviderImage chain).
    // Attackers locate the exact RVA where a provider DLL calls EventRegister
    // and NOP/redirect it.  Monitor EventUnregister (disabling providers) and
    // TraceLogging API entry points (self-describing provider lifecycle).
    { "advapi32.dll", "EventUnregister",    nullptr, {}, false },
    { "advapi32.dll", "EventWriteEx",       nullptr, {}, false },
    { "ntdll.dll",    "EtwEventRegister",   nullptr, {}, false },
    { "ntdll.dll",    "EtwEventUnregister", nullptr, {}, false },
    { "ntdll.dll",    "EtwEventWriteTransfer", nullptr, {}, false },
    { "ntdll.dll",    "EtwEventWriteNoRegistration", nullptr, {}, false },
    // ETW provider/session property manipulation APIs — attackers call these to
    // silently alter provider traits or session config from within the process.
    { "ntdll.dll",    "EventSetInformation",      nullptr, {}, false },
    { "advapi32.dll", "TraceSetInformation",      nullptr, {}, false },
    { "sechost.dll",  "TraceSetInformation",      nullptr, {}, false },
    // ETW controller APIs — patching these prevents session management.
    // advapi32.dll exports (forwarded to sechost.dll on Win10 1709+)
    { "advapi32.dll", "StartTraceW",           nullptr, {}, false },
    { "advapi32.dll", "ControlTraceW",         nullptr, {}, false },
    { "advapi32.dll", "EnableTraceEx2",        nullptr, {}, false },
    { "advapi32.dll", "OpenTraceW",            nullptr, {}, false },
    { "advapi32.dll", "ProcessTrace",          nullptr, {}, false },
    { "advapi32.dll", "CloseTrace",            nullptr, {}, false },
    { "advapi32.dll", "QueryAllTracesW",       nullptr, {}, false },
    { "advapi32.dll", "EnumerateTraceGuidsEx", nullptr, {}, false },
    { "advapi32.dll", "StopTraceW",            nullptr, {}, false },
    // sechost.dll — Win10 1709+ real implementation (advapi32 forwards here).
    // Monitor both layers so patching either is detected.
    { "sechost.dll",  "StartTraceW",           nullptr, {}, false },
    { "sechost.dll",  "ControlTraceW",         nullptr, {}, false },
    { "sechost.dll",  "EnableTraceEx2",        nullptr, {}, false },
    { "sechost.dll",  "OpenTraceW",            nullptr, {}, false },
    { "sechost.dll",  "ProcessTrace",          nullptr, {}, false },
    { "sechost.dll",  "CloseTrace",            nullptr, {}, false },
    { "sechost.dll",  "QueryAllTracesW",       nullptr, {}, false },
    { "sechost.dll",  "EnumerateTraceGuidsEx", nullptr, {}, false },
    { "sechost.dll",  "StopTraceW",            nullptr, {}, false },
    // Mimikatz crypto::capi / crypto::cng patches these to force-export
    // non-exportable private keys (CRYPT_EXPORTABLE flag bypass).
    { "ncrypt.dll", "NCryptOpenStorageProvider", nullptr, {}, false },
    { "ncrypt.dll", "NCryptExportKey",           nullptr, {}, false },
    { "ncrypt.dll", "NCryptFreeObject",          nullptr, {}, false },
    { nullptr, nullptr, nullptr, {}, false }
};

static void InitCriticalFuncGuards() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        HMODULE hMod = GetModuleHandleA(g_etwGuards[i].modName);
        if (!hMod) continue;
        BYTE* fn = (BYTE*)GetProcAddress(hMod, g_etwGuards[i].funcName);
        if (!fn) continue;

        g_etwGuards[i].addr = fn;
        __try {
            memcpy(g_etwGuards[i].baseline, fn, 64);
            g_etwGuards[i].valid = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

static void VerifyCriticalFuncIntegrity() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        CriticalFuncGuard& g = g_etwGuards[i];
        if (!g.valid || !g.addr) continue;

        // amsi.dll may not be loaded yet — re-resolve on each check
        if (!g.valid && !g.addr) {
            HMODULE hMod = GetModuleHandleA(g.modName);
            if (!hMod) continue;
            BYTE* fn = (BYTE*)GetProcAddress(hMod, g.funcName);
            if (!fn) continue;
            g.addr = fn;
            __try {
                memcpy(g.baseline, fn, 64);
                g.valid = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }

        // --- PAGE_NOACCESS / PAGE_GUARD detection ---
        // An attacker can change the page protection of a critical function
        // to PAGE_NOACCESS or add PAGE_GUARD, then register a VEH to
        // intercept the resulting exception and return a fake success value.
        // The function prologue is never modified, so byte-level checks pass.
        // Detection: VirtualQuery the function address and verify the page
        // has execute permission and no PAGE_GUARD flag.
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(g.addr, &mbi, sizeof(mbi)) >= sizeof(mbi)) {
                DWORD prot = mbi.Protect;
                bool noExec = (prot == PAGE_NOACCESS ||
                               prot == PAGE_READONLY ||
                               prot == PAGE_READWRITE ||
                               prot == PAGE_WRITECOPY);
                bool hasGuard = (prot & PAGE_GUARD) != 0;

                if (noExec || hasGuard) {
                    char det[300];
                    _snprintf_s(det, sizeof(det), _TRUNCATE,
                        "%s!%s page protection TAMPERED: 0x%lX (%s%s) — "
                        "function page is %s, exception-based hooking "
                        "suspected (VEH/SEH intercepts access violation) "
                        "(T1562.002)",
                        g.modName, g.funcName, prot,
                        noExec ? "NO_EXECUTE" : "",
                        hasGuard ? "PAGE_GUARD" : "",
                        noExec ? "non-executable" : "guard-flagged");
                    SendHookEvent("Critical", "PageProtectionTamper", 0, det);

                    // Restore execute permission
                    DWORD old = 0;
                    if (g_vpOriginal)
                        g_vpOriginal(g.addr, 64, PAGE_EXECUTE_READ, &old);
                }
            }
        }

        bool tampered = false;
        BYTE current[64] = {};
        __try {
            memcpy(current, g.addr, 64);
            tampered = (memcmp(current, g.baseline, 64) != 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // If we can't read the prologue, the page may have been made
            // inaccessible — this is itself evidence of tampering
            char det[256];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "%s!%s prologue UNREADABLE — page access violation during "
                "integrity check, likely PAGE_NOACCESS/PAGE_GUARD attack "
                "(T1562.002)",
                g.modName, g.funcName);
            SendHookEvent("Critical", "PageProtectionTamper", 0, det);
            continue;
        }

        if (!tampered) continue;

        // Identify the specific patch pattern for better alerting
        const char* pattern = "unknown modification";
        if (current[0] == 0xCC)
            pattern = "INT3 (0xCC) — software breakpoint hook (VEH/SEH-based "
                "function hijacking without trampoline)";
        else if (current[0] == 0xC3)
            pattern = "ret (0xC3) — XPN ETW/AMSI blind technique";
        else if (current[0] == 0xB8 && current[5] == 0xC3)
            pattern = "mov eax,imm + ret — forced clean return";
        else if (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3)
            pattern = "xor eax,eax + ret — forced S_OK return";
        else if (current[0] == 0x48 && current[1] == 0x31 && current[2] == 0xC0 && current[3] == 0xC3)
            pattern = "xor rax,rax + ret — forced zero return (x64)";
        else if (current[0] == 0xE9)
            pattern = "JMP rel32 (0xE9) — near jump trampoline hook";
        else if (current[0] == 0xFF && current[1] == 0x25)
            pattern = "JMP [rip+disp32] (FF 25) — indirect jump hook";
        else if (current[0] == 0x48 && current[1] == 0xB8 &&
                 current[10] == 0xFF && current[11] == 0xE0)
            pattern = "MOV rax,imm64 + JMP rax — 64-bit trampoline hook";
        else if (current[0] == 0x68 && current[5] == 0xC3)
            pattern = "PUSH imm32 + RET — push/ret trampoline hook";
        else {
            // Scan for INT3 at non-zero offsets (instruction boundary hooks).
            // With 64-byte baselines, we catch splices/trampolines placed deep
            // past the prologue that 16/32-byte checks would miss entirely.
            for (int b = 1; b < 64; b++) {
                if (current[b] == 0xCC && g.baseline[b] != 0xCC) {
                    pattern = "INT3 at non-zero offset — mid-function software "
                        "breakpoint hook (targets instruction boundary)";
                    break;
                }
            }
        }

        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "%s!%s prologue patched: %s — "
            "original %02X%02X%02X%02X now %02X%02X%02X%02X",
            g.modName, g.funcName, pattern,
            g.baseline[0], g.baseline[1], g.baseline[2], g.baseline[3],
            current[0], current[1], current[2], current[3]);
        SendHookEvent("Critical", "EtwAmsiIntegrity", 0, det);

        // Restore the original prologue (64 bytes) to re-enable ETW/AMSI
        DWORD old = 0;
        if (g_vpOriginal &&
            g_vpOriginal(g.addr, 64, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(g.addr, g.baseline, 64);
            g_vpOriginal(g.addr, 64, old, &old);
        }
    }
}

// ---------------------------------------------------------------------------
// TLS callback integrity — malware can overwrite a loaded DLL's
// IMAGE_TLS_DIRECTORY.AddressOfCallBacks array (or add a new callback via
// AddrOfCallBacks pointer redirection) so their code runs on every thread
// creation/exit.  This is a classic persistence + ETW-bypass vector because
// TLS callbacks execute before DllMain on every thread attach.
//
// Coverage: baseline the list of TLS callback addresses for critical modules
// at init; on each watchdog tick, re-walk and diff.  Any addition/change
// outside of baseline is reported.
// ---------------------------------------------------------------------------
struct TlsGuard {
    const char* modName;
    HMODULE     hMod;
    PVOID*      cbArray;         // address of AddressOfCallBacks array
    PVOID       baselineCbs[16]; // captured callback pointers
    ULONG       baselineCount;
    bool        valid;
};

static TlsGuard g_tlsGuards[] = {
    { "ntdll.dll",   nullptr, nullptr, {}, 0, false },
    { "kernel32.dll",nullptr, nullptr, {}, 0, false },
    { "kernelbase.dll", nullptr, nullptr, {}, 0, false },
    { "advapi32.dll",nullptr, nullptr, {}, 0, false },
    { "sechost.dll", nullptr, nullptr, {}, 0, false },
    { "amsi.dll",    nullptr, nullptr, {}, 0, false },
    { "NortonEDR_HookDll.dll", nullptr, nullptr, {}, 0, false },
    { nullptr, nullptr, nullptr, {}, 0, false }
};

static PVOID* ResolveTlsCallbackArray(HMODULE hMod) {
    if (!hMod) return nullptr;
    BYTE* base = (BYTE*)hMod;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        IMAGE_DATA_DIRECTORY& tlsDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0) return nullptr;
        PIMAGE_TLS_DIRECTORY tls =
            (PIMAGE_TLS_DIRECTORY)(base + tlsDir.VirtualAddress);
        // AddressOfCallBacks is a VA (not RVA); returns pointer to a
        // null-terminated array of PIMAGE_TLS_CALLBACK.
        return (PVOID*)tls->AddressOfCallBacks;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static ULONG CaptureTlsCallbacks(PVOID* arr, PVOID out[16]) {
    if (!arr) return 0;
    ULONG n = 0;
    __try {
        while (n < 16 && arr[n] != nullptr) {
            out[n] = arr[n];
            n++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return n;
}

static void InitTlsGuards() {
    for (int i = 0; g_tlsGuards[i].modName; i++) {
        HMODULE hMod = GetModuleHandleA(g_tlsGuards[i].modName);
        if (!hMod) continue;
        PVOID* arr = ResolveTlsCallbackArray(hMod);
        if (!arr) continue;
        g_tlsGuards[i].hMod = hMod;
        g_tlsGuards[i].cbArray = arr;
        g_tlsGuards[i].baselineCount =
            CaptureTlsCallbacks(arr, g_tlsGuards[i].baselineCbs);
        g_tlsGuards[i].valid = true;
    }
}

static void CheckTlsCallbacks() {
    for (int i = 0; g_tlsGuards[i].modName; i++) {
        TlsGuard& g = g_tlsGuards[i];
        // Late-bind if the module wasn't loaded at init
        if (!g.valid) {
            HMODULE hMod = GetModuleHandleA(g.modName);
            if (!hMod) continue;
            PVOID* arr = ResolveTlsCallbackArray(hMod);
            if (!arr) continue;
            g.hMod = hMod;
            g.cbArray = arr;
            g.baselineCount = CaptureTlsCallbacks(arr, g.baselineCbs);
            g.valid = true;
            continue;
        }
        if (!g.cbArray) continue;

        PVOID current[16] = {};
        ULONG curN = CaptureTlsCallbacks(g.cbArray, current);

        if (curN != g.baselineCount) {
            char det[300];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "%s TLS callback count changed: %lu -> %lu — malware may have "
                "appended a TLS callback to gain per-thread execution "
                "(T1546.015)", g.modName, g.baselineCount, curN);
            SendHookEvent("Critical", "TlsCallbackTamper", 0, det);
            continue;
        }
        for (ULONG k = 0; k < curN; k++) {
            if (current[k] != g.baselineCbs[k]) {
                char det[300];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "%s TLS callback[%lu] pointer changed: %p -> %p — "
                    "callback redirection, possible hook/persistence "
                    "(T1546.015)",
                    g.modName, k, g.baselineCbs[k], current[k]);
                SendHookEvent("Critical", "TlsCallbackTamper", 0, det);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// First-in-line Vectored Exception Handler — catches exception-based hooks
// (INT3 0xCC, PAGE_GUARD, PAGE_NOACCESS, hardware breakpoints DR0-DR3) that
// fire on critical-module addresses.  AddVectoredExceptionHandler is already
// hooked for post-load registrations; this handler covers the *runtime fire*
// signal even for pre-existing malware VEHs that registered before our DLL
// loaded.  We register with FirstHandler=1 so we see the exception first.
// ---------------------------------------------------------------------------
static PVOID g_firstVeh = nullptr;

static LONG CALLBACK FirstVectoredHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    // Only surface exceptions commonly used for hooking and only when they
    // fire inside a known critical module — reduces false positives from
    // normal app exception flow (STATUS_ACCESS_VIOLATION in game code etc.).
    bool hookLike =
        (code == EXCEPTION_BREAKPOINT)      ||  // INT3 (0xCC) hook
        (code == EXCEPTION_SINGLE_STEP)     ||  // DR0-DR3 hardware bp fire
        (code == STATUS_GUARD_PAGE_VIOLATION) ||
        (code == EXCEPTION_ACCESS_VIOLATION);

    if (!hookLike) return EXCEPTION_CONTINUE_SEARCH;
    if (!IsAddressInKnownModule(addr)) return EXCEPTION_CONTINUE_SEARCH;

    char det[300];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "Exception-based hook fire: code=0x%08lX at %p (critical module) — "
        "INT3/GUARD/DR fire inside EDR-monitored code, an attacker VEH likely "
        "handles this to emulate the function (T1562.002)",
        code, addr);
    SendHookEvent("Critical", "VehHookFire", 0, det);

    // Pass through — any legitimate handler (including debuggers) still runs.
    return EXCEPTION_CONTINUE_SEARCH;
}

static void InstallFirstVeh() {
    if (g_firstVeh) return;
    g_firstVeh = AddVectoredExceptionHandler(1 /* FirstHandler */,
        FirstVectoredHandler);
}

// Check for amsi.dll loads that happened after our initial scan
static void RefreshAmsiGuards() {
    for (int i = 0; g_etwGuards[i].modName; i++) {
        if (g_etwGuards[i].valid) continue;
        HMODULE hMod = GetModuleHandleA(g_etwGuards[i].modName);
        if (!hMod) continue;
        BYTE* fn = (BYTE*)GetProcAddress(hMod, g_etwGuards[i].funcName);
        if (!fn) continue;
        g_etwGuards[i].addr = fn;
        __try {
            memcpy(g_etwGuards[i].baseline, fn, 64);
            g_etwGuards[i].valid = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ---------------------------------------------------------------------------
// Hardware breakpoint hooking detection (DR0-DR3 abuse)
//
// Attackers use SetThreadContext to set hardware breakpoints (DR0-DR3) on
// ETW/AMSI/ntdll functions, then register a VEH handler that intercepts the
// breakpoint exception, modifies registers/return values, and continues.
// This hooks functions WITHOUT modifying code bytes, bypassing prologue
// integrity checks.
//
// Detection: enumerate ALL threads in the current process via
// CreateToolhelp32Snapshot and check each thread's DR0-DR3 registers against
// security-critical module address ranges.  Previous versions only checked
// the current thread — attackers set breakpoints from a DIFFERENT thread to
// evade single-thread detection.
//
// Legitimate software almost never sets hardware breakpoints; only debuggers
// and offensive tools (TamperingSyscalls, HWSyscalls, AMSI-bypass-via-hwbp).
// ---------------------------------------------------------------------------

static void CheckHardwareBreakpointsOnThread(HANDLE hThread, DWORD tid,
    const char* critModNames[], ULONG_PTR critModBases[],
    ULONG_PTR critModEnds[], int numMods)
{
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return;

    // DR7 bit layout: bits 0,2,4,6 = local enable for DR0-DR3
    if ((ctx.Dr7 & 0x55) == 0) return;

    ULONG_PTR breakpoints[4] = { ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 };
    BYTE localEnable[4] = {
        (BYTE)(ctx.Dr7 & 1),
        (BYTE)((ctx.Dr7 >> 2) & 1),
        (BYTE)((ctx.Dr7 >> 4) & 1),
        (BYTE)((ctx.Dr7 >> 6) & 1),
    };

    for (int i = 0; i < 4; i++) {
        if (!localEnable[i] || breakpoints[i] == 0) continue;

        for (int m = 0; m < numMods; m++) {
            if (critModBases[m] == 0) continue;

            if (breakpoints[i] >= critModBases[m] &&
                breakpoints[i] < critModEnds[m]) {
                char det[300];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Hardware breakpoint hooking: DR%d=0x%llX on thread %lu "
                    "points into %s — VEH-based function hooking without "
                    "code modification (AMSI/ETW/syscall bypass via hwbp)",
                    i, (unsigned long long)breakpoints[i], tid,
                    critModNames[m]);
                SendHookEvent("Critical", "HardwareBreakpointHook", 0, det);

                // Clear the breakpoint to neutralize the hook
                switch (i) {
                    case 0: ctx.Dr0 = 0; break;
                    case 1: ctx.Dr1 = 0; break;
                    case 2: ctx.Dr2 = 0; break;
                    case 3: ctx.Dr3 = 0; break;
                }
                ctx.Dr7 &= ~(3ULL << (i * 2)); // clear local+global enable
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                SetThreadContext(hThread, &ctx);
                break;
            }
        }
    }
}

static void CheckHardwareBreakpoints()
{
    // Resolve critical module address ranges once per check cycle
    static const char* kCritModNames[] = {
        "ntdll.dll", "amsi.dll", "sspicli.dll", "kernelbase.dll",
        "advapi32.dll", "sechost.dll",
    };
    constexpr int kNumMods = _countof(kCritModNames);
    ULONG_PTR bases[kNumMods] = {};
    ULONG_PTR ends[kNumMods]  = {};

    for (int m = 0; m < kNumMods; m++) {
        HMODULE hMod = GetModuleHandleA(kCritModNames[m]);
        if (!hMod) continue;
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
            bases[m] = (ULONG_PTR)mi.lpBaseOfDll;
            ends[m]  = bases[m] + mi.SizeOfImage;
        }
    }

    // Enumerate ALL threads in the current process
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        // Fallback: check current thread only
        CheckHardwareBreakpointsOnThread(
            GetCurrentThread(), GetCurrentThreadId(),
            kCritModNames, bases, ends, kNumMods);
        return;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (!hThread) continue;

            // Must suspend thread to safely read debug registers
            // (skip our own thread — we can read it directly)
            bool isSelf = (te.th32ThreadID == GetCurrentThreadId());
            if (!isSelf) SuspendThread(hThread);

            CheckHardwareBreakpointsOnThread(
                hThread, te.th32ThreadID,
                kCritModNames, bases, ends, kNumMods);

            if (!isSelf) ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
// KUSER_SHARED_DATA.TracingFlags integrity check
//
// KUSER_SHARED_DATA is mapped read-only at 0x7FFE0000 in every user-mode
// process.  Offset 0x2D8 contains TracingFlags — a ULONG where bit 0
// (EtwpEventTracingProvEnabled) controls whether ANY user-mode ETW event
// emission occurs.  EtwEventWrite checks this flag before doing anything:
//
//   if (!(SharedUserData->TracingFlags & 1)) return STATUS_SUCCESS;
//
// An attacker with kernel write access (BYOVD, vulnerable driver) can zero
// this single bit to disable ALL user-mode ETW providers system-wide.  This
// bypasses every prologue integrity check because the function itself
// short-circuits before reaching any hooked code.
//
// Detection: baseline TracingFlags on first check, alert if zeroed.
// We also check bit 1 (EtwpContextSwapTracingEnabled) and bit 2 (EtwpSpare).
// ---------------------------------------------------------------------------

static void CheckTracingFlags()
{
    // KUSER_SHARED_DATA is always at 0x7FFE0000 in user-mode
    static constexpr ULONG_PTR kSharedUserDataBase = 0x7FFE0000;
    static constexpr ULONG     kTracingFlagsOffset = 0x2D8;

    static ULONG s_baseline      = 0;
    static bool  s_baselineTaken = false;

    __try {
        volatile ULONG* pFlags = reinterpret_cast<volatile ULONG*>(
            kSharedUserDataBase + kTracingFlagsOffset);
        ULONG current = *pFlags;

        if (!s_baselineTaken) {
            s_baseline      = current;
            s_baselineTaken = true;
            return;
        }

        // Bit 0: EtwpEventTracingProvEnabled — if cleared, ALL ETW is dead
        if ((s_baseline & 1) && !(current & 1)) {
            SendHookEvent("Critical", "TracingFlagsTamper", 0,
                "KUSER_SHARED_DATA.TracingFlags bit 0 (EtwpEventTracingProvEnabled) "
                "CLEARED — all user-mode ETW event emission is DISABLED system-wide. "
                "Attacker used kernel write to zero SharedUserData+0x2D8 (T1562.002)");
        }

        // Full value changed (bits 1-2 control context-switch tracing)
        if (current != s_baseline && (current & 1)) {
            char det[256];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "KUSER_SHARED_DATA.TracingFlags modified: 0x%08lX -> 0x%08lX "
                "— ETW tracing configuration altered (T1562.002)",
                s_baseline, current);
            SendHookEvent("Warning", "TracingFlagsTamper", 0, det);
        }

        // Update baseline only if bit 0 is still set (don't baseline a tampered state)
        if (current & 1) s_baseline = current;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ---------------------------------------------------------------------------
// ntdll!EtwpEventTracingProvEnabled global integrity check
//
// SEPARATE from KUSER_SHARED_DATA.TracingFlags — this is a DWORD in ntdll's
// .data section that EtwEventWrite checks FIRST before any other logic:
//
//   EtwEventWrite:
//     cmp dword ptr [ntdll!EtwpEventTracingProvEnabled], 0
//     je  early_return       ; ← if zero, skip ALL event emission
//
// An attacker can zero this single DWORD to disable all ETW emission from
// the process without patching any function prologue and without touching
// KUSER_SHARED_DATA.  Since it's a writable .data section variable, it
// only requires PAGE_READWRITE access (already the default for .data).
//
// Resolution strategy: scan the first ~0x40 bytes of ntdll!EtwEventWrite
// for a CMP/TEST instruction with a RIP-relative operand (the pattern that
// loads EtwpEventTracingProvEnabled).  Common patterns:
//   83 3D xx xx xx xx 00     CMP dword ptr [rip+disp32], 0
//   39 05 xx xx xx xx        CMP [rip+disp32], eax (where eax=0 from xor)
//   85 05 xx xx xx xx        TEST [rip+disp32], eax
//   8B 05 xx xx xx xx        MOV eax, [rip+disp32] (followed by test eax,eax)
// ---------------------------------------------------------------------------

static volatile ULONG* s_pEtwpProvEnabled  = nullptr;
static ULONG            s_etwpProvBaseline  = 0;
static bool             s_etwpProvResolved  = false;
static bool             s_etwpProvBaselined = false;

static void ResolveEtwpEventTracingProvEnabled()
{
    if (s_etwpProvResolved) return;
    s_etwpProvResolved = true;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    BYTE* pEtwEventWrite = (BYTE*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;

    // Get ntdll module bounds for validation
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi)))
        return;
    ULONG_PTR ntdllBase = (ULONG_PTR)mi.lpBaseOfDll;
    ULONG_PTR ntdllEnd  = ntdllBase + mi.SizeOfImage;

    __try {
        // Scan the first 0x60 bytes of EtwEventWrite for RIP-relative
        // memory operands that reference a .data section global.
        for (int i = 0; i < 0x60 - 6; i++) {
            ULONG_PTR candidate = 0;

            // Pattern 1: 83 3D xx xx xx xx 00 — CMP [rip+disp32], 0
            if (pEtwEventWrite[i] == 0x83 && pEtwEventWrite[i+1] == 0x3D &&
                pEtwEventWrite[i+6] == 0x00) {
                LONG disp = *(LONG*)(&pEtwEventWrite[i+2]);
                candidate = (ULONG_PTR)(&pEtwEventWrite[i+7]) + disp;
            }
            // Pattern 2: 8B 05 xx xx xx xx — MOV eax, [rip+disp32]
            // (typically followed by 85 C0 = TEST eax,eax or 3B C0)
            else if (pEtwEventWrite[i] == 0x8B && pEtwEventWrite[i+1] == 0x05) {
                LONG disp = *(LONG*)(&pEtwEventWrite[i+2]);
                candidate = (ULONG_PTR)(&pEtwEventWrite[i+6]) + disp;
            }
            // Pattern 3: 39 05 xx xx xx xx — CMP [rip+disp32], reg
            else if (pEtwEventWrite[i] == 0x39 && pEtwEventWrite[i+1] == 0x05) {
                LONG disp = *(LONG*)(&pEtwEventWrite[i+2]);
                candidate = (ULONG_PTR)(&pEtwEventWrite[i+6]) + disp;
            }
            // Pattern 4: 85 05 xx xx xx xx — TEST [rip+disp32], reg
            else if (pEtwEventWrite[i] == 0x85 && pEtwEventWrite[i+1] == 0x05) {
                LONG disp = *(LONG*)(&pEtwEventWrite[i+2]);
                candidate = (ULONG_PTR)(&pEtwEventWrite[i+6]) + disp;
            }
            // Pattern 5: 44 8B 05 xx xx xx xx — MOV r8d, [rip+disp32]
            // (some Windows builds use r8d instead of eax)
            else if (pEtwEventWrite[i] == 0x44 && pEtwEventWrite[i+1] == 0x8B &&
                     pEtwEventWrite[i+2] == 0x05) {
                LONG disp = *(LONG*)(&pEtwEventWrite[i+3]);
                candidate = (ULONG_PTR)(&pEtwEventWrite[i+7]) + disp;
            }

            if (candidate == 0) continue;

            // Validate: must be within ntdll's image
            if (candidate < ntdllBase || candidate >= ntdllEnd) continue;

            // Validate: must be readable and contain a plausible value
            // EtwpEventTracingProvEnabled should be nonzero (1) when ETW is active
            ULONG val = *(volatile ULONG*)candidate;
            if (val == 0 || val > 0xFF) continue;  // typically 1

            s_pEtwpProvEnabled = (volatile ULONG*)candidate;
            s_etwpProvBaseline = val;
            s_etwpProvBaselined = true;
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void CheckEtwpEventTracingProvEnabled()
{
    if (!s_etwpProvResolved) {
        ResolveEtwpEventTracingProvEnabled();
        return;  // first call — just resolve, check next cycle
    }

    if (!s_etwpProvBaselined || !s_pEtwpProvEnabled) return;

    __try {
        ULONG current = *s_pEtwpProvEnabled;

        if (s_etwpProvBaseline != 0 && current == 0) {
            char det[350];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "ntdll!EtwpEventTracingProvEnabled ZEROED at %p (was 0x%lX) — "
                "ALL EtwEventWrite calls in this process will short-circuit "
                "before reaching any ETW code. This is SEPARATE from "
                "KUSER_SHARED_DATA.TracingFlags — attacker patched ntdll "
                ".data section directly (T1562.002)",
                (void*)s_pEtwpProvEnabled, s_etwpProvBaseline);
            SendHookEvent("Critical", "EtwpProvEnabledZeroed", 0, det);

            // Restore the original value
            DWORD old = 0;
            if (g_vpOriginal &&
                g_vpOriginal((LPVOID)s_pEtwpProvEnabled, 4,
                    PAGE_READWRITE, &old)) {
                *s_pEtwpProvEnabled = s_etwpProvBaseline;
                g_vpOriginal((LPVOID)s_pEtwpProvEnabled, 4, old, &old);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ---------------------------------------------------------------------------
// EventSetInformation / TraceSetInformation interception
//
// These APIs modify provider/session properties from within the process:
//   EventSetInformation(REGHANDLE, EVENT_INFO_CLASS, data, dataSize)
//     - EventProviderSetTraits: alters provider metadata
//     - EventProviderUseDescriptorType: changes event encoding
//   TraceSetInformation(TRACEHANDLE, TRACE_INFO_CLASS, data, dataSize)
//     - TraceProviderBinaryTracking: changes provider binary path tracking
//     - TraceSetGlobalLoggerHandle: redirects system logger
//
// We monitor these by hooking the ntdll-level stubs.  Since they're rarely
// called by legitimate code, any call from non-system code is suspicious.
// ---------------------------------------------------------------------------

// EventSetInformation — ntdll export
typedef ULONG (WINAPI *FnEventSetInformation)(
    REGHANDLE RegHandle, ULONG EventInfoClass, PVOID EventInfo, ULONG InfoLength);
static FnEventSetInformation g_origEventSetInformation = nullptr;

static ULONG WINAPI Hook_EventSetInformation(
    REGHANDLE RegHandle, ULONG EventInfoClass, PVOID EventInfo, ULONG InfoLength)
{
    // EventInfoClass values:
    //   2 = EventProviderSetTraits        — alters provider identity
    //   3 = EventProviderUseDescriptorType — changes event format
    //   4 = EventProviderDecodeGuid       — redirect GUID decoding
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "EventSetInformation(class=%lu, len=%lu) — provider property modification "
        "from within process (T1562.002)",
        EventInfoClass, InfoLength);
    SendHookEvent("Warning", "EventSetInformation", 0, det);

    if (g_origEventSetInformation)
        return g_origEventSetInformation(RegHandle, EventInfoClass, EventInfo, InfoLength);
    return ERROR_INVALID_FUNCTION;
}

// TraceSetInformation — advapi32/sechost export
typedef ULONG (WINAPI *FnTraceSetInformation)(
    ULONG_PTR TraceHandle, ULONG TraceInfoClass, PVOID Info, ULONG InfoLength);
static FnTraceSetInformation g_origTraceSetInformation = nullptr;

static ULONG WINAPI Hook_TraceSetInformation(
    ULONG_PTR TraceHandle, ULONG TraceInfoClass, PVOID Info, ULONG InfoLength)
{
    // TraceInfoClass values of concern:
    //   6  = TraceProviderBinaryTracking  — alter provider binary association
    //   11 = TraceSystemTraceEnableFlagsInfo — modify system trace flags
    //   12 = TraceSampledProfileIntervalInfo — alter profiling
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "TraceSetInformation(class=%lu, handle=0x%llX, len=%lu) — "
        "session/provider config modification from within process (T1562.002)",
        TraceInfoClass, (unsigned long long)TraceHandle, InfoLength);
    SendHookEvent("Warning", "TraceSetInformation", 0, det);

    if (g_origTraceSetInformation)
        return g_origTraceSetInformation(TraceHandle, TraceInfoClass, Info, InfoLength);
    return ERROR_INVALID_FUNCTION;
}

// EventUnregister interception — detect unauthorized provider unregistration
// that silently kills ETW event flow without patching any function.
typedef ULONG (WINAPI *FnEventUnregister)(REGHANDLE RegHandle);
static FnEventUnregister g_origEventUnregister = nullptr;

static ULONG WINAPI Hook_EventUnregister(REGHANDLE RegHandle)
{
    // Any EventUnregister from non-system code is suspicious in an EDR-injected
    // process — legitimate code unregisters at shutdown, not mid-execution.
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "EventUnregister(REGHANDLE=0x%llX) — provider unregistration may disable "
        "ETW emission from this process without patching any code (T1562.002)",
        (unsigned long long)RegHandle);
    SendHookEvent("Warning", "EventUnregister", 0, det);

    if (g_origEventUnregister)
        return g_origEventUnregister(RegHandle);
    return ERROR_INVALID_FUNCTION;
}

// ---------------------------------------------------------------------------
// ETW-disabling environment variable detection
//
// The .NET CLR reads specific environment variables at startup to decide
// whether ETW providers are registered.  These are checked ONCE at CLR init
// and never re-checked — setting them before launching a .NET process
// permanently blinds all CLR ETW telemetry for that process.
//
// Attack pattern (Cobalt Strike, Sliver, execute-assembly wrappers):
//   set COMPlus_ETWEnabled=0   ← .NET Framework 4.x
//   set DOTNET_ETWEnabled=0    ← .NET 6+
//   dotnet_payload.exe
//
// Our CLR ETW session stays alive, but the provider inside the target process
// never emits — complete evasion of assembly/JIT/module load detection.
//
// Also checks for other telemetry-suppressing environment variables:
//   COMPlus_ETWFlags=0         — zeros the CLR ETW keyword mask
//   COMPlus_PerfMapEnabled=0   — disables perf-map generation
//   DOTNET_PerfMapEnabled=0    — .NET 6+ equivalent
//   COMPlus_EnableEventLog=0   — disables CLR event log writing
//   COMPlus_LegacyCorruptedState...=1 — suppresses CSE crash indicators
// ---------------------------------------------------------------------------

static void CheckEtwEnvironmentVariables()
{
    static const struct {
        const char* varName;
        const char* blindValue;  // value that disables telemetry (NULL = any non-empty)
        const char* description;
        const char* severity;    // "Critical" or "Warning"
    } kEtwEnvVars[] = {
        { "COMPlus_ETWEnabled",    "0",
          "CLR ETW providers DISABLED (.NET Framework) — all .NET assembly/JIT/module "
          "telemetry from this process is blind",
          "Critical" },
        { "DOTNET_ETWEnabled",     "0",
          "CLR ETW providers DISABLED (.NET 6+) — all .NET assembly/JIT/module "
          "telemetry from this process is blind",
          "Critical" },
        { "COMPlus_ETWFlags",      "0",
          "CLR ETW keyword mask ZEROED — CLR events filtered to nothing",
          "Critical" },
        { "COMPlus_PerfMapEnabled","0",
          "CLR PerfMap generation disabled — auxiliary .NET telemetry suppressed",
          "Warning" },
        { "DOTNET_PerfMapEnabled", "0",
          "CLR PerfMap generation disabled (.NET 6+) — auxiliary .NET telemetry suppressed",
          "Warning" },
        { "COMPlus_EnableEventLog","0",
          "CLR Event Log writing disabled — .NET runtime events not written to Windows Event Log",
          "Warning" },
        { "COMPlus_LegacyCorruptedStateExceptionsPolicy", "1",
          "Corrupted State Exceptions policy overridden — crash indicators suppressed",
          "Warning" },
        { "DOTNET_LegacyCorruptedStateExceptionsPolicy", "1",
          "Corrupted State Exceptions policy overridden (.NET 6+) — crash "
          "indicators suppressed", "Warning" },
        // OpenTelemetry / diagnostics suppression — modern .NET and OTel SDK
        // read these at startup; setting them pre-launch blinds tracing/logs.
        { "OTEL_SDK_DISABLED",     "true",
          "OpenTelemetry SDK disabled — all OTel spans/metrics/logs suppressed",
          "Warning" },
        { "OTEL_TRACES_EXPORTER",  "none",
          "OpenTelemetry trace export set to 'none' — tracing data dropped",
          "Warning" },
        { "OTEL_METRICS_EXPORTER", "none",
          "OpenTelemetry metrics export set to 'none' — metrics dropped",
          "Warning" },
        { "OTEL_LOGS_EXPORTER",    "none",
          "OpenTelemetry logs export set to 'none' — structured logs dropped",
          "Warning" },
        { "DOTNET_EnableDiagnostics", "0",
          "DiagnosticsServer disabled — EventPipe/ICorProfiler attach blocked, "
          "dotnet-trace/dotnet-counters blind (T1562.002)", "Critical" },
        { "DOTNET_EnableDiagnostics_Profiler", "0",
          "ICorProfiler diagnostics disabled — profiling/ETW-via-CLR blocked "
          "(T1562.002)", "Critical" },
        { "COREHOST_TRACE",        "0",
          "CoreCLR host trace disabled — runtime startup telemetry suppressed",
          "Warning" },
        { "DOTNET_CLI_TELEMETRY_OPTOUT", "1",
          "DOTNET CLI telemetry opted out — benign alone, noted as part of "
          "telemetry-suppression clusters", "Warning" },
        // AMSI environment variable bypass (rare but documented)
        { "COMPLUS_LEGACYCORRUPTEDSTATE", nullptr,
          nullptr, nullptr },  // sentinel
    };

    // Track which vars we've already alerted on to avoid spamming every 2s
    static DWORD s_alertedMask = 0;

    char valBuf[64] = {};
    for (int i = 0; kEtwEnvVars[i].description; i++) {
        DWORD len = GetEnvironmentVariableA(
            kEtwEnvVars[i].varName, valBuf, sizeof(valBuf));
        if (len == 0) continue;  // not set

        bool match = false;
        if (kEtwEnvVars[i].blindValue) {
            match = (strcmp(valBuf, kEtwEnvVars[i].blindValue) == 0);
        } else {
            match = (len > 0);  // any value
        }

        if (!match) continue;

        // Only alert once per variable per process lifetime
        if (s_alertedMask & (1u << i)) continue;
        s_alertedMask |= (1u << i);

        char det[400];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "ETW environment variable bypass: %s=%s — %s (T1562.002)",
            kEtwEnvVars[i].varName, valBuf, kEtwEnvVars[i].description);
        SendHookEvent(kEtwEnvVars[i].severity, "EtwEnvVarBypass", 0, det);
    }
}

static void CheckEtwRegistrations();

static DWORD WINAPI WatchThreadProc(LPVOID) {
    // WaitForSingleObject with 2000 ms timeout: fires VerifyHooks on each expiry,
    // exits cleanly when g_watchStop is signalled from RemoveHooks().
    while (WaitForSingleObject(g_watchStop, 2000) == WAIT_TIMEOUT) {
        VerifyHooks();
        RefreshAmsiGuards();
        VerifyCriticalFuncIntegrity();
        CheckHardwareBreakpoints();
        CheckTlsCallbacks();
        CheckTracingFlags();
        CheckEtwpEventTracingProvEnabled();
        CheckEtwEnvironmentVariables();
        CheckEtwRegistrations();
    }
    return 0;
}

static void InstallAllInlineHooks() {
    // Capture VirtualProtect before any inline/IAT patching.  Used by
    // VerifyHooks() to re-apply patches without triggering our own hook stub.
    g_vpOriginal = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");

    g_trampolinePool = (BYTE*)VirtualAlloc(
        nullptr, HOOK_COUNT * kTrampolineSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_trampolinePool) {
        // VirtualAlloc(PAGE_EXECUTE_READWRITE) failed in-process.
        // Most likely cause: ProcessDynamicCodePolicy (ProhibitDynamicCode) is active,
        // which the kernel enforces by rejecting RWX allocations.
        // IAT patches will still be applied but inline hooks cannot be installed —
        // coverage is significantly reduced (no GetProcAddress-path interception).
        SendHookEvent("Critical", "DynamicCodePolicy", 0,
            "VirtualAlloc(RWX) failed — ProcessDynamicCodePolicy likely active; "
            "trampoline pool not created, inline hooks will NOT be installed");
        return;
    }

    for (int i = 0; i < HOOK_COUNT; i++)
        InstallInlineHook(g_hooks[i], g_trampolinePool + i * kTrampolineSize);

    // Harden: flip pool RWX → RX.  Any future in-process write to a trampoline
    // now requires VirtualProtect (which we hook), making the attempt visible.
    DWORD old = 0;
    VirtualProtect(g_trampolinePool, (SIZE_T)(HOOK_COUNT * kTrampolineSize),
                   PAGE_EXECUTE_READ, &old);
}

static void RemoveAllInlineHooks() {
    for (int i = 0; i < HOOK_COUNT; i++)
        RemoveInlineHook(g_hooks[i]);

    if (g_trampolinePool) {
        VirtualFree(g_trampolinePool, 0, MEM_RELEASE);
        g_trampolinePool = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Hook stubs
// All stubs call GetCallThrough(idx) for call-through, which is correct
// regardless of which hook types are active.
// ---------------------------------------------------------------------------

static LPVOID WINAPI Hook_VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    typedef LPVOID(WINAPI* Fn)(LPVOID, SIZE_T, DWORD, DWORD);
    if (flProtect == PAGE_EXECUTE_READWRITE || flProtect == PAGE_EXECUTE_WRITECOPY) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "RWX alloc: size=0x%llX prot=0x%lX", (ULONG64)dwSize, flProtect);
        SendHookEvent("Warning", "VirtualAlloc", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_VIRTUALALLOC))(
        lpAddress, dwSize, flAllocationType, flProtect);
}

static LPVOID WINAPI Hook_VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect)
{
    typedef LPVOID(WINAPI* Fn)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        const char* sev = (flProtect == PAGE_EXECUTE_READWRITE ||
                           flProtect == PAGE_EXECUTE_WRITECOPY)
                          ? "Critical" : "High";
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote alloc: targetPid=%lu size=0x%llX prot=0x%lX",
            targetPid, (ULONG64)dwSize, flProtect);
        SendHookEvent(sev, "VirtualAllocEx", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_VIRTUALALLOCEX))(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

// ---------------------------------------------------------------------------
// Checks whether [lpBaseAddress, lpBaseAddress+nSize) overlaps with the
// target process's PEB->ProcessParameters->CommandLine buffer.
//
// Used to detect argument-spoofing: attacker spawns child with CREATE_SUSPENDED
// + benign-looking args, then overwrites the PEB CommandLine before resume so
// the child runs with different args than what NtCreateUserProcess recorded.
// Also catches self-modification (process hiding its own launch args from
// scanners that read user-mode PEB).
//
// Offsets are 64-bit Windows layout:
//   PEB+0x20          → ProcessParameters pointer
//   ProcessParameters+0x72 → CommandLine.MaximumLength (USHORT)
//   ProcessParameters+0x78 → CommandLine.Buffer (PWSTR)
// ---------------------------------------------------------------------------
static BOOL IsWriteTargetingCmdLine(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T nSize)
{
    typedef NTSTATUS (NTAPI *NtQIP_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static NtQIP_t fnNtQIP = nullptr;
    if (!fnNtQIP)
        fnNtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                           "NtQueryInformationProcess");
    if (!fnNtQIP) return FALSE;

    PROCESS_BASIC_INFORMATION pbi = {};
    if (!NT_SUCCESS(fnNtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)))
        return FALSE;

    BYTE* pebBase = (BYTE*)pbi.PebBaseAddress;
    if (!pebBase) return FALSE;

    // Read PEB->ProcessParameters pointer (offset 0x20 in 64-bit PEB)
    ULONG_PTR pParamsAddr = 0;
    if (!ReadProcessMemory(hProcess, pebBase + 0x20, &pParamsAddr, sizeof(pParamsAddr), nullptr) || !pParamsAddr)
        return FALSE;

    // Read CommandLine.MaximumLength (offset 0x72) and .Buffer (offset 0x78)
    USHORT   cmdMaxLen  = 0;
    ULONG_PTR cmdBufPtr = 0;
    if (!ReadProcessMemory(hProcess, (BYTE*)pParamsAddr + 0x72, &cmdMaxLen,  sizeof(cmdMaxLen),  nullptr) || !cmdMaxLen)
        return FALSE;
    if (!ReadProcessMemory(hProcess, (BYTE*)pParamsAddr + 0x78, &cmdBufPtr,  sizeof(cmdBufPtr),  nullptr) || !cmdBufPtr)
        return FALSE;

    BYTE* writeStart = (BYTE*)lpBaseAddress;
    BYTE* writeEnd   = writeStart + nSize;
    BYTE* cmdStart   = (BYTE*)cmdBufPtr;
    BYTE* cmdEnd     = cmdStart + cmdMaxLen;
    return (writeStart < cmdEnd && writeEnd > cmdStart) ? TRUE : FALSE;
}

static BOOL WINAPI Hook_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,
    SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    DWORD targetPid    = GetProcessId(hProcess);
    DWORD effectivePid = targetPid ? targetPid : g_selfPid;  // pseudo-handle (-1) → self

    if (targetPid && targetPid != g_selfPid) {
        // Cross-process write — always suspicious
        const char* tag = "";
        if (nSize >= 2 && lpBuffer) {
            __try { if (*(const WORD*)lpBuffer == 0x5A4D) tag = " [MZ]"; }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote write: targetPid=%lu dst=%p size=0x%llX%s",
            targetPid, lpBaseAddress, (ULONG64)nSize, tag);
        SendHookEvent("Critical", "WriteProcessMemory", targetPid, det);
    }

    // Argument spoofing / self-hiding: does this write land on the target's
    // PEB CommandLine buffer?  Fires for both cross-process and self-writes.
    if (nSize > 0 && IsWriteTargetingCmdLine(hProcess, lpBaseAddress, nSize)) {
        char spoof[192];
        _snprintf_s(spoof, sizeof(spoof), _TRUNCATE,
            "%s: write targets PEB CommandLine of pid=%lu dst=%p size=0x%llX",
            (effectivePid == g_selfPid)
                ? "PEB CommandLine self-modification (scanner evasion)"
                : "Argument spoofing: cross-process PEB CommandLine overwrite",
            effectivePid, lpBaseAddress, (ULONG64)nSize);
        SendHookEvent("Critical", "WriteProcessMemory", effectivePid, spoof);
    }

    return ((Fn)GetCallThrough(IDX_WRITEPROCESSMEMORY))(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

static HANDLE WINAPI Hook_CreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote thread: targetPid=%lu startAddr=%p", targetPid, lpStartAddress);
        SendHookEvent("Critical", "CreateRemoteThread", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEREMOTETHREAD))(
        hProcess, lpSA, dwStackSize, lpStartAddress, lpParam, dwCreationFlags, lpThreadId);
}

static HANDLE WINAPI Hook_CreateRemoteThreadEx(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttrList, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
    DWORD targetPid = GetProcessId(hProcess);
    if (targetPid && targetPid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "remote thread ex: targetPid=%lu startAddr=%p", targetPid, lpStartAddress);
        SendHookEvent("Critical", "CreateRemoteThreadEx", targetPid, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEREMOTETHREADEX))(
        hProcess, lpSA, dwStackSize, lpStartAddress, lpParam,
        dwCreationFlags, lpAttrList, lpThreadId);
}

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName) {
    typedef HMODULE(WINAPI* Fn)(LPCSTR);
    if (lpLibFileName) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE, "path=%s", lpLibFileName);
        SendHookEvent("Info", "LoadLibraryA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYA))(lpLibFileName);
}

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName) {
    typedef HMODULE(WINAPI* Fn)(LPCWSTR);
    if (lpLibFileName) {
        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, lpLibFileName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE, "path=%s", narrow);
        SendHookEvent("Info", "LoadLibraryW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYW))(lpLibFileName);
}

static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    typedef HMODULE(WINAPI* Fn)(LPCSTR, HANDLE, DWORD);
    if (lpLibFileName && dwFlags == 0) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "path=%s flags=0x%lX", lpLibFileName, dwFlags);
        SendHookEvent("Info", "LoadLibraryExA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYEXA))(lpLibFileName, hFile, dwFlags);
}

static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    typedef HMODULE(WINAPI* Fn)(LPCWSTR, HANDLE, DWORD);
    if (lpLibFileName && dwFlags == 0) {
        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, lpLibFileName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "path=%s flags=0x%lX", narrow, dwFlags);
        SendHookEvent("Info", "LoadLibraryExW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_LOADLIBRARYEXW))(lpLibFileName, hFile, dwFlags);
}

static DWORD WINAPI Hook_ResumeThread(HANDLE hThread) {
    typedef DWORD(WINAPI* Fn)(HANDLE);
    DWORD tid = GetThreadId(hThread);
    DWORD pid = tid ? GetProcessIdOfThread(hThread) : 0;
    if (pid && pid != g_selfPid) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "cross-process resume: targetPid=%lu tid=%lu", pid, tid);
        SendHookEvent("High", "ResumeThread", pid, det);
    }
    return ((Fn)GetCallThrough(IDX_RESUMETHREAD))(hThread);
}

static BOOL WINAPI Hook_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    typedef BOOL(WINAPI* Fn)(HANDLE, const CONTEXT*);
    DWORD tid = GetThreadId(hThread);
    DWORD pid = tid ? GetProcessIdOfThread(hThread) : 0;

    if (pid && pid != g_selfPid) {
        // Cross-process context manipulation: RIP redirect or inject via debug regs
        DWORD64 rip = 0;
        if (lpContext && (lpContext->ContextFlags & CONTEXT_CONTROL))
            rip = lpContext->Rip;
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "cross-process SetThreadContext: targetPid=%lu tid=%lu RIP=0x%llX",
            pid, tid, rip);
        SendHookEvent("Critical", "SetThreadContext", pid, det);
    }

    // VEH hardware breakpoint bypass: same-process thread arming DR0-DR3.
    // An attacker sets a hardware breakpoint on the inline-hook JMP target so
    // a EXCEPTION_SINGLE_STEP/EXCEPTION_BREAKPOINT fires BEFORE the hook runs,
    // then redirects RIP from inside the VEH — bypassing our inline hook entirely.
    // Detect any same-process call that sets at least one DR with CONTEXT_DEBUG_REGISTERS.
    if (lpContext && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        if (lpContext->Dr0 || lpContext->Dr1 || lpContext->Dr2 || lpContext->Dr3) {
            char det[200];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "SetThreadContext(CONTEXT_DEBUG_REGISTERS) tid=%lu "
                "Dr0=0x%llX Dr1=0x%llX Dr2=0x%llX Dr3=0x%llX — "
                "hardware BP may be used to bypass inline hooks via VEH",
                tid,
                (unsigned long long)lpContext->Dr0,
                (unsigned long long)lpContext->Dr1,
                (unsigned long long)lpContext->Dr2,
                (unsigned long long)lpContext->Dr3);
            SendHookEvent("High", "SetThreadContext", pid ? pid : g_selfPid, det);
        }
    }

    return ((Fn)GetCallThrough(IDX_SETTHREADCONTEXT))(hThread, lpContext);
}

static bool IsPersistenceValue(const char* name) {
    if (!name) return false;
    static const char* kSuspect[] = {
        "Run", "RunOnce", "Load", "Shell", "Userinit",
        "AppInit_DLLs", "BootExecute", nullptr
    };
    for (int i = 0; kSuspect[i]; i++)
        if (_stricmp(name, kSuspect[i]) == 0) return true;
    return false;
}

static LONG WINAPI Hook_RegSetValueExA(
    HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    typedef LONG(WINAPI* Fn)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    const char* sev = IsPersistenceValue(lpValueName) ? "High" : "Info";
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "value=%s type=%lu size=%lu",
        lpValueName ? lpValueName : "(default)", dwType, cbData);
    SendHookEvent(sev, "RegSetValueExA", 0, det);
    return ((Fn)GetCallThrough(IDX_REGSETVALUEEX_A))(
        hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

static LONG WINAPI Hook_RegSetValueExW(
    HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    typedef LONG(WINAPI* Fn)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    char narrow[128] = {};
    if (lpValueName)
        WideCharToMultiByte(CP_UTF8, 0, lpValueName, -1,
                            narrow, sizeof(narrow) - 1, nullptr, nullptr);
    const char* sev = IsPersistenceValue(narrow) ? "High" : "Info";
    char det[256];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "value=%s type=%lu size=%lu",
        narrow[0] ? narrow : "(default)", dwType, cbData);
    SendHookEvent(sev, "RegSetValueExW", 0, det);
    return ((Fn)GetCallThrough(IDX_REGSETVALUEEX_W))(
        hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// ---------------------------------------------------------------------------
// Deception helpers
// ---------------------------------------------------------------------------

// Canary NTLM hash (MD4 of empty string) — universally flagged by SIEMs and
// domain controllers if used in pass-the-hash or Kerberos attacks.
static const BYTE kCanaryNtlmHash[16] = {
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
};

// EDR process names to conceal from NtQuerySystemInformation output.
// The attacker sees an unprotected host — no defenders visible.
static const char* kEdrProcessNames[] = {
    "NortonEDR.exe", "nortonav.exe", "MsMpEng.exe",
    "SentinelAgent.exe", "CSFalconService.exe", nullptr
};

// Name of the injected decoy process — appears as an attractive SYSTEM process
// with no parent, ready for injection (a honeypot for injection attempts).
static const char kDecoyProcessName[] = "svchost_config.exe";

static bool IsLsassHandle(HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    if (!pid) return false;
    // Open a query-only handle to get the image name
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    char name[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    // Use QueryFullProcessImageNameA for reliability
    typedef BOOL(WINAPI* QFn)(HANDLE, DWORD, LPSTR, PDWORD);
    static QFn qfn = (QFn)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                          "QueryFullProcessImageNameA");
    bool result = false;
    if (qfn && qfn(h, 0, name, &sz)) {
        // Match basename "lsass.exe" case-insensitively
        const char* base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        result = (_stricmp(base, "lsass.exe") == 0);
    }
    CloseHandle(h);
    return result;
}

// Scan buffer for 16-byte windows that look like NTLM hashes and replace them.
// Heuristic: >= 8 non-zero bytes AND >= 5 bytes in 0x80-0xFF range AND max
// run of identical bytes <= 4.
static void PatchNtlmHashesInBuffer(LPVOID buffer, SIZE_T size) {
    if (!buffer || size < 16) return;
    BYTE* buf = (BYTE*)buffer;
    DWORD patched = 0;
    for (SIZE_T off = 0; off + 16 <= size; off += 8) {
        BYTE* w = buf + off;
        int nonZero = 0, highByte = 0, maxRun = 0, run = 1;
        for (int i = 0; i < 16; i++) {
            if (w[i]) nonZero++;
            if (w[i] >= 0x80) highByte++;
            if (i > 0) {
                if (w[i] == w[i-1]) run++; else run = 1;
                if (run > maxRun) maxRun = run;
            }
        }
        if (nonZero >= 8 && highByte >= 5 && maxRun <= 4) {
            memcpy(w, kCanaryNtlmHash, 16);
            patched++;
            off += 8; // skip to avoid partial overlap
        }
    }
    if (patched) {
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "Replaced %lu NTLM hash candidate(s) with canary in LSASS read buffer", patched);
        SendHookEvent("Critical", "ReadProcessMemory[Deception]", 0, msg);
    }
}

// ---------------------------------------------------------------------------
// Hook_ReadProcessMemory — post-read LSASS buffer deception
// ---------------------------------------------------------------------------
static BOOL WINAPI Hook_ReadProcessMemory(
    HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    Fn real = (Fn)GetCallThrough(IDX_READPROCESSMEMORY);

    // Execute the real read first
    BOOL result = real(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    if (!result || !lpBuffer || nSize < 16) return result;

    DWORD targetPid = GetProcessId(hProcess);
    if (!IsLsassHandle(hProcess)) return result;

    // Target is LSASS — log the attempt
    char det[128];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "LSASS read: base=0x%p size=%zu — applying credential deception",
        lpBaseAddress, nSize);
    SendHookEvent("Critical", "ReadProcessMemory", targetPid, det);

    // Corrupt NTLM hash candidates in the output buffer
    SIZE_T bytesRead = lpNumberOfBytesRead ? *lpNumberOfBytesRead : nSize;
    PatchNtlmHashesInBuffer(lpBuffer, bytesRead);

    return result;
}

// ---------------------------------------------------------------------------
// Hook_NtQuerySystemInformation — process list deception
//
// SystemProcessInformation (class 5): patch the linked list of
// SYSTEM_PROCESS_INFORMATION entries to:
//   a) Remove entries whose ImageName matches a known EDR process name.
//      The attacker sees no active defenders.
//   b) Inject a single decoy SYSTEM_PROCESS_INFORMATION entry that looks
//      like a lightly protected svchost variant — a honeypot for injection.
// ---------------------------------------------------------------------------

// Minimal SYSTEM_PROCESS_INFORMATION layout (matches Windows internals)
struct SPI_ENTRY {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE  Reserved1[48];
    UNICODE_STRING ImageName;
    LONG  BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    // ... more fields follow but we only need offsets above
};

static bool IsEdrProcess(const wchar_t* name, int nameLen) {
    if (!name || nameLen <= 0) return false;
    char narrow[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, name, nameLen,
                        narrow, sizeof(narrow)-1, nullptr, nullptr);
    for (int i = 0; kEdrProcessNames[i]; i++)
        if (_stricmp(narrow, kEdrProcessNames[i]) == 0) return true;
    return false;
}

static BOOL WINAPI Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    typedef BOOL(WINAPI* Fn)(ULONG, PVOID, ULONG, PULONG);
    Fn real = (Fn)GetCallThrough(IDX_NTQUERYSYSTEMINFO);

    BOOL result = real(SystemInformationClass, SystemInformation,
                       SystemInformationLength, ReturnLength);

    // Only patch SystemProcessInformation (class 5)
    if (!result || SystemInformationClass != 5 ||
        !SystemInformation || !SystemInformationLength) return result;

    // Walk the linked list and unlink any EDR process entries
    BYTE* base  = (BYTE*)SystemInformation;
    SPI_ENTRY* prev = nullptr;
    SPI_ENTRY* cur  = (SPI_ENTRY*)base;
    DWORD removedCount = 0;

    while (true) {
        // Validate entry is within buffer bounds
        if ((BYTE*)cur < base ||
            (BYTE*)cur + sizeof(SPI_ENTRY) > base + SystemInformationLength) break;

        bool remove = false;
        if (cur->ImageName.Buffer && cur->ImageName.Length > 0) {
            remove = IsEdrProcess(cur->ImageName.Buffer,
                                  cur->ImageName.Length / sizeof(wchar_t));
        }

        if (remove) {
            removedCount++;
            if (prev) {
                // Unlink: previous entry skips directly to our successor
                if (cur->NextEntryOffset == 0)
                    prev->NextEntryOffset = 0;  // we were last
                else
                    prev->NextEntryOffset += cur->NextEntryOffset;
            } else if (cur->NextEntryOffset != 0) {
                // We're the first entry — slide the buffer start
                MoveMemory(base, base + cur->NextEntryOffset,
                           SystemInformationLength - cur->NextEntryOffset);
                cur = (SPI_ENTRY*)base;
                continue;
            }
        }

        prev = remove ? prev : cur;
        if (cur->NextEntryOffset == 0) break;
        cur = (SPI_ENTRY*)((BYTE*)cur + cur->NextEntryOffset);
    }

    if (removedCount) {
        char msg[64];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "Removed %lu EDR process(es) from SystemProcessInformation", removedCount);
        SendHookEvent("Info", "NtQuerySystemInformation[Deception]", 0, msg);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Category 1 stubs — injection precursors and missing execution paths
// ---------------------------------------------------------------------------

// OpenProcess: log every cross-process handle acquisition with its desired access.
// This is the universal precursor to every injection technique and credential dump.
static HANDLE WINAPI Hook_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    typedef HANDLE(WINAPI* Fn)(DWORD, BOOL, DWORD);
    if (dwProcessId != g_selfPid) {
        const char* sev = (dwDesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_READ |
                           PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) ? "High" : "Info";
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "targetPid=%lu access=0x%lX", dwProcessId, dwDesiredAccess);
        SendHookEvent(sev, "OpenProcess", dwProcessId, det);
    }
    return ((Fn)GetCallThrough(IDX_OPENPROCESS))(dwDesiredAccess, bInheritHandle, dwProcessId);
}

// VirtualProtect: alert when marking a region PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY.
// Catches in-process shellcode staging that doesn't go through VirtualAlloc.
static BOOL WINAPI Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    typedef BOOL(WINAPI* Fn)(LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL inModule = lpAddress ? IsAddressInKnownModule(lpAddress) : FALSE;

    if (flNewProtect == PAGE_EXECUTE_READWRITE || flNewProtect == PAGE_EXECUTE_WRITECOPY) {
        char det[160];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "addr=%p size=0x%llX prot=0x%lX inModule=%d",
            lpAddress, (ULONG64)dwSize, flNewProtect, (int)inModule);
        // RWX outside a module = shellcode staging (Critical); inside = trampoline noise (Info)
        SendHookEvent(inModule ? "Info" : "Critical", "VirtualProtect", 0, det);
    } else if ((flNewProtect == PAGE_READWRITE || flNewProtect == PAGE_WRITECOPY) && inModule) {
        // Write-only on a loaded module's code section — ntdll/DLL stomp pattern.
        // PAGE_READWRITE is the protection malware uses before memcpy'ing clean ntdll bytes
        // over our inline hooks; it doesn't trigger the RWX check above so needs its own path.
        char det[200];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "addr=%p size=0x%llX prot=0x%lX — write permission on loaded module "
            "(ntdll/DLL stomp pattern)",
            lpAddress, (ULONG64)dwSize, flNewProtect);
        SendHookEvent("Critical", "VirtualProtect", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_VIRTUALPROTECT))(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// CreateFileMapping: flag executable sections (SEC_IMAGE or PAGE_EXECUTE_*)
static HANDLE WINAPI Hook_CreateFileMappingW(
    HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttr, DWORD flProtect,
    DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCWSTR lpName)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    DWORD prot = flProtect & 0xFF; // low byte is page protection
    if (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
        prot == PAGE_EXECUTE_WRITECOPY || (flProtect & SEC_IMAGE)) {
        char name[64] = {};
        if (lpName) WideCharToMultiByte(CP_UTF8, 0, lpName, -1, name, sizeof(name)-1, nullptr, nullptr);
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable section: prot=0x%lX name=%s", flProtect, name[0] ? name : "(anon)");
        SendHookEvent("High", "CreateFileMappingW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFILEMAPPINGW))(
        hFile, lpAttr, flProtect, dwMaxSizeHigh, dwMaxSizeLow, lpName);
}

static HANDLE WINAPI Hook_CreateFileMappingA(
    HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttr, DWORD flProtect,
    DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow, LPCSTR lpName)
{
    typedef HANDLE(WINAPI* Fn)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    DWORD prot = flProtect & 0xFF;
    if (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
        prot == PAGE_EXECUTE_WRITECOPY || (flProtect & SEC_IMAGE)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable section: prot=0x%lX name=%s", flProtect, lpName ? lpName : "(anon)");
        SendHookEvent("High", "CreateFileMappingA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFILEMAPPINGA))(
        hFile, lpAttr, flProtect, dwMaxSizeHigh, dwMaxSizeLow, lpName);
}

// EnumSystemLocalesW — W variant of the callback-abuse technique
static BOOL WINAPI Hook_EnumSystemLocalesW(LOCALE_ENUMPROCW lpLocaleEnumProc, DWORD dwFlags) {
    typedef BOOL(WINAPI* Fn)(LOCALE_ENUMPROCW, DWORD);
    if (lpLocaleEnumProc && !IsAddressInKnownModule((const void*)lpLocaleEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpLocaleEnumProc);
        SendHookEvent("Critical", "EnumSystemLocalesW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSTEMLOCALESW))(lpLocaleEnumProc, dwFlags);
}

// CallWindowProc: used to dispatch shellcode through an existing window procedure slot
static LRESULT WINAPI Hook_CallWindowProcA(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wP, LPARAM lP) {
    typedef LRESULT(WINAPI* Fn)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
    if (lpPrevWndFunc && !IsAddressInKnownModule((const void*)lpPrevWndFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module", (void*)lpPrevWndFunc);
        SendHookEvent("Critical", "CallWindowProcA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CALLWINDOWPROCA))(lpPrevWndFunc, hWnd, Msg, wP, lP);
}

static LRESULT WINAPI Hook_CallWindowProcW(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wP, LPARAM lP) {
    typedef LRESULT(WINAPI* Fn)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
    if (lpPrevWndFunc && !IsAddressInKnownModule((const void*)lpPrevWndFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module", (void*)lpPrevWndFunc);
        SendHookEvent("Critical", "CallWindowProcW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CALLWINDOWPROCW))(lpPrevWndFunc, hWnd, Msg, wP, lP);
}

static BOOL WINAPI Hook_EnumThreadWindows(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(DWORD, WNDENUMPROC, LPARAM);
    if (lpfn && !IsAddressInKnownModule((const void*)lpfn)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpfn);
        SendHookEvent("Critical", "EnumThreadWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMTHREADWINDOWS))(dwThreadId, lpfn, lParam);
}

// Fiber-based shellcode: ConvertThreadToFiber + CreateFiber + SwitchToFiber
// The detection point is SwitchToFiber with a non-module address — that's when
// execution is transferred. ConvertThreadToFiber and CreateFiber are logged for
// context but not blocked (they're legitimately used by runtimes like .NET).
static LPVOID WINAPI Hook_ConvertThreadToFiber(LPVOID lpParameter) {
    typedef LPVOID(WINAPI* Fn)(LPVOID);
    SendHookEvent("Info", "ConvertThreadToFiber", 0, "thread converted to fiber");
    return ((Fn)GetCallThrough(IDX_CONVERTTHREADTOFIBER))(lpParameter);
}

static LPVOID WINAPI Hook_CreateFiber(
    SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    typedef LPVOID(WINAPI* Fn)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
    if (lpStartAddress && !IsAddressInKnownModule((const void*)lpStartAddress)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "fiberStart=%p NOT in any loaded module", (void*)lpStartAddress);
        SendHookEvent("Critical", "CreateFiber", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATEFIBER))(dwStackSize, lpStartAddress, lpParameter);
}

static VOID WINAPI Hook_SwitchToFiber(LPVOID lpFiber) {
    typedef VOID(WINAPI* Fn)(LPVOID);
    if (lpFiber && !IsAddressInKnownModule(lpFiber)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "fiberAddr=%p NOT in any loaded module — shellcode fiber execution", lpFiber);
        SendHookEvent("Critical", "SwitchToFiber", 0, det);
    }
    ((Fn)GetCallThrough(IDX_SWITCHTOFIBER))(lpFiber);
}

// RtlCreateUserThread: direct ntdll thread creation, bypasses CreateThread hook.
// Used by Metasploit, Cobalt Strike, and Mimikatz for remote thread injection.
typedef NTSTATUS (NTAPI* RtlCreateUserThread_t)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);

static NTSTATUS NTAPI Hook_RtlCreateUserThread(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended, ULONG StackZeroBits,
    SIZE_T StackReserve, SIZE_T StackCommit,
    PVOID StartAddress, PVOID Parameter,
    PHANDLE ThreadHandle, PVOID ClientId)
{
    DWORD targetPid = GetProcessId(ProcessHandle);
    const char* sev = (targetPid && targetPid != g_selfPid) ? "Critical" : "High";
    char det[128];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "targetPid=%lu startAddr=%p inModule=%d",
        targetPid, StartAddress, (int)IsAddressInKnownModule(StartAddress));
    SendHookEvent(sev, "RtlCreateUserThread", targetPid, det);
    return ((RtlCreateUserThread_t)GetCallThrough(IDX_RTLCREATEUSERTHREAD))(
        ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits,
        StackReserve, StackCommit, StartAddress, Parameter, ThreadHandle, ClientId);
}

// CreateWaitableTimerExW — timer variant with APC callback (missed in first pass)
static HANDLE WINAPI Hook_CreateWaitableTimerExW(
    LPSECURITY_ATTRIBUTES lpAttr, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)
{
    typedef HANDLE(WINAPI* Fn)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
    // Log creation; execution trigger is caught by SetWaitableTimer hook
    SendHookEvent("Info", "CreateWaitableTimerExW", 0, "waitable timer created");
    return ((Fn)GetCallThrough(IDX_CREATEWAITABLETIMEREXW))(lpAttr, lpName, dwFlags, dwDesiredAccess);
}

// SetWindowLongPtr(GWLP_WNDPROC): post-creation WndProc replacement.
// This is Path B of the window-message shellcode technique — the attacker
// creates a legitimate window then replaces its WndProc with a shellcode
// address, bypassing our RegisterClassEx hook entirely.
#ifndef GWLP_WNDPROC
#define GWLP_WNDPROC (-4)
#endif

static LONG_PTR WINAPI Hook_SetWindowLongPtrA(HWND hWnd, int nIndex, LONG_PTR dwNewLong) {
    typedef LONG_PTR(WINAPI* Fn)(HWND, int, LONG_PTR);
    if (nIndex == GWLP_WNDPROC && dwNewLong &&
        !IsAddressInKnownModule((const void*)dwNewLong)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "GWLP_WNDPROC replaced with addr=%p NOT in any loaded module "
            "(window-message shellcode dispatch, Path B)",
            (void*)dwNewLong);
        SendHookEvent("Critical", "SetWindowLongPtrA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWINDOWLONGPTRA))(hWnd, nIndex, dwNewLong);
}

static LONG_PTR WINAPI Hook_SetWindowLongPtrW(HWND hWnd, int nIndex, LONG_PTR dwNewLong) {
    typedef LONG_PTR(WINAPI* Fn)(HWND, int, LONG_PTR);
    if (nIndex == GWLP_WNDPROC && dwNewLong &&
        !IsAddressInKnownModule((const void*)dwNewLong)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "GWLP_WNDPROC replaced with addr=%p NOT in any loaded module "
            "(window-message shellcode dispatch, Path B)",
            (void*)dwNewLong);
        SendHookEvent("Critical", "SetWindowLongPtrW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWINDOWLONGPTRW))(hWnd, nIndex, dwNewLong);
}

// CertFindCertificateInStore / CertEnumCertificatesInStore:
// Both accept a pfnFindCallback function pointer (optional, may be NULL).
// When non-NULL and pointing outside loaded modules, this is the CRYPT32
// callback abuse technique — shellcode passed as a certificate enumeration
// callback (score 94, mal 24-27 in differential, zero clean use).
// Note: CertEnumCertificatesInStore has no explicit callback argument —
// we hook it purely as a telemetry signal since it appears in the Mimikatz
// certificate-store enumeration path alongside cryptdll.dll.
static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertFindCertificateInStore(
    HCERTSTORE_OPAQUE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags,
    DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT_OPAQUE pPrevCertContext)
{
    typedef PCCERT_CONTEXT_OPAQUE(WINAPI* Fn)(HCERTSTORE_OPAQUE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT_OPAQUE);
    // dwFindType == 6 (CERT_FIND_SUBJECT_FUNC) or 8 (CERT_FIND_ISSUER_FUNC)
    // means pvFindPara is a function pointer — the callback abuse path.
    if (pvFindPara &&
        (dwFindType == 6 || dwFindType == 8) &&
        !IsAddressInKnownModule(pvFindPara)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module findType=%lu (CRYPT32 callback abuse)",
            pvFindPara, dwFindType);
        SendHookEvent("Critical", "CertFindCertificateInStore", 0, det);
    } else {
        SendHookEvent("Info", "CertFindCertificateInStore", 0, "certificate store access");
    }
    return ((Fn)GetCallThrough(IDX_CERTFINDCERTIFICATE))(
        hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext);
}

static PCCERT_CONTEXT_OPAQUE WINAPI Hook_CertEnumCertificatesInStore(
    HCERTSTORE_OPAQUE hCertStore, PCCERT_CONTEXT_OPAQUE pPrevCertContext)
{
    typedef PCCERT_CONTEXT_OPAQUE(WINAPI* Fn)(HCERTSTORE_OPAQUE, PCCERT_CONTEXT_OPAQUE);
    if (pPrevCertContext == nullptr)
        SendHookEvent("Info", "CertEnumCertificatesInStore", 0, "certificate store enumeration start");
    return ((Fn)GetCallThrough(IDX_CERTENUMCERTIFICATES))(hCertStore, pPrevCertContext);
}

// ---------------------------------------------------------------------------
// IsAddressInKnownModule
//
// Returns true if `addr` falls within the virtual address range of any module
// loaded in the current process. Used by all execution-trigger hooks to detect
// shellcode function pointers that live in heap or anonymous mapped memory.
// ---------------------------------------------------------------------------

static bool IsAddressInKnownModule(const void* addr) {
    if (!addr) return true; // NULL is not shellcode
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return true; // can't tell — don't false-positive
    DWORD n = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < n; i++) {
        if (!mods[i]) continue;
        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        const BYTE* base = (const BYTE*)mi.lpBaseOfDll;
        if ((const BYTE*)addr >= base && (const BYTE*)addr < base + mi.SizeOfImage)
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Evasion-path execution trigger stubs
// ---------------------------------------------------------------------------

// Technique 3: local CreateThread with shellcode start address (heap staging)
static HANDLE WINAPI Hook_CreateThread(
    LPSECURITY_ATTRIBUTES lpSA, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    typedef HANDLE(WINAPI* Fn)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    if (lpStartAddress && !IsAddressInKnownModule((const void*)lpStartAddress)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "local thread: startAddr=%p NOT in any loaded module (heap/anon shellcode)",
            (void*)lpStartAddress);
        SendHookEvent("Critical", "CreateThread", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATETHREAD))(
        lpSA, dwStackSize, lpStartAddress, lpParam, dwCreationFlags, lpThreadId);
}

// Technique 6: MapViewOfFile with FILE_MAP_EXECUTE — file-backed section / module stomping
static LPVOID WINAPI Hook_MapViewOfFile(
    HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    typedef LPVOID(WINAPI* Fn)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    if (dwDesiredAccess & FILE_MAP_EXECUTE) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "executable file mapping: access=0x%lX size=0x%llX",
            dwDesiredAccess, (ULONG64)dwNumberOfBytesToMap);
        SendHookEvent("High", "MapViewOfFile", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_MAPVIEWOFFILE))(
        hFileMappingObject, dwDesiredAccess,
        dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

// Technique 2: RegisterClassEx with WndProc shellcode address (window message dispatch)
static ATOM WINAPI Hook_RegisterClassExA(const WNDCLASSEXA* lpwcx) {
    typedef ATOM(WINAPI* Fn)(const WNDCLASSEXA*);
    if (lpwcx && lpwcx->lpfnWndProc &&
        !IsAddressInKnownModule((const void*)lpwcx->lpfnWndProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module — window message shellcode dispatch",
            (void*)lpwcx->lpfnWndProc);
        SendHookEvent("Critical", "RegisterClassExA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_REGISTERCLASSEXA))(lpwcx);
}

static ATOM WINAPI Hook_RegisterClassExW(const WNDCLASSEXW* lpwcx) {
    typedef ATOM(WINAPI* Fn)(const WNDCLASSEXW*);
    if (lpwcx && lpwcx->lpfnWndProc &&
        !IsAddressInKnownModule((const void*)lpwcx->lpfnWndProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WndProc=%p NOT in any loaded module — window message shellcode dispatch",
            (void*)lpwcx->lpfnWndProc);
        SendHookEvent("Critical", "RegisterClassExW", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_REGISTERCLASSEXW))(lpwcx);
}

// Technique 4: Callback abuse — Enum* functions used to dispatch shellcode
static BOOL WINAPI Hook_EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags) {
    typedef BOOL(WINAPI* Fn)(LOCALE_ENUMPROCA, DWORD);
    if (lpLocaleEnumProc && !IsAddressInKnownModule((const void*)lpLocaleEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpLocaleEnumProc);
        SendHookEvent("Critical", "EnumSystemLocalesA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSTEMLOCALESA))(lpLocaleEnumProc, dwFlags);
}

// EnumSystemLanguageGroupsA — rarity score 100 in malware differential: never in clean,
// seen in 16 malicious samples. Treat as Critical unconditionally when callback is
// outside module space.
static BOOL WINAPI Hook_EnumSystemLanguageGroupsA(
    LANGUAGEGROUP_ENUMPROCA lpLanguageGroupEnumProc, DWORD dwFlags, LONG_PTR lParam)
{
    typedef BOOL(WINAPI* Fn)(LANGUAGEGROUP_ENUMPROCA, DWORD, LONG_PTR);
    if (lpLanguageGroupEnumProc &&
        !IsAddressInKnownModule((const void*)lpLanguageGroupEnumProc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module [rarity-100 malware indicator]",
            (void*)lpLanguageGroupEnumProc);
        SendHookEvent("Critical", "EnumSystemLanguageGroupsA", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMSYSLANGGRPA))(
        lpLanguageGroupEnumProc, dwFlags, lParam);
}

static BOOL WINAPI Hook_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(WNDENUMPROC, LPARAM);
    if (lpEnumFunc && !IsAddressInKnownModule((const void*)lpEnumFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpEnumFunc);
        SendHookEvent("Critical", "EnumWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMWINDOWS))(lpEnumFunc, lParam);
}

static BOOL WINAPI Hook_EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    typedef BOOL(WINAPI* Fn)(HWND, WNDENUMPROC, LPARAM);
    if (lpEnumFunc && !IsAddressInKnownModule((const void*)lpEnumFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)lpEnumFunc);
        SendHookEvent("Critical", "EnumChildWindows", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_ENUMCHILDWINDOWS))(hWndParent, lpEnumFunc, lParam);
}

// Technique 5: Timer callbacks — shellcode registered as timer handler
static UINT_PTR WINAPI Hook_SetTimer(
    HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
{
    typedef UINT_PTR(WINAPI* Fn)(HWND, UINT_PTR, UINT, TIMERPROC);
    if (lpTimerFunc && !IsAddressInKnownModule((const void*)lpTimerFunc)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "TimerProc=%p NOT in any loaded module", (void*)lpTimerFunc);
        SendHookEvent("Critical", "SetTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETTIMER))(hWnd, nIDEvent, uElapse, lpTimerFunc);
}

static BOOL WINAPI Hook_SetWaitableTimer(
    HANDLE hTimer, const LARGE_INTEGER* lpDueTime, LONG lPeriod,
    PTIMERAPCROUTINE pfnCompletionRoutine, PVOID lpArgToCompletionRoutine, BOOL fResume)
{
    typedef BOOL(WINAPI* Fn)(HANDLE, const LARGE_INTEGER*, LONG,
                              PTIMERAPCROUTINE, PVOID, BOOL);
    if (pfnCompletionRoutine &&
        !IsAddressInKnownModule((const void*)pfnCompletionRoutine)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "APC routine=%p NOT in any loaded module", (void*)pfnCompletionRoutine);
        SendHookEvent("Critical", "SetWaitableTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_SETWAITABLETIMER))(
        hTimer, lpDueTime, lPeriod, pfnCompletionRoutine,
        lpArgToCompletionRoutine, fResume);
}

static BOOL WINAPI Hook_CreateTimerQueueTimer(
    PHANDLE phNewTimer, HANDLE TimerQueue,
    WAITORTIMERCALLBACK Callback, PVOID Parameter,
    DWORD DueTime, DWORD Period, ULONG Flags)
{
    typedef BOOL(WINAPI* Fn)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID,
                              DWORD, DWORD, ULONG);
    if (Callback && !IsAddressInKnownModule((const void*)Callback)) {
        char det[128];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "callback=%p NOT in any loaded module", (void*)Callback);
        SendHookEvent("Critical", "CreateTimerQueueTimer", 0, det);
    }
    return ((Fn)GetCallThrough(IDX_CREATETIMERQUEUETIMER))(
        phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);
}

// ---------------------------------------------------------------------------
// VEH hooking bypass coverage
//
// Technique: attacker calls AddVectoredExceptionHandler / RtlAddVectoredExceptionHandler
// with a shellcode address, then intentionally triggers an exception (div-by-zero,
// access violation, or a hardware debug breakpoint set via SetThreadContext DR0-DR3).
// The VEH fires BEFORE the inline hook JMP is reached — bypassing our detour
// entirely — and the VEH handler can redirect RIP to any address.
//
// We flag registrations whose handler address does not belong to any loaded PE
// module on disk, which is the signature of heap/stack shellcode.
// ---------------------------------------------------------------------------

// Shared logic for all four VEH registration APIs.
static void CheckVehHandler(const char* apiName, PVECTORED_EXCEPTION_HANDLER handler) {
    if (!handler) return;
    if (!IsAddressInKnownModule((const void*)handler)) {
        char det[160];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "VEH handler=%p NOT in any loaded module — "
            "shellcode may be registered as vectored exception handler to bypass inline hooks",
            (void*)handler);
        SendHookEvent("Critical", apiName, g_selfPid, det);
    }
}

static PVOID WINAPI Hook_AddVectoredExceptionHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(WINAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("AddVectoredExceptionHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_ADDVECTOREDEXCEPTIONHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID WINAPI Hook_AddVectoredContinueHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(WINAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("AddVectoredContinueHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_ADDVECTOREDCONTINUEHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID NTAPI Hook_RtlAddVectoredExceptionHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(NTAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("RtlAddVectoredExceptionHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_RTLADDVECTOREDEXCEPTIONHANDLER))(FirstHandler, VectoredHandler);
}

static PVOID NTAPI Hook_RtlAddVectoredContinueHandler(
    ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    typedef PVOID(NTAPI* Fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    CheckVehHandler("RtlAddVectoredContinueHandler", VectoredHandler);
    return ((Fn)GetCallThrough(IDX_RTLADDVECTOREDCONTINUEHANDLER))(FirstHandler, VectoredHandler);
}

// ---------------------------------------------------------------------------
// Sleep obfuscation detection — SystemFunction032 hook (Ekko/Foliage/Cronos)
//
// Sleep obfuscation frameworks (Ekko, Foliage, Cronos, Havoc sleep masks)
// use SystemFunction032 (RC4) to encrypt their implant's memory while sleeping.
// The pattern: VirtualProtect(RX→RW) → SystemFunction032(encrypt) → Sleep →
// SystemFunction032(decrypt) → VirtualProtect(RW→RX).
//
// Detection: when SystemFunction032 is called on a buffer that resides in a
// MEM_PRIVATE region (not a loaded module), this is almost certainly sleep
// obfuscation — legitimate code uses CryptEncrypt or BCrypt, not the
// undocumented SystemFunction032.
// ---------------------------------------------------------------------------

static NTSTATUS WINAPI Hook_SystemFunction032(USTRING* data, USTRING* key)
{
    typedef NTSTATUS(WINAPI* Fn)(USTRING*, USTRING*);

    if (data && data->Buffer && data->Length > 0) {
        // Check if the target buffer is in a private (non-module) region
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(data->Buffer, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // MEM_PRIVATE + large buffer = sleep obfuscation indicator
            // Legitimate RC4 usage is on small data blobs, not entire PE sections.
            if (mbi.Type == MEM_PRIVATE && data->Length > 4096) {
                char det[256];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Sleep obfuscation (Ekko/Foliage/Cronos): SystemFunction032 called on "
                    "MEM_PRIVATE region at %p (size=%lu, protect=0x%lx) — "
                    "RC4 encrypt/decrypt of implant memory during beacon sleep",
                    (void*)data->Buffer, data->Length, mbi.Protect);
                SendHookEvent("Critical", "SystemFunction032", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_SYSTEMFUNCTION032))(data, key);
}

// ---------------------------------------------------------------------------
// DPAPI credential harvesting — CryptUnprotectData hook
//
// Browser credential stealers (SharpChromium, HackBrowserData, Mimikatz
// dpapi::chrome, CookieMonster) call CryptUnprotectData to decrypt the
// browser's AES-GCM master key (stored in Local State, DPAPI-encrypted).
// Legitimate browsers call this themselves; any OTHER process calling it
// is harvesting credentials.
// ---------------------------------------------------------------------------

static BOOL WINAPI Hook_CryptUnprotectData(
    HOOK_DATA_BLOB* pDataIn, wchar_t** ppszDataDescr,
    HOOK_DATA_BLOB* pOptionalEntropy, PVOID pvReserved,
    PVOID pPromptStruct, DWORD dwFlags, HOOK_DATA_BLOB* pDataOut)
{
    typedef BOOL(WINAPI* Fn)(HOOK_DATA_BLOB*, wchar_t**, HOOK_DATA_BLOB*,
                              PVOID, PVOID, DWORD, HOOK_DATA_BLOB*);

    // Only flag non-browser processes calling CryptUnprotectData
    char exeName[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
    const char* base = exeName;
    for (const char* p = exeName; *p; p++)
        if (*p == '\\' || *p == '/') base = p + 1;

    BOOL isBrowser = (_stricmp(base, "chrome.exe")   == 0 ||
                      _stricmp(base, "msedge.exe")   == 0 ||
                      _stricmp(base, "firefox.exe")  == 0 ||
                      _stricmp(base, "opera.exe")    == 0 ||
                      _stricmp(base, "brave.exe")    == 0 ||
                      _stricmp(base, "vivaldi.exe")  == 0 ||
                      _stricmp(base, "iexplore.exe") == 0);

    // Legitimate DPAPI callers: browsers, credential manager, system
    BOOL isSystem = (_stricmp(base, "lsass.exe")     == 0 ||
                     _stricmp(base, "svchost.exe")   == 0 ||
                     _stricmp(base, "services.exe")  == 0 ||
                     _stricmp(base, "NortonEDR.exe") == 0);

    if (!isBrowser && !isSystem && pDataIn && pDataIn->cbData > 0) {
        // CRYPTPROTECT_UI_FORBIDDEN (0x01) = programmatic access without UI prompt
        // — credential stealers always set this flag.
        const char* severity = (dwFlags & 0x01) ? "Critical" : "Warning";
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "DPAPI credential harvesting: %s called CryptUnprotectData "
            "(size=%lu, flags=0x%lx) — possible browser/credential theft "
            "(SharpChromium/HackBrowserData/Mimikatz dpapi)",
            base, pDataIn->cbData, dwFlags);
        SendHookEvent(severity, "CryptUnprotectData", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_CRYPTUNPROTECTDATA))(
        pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved,
        pPromptStruct, dwFlags, pDataOut);
}

// ---------------------------------------------------------------------------
// Process Ghosting detection — NtSetInformationFile hook
//
// Process Ghosting: attacker creates a file, writes malicious PE, marks it
// delete-pending (NtSetInformationFile with FileDispositionInformation),
// creates a section from it, then closes the handle (file is deleted).
// The section survives, and the process is created from a "ghost" file
// that no longer exists on disk.
//
// Detection: NtSetInformationFile with FileDispositionInformation (class 13)
// or FileDispositionInformationEx (class 64) from a non-system process.
// Legitimate software rarely marks files delete-pending while keeping the
// handle open for section creation.
// ---------------------------------------------------------------------------

// Helper: detect ETW log/event file targets by path substring.  Matches
// .etl (trace log) and .evtx (Windows Event Log) under the standard system
// locations.  Flags deletion/rename/truncation of these files as telemetry
// destruction (T1070.001 / T1562.002).
static bool PathIsEtwLogFile(const WCHAR* path) {
    if (!path) return false;
    // Normalize by walking the tail for extension and middle for folder.
    const WCHAR* ext = nullptr;
    const WCHAR* p = path;
    for (; *p; p++) { if (*p == L'.') ext = p; }
    if (!ext) return false;
    bool isEtl  = (_wcsicmp(ext, L".etl")  == 0);
    bool isEvtx = (_wcsicmp(ext, L".evtx") == 0);
    if (!isEtl && !isEvtx) return false;
    // Require the path to be in a known telemetry directory to avoid noise.
    return (wcsstr(path, L"\\LogFiles\\WMI\\")  != nullptr) ||
           (wcsstr(path, L"\\winevt\\Logs\\")   != nullptr) ||
           (wcsstr(path, L"\\Microsoft\\Diagnosis\\") != nullptr) ||
           (wcsstr(path, L"\\ETW\\")             != nullptr);
}

static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation,
    ULONG Length, ULONG FileInformationClass)
{
    typedef NTSTATUS(NTAPI* Fn)(HANDLE, PVOID, PVOID, ULONG, ULONG);

    // ETW log destruction: delete (13/64), rename (10/65), or truncate (20)
    // of .etl/.evtx files under system telemetry directories.  Resolve the
    // handle path up front so we can annotate all three paths.
    bool isEtwLog = false;
    WCHAR filePath[MAX_PATH] = {};
    if (FileHandle && (FileInformationClass == 13 || FileInformationClass == 64 ||
                       FileInformationClass == 10 || FileInformationClass == 65 ||
                       FileInformationClass == 20))
    {
        // VOLUME_NAME_DOS returns the drive-letter form
        DWORD got = GetFinalPathNameByHandleW(FileHandle, filePath,
            sizeof(filePath)/sizeof(filePath[0]), 0x0 /*VOLUME_NAME_DOS*/);
        if (got > 0 && got < sizeof(filePath)/sizeof(filePath[0]))
            isEtwLog = PathIsEtwLogFile(filePath);
    }

    // FileEndOfFileInformation (20) — truncation attack on open ETL handle
    if (FileInformationClass == 20 && isEtwLog) {
        char det[400];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "ETW log truncation: SetFileInformation(EndOfFile) on "
            "'%ls' — recorded events destroyed (T1070.001/T1562.002)",
            filePath);
        SendHookEvent("Critical", "NtSetInformationFile", 0, det);
    }

    // FileRenameInformation (10) / FileRenameInformationEx (65) — move ETL/EVTX
    if ((FileInformationClass == 10 || FileInformationClass == 65) && isEtwLog) {
        char det[400];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "ETW log rename: '%ls' moved via SetFileInformation — "
            "telemetry path redirect / evidence relocation (T1070.001)",
            filePath);
        SendHookEvent("Critical", "NtSetInformationFile", 0, det);
    }

    // FileDispositionInformation = 13, FileDispositionInformationEx = 64
    if ((FileInformationClass == 13 || FileInformationClass == 64) &&
        FileInformation && Length >= sizeof(BOOLEAN))
    {
        BOOLEAN deleteFile = *(BOOLEAN*)FileInformation;
        if (deleteFile && isEtwLog) {
            char det[400];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "ETW log DELETE-pending on '%ls' — recorded events destroyed "
                "(T1070.001/T1562.002)",
                filePath);
            SendHookEvent("Critical", "NtSetInformationFile", 0, det);
        }
        if (deleteFile) {
            // Check if this file handle was recently written to (heuristic for ghosting)
            // For now, flag delete-pending from non-system processes as suspicious
            char exeName[MAX_PATH] = {};
            GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
            const char* base = exeName;
            for (const char* p = exeName; *p; p++)
                if (*p == '\\' || *p == '/') base = p + 1;

            BOOL isTrusted = (_stricmp(base, "explorer.exe") == 0 ||
                              _stricmp(base, "svchost.exe")  == 0 ||
                              _stricmp(base, "msiexec.exe")  == 0 ||
                              _stricmp(base, "TiWorker.exe") == 0 ||
                              _stricmp(base, "setup.exe")    == 0 ||
                              _stricmp(base, "NortonEDR.exe") == 0);

            if (!isTrusted) {
                char det[256];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Process Ghosting indicator: %s set FileDispositionInfo%s "
                    "(delete-pending) — file may be used for ghost process creation "
                    "(T1055.012 variant)",
                    base,
                    FileInformationClass == 64 ? "Ex" : "");
                SendHookEvent("Warning", "NtSetInformationFile", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_NTSETINFORMATIONFILE))(
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

// ---------------------------------------------------------------------------
// Transacted Hollowing — NtCreateTransaction hook (user-mode complement)
//
// The kernel syscall hook already catches NtCreateTransaction; this user-mode
// hook provides redundancy and catches cases where the syscall hook is bypassed
// (e.g., via direct syscall from injected code that was already inside a
// process before HookDll loaded).
//
// Transacted Hollowing combines TxF (NTFS transactions) with process hollowing:
// create a transaction, write malicious PE to a transacted file, create a
// MEM_IMAGE section from it, then rollback (artifact-free on disk).
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI Hook_NtCreateTransaction(
    PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID Uow, HANDLE TmHandle,
    ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags,
    PLARGE_INTEGER Timeout, PVOID Description)
{
    typedef NTSTATUS(NTAPI* Fn)(PHANDLE, ACCESS_MASK, PVOID, PVOID, HANDLE,
                                 ULONG, ULONG, ULONG, PLARGE_INTEGER, PVOID);

    // NtCreateTransaction is almost never called by legitimate user-mode software.
    // TxF is deprecated since Windows 8 and MS discourages its use.
    char exeName[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
    const char* base = exeName;
    for (const char* p = exeName; *p; p++)
        if (*p == '\\' || *p == '/') base = p + 1;

    BOOL isTrusted = (_stricmp(base, "svchost.exe")  == 0 ||
                      _stricmp(base, "msiexec.exe")  == 0 ||
                      _stricmp(base, "TiWorker.exe") == 0 ||
                      _stricmp(base, "NortonEDR.exe") == 0);

    if (!isTrusted) {
        char det[256];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "Transacted Hollowing: %s called NtCreateTransaction "
            "— TxF is deprecated; likely Process Doppelganging / "
            "Transacted Hollowing evasion technique",
            base);
        SendHookEvent("Warning", "NtCreateTransaction", 0, det);
    }

    return ((Fn)GetCallThrough(IDX_NTCREATETRANSACTION))(
        TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle,
        CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
}

// ---------------------------------------------------------------------------
// WFP manipulation detection — fwpuclnt.dll hooks
//
// EDRSilencer and similar tools call these user-mode WFP APIs to add BLOCK
// filters, delete EDR filters, inject rogue callouts/sublayers, or close
// WFP engine handles.  Hooking fwpuclnt.dll lets us intercept the call
// in real-time — before it reaches the BFE service — and alert/block.
//
// fwpuclnt.dll is loaded on-demand; the hook infrastructure handles deferred
// patching when the module appears.
// ---------------------------------------------------------------------------

// Helper: get process name for WFP hook alerts.
static const char* GetWfpCallerName()
{
    static thread_local char s_buf[MAX_PATH];
    GetModuleFileNameA(nullptr, s_buf, sizeof(s_buf));
    const char* base = s_buf;
    for (const char* p = s_buf; *p; p++)
        if (*p == '\\' || *p == '/') base = p + 1;
    return base;
}

static BOOL IsWfpCallerTrusted()
{
    const char* base = GetWfpCallerName();
    return (_stricmp(base, "svchost.exe")    == 0 ||
            _stricmp(base, "lsass.exe")      == 0 ||
            _stricmp(base, "services.exe")   == 0 ||
            _stricmp(base, "NortonEDR.exe")  == 0 ||
            _stricmp(base, "WmiPrvSE.exe")   == 0 ||
            _stricmp(base, "mmc.exe")        == 0);  // Firewall snap-in
}

// FwpmFilterAdd0 — detects rogue filter injection (EDRSilencer primary vector).
static DWORD WINAPI Hook_FwpmFilterAdd0(
    HANDLE engineHandle, const PVOID filter,
    PVOID sd, UINT64* filterId)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmFilterAdd0 — "
            "EDRSilencer-class attack: injecting WFP filter to block "
            "EDR telemetry or intercept network traffic",
            GetWfpCallerName());
        SendHookEvent("Critical", "FwpmFilterAdd0", g_selfPid, det);
    }

    return ((FnFwpmFilterAdd0)GetCallThrough(IDX_FWPMFILTERADD0))(
        engineHandle, filter, sd, filterId);
}

// FwpmFilterDeleteById0 — detects EDR filter deletion.
static DWORD WINAPI Hook_FwpmFilterDeleteById0(
    HANDLE engineHandle, UINT64 filterId)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmFilterDeleteById0 "
            "(filterId=%llu) — may be deleting EDR WFP filter to "
            "disable network monitoring",
            GetWfpCallerName(), filterId);
        SendHookEvent("Critical", "FwpmFilterDeleteById0", g_selfPid, det);
    }

    return ((FnFwpmFilterDeleteById0)GetCallThrough(IDX_FWPMFILTERDELETEBYID0))(
        engineHandle, filterId);
}

// FwpmCalloutAdd0 — detects rogue callout injection.
static DWORD WINAPI Hook_FwpmCalloutAdd0(
    HANDLE engineHandle, const PVOID callout,
    PVOID sd, UINT32* calloutId)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmCalloutAdd0 — "
            "rogue callout injection to intercept/modify network "
            "packets before EDR callout fires",
            GetWfpCallerName());
        SendHookEvent("Critical", "FwpmCalloutAdd0", g_selfPid, det);
    }

    return ((FnFwpmCalloutAdd0)GetCallThrough(IDX_FWPMCALLOUTADD0))(
        engineHandle, callout, sd, calloutId);
}

// FwpmSubLayerAdd0 — detects rogue sublayer injection.
static DWORD WINAPI Hook_FwpmSubLayerAdd0(
    HANDLE engineHandle, const PVOID subLayer, PVOID sd)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmSubLayerAdd0 — "
            "rogue sublayer injection to stage BLOCK filters or "
            "manipulate WFP arbitration",
            GetWfpCallerName());
        SendHookEvent("Critical", "FwpmSubLayerAdd0", g_selfPid, det);
    }

    return ((FnFwpmSubLayerAdd0)GetCallThrough(IDX_FWPMSUBLAYERADD0))(
        engineHandle, subLayer, sd);
}

// FwpmSubLayerDeleteByKey0 — detects sublayer deletion (cascade attack).
static DWORD WINAPI Hook_FwpmSubLayerDeleteByKey0(
    HANDLE engineHandle, const GUID* key)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmSubLayerDeleteByKey0 — "
            "sublayer deletion cascade-deletes all filters within it. "
            "May be targeting NortonEDR sublayer",
            GetWfpCallerName());
        SendHookEvent("Critical", "FwpmSubLayerDeleteByKey0", g_selfPid, det);
    }

    return ((FnFwpmSubLayerDeleteByKey0)GetCallThrough(IDX_FWPMSUBLAYERDELETEBYKEY0))(
        engineHandle, key);
}

// FwpmEngineClose0 — detects engine handle closure.
// An attacker can close WFP engine handles to disrupt active sessions.
static DWORD WINAPI Hook_FwpmEngineClose0(HANDLE engineHandle)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP MANIPULATION: %s called FwpmEngineClose0 — "
            "closing WFP engine handle to disrupt active WFP sessions "
            "or prevent re-registration of filters",
            GetWfpCallerName());
        SendHookEvent("Critical", "FwpmEngineClose0", g_selfPid, det);
    }

    return ((FnFwpmEngineClose0)GetCallThrough(IDX_FWPMENGINECLOSE0))(
        engineHandle);
}

// ---------------------------------------------------------------------------
// WFP enumeration/recon detection — fwpuclnt.dll hooks
//
// EDRSilencer and similar tools enumerate WFP state (filters, callouts,
// sublayers, providers, security descriptors) before injecting BLOCK filters.
// Detecting enumeration catches the recon phase of the attack — before any
// modification occurs.  These are Warning-level (recon is not destructive).
// ---------------------------------------------------------------------------

// FwpmFilterEnum0 — enumerating all WFP filters (EDRSilencer recon phase).
static DWORD WINAPI Hook_FwpmFilterEnum0(
    HANDLE engineHandle, HANDLE enumHandle,
    UINT32 numEntriesRequested, PVOID* entries, UINT32* numEntriesReturned)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmFilterEnum0 — "
            "enumerating WFP filters to discover EDR filter rules "
            "before tampering (pre-attack reconnaissance)",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmFilterEnum0", g_selfPid, det);
    }

    return ((FnFwpmFilterEnum0)GetCallThrough(IDX_FWPMFILTERENUM0))(
        engineHandle, enumHandle, numEntriesRequested, entries, numEntriesReturned);
}

// FwpmCalloutEnum0 — enumerating WFP callouts to find EDR inspection points.
static DWORD WINAPI Hook_FwpmCalloutEnum0(
    HANDLE engineHandle, HANDLE enumHandle,
    UINT32 numEntriesRequested, PVOID* entries, UINT32* numEntriesReturned)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmCalloutEnum0 — "
            "enumerating WFP callouts to identify EDR inspection "
            "hooks before disabling or outweighing them",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmCalloutEnum0", g_selfPid, det);
    }

    return ((FnFwpmCalloutEnum0)GetCallThrough(IDX_FWPMCALLOUTENUM0))(
        engineHandle, enumHandle, numEntriesRequested, entries, numEntriesReturned);
}

// FwpmSubLayerEnum0 — enumerating sublayers to find EDR sublayer for deletion.
static DWORD WINAPI Hook_FwpmSubLayerEnum0(
    HANDLE engineHandle, HANDLE enumHandle,
    UINT32 numEntriesRequested, PVOID* entries, UINT32* numEntriesReturned)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmSubLayerEnum0 — "
            "enumerating WFP sublayers to identify EDR sublayer "
            "GUID for targeted deletion or weight manipulation",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmSubLayerEnum0", g_selfPid, det);
    }

    return ((FnFwpmSubLayerEnum0)GetCallThrough(IDX_FWPMSUBLAYERENUM0))(
        engineHandle, enumHandle, numEntriesRequested, entries, numEntriesReturned);
}

// FwpmProviderEnum0 — enumerating providers to fingerprint security products.
static DWORD WINAPI Hook_FwpmProviderEnum0(
    HANDLE engineHandle, HANDLE enumHandle,
    UINT32 numEntriesRequested, PVOID* entries, UINT32* numEntriesReturned)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmProviderEnum0 — "
            "enumerating WFP providers to fingerprint installed "
            "security products and their WFP registrations",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmProviderEnum0", g_selfPid, det);
    }

    return ((FnFwpmProviderEnum0)GetCallThrough(IDX_FWPMPROVIDERENUM0))(
        engineHandle, enumHandle, numEntriesRequested, entries, numEntriesReturned);
}

// FwpmEngineGetSecurityInfo0 — querying WFP engine ACL to check permissions.
static DWORD WINAPI Hook_FwpmEngineGetSecurityInfo0(
    HANDLE engineHandle, SECURITY_INFORMATION secInfo,
    PSID* sidOwner, PSID* sidGroup, PACL* dacl, PACL* sacl,
    PSECURITY_DESCRIPTOR* sd)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmEngineGetSecurityInfo0 — "
            "querying WFP engine security descriptor to probe "
            "whether modification attacks are permitted",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmEngineGetSecurityInfo0", g_selfPid, det);
    }

    return ((FnFwpmEngineGetSecurityInfo0)GetCallThrough(IDX_FWPMENGINEGETSECINFOBYKEY0))(
        engineHandle, secInfo, sidOwner, sidGroup, dacl, sacl, sd);
}

// FwpmFilterGetSecurityInfoByKey0 — querying filter-level ACL before tampering.
static DWORD WINAPI Hook_FwpmFilterGetSecurityInfoByKey0(
    HANDLE engineHandle, const GUID* key, SECURITY_INFORMATION secInfo,
    PSID* sidOwner, PSID* sidGroup, PACL* dacl, PACL* sacl,
    PSECURITY_DESCRIPTOR* sd)
{
    if (!IsWfpCallerTrusted()) {
        char det[300];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "WFP RECON: %s called FwpmFilterGetSecurityInfoByKey0 — "
            "querying filter security descriptor to check if EDR "
            "filter can be deleted or modified",
            GetWfpCallerName());
        SendHookEvent("Warning", "FwpmFilterGetSecurityInfoByKey0", g_selfPid, det);
    }

    return ((FnFwpmFilterGetSecurityInfoByKey0)GetCallThrough(IDX_FWPMFILTERGETSECINFOBYKEY0))(
        engineHandle, key, secInfo, sidOwner, sidGroup, dacl, sacl, sd);
}

// ---------------------------------------------------------------------------
// Weaver Ant: COM object monitoring — script engines, shell execution,
// and DCOM lateral movement CLSIDs.
//
// Category 1 — Script engines (China Chopper / INMemory eval() execution):
//   {F414C260-6AC0-11CF-B6D1-00AA00BBBB58} — JScript
//   {B54F3741-5B07-11CF-A4B0-00AA004A55E8} — VBScript
//   {0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC} — MSScriptControl.ScriptControl
//   {06290BD5-48AA-11D2-8432-006008C3FBFC} — scrobj.dll Scriptlet factory
//
// Category 2 — Shell execution (web shell Run/Exec, lateral movement):
//   {72C24DD5-D70A-438B-8A42-98424B88AFB8} — WScript.Shell (Run/Exec)
//   {13709620-C279-11CE-A49E-444553540000} — Shell.Application (ShellExecute)
//
// Category 3 — DCOM lateral movement (impacket, CrackMapExec, Evil-WinRM):
//   {49B2791A-B1AE-4C90-9B8E-E860BA07F889} — MMC20.Application (ExecuteShellCommand)
//   {9BA05972-F6A8-11CF-A442-00A0C90A8F39} — ShellWindows (Document.Application.ShellExecute)
//   {C08AFD90-F2A1-11D1-8455-00A0C91F3880} — ShellBrowserWindow
// ---------------------------------------------------------------------------

// Category 1: Script engines
static const GUID CLSID_JScript         = { 0xF414C260, 0x6AC0, 0x11CF, { 0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58 } };
static const GUID CLSID_VBScript        = { 0xB54F3741, 0x5B07, 0x11CF, { 0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8 } };
static const GUID CLSID_ScriptControl   = { 0x0E59F1D5, 0x1FBE, 0x11D0, { 0x8F, 0xF2, 0x00, 0xA0, 0xD1, 0x00, 0x38, 0xBC } };
static const GUID CLSID_Scriptlet       = { 0x06290BD5, 0x48AA, 0x11D2, { 0x84, 0x32, 0x00, 0x60, 0x08, 0xC3, 0xFB, 0xFC } };
// Category 2: Shell execution
static const GUID CLSID_WScriptShell    = { 0x72C24DD5, 0xD70A, 0x438B, { 0x8A, 0x42, 0x98, 0x42, 0x4B, 0x88, 0xAF, 0xB8 } };
static const GUID CLSID_ShellApp        = { 0x13709620, 0xC279, 0x11CE, { 0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
// Category 3: DCOM lateral movement
static const GUID CLSID_MMC20App        = { 0x49B2791A, 0xB1AE, 0x4C90, { 0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89 } };
static const GUID CLSID_ShellWindows    = { 0x9BA05972, 0xF6A8, 0x11CF, { 0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39 } };
static const GUID CLSID_ShellBrowser    = { 0xC08AFD90, 0xF2A1, 0x11D1, { 0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80 } };

struct MonitoredCLSID {
    const GUID*  clsid;
    const char*  name;
    const char*  category;   // "ScriptEngine", "ShellExec", "DCOM-LateralMove"
};

static const MonitoredCLSID kMonitoredCLSIDs[] = {
    // Script engines
    { &CLSID_JScript,        "JScript",                  "ScriptEngine" },
    { &CLSID_VBScript,       "VBScript",                 "ScriptEngine" },
    { &CLSID_ScriptControl,  "MSScriptControl",          "ScriptEngine" },
    { &CLSID_Scriptlet,      "scrobj Scriptlet",         "ScriptEngine" },
    // Shell execution
    { &CLSID_WScriptShell,   "WScript.Shell",            "ShellExec" },
    { &CLSID_ShellApp,       "Shell.Application",        "ShellExec" },
    // DCOM lateral movement
    { &CLSID_MMC20App,       "MMC20.Application",        "DCOM-LateralMove" },
    { &CLSID_ShellWindows,   "ShellWindows",             "DCOM-LateralMove" },
    { &CLSID_ShellBrowser,   "ShellBrowserWindow",       "DCOM-LateralMove" },
};

// Shared helper: determine host process name and legitimacy.
static const char* kScriptLegitHosts[] = {
    "wscript.exe", "cscript.exe", "mshta.exe", "iexplore.exe",
    "msedge.exe", "excel.exe", "winword.exe", "powerpnt.exe",
    "outlook.exe", "mmc.exe",
    nullptr
};

static bool IsScriptLegitHost(const char* baseName) {
    for (int j = 0; kScriptLegitHosts[j]; j++) {
        if (_stricmp(baseName, kScriptLegitHosts[j]) == 0) return true;
    }
    return false;
}

static const char* GetHostBaseName(char* buf, SIZE_T bufSize) {
    GetModuleFileNameA(nullptr, buf, (DWORD)bufSize);
    const char* base = strrchr(buf, '\\');
    return base ? base + 1 : buf;
}

// Check a CLSID against the monitored table and emit alert if matched.
// Returns the matched entry or nullptr.
static const MonitoredCLSID* CheckMonitoredCLSID(
    REFCLSID rclsid, const char* apiName, DWORD dwClsContext)
{
    for (int i = 0; i < ARRAYSIZE(kMonitoredCLSIDs); i++) {
        if (memcmp(&rclsid, kMonitoredCLSIDs[i].clsid, sizeof(GUID)) == 0) {
            char hostExe[MAX_PATH] = {};
            const char* base = GetHostBaseName(hostExe, sizeof(hostExe));

            // DCOM lateral movement CLSIDs are always critical — they should
            // never be instantiated from user workstations in normal operation.
            bool isDcom = (strcmp(kMonitoredCLSIDs[i].category, "DCOM-LateralMove") == 0);
            bool isLegit = !isDcom && IsScriptLegitHost(base);

            // WScript.Shell from cmd.exe/powershell is suspicious but common
            // in admin scripts; from w3wp.exe it's critical (web shell).
            bool isWebServer = (_stricmp(base, "w3wp.exe") == 0 ||
                                _stricmp(base, "httpd.exe") == 0 ||
                                _stricmp(base, "nginx.exe") == 0 ||
                                _stricmp(base, "php-cgi.exe") == 0 ||
                                _stricmp(base, "java.exe") == 0 ||
                                _stricmp(base, "tomcat9.exe") == 0);

            const char* sev;
            if (isDcom || isWebServer)
                sev = "Critical";
            else if (isLegit)
                sev = "Info";
            else
                sev = "High";

            char det[420];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "%s: %s [%s] instantiated in %s (CLSCTX=0x%lX)%s%s",
                apiName, kMonitoredCLSIDs[i].name,
                kMonitoredCLSIDs[i].category,
                hostExe, dwClsContext,
                isWebServer ? " — WEB SHELL EXECUTION" : "",
                isDcom ? " — DCOM LATERAL MOVEMENT" : "");
            SendHookEvent(sev, apiName, 0, det);
            return &kMonitoredCLSIDs[i];
        }
    }
    return nullptr;
}

static HRESULT WINAPI Hook_CoCreateInstance(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
    CheckMonitoredCLSID(rclsid, "CoCreateInstance", dwClsContext);

    return ((FnCoCreateInstance)GetCallThrough(IDX_COCREATEINSTANCE))(
        rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

// ---------------------------------------------------------------------------
// CoCreateInstanceEx — DCOM remote COM instantiation.
// When dwClsContext includes CLSCTX_REMOTE_SERVER (0x10), the COM object is
// created on a remote machine.  This is the execution path for:
//   - impacket dcomexec.py (MMC20.Application, ShellWindows, ShellBrowserWindow)
//   - CrackMapExec DCOM lateral movement
//   - Evil-WinRM DCOM execution
// Even local instantiation of DCOM objects is suspicious from non-admin tools.
// ---------------------------------------------------------------------------
static HRESULT WINAPI Hook_CoCreateInstanceEx(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, PVOID pServerInfo, DWORD dwCount, PVOID pResults)
{
    const MonitoredCLSID* match = CheckMonitoredCLSID(
        rclsid, "CoCreateInstanceEx", dwClsContext);

    // Extra alert for remote server context — definitive lateral movement
    if (pServerInfo && (dwClsContext & 0x10)) {  // CLSCTX_REMOTE_SERVER = 0x10
        char hostExe[MAX_PATH] = {};
        const char* base = GetHostBaseName(hostExe, sizeof(hostExe));

        char det[384];
        if (match) {
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "DCOM REMOTE EXEC: %s instantiated with CLSCTX_REMOTE_SERVER "
                "from %s — confirmed lateral movement (impacket/CrackMapExec)",
                match->name, hostExe);
        } else {
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "DCOM REMOTE: unknown CLSID instantiated with CLSCTX_REMOTE_SERVER "
                "from %s — possible lateral movement",
                hostExe);
        }
        SendHookEvent("Critical", "CoCreateInstanceEx[Remote]", 0, det);
    }

    return ((FnCoCreateInstanceEx)GetCallThrough(IDX_COCREATEINSTANCEEX))(
        rclsid, pUnkOuter, dwClsContext, pServerInfo, dwCount, pResults);
}

// ---------------------------------------------------------------------------
// CLSIDFromProgID — attackers resolve ProgIDs to CLSIDs at runtime to avoid
// hardcoding CLSIDs in tooling.  Common attack ProgIDs:
//   "JScript", "VBScript", "WScript.Shell", "WScript.Shell.1",
//   "Shell.Application", "MMC20.Application", "ScriptControl",
//   "MSScriptControl.ScriptControl", "Scripting.FileSystemObject",
//   "htmlfile" (used by some web shell downloaders)
// ---------------------------------------------------------------------------

struct MonitoredProgID {
    const wchar_t*  progid;
    const char*     name;
    bool            critical;   // true = always critical, false = host-dependent
};

static const MonitoredProgID kMonitoredProgIDs[] = {
    // Script engines
    { L"JScript",                            "JScript engine",          false },
    { L"VBScript",                           "VBScript engine",         false },
    { L"MSScriptControl.ScriptControl",      "MSScriptControl",         false },
    { L"ScriptControl",                      "ScriptControl",           false },
    { L"Scripting.FileSystemObject",         "FSO (file access)",       false },
    { L"Scripting.Dictionary",               "Scripting.Dictionary",    false },
    // Shell execution
    { L"WScript.Shell",                      "WScript.Shell (Run/Exec)", false },
    { L"WScript.Shell.1",                    "WScript.Shell.1",         false },
    { L"Shell.Application",                  "Shell.Application",       false },
    { L"Shell.Application.1",               "Shell.Application.1",     false },
    // DCOM lateral movement
    { L"MMC20.Application",                  "MMC20.Application",       true },
    { L"MMC20.Application.1",               "MMC20.Application.1",     true },
    // Downloader / evasion
    { L"MSXML2.ServerXMLHTTP",              "ServerXMLHTTP (C2 comms)", false },
    { L"MSXML2.XMLHTTP",                    "XMLHTTP (C2 downloader)", false },
    { L"Microsoft.XMLHTTP",                 "XMLHTTP (legacy)",        false },
    { L"htmlfile",                           "htmlfile (web shell loader)", false },
};

static HRESULT WINAPI Hook_CLSIDFromProgID(LPCOLESTR lpszProgID, LPCLSID lpclsid)
{
    if (lpszProgID) {
        for (int i = 0; i < ARRAYSIZE(kMonitoredProgIDs); i++) {
            // Case-insensitive wide string compare
            if (_wcsicmp(lpszProgID, kMonitoredProgIDs[i].progid) == 0) {
                char hostExe[MAX_PATH] = {};
                const char* base = GetHostBaseName(hostExe, sizeof(hostExe));

                bool isWebServer = (_stricmp(base, "w3wp.exe") == 0 ||
                                    _stricmp(base, "httpd.exe") == 0 ||
                                    _stricmp(base, "nginx.exe") == 0 ||
                                    _stricmp(base, "php-cgi.exe") == 0 ||
                                    _stricmp(base, "java.exe") == 0);

                const char* sev;
                if (kMonitoredProgIDs[i].critical || isWebServer)
                    sev = "Critical";
                else if (IsScriptLegitHost(base))
                    sev = "Info";
                else
                    sev = "High";

                // Convert ProgID to narrow string for logging
                char progidNarrow[128] = {};
                for (int c = 0; c < 127 && lpszProgID[c]; c++)
                    progidNarrow[c] = (lpszProgID[c] < 128) ? (char)lpszProgID[c] : '?';

                char det[384];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "ProgID resolution: \"%s\" (%s) resolved in %s%s",
                    progidNarrow, kMonitoredProgIDs[i].name, hostExe,
                    isWebServer ? " — WEB SHELL ProgID RESOLUTION" : "");
                SendHookEvent(sev, "CLSIDFromProgID", 0, det);
                break;
            }
        }
    }

    return ((FnCLSIDFromProgID)GetCallThrough(IDX_CLSIDFROMPROGID))(
        lpszProgID, lpclsid);
}

// ---------------------------------------------------------------------------
// ETW Filter Descriptor attack detection — EnableTraceEx2 hook
//
// EnableTraceEx2 accepts ENABLE_TRACE_PARAMETERS with an array of
// EVENT_FILTER_DESCRIPTOR entries.  An attacker with SeDebugPrivilege or
// session controller access can attach filter descriptors that silently drop
// events matching specific criteria — without disabling the provider.
//
// Dangerous filter types:
//   EVENT_FILTER_TYPE_PAYLOAD   (0x80000100) — drop events by field value
//   EVENT_FILTER_TYPE_EVENT_ID  (0x80000200) — drop events by ID
//   EVENT_FILTER_TYPE_EVENT_NAME(0x80000400) — drop events by name
//   EVENT_FILTER_TYPE_STACKWALK (0x80001000) — suppress stack collection
//   EVENT_FILTER_TYPE_PID       (0x80000010) — restrict to specific PIDs
//
// This hook logs all EnableTraceEx2 calls with filter descriptors and
// emits Critical alerts when dangerous filter types are used.
// ---------------------------------------------------------------------------
static ULONG WINAPI Hook_EnableTraceEx2(
    ULONG_PTR TraceHandle, const GUID* ProviderId, ULONG ControlCode,
    UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
    ULONG Timeout, ENABLE_TRACE_PARAMETERS_HOOK* EnableParameters)
{
    // Detect provider removal from trace session (EVENT_CONTROL_CODE_DISABLE_PROVIDER)
    // Attack: `logman update trace <name> --p <provider> --ets` or direct
    // sechost!EnableTraceEx2(..., ControlCode=0, ...) to silently unhook a
    // security provider from a running session without stopping the session.
    if (ControlCode == 0) {
        char pdet[384];
        if (ProviderId) {
            _snprintf_s(pdet, sizeof(pdet), _TRUNCATE,
                "EnableTraceEx2(DISABLE): provider {%08lX-%04X-%04X-%02X%02X-"
                "%02X%02X%02X%02X%02X%02X} removed from session handle=0x%llX "
                "— provider unhooked from running trace (T1562.002)",
                ProviderId->Data1, ProviderId->Data2, ProviderId->Data3,
                ProviderId->Data4[0], ProviderId->Data4[1],
                ProviderId->Data4[2], ProviderId->Data4[3],
                ProviderId->Data4[4], ProviderId->Data4[5],
                ProviderId->Data4[6], ProviderId->Data4[7],
                (unsigned long long)TraceHandle);
        } else {
            _snprintf_s(pdet, sizeof(pdet), _TRUNCATE,
                "EnableTraceEx2(DISABLE): NULL provider GUID on session "
                "handle=0x%llX — mass provider removal (T1562.002)",
                (unsigned long long)TraceHandle);
        }
        SendHookEvent("Critical", "EnableTraceEx2", 0, pdet);
    }

    // Detect keyword downgrade: MatchAnyKeyword=0 with enable silently drops all
    if (ControlCode == 1 && MatchAnyKeyword == 0) {
        SendHookEvent("Critical", "EnableTraceEx2",
            0, "MatchAnyKeyword=0 — ALL events silently filtered, "
               "provider appears enabled but blind (T1562.002)");
    }

    // Detect level downgrade to Critical-only
    if (ControlCode == 1 && Level == 1) {
        SendHookEvent("Critical", "EnableTraceEx2",
            0, "Level=1 (Critical only) — Info/Warning/Error events "
               "silently suppressed (T1562.002)");
    }

    // Inspect filter descriptors
    if (EnableParameters != nullptr && EnableParameters->FilterDescCount > 0) {
        ULONG fdCount = EnableParameters->FilterDescCount;

        // Cap inspection to prevent abuse
        if (fdCount > 64) fdCount = 64;

        static const struct {
            ULONG type;
            const char* name;
        } kDangerousTypes[] = {
            { 0x80000100, "PAYLOAD" },
            { 0x80000200, "EVENT_ID" },
            { 0x80000400, "EVENT_NAME" },
            { 0x80001000, "STACKWALK" },
            { 0x80000800, "SCHEMATIZED" },
            { 0x80000010, "PID" },
        };

        // EVENT_FILTER_DESCRIPTOR: { ULONGLONG Ptr; ULONG Size; ULONG Type; }
        struct FilterDesc { ULONGLONG Ptr; ULONG Size; ULONG Type; };
        FilterDesc* fdArr = (FilterDesc*)EnableParameters->EnableFilterDesc;

        char det[384];
        _snprintf_s(det, sizeof(det), _TRUNCATE,
            "EnableTraceEx2: %lu filter descriptor(s) attached — "
            "event suppression filters detected (T1562.002)",
            EnableParameters->FilterDescCount);
        SendHookEvent("Warning", "EnableTraceEx2", 0, det);

        if (fdArr) {
            __try {
                for (ULONG i = 0; i < fdCount; i++) {
                    for (auto& dt : kDangerousTypes) {
                        if (fdArr[i].Type == dt.type) {
                            char fdDet[384];
                            _snprintf_s(fdDet, sizeof(fdDet), _TRUNCATE,
                                "EnableTraceEx2: DANGEROUS filter type %s "
                                "(0x%08lX) — silently drops matching events "
                                "(size=%lu bytes) (T1562.002)",
                                dt.name, dt.type, fdArr[i].Size);
                            SendHookEvent("Critical", "EnableTraceEx2", 0, fdDet);
                            break;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    return ((FnEnableTraceEx2)GetCallThrough(IDX_ENABLETRACEEX2))(
        TraceHandle, ProviderId, ControlCode, Level,
        MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters);
}

// ---------------------------------------------------------------------------
// Hook_EtwEventWrite — detects attacker-nulled REGHANDLE.
//
// Attack: malware locates a provider's REGHANDLE variable (typically a global
// in the providing DLL, returned by EventRegister) and zeroes it directly in
// memory.  The target code still calls EventWrite, but with handle=0 — ETW
// silently drops the event because the registration slot is invalid.
//
// Normal call sites either check `if (handle)` before writing, or only arrive
// here AFTER a successful EventRegister — so a handle=0 in this hook is
// strong evidence of tampering.  Rate-limited to bound perf overhead on this
// hot path.
// ---------------------------------------------------------------------------
static volatile LONG g_nullRegHandleAlerted = 0;
static ULONG NTAPI Hook_EtwEventWrite(
    REGHANDLE RegHandle, PVOID EventDescriptor,
    ULONG UserDataCount, PVOID UserData)
{
    if (RegHandle == 0 &&
        InterlockedCompareExchange(&g_nullRegHandleAlerted, 1, 0) == 0)
    {
        SendHookEvent("Critical", "EtwEventWrite_NullRegHandle", 0,
            "EtwEventWrite called with RegHandle=0 — provider REGHANDLE "
            "zeroed in caller memory, events silently dropped (T1562.002)");
    }
    return ((FnEtwEventWrite)GetCallThrough(IDX_ETWEVENTWRITE))(
        RegHandle, EventDescriptor, UserDataCount, UserData);
}

// ---------------------------------------------------------------------------
// Hook_EventAccessControl — detects session/provider security descriptor
// rewrites.  EventAccessControl modifies the DACL on an ETW provider or
// session GUID, granting arbitrary SIDs rights like TRACELOG_GUID_ENABLE
// or WMIGUID_NOTIFICATION.  Legitimate callers are rare (wevtutil, logman,
// session-creation installers).  Any call from non-trusted code is a strong
// signal of a session-takeover prep step.
// ---------------------------------------------------------------------------
static ULONG WINAPI Hook_EventAccessControl(
    LPGUID Guid, ULONG Operation, PSID Sid, ULONG Rights, BOOLEAN AllowOrDeny)
{
    char guidStr[64] = "<null>";
    if (Guid) {
        _snprintf_s(guidStr, sizeof(guidStr), _TRUNCATE,
            "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            Guid->Data1, Guid->Data2, Guid->Data3,
            Guid->Data4[0], Guid->Data4[1], Guid->Data4[2], Guid->Data4[3],
            Guid->Data4[4], Guid->Data4[5], Guid->Data4[6], Guid->Data4[7]);
    }
    // Operation: 0=EventSecuritySetDACL, 1=EventSecuritySetSACL,
    // 2=EventSecurityAddDACL, 3=EventSecurityAddSACL
    char det[384];
    _snprintf_s(det, sizeof(det), _TRUNCATE,
        "EventAccessControl: Guid=%s Op=%lu Rights=0x%08lX Allow=%u — "
        "session/provider DACL %s, possible access grant to rogue SID for "
        "subsequent session takeover (T1562.002)",
        guidStr, Operation, Rights, AllowOrDeny,
        (Operation == 0 || Operation == 2) ? "modified" : "SACL changed");
    SendHookEvent("Critical", "EventAccessControl", 0, det);

    return ((FnEventAccessControl)GetCallThrough(IDX_EVENTACCESSCONTROL))(
        Guid, Operation, Sid, Rights, AllowOrDeny);
}

// ---------------------------------------------------------------------------
// Hook_OpenTraceW — detects rogue real-time consumers attaching to live
// ETW sessions.  EVENT_TRACE_REAL_TIME_MODE (0x100) in the logfile mode
// means the caller wants live event delivery.  Only a narrow set of
// processes legitimately consume real-time: Event Viewer (mmc.exe),
// logman.exe, wevtutil.exe, Sysmon, the Windows SDK xperf tools, and us.
// Any other caller performing a real-time attach is suspicious.
// ---------------------------------------------------------------------------
static ULONG_PTR WINAPI Hook_OpenTraceW(PVOID Logfile)
{
    // EVENT_TRACE_LOGFILEW layout (offsets stable across Win7+):
    //   +0x00 LPWSTR LogFileName
    //   +0x08 LPWSTR LoggerName
    //   +0x10 LONGLONG CurrentTime
    //   +0x18 ULONG BuffersRead
    //   +0x1C ULONG LogFileMode
    ULONG logFileMode = 0;
    WCHAR loggerName[128] = {};
    if (Logfile) {
        __try {
            logFileMode = *(PULONG)((PUCHAR)Logfile + 0x1C);
            LPWSTR ln = *(LPWSTR*)((PUCHAR)Logfile + 0x08);
            if (ln) {
                for (int i = 0; i < 127 && ln[i]; i++) loggerName[i] = ln[i];
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (logFileMode & 0x100 /* EVENT_TRACE_REAL_TIME_MODE */) {
        char exeName[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exeName, sizeof(exeName));
        const char* base = exeName;
        for (const char* p = exeName; *p; p++)
            if (*p == '\\' || *p == '/') base = p + 1;

        bool trusted =
            _stricmp(base, "mmc.exe")       == 0 ||  // Event Viewer
            _stricmp(base, "logman.exe")    == 0 ||
            _stricmp(base, "wevtutil.exe")  == 0 ||
            _stricmp(base, "tracerpt.exe")  == 0 ||
            _stricmp(base, "xperf.exe")     == 0 ||
            _stricmp(base, "wpr.exe")       == 0 ||
            _stricmp(base, "perfmon.exe")   == 0 ||
            _stricmp(base, "Sysmon.exe")    == 0 ||
            _stricmp(base, "Sysmon64.exe")  == 0 ||
            _stricmp(base, "NortonEDR.exe") == 0;

        if (!trusted) {
            char det[400];
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "Rogue real-time ETW consumer: %s attached to session '%ls' "
                "(LogFileMode=0x%08lX) — consumer intercepts events live "
                "before any file write, can drop/modify events in transit "
                "(T1562.002)",
                base, loggerName[0] ? loggerName : L"<unknown>", logFileMode);
            SendHookEvent("Critical", "OpenTraceW_RogueConsumer", 0, det);
        }
    }

    return ((FnOpenTraceW)GetCallThrough(IDX_OPENTRACEW))(Logfile);
}

// ---------------------------------------------------------------------------
// Hook_EtwEventRegister — Dylan Hall "Universally Evading Sysmon and ETW".
//
// Attack: the attacker walks ntdll!EtwpRegistrationTable in user-mode and
// overwrites _ETW_REG_ENTRY.EnableMask (and optionally .Callback) to zero.
// Subsequent EtwEventWrite calls bail out in the "am I enabled?" check and
// never trap to kernel, so the kernel-side baseline we maintain never sees
// tampering.  We backstop by baselining EnableMask byte directly in the
// user-mode struct, which we can locate via the returned REGHANDLE.
//
// REGHANDLE encoding (pre-20H1): bits [63:16] = _ETW_REG_ENTRY pointer.
// On 20H1+ the handle encodes a table index and obfuscation; we fall back
// to a probe heuristic that scans a narrow range around the observed
// handle for the provider GUID and anchors on that.
// ---------------------------------------------------------------------------
struct EtwRegBaseline {
    REGHANDLE regHandle;
    GUID      providerGuid;
    PVOID     regEntryAddr;      // nullptr if not resolvable on this build
    UCHAR     enableMaskBaseline;
    PVOID     callbackBaseline;
    bool      valid;
    bool      tampered;          // one-shot alert latch
};

static CRITICAL_SECTION g_etwRegCs;
static EtwRegBaseline  g_etwRegs[128];
static volatile LONG   g_etwRegCount = 0;
static bool            g_etwRegCsInit = false;

static PVOID ResolveEtwRegEntry(REGHANDLE h) {
    // Pre-20H1: _ETW_REG_ENTRY* = (h >> 16) sign-extended; pointer must
    // be a kernel-looking user-heap address (ntdll private heap) —
    // validate via MEM_COMMIT + PAGE_READWRITE probe.
    ULONGLONG candidate = (ULONGLONG)(h >> 16);
    // User-mode heap lives below 0x00007FFFFFFFFFFF
    if (candidate == 0 || candidate > 0x00007FFFFFFFFFFFULL) return nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)candidate, &mbi, sizeof(mbi)) == 0) return nullptr;
    if (mbi.State != MEM_COMMIT) return nullptr;
    if (!(mbi.Protect & (PAGE_READWRITE | PAGE_READONLY))) return nullptr;
    return (PVOID)candidate;
}

// Offsets within _ETW_REG_ENTRY that vary by build.  We scan a window
// around the resolved struct for a matching provider GUID and lock our
// EnableMask offset relative to that anchor.
static bool CaptureRegEntryBaseline(EtwRegBaseline* b) {
    if (!b->regEntryAddr) return false;
    __try {
        // Scan first 0x100 bytes of the struct for the provider GUID.
        // When found, typical layouts place EnableMask ~0x28..0x30 after
        // the GUID anchor.  We baseline a conservative 8-byte window.
        PUCHAR p = (PUCHAR)b->regEntryAddr;
        for (ULONG off = 0; off < 0x100; off += 8) {
            if (memcmp(p + off, &b->providerGuid, sizeof(GUID)) == 0) {
                // Try offsets {0x28, 0x30, 0x20} after GUID anchor for EnableMask
                ULONG kMaskOffsets[] = { 0x28, 0x30, 0x20 };
                for (ULONG mo : kMaskOffsets) {
                    UCHAR m = *(p + off + mo);
                    if (m != 0) {
                        b->enableMaskBaseline = m;
                        b->regEntryAddr = (PVOID)(p + off); // re-anchor to GUID
                        // Callback is typically further out; capture at +0x38/+0x40/+0x48
                        b->callbackBaseline = *(PVOID*)(p + off + 0x40);
                        return true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

static ULONG NTAPI Hook_EtwEventRegister(
    LPCGUID ProviderId, PVOID EnableCallback, PVOID CallbackContext,
    REGHANDLE* RegHandle)
{
    ULONG status = ((FnEtwEventRegister)GetCallThrough(IDX_ETWEVENTREGISTER))(
        ProviderId, EnableCallback, CallbackContext, RegHandle);

    if (status == 0 /*ERROR_SUCCESS*/ && RegHandle && *RegHandle != 0 && ProviderId) {
        if (!g_etwRegCsInit) return status;

        EnterCriticalSection(&g_etwRegCs);
        LONG idx = InterlockedCompareExchange(&g_etwRegCount, 0, 0);
        if (idx < (LONG)(sizeof(g_etwRegs) / sizeof(g_etwRegs[0]))) {
            EtwRegBaseline* b = &g_etwRegs[idx];
            b->regHandle    = *RegHandle;
            b->providerGuid = *ProviderId;
            b->regEntryAddr = ResolveEtwRegEntry(*RegHandle);
            b->enableMaskBaseline = 0;
            b->callbackBaseline = nullptr;
            b->tampered = false;
            b->valid = CaptureRegEntryBaseline(b);
            // Even if direct baseline failed, keep the REGHANDLE for the
            // layer-1 functional probe (EtwEventEnabled call below).
            InterlockedIncrement(&g_etwRegCount);
        }
        LeaveCriticalSection(&g_etwRegCs);
    }
    return status;
}

// Functional probe + struct-diff check — called from WatchThreadProc tick.
typedef BOOLEAN (NTAPI *FnEtwEventEnabled)(REGHANDLE, PVOID);
static void CheckEtwRegistrations() {
    if (!g_etwRegCsInit) return;

    static FnEtwEventEnabled pEtwEventEnabled = nullptr;
    if (!pEtwEventEnabled) {
        HMODULE h = GetModuleHandleW(L"ntdll.dll");
        if (h) pEtwEventEnabled =
            (FnEtwEventEnabled)GetProcAddress(h, "EtwEventEnabled");
    }

    EnterCriticalSection(&g_etwRegCs);
    LONG n = InterlockedCompareExchange(&g_etwRegCount, 0, 0);
    for (LONG i = 0; i < n; i++) {
        EtwRegBaseline* b = &g_etwRegs[i];
        if (b->tampered) continue;

        // --- Layer 2: direct struct-byte diff ---
        if (b->valid && b->regEntryAddr && b->enableMaskBaseline != 0) {
            __try {
                PUCHAR anchor = (PUCHAR)b->regEntryAddr; // GUID anchor
                bool hit = false;
                ULONG kMaskOffsets[] = { 0x28, 0x30, 0x20 };
                for (ULONG mo : kMaskOffsets) {
                    UCHAR cur = *(anchor + mo);
                    if (cur == 0 && b->enableMaskBaseline != 0) {
                        char det[384];
                        _snprintf_s(det, sizeof(det), _TRUNCATE,
                            "User-mode _ETW_REG_ENTRY.EnableMask zeroed "
                            "(was 0x%02X) for provider "
                            "{%08lX-%04X-%04X-...} — Dylan Hall technique, "
                            "provider silently suppressed (T1562.002)",
                            b->enableMaskBaseline,
                            b->providerGuid.Data1, b->providerGuid.Data2,
                            b->providerGuid.Data3);
                        SendHookEvent("Critical", "EtwRegEntry_Tamper", 0, det);
                        // Restore under VirtualProtect
                        DWORD old = 0;
                        if (VirtualProtect(anchor + mo, 1, PAGE_READWRITE, &old)) {
                            *(anchor + mo) = b->enableMaskBaseline;
                            VirtualProtect(anchor + mo, 1, old, &old);
                        }
                        b->tampered = true;
                        hit = true;
                        break;
                    }
                }
                if (!hit && b->callbackBaseline) {
                    PVOID curCb = *(PVOID*)(anchor + 0x40);
                    if (curCb != b->callbackBaseline) {
                        char det[384];
                        _snprintf_s(det, sizeof(det), _TRUNCATE,
                            "User-mode _ETW_REG_ENTRY.Callback hijacked for "
                            "{%08lX-...} (baseline=%p current=%p) — "
                            "provider redirected to attacker handler (T1562.002)",
                            b->providerGuid.Data1,
                            b->callbackBaseline, curCb);
                        SendHookEvent("Critical", "EtwRegEntry_Tamper", 0, det);
                        DWORD old = 0;
                        if (VirtualProtect(anchor + 0x40, sizeof(PVOID),
                                           PAGE_READWRITE, &old)) {
                            *(PVOID*)(anchor + 0x40) = b->callbackBaseline;
                            VirtualProtect(anchor + 0x40, sizeof(PVOID), old, &old);
                        }
                        b->tampered = true;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // --- Layer 1: functional probe (version-agnostic backstop) ---
        // If EtwEventEnabled returns FALSE for every reasonable level,
        // the provider is disabled.  Since we don't track legitimate
        // disables via NtTraceControl(31) in user-mode, rely on kernel
        // correlation — here we only alert if struct-diff already showed
        // tamper but we missed the exact byte (e.g., 20H1+ layout shift).
        if (!b->tampered && pEtwEventEnabled && !b->valid) {
            __try {
                BOOLEAN en = pEtwEventEnabled(b->regHandle, nullptr);
                // Without a kernel legitimate-disable feed, we can't
                // distinguish attacker-disable from admin-disable here,
                // so leave this probe informational / telemetry only.
                (void)en;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    LeaveCriticalSection(&g_etwRegCs);
}

// ---------------------------------------------------------------------------
// Authentication downgrade detection — SSPI hooks (T1556.001)
//
// 1. AcquireCredentialsHandleW — monitors which authentication package is
//    requested.  Explicit "NTLM" or "WDigest" acquisition from a non-system
//    process is suspicious (mimikatz sekurlsa, ntlmrelayx, Inveigh).
//    Legitimate apps use "Negotiate" which prefers Kerberos.
//
// 2. InitializeSecurityContextW — monitors the target SPN.  When pszTargetName
//    is NULL or contains "NTLM" (forced NTLM instead of Kerberos), the
//    Negotiate SSP falls back to NTLM — this is the runtime downgrade.
//    Also detects missing SPN (common in relay attacks where the attacker
//    intentionally omits the SPN to force NTLM).
// ---------------------------------------------------------------------------

// Case-insensitive wide-string comparison for SSP package names.
static bool WideStrEqualI(const wchar_t* a, const wchar_t* b) {
    if (!a || !b) return false;
    for (int i = 0; ; i++) {
        wchar_t ca = (a[i] >= L'A' && a[i] <= L'Z') ? a[i] + 32 : a[i];
        wchar_t cb = (b[i] >= L'A' && b[i] <= L'Z') ? b[i] + 32 : b[i];
        if (ca != cb) return false;
        if (ca == L'\0') return true;
    }
}

// Processes that legitimately acquire NTLM credentials (lsass, svchost, etc.).
static bool IsSspiTrustedProcess() {
    char name[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, name, sizeof(name))) return false;
    // Extract just the filename
    const char* base = name;
    for (const char* p = name; *p; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    return (_stricmp(base, "lsass.exe")    == 0 ||
            _stricmp(base, "svchost.exe")  == 0 ||
            _stricmp(base, "services.exe") == 0 ||
            _stricmp(base, "winlogon.exe") == 0 ||
            _stricmp(base, "System")       == 0 ||
            _stricmp(base, "NortonEDR.exe") == 0);
}

static LONG WINAPI Hook_AcquireCredentialsHandleW(
    wchar_t* pszPrincipal, wchar_t* pszPackage, ULONG fCredentialUse,
    PVOID pvLogonID, PVOID pAuthData, PVOID pGetKeyFn,
    PVOID pvGetKeyArgument, PCredHandle phCredential, PLARGE_INTEGER ptsExpiry)
{
    typedef LONG(WINAPI* Fn)(wchar_t*, wchar_t*, ULONG, PVOID, PVOID,
                              PVOID, PVOID, PCredHandle, PLARGE_INTEGER);

    // Flag explicit NTLM / WDigest / LM package acquisition from non-system processes.
    // Legitimate apps use "Negotiate" (which tries Kerberos first).
    if (pszPackage && !IsSspiTrustedProcess()) {
        bool isNtlm    = WideStrEqualI(pszPackage, L"NTLM");
        bool isWDigest = WideStrEqualI(pszPackage, L"WDigest");

        if (isNtlm || isWDigest) {
            char det[200];
            char pkgA[32] = {};
            for (int i = 0; i < 31 && pszPackage[i]; i++)
                pkgA[i] = (char)(pszPackage[i] & 0x7F);
            _snprintf_s(det, sizeof(det), _TRUNCATE,
                "Auth downgrade (T1556.001): explicit %s credential acquisition "
                "— non-Negotiate auth enables relay/downgrade attacks",
                pkgA);
            SendHookEvent(isWDigest ? "Critical" : "Warning",
                "AcquireCredentialsHandleW", 0, det);
        }
    }

    return ((Fn)GetCallThrough(IDX_ACQUIRECREDENTIALSHANDLEW))(
        pszPrincipal, pszPackage, fCredentialUse, pvLogonID, pAuthData,
        pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}

static LONG WINAPI Hook_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, wchar_t* pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, ULONG* pfContextAttr, PLARGE_INTEGER ptsExpiry)
{
    typedef LONG(WINAPI* Fn)(PCredHandle, PCtxtHandle, wchar_t*, ULONG, ULONG,
                              ULONG, PSecBufferDesc, ULONG, PCtxtHandle,
                              PSecBufferDesc, ULONG*, PLARGE_INTEGER);

    if (!IsSspiTrustedProcess()) {
        // Detection 1: NULL target SPN — forces NTLM fallback.
        // Legitimate Kerberos auth always specifies an SPN (e.g., "HTTP/server.domain").
        // Relay tools (ntlmrelayx, Inveigh) omit the SPN to force NTLM.
        if (!pszTargetName && !phContext) {
            // First call (phContext==NULL) with no SPN = forced NTLM
            SendHookEvent("Warning", "InitializeSecurityContextW", 0,
                "Auth downgrade (T1556.001): InitializeSecurityContext called "
                "with NULL target SPN — forces Negotiate→NTLM fallback "
                "(relay attack / credential theft)");
        }

        // Detection 2: Target name containing explicit NTLM force-strings.
        // Some attack tools pass pszTargetName = "NTLM" or empty string
        // to override the Negotiate package's Kerberos preference.
        if (pszTargetName && !phContext) {
            bool forceNtlm = (pszTargetName[0] == L'\0') ||
                              WideStrEqualI(pszTargetName, L"NTLM");
            if (forceNtlm) {
                char det[200];
                _snprintf_s(det, sizeof(det), _TRUNCATE,
                    "Auth downgrade (T1556.001): InitializeSecurityContext "
                    "target='%S' — forced NTLM authentication bypass of Kerberos",
                    pszTargetName[0] ? pszTargetName : L"(empty)");
                SendHookEvent("Warning", "InitializeSecurityContextW", 0, det);
            }
        }
    }

    return ((Fn)GetCallThrough(IDX_INITIALIZESECURITYCONTEXTW))(
        phCredential, phContext, pszTargetName, fContextReq, Reserved1,
        TargetDataRep, pInput, Reserved2, phNewContext, pOutput,
        pfContextAttr, ptsExpiry);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void InstallHooks() {
    g_selfPid = GetCurrentProcessId();
    InitializeCriticalSection(&g_pipeLock);
    g_lockInit = true;

    ConnectToPipe();
    InstallAllInlineHooks(); // prologue patches first — catches GetProcAddress callers
    PatchAllModules(false);  // IAT patches catch load-time importers

    // Confirm successful injection to kernel driver — enables injection timeout detection.
    // NORTONAV_HOOKDLL_CONFIRM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
    {
        HANDLE hDev = CreateFileA("\\\\.\\NortonEDR",
            GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDev != INVALID_HANDLE_VALUE) {
            DWORD pid = g_selfPid;
            DWORD returned = 0;
            DeviceIoControl(hDev, 0x00222018,
                &pid, sizeof(pid), nullptr, 0, &returned, nullptr);
            CloseHandle(hDev);
        }
    }

    // Initialize the Dylan-Hall ETW registration baseline list.
    if (!g_etwRegCsInit) {
        InitializeCriticalSection(&g_etwRegCs);
        g_etwRegCsInit = true;
    }

    // Snapshot ETW/AMSI critical function prologues before the watch thread starts.
    // These baselines are checked every 2s to detect XPN-style patching.
    InitCriticalFuncGuards();

    // Snapshot TLS callback arrays for critical modules — detects callback
    // injection/redirection used for persistence and ETW-bypass shims.
    InitTlsGuards();

    // Install first-in-line VEH — catches exception-based hook fires
    // (INT3/PAGE_GUARD/DR0-DR3) that originate inside critical modules,
    // including those registered by malware BEFORE HookDll loaded.
    InstallFirstVeh();

    // Check for ETW-disabling environment variables set BEFORE injection.
    // The CLR reads these at startup — if already set, .NET telemetry is dead.
    CheckEtwEnvironmentVariables();

    // --- Install ETW control API interception hooks ---
    // These are manual IAT-style hooks for APIs that modify ETW provider/session
    // properties from within the process.  Not in the main hook table because
    // they're low-frequency APIs that only need alerting, not full IAT coverage.
    {
        // EventSetInformation — ntdll.dll (modifies provider traits/encoding)
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            g_origEventSetInformation = (FnEventSetInformation)
                GetProcAddress(hNtdll, "EventSetInformation");
        }

        // TraceSetInformation — advapi32.dll / sechost.dll
        HMODULE hAdv = GetModuleHandleA("advapi32.dll");
        if (hAdv) {
            g_origTraceSetInformation = (FnTraceSetInformation)
                GetProcAddress(hAdv, "TraceSetInformation");
        }
        if (!g_origTraceSetInformation) {
            HMODULE hSec = GetModuleHandleA("sechost.dll");
            if (hSec) {
                g_origTraceSetInformation = (FnTraceSetInformation)
                    GetProcAddress(hSec, "TraceSetInformation");
            }
        }

        // EventUnregister — advapi32.dll (provider unregistration)
        if (hAdv) {
            g_origEventUnregister = (FnEventUnregister)
                GetProcAddress(hAdv, "EventUnregister");
        }

        // Add these to the critical function guard list for prologue checks
        // (already covered by g_etwGuards[] entries for EventUnregister/advapi32
        //  and EtwEventUnregister/ntdll — the hooks here add CALL interception
        //  on top of the prologue integrity monitoring).
    }

    // Start the hook-integrity watch thread.
    // WatchThreadProc is inside HookDll so IsAddressInKnownModule() returns true
    // for its start address — Hook_CreateThread won't fire a false alarm.
    g_watchStop = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (g_watchStop)
        g_watchThread = CreateThread(nullptr, 0, WatchThreadProc, nullptr, 0, nullptr);
}

void RemoveHooks() {
    // Stop the watch thread first — it must not run while we're restoring patches,
    // or it may race on inlinePatched/inlineTarget and re-apply a hook mid-restore.
    if (g_watchStop) {
        SetEvent(g_watchStop);
        if (g_watchThread) {
            WaitForSingleObject(g_watchThread, 3000);
            CloseHandle(g_watchThread);
            g_watchThread = nullptr;
        }
        CloseHandle(g_watchStop);
        g_watchStop = nullptr;
    }

    RemoveAllInlineHooks(); // restore prologues before IAT (avoid re-entry during teardown)
    PatchAllModules(true);

    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    if (g_lockInit) {
        DeleteCriticalSection(&g_pipeLock);
        g_lockInit = false;
    }
}

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstDll);

        // Pin the DLL — bump refcount so FreeLibrary from malware cannot unload us.
        // GetModuleHandleEx with GET_MODULE_HANDLE_EX_FLAG_PIN sets the refcount to
        // MAXULONG, making the module permanently loaded until process exit.
        {
            HMODULE hPin = nullptr;
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                (LPCWSTR)DllMain,
                &hPin);
        }

        InstallHooks();
        break;

    case DLL_PROCESS_DETACH:
        // lpReserved != NULL means the process is terminating — safe to clean up.
        // lpReserved == NULL means someone called FreeLibrary — this should not
        // happen since we pinned the DLL, but if it does, alert and refuse.
        if (lpReserved == NULL) {
            SendHookEvent("Critical", "DLL_PROCESS_DETACH",
                g_selfPid,
                "FreeLibrary called on HookDll — "
                "EDR hook removal attempt (DLL should be pinned)");
            return FALSE;  // reject the unload
        }
        RemoveHooks();
        break;
    }
    return TRUE;
}
