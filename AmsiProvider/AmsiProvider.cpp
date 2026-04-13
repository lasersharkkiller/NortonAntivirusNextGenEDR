#define INITGUID
#include "AmsiProvider.h"
#include <cstdio>
#include <cctype>
#include <new>

// ---------------------------------------------------------------------------
// Module-level ref-count tracking for DllCanUnloadNow
// ---------------------------------------------------------------------------
static volatile LONG g_objectCount = 0;
static volatile LONG g_lockCount   = 0;
static HINSTANCE     g_hModule     = nullptr;

// ---------------------------------------------------------------------------
// Malicious keyword list (lowercase; checked against lowercase content)
// ---------------------------------------------------------------------------
static const char* const kMaliciousKeywords[] = {
    // Mimikatz / credential theft
    "invoke-mimikatz",
    "sekurlsa::logonpasswords",
    "sekurlsa::wdigest",
    "kerberos::ptt",
    "kerberos::golden",
    "kerberos::silver",
    "lsadump::sam",
    "lsadump::dcsync",
    "privilege::debug",
    "token::elevate",
    // PowerShell attack frameworks
    "invoke-shellcode",
    "invoke-reflectivepeinjection",
    "invoke-bloodhound",
    "powersploit",
    "powerup",
    "powerview",
    "sharphound",
    // AMSI bypass reflection patterns
    "amsibypass",
    "amsiutils",
    "amsicontext",
    "[ref].assembly.gettype",
    "system.management.automation.amsi",
    // Shellcode / loader patterns
    "virtualalloc",          // in script context
    "createthread",          // in script context
    "shellcode",
    "meterpreter",
    "cobaltstrike",
    // Network stager patterns
    "downloadstring(",
    "downloaddata(",
    "net.webclient",
    "wscript.shell",
    // ---------------------------------------------------------------
    // Web shell signatures — China Chopper, Godzilla, Behinder/Bingxie,
    // AntSword, and generic ASPX/JSP/PHP web shell patterns.
    // ---------------------------------------------------------------
    // China Chopper (classic one-liner web shell)
    "eval(request",                    // eval(Request.Item["..."])
    "eval(request.item",               // exact China Chopper pattern
    "execute(request(",                // ASP classic variant
    "eval request(",                   // VBScript variant
    "<%eval request",                  // raw ASP China Chopper
    "response.write(eval(",            // response eval variant
    // Godzilla web shell
    "gaborone",                        // Godzilla default session key
    "pass=",                           // Godzilla password parameter
    "javax.crypto.cipher",             // Godzilla Java AES encryption
    "aesencode",                       // Godzilla C# AES encryption helper
    "createaescipher",                 // Godzilla AES cipher creation
    // Behinder (Bingxie) web shell
    "behinder",                        // tool name reference
    "e45e329feb5d925b",                // Behinder default AES key MD5 prefix
    "javax.crypto.spec.secretkeyspec", // Behinder Java AES key spec
    "aes/ecb/pkcs5padding",            // Behinder AES mode (ECB is unusual)
    "classloader.defineclass",         // Behinder runtime class loading
    "assembly.load(convert.frombase64string", // Behinder .NET payload loading
    // AntSword web shell
    "antsword",                        // tool name reference
    "ant_",                            // AntSword default parameter prefix
    "asoutputstream",                  // AntSword Java output stream pattern
    "@eval(base64_decode(",            // AntSword PHP base64 eval
    "assert(base64_decode(",           // AntSword PHP assert variant
    // Generic web shell patterns
    "system.reflection.assembly.load", // .NET reflective assembly load (web shells)
    "processbuilder(",                 // Java command execution
    "runtime.getruntime().exec(",      // Java Runtime.exec
    "unsafe.eval(",                    // unsafe eval wrapper
    "frombase64string",                // base64 decode + assembly load combo
    "thread_start(system.delegate",    // .NET thread-based execution
    "httppostedfile",                  // file upload control (web shell dropper)
    "file_put_contents(",              // PHP file write (web shell dropper)
    "passthru(",                       // PHP command execution
    "system(",                         // PHP/Python command execution (in script context)
    "proc_open(",                      // PHP process execution
    "pcntl_exec(",                     // PHP direct exec
    nullptr
};

// ---------------------------------------------------------------------------
// Log a detection event to a file alongside the EDR binary
// ---------------------------------------------------------------------------
static void LogDetection(const wchar_t* contentName, const char* keyword) {
    FILE* f = nullptr;
    if (fopen_s(&f, "norton_amsi_detections.log", "a") != 0 || !f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f,
        "[%04d-%02d-%02d %02d:%02d:%02d] DETECTED keyword=\"%s\" content=\"%ls\"\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        keyword,
        contentName ? contentName : L"<unknown>");
    fclose(f);
}

// ---------------------------------------------------------------------------
// NortonAmsiProvider — IUnknown
// ---------------------------------------------------------------------------
NortonAmsiProvider::NortonAmsiProvider() : m_refCount(1) {
    InterlockedIncrement(&g_objectCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProvider::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProvider::Release() {
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) {
        InterlockedDecrement(&g_objectCount);
        delete this;
    }
    return ref;
}

STDMETHODIMP NortonAmsiProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// ---------------------------------------------------------------------------
// NortonAmsiProvider::Scan — core detection logic
// ---------------------------------------------------------------------------
STDMETHODIMP NortonAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_CLEAN;

    try {
        // Retrieve content size
        ULONGLONG contentSize = 0;
        ULONG returned = 0;
        HRESULT hr = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_SIZE,
            sizeof(contentSize), (BYTE*)&contentSize, &returned);
        if (FAILED(hr) || returned < sizeof(contentSize) || contentSize == 0)
            return S_OK;

        // Cap to 8 MB to bound scan time
        if (contentSize > 8ULL * 1024 * 1024)
            contentSize = 8ULL * 1024 * 1024;

        // Try to get a direct pointer to the content
        ULONG_PTR contentAddr = 0;
        hr = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_ADDRESS,
            sizeof(contentAddr), (BYTE*)&contentAddr, &returned);

        std::vector<BYTE> readBuf;
        const BYTE* bytes = nullptr;
        ULONG byteCount = 0;

        if (SUCCEEDED(hr) && contentAddr != 0) {
            bytes     = reinterpret_cast<const BYTE*>(contentAddr);
            byteCount = static_cast<ULONG>(contentSize);
        } else {
            // Fall back to IAmsiStream::Read
            readBuf.resize(static_cast<size_t>(contentSize));
            ULONG readSize = 0;
            hr = stream->Read(0, static_cast<ULONG>(contentSize), readBuf.data(), &readSize);
            if (FAILED(hr) || readSize == 0) return S_OK;
            bytes     = readBuf.data();
            byteCount = readSize;
        }

        // Build a lowercase searchable string.
        // Handle both wide (UTF-16 LE) and narrow (ANSI/UTF-8) content.
        // Heuristic: if the second byte is NUL, treat as wide.
        std::string searchable;
        searchable.reserve(byteCount);

        bool isWide = (byteCount >= 2 && bytes[1] == 0);
        if (isWide) {
            const wchar_t* wptr = reinterpret_cast<const wchar_t*>(bytes);
            ULONG wlen = byteCount / 2;
            for (ULONG i = 0; i < wlen; i++) {
                wchar_t wc = wptr[i];
                searchable += (wc < 0x80)
                    ? static_cast<char>(tolower(static_cast<unsigned char>(wc)))
                    : '?';
            }
        } else {
            for (ULONG i = 0; i < byteCount; i++) {
                searchable += static_cast<char>(tolower(static_cast<unsigned char>(bytes[i])));
            }
        }

        // Scan for malicious keywords
        const char* hitKeyword = nullptr;
        for (int i = 0; kMaliciousKeywords[i]; i++) {
            if (searchable.find(kMaliciousKeywords[i]) != std::string::npos) {
                hitKeyword = kMaliciousKeywords[i];
                break;
            }
        }

        if (hitKeyword) {
            *result = AMSI_RESULT_DETECTED;

            // Get content name for logging
            PWSTR contentName = nullptr;
            ULONG nameRet = 0;
            stream->GetAttribute(
                AMSI_ATTRIBUTE_CONTENT_NAME,
                sizeof(contentName), (BYTE*)&contentName, &nameRet);

            LogDetection(contentName, hitKeyword);
        }
    }
    catch (...) {
        // Never crash the host process
    }

    return S_OK;
}

STDMETHODIMP_(void) NortonAmsiProvider::CloseSession(ULONGLONG /*session*/) {}

STDMETHODIMP NortonAmsiProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_INVALIDARG;
    const wchar_t* name = L"NortonAntivirusNextGenEDR";
    size_t len = wcslen(name) + 1;
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
    if (!*displayName) return E_OUTOFMEMORY;
    wcscpy_s(*displayName, len, name);
    return S_OK;
}

// ---------------------------------------------------------------------------
// NortonAmsiProviderFactory — IClassFactory
// ---------------------------------------------------------------------------
NortonAmsiProviderFactory::NortonAmsiProviderFactory() : m_refCount(1) {}

STDMETHODIMP_(ULONG) NortonAmsiProviderFactory::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

STDMETHODIMP_(ULONG) NortonAmsiProviderFactory::Release() {
    LONG ref = InterlockedDecrement(&m_refCount);
    if (ref == 0) delete this;
    return ref;
}

STDMETHODIMP NortonAmsiProviderFactory::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

STDMETHODIMP NortonAmsiProviderFactory::CreateInstance(
    IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;

    NortonAmsiProvider* provider = new (std::nothrow) NortonAmsiProvider();
    if (!provider) return E_OUTOFMEMORY;

    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();
    return hr;
}

STDMETHODIMP NortonAmsiProviderFactory::LockServer(BOOL fLock) {
    if (fLock) InterlockedIncrement(&g_lockCount);
    else       InterlockedDecrement(&g_lockCount);
    return S_OK;
}

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_hModule = hinstDLL;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// COM exports
// ---------------------------------------------------------------------------
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_NortonAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;

    NortonAmsiProviderFactory* factory =
        new (std::nothrow) NortonAmsiProviderFactory();
    if (!factory) return E_OUTOFMEMORY;

    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return (g_lockCount == 0 && g_objectCount == 0) ? S_OK : S_FALSE;
}

// ---------------------------------------------------------------------------
// Self-registration helpers
// ---------------------------------------------------------------------------
static LONG WriteRegSz(HKEY root, const wchar_t* path, const wchar_t* name,
                        const wchar_t* value) {
    HKEY hKey = nullptr;
    LONG r = RegCreateKeyExW(root, path, 0, nullptr, REG_OPTION_NON_VOLATILE,
                             KEY_WRITE, nullptr, &hKey, nullptr);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(hKey, name, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(value),
                       static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return r;
}

STDAPI DllRegisterServer() {
    WCHAR dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    // HKLM\SOFTWARE\Classes\CLSID\{...}\InProcServer32 = <path>
    WCHAR keyPath[300];
    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32", kProviderClsidStr);

    LONG r = WriteRegSz(HKEY_LOCAL_MACHINE, keyPath, nullptr, dllPath);
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);

    r = WriteRegSz(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);

    // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{...}
    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", kProviderClsidStr);

    HKEY hKey = nullptr;
    r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &hKey, nullptr);
    if (r == ERROR_SUCCESS) RegCloseKey(hKey);

    return S_OK;
}

STDAPI DllUnregisterServer() {
    WCHAR keyPath[300];

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Classes\\CLSID\\%s", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    swprintf_s(keyPath, ARRAYSIZE(keyPath),
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", kProviderClsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath);

    return S_OK;
}
