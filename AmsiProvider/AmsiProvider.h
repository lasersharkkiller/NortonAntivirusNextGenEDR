#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <objbase.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// AMSI interface definitions (mirrors amsi.h from Windows SDK)
// ---------------------------------------------------------------------------

typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN             = 0,
    AMSI_RESULT_NOT_DETECTED      = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479,
    AMSI_RESULT_DETECTED          = 32768,
} AMSI_RESULT;

typedef enum AMSI_ATTRIBUTE {
    AMSI_ATTRIBUTE_APP_NAME             = 0,
    AMSI_ATTRIBUTE_CONTENT_NAME         = 1,
    AMSI_ATTRIBUTE_CONTENT_SIZE         = 2,
    AMSI_ATTRIBUTE_CONTENT_ADDRESS      = 3,
    AMSI_ATTRIBUTE_SESSION              = 4,
    AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE  = 5,
    AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS = 6,
    AMSI_ATTRIBUTE_ALL_SIZE             = 7,
    AMSI_ATTRIBUTE_ALL_ADDRESS          = 8,
    AMSI_ATTRIBUTE_QUIET                = 9,
} AMSI_ATTRIBUTE;

// IAmsiStream {3e47f2e5-81d4-4d3b-897f-545096770373}
DEFINE_GUID(IID_IAmsiStream,
    0x3e47f2e5, 0x81d4, 0x4d3b, 0x89, 0x7f, 0x54, 0x50, 0x96, 0x77, 0x03, 0x73);

struct __declspec(uuid("3e47f2e5-81d4-4d3b-897f-545096770373"))
IAmsiStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetAttribute(
        AMSI_ATTRIBUTE attribute,
        ULONG dataSize,
        BYTE* data,
        ULONG* retData) = 0;

    virtual HRESULT STDMETHODCALLTYPE Read(
        ULONGLONG position,
        ULONG size,
        BYTE* buffer,
        ULONG* readSize) = 0;
};

// IAntimalwareProvider {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
DEFINE_GUID(IID_IAntimalwareProvider,
    0xb2cabfe3, 0xfe04, 0x42b1, 0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25);

struct __declspec(uuid("b2cabfe3-fe04-42b1-a5df-08d483d4d125"))
IAntimalwareProvider : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Scan(
        IAmsiStream* stream,
        AMSI_RESULT* result) = 0;

    virtual void STDMETHODCALLTYPE CloseSession(
        ULONGLONG session) = 0;

    virtual HRESULT STDMETHODCALLTYPE DisplayName(
        LPWSTR* displayName) = 0;
};

// Provider CLSID: {C18BED31-4E42-4E0F-B00D-A7E3FE09E18D}
DEFINE_GUID(CLSID_NortonAmsiProvider,
    0xC18BED31, 0x4E42, 0x4E0F, 0xB0, 0x0D, 0xA7, 0xE3, 0xFE, 0x09, 0xE1, 0x8D);

static const wchar_t* const kProviderClsidStr =
    L"{C18BED31-4E42-4E0F-B00D-A7E3FE09E18D}";

// ---------------------------------------------------------------------------
// NortonAmsiProvider — IAntimalwareProvider implementation
// ---------------------------------------------------------------------------
class NortonAmsiProvider : public IAntimalwareProvider {
    volatile LONG m_refCount;

public:
    NortonAmsiProvider();
    ~NortonAmsiProvider() = default;

    // IUnknown
    STDMETHODIMP_(ULONG) AddRef()  override;
    STDMETHODIMP_(ULONG) Release() override;
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // IAntimalwareProvider
    STDMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result) override;
    STDMETHODIMP_(void) CloseSession(ULONGLONG session) override;
    STDMETHODIMP DisplayName(LPWSTR* displayName) override;
};

// ---------------------------------------------------------------------------
// NortonAmsiProviderFactory — IClassFactory
// ---------------------------------------------------------------------------
class NortonAmsiProviderFactory : public IClassFactory {
    volatile LONG m_refCount;

public:
    NortonAmsiProviderFactory();
    ~NortonAmsiProviderFactory() = default;

    // IUnknown
    STDMETHODIMP_(ULONG) AddRef()  override;
    STDMETHODIMP_(ULONG) Release() override;
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // IClassFactory
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override;
    STDMETHODIMP LockServer(BOOL fLock) override;
};
