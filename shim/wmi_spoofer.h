/*
   Ghost Sandbox — WMI/COM Query Interceptor
   Hooks IWbemLocator::ConnectServer to reach the IWbemServices object, then
   wraps ExecQuery / CreateInstanceEnum / GetObject so every hardware class
   object a target enumerates carries the profile's identity.

   WMI enumerators are consumed lazily, so the interception happens in a
   custom IEnumWbemClassObject wrapper that rewrites each object as the
   caller pulls it. (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#include <windows.h>
#include <objbase.h>
#include <wbemidl.h>
#include <stdio.h>
#include <string.h>
#include "trace_format.h"
#include "hw_spoofer.h"
#include "hw_identity.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* ─── Forward declarations ───────────────────────────────── */
extern PipeClient g_Pipe;
extern BOOL g_TracingPaused;

/* ─── Original function pointers ─────────────────────────── */
typedef HRESULT (WINAPI *PFN_CoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, REFIID riid, LPVOID* ppv);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ConnectServer)(
    IWbemLocator* pThis, const BSTR strNetworkResource, const BSTR strUser,
    const BSTR strPassword, const BSTR strLocale, LONG lSecurityFlags,
    const BSTR strAuthority, IWbemContext* pCtx, IWbemServices** ppNamespace);

typedef HRESULT (STDMETHODCALLTYPE *PFN_ExecQuery)(
    IWbemServices* pThis, const BSTR strQueryLanguage, const BSTR strQuery,
    long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum);

typedef HRESULT (STDMETHODCALLTYPE *PFN_GetObject)(
    IWbemServices* pThis, const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
    IWbemClassObject** ppObject, IWbemCallResult** ppCallResult);

typedef HRESULT (STDMETHODCALLTYPE *PFN_CreateInstanceEnum)(
    IWbemServices* pThis, const BSTR strFilter, long lFlags, IWbemContext* pCtx,
    IEnumWbemClassObject** ppEnum);

static PFN_CoCreateInstance  Real_CoCreateInstance  = NULL;
static PFN_ConnectServer     Real_ConnectServer     = NULL;
static PFN_ExecQuery         Real_ExecQuery         = NULL;
static PFN_GetObject         Real_GetObject         = NULL;
static PFN_CreateInstanceEnum Real_CreateInstanceEnum = NULL;
static BOOL g_WmiLocatorHooked  = FALSE;
static BOOL g_WmiServicesHooked = FALSE;

/* ─── WMI Query Classification ───────────────────────────── */
enum WmiQueryType {
    WMI_UNKNOWN = 0,
    WMI_PROCESSOR,
    WMI_VIDEO_CONTROLLER,
    WMI_BASEBOARD,
    WMI_PHYSICAL_MEMORY,
    WMI_MEMORY_ARRAY,
    WMI_DISK_DRIVE,
    WMI_NETWORK_ADAPTER,
    WMI_COMPUTER_SYSTEM,
    WMI_BIOS,
    WMI_CS_PRODUCT,
};

/* Case-insensitive substring search for WQL class names. */
static BOOL WmiContainsCI(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle) return FALSE;
    size_t nl = wcslen(needle);
    if (nl == 0) return TRUE;
    for (const wchar_t* p = hay; *p; ++p) {
        if (_wcsnicmp(p, needle, nl) == 0) return TRUE;
    }
    return FALSE;
}

static WmiQueryType ClassifyWmiQuery(const wchar_t* query) {
    if (!query) return WMI_UNKNOWN;

    if (WmiContainsCI(query, L"Win32_Processor"))       return WMI_PROCESSOR;
    if (WmiContainsCI(query, L"Win32_VideoController")) return WMI_VIDEO_CONTROLLER;
    if (WmiContainsCI(query, L"Win32_BaseBoard"))       return WMI_BASEBOARD;
    if (WmiContainsCI(query, L"Win32_PhysicalMemoryArray")) return WMI_MEMORY_ARRAY;
    if (WmiContainsCI(query, L"Win32_PhysicalMemory"))  return WMI_PHYSICAL_MEMORY;
    if (WmiContainsCI(query, L"Win32_DiskDrive"))       return WMI_DISK_DRIVE;
    if (WmiContainsCI(query, L"Win32_NetworkAdapter"))  return WMI_NETWORK_ADAPTER;
    if (WmiContainsCI(query, L"Win32_ComputerSystemProduct")) return WMI_CS_PRODUCT;
    if (WmiContainsCI(query, L"Win32_ComputerSystem"))  return WMI_COMPUTER_SYSTEM;
    if (WmiContainsCI(query, L"Win32_BIOS"))            return WMI_BIOS;

    return WMI_UNKNOWN;
}

/* ─── Helpers: property writers ──────────────────────────── */
static void SetWmiStringPropertyW(IWbemClassObject* pObj, const wchar_t* propName,
                                  const wchar_t* value) {
    if (!pObj || !propName || !value) return;
    VARIANT var;
    VariantInit(&var);
    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(value);
    if (var.bstrVal) {
        pObj->Put(propName, 0, &var, 0);
        SysFreeString(var.bstrVal);
    }
}

static void SetWmiStringProperty(IWbemClassObject* pObj, const wchar_t* propName,
                                 const char* valueUtf8) {
    if (!valueUtf8) return;
    wchar_t wvalue[256];
    HwUtf8ToWide(valueUtf8, wvalue, 256);
    SetWmiStringPropertyW(pObj, propName, wvalue);
}

static void SetWmiUint32Property(IWbemClassObject* pObj, const wchar_t* propName, DWORD value) {
    if (!pObj) return;
    VARIANT var;
    VariantInit(&var);
    var.vt = VT_I4;
    var.lVal = (LONG)value;
    pObj->Put(propName, 0, &var, 0);
}

static void SetWmiUint64Property(IWbemClassObject* pObj, const wchar_t* propName,
                                 ULONGLONG value) {
    if (!pObj) return;
    VARIANT var;
    VariantInit(&var);
    var.vt = VT_BSTR;
    wchar_t buf[32];
    swprintf_s(buf, L"%llu", value);
    var.bstrVal = SysAllocString(buf);
    if (var.bstrVal) {
        pObj->Put(propName, 0, &var, 0);
        SysFreeString(var.bstrVal);
    }
}

/* "04/15/2024" -> "20240415000000.000000+000" (CIM datetime). */
static void WmiCimDate(const char* dateIn, wchar_t* out, DWORD cchOut) {
    int m = 0, d = 0, y = 0;
    if (dateIn && sscanf_s(dateIn, "%d/%d/%d", &m, &d, &y) == 3) {
        swprintf_s(out, cchOut, L"%04d%02d%02d000000.000000+000", y, m, d);
    } else {
        out[0] = 0;
    }
}

static void WmiMacString(DWORD index, wchar_t* out, DWORD cchOut) {
    BYTE mac[6];
    HwDeriveMac(index, mac);
    swprintf_s(out, cchOut, L"%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ─── Object spoofing ────────────────────────────────────── */
static void SpoofWmiObject(WmiQueryType qtype, IWbemClassObject* pObj, DWORD index) {
    if (!pObj || !g_ProfileLoaded || qtype == WMI_UNKNOWN) return;

    const SharedCpuProfile* cpu = &g_Profile.cpu;
    const SharedGpuProfile* gpu = &g_Profile.gpu;
    const SharedMotherboardProfile* mb = &g_Profile.motherboard;
    const SharedMemoryProfile* mem = &g_Profile.memory;
    const SharedStorageProfile* st = &g_Profile.storage;

    switch (qtype) {
        case WMI_PROCESSOR: {
            wchar_t ident[128];
            HwBuildCpuIdentifier(ident, 128);
            SetWmiStringProperty(pObj, L"Manufacturer", cpu->manufacturer);
            SetWmiStringProperty(pObj, L"Name", cpu->brand_string);
            SetWmiStringProperty(pObj, L"Caption", cpu->brand_string);
            SetWmiStringPropertyW(pObj, L"Description", ident);
            SetWmiStringProperty(pObj, L"SocketDesignation", cpu->socket);
            SetWmiUint32Property(pObj, L"NumberOfCores", cpu->cores_physical);
            SetWmiUint32Property(pObj, L"NumberOfLogicalProcessors", cpu->cores_logical);
            SetWmiUint32Property(pObj, L"MaxClockSpeed", cpu->max_clock_mhz);
            SetWmiUint32Property(pObj, L"CurrentClockSpeed", cpu->base_clock_mhz);
            SetWmiUint32Property(pObj, L"ExtClock", 100);
            SetWmiUint32Property(pObj, L"Family", cpu->family);
            SetWmiUint32Property(pObj, L"Stepping", cpu->stepping);
            SetWmiUint32Property(pObj, L"Revision", (cpu->model << 8) | (cpu->stepping & 0xFF));
            SetWmiUint32Property(pObj, L"L2CacheSize", cpu->l2_cache_kb);
            SetWmiUint32Property(pObj, L"L3CacheSize", cpu->l3_cache_kb);
            break;
        }

        case WMI_VIDEO_CONTROLLER: {
            SetWmiStringProperty(pObj, L"Name", gpu->name);
            SetWmiStringProperty(pObj, L"Caption", gpu->name);
            SetWmiStringProperty(pObj, L"Description", gpu->name);
            SetWmiStringProperty(pObj, L"AdapterCompatibility", gpu->vendor);
            SetWmiStringProperty(pObj, L"DriverVersion", gpu->driver_version);
            SetWmiUint32Property(pObj, L"AdapterRAM", gpu->vram_mb * 1024u * 1024u);
            wchar_t pnp[128];
            swprintf_s(pnp, L"PCI\\VEN_%04X&DEV_%04X&SUBSYS_%08X&REV_%02X",
                gpu->vendor_id, gpu->device_id, gpu->subsystem_id, gpu->revision & 0xFF);
            SetWmiStringPropertyW(pObj, L"PNPDeviceID", pnp);
            break;
        }

        case WMI_BASEBOARD:
            SetWmiStringProperty(pObj, L"Manufacturer", mb->manufacturer);
            SetWmiStringProperty(pObj, L"Product", mb->product);
            SetWmiStringProperty(pObj, L"SerialNumber", mb->serial);
            SetWmiStringProperty(pObj, L"Version", mb->version);
            break;

        case WMI_BIOS: {
            SetWmiStringProperty(pObj, L"Manufacturer", mb->bios_vendor);
            SetWmiStringProperty(pObj, L"SMBIOSBIOSVersion", mb->bios_version);
            SetWmiStringProperty(pObj, L"Version", mb->bios_version);
            SetWmiStringProperty(pObj, L"SerialNumber", mb->serial);
            wchar_t cim[32];
            WmiCimDate(mb->bios_date, cim, 32);
            if (cim[0]) SetWmiStringPropertyW(pObj, L"ReleaseDate", cim);
            SetWmiUint32Property(pObj, L"SMBIOSMajorVersion", 3);
            SetWmiUint32Property(pObj, L"SMBIOSMinorVersion", 5);
            break;
        }

        case WMI_PHYSICAL_MEMORY: {
            DWORD dimms = mem->dimm_count ? mem->dimm_count : 2;
            ULONGLONG perModule = (ULONGLONG)mem->total_gb * 1024ULL * 1024ULL * 1024ULL / dimms;
            SetWmiUint64Property(pObj, L"Capacity", perModule);
            SetWmiUint32Property(pObj, L"Speed", mem->speed_mhz);
            SetWmiUint32Property(pObj, L"ConfiguredClockSpeed", mem->speed_mhz);
            SetWmiUint32Property(pObj, L"SMBIOSMemoryType", HwSmbiosMemoryType(mem->mm_type));
            SetWmiUint32Property(pObj, L"MemoryType", HwSmbiosMemoryType(mem->mm_type));
            SetWmiUint32Property(pObj, L"TotalWidth", 64);
            SetWmiUint32Property(pObj, L"DataWidth", 64);
            SetWmiStringProperty(pObj, L"Manufacturer", mem->mm_manufacturer);
            SetWmiStringProperty(pObj, L"PartNumber", mem->mm_part);
            SetWmiStringPropertyW(pObj, L"SerialNumber", L"");
            wchar_t locator[16];
            swprintf_s(locator, L"DIMM_%c1", L'A' + (index % 4));
            SetWmiStringPropertyW(pObj, L"DeviceLocator", locator);
            SetWmiStringPropertyW(pObj, L"BankLabel", L"BANK 0");
            break;
        }

        case WMI_MEMORY_ARRAY: {
            SetWmiUint64Property(pObj, L"MaxCapacity",
                (ULONGLONG)mem->total_gb * 1024ULL * 1024ULL);
            SetWmiUint32Property(pObj, L"MemoryDevices", mem->dimm_count ? mem->dimm_count : 2);
            SetWmiUint32Property(pObj, L"MemoryErrorCorrection", 3);
            break;
        }

        case WMI_DISK_DRIVE: {
            const SharedStorageDrive* d = (index == 1 && st->drives[1].model[0])
                ? &st->drives[1] : &st->drives[0];
            SetWmiStringProperty(pObj, L"Model", d->model);
            SetWmiStringProperty(pObj, L"Caption", d->model);
            SetWmiStringProperty(pObj, L"Name", d->model);
            SetWmiStringProperty(pObj, L"SerialNumber", d->serial);
            SetWmiStringProperty(pObj, L"FirmwareRevision", d->firmware);
            SetWmiUint64Property(pObj, L"Size",
                (ULONGLONG)d->capacity_gb * 1000ULL * 1000ULL * 1000ULL);
            SetWmiStringProperty(pObj, L"InterfaceType", d->drive_type);
            SetWmiStringPropertyW(pObj, L"MediaType", L"Fixed hard disk media");
            break;
        }

        case WMI_NETWORK_ADAPTER: {
            wchar_t mac[24];
            WmiMacString(index, mac, 24);
            SetWmiStringPropertyW(pObj, L"MACAddress", mac);
            SetWmiStringProperty(pObj, L"Name", g_Profile.network.name);
            SetWmiStringProperty(pObj, L"Caption", g_Profile.network.name);
            SetWmiStringProperty(pObj, L"Description", g_Profile.network.name);
            SetWmiStringPropertyW(pObj, L"AdapterType", L"Ethernet 802.3");
            if (g_Profile.network.speed_mbps) {
                SetWmiUint64Property(pObj, L"Speed",
                    (ULONGLONG)g_Profile.network.speed_mbps * 1000ULL * 1000ULL);
            }
            break;
        }

        case WMI_COMPUTER_SYSTEM: {
            SetWmiStringPropertyW(pObj, L"Name", g_Profile.identity.computer_name);
            SetWmiStringProperty(pObj, L"Manufacturer", mb->manufacturer);
            SetWmiStringProperty(pObj, L"Model", mb->product);
            SetWmiUint64Property(pObj, L"TotalPhysicalMemory",
                (ULONGLONG)mem->total_gb * 1024ULL * 1024ULL * 1024ULL);
            SetWmiUint32Property(pObj, L"NumberOfProcessors", 1);
            SetWmiUint32Property(pObj, L"NumberOfLogicalProcessors", cpu->cores_logical);
            SetWmiStringPropertyW(pObj, L"SystemType", L"x64-based PC");
            break;
        }

        case WMI_CS_PRODUCT:
            SetWmiStringProperty(pObj, L"Name", mb->product);
            SetWmiStringProperty(pObj, L"Vendor", mb->manufacturer);
            SetWmiStringProperty(pObj, L"IdentifyingNumber", mb->serial);
            SetWmiStringProperty(pObj, L"Version", mb->version);
            break;

        default:
            break;
    }
}

/* ─── Enumerator wrapper ─────────────────────────────────── */
class WmiSpoofEnum : public IEnumWbemClassObject {
public:
    WmiSpoofEnum(IEnumWbemClassObject* real, WmiQueryType type)
        : m_ref(1), m_real(real), m_type(type) {
        if (m_real) m_real->AddRef();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppv) : E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return (ULONG)InterlockedIncrement(&m_ref);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) {
            delete this;
            return 0;
        }
        return (ULONG)r;
    }

    HRESULT STDMETHODCALLTYPE Reset() override {
        m_index = 0;
        return m_real ? m_real->Reset() : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE Next(long lTimeout, ULONG uCount,
                                   IWbemClassObject** apObjects, ULONG* puReturned) override {
        if (!m_real) return E_FAIL;
        HRESULT hr = m_real->Next(lTimeout, uCount, apObjects, puReturned);
        if (SUCCEEDED(hr) && apObjects && puReturned) {
            for (ULONG i = 0; i < *puReturned; i++) {
                SpoofWmiObject(m_type, apObjects[i], m_index + i);
            }
            m_index += *puReturned;
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE NextAsync(ULONG uCount, IWbemObjectSink* pSink) override {
        return m_real ? m_real->NextAsync(uCount, pSink) : E_FAIL;
    }

    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** ppEnum) override {
        if (!m_real || !ppEnum) return E_FAIL;
        IEnumWbemClassObject* inner = NULL;
        HRESULT hr = m_real->Clone(&inner);
        if (FAILED(hr) || !inner) return hr;
        WmiSpoofEnum* clone = new WmiSpoofEnum(inner, m_type);
        clone->m_index = m_index;
        inner->Release();
        *ppEnum = clone;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Skip(long lTimeout, ULONG nCount) override {
        if (!m_real) return E_FAIL;
        m_index += nCount;
        return m_real->Skip(lTimeout, nCount);
    }

private:
    virtual ~WmiSpoofEnum() {
        if (m_real) m_real->Release();
    }

    LONG m_ref;
    IEnumWbemClassObject* m_real;
    WmiQueryType m_type;
    DWORD m_index = 0;
};

/* Wrap an enumerator when the query targets a spoofed class. */
static HRESULT WrapWmiEnum(const wchar_t* queryText, IEnumWbemClassObject** ppEnum) {
    if (!ppEnum || !*ppEnum) return S_OK;
    if (!g_ProfileLoaded) return S_OK;
    WmiQueryType qtype = ClassifyWmiQuery(queryText);
    if (qtype == WMI_UNKNOWN) return S_OK;
    IEnumWbemClassObject* wrapped = new WmiSpoofEnum(*ppEnum, qtype);
    (*ppEnum)->Release();
    *ppEnum = wrapped;
    return S_OK;
}

/* ─── Spoofed IWbemServices methods ──────────────────────── */
static HRESULT STDMETHODCALLTYPE Hooked_ExecQuery(
    IWbemServices* pThis, const BSTR strQueryLanguage, const BSTR strQuery,
    long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) {

    HRESULT hr = Real_ExecQuery
        ? Real_ExecQuery(pThis, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum)
        : E_FAIL;

    if (SUCCEEDED(hr)) {
        if (!g_TracingPaused && strQuery && ClassifyWmiQuery(strQuery) != WMI_UNKNOWN) {
            char queryUtf8[512];
            queryUtf8[0] = 0;
            WideCharToMultiByte(CP_UTF8, 0, strQuery, -1, queryUtf8, sizeof(queryUtf8), NULL, NULL);
            char params[512];
            snprintf(params, sizeof(params), "query=\"%s\"", queryUtf8);
            g_Pipe.SendTrace("IWbemServices::ExecQuery", "wmi", params, "S_OK (spoofed)", 0, TRUE,
                0, 0, 0, 0, 0, 0, 0);
        }
        WrapWmiEnum(strQuery, ppEnum);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hooked_CreateInstanceEnum(
    IWbemServices* pThis, const BSTR strFilter, long lFlags, IWbemContext* pCtx,
    IEnumWbemClassObject** ppEnum) {

    HRESULT hr = Real_CreateInstanceEnum
        ? Real_CreateInstanceEnum(pThis, strFilter, lFlags, pCtx, ppEnum)
        : E_FAIL;
    if (SUCCEEDED(hr)) {
        WrapWmiEnum(strFilter, ppEnum);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hooked_GetObject(
    IWbemServices* pThis, const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
    IWbemClassObject** ppObject, IWbemCallResult** ppCallResult) {

    HRESULT hr = Real_GetObject
        ? Real_GetObject(pThis, strObjectPath, lFlags, pCtx, ppObject, ppCallResult)
        : E_FAIL;
    if (SUCCEEDED(hr) && ppObject && *ppObject) {
        WmiQueryType qtype = ClassifyWmiQuery(strObjectPath);
        SpoofWmiObject(qtype, *ppObject, 0);
    }
    return hr;
}

/* ─── Hook WMI services ──────────────────────────────────── */
static void HookWmiServices(IUnknown* pUnk) {
    if (!pUnk) return;

    IWbemServices* pSvc = NULL;
    HRESULT hr = pUnk->QueryInterface(__uuidof(IWbemServices), (void**)&pSvc);
    if (FAILED(hr) || !pSvc) return;

    void** vtable = *(void***)pSvc;
    if (!g_WmiServicesHooked && vtable) {
        DWORD oldProtect;
        if (VirtualProtect(&vtable[6], sizeof(void*) * 15, PAGE_READWRITE, &oldProtect)) {
            /* vtable[6] GetObject, vtable[18] CreateInstanceEnum, vtable[20] ExecQuery */
            if (!Real_GetObject) {
                Real_GetObject = (PFN_GetObject)vtable[6];
                vtable[6] = (void*)Hooked_GetObject;
            }
            if (!Real_CreateInstanceEnum) {
                Real_CreateInstanceEnum = (PFN_CreateInstanceEnum)vtable[18];
                vtable[18] = (void*)Hooked_CreateInstanceEnum;
            }
            if (!Real_ExecQuery) {
                Real_ExecQuery = (PFN_ExecQuery)vtable[20];
                vtable[20] = (void*)Hooked_ExecQuery;
            }
            VirtualProtect(&vtable[6], sizeof(void*) * 15, oldProtect, &oldProtect);
            g_WmiServicesHooked = TRUE;
        }
    }

    pSvc->Release();
}

/* ─── Hooked IWbemLocator::ConnectServer ─────────────────── */
static HRESULT STDMETHODCALLTYPE Hooked_ConnectServer(
    IWbemLocator* pThis, const BSTR strNetworkResource, const BSTR strUser,
    const BSTR strPassword, const BSTR strLocale, LONG lSecurityFlags,
    const BSTR strAuthority, IWbemContext* pCtx, IWbemServices** ppNamespace) {

    HRESULT hr = Real_ConnectServer
        ? Real_ConnectServer(pThis, strNetworkResource, strUser, strPassword,
            strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace)
        : E_FAIL;

    if (SUCCEEDED(hr) && ppNamespace && *ppNamespace) {
        HookWmiServices(*ppNamespace);
    }
    return hr;
}

/* ─── Hooked CoCreateInstance ────────────────────────────── */
// CLSID_WbemLocator = {4590f811-1d3a-11d0-891f-00aa004b2e24}
static const CLSID CLSID_WbemLocator_Local =
    {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

HRESULT WINAPI Hooked_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, REFIID riid, LPVOID* ppv) {

    HRESULT hr = Real_CoCreateInstance
        ? Real_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
        : E_FAIL;

    if (SUCCEEDED(hr) && ppv && *ppv && g_ProfileLoaded) {
        if (IsEqualCLSID(rclsid, CLSID_WbemLocator_Local)) {
            if (!g_TracingPaused) {
                g_Pipe.SendTrace("CoCreateInstance", "ole32.dll",
                    "CLSID_WbemLocator", "S_OK", 0, FALSE,
                    0, 0, 0, 0, 0, 0, 0);
            }
            /* Patch IWbemLocator::ConnectServer (vtable index 3) so we can
               intercept the IWbemServices object it returns. */
            if (!g_WmiLocatorHooked) {
                IWbemLocator* loc = (IWbemLocator*)0;
                if (SUCCEEDED(((IUnknown*)*ppv)->QueryInterface(
                        __uuidof(IWbemLocator), (void**)&loc)) && loc) {
                    void** vtable = *(void***)loc;
                    if (vtable) {
                        DWORD oldProtect;
                        if (VirtualProtect(&vtable[3], sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                            Real_ConnectServer = (PFN_ConnectServer)vtable[3];
                            vtable[3] = (void*)Hooked_ConnectServer;
                            VirtualProtect(&vtable[3], sizeof(void*), oldProtect, &oldProtect);
                            g_WmiLocatorHooked = TRUE;
                        }
                    }
                    loc->Release();
                }
            }
        }
    }

    return hr;
}

/* ─── Install WMI Hooks ──────────────────────────────────── */
static void InstallWmiHooks() {
    HMODULE hOle32 = GetModuleHandleA("ole32.dll");
    if (!hOle32) hOle32 = LoadLibraryA("ole32.dll");

    if (hOle32) {
        Real_CoCreateInstance = (PFN_CoCreateInstance)GetProcAddress(hOle32, "CoCreateInstance");
        if (Real_CoCreateInstance) {
            InstallInlineHook(Real_CoCreateInstance, (void*)Hooked_CoCreateInstance,
                (void**)&Real_CoCreateInstance, "CoCreateInstance");
        }
    }
}
