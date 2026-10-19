/*
   Ghost Sandbox — DXGI COM VTable Spoofer
   Hooks DXGI factory creation and adapter description queries so every
   adapter a target enumerates reports the profile's GPU identity.
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi.h>
#include <stdio.h>
#include "trace_format.h"
#include "hw_spoofer.h"
#include "hw_identity.h"

#pragma comment(lib, "dxgi.lib")

/* ─── Forward declarations ───────────────────────────────── */
extern PipeClient g_Pipe;
extern BOOL g_TracingPaused;

/* ─── Original function pointers ─────────────────────────── */
typedef HRESULT (WINAPI *PFN_CreateDXGIFactory)(REFIID riid, void** ppFactory);
typedef HRESULT (WINAPI *PFN_CreateDXGIFactory1)(REFIID riid, void** ppFactory);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GetDesc)(IDXGIAdapter* pThis, DXGI_ADAPTER_DESC* pDesc);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GetDesc1)(IDXGIAdapter1* pThis, DXGI_ADAPTER_DESC1* pDesc);

static PFN_CreateDXGIFactory  Real_CreateDXGIFactory  = NULL;
static PFN_CreateDXGIFactory1 Real_CreateDXGIFactory1 = NULL;

/* ─── Hooked vtable slots (per distinct vtable entry) ────── */
#define DXGI_MAX_SITES 16

typedef struct DxgiHookedSlot {
    void** slot;        // address of the vtable entry
    void*  original;    // original entry value
} DxgiHookedSlot;

static DxgiHookedSlot g_DxgiSites[DXGI_MAX_SITES];
static volatile LONG g_DxgiSiteCount = 0;

static void* DxgiGetOriginal(void** slot) {
    LONG n = g_DxgiSiteCount;
    if (n > DXGI_MAX_SITES) n = DXGI_MAX_SITES;
    for (LONG i = 0; i < n; i++) {
        if (g_DxgiSites[i].slot == slot) return g_DxgiSites[i].original;
    }
    return NULL;
}

static void DxgiHookSlot(void** vtable, int index, void* hook) {
    if (!vtable) return;
    void** slot = &vtable[index];

    LONG n = g_DxgiSiteCount;
    if (n > DXGI_MAX_SITES) n = DXGI_MAX_SITES;
    for (LONG i = 0; i < n; i++) {
        if (g_DxgiSites[i].slot == slot) return;   // already hooked
    }

    LONG idx = InterlockedIncrement(&g_DxgiSiteCount) - 1;
    if (idx >= DXGI_MAX_SITES) {
        InterlockedDecrement(&g_DxgiSiteCount);
        return;
    }

    DWORD oldProtect = 0;
    if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        g_DxgiSites[idx].slot = slot;
        g_DxgiSites[idx].original = *slot;
        *slot = hook;
        DWORD restore = 0;
        VirtualProtect(slot, sizeof(void*), oldProtect, &restore);
        FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
    } else {
        InterlockedDecrement(&g_DxgiSiteCount);
    }
}

/* ─── Spoofed GetDesc / GetDesc1 ─────────────────────────── */
static void DxgiApplyProfile(DXGI_ADAPTER_DESC* pDesc) {
    const SharedGpuProfile* gpu = &g_Profile.gpu;
    HwUtf8ToWide(gpu->name, pDesc->Description, 128);
    pDesc->VendorId = gpu->vendor_id;
    pDesc->DeviceId = gpu->device_id;
    pDesc->SubSysId = gpu->subsystem_id;
    pDesc->Revision = gpu->revision & 0xFF;
    pDesc->DedicatedVideoMemory = (SIZE_T)gpu->vram_mb * 1024ULL * 1024ULL;
    pDesc->DedicatedSystemMemory = 0;
    pDesc->SharedSystemMemory = (SIZE_T)gpu->shared_memory_mb * 1024ULL * 1024ULL;
}

static HRESULT STDMETHODCALLTYPE Hooked_GetDesc(IDXGIAdapter* pThis, DXGI_ADAPTER_DESC* pDesc) {
    PFN_GetDesc orig = pThis ? (PFN_GetDesc)DxgiGetOriginal(&(*(void***)pThis)[8]) : NULL;
    HRESULT hr = orig ? orig(pThis, pDesc) : E_FAIL;

    if (SUCCEEDED(hr) && pDesc && g_ProfileLoaded) {
        DxgiApplyProfile(pDesc);

        if (!g_TracingPaused) {
            char params[512], retVal[64];
            snprintf(params, sizeof(params),
                "Adapter->GetDesc() [spoofed: %s, VEN_%04X DEV_%04X, VRAM=%u MB]",
                g_Profile.gpu.name, g_Profile.gpu.vendor_id, g_Profile.gpu.device_id,
                g_Profile.gpu.vram_mb);
            snprintf(retVal, sizeof(retVal), "S_OK");
            g_Pipe.SendTrace("IDXGIAdapter::GetDesc", "dxgi.dll", params, retVal, 0, TRUE,
                0, 0, 0, 0, 0, 0, 0);
        }
    }

    return hr;
}

static HRESULT STDMETHODCALLTYPE Hooked_GetDesc1(IDXGIAdapter1* pThis, DXGI_ADAPTER_DESC1* pDesc) {
    PFN_GetDesc1 orig = pThis ? (PFN_GetDesc1)DxgiGetOriginal(&(*(void***)pThis)[10]) : NULL;
    HRESULT hr = orig ? orig(pThis, pDesc) : E_FAIL;

    if (SUCCEEDED(hr) && pDesc && g_ProfileLoaded) {
        DxgiApplyProfile((DXGI_ADAPTER_DESC*)pDesc);
        pDesc->Flags = 0;   // never advertise remote/software flags

        if (!g_TracingPaused) {
            char params[512], retVal[64];
            snprintf(params, sizeof(params), "Adapter1->GetDesc1() [spoofed: %s]",
                g_Profile.gpu.name);
            snprintf(retVal, sizeof(retVal), "S_OK");
            g_Pipe.SendTrace("IDXGIAdapter1::GetDesc1", "dxgi.dll", params, retVal, 0, TRUE,
                0, 0, 0, 0, 0, 0, 0);
        }
    }

    return hr;
}

/* ─── Hook the vtable of an adapter object ───────────────── */
static void HookAdapterObject(IUnknown* pObject) {
    if (!pObject) return;

    IDXGIAdapter* adapter = NULL;
    if (SUCCEEDED(pObject->QueryInterface(__uuidof(IDXGIAdapter), (void**)&adapter)) && adapter) {
        DxgiHookSlot(*(void***)adapter, 8, (void*)Hooked_GetDesc);
        adapter->Release();
    }

    IDXGIAdapter1* adapter1 = NULL;
    if (SUCCEEDED(pObject->QueryInterface(__uuidof(IDXGIAdapter1), (void**)&adapter1)) && adapter1) {
        DxgiHookSlot(*(void***)adapter1, 10, (void*)Hooked_GetDesc1);
        adapter1->Release();
    }
}

static void HookAdaptersFromFactory(IUnknown* pFactory) {
    IDXGIFactory* factory = NULL;
    HRESULT hr = pFactory->QueryInterface(__uuidof(IDXGIFactory), (void**)&factory);
    if (FAILED(hr) || !factory) return;

    for (UINT i = 0; i < 8; i++) {
        IDXGIAdapter* adapter = NULL;
        if (factory->EnumAdapters(i, &adapter) != S_OK || !adapter) break;
        HookAdapterObject((IUnknown*)adapter);
        adapter->Release();
    }

    factory->Release();
}

HRESULT WINAPI Hooked_CreateDXGIFactory(REFIID riid, void** ppFactory) {
    HRESULT hr = Real_CreateDXGIFactory ? Real_CreateDXGIFactory(riid, ppFactory) : E_FAIL;

    if (SUCCEEDED(hr) && ppFactory && *ppFactory && g_ProfileLoaded) {
        HookAdaptersFromFactory((IUnknown*)*ppFactory);
    }

    if (!g_TracingPaused) {
        char retVal[64];
        snprintf(retVal, sizeof(retVal), "0x%08X", (unsigned)hr);
        g_Pipe.SendTrace("CreateDXGIFactory", "dxgi.dll", "", retVal, 0, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }

    return hr;
}

HRESULT WINAPI Hooked_CreateDXGIFactory1(REFIID riid, void** ppFactory) {
    HRESULT hr = Real_CreateDXGIFactory1 ? Real_CreateDXGIFactory1(riid, ppFactory) : E_FAIL;

    if (SUCCEEDED(hr) && ppFactory && *ppFactory && g_ProfileLoaded) {
        HookAdaptersFromFactory((IUnknown*)*ppFactory);
    }

    if (!g_TracingPaused) {
        char retVal[64];
        snprintf(retVal, sizeof(retVal), "0x%08X", (unsigned)hr);
        g_Pipe.SendTrace("CreateDXGIFactory1", "dxgi.dll", "", retVal, 0, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }

    return hr;
}

/* ─── Install DXGI Hooks ─────────────────────────────────── */
static void InstallDXGIHooks() {
    HMODULE hDxgi = GetModuleHandleA("dxgi.dll");
    if (!hDxgi) hDxgi = LoadLibraryA("dxgi.dll");

    if (hDxgi) {
        Real_CreateDXGIFactory = (PFN_CreateDXGIFactory)GetProcAddress(hDxgi, "CreateDXGIFactory");
        Real_CreateDXGIFactory1 = (PFN_CreateDXGIFactory1)GetProcAddress(hDxgi, "CreateDXGIFactory1");

        if (Real_CreateDXGIFactory) {
            InstallInlineHook(Real_CreateDXGIFactory, (void*)Hooked_CreateDXGIFactory,
                (void**)&Real_CreateDXGIFactory, "CreateDXGIFactory");
        }
        if (Real_CreateDXGIFactory1) {
            InstallInlineHook(Real_CreateDXGIFactory1, (void*)Hooked_CreateDXGIFactory1,
                (void**)&Real_CreateDXGIFactory1, "CreateDXGIFactory1");
        }
    }
}
