/*
   Ghost Sandbox — Hardware Spoofer
   Profile-driven hardware identity spoofing.
   Reads configuration from shared memory and provides hooked function
   implementations that return spoofed values.
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")

#include "trace_format.h"

/* ─── Shared Profile Structure ───────────────────────────── */
/*
   This must match the Rust controller's serialized profile.
   For simplicity, we use fixed-size char arrays.
*/
#pragma pack(push, 1)

struct SharedCpuFeatures {
    BYTE sse, sse2, sse3, ssse3, sse4_1, sse4_2;
    BYTE avx, avx2, avx512f, avx512bw, avx512vl;
    BYTE fma, aes_ni, popcnt, rdrand, rdseed;
    BYTE bmi1, bmi2, adx, sha, clmul;
    BYTE f16c, movbe, lzcnt, abm, tsx, sgx;
    BYTE vaes, vpclmulqdq, avx_vnni;
};

struct SharedCpuProfile {
    char manufacturer[64];
    char brand_string[128];
    DWORD family, model, stepping;
    DWORD cores_physical, cores_logical;
    DWORD base_clock_mhz, max_clock_mhz;
    DWORD l1_cache_kb, l2_cache_kb, l3_cache_kb;
    SharedCpuFeatures features;
    char socket[24];
};

struct SharedGpuProfile {
    char name[128];
    char vendor[64];
    DWORD vendor_id, device_id, subsystem_id, revision;
    char driver_version[32];
    DWORD vram_mb, shared_memory_mb;
    DWORD pcie_gen, pcie_width;
};

struct SharedMotherboardProfile {
    char manufacturer[64];
    char product[128];
    char serial[64];
    char version[32];
    char bios_vendor[64];
    char bios_version[32];
    char bios_date[32];
    BYTE secure_boot;
};

struct SharedIdentityProfile {
    wchar_t computer_name[64];
    wchar_t user_name[64];
    char machine_guid[64];
    char volume_serial[16];
    char product_id[32];
};

struct SharedNetworkAdapter {
    char name[128];
    BYTE mac[6];
    DWORD vendor_id, device_id;
    DWORD speed_mbps;
    char ipv4[16];
};

struct SharedMemoryProfile {
    DWORD total_gb;
    DWORD speed_mhz;
    char mm_type[16];           // "DDR5", "DDR4", ...
    DWORD dimm_count;
    char mm_manufacturer[32];
    char mm_part[64];
};

struct SharedStorageDrive {
    char model[128];
    char serial[64];
    char firmware[32];
    DWORD capacity_gb;
    char drive_type[16];        // "NVMe", "SSD", "HDD"
};

struct SharedStorageProfile {
    SharedStorageDrive drives[2];
};

struct SharedProfile {
    DWORD magic;            // 'GSND' = 0x444E5347
    DWORD version;          // 1
    SharedIdentityProfile identity;
    SharedCpuProfile cpu;
    SharedGpuProfile gpu;
    SharedMotherboardProfile motherboard;
    SharedMemoryProfile memory;
    SharedNetworkAdapter network;  // Primary adapter
    SharedStorageProfile storage;  // Up to 2 drives
};

#pragma pack(pop)

/* ─── Global Profile ─────────────────────────────────────── */
static SharedProfile g_Profile;
static BOOL g_ProfileLoaded = FALSE;

static BOOL ReadProfileFromSharedMemory() {
    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, GHOST_SANDBOX_SHMEM_NAME);
    if (!hMap) return FALSE;
    
    void* pData = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, sizeof(SharedProfile));
    if (!pData) {
        CloseHandle(hMap);
        return FALSE;
    }
    
    memcpy(&g_Profile, pData, sizeof(SharedProfile));
    UnmapViewOfFile(pData);
    CloseHandle(hMap);
    
    if (g_Profile.magic != 0x444E5347) return FALSE;
    
    g_ProfileLoaded = TRUE;
    return TRUE;
}

/* ─── Original Function Pointers ─────────────────────────── */
typedef void (WINAPI *PFN_GetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PFN_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef BOOL (WINAPI *PFN_GetComputerNameW)(LPWSTR, LPDWORD);
typedef BOOL (WINAPI *PFN_IsProcessorFeaturePresent)(DWORD);
typedef UINT (WINAPI *PFN_GetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
typedef BOOL (WINAPI *PFN_SetupDiGetDeviceRegistryPropertyW)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
typedef ULONG (WINAPI *PFN_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

static PFN_GetSystemInfo Real_GetSystemInfo = NULL;
static PFN_GlobalMemoryStatusEx Real_GlobalMemoryStatusEx = NULL;
static PFN_GetComputerNameW Real_GetComputerNameW = NULL;
static PFN_IsProcessorFeaturePresent Real_IsProcessorFeaturePresent = NULL;
static PFN_GetSystemFirmwareTable Real_GetSystemFirmwareTable = NULL;
static PFN_SetupDiGetDeviceRegistryPropertyW Real_SetupDiGetDeviceRegistryPropertyW = NULL;
static PFN_GetAdaptersAddresses Real_GetAdaptersAddresses = NULL;

/* ─── Hooked Functions ───────────────────────────────────── */

void WINAPI Hooked_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    void* ra = DRM_RET();
    if (Real_GetSystemInfo) Real_GetSystemInfo(lpSystemInfo);
    
    if (g_ProfileLoaded && lpSystemInfo) {
        lpSystemInfo->dwNumberOfProcessors = g_Profile.cpu.cores_logical;
        lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        lpSystemInfo->wProcessorLevel = (WORD)g_Profile.cpu.family;
        lpSystemInfo->wProcessorRevision =
            (WORD)(((g_Profile.cpu.model & 0xFF) << 8) | (g_Profile.cpu.stepping & 0xFF));
        lpSystemInfo->dwProcessorType = PROCESSOR_AMD_X8664;
    }
    
    if (g_DrmEnabled) {
        char ret[96];
        if (lpSystemInfo) {
            snprintf(ret, sizeof(ret), "cores=%lu%s",
                (unsigned long)lpSystemInfo->dwNumberOfProcessors,
                g_ProfileLoaded ? " (profile applied)" : "");
        } else {
            strncpy_s(ret, "(null)", _TRUNCATE);
        }
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_INFO,
            DRM_VERDICT_UNKNOWN, "GetSystemInfo", "kernel32.dll",
            "CPU core count / architecture (fingerprint + VM heuristic)",
            ret, "", 0);
    }
}

BOOL WINAPI Hooked_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer) {
    void* ra = DRM_RET();
    BOOL result = Real_GlobalMemoryStatusEx ? Real_GlobalMemoryStatusEx(lpBuffer) : FALSE;
    
    if (g_ProfileLoaded && lpBuffer && result) {
        ULONGLONG realTotal = lpBuffer->ullTotalPhys;
        ULONGLONG totalBytes = (ULONGLONG)g_Profile.memory.total_gb * 1024ULL * 1024ULL * 1024ULL;
        ULONGLONG avail = lpBuffer->ullAvailPhys;
        /* Scale the real "available" figure onto the profile's total so the
           used/available split stays plausible. */
        if (realTotal > 0 && totalBytes > 0) {
            avail = (ULONGLONG)((double)avail / (double)realTotal * (double)totalBytes);
        }
        if (avail > totalBytes) avail = totalBytes * 9 / 10;
        lpBuffer->ullTotalPhys = totalBytes;
        lpBuffer->ullAvailPhys = avail;
    }
    
    if (g_DrmEnabled) {
        char ret[96];
        if (lpBuffer && result) {
            snprintf(ret, sizeof(ret), "totalPhys=%llu MB",
                (unsigned long long)(lpBuffer->ullTotalPhys / (1024ULL * 1024ULL)));
        } else {
            strncpy_s(ret, result ? "(null)" : "(failed)", _TRUNCATE);
        }
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_INFO,
            DRM_VERDICT_UNKNOWN, "GlobalMemoryStatusEx", "kernel32.dll",
            "physical memory size (fingerprint + VM heuristic)",
            ret, "", 0);
    }
    return result;
}

BOOL WINAPI Hooked_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
    void* ra = DRM_RET();
    BOOL result;
    char name8[128] = "";
    
    if (g_ProfileLoaded && lpBuffer && nSize) {
        DWORD len = (DWORD)wcslen(g_Profile.identity.computer_name);
        if (*nSize > len) {
            wcscpy_s(lpBuffer, *nSize, g_Profile.identity.computer_name);
            *nSize = len;
            result = TRUE;
        } else {
            *nSize = len + 1;
            SetLastError(ERROR_BUFFER_OVERFLOW);
            result = FALSE;
        }
        DrmWideToUtf8(g_Profile.identity.computer_name, name8, sizeof(name8));
    } else {
        result = Real_GetComputerNameW ? Real_GetComputerNameW(lpBuffer, nSize) : FALSE;
        if (result && lpBuffer) DrmWideToUtf8(lpBuffer, name8, sizeof(name8));
    }
    
    if (g_DrmEnabled) {
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_INFO,
            DRM_VERDICT_UNKNOWN, "GetComputerNameW", "kernel32.dll",
            "computer name (host fingerprint)",
            name8[0] ? name8 : (result ? "(read)" : "(failed)"), "",
            (ULONGLONG)result);
    }
    return result;
}

BOOL WINAPI Hooked_IsProcessorFeaturePresent(DWORD ProcessorFeature) {
    if (g_ProfileLoaded) {
        switch (ProcessorFeature) {
            case PF_XMMI_INSTRUCTIONS_AVAILABLE:     return g_Profile.cpu.features.sse;    // SSE
            case PF_XMMI64_INSTRUCTIONS_AVAILABLE:   return g_Profile.cpu.features.sse2;   // SSE2
            case PF_SSE3_INSTRUCTIONS_AVAILABLE:     return g_Profile.cpu.features.sse3;   // SSE3
            case PF_SSSE3_INSTRUCTIONS_AVAILABLE:    return g_Profile.cpu.features.ssse3;
            case PF_SSE4_1_INSTRUCTIONS_AVAILABLE:   return g_Profile.cpu.features.sse4_1;
            case PF_SSE4_2_INSTRUCTIONS_AVAILABLE:   return g_Profile.cpu.features.sse4_2;
            case PF_AVX_INSTRUCTIONS_AVAILABLE:      return g_Profile.cpu.features.avx;
            case PF_AVX2_INSTRUCTIONS_AVAILABLE:     return g_Profile.cpu.features.avx2;
            case PF_AVX512F_INSTRUCTIONS_AVAILABLE:  return g_Profile.cpu.features.avx512f;
            case PF_RDRAND_INSTRUCTION_AVAILABLE:    return g_Profile.cpu.features.rdrand;
            default:
                return Real_IsProcessorFeaturePresent ? Real_IsProcessorFeaturePresent(ProcessorFeature) : FALSE;
        }
    }
    return Real_IsProcessorFeaturePresent ? Real_IsProcessorFeaturePresent(ProcessorFeature) : FALSE;
}

BOOL WINAPI Hooked_SetupDiGetDeviceRegistryPropertyW(
    HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData,
    DWORD Property, PDWORD PropertyRegDataType,
    PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize) {
    
    if (g_ProfileLoaded && (Property == SPDRP_HARDWAREID || Property == SPDRP_DEVICEDESC)) {
        // Build spoofed hardware ID from GPU profile
        wchar_t spoofed[256];
        
        if (Property == SPDRP_DEVICEDESC) {
            // Convert GPU name to wide string
            MultiByteToWideChar(CP_UTF8, 0, g_Profile.gpu.name, -1, spoofed, 256);
        } else {
            // Build PCI hardware ID
            swprintf_s(spoofed, 256, L"PCI\\VEN_%04X&DEV_%04X&SUBSYS_%08X&REV_%02X",
                g_Profile.gpu.vendor_id, g_Profile.gpu.device_id,
                g_Profile.gpu.subsystem_id, g_Profile.gpu.revision);
        }
        
        DWORD needed = ((DWORD)wcslen(spoofed) + 2) * sizeof(wchar_t);
        if (RequiredSize) *RequiredSize = needed;
        
        if (PropertyBuffer && PropertyBufferSize >= needed) {
            wcscpy_s((wchar_t*)PropertyBuffer, PropertyBufferSize / sizeof(wchar_t), spoofed);
            // Double null for MULTI_SZ
            PropertyBuffer[needed - 2] = 0;
            PropertyBuffer[needed - 1] = 0;
            if (PropertyRegDataType) {
                *PropertyRegDataType = (Property == SPDRP_HARDWAREID) ? REG_MULTI_SZ : REG_SZ;
            }
            return TRUE;
        } else {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }
    
    return Real_SetupDiGetDeviceRegistryPropertyW
        ? Real_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData,
            Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)
        : FALSE;
}
