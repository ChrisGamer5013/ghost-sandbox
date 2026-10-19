/*
   Ghost Sandbox — Injected Shim DLL
   Core instrumentation engine. Hooks Windows APIs, captures trace events,
   spoofs hardware queries, and communicates with the controller via named pipe.
   
   (c) 2026 Ghost Project
   
   Compile: cl.exe /LD /O2 /EHsc /DNDEBUG sandbox_shim.cpp
            /Fe:sandbox_shim.dll /link /DLL kernel32.lib user32.lib
            advapi32.lib setupapi.lib iphlpapi.lib crypt32.lib wintrust.lib
*/

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

/* ─── Include Sandbox Components ─────────────────────────── */
#include "trace_format.h"

/* ShimLog is defined later in this file; component headers may log through it. */
static void ShimLog(const char* fmt, ...);
#define HOOK_LOG(...) ShimLog(__VA_ARGS__)

#include "pipe_client.h"
#include "hook_engine.h"
#include "drm_watch.h"
#include "policy_watch.h"
#include "struct_serializer.h"
#include "hw_spoofer.h"
#include "hw_identity.h"
#include "cpuid_trap.h"
#include "dxgi_spoofer.h"
#include "wmi_spoofer.h"

/* Malware-analysis guard (behaviour mediation + shadow store). Included
   late in the component list: it reuses the DRM caller-attribution helpers. */
#include "malware_guard.h"

/* Consumed by Hooked_RegQueryValueExW (defined before malware_guard.h): */
static BOOL MwTryAnswerRegQuery(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpType,
                                LPBYTE lpData, LPDWORD lpcbData, LSTATUS* outStatus);
static BOOL MwTryShadowRegistryRead(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpType,
                                    LPBYTE lpData, LPDWORD lpcbData, LSTATUS* outStatus);

/* ─── Globals ────────────────────────────────────────────── */
static PipeClient g_Pipe;
HMODULE g_hSelf = NULL;   /* non-static: used by cpuid_trap.h */
static FILE* g_LogFile = NULL;
static BOOL g_TracingPaused = FALSE;

/* ─── File Logging ───────────────────────────────────────── */
static CRITICAL_SECTION g_LogLock;

static void ShimLog(const char* fmt, ...) {
    if (!g_LogFile) return;
    
    EnterCriticalSection(&g_LogLock);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(g_LogFile, fmt, args);
    va_end(args);
    
    fprintf(g_LogFile, "\n");
    fflush(g_LogFile);
    
    LeaveCriticalSection(&g_LogLock);
}

/* ─── Original Function Pointers (kernel32) ──────────────── */
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PFN_GetModuleHandleA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_GetModuleHandleW)(LPCWSTR);

static PFN_LoadLibraryA Real_LoadLibraryA = NULL;
static PFN_LoadLibraryW Real_LoadLibraryW = NULL;
static PFN_LoadLibraryExA Real_LoadLibraryExA = NULL;
static PFN_LoadLibraryExW Real_LoadLibraryExW = NULL;
static PFN_GetProcAddress Real_GetProcAddress = NULL;
static PFN_GetModuleHandleA Real_GetModuleHandleA = NULL;
static PFN_GetModuleHandleW Real_GetModuleHandleW = NULL;

/* ─── Original Function Pointers (wintrust/crypt32) ──────── */
typedef LONG (WINAPI *PFN_WinVerifyTrust)(HWND, GUID*, LPVOID);
typedef BOOL (WINAPI *PFN_CertVerifyCertificateChainPolicy)(LPCSTR, PCCERT_CHAIN_CONTEXT, PCERT_CHAIN_POLICY_PARA, PCERT_CHAIN_POLICY_STATUS);

static PFN_WinVerifyTrust Real_WinVerifyTrust = NULL;
static PFN_CertVerifyCertificateChainPolicy Real_CertVerifyCertificateChainPolicy = NULL;

/* ─── Original Function Pointers (ntdll) ─────────────────── */
typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0
#define SystemBasicInformation 0
#define SystemProcessorInformation 1

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
static PFN_NtQuerySystemInformation Real_NtQuerySystemInformation = NULL;

/* ─── Original Function Pointers (kernelbase) ────────────── */
typedef LSTATUS (WINAPI *PFN_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static PFN_RegQueryValueExW Real_RegQueryValueExW = NULL;

/* ─── Hooked: LoadLibraryA ───────────────────────────────── */
HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    HMODULE result = Real_LoadLibraryA ? Real_LoadLibraryA(lpLibFileName) : NULL;
    
    ULONGLONG dur = MicrosecondsSince(start);
    
    // Sandbox policy: patch the freshly loaded module's IAT / exports
    if (result && g_PolicyCount > 0) PolicyApplyToModule(result);
    // CPUID interception: patch the module's executable sections
    if (result) CpuidPatchModule(result);

    char params[512], retVal[128];
    snprintf(params, sizeof(params), "lpLibFileName=\"%s\"", lpLibFileName ? lpLibFileName : "(null)");
    snprintf(retVal, sizeof(retVal), "0x%p", result);
    
    if (!g_TracingPaused) {
        g_Pipe.SendTrace("LoadLibraryA", "kernel32.dll", params, retVal, dur, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    ShimLog("LoadLibraryA(\"%s\") = 0x%p [%llu us]", lpLibFileName, result, dur);
    
    // Notify controller of DLL load
    if (result) {
        MODULEINFO mi = {};
        // Get module info if possible
        g_Pipe.SendDllLoad(lpLibFileName ? lpLibFileName : "?",
            (ULONGLONG)result, 0);
    }
    
    return result;
}

/* ─── Hooked: LoadLibraryW ───────────────────────────────── */
HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    HMODULE result = Real_LoadLibraryW ? Real_LoadLibraryW(lpLibFileName) : NULL;
    
    ULONGLONG dur = MicrosecondsSince(start);

    // Sandbox policy: patch the freshly loaded module's IAT / exports
    if (result && g_PolicyCount > 0) PolicyApplyToModule(result);
    // CPUID interception: patch the module's executable sections
    if (result) CpuidPatchModule(result);

    char params[512], retVal[128], nameUtf8[260];
    FormatWideString(nameUtf8, sizeof(nameUtf8), lpLibFileName);
    snprintf(params, sizeof(params), "lpLibFileName=\"%s\"", nameUtf8);
    snprintf(retVal, sizeof(retVal), "0x%p", result);
    
    if (!g_TracingPaused) {
        g_Pipe.SendTrace("LoadLibraryW", "kernel32.dll", params, retVal, dur, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    ShimLog("LoadLibraryW(\"%s\") = 0x%p [%llu us]", nameUtf8, result, dur);
    
    if (result) {
        g_Pipe.SendDllLoad(nameUtf8, (ULONGLONG)result, 0);
    }
    
    return result;
}

/* ─── Hooked: GetProcAddress ─────────────────────────────── */
FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    FARPROC result = Real_GetProcAddress ? Real_GetProcAddress(hModule, lpProcName) : NULL;
    
    ULONGLONG dur = MicrosecondsSince(start);

    // Sandbox policy: intercept dynamic resolution of targeted imports
    if (result && (ULONGLONG)lpProcName > 0xFFFF && g_PolicyCount > 0) {
        PolicyInterceptGetProcAddress(hModule, lpProcName, &result);
    }
    
    char params[512], retVal[128];
    if ((ULONGLONG)lpProcName > 0xFFFF) {
        snprintf(params, sizeof(params), "hModule=0x%p, lpProcName=\"%s\"", hModule, lpProcName);
    } else {
        snprintf(params, sizeof(params), "hModule=0x%p, ordinal=%llu", hModule, (ULONGLONG)lpProcName);
    }
    snprintf(retVal, sizeof(retVal), "0x%p", result);
    
    if (!g_TracingPaused) {
        g_Pipe.SendTrace("GetProcAddress", "kernel32.dll", params, retVal, dur, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    return result;
}

/* ─── Hooked: NtQuerySystemInformation ───────────────────── */
NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength) {
    
    void* ra = DRM_RET();
    NTSTATUS status = Real_NtQuerySystemInformation
        ? Real_NtQuerySystemInformation(SystemInformationClass, SystemInformation,
            SystemInformationLength, ReturnLength)
        : -1;
    
    BOOL spoofed = FALSE;
    if (g_ProfileLoaded) {
        switch (SystemInformationClass) {
            case 0:  /* SystemBasicInformation */
                if (status == STATUS_SUCCESS && SystemInformation) {
                    HwPatchBasicInformation(SystemInformation, SystemInformationLength);
                    spoofed = TRUE;
                }
                break;
            case 1:  /* SystemProcessorInformation */
                if (status == STATUS_SUCCESS && SystemInformation) {
                    HwPatchProcessorInformation(SystemInformation, SystemInformationLength);
                    spoofed = TRUE;
                }
                break;
            case 2:  /* SystemPerformanceInformation */
                if (status == STATUS_SUCCESS && SystemInformation) {
                    HwPatchPerformanceInformation(SystemInformation, SystemInformationLength);
                    spoofed = TRUE;
                }
                break;
            case 8: {  /* SystemProcessorPerformanceInformation (per-CPU array) */
                NTSTATUS patched = HwPatchProcessorPerformanceInformation(
                    SystemInformation, SystemInformationLength, ReturnLength);
                if (patched != 0) {
                    /* Buffer too small for the profiled processor count. */
                    status = patched;
                }
                spoofed = TRUE;
                break;
            }
            default:
                break;
        }
    }
    
    if (!g_TracingPaused) {
        char params[256], retVal[64];
        snprintf(params, sizeof(params), "class=%u, len=%u", SystemInformationClass, SystemInformationLength);
        snprintf(retVal, sizeof(retVal), "0x%08X", (unsigned)status);
        g_Pipe.SendTrace("NtQuerySystemInformation", "ntdll.dll", params, retVal, 0, spoofed,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled) {
        char retVal2[64], det[64];
        snprintf(retVal2, sizeof(retVal2), "status=0x%08X", (unsigned)status);
        snprintf(det, sizeof(det), "class=%u", SystemInformationClass);
        DrmEmit(ra, &g_Thr_NtQsiProbe, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_WARN,
            spoofed ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
            "NtQuerySystemInformation", "ntdll.dll",
            spoofed ? "system information rewritten from the hardware profile"
                    : "benign system information (VM-detection classes expose the sandbox)",
            retVal2, det, (ULONGLONG)status);
    }
    
    return status;
}

/* ─── Hooked: NtPowerInformation (processor clocks) ──────── */
typedef NTSTATUS (NTAPI *PFN_NtPowerInformation)(ULONG, PVOID, ULONG, PVOID, ULONG);
static PFN_NtPowerInformation Real_NtPowerInformation = NULL;

#define HW_POWER_PROCESSOR_INFORMATION 11

NTSTATUS NTAPI Hooked_NtPowerInformation(ULONG InformationLevel, PVOID InputBuffer,
    ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {

    NTSTATUS status = Real_NtPowerInformation
        ? Real_NtPowerInformation(InformationLevel, InputBuffer, InputBufferLength,
            OutputBuffer, OutputBufferLength)
        : -1;

    if (g_ProfileLoaded && status == STATUS_SUCCESS &&
        InformationLevel == HW_POWER_PROCESSOR_INFORMATION && OutputBuffer) {
        HwFillProcessorPowerInformation(OutputBuffer, OutputBufferLength);
    }

    return status;
}


/* ─── Hooked: GetSystemFirmwareTable (SMBIOS) ────────────── */
UINT WINAPI Hooked_GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    
    void* ra = DRM_RET();
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    UINT result = 0;
    BOOL spoofed = FALSE;

    if (g_ProfileLoaded && FirmwareTableProviderSignature == 'RSMB') {
        /* Raw SMBIOS: serve a synthetic table that matches the profile. */
        DWORD needed = HwBuildSmbios(NULL, 0);
        if (needed > 0) {
            if (!pFirmwareTableBuffer || BufferSize < needed) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                result = needed;
            } else {
                HwBuildSmbios((BYTE*)pFirmwareTableBuffer, BufferSize);
                result = needed;
                spoofed = TRUE;
            }
        }
    }

    if (!spoofed && result == 0) {
        result = Real_GetSystemFirmwareTable
            ? Real_GetSystemFirmwareTable(FirmwareTableProviderSignature,
                FirmwareTableID, pFirmwareTableBuffer, BufferSize)
            : 0;
    }
    
    ULONGLONG dur = MicrosecondsSince(start);
    
    if (!g_TracingPaused) {
        char params[256], retVal[64];
        snprintf(params, sizeof(params), "provider=0x%08X ('%c%c%c%c'), tableID=0x%08X, bufSize=%u",
            FirmwareTableProviderSignature,
            (char)(FirmwareTableProviderSignature & 0xFF),
            (char)((FirmwareTableProviderSignature >> 8) & 0xFF),
            (char)((FirmwareTableProviderSignature >> 16) & 0xFF),
            (char)((FirmwareTableProviderSignature >> 24) & 0xFF),
            FirmwareTableID, BufferSize);
        snprintf(retVal, sizeof(retVal), "%u bytes", result);
        g_Pipe.SendTrace("GetSystemFirmwareTable", "kernelbase.dll", params, retVal, dur, spoofed,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled) {
        char retVal2[64], det[96];
        snprintf(retVal2, sizeof(retVal2), "%u bytes", result);
        snprintf(det, sizeof(det), "provider=0x%08X%s", FirmwareTableProviderSignature,
            (FirmwareTableProviderSignature == 'RSMB') ? " (raw SMBIOS)" : "");
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_WARN,
            spoofed ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
            "GetSystemFirmwareTable", "kernelbase.dll",
            spoofed ? "synthetic SMBIOS table served from the hardware profile"
                    : "motherboard/BIOS identity (SMBIOS is a hardware fingerprint source)",
            retVal2, det, (ULONGLONG)result);
    }
    
    return result;
}

/* ─── Hooked: RegQueryValueExW ───────────────────────────── */
LSTATUS WINAPI Hooked_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName,
    LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    
    void* ra = DRM_RET();

    /* Malware analysis mode: fake-key reads and read-back of values the
       sample "wrote" are answered from the shim's shadow registry. */
    LSTATUS mwStatus = ERROR_FILE_NOT_FOUND;
    if (MwTryAnswerRegQuery(hKey, lpValueName, lpType, lpData, lpcbData, &mwStatus) ||
        MwTryShadowRegistryRead(hKey, lpValueName, lpType, lpData, lpcbData, &mwStatus)) {
        if (!g_TracingPaused && lpValueName) {
            char valName[256];
            WideCharToMultiByte(CP_UTF8, 0, lpValueName, -1, valName, sizeof(valName), NULL, NULL);
            char params[512], retVal[64];
            snprintf(params, sizeof(params), "valueName=\"%s\"", valName);
            snprintf(retVal, sizeof(retVal), "%s (%lu) [shim shadow]",
                     mwStatus == ERROR_SUCCESS ? "SUCCESS" : "FAIL", (unsigned long)mwStatus);
            g_Pipe.SendTrace("RegQueryValueExW", "kernelbase.dll", params, retVal, 0, TRUE,
                0, 0, 0, 0, 0, 0, 0);
        }
        return mwStatus;
    }

    /* Remember the caller's buffer size before the real call updates it. */
    DWORD callerCb = (lpData && lpcbData) ? *lpcbData : 0;

    LSTATUS result = Real_RegQueryValueExW
        ? Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
        : ERROR_FILE_NOT_FOUND;
    
    BOOL spoofed = FALSE;
    
    /* Hardware identity values (CPU name, BIOS strings, system identity,
       MachineGuid, computer name) are always answered from the profile:
       whether the host value exists (or fits the caller's probe buffer)
       must not change the response. */
    if (g_ProfileLoaded && lpValueName) {
        HwSpoofValue sv;
        if (HwSpoofRegistryValue(hKey, lpValueName, &sv)) {
            result = HwApplyRegValue(&sv, lpType, lpData, lpcbData, callerCb);
            spoofed = TRUE;
        }
    }
    
    if (!g_TracingPaused && lpValueName) {
        char valName[256];
        WideCharToMultiByte(CP_UTF8, 0, lpValueName, -1, valName, sizeof(valName), NULL, NULL);
        char params[512], retVal[64];
        snprintf(params, sizeof(params), "valueName=\"%s\"", valName);
        snprintf(retVal, sizeof(retVal), "%s (%lu)", result == ERROR_SUCCESS ? "SUCCESS" : "FAIL", result);
        g_Pipe.SendTrace("RegQueryValueExW", "kernelbase.dll", params, retVal, 0, spoofed,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled && lpValueName) {
        char valName[256], retVal2[64];
        DrmWideToUtf8(lpValueName, valName, sizeof(valName));
        snprintf(retVal2, sizeof(retVal2), "%s (%lu)",
            result == ERROR_SUCCESS ? "SUCCESS" : "FAIL", (unsigned long)result);
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_WARN,
            spoofed ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
            "RegQueryValueExW", "kernelbase.dll",
            spoofed ? "spoofed identity value from profile (MachineGuid etc.)"
                    : "machine identity value read (host fingerprinting)",
            retVal2, valName, (ULONGLONG)result);
    }
    
    return result;
}

/* ─── Hooked: GetAdaptersAddresses ───────────────────────── */
ULONG WINAPI Hooked_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer) {
    
    void* ra = DRM_RET();
    ULONG result = Real_GetAdaptersAddresses
        ? Real_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer)
        : ERROR_BUFFER_OVERFLOW;
    
    if (g_ProfileLoaded && result == ERROR_SUCCESS && AdapterAddresses) {
        /* All physical adapters get profile-derived MACs, and the name
           pointers are repointed at owned static strings (the API contract
           leaves the caller no ownership over them). */
        static wchar_t s_adapterNames[8][96];
        static wchar_t s_adapterDescs[8][128];
        static volatile LONG s_adapterNamesInit = 0;
        if (InterlockedCompareExchange(&s_adapterNamesInit, 1, 0) == 0) {
            wchar_t base[96];
            HwUtf8ToWide(g_Profile.network.name, base, 96);
            for (int i = 0; i < 8; i++) {
                if (i == 0) {
                    wcsncpy_s(s_adapterNames[i], 96, base, _TRUNCATE);
                    wcsncpy_s(s_adapterDescs[i], 128, base, _TRUNCATE);
                } else {
                    swprintf_s(s_adapterNames[i], L"Ethernet %d", i + 1);
                    swprintf_s(s_adapterDescs[i], L"%s #%d", base, i + 1);
                }
            }
        }

        PIP_ADAPTER_ADDRESSES adapter = AdapterAddresses;
        DWORD physIndex = 0;
        while (adapter) {
            if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD ||
                adapter->IfType == IF_TYPE_IEEE80211 ||
                adapter->IfType == IF_TYPE_PPP ||
                adapter->IfType == IF_TYPE_WWANPP ||
                adapter->IfType == IF_TYPE_WWANPP2) {
                if (adapter->PhysicalAddressLength == 6) {
                    HwDeriveMac(physIndex, adapter->PhysicalAddress);
                }
                if (physIndex < 8) {
                    adapter->FriendlyName = s_adapterNames[physIndex];
                    adapter->Description = s_adapterDescs[physIndex];
                }
                physIndex++;
            }
            adapter = adapter->Next;
        }
    }
    
    if (!g_TracingPaused) {
        char params[256], retVal[64];
        snprintf(params, sizeof(params), "family=%u, flags=0x%X", Family, Flags);
        snprintf(retVal, sizeof(retVal), "%lu", result);
        BOOL spoofed = (g_ProfileLoaded && result == ERROR_SUCCESS);
        g_Pipe.SendTrace("GetAdaptersAddresses", "iphlpapi.dll", params, retVal, 0, spoofed,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled) {
        char retVal2[64];
        snprintf(retVal2, sizeof(retVal2), "%lu", (unsigned long)result);
        DrmEmit(ra, &g_Thr_EnvProbes, 10, 100, DRM_CAT_ENVIRONMENT, DRM_SEV_WARN,
            DRM_VERDICT_UNKNOWN, "GetAdaptersAddresses", "iphlpapi.dll",
            "network adapter identity (MAC address fingerprinting)",
            retVal2, "", (ULONGLONG)result);
    }
    
    return result;
}

/* ═══════════════════════════════════════════════════════════
   Hardware identity hooks (see shim/hw_identity.h)
   ═══════════════════════════════════════════════════════════ */

/* ─── Hooked: GetAdaptersInfo (legacy IP Helper) ─────────── */
typedef ULONG (WINAPI *PFN_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
static PFN_GetAdaptersInfo Real_GetAdaptersInfo = NULL;

ULONG WINAPI Hooked_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer) {
    ULONG result = Real_GetAdaptersInfo
        ? Real_GetAdaptersInfo(AdapterInfo, SizePointer)
        : ERROR_BUFFER_OVERFLOW;

    if (g_ProfileLoaded && result == ERROR_SUCCESS && AdapterInfo) {
        static char s_desc[8][132];
        static volatile LONG s_descInit = 0;
        if (InterlockedCompareExchange(&s_descInit, 1, 0) == 0) {
            for (int i = 0; i < 8; i++) {
                if (i == 0) {
                    strncpy_s(s_desc[i], sizeof(s_desc[i]), g_Profile.network.name, _TRUNCATE);
                } else {
                    sprintf_s(s_desc[i], sizeof(s_desc[i]), "Ethernet %d", i + 1);
                }
            }
        }
        PIP_ADAPTER_INFO a = AdapterInfo;
        DWORD idx = 0;
        while (a) {
            if (a->AddressLength >= 6) {
                BYTE mac[6];
                HwDeriveMac(idx, mac);
                memcpy(a->Address, mac, 6);
            }
            if (idx < 8) {
                strncpy_s(a->Description, sizeof(a->Description), s_desc[idx], _TRUNCATE);
            }
            idx++;
            a = a->Next;
        }
    }

    return result;
}

/* ─── Hooked: GetLogicalProcessorInformation ─────────────── */
typedef BOOL (WINAPI *PFN_GetLogicalProcessorInformation)(
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
static PFN_GetLogicalProcessorInformation Real_GetLogicalProcessorInformation = NULL;

BOOL WINAPI Hooked_GetLogicalProcessorInformation(
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer, PDWORD ReturnLength) {

    if (g_ProfileLoaded && ReturnLength) {
        DWORD needed = 0;
        HwBuildGlpi(RelationAll, NULL, 0, &needed);
        if (needed > 0) {
            if (!Buffer || *ReturnLength < needed) {
                *ReturnLength = needed;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            if (HwBuildGlpi(RelationAll, Buffer, *ReturnLength, &needed)) {
                *ReturnLength = needed;
                SetLastError(ERROR_SUCCESS);
                return TRUE;
            }
        }
    }

    return Real_GetLogicalProcessorInformation
        ? Real_GetLogicalProcessorInformation(Buffer, ReturnLength)
        : FALSE;
}

/* ─── Hooked: GetLogicalProcessorInformationEx ───────────── */
typedef BOOL (WINAPI *PFN_GetLogicalProcessorInformationEx)(
    LOGICAL_PROCESSOR_RELATIONSHIP, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD);
static PFN_GetLogicalProcessorInformationEx Real_GetLogicalProcessorInformationEx = NULL;

BOOL WINAPI Hooked_GetLogicalProcessorInformationEx(
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship,
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer, PDWORD ReturnLength) {

    if (g_ProfileLoaded && ReturnLength) {
        DWORD needed = 0;
        if (HwBuildGlpie(Relationship, NULL, 0, &needed) && needed > 0) {
            if (!Buffer || *ReturnLength < needed) {
                *ReturnLength = needed;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            if (HwBuildGlpie(Relationship, Buffer, *ReturnLength, &needed)) {
                *ReturnLength = needed;
                SetLastError(ERROR_SUCCESS);
                return TRUE;
            }
        }
    }

    return Real_GetLogicalProcessorInformationEx
        ? Real_GetLogicalProcessorInformationEx(Relationship, Buffer, ReturnLength)
        : FALSE;
}

/* ─── Hooked: GetPhysicallyInstalledSystemMemory ─────────── */
typedef BOOL (WINAPI *PFN_GetPhysicallyInstalledSystemMemory)(PULONGLONG);
static PFN_GetPhysicallyInstalledSystemMemory Real_GetPhysicallyInstalledSystemMemory = NULL;

BOOL WINAPI Hooked_GetPhysicallyInstalledSystemMemory(PULONGLONG TotalMemoryInKilobytes) {
    if (g_ProfileLoaded && TotalMemoryInKilobytes) {
        *TotalMemoryInKilobytes = (ULONGLONG)g_Profile.memory.total_gb * 1024ULL * 1024ULL;
        return TRUE;
    }
    return Real_GetPhysicallyInstalledSystemMemory
        ? Real_GetPhysicallyInstalledSystemMemory(TotalMemoryInKilobytes)
        : FALSE;
}

/* ─── Hooked: GetNativeSystemInfo ────────────────────────── */
typedef void (WINAPI *PFN_GetNativeSystemInfo)(LPSYSTEM_INFO);
static PFN_GetNativeSystemInfo Real_GetNativeSystemInfo = NULL;

void WINAPI Hooked_GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    if (Real_GetNativeSystemInfo) Real_GetNativeSystemInfo(lpSystemInfo);
    if (g_ProfileLoaded && lpSystemInfo) {
        lpSystemInfo->dwNumberOfProcessors = g_Profile.cpu.cores_logical;
        lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        lpSystemInfo->wProcessorLevel = (WORD)g_Profile.cpu.family;
        lpSystemInfo->wProcessorRevision =
            (WORD)(((g_Profile.cpu.model & 0xFF) << 8) | (g_Profile.cpu.stepping & 0xFF));
        lpSystemInfo->dwProcessorType = PROCESSOR_AMD_X8664;
    }
}

/* ─── Hooked: GetVolumeInformationW (volume serial) ──────── */
typedef BOOL (WINAPI *PFN_GetVolumeInformationW)(LPCWSTR, LPWSTR, DWORD, LPDWORD,
    LPDWORD, LPDWORD, LPWSTR, DWORD);
static PFN_GetVolumeInformationW Real_GetVolumeInformationW = NULL;

BOOL WINAPI Hooked_GetVolumeInformationW(LPCWSTR lpRootPathName,
    LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags,
    LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize) {

    BOOL result = Real_GetVolumeInformationW
        ? Real_GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
            lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags,
            lpFileSystemNameBuffer, nFileSystemNameSize)
        : FALSE;

    if (g_ProfileLoaded && result && lpVolumeSerialNumber) {
        DWORD serial = 0;
        if (HwParseVolumeSerial(g_Profile.identity.volume_serial, &serial)) {
            *lpVolumeSerialNumber = serial;
        }
    }

    return result;
}

/* ─── Hooked: RegQueryValueExA ───────────────────────────── */
typedef LSTATUS (WINAPI *PFN_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static PFN_RegQueryValueExA Real_RegQueryValueExA = NULL;

LSTATUS WINAPI Hooked_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
    LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {

    DWORD callerCb = (lpData && lpcbData) ? *lpcbData : 0;

    LSTATUS result = Real_RegQueryValueExA
        ? Real_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
        : ERROR_FILE_NOT_FOUND;

    if (g_ProfileLoaded && lpValueName) {
        wchar_t wname[256];
        HwUtf8ToWide(lpValueName, wname, 256);
        HwSpoofValue sv;
        if (HwSpoofRegistryValue(hKey, wname, &sv)) {
            HwSpoofValue out = sv;
            if (sv.type != REG_DWORD) {
                /* Convert the wide string value to ANSI. */
                char ansi[HW_VAL_MAX];
                int wchars = (int)(sv.dataBytes / sizeof(wchar_t));
                int n = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)sv.data, wchars,
                    ansi, sizeof(ansi), NULL, NULL);
                if (n <= 0) return result;
                memset(&out, 0, sizeof(out));
                out.type = sv.type;
                out.dataBytes = (DWORD)n;
                memcpy(out.data, ansi, n);
            }
            return HwApplyRegValue(&out, lpType, lpData, lpcbData, callerCb);
        }
    }

    return result;
}

/* ─── Hooked: RegGetValueW / RegGetValueA ────────────────── */
typedef LSTATUS (WINAPI *PFN_RegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI *PFN_RegGetValueA)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static PFN_RegGetValueW Real_RegGetValueW = NULL;
static PFN_RegGetValueA Real_RegGetValueA = NULL;

LSTATUS WINAPI Hooked_RegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue,
    DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) {

    DWORD callerCb = (pvData && pcbData) ? *pcbData : 0;

    LSTATUS result = Real_RegGetValueW
        ? Real_RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
        : ERROR_FILE_NOT_FOUND;

    if (g_ProfileLoaded && lpValue) {
        wchar_t path[640];
        if (HwGetKeyPath(hKey, path, 640)) {
            wchar_t full[640];
            if (lpSubKey && lpSubKey[0]) {
                swprintf_s(full, L"%s\\%s", path, lpSubKey);
            } else {
                wcsncpy_s(full, 640, path, _TRUNCATE);
            }
            HwSpoofValue sv;
            if (HwSpoofRegistryValuePath(full, lpValue, &sv)) {
                return HwApplyRegValue(&sv, pdwType, (LPBYTE)pvData, pcbData, callerCb);
            }
        }
    }

    return result;
}

LSTATUS WINAPI Hooked_RegGetValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue,
    DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) {

    DWORD callerCb = (pvData && pcbData) ? *pcbData : 0;

    LSTATUS result = Real_RegGetValueA
        ? Real_RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
        : ERROR_FILE_NOT_FOUND;

    if (g_ProfileLoaded && lpValue) {
        wchar_t wname[256], wsub[512];
        HwUtf8ToWide(lpValue, wname, 256);
        HwUtf8ToWide(lpSubKey ? lpSubKey : "", wsub, 512);
        wchar_t path[640];
        if (HwGetKeyPath(hKey, path, 640)) {
            wchar_t full[640];
            if (wsub[0]) {
                swprintf_s(full, L"%s\\%s", path, wsub);
            } else {
                wcsncpy_s(full, 640, path, _TRUNCATE);
            }
            HwSpoofValue sv;
            if (HwSpoofRegistryValuePath(full, wname, &sv)) {
                HwSpoofValue out = sv;
                if (sv.type != REG_DWORD) {
                    char ansi[HW_VAL_MAX];
                    int wchars = (int)(sv.dataBytes / sizeof(wchar_t));
                    int n = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)sv.data, wchars,
                        ansi, sizeof(ansi), NULL, NULL);
                    if (n <= 0) return result;
                    memset(&out, 0, sizeof(out));
                    out.type = sv.type;
                    out.dataBytes = (DWORD)n;
                    memcpy(out.data, ansi, n);
                }
                return HwApplyRegValue(&out, pdwType, (LPBYTE)pvData, pcbData, callerCb);
            }
        }
    }

    return result;
}

/* ─── Hooked: LoadLibraryExA / LoadLibraryExW ────────────── */
HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE result = Real_LoadLibraryExA
        ? Real_LoadLibraryExA(lpLibFileName, hFile, dwFlags)
        : NULL;
    if (result && g_PolicyCount > 0) PolicyApplyToModule(result);
    if (result) CpuidPatchModule(result);
    return result;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE result = Real_LoadLibraryExW
        ? Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags)
        : NULL;
    if (result && g_PolicyCount > 0) PolicyApplyToModule(result);
    if (result) CpuidPatchModule(result);
    return result;
}

/* ─── Hooked: WinVerifyTrust ─────────────────────────────── */
LONG WINAPI Hooked_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData) {
    void* ra = DRM_RET();
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    LONG result = Real_WinVerifyTrust ? Real_WinVerifyTrust(hwnd, pgActionID, pWVTData) : 0;
    
    ULONGLONG dur = MicrosecondsSince(start);
    
    char params[512], retVal[128];
    if (pgActionID) {
        snprintf(params, sizeof(params), "action={%08X-%04X-%04X-...}",
            pgActionID->Data1, pgActionID->Data2, pgActionID->Data3);
    } else {
        strncpy_s(params, "action=NULL", _TRUNCATE);
    }
    snprintf(retVal, sizeof(retVal), "0x%08X (%s)", result,
        result == 0 ? "TRUST_SUCCESS" : "TRUST_FAILURE");
    
    if (!g_TracingPaused) {
        g_Pipe.SendTrace("WinVerifyTrust", "wintrust.dll", params, retVal, dur, FALSE,
            0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled) {
        DrmEmit(ra, NULL, 0, 0, DRM_CAT_INTEGRITY, DRM_SEV_CRIT,
            result == 0 ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
            "WinVerifyTrust", "wintrust.dll",
            "ERROR_SUCCESS (0) - Authenticode signature / trust verified",
            retVal, "trust verification performed by the target",
            (ULONGLONG)result);
    }
    
    ShimLog("WinVerifyTrust() = 0x%08X [%llu us]", result, dur);
    
    return result;
}

/* ─── Hooked: CertVerifyCertificateChainPolicy ───────────── */
BOOL WINAPI Hooked_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID, PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara, PCERT_CHAIN_POLICY_STATUS pPolicyStatus) {
    
    void* ra = DRM_RET();
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    
    BOOL result = Real_CertVerifyCertificateChainPolicy
        ? Real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus)
        : FALSE;
    
    ULONGLONG dur = MicrosecondsSince(start);
    
    char params[512], retVal[128];
    snprintf(params, sizeof(params), "pszPolicyOID=0x%p, chainContext=0x%p",
        pszPolicyOID, pChainContext);
    snprintf(retVal, sizeof(retVal), "%s (status.dwError=0x%08X)",
        result ? "TRUE" : "FALSE",
        pPolicyStatus ? pPolicyStatus->dwError : 0xFFFFFFFF);
    
    if (!g_TracingPaused) {
        g_Pipe.SendTrace("CertVerifyCertificateChainPolicy", "crypt32.dll",
            params, retVal, dur, FALSE, 0, 0, 0, 0, 0, 0, 0);
    }
    
    if (g_DrmEnabled) {
        DrmEmit(ra, NULL, 0, 0, DRM_CAT_INTEGRITY, DRM_SEV_CRIT,
            result ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
            "CertVerifyCertificateChainPolicy", "crypt32.dll",
            "TRUE - certificate chain satisfies the requested policy",
            retVal, "", (ULONGLONG)result);
    }
    
    return result;
}

/* ─── Command Handler ────────────────────────────────────── */

/* ─── Live memory / registers / module helpers ───────────── */

/* Main thread of this process: the thread with the lowest id that is not the
   command-processing thread (thread ids are allocated in creation order, so
   the process's initial thread is the oldest). */
static DWORD FindMainThreadId() {
    DWORD pid = GetCurrentProcessId();
    DWORD self = GetCurrentThreadId();
    DWORD best = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid && te.th32ThreadID != self) {
                    if (best == 0 || te.th32ThreadID < best) best = te.th32ThreadID;
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    return best;
}

/* Controller-requested events must not be lost to a full ring during a burst:
   retry briefly before giving up. */
static BOOL SendEventRetry(const void* event, DWORD size, int attempts, DWORD delayMs) {
    for (int i = 0; i < attempts; i++) {
        if (g_Pipe.SendEvent(event, size)) return TRUE;
        Sleep(delayMs);
    }
    ShimLog("[pipe] SendEventRetry: gave up after %d attempts (size=%lu)", attempts,
            (unsigned long)size);
    return FALSE;
}

/* Capture a register snapshot (CMD_GET_REGS) and send EVT_REGISTERS. */
static void SendRegisterSnapshot(DWORD threadId) {
    DWORD tid = threadId ? threadId : FindMainThreadId();
    if (!tid) {
        ShimLog("registers: no target thread found");
        return;
    }

    HANDLE hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) {
        ShimLog("registers: OpenThread(%lu) failed err=%lu", tid, GetLastError());
        return;
    }

    DWORD prev = SuspendThread(hThread);
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    BOOL ok = GetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    if (prev == (DWORD)-1) ok = FALSE;

    if (ok) {
        TraceEventRegisters evt = {};
        evt.header.type = EVT_REGISTERS;
        evt.header.size = sizeof(evt);
        QueryPerformanceCounter(&evt.header.timestamp);
        evt.header.threadId = tid;
        evt.rax = ctx.Rax; evt.rbx = ctx.Rbx; evt.rcx = ctx.Rcx; evt.rdx = ctx.Rdx;
        evt.rsi = ctx.Rsi; evt.rdi = ctx.Rdi; evt.rsp = ctx.Rsp; evt.rbp = ctx.Rbp;
        evt.r8 = ctx.R8;   evt.r9 = ctx.R9;   evt.r10 = ctx.R10; evt.r11 = ctx.R11;
        evt.r12 = ctx.R12; evt.r13 = ctx.R13; evt.r14 = ctx.R14; evt.r15 = ctx.R15;
        evt.rip = ctx.Rip; evt.rflags = ctx.EFlags;
        SendEventRetry(&evt, sizeof(evt), 40, 25);
        ShimLog("registers: thread %lu rip=0x%llX rsp=0x%llX",
                tid, (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp);
    } else {
        ShimLog("registers: GetThreadContext failed err=%lu", GetLastError());
    }
    CloseHandle(hThread);
}

/* Walk the PEB loader list and send EVT_MODULE_LIST with full paths, bases,
   sizes, entry points and (cheap) import/export counts. Safe under the loader
   lock — no snapshot APIs on the module list itself. */
static BOOL SendModuleList() {
    struct SHIM_LDR_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } FullDllName;
        struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } BaseDllName;
    };

    const int MAX_MODULES = 96;
    static ModuleWireEntry entries[MAX_MODULES];
    int count = 0;

    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (peb) {
        BYTE* ldr = *(BYTE**)(peb + 0x18);
        if (ldr) {
            LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x20);   /* InMemoryOrderModuleList */
            LIST_ENTRY* e = head->Flink;
            __try {
                while (e && e != head && count < MAX_MODULES) {
                    SHIM_LDR_ENTRY* ent = CONTAINING_RECORD(e, SHIM_LDR_ENTRY, InMemoryOrderLinks);
                    if (ent->DllBase) {
                        ModuleWireEntry* out = &entries[count];
                        memset(out, 0, sizeof(*out));

                        /* Prefer the full path, fall back to the base name. */
                        const void* nameBuf = NULL;
                        USHORT nameChars = 0;
                        if (ent->FullDllName.Buffer && ent->FullDllName.Length) {
                            nameBuf = ent->FullDllName.Buffer;
                            nameChars = (USHORT)(ent->FullDllName.Length / sizeof(WCHAR));
                        } else if (ent->BaseDllName.Buffer && ent->BaseDllName.Length) {
                            nameBuf = ent->BaseDllName.Buffer;
                            nameChars = (USHORT)(ent->BaseDllName.Length / sizeof(WCHAR));
                        }
                        if (nameBuf) {
                            if (nameChars > 259) nameChars = 259;
                            int n = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)nameBuf, nameChars,
                                                        out->name, 259, NULL, NULL);
                            out->name[n > 0 ? n : 0] = 0;
                        }

                        out->baseAddress = (ULONGLONG)ent->DllBase;
                        out->size = ent->SizeOfImage;
                        out->entryPoint = ent->EntryPoint ? (ULONGLONG)ent->EntryPoint : 0;

                        /* Cheap PE stats: exported functions + imported functions. */
                        BYTE* base = (BYTE*)ent->DllBase;
                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                DWORD expRva = nt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                if (expRva) {
                                    PIMAGE_EXPORT_DIRECTORY exp =
                                        (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
                                    out->numExports = exp->NumberOfFunctions;
                                }
                                DWORD impRva = nt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                                if (impRva) {
                                    PIMAGE_IMPORT_DESCRIPTOR desc =
                                        (PIMAGE_IMPORT_DESCRIPTOR)(base + impRva);
                                    DWORD total = 0;
                                    while (desc->Name && total < 5000) {
                                        PIMAGE_THUNK_DATA thunk =
                                            (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
                                        while (thunk->u1.Function) { total++; thunk++; }
                                        desc++;
                                    }
                                    out->numImports = total;
                                }
                            }
                        }
                        count++;
                    }
                    e = e->Flink;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ShimLog("module list: walk faulted (0x%08X)", GetExceptionCode());
            }
        }
    }

    static BYTE frame[sizeof(TraceEventHeader) + 4 + MAX_MODULES * sizeof(ModuleWireEntry)];
    DWORD size = (DWORD)(sizeof(TraceEventHeader) + 4 + count * sizeof(ModuleWireEntry));
    TraceEventHeader* hdr = (TraceEventHeader*)frame;
    hdr->type = EVT_MODULE_LIST;
    hdr->size = size;
    QueryPerformanceCounter(&hdr->timestamp);
    hdr->threadId = GetCurrentThreadId();
    *(DWORD*)(frame + sizeof(TraceEventHeader)) = (DWORD)count;
    if (count) {
        memcpy(frame + sizeof(TraceEventHeader) + 4, entries,
               (size_t)count * sizeof(ModuleWireEntry));
    }
    if (!g_Pipe.SendEvent(frame, size)) {
        ShimLog("module list: send dropped (%d modules, %lu bytes) — retrying", count,
                (unsigned long)size);
        return FALSE;
    }
    ShimLog("module list sent (%d modules, %lu bytes)", count, (unsigned long)size);
    return TRUE;
}

/* The ring can be full during the startup burst, so a one-shot send may be
   dropped. Retry until queued (or the target goes away). */
static BOOL SendModuleListWithRetry(int attempts, DWORD delayMs) {
    for (int i = 0; i < attempts; i++) {
        if (!g_Pipe.IsConnected()) return FALSE;
        if (SendModuleList()) return TRUE;
        Sleep(delayMs);
    }
    ShimLog("module list: giving up after %d retries", attempts);
    return FALSE;
}

/* The controller may be slow to start; publish the initial module list as soon
   as the pipe is up (covers late connects). */
static DWORD WINAPI ModuleListThread(LPVOID) {
    for (int i = 0; i < 1200; i++) {          /* up to 60 s */
        if (g_Pipe.IsConnected()) {
            Sleep(100);                       /* let pending startup events flush */
            SendModuleListWithRetry(200, 50); /* ring can be full during a burst */
            return 0;
        }
        Sleep(50);
    }
    return 0;
}

/* Controller-requested refresh — retry in the background so the command
   thread stays responsive. */
static DWORD WINAPI ModuleListRetryThread(LPVOID) {
    SendModuleListWithRetry(200, 50);
    return 0;
}

static void HandleCommand(const CommandHeader* cmd) {
    ShimLog("Received command type=%d size=%u", cmd->type, cmd->size);
    
    switch (cmd->type) {
        case CMD_PATCH: {
            const CommandPatch* patch = (const CommandPatch*)cmd;
            DWORD oldProtect;
            void* addr = (void*)patch->address;
            
            if (VirtualProtect(addr, patch->length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(addr, patch->data, patch->length);
                VirtualProtect(addr, patch->length, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), addr, patch->length);
                
                TraceEventPatchAck ack = {};
                ack.header.type = EVT_PATCH_ACK;
                ack.header.size = sizeof(ack);
                QueryPerformanceCounter(&ack.header.timestamp);
                ack.header.threadId = GetCurrentThreadId();
                ack.address = patch->address;
                ack.success = 1;
                g_Pipe.SendEvent(&ack, sizeof(ack));
                
                ShimLog("PATCH applied at 0x%llX (%u bytes)", patch->address, patch->length);
            }
            break;
        }
        
        case CMD_PATCH_JMP: {
            const CommandPatchJmp* pjmp = (const CommandPatchJmp*)cmd;
            void* addr = (void*)pjmp->address;
            BYTE* code = (BYTE*)addr;
            
            DWORD oldProtect;
            if (VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // Detect current instruction and convert to JMP
                if (code[0] == 0x74 || code[0] == 0x75) {
                    // Short conditional jump -> short JMP
                    code[0] = 0xEB;
                    ShimLog("PATCH JZ/JNZ -> JMP (short) at 0x%llX", pjmp->address);
                } else if (code[0] == 0x0F && (code[1] == 0x84 || code[1] == 0x85)) {
                    // Near conditional jump -> near JMP + NOP
                    // 0F 84/85 xx xx xx xx -> E9 xx xx xx xx 90
                    DWORD offset;
                    memcpy(&offset, &code[2], 4);
                    code[0] = 0xE9;
                    // Adjust offset: original was 6-byte instruction, E9 is 5-byte
                    offset += 1;
                    memcpy(&code[1], &offset, 4);
                    code[5] = 0x90;  // NOP the extra byte
                    ShimLog("PATCH JZ/JNZ -> JMP (near) at 0x%llX", pjmp->address);
                }
                
                VirtualProtect(addr, 6, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), addr, 6);
            }
            break;
        }
        
        case CMD_PATCH_NOP: {
            const CommandPatchNop* pnop = (const CommandPatchNop*)cmd;
            void* addr = (void*)pnop->address;
            
            DWORD oldProtect;
            if (VirtualProtect(addr, pnop->length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memset(addr, 0x90, pnop->length);
                VirtualProtect(addr, pnop->length, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), addr, pnop->length);
                ShimLog("NOP %u bytes at 0x%llX", pnop->length, pnop->address);
            }
            break;
        }
        
        case CMD_DUMP: {
            const CommandDump* dump = (const CommandDump*)cmd;
            DWORD len = min(dump->length, 4096);
            
            TraceEventMemoryDump evt = {};
            evt.header.type = EVT_MEMORY_DUMP;
            evt.header.size = sizeof(evt);
            QueryPerformanceCounter(&evt.header.timestamp);
            evt.header.threadId = GetCurrentThreadId();
            evt.address = dump->address;
            evt.length = len;
            
            __try {
                memcpy(evt.data, (void*)dump->address, len);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                evt.length = 0;
            }
            
            SendEventRetry(&evt, sizeof(evt), 40, 25);
            break;
        }

        case CMD_GET_REGS: {
            DWORD tid = (cmd->size >= sizeof(CommandGetRegs))
                            ? ((const CommandGetRegs*)cmd)->threadId
                            : 0;
            SendRegisterSnapshot(tid);
            break;
        }

        case CMD_LIST_MODULES: {
            HANDLE h = CreateThread(NULL, 0, ModuleListRetryThread, NULL, 0, NULL);
            if (h) CloseHandle(h);
            break;
        }

        case CMD_TRACE_PAUSE:
            g_TracingPaused = TRUE;
            ShimLog("Tracing paused");
            break;
            
        case CMD_TRACE_RESUME:
            g_TracingPaused = FALSE;
            ShimLog("Tracing resumed");
            break;
            
        case CMD_PROFILE_RELOAD:
            if (ReadProfileFromSharedMemory()) {
                ShimLog("Profile reloaded from shared memory");
            } else {
                ShimLog("Failed to reload profile");
            }
            break;
            
        case CMD_DRM_MODE: {
            BOOL enabled = (cmd->size >= 6) ? (((const BYTE*)cmd)[5] != 0) : TRUE;
            g_DrmEnabled = enabled;
            ShimLog("DRM watch mode %s", enabled ? "ENABLED" : "DISABLED");
            // Ack as a DRM event so the controller shows the mode change in-stream.
            DrmEmitRaw(_ReturnAddress(), TRUE, NULL, 0, 0,
                DRM_CAT_ENVIRONMENT, DRM_SEV_INFO, DRM_VERDICT_BENIGN,
                "GhostDRM:Mode", "sandbox_shim.dll",
                "controller toggles DRM / anti-tamper watch mode",
                enabled ? "ENABLED" : "DISABLED", "", enabled ? 1 : 0);
            break;
        }

        case CMD_POLICY: {
            PolicyApplyFromCommand((const CommandPolicy*)cmd, cmd->size);
            break;
        }

        case CMD_MALWARE_VERDICT: {
            if (cmd->size >= sizeof(CommandMalwareVerdict)) {
                const CommandMalwareVerdict* v = (const CommandMalwareVerdict*)cmd;
                MalwareGuardHandleVerdict(v->opId, v->allow);
                ShimLog("[malware] verdict op=0x%08X allow=%u", v->opId, v->allow);
            }
            break;
        }
    }
}

/* ─── Install All Hooks ──────────────────────────────────── */

static void InstallAllHooks() {
    ShimLog("Installing hooks...");
    
    // ── kernel32.dll (IAT hooks) ────────────────────────
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        Real_LoadLibraryA = (PFN_LoadLibraryA)GetProcAddress(hKernel32, "LoadLibraryA");
        Real_LoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel32, "LoadLibraryW");
        Real_GetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
        Real_GetModuleHandleA = (PFN_GetModuleHandleA)GetProcAddress(hKernel32, "GetModuleHandleA");
        Real_GetModuleHandleW = (PFN_GetModuleHandleW)GetProcAddress(hKernel32, "GetModuleHandleW");
        
        // Inline hooks on LoadLibrary variants
        InstallInlineHook(Real_LoadLibraryA, (void*)Hooked_LoadLibraryA, (void**)&Real_LoadLibraryA, "LoadLibraryA");
        InstallInlineHook(Real_LoadLibraryW, (void*)Hooked_LoadLibraryW, (void**)&Real_LoadLibraryW, "LoadLibraryW");
        InstallInlineHook(Real_GetProcAddress, (void*)Hooked_GetProcAddress, (void**)&Real_GetProcAddress, "GetProcAddress");

        Real_LoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel32, "LoadLibraryExA");
        Real_LoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hKernel32, "LoadLibraryExW");
        if (Real_LoadLibraryExA) {
            InstallInlineHook(Real_LoadLibraryExA, (void*)Hooked_LoadLibraryExA,
                (void**)&Real_LoadLibraryExA, "LoadLibraryExA");
        }
        if (Real_LoadLibraryExW) {
            InstallInlineHook(Real_LoadLibraryExW, (void*)Hooked_LoadLibraryExW,
                (void**)&Real_LoadLibraryExW, "LoadLibraryExW");
        }
        
        // Hardware spoofing hooks
        Real_GetSystemInfo = (PFN_GetSystemInfo)GetProcAddress(hKernel32, "GetSystemInfo");
        Real_GlobalMemoryStatusEx = (PFN_GlobalMemoryStatusEx)GetProcAddress(hKernel32, "GlobalMemoryStatusEx");
        Real_GetComputerNameW = (PFN_GetComputerNameW)GetProcAddress(hKernel32, "GetComputerNameW");
        Real_IsProcessorFeaturePresent = (PFN_IsProcessorFeaturePresent)GetProcAddress(hKernel32, "IsProcessorFeaturePresent");
        
        InstallInlineHook(Real_GetSystemInfo, (void*)Hooked_GetSystemInfo, (void**)&Real_GetSystemInfo, "GetSystemInfo");
        InstallInlineHook(Real_GlobalMemoryStatusEx, (void*)Hooked_GlobalMemoryStatusEx, (void**)&Real_GlobalMemoryStatusEx, "GlobalMemoryStatusEx");
        InstallInlineHook(Real_GetComputerNameW, (void*)Hooked_GetComputerNameW, (void**)&Real_GetComputerNameW, "GetComputerNameW");
        InstallInlineHook(Real_IsProcessorFeaturePresent, (void*)Hooked_IsProcessorFeaturePresent, (void**)&Real_IsProcessorFeaturePresent, "IsProcessorFeaturePresent");
        
        ShimLog("kernel32 hooks installed (%d total)", g_HookCount);
    }
    
    // ── setupapi.dll ────────────────────────────────────
    HMODULE hSetupApi = GetModuleHandleA("setupapi.dll");
    if (!hSetupApi) hSetupApi = LoadLibraryA("setupapi.dll");
    if (hSetupApi) {
        Real_SetupDiGetDeviceRegistryPropertyW = (PFN_SetupDiGetDeviceRegistryPropertyW)
            GetProcAddress(hSetupApi, "SetupDiGetDeviceRegistryPropertyW");
        if (Real_SetupDiGetDeviceRegistryPropertyW) {
            InstallInlineHook(Real_SetupDiGetDeviceRegistryPropertyW,
                (void*)Hooked_SetupDiGetDeviceRegistryPropertyW,
                (void**)&Real_SetupDiGetDeviceRegistryPropertyW,
                "SetupDiGetDeviceRegistryPropertyW");
        }
        ShimLog("setupapi hooks installed");
    }
    
    // ── wintrust.dll ────────────────────────────────────
    HMODULE hWintrust = GetModuleHandleA("wintrust.dll");
    if (!hWintrust) hWintrust = LoadLibraryA("wintrust.dll");
    if (hWintrust) {
        Real_WinVerifyTrust = (PFN_WinVerifyTrust)
            GetProcAddress(hWintrust, "WinVerifyTrust");
        if (Real_WinVerifyTrust) {
            InstallInlineHook(Real_WinVerifyTrust,
                (void*)Hooked_WinVerifyTrust,
                (void**)&Real_WinVerifyTrust,
                "WinVerifyTrust");
        }
        ShimLog("wintrust hooks installed");
    }
    
    // ── crypt32.dll ─────────────────────────────────────
    HMODULE hCrypt32 = GetModuleHandleA("crypt32.dll");
    if (!hCrypt32) hCrypt32 = LoadLibraryA("crypt32.dll");
    if (hCrypt32) {
        Real_CertVerifyCertificateChainPolicy = (PFN_CertVerifyCertificateChainPolicy)
            GetProcAddress(hCrypt32, "CertVerifyCertificateChainPolicy");
        if (Real_CertVerifyCertificateChainPolicy) {
            InstallInlineHook(Real_CertVerifyCertificateChainPolicy,
                (void*)Hooked_CertVerifyCertificateChainPolicy,
                (void**)&Real_CertVerifyCertificateChainPolicy,
                "CertVerifyCertificateChainPolicy");
        }
        ShimLog("crypt32 hooks installed");
    }
    
    // ── ntdll.dll ────────────────────────────────────────
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        Real_NtQuerySystemInformation = (PFN_NtQuerySystemInformation)
            GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (Real_NtQuerySystemInformation) {
            InstallInlineHook(Real_NtQuerySystemInformation,
                (void*)Hooked_NtQuerySystemInformation,
                (void**)&Real_NtQuerySystemInformation,
                "NtQuerySystemInformation");
        }
        Real_NtPowerInformation = (PFN_NtPowerInformation)
            GetProcAddress(hNtdll, "NtPowerInformation");
        if (Real_NtPowerInformation) {
            InstallInlineHook(Real_NtPowerInformation,
                (void*)Hooked_NtPowerInformation,
                (void**)&Real_NtPowerInformation,
                "NtPowerInformation");
        }
        ShimLog("ntdll hooks installed");
    }
    
    // ── kernelbase.dll ──────────────────────────────────
    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
    if (hKernelBase) {
        Real_GetSystemFirmwareTable = (PFN_GetSystemFirmwareTable)
            GetProcAddress(hKernelBase, "GetSystemFirmwareTable");
        if (Real_GetSystemFirmwareTable) {
            InstallInlineHook(Real_GetSystemFirmwareTable,
                (void*)Hooked_GetSystemFirmwareTable,
                (void**)&Real_GetSystemFirmwareTable,
                "GetSystemFirmwareTable");
        }
        
        Real_RegQueryValueExW = (PFN_RegQueryValueExW)
            GetProcAddress(hKernelBase, "RegQueryValueExW");
        if (Real_RegQueryValueExW) {
            InstallInlineHook(Real_RegQueryValueExW,
                (void*)Hooked_RegQueryValueExW,
                (void**)&Real_RegQueryValueExW,
                "RegQueryValueExW");
        }

        Real_RegQueryValueExA = (PFN_RegQueryValueExA)
            GetProcAddress(hKernelBase, "RegQueryValueExA");
        if (Real_RegQueryValueExA) {
            InstallInlineHook(Real_RegQueryValueExA,
                (void*)Hooked_RegQueryValueExA,
                (void**)&Real_RegQueryValueExA,
                "RegQueryValueExA");
        }

        Real_RegGetValueW = (PFN_RegGetValueW)
            GetProcAddress(hKernelBase, "RegGetValueW");
        if (Real_RegGetValueW) {
            InstallInlineHook(Real_RegGetValueW,
                (void*)Hooked_RegGetValueW,
                (void**)&Real_RegGetValueW,
                "RegGetValueW");
        }

        Real_RegGetValueA = (PFN_RegGetValueA)
            GetProcAddress(hKernelBase, "RegGetValueA");
        if (Real_RegGetValueA) {
            InstallInlineHook(Real_RegGetValueA,
                (void*)Hooked_RegGetValueA,
                (void**)&Real_RegGetValueA,
                "RegGetValueA");
        }

        Real_GetNativeSystemInfo = (PFN_GetNativeSystemInfo)
            GetProcAddress(hKernelBase, "GetNativeSystemInfo");
        if (Real_GetNativeSystemInfo) {
            InstallInlineHook(Real_GetNativeSystemInfo,
                (void*)Hooked_GetNativeSystemInfo,
                (void**)&Real_GetNativeSystemInfo,
                "GetNativeSystemInfo");
        }

        Real_GetLogicalProcessorInformation = (PFN_GetLogicalProcessorInformation)
            GetProcAddress(hKernelBase, "GetLogicalProcessorInformation");
        if (Real_GetLogicalProcessorInformation) {
            InstallInlineHook(Real_GetLogicalProcessorInformation,
                (void*)Hooked_GetLogicalProcessorInformation,
                (void**)&Real_GetLogicalProcessorInformation,
                "GetLogicalProcessorInformation");
        }

        Real_GetLogicalProcessorInformationEx = (PFN_GetLogicalProcessorInformationEx)
            GetProcAddress(hKernelBase, "GetLogicalProcessorInformationEx");
        if (Real_GetLogicalProcessorInformationEx) {
            InstallInlineHook(Real_GetLogicalProcessorInformationEx,
                (void*)Hooked_GetLogicalProcessorInformationEx,
                (void**)&Real_GetLogicalProcessorInformationEx,
                "GetLogicalProcessorInformationEx");
        }

        Real_GetPhysicallyInstalledSystemMemory = (PFN_GetPhysicallyInstalledSystemMemory)
            GetProcAddress(hKernelBase, "GetPhysicallyInstalledSystemMemory");
        if (Real_GetPhysicallyInstalledSystemMemory) {
            InstallInlineHook(Real_GetPhysicallyInstalledSystemMemory,
                (void*)Hooked_GetPhysicallyInstalledSystemMemory,
                (void**)&Real_GetPhysicallyInstalledSystemMemory,
                "GetPhysicallyInstalledSystemMemory");
        }

        Real_GetVolumeInformationW = (PFN_GetVolumeInformationW)
            GetProcAddress(hKernelBase, "GetVolumeInformationW");
        if (Real_GetVolumeInformationW) {
            InstallInlineHook(Real_GetVolumeInformationW,
                (void*)Hooked_GetVolumeInformationW,
                (void**)&Real_GetVolumeInformationW,
                "GetVolumeInformationW");
        }

        ShimLog("kernelbase hooks installed");
    }
    
    // ── iphlpapi.dll ────────────────────────────────────
    HMODULE hIphlpapi = GetModuleHandleA("iphlpapi.dll");
    if (!hIphlpapi) hIphlpapi = LoadLibraryA("iphlpapi.dll");
    if (hIphlpapi) {
        Real_GetAdaptersAddresses = (PFN_GetAdaptersAddresses)
            GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
        if (Real_GetAdaptersAddresses) {
            InstallInlineHook(Real_GetAdaptersAddresses,
                (void*)Hooked_GetAdaptersAddresses,
                (void**)&Real_GetAdaptersAddresses,
                "GetAdaptersAddresses");
        }
        Real_GetAdaptersInfo = (PFN_GetAdaptersInfo)
            GetProcAddress(hIphlpapi, "GetAdaptersInfo");
        if (Real_GetAdaptersInfo) {
            InstallInlineHook(Real_GetAdaptersInfo,
                (void*)Hooked_GetAdaptersInfo,
                (void**)&Real_GetAdaptersInfo,
                "GetAdaptersInfo");
        }
        ShimLog("iphlpapi hooks installed");
    }
    
    // ── DXGI (COM vtable hooks) ─────────────────────────
    InstallDXGIHooks();
    ShimLog("DXGI hooks installed");
    
    // ── WMI (COM hooks) ─────────────────────────────────
    InstallWmiHooks();
    ShimLog("WMI hooks installed");
    
    // ── CPUID VEH Trap ──────────────────────────────────
    InstallCpuidTrap();
    ShimLog("CPUID VEH trap installed");
    
    // ── DRM / Anti-Tamper watch hooks ───────────────────
    InstallDrmHooks();
    
    ShimLog("All hooks installed. Total: %d", g_HookCount);
}

/* ─── DLL Entry Point ────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hSelf = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        
        // Initialize logging
        InitializeCriticalSection(&g_LogLock);
        
        char logPath[MAX_PATH];
        GetTempPathA(MAX_PATH, logPath);
        strcat_s(logPath, GHOST_SANDBOX_LOG_FILE);
        fopen_s(&g_LogFile, logPath, "a");
        
        ShimLog("=== GHOST SANDBOX SHIM v1.0 LOADED ===");
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        ShimLog("Target process: %s (PID %u)", exePath, GetCurrentProcessId());
        
        // Read hardware profile from shared memory
        if (ReadProfileFromSharedMemory()) {
            ShimLog("Hardware profile loaded (magic=0x%08X)", g_Profile.magic);
            ShimLog("Spoofed CPU: %s", g_Profile.cpu.brand_string);
            ShimLog("Spoofed GPU: %s (VEN_%04X DEV_%04X)",
                g_Profile.gpu.name, g_Profile.gpu.vendor_id, g_Profile.gpu.device_id);
        } else {
            ShimLog("WARNING: No hardware profile found in shared memory");
        }
        
        // Connect to controller pipe
        g_Pipe.Init(HandleCommand);
        if (g_Pipe.Connect()) {
            ShimLog("Connected to controller pipe");
            
            // Send connected event
            TraceEventHeader evt = {};
            evt.type = EVT_CONNECTED;
            evt.size = sizeof(evt);
            QueryPerformanceCounter(&evt.timestamp);
            evt.threadId = GetCurrentThreadId();
            g_Pipe.SendEvent(&evt, sizeof(evt));
        } else {
            ShimLog("WARNING: Could not connect to controller pipe (standalone mode)");
        }

        // Publish the initial module list once the pipe is up (also covers the
        // late-connect path when the controller starts after the target).
        CreateThread(NULL, 0, ModuleListThread, NULL, 0, NULL);
        
        // Install all hooks
        DrmInit(&g_Pipe);   // DRM watch events go through the same pipe
        InstallAllHooks();
        PolicyInit(&g_Pipe); // sandbox policy (shared memory -> applied)
        MalwareGuardInit(&g_Pipe); // malware analysis mode (env-configured)
        
        ShimLog("Initialization complete. Ready.");
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        ShimLog("=== GHOST SANDBOX SHIM UNLOADING ===");
        
        // Last-chance drain: final verdicts emitted just before exit are still
        // in the send ring and would be lost when the process dies.
        g_Pipe.Flush();
        g_Pipe.Destroy();
        
        if (g_LogFile) {
            fclose(g_LogFile);
            g_LogFile = NULL;
        }
        
        DeleteCriticalSection(&g_LogLock);
    }
    
    return TRUE;
}
