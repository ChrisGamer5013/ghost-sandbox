/*
   Ghost Sandbox — DRM / Anti-Tamper Watch Mode
   Catches integrity checks, verification calls, anti-debug probes and
   module-scanning DRM tricks. For every intercepted call it reports:
     - which module CALLED it (caller attribution: module + RVA)
     - what a benign environment would have returned ("expected")
     - what the caller actually received ("returned")
     - a verdict (benign / detected / unknown) and extra decoded detail.

   Events are rate-limited per API so hot probes (timing checks, CPUID)
   cannot flood the pipe. Wiring: TraceEventDrm / EVT_DRM in trace_format.h.

   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include "trace_format.h"

/* ─── Mode State ─────────────────────────────────────────── */
/* Toggled by CMD_DRM_MODE; watched only when TRUE. */
static BOOL g_DrmEnabled = TRUE;

/* Pipe used for DRM events; set via DrmInit(&g_Pipe) at startup. */
class PipeClient;
static PipeClient* g_DrmPipe = NULL;
static void DrmInit(PipeClient* pipe) { g_DrmPipe = pipe; }

/* Hard cap on total DRM events per process (safety valve). */
#define GHOST_DRM_MAX_EVENTS 20000
static volatile LONG g_DrmSent = 0;

/* Shared rate-limit counters for the environment/identity probes. */
static LONG g_Thr_EnvProbes = 0;
static LONG g_Thr_NtQsiProbe = 0;

/* ─── Caller Attribution ─────────────────────────────────── */
/* Hooks pass the return address captured with DRM_RET() so the
   attribution points at the APPLICATION call site, not the hook. */
#define DRM_RET() _ReturnAddress()

static HMODULE DrmSelfModule() {
    static HMODULE s_self = NULL;
    if (!s_self) {
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&DrmSelfModule, &s_self);
    }
    return s_self;
}

static HMODULE DrmCallerModule(void* callerRet, ULONGLONG* outRva) {
    HMODULE mod = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)callerRet, &mod) && mod) {
        *outRva = (ULONGLONG)((BYTE*)callerRet - (BYTE*)mod);
        return mod;
    }
    *outRva = (ULONGLONG)(ULONG_PTR)callerRet;
    return NULL;
}

/* TRUE when the call came from inside this shim (our own internals). */
static BOOL DrmCallerIsSelf(void* callerRet) {
    ULONGLONG rva = 0;
    HMODULE caller = DrmCallerModule(callerRet, &rva);
    HMODULE self = DrmSelfModule();
    return caller && self && caller == self;
}

static void DrmModuleBaseName(HMODULE mod, char* out, int outLen) {
    out[0] = 0;
    if (!mod) {
        strncpy_s(out, outLen, "?", _TRUNCATE);
        return;
    }
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(mod, path, MAX_PATH);
    const char* base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    strncpy_s(out, outLen, base, _TRUNCATE);
}

static void DrmWideToUtf8(const WCHAR* src, char* out, int outLen) {
    if (outLen <= 0) return;
    out[0] = 0;
    if (!src) return;
    WideCharToMultiByte(CP_UTF8, 0, src, -1, out, outLen, NULL, NULL);
    out[outLen - 1] = 0;
}

/* ─── Rate Limiting ──────────────────────────────────────── */
/* Log/emit the first `first` calls, then one sample every `every`. */
static BOOL DrmThrottlePass(LONG* counter, LONG first, LONG every) {
    if (!counter) return TRUE;
    LONG n = InterlockedIncrement(counter);
    if (n <= first) return TRUE;
    if (every > 0 && (n % every) == 0) return TRUE;
    return FALSE;
}

/* ─── Event Emission ─────────────────────────────────────── */
/*
   callerRet — return address captured in the hook via DRM_RET()
   force     — send even when DRM mode is off (mode-toggle acks)
*/
static void DrmEmitRaw(void* callerRet, BOOL force,
                       LONG* thr, LONG first, LONG every,
                       DWORD category, DWORD severity, DWORD verdict,
                       const char* api, const char* apiModule,
                       const char* expected, const char* returned,
                       const char* detail, ULONGLONG retValue) {
    /* Anti-tamper code routinely inspects GetLastError() right after the
       watched call. The emission machinery (GetModuleHandleExW, pipe writes,
       shim logging) would clobber it, so capture and restore it. */
    DWORD callerLastError = GetLastError();

    if (!g_DrmEnabled && !force) return;
    if (!DrmThrottlePass(thr, first, every)) return;
    if (InterlockedIncrement(&g_DrmSent) > GHOST_DRM_MAX_EVENTS) return;

    TraceEventDrm ev = {};
    ev.header.type = EVT_DRM;
    ev.header.size = sizeof(ev);
    ev.header.timestamp.QuadPart = (LONGLONG)__rdtsc(); /* never QPC: QPC itself is watched */
    ev.header.threadId = GetCurrentThreadId();

    ev.category = category;
    ev.severity = severity;
    ev.verdict = verdict;
    strncpy_s(ev.api, api ? api : "", _TRUNCATE);
    strncpy_s(ev.apiModule, apiModule ? apiModule : "", _TRUNCATE);

    ULONGLONG rva = 0;
    HMODULE caller = DrmCallerModule(callerRet, &rva);
    DrmModuleBaseName(caller, ev.callerModule, sizeof(ev.callerModule));
    ev.callerRva = rva;

    strncpy_s(ev.expected, expected ? expected : "", _TRUNCATE);
    strncpy_s(ev.returned, returned ? returned : "", _TRUNCATE);
    strncpy_s(ev.detail, detail ? detail : "", _TRUNCATE);
    ev.retValue = retValue;

    if (g_DrmPipe) g_DrmPipe->SendEvent(&ev, sizeof(ev));

    const char* verdictName = verdict == DRM_VERDICT_DETECTED ? "DETECTED"
                            : verdict == DRM_VERDICT_BENIGN ? "benign" : "unknown";
    HOOK_LOG("[DRM] %s.%s -> %s | caller=%s+0x%llX | expected=\"%s\" | returned=\"%s\" | detail=\"%s\"",
        ev.apiModule, ev.api, verdictName, ev.callerModule, ev.callerRva,
        ev.expected, ev.returned, ev.detail);

    SetLastError(callerLastError);
}

static void DrmEmit(void* callerRet,
                    LONG* thr, LONG first, LONG every,
                    DWORD category, DWORD severity, DWORD verdict,
                    const char* api, const char* apiModule,
                    const char* expected, const char* returned,
                    const char* detail, ULONGLONG retValue) {
    DrmEmitRaw(callerRet, FALSE, thr, first, every, category, severity, verdict,
        api, apiModule, expected, returned, detail, retValue);
}

/* ─── Watch Hooks: Debugger Detection ────────────────────── */
typedef BOOL (WINAPI *PFN_IsDebuggerPresent)(void);
typedef BOOL (WINAPI *PFN_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef LONG (NTAPI   *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_IsDebuggerPresent Real_IsDebuggerPresent = NULL;
static PFN_CheckRemoteDebuggerPresent Real_CheckRemoteDebuggerPresent = NULL;
static PFN_NtQueryInformationProcess Real_NtQueryInformationProcess = NULL;

static LONG g_Thr_IsDebuggerPresent = 0;
static LONG g_Thr_CheckRemoteDebugger = 0;
static LONG g_Thr_NtQip = 0;

static BOOL WINAPI Hooked_IsDebuggerPresent(void) {
    void* ra = DRM_RET();
    BOOL r = Real_IsDebuggerPresent ? Real_IsDebuggerPresent() : FALSE;
    DrmEmit(ra, NULL, 0, 0, DRM_CAT_DEBUGGER, DRM_SEV_CRIT,
        r ? DRM_VERDICT_DETECTED : DRM_VERDICT_BENIGN,
        "IsDebuggerPresent", "kernel32.dll",
        "FALSE (no debugger attached)", r ? "TRUE" : "FALSE",
        r ? "Anti-debug check reports a debugger is present"
          : "No debugger reported (spoofing keeps this clean)",
        (ULONGLONG)r);
    return r;
}

static BOOL WINAPI Hooked_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    void* ra = DRM_RET();
    BOOL r = Real_CheckRemoteDebuggerPresent
        ? Real_CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent) : FALSE;
    BOOL present = (r && pbDebuggerPresent) ? *pbDebuggerPresent : FALSE;
    char ret[128];
    snprintf(ret, sizeof(ret), "%s%s", r ? "TRUE" : "FALSE",
        (r && pbDebuggerPresent) ? (present ? ", *present=TRUE" : ", *present=FALSE") : "");
    DrmEmit(ra, &g_Thr_CheckRemoteDebugger, 10, 100, DRM_CAT_DEBUGGER, DRM_SEV_CRIT,
        present ? DRM_VERDICT_DETECTED : (r ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN),
        "CheckRemoteDebuggerPresent", "kernel32.dll",
        "FALSE (no remote debugger)", ret,
        present ? "Remote debugger presence detected" : "Clean result returned to caller",
        (ULONGLONG)r);
    return r;
}

static LONG NTAPI Hooked_NtQueryInformationProcess(
    HANDLE hProcess, ULONG InformationClass, PVOID buf, ULONG len, PULONG retLen) {

    void* ra = DRM_RET();
    LONG st = Real_NtQueryInformationProcess
        ? Real_NtQueryInformationProcess(hProcess, InformationClass, buf, len, retLen)
        : (LONG)0xC0000002; /* STATUS_NOT_IMPLEMENTED */

    char expected[128] = "benign process information";
    char returned[128];
    char detail[128] = "";
    DWORD sev = DRM_SEV_INFO;
    DWORD verdict = DRM_VERDICT_UNKNOWN;

    if (InformationClass == 0x07) {           /* ProcessDebugPort */
        ULONG_PTR port = 0;
        if (st == 0 && buf) {
            __try { port = *(ULONG_PTR*)buf; } __except (EXCEPTION_EXECUTE_HANDLER) { port = 0; }
        }
        snprintf(expected, sizeof(expected), "ProcessDebugPort = 0 (not being debugged)");
        snprintf(returned, sizeof(returned), "status=0x%08lX, port=0x%llX",
            (unsigned long)st, (unsigned long long)port);
        snprintf(detail, sizeof(detail), "class=ProcessDebugPort(7)");
        sev = DRM_SEV_CRIT;
        verdict = (st == 0) ? (port == 0 ? DRM_VERDICT_BENIGN : DRM_VERDICT_DETECTED)
                            : DRM_VERDICT_UNKNOWN;
    } else if (InformationClass == 0x1E) {    /* ProcessDebugObjectHandle */
        ULONG_PTR handle = 0;
        if (st == 0 && buf) {
            __try { handle = *(ULONG_PTR*)buf; } __except (EXCEPTION_EXECUTE_HANDLER) { handle = 0; }
        }
        snprintf(expected, sizeof(expected), "ProcessDebugObjectHandle = NULL");
        snprintf(returned, sizeof(returned), "status=0x%08lX, handle=0x%llX",
            (unsigned long)st, (unsigned long long)handle);
        snprintf(detail, sizeof(detail), "class=ProcessDebugObjectHandle(0x1E)");
        sev = DRM_SEV_CRIT;
        verdict = (st == 0) ? (handle == 0 ? DRM_VERDICT_BENIGN : DRM_VERDICT_DETECTED)
                            : DRM_VERDICT_UNKNOWN;
    } else if (InformationClass == 0x1F) {    /* ProcessDebugFlags */
        ULONG flags = 0;
        if (st == 0 && buf) {
            __try { flags = *(ULONG*)buf; } __except (EXCEPTION_EXECUTE_HANDLER) { flags = 0; }
        }
        snprintf(expected, sizeof(expected), "ProcessDebugFlags = 1 (NoDebugInherit set)");
        snprintf(returned, sizeof(returned), "status=0x%08lX, flags=%lu",
            (unsigned long)st, (unsigned long)flags);
        snprintf(detail, sizeof(detail), "class=ProcessDebugFlags(0x1F)");
        sev = DRM_SEV_CRIT;
        verdict = (st == 0) ? (flags == 1 ? DRM_VERDICT_BENIGN : DRM_VERDICT_DETECTED)
                            : DRM_VERDICT_UNKNOWN;
    } else {
        snprintf(returned, sizeof(returned), "status=0x%08lX", (unsigned long)st);
        snprintf(detail, sizeof(detail), "class=0x%X", InformationClass);
    }

    DrmEmit(ra, &g_Thr_NtQip, 10, 100, DRM_CAT_DEBUGGER, sev, verdict,
        "NtQueryInformationProcess", "ntdll.dll",
        expected, returned, detail, (ULONGLONG)(ULONG_PTR)st);
    return st;
}

/* ─── Watch Hooks: Integrity / Checksums ─────────────────── */
typedef DWORD (WINAPI *PFN_MapFileAndCheckSumA)(PCSTR, PDWORD, PDWORD);
typedef DWORD (WINAPI *PFN_MapFileAndCheckSumW)(PCWSTR, PDWORD, PDWORD);
typedef PIMAGE_NT_HEADERS (WINAPI *PFN_CheckSumMappedFile)(PVOID, DWORD, PDWORD, PDWORD);

static PFN_MapFileAndCheckSumA Real_MapFileAndCheckSumA = NULL;
static PFN_MapFileAndCheckSumW Real_MapFileAndCheckSumW = NULL;
static PFN_CheckSumMappedFile Real_CheckSumMappedFile = NULL;

static DWORD WINAPI Hooked_MapFileAndCheckSumA(PCSTR filename, PDWORD headerSum, PDWORD checkSum) {
    void* ra = DRM_RET();
    DWORD r = Real_MapFileAndCheckSumA ? Real_MapFileAndCheckSumA(filename, headerSum, checkSum) : 1;
    char ret[192];
    snprintf(ret, sizeof(ret), "status=%lu, headerSum=0x%08X, checkSum=0x%08X",
        (unsigned long)r, headerSum ? *headerSum : 0, checkSum ? *checkSum : 0);
    DrmEmit(ra, NULL, 0, 0, DRM_CAT_INTEGRITY, DRM_SEV_CRIT,
        (r == 0) ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
        "MapFileAndCheckSumA", "imagehlp.dll",
        "CHECKSUM_SUCCESS(0) + caller compares sum against stored value", ret,
        filename ? filename : "(null)", (ULONGLONG)r);
    return r;
}

static DWORD WINAPI Hooked_MapFileAndCheckSumW(PCWSTR filename, PDWORD headerSum, PDWORD checkSum) {
    void* ra = DRM_RET();
    DWORD r = Real_MapFileAndCheckSumW ? Real_MapFileAndCheckSumW(filename, headerSum, checkSum) : 1;
    char ret[192], file[260];
    snprintf(ret, sizeof(ret), "status=%lu, headerSum=0x%08X, checkSum=0x%08X",
        (unsigned long)r, headerSum ? *headerSum : 0, checkSum ? *checkSum : 0);
    DrmWideToUtf8(filename, file, sizeof(file));
    DrmEmit(ra, NULL, 0, 0, DRM_CAT_INTEGRITY, DRM_SEV_CRIT,
        (r == 0) ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
        "MapFileAndCheckSumW", "imagehlp.dll",
        "CHECKSUM_SUCCESS(0) + caller compares sum against stored value", ret,
        file[0] ? file : "(null)", (ULONGLONG)r);
    return r;
}

static PIMAGE_NT_HEADERS WINAPI Hooked_CheckSumMappedFile(
    PVOID baseAddress, DWORD fileLength, PDWORD headerSum, PDWORD checkSum) {
    void* ra = DRM_RET();
    PIMAGE_NT_HEADERS r = Real_CheckSumMappedFile
        ? Real_CheckSumMappedFile(baseAddress, fileLength, headerSum, checkSum) : NULL;
    char ret[160];
    snprintf(ret, sizeof(ret), "ntHeaders=%s, headerSum=0x%08X, checkSum=0x%08X",
        r ? "valid" : "NULL", headerSum ? *headerSum : 0, checkSum ? *checkSum : 0);
    char det[160];
    snprintf(det, sizeof(det), "image=%p, fileLength=%lu", baseAddress, (unsigned long)fileLength);
    DrmEmit(ra, NULL, 0, 0, DRM_CAT_INTEGRITY, DRM_SEV_CRIT, DRM_VERDICT_UNKNOWN,
        "CheckSumMappedFile", "imagehlp.dll",
        "checksum computed for caller comparison (self-integrity hash)", ret, det,
        (ULONGLONG)(ULONG_PTR)r);
    return r;
}

/* ─── Watch Hooks: Crypto Verification ───────────────────── */
typedef BOOL (WINAPI *PFN_CryptVerifySignatureW)(HCRYPTHASH, const BYTE*, DWORD, HCRYPTKEY, LPCWSTR, DWORD);
static PFN_CryptVerifySignatureW Real_CryptVerifySignatureW = NULL;

static BOOL WINAPI Hooked_CryptVerifySignatureW(
    HCRYPTHASH hHash, const BYTE* pbSignature, DWORD dwSigLen,
    HCRYPTKEY hPubKey, LPCWSTR szDescription, DWORD dwFlags) {
    void* ra = DRM_RET();
    BOOL r = Real_CryptVerifySignatureW
        ? Real_CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags) : FALSE;
    char det[192], desc[128];
    DrmWideToUtf8(szDescription, desc, sizeof(desc));
    snprintf(det, sizeof(det), "sigLen=%lu, description=\"%s\", flags=0x%X",
        (unsigned long)dwSigLen, desc, dwFlags);
    DrmEmit(ra, NULL, 0, 0, DRM_CAT_CRYPTO, DRM_SEV_CRIT,
        r ? DRM_VERDICT_BENIGN : DRM_VERDICT_UNKNOWN,
        "CryptVerifySignatureW", "advapi32.dll",
        "TRUE (signature validates against the embedded key)",
        r ? "TRUE" : "FALSE", det, (ULONGLONG)r);
    return r;
}

/* ─── Watch Hooks: Module / Process Scanning ─────────────── */
typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (WINAPI *PFN_EnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD (WINAPI *PFN_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);

static PFN_CreateToolhelp32Snapshot Real_CreateToolhelp32Snapshot = NULL;
static PFN_EnumProcessModules Real_EnumProcessModules = NULL;
static PFN_GetModuleFileNameW Real_GetModuleFileNameW = NULL;

static LONG g_Thr_Toolhelp32 = 0;
static LONG g_Thr_EnumModules = 0;
static LONG g_Thr_GetModuleFileName = 0;

static HANDLE WINAPI Hooked_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    void* ra = DRM_RET();
    HANDLE r = Real_CreateToolhelp32Snapshot
        ? Real_CreateToolhelp32Snapshot(dwFlags, th32ProcessID) : INVALID_HANDLE_VALUE;
    BOOL moduleSnap = (dwFlags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) != 0;
    char ret[64], det[160];
    snprintf(ret, sizeof(ret), "handle=%s",
        r != INVALID_HANDLE_VALUE ? "valid" : "INVALID_HANDLE_VALUE");
    snprintf(det, sizeof(det), "flags=0x%X%s, pid=%lu", dwFlags,
        moduleSnap ? " (MODULE scan)" : ((dwFlags & TH32CS_SNAPPROCESS) ? " (process scan)" : ""),
        (unsigned long)th32ProcessID);
    DrmEmit(ra, &g_Thr_Toolhelp32, 10, 100,
        DRM_CAT_MODULE_SCAN, moduleSnap ? DRM_SEV_CRIT : DRM_SEV_INFO, DRM_VERDICT_UNKNOWN,
        "CreateToolhelp32Snapshot", "kernel32.dll",
        moduleSnap ? "enumerating loaded modules (hunts injected DLLs / hooks)"
                   : "enumerating system state",
        ret, det, (ULONGLONG)(ULONG_PTR)r);
    return r;
}

static BOOL WINAPI Hooked_EnumProcessModules(
    HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
    void* ra = DRM_RET();
    BOOL r = Real_EnumProcessModules
        ? Real_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded) : FALSE;
    DWORD count = (r && lpcbNeeded) ? (*lpcbNeeded / (DWORD)sizeof(HMODULE)) : 0;
    char ret[96], det[160];
    snprintf(ret, sizeof(ret), "ok=%s, modules=%lu", r ? "TRUE" : "FALSE", (unsigned long)count);
    snprintf(det, sizeof(det), "hProcess=0x%p%s", hProcess,
        (hProcess == GetCurrentProcess()) ? " (own process)" : "");
    DrmEmit(ra, &g_Thr_EnumModules, 10, 100, DRM_CAT_MODULE_SCAN, DRM_SEV_CRIT,
        DRM_VERDICT_UNKNOWN, "EnumProcessModules", "psapi.dll",
        "no foreign/injected modules visible in the list", ret, det,
        (ULONGLONG)(ULONG_PTR)r);
    return r;
}

static DWORD WINAPI Hooked_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    void* ra = DRM_RET();
    DWORD r = Real_GetModuleFileNameW ? Real_GetModuleFileNameW(hModule, lpFilename, nSize) : 0;
    /* Only report self-location checks (the common DRM/anti-tamper case). */
    if (hModule == NULL || hModule == GetModuleHandleW(NULL)) {
        char path[520];
        DrmWideToUtf8(lpFilename, path, sizeof(path));
        DrmEmit(ra, &g_Thr_GetModuleFileName, 10, 100, DRM_CAT_MODULE_SCAN, DRM_SEV_INFO,
            DRM_VERDICT_UNKNOWN, "GetModuleFileNameW", "kernel32.dll",
            "own image path (self-location / path-spoofing check)",
            r ? path : "(failed)", r == 0 ? "call failed — loader may be tampered" : "",
            (ULONGLONG)r);
    }
    return r;
}

/* ─── Watch Hooks: Memory Protection ─────────────────────── */
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
static PFN_VirtualProtect Real_VirtualProtect = NULL;
static LONG g_Thr_VirtualProtect = 0;

static BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    void* ra = DRM_RET();
    BOOL r = Real_VirtualProtect
        ? Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
    /* The shim itself patches memory via VirtualProtect — never report our own calls. */
    if (DrmCallerIsSelf(ra)) return r;

    BOOL exec = (flNewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    char retVal[96], det[192];
    snprintf(retVal, sizeof(retVal), "ok=%s, oldProtect=0x%X", r ? "TRUE" : "FALSE",
        (r && lpflOldProtect) ? *lpflOldProtect : 0);
    snprintf(det, sizeof(det), "addr=0x%llX, size=%llu, newProtect=0x%X%s",
        (unsigned long long)(ULONG_PTR)lpAddress, (unsigned long long)dwSize,
        flNewProtect, exec ? " (executable)" : "");
    DrmEmit(ra, &g_Thr_VirtualProtect, 20, 200, DRM_CAT_MEMORY,
        exec ? DRM_SEV_WARN : DRM_SEV_INFO, DRM_VERDICT_UNKNOWN,
        "VirtualProtect", "kernel32.dll",
        "page protection change (unpacking / self-modification / anti-tamper)",
        retVal, det, (ULONGLONG)r);
    return r;
}

/* ─── Watch Hooks: Timing Probes ─────────────────────────── */
typedef BOOL (WINAPI *PFN_QueryPerformanceCounter)(LARGE_INTEGER*);
typedef ULONGLONG (WINAPI *PFN_GetTickCount64)(void);
static PFN_QueryPerformanceCounter Real_QueryPerformanceCounter = NULL;
static PFN_GetTickCount64 Real_GetTickCount64 = NULL;

static LONG g_Thr_Qpc = 0;
static LONG g_Thr_Gtc64 = 0;

static BOOL WINAPI Hooked_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    void* ra = DRM_RET();
    BOOL r = Real_QueryPerformanceCounter
        ? Real_QueryPerformanceCounter(lpPerformanceCount) : FALSE;
    /* Silence the shim's own timing (hook duration sampling etc.). */
    if (!DrmCallerIsSelf(ra)) {
        DrmEmit(ra, &g_Thr_Qpc, 10, 2000, DRM_CAT_TIMING, DRM_SEV_INFO, DRM_VERDICT_UNKNOWN,
            "QueryPerformanceCounter", "kernel32.dll",
            "monotonic high-resolution clock (anti-debug measures call deltas)",
            r ? "counter read" : "FALSE", "",
            (ULONGLONG)((r && lpPerformanceCount) ? lpPerformanceCount->QuadPart : 0));
    }
    return r;
}

static ULONGLONG WINAPI Hooked_GetTickCount64(void) {
    void* ra = DRM_RET();
    ULONGLONG r = Real_GetTickCount64 ? Real_GetTickCount64() : 0;
    if (!DrmCallerIsSelf(ra)) {
        DrmEmit(ra, &g_Thr_Gtc64, 10, 2000, DRM_CAT_TIMING, DRM_SEV_INFO, DRM_VERDICT_UNKNOWN,
            "GetTickCount64", "kernel32.dll",
            "system uptime in ms (anti-debug measures elapsed time)",
            "value read", "", (ULONGLONG)r);
    }
    return r;
}

/* ─── Install ────────────────────────────────────────────── */
static void InstallDrmHooks() {
    HOOK_LOG("Installing DRM watch hooks...");

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt  = GetModuleHandleA("ntdll.dll");
    HMODULE cr  = GetModuleHandleA("crypt32.dll");
    if (!cr) cr = LoadLibraryA("crypt32.dll");
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    if (!adv) adv = LoadLibraryA("advapi32.dll");
    HMODULE ih  = LoadLibraryA("imagehlp.dll");
    HMODULE ps  = LoadLibraryA("psapi.dll");

    if (k32) {
        Real_IsDebuggerPresent = (PFN_IsDebuggerPresent)GetProcAddress(k32, "IsDebuggerPresent");
        if (Real_IsDebuggerPresent)
            InstallInlineHook((void*)Real_IsDebuggerPresent, (void*)Hooked_IsDebuggerPresent,
                (void**)&Real_IsDebuggerPresent, "IsDebuggerPresent");

        Real_CheckRemoteDebuggerPresent = (PFN_CheckRemoteDebuggerPresent)
            GetProcAddress(k32, "CheckRemoteDebuggerPresent");
        if (Real_CheckRemoteDebuggerPresent)
            InstallInlineHook((void*)Real_CheckRemoteDebuggerPresent, (void*)Hooked_CheckRemoteDebuggerPresent,
                (void**)&Real_CheckRemoteDebuggerPresent, "CheckRemoteDebuggerPresent");

        Real_VirtualProtect = (PFN_VirtualProtect)GetProcAddress(k32, "VirtualProtect");
        if (Real_VirtualProtect)
            InstallInlineHook((void*)Real_VirtualProtect, (void*)Hooked_VirtualProtect,
                (void**)&Real_VirtualProtect, "VirtualProtect");

        Real_CreateToolhelp32Snapshot = (PFN_CreateToolhelp32Snapshot)
            GetProcAddress(k32, "CreateToolhelp32Snapshot");
        if (Real_CreateToolhelp32Snapshot)
            InstallInlineHook((void*)Real_CreateToolhelp32Snapshot, (void*)Hooked_CreateToolhelp32Snapshot,
                (void**)&Real_CreateToolhelp32Snapshot, "CreateToolhelp32Snapshot");

        Real_GetModuleFileNameW = (PFN_GetModuleFileNameW)GetProcAddress(k32, "GetModuleFileNameW");
        if (Real_GetModuleFileNameW)
            InstallInlineHook((void*)Real_GetModuleFileNameW, (void*)Hooked_GetModuleFileNameW,
                (void**)&Real_GetModuleFileNameW, "GetModuleFileNameW");

        Real_QueryPerformanceCounter = (PFN_QueryPerformanceCounter)
            GetProcAddress(k32, "QueryPerformanceCounter");
        if (Real_QueryPerformanceCounter)
            InstallInlineHook((void*)Real_QueryPerformanceCounter, (void*)Hooked_QueryPerformanceCounter,
                (void**)&Real_QueryPerformanceCounter, "QueryPerformanceCounter");

        Real_GetTickCount64 = (PFN_GetTickCount64)GetProcAddress(k32, "GetTickCount64");
        if (Real_GetTickCount64)
            InstallInlineHook((void*)Real_GetTickCount64, (void*)Hooked_GetTickCount64,
                (void**)&Real_GetTickCount64, "GetTickCount64");
    }

    if (nt) {
        Real_NtQueryInformationProcess = (PFN_NtQueryInformationProcess)
            GetProcAddress(nt, "NtQueryInformationProcess");
        if (Real_NtQueryInformationProcess)
            InstallInlineHook((void*)Real_NtQueryInformationProcess, (void*)Hooked_NtQueryInformationProcess,
                (void**)&Real_NtQueryInformationProcess, "NtQueryInformationProcess");
    }

    if (ih) {
        Real_MapFileAndCheckSumA = (PFN_MapFileAndCheckSumA)GetProcAddress(ih, "MapFileAndCheckSumA");
        if (Real_MapFileAndCheckSumA)
            InstallInlineHook((void*)Real_MapFileAndCheckSumA, (void*)Hooked_MapFileAndCheckSumA,
                (void**)&Real_MapFileAndCheckSumA, "MapFileAndCheckSumA");

        Real_MapFileAndCheckSumW = (PFN_MapFileAndCheckSumW)GetProcAddress(ih, "MapFileAndCheckSumW");
        if (Real_MapFileAndCheckSumW)
            InstallInlineHook((void*)Real_MapFileAndCheckSumW, (void*)Hooked_MapFileAndCheckSumW,
                (void**)&Real_MapFileAndCheckSumW, "MapFileAndCheckSumW");

        Real_CheckSumMappedFile = (PFN_CheckSumMappedFile)GetProcAddress(ih, "CheckSumMappedFile");
        if (Real_CheckSumMappedFile)
            InstallInlineHook((void*)Real_CheckSumMappedFile, (void*)Hooked_CheckSumMappedFile,
                (void**)&Real_CheckSumMappedFile, "CheckSumMappedFile");
    }

    if (cr) {
        Real_CryptVerifySignatureW = (PFN_CryptVerifySignatureW)
            GetProcAddress(cr, "CryptVerifySignatureW");
    }
    if (!Real_CryptVerifySignatureW && adv) {
        /* CryptoAPI's CryptVerifySignatureW is exported by advapi32. */
        Real_CryptVerifySignatureW = (PFN_CryptVerifySignatureW)
            GetProcAddress(adv, "CryptVerifySignatureW");
    }
    if (Real_CryptVerifySignatureW)
        InstallInlineHook((void*)Real_CryptVerifySignatureW, (void*)Hooked_CryptVerifySignatureW,
            (void**)&Real_CryptVerifySignatureW, "CryptVerifySignatureW");

    /* EnumProcessModules lives in psapi (kernel32 exposes K32EnumProcessModules). */
    if (ps) Real_EnumProcessModules = (PFN_EnumProcessModules)GetProcAddress(ps, "EnumProcessModules");
    if (!Real_EnumProcessModules && k32)
        Real_EnumProcessModules = (PFN_EnumProcessModules)GetProcAddress(k32, "K32EnumProcessModules");
    if (Real_EnumProcessModules)
        InstallInlineHook((void*)Real_EnumProcessModules, (void*)Hooked_EnumProcessModules,
            (void**)&Real_EnumProcessModules, "EnumProcessModules");

    HOOK_LOG("DRM watch hooks installed (%d total hooks)", g_HookCount);
}
