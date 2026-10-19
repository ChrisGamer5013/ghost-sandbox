/*
   Ghost Sandbox — hook engine self-test
   Validates shim/hook_engine.h against this machine's real system DLLs:
     1. decodes the prologue of every function the shim hooks
     2. installs inline hooks on safe APIs and calls them through the hook
     3. verifies the trampoline reaches the original implementation
     4. unhooks and verifies the original bytes are restored exactly
   Compile (from a vcvars64 prompt or with cl on PATH):
     cl /nologo /O2 /EHsc /MT /utf-8 hook_selftest.cpp /I..\..\shim ^
        /Fe:hook_selftest.exe /link kernel32.lib user32.lib
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static int g_calls = 0;
static int g_pass = 0;
static int g_fail = 0;

static void ShimLog(const char* fmt, ...) {
    va_list a;
    va_start(a, fmt);
    vfprintf(stdout, fmt, a);
    va_end(a);
    fputc('\n', stdout);
    fflush(stdout);
}
#define HOOK_LOG(...) ShimLog(__VA_ARGS__)

#include "hook_engine.h"
#include "pipe_client.h"
#include "drm_watch.h"
#include "policy_watch.h"

#define CHECK(cond, msg) \
    do { if (cond) { g_pass++; ShimLog("  PASS: %s", msg); } \
         else { g_fail++; ShimLog("  FAIL: %s", msg); } } while (0)

/* ── Real pointers ─────────────────────────────────────────── */
typedef HMODULE (WINAPI *PFN_LLA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LLW)(LPCWSTR);
typedef FARPROC (WINAPI *PFN_GPA)(HMODULE, LPCSTR);
typedef void    (WINAPI *PFN_GSI)(LPSYSTEM_INFO);
typedef BOOL    (WINAPI *PFN_GMS)(LPMEMORYSTATUSEX);
typedef BOOL    (WINAPI *PFN_GCN)(LPWSTR, LPDWORD);
typedef BOOL    (WINAPI *PFN_IPFP)(DWORD);
typedef LONG (NTAPI    *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);

static PFN_LLA  Real_LLA = NULL;
static PFN_LLW  Real_LLW = NULL;
static PFN_GPA  Real_GPA = NULL;
static PFN_GSI  Real_GSI = NULL;
static PFN_GMS  Real_GMS = NULL;
static PFN_GCN  Real_GCN = NULL;
static PFN_IPFP Real_IPFP = NULL;
static PFN_NTQSI Real_NTQSI = NULL;
static PFN_NTQSI StubNtQsi = NULL;   // raw stub address, pre-patch

/* ── Hook shims ────────────────────────────────────────────── */
static HMODULE WINAPI Hook_LLA(LPCSTR n)            { g_calls++; return Real_LLA(n); }
static HMODULE WINAPI Hook_LLW(LPCWSTR n)           { g_calls++; return Real_LLW(n); }
static FARPROC WINAPI Hook_GPA(HMODULE h, LPCSTR n) { g_calls++; return Real_GPA(h, n); }
static void    WINAPI Hook_GSI(LPSYSTEM_INFO si)    { g_calls++; Real_GSI(si); }
static BOOL    WINAPI Hook_GMS(LPMEMORYSTATUSEX ms) { g_calls++; return Real_GMS(ms); }
static BOOL    WINAPI Hook_GCN(LPWSTR b, LPDWORD s) { g_calls++; return Real_GCN(b, s); }
static BOOL    WINAPI Hook_IPFP(DWORD f)            { g_calls++; return Real_IPFP(f); }
static LONG NTAPI      Hook_NTQSI(ULONG c, PVOID b, ULONG l, PULONG r) {
    g_calls++; return Real_NTQSI(c, b, l, r);
}

/* DRM call-through shims (section 7) */
typedef BOOL      (WINAPI *PFN_DRM_IDP)(void);
typedef ULONGLONG (WINAPI *PFN_DRM_GTC)(void);
typedef BOOL      (WINAPI *PFN_DRM_QPC)(LARGE_INTEGER*);
typedef BOOL      (WINAPI *PFN_DRM_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
static PFN_DRM_IDP Real_DRM_IDP = NULL;
static PFN_DRM_GTC Real_DRM_GTC = NULL;
static PFN_DRM_QPC Real_DRM_QPC = NULL;
static PFN_DRM_VP  Real_DRM_VP = NULL;
static BOOL      WINAPI DrmHook_IDP(void)          { g_calls++; return Real_DRM_IDP(); }
static ULONGLONG WINAPI DrmHook_GTC(void)          { g_calls++; return Real_DRM_GTC(); }
static BOOL      WINAPI DrmHook_QPC(LARGE_INTEGER* p) { g_calls++; return Real_DRM_QPC(p); }
static BOOL      WINAPI DrmHook_VP(LPVOID a, SIZE_T s, DWORD p, PDWORD o) { g_calls++; return Real_DRM_VP(a, s, p, o); }

/* Policy engine test targets (section 8) — plain functions used as fake IAT slots. */
static int g_PolicyTargetCalls = 0;
static __declspec(noinline) int _PolicyTargetAdd(int a, int b) { g_PolicyTargetCalls++; return a + b + 100; }
static __declspec(noinline) int _PolicyTargetMul(int a, int b) { g_PolicyTargetCalls++; return a * b; }

/* ── Helpers ───────────────────────────────────────────────── */
static void DecodeReport(const char* label, void* fn) {
    BYTE code[32];
    memcpy(code, fn, sizeof(code));
    InsnInfo ii;
    int len = DecodeInsn64(code, (int)sizeof(code), &ii);
    if (len > 0) {
        ShimLog("  decode %-30s len=%2d relocs=%d  [%02X %02X %02X %02X %02X %02X %02X %02X]",
            label, len, ii.nRelocs,
            code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7]);
    } else {
        ShimLog("  decode %-30s UNSUPPORTED  [%02X %02X %02X %02X %02X %02X %02X %02X]",
            label, code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7]);
    }
}

static void SaveBytes(void* fn, BYTE* out, int n) { memcpy(out, fn, n); }
static BOOL BytesEqual(void* fn, const BYTE* ref, int n) { return memcmp(fn, ref, n) == 0; }

int main() {
    ShimLog("=== Ghost Sandbox hook engine self-test ===");

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE kb  = GetModuleHandleA("kernelbase.dll");
    HMODULE nt  = GetModuleHandleA("ntdll.dll");
    HMODULE sa  = LoadLibraryA("setupapi.dll");
    HMODULE wt  = LoadLibraryA("wintrust.dll");
    HMODULE cr  = LoadLibraryA("crypt32.dll");
    HMODULE ip  = LoadLibraryA("iphlpapi.dll");
    HMODULE dx  = LoadLibraryA("dxgi.dll");
    HMODULE ol  = LoadLibraryA("ole32.dll");

    /* ── 1. Decoder report over every shim target ──────────── */
    ShimLog("[1] prologue decode of shim targets:");
    DecodeReport("kernel32!LoadLibraryA",        (void*)GetProcAddress(k32, "LoadLibraryA"));
    DecodeReport("kernel32!LoadLibraryW",        (void*)GetProcAddress(k32, "LoadLibraryW"));
    DecodeReport("kernel32!GetProcAddress",      (void*)GetProcAddress(k32, "GetProcAddress"));
    DecodeReport("kernel32!GetSystemInfo",       (void*)GetProcAddress(k32, "GetSystemInfo"));
    DecodeReport("kernel32!GlobalMemoryStatusEx",(void*)GetProcAddress(k32, "GlobalMemoryStatusEx"));
    DecodeReport("kernel32!GetComputerNameW",    (void*)GetProcAddress(k32, "GetComputerNameW"));
    DecodeReport("kernel32!IsProcessorFeaturePresent", (void*)GetProcAddress(k32, "IsProcessorFeaturePresent"));
    DecodeReport("ntdll!NtQuerySystemInformation", (void*)GetProcAddress(nt, "NtQuerySystemInformation"));
    DecodeReport("kernelbase!GetSystemFirmwareTable", (void*)GetProcAddress(kb, "GetSystemFirmwareTable"));
    DecodeReport("kernelbase!RegQueryValueExW",  (void*)GetProcAddress(kb, "RegQueryValueExW"));
    DecodeReport("setupapi!SetupDiGetDeviceRegistryPropertyW", (void*)GetProcAddress(sa, "SetupDiGetDeviceRegistryPropertyW"));
    DecodeReport("wintrust!WinVerifyTrust",      (void*)GetProcAddress(wt, "WinVerifyTrust"));
    DecodeReport("crypt32!CertVerifyCertificateChainPolicy", (void*)GetProcAddress(cr, "CertVerifyCertificateChainPolicy"));
    DecodeReport("iphlpapi!GetAdaptersAddresses",(void*)GetProcAddress(ip, "GetAdaptersAddresses"));
    DecodeReport("ole32!CoCreateInstance",       (void*)GetProcAddress(ol, "CoCreateInstance"));
    DecodeReport("dxgi!CreateDXGIFactory",       (void*)GetProcAddress(dx, "CreateDXGIFactory"));
    DecodeReport("dxgi!CreateDXGIFactory1",      (void*)GetProcAddress(dx, "CreateDXGIFactory1"));

    /* ── 2. Install hooks on callable APIs ─────────────────── */
    ShimLog("[2] installing hooks:");
    BYTE origGPA[8];
    SaveBytes((void*)GetProcAddress(k32, "GetProcAddress"), origGPA, 8);

    Real_LLA  = (PFN_LLA) GetProcAddress(k32, "LoadLibraryA");
    Real_LLW  = (PFN_LLW) GetProcAddress(k32, "LoadLibraryW");
    Real_GPA  = (PFN_GPA) GetProcAddress(k32, "GetProcAddress");
    Real_GSI  = (PFN_GSI) GetProcAddress(k32, "GetSystemInfo");
    Real_GMS  = (PFN_GMS) GetProcAddress(k32, "GlobalMemoryStatusEx");
    Real_GCN  = (PFN_GCN) GetProcAddress(k32, "GetComputerNameW");
    Real_IPFP = (PFN_IPFP)GetProcAddress(k32, "IsProcessorFeaturePresent");
    Real_NTQSI= (PFN_NTQSI)GetProcAddress(nt, "NtQuerySystemInformation");
    StubNtQsi = Real_NTQSI;

    // Ground truth: call the untouched stub once before any patching
    BYTE sbi0[256]; ULONG rl0 = 0;
    LONG st0 = StubNtQsi(0, sbi0, sizeof(sbi0), &rl0);
    ShimLog("  baseline NtQSI (unhooked) = 0x%08X, retLen=%u", (unsigned)st0, (unsigned)rl0);

    int hLLA  = InstallInlineHook((void*)Real_LLA,  (void*)Hook_LLA,  (void**)&Real_LLA,  "LoadLibraryA");
    int hLLW  = InstallInlineHook((void*)Real_LLW,  (void*)Hook_LLW,  (void**)&Real_LLW,  "LoadLibraryW");
    int hGPA  = InstallInlineHook((void*)Real_GPA,  (void*)Hook_GPA,  (void**)&Real_GPA,  "GetProcAddress");
    int hGSI  = InstallInlineHook((void*)Real_GSI,  (void*)Hook_GSI,  (void**)&Real_GSI,  "GetSystemInfo");
    int hGMS  = InstallInlineHook((void*)Real_GMS,  (void*)Hook_GMS,  (void**)&Real_GMS,  "GlobalMemoryStatusEx");
    int hGCN  = InstallInlineHook((void*)Real_GCN,  (void*)Hook_GCN,  (void**)&Real_GCN,  "GetComputerNameW");
    int hIPFP = InstallInlineHook((void*)Real_IPFP, (void*)Hook_IPFP, (void**)&Real_IPFP, "IsProcessorFeaturePresent");
    int hNTQ  = InstallInlineHook((void*)Real_NTQSI, (void*)Hook_NTQSI, (void**)&Real_NTQSI, "NtQuerySystemInformation");

    CHECK(hLLA >= 0,  "LoadLibraryA hook installed");
    CHECK(hLLW >= 0,  "LoadLibraryW hook installed");
    CHECK(hGPA >= 0,  "GetProcAddress hook installed");
    CHECK(hGSI >= 0,  "GetSystemInfo hook installed");
    CHECK(hGMS >= 0,  "GlobalMemoryStatusEx hook installed");
    CHECK(hGCN >= 0,  "GetComputerNameW hook installed");
    CHECK(hIPFP >= 0, "IsProcessorFeaturePresent hook installed");
    CHECK(hNTQ >= 0,  "NtQuerySystemInformation hook installed");
    ShimLog("  g_HookCount = %d", g_HookCount);

    /* ── 3. Call every hooked API through the hook+trampoline ─ */
    ShimLog("[3] calling hooked APIs (this would crash with the v1 engine):");
    g_calls = 0;

    HMODULE v1 = LoadLibraryA("version.dll");
    CHECK(v1 != NULL, "LoadLibraryA(\"version.dll\") works through hook");

    HMODULE v2 = LoadLibraryW(L"version.dll");
    CHECK(v2 != NULL, "LoadLibraryW through hook");

    FARPROC p1 = GetProcAddress(k32, "VirtualAlloc");
    CHECK(p1 != NULL, "GetProcAddress through hook");

    SYSTEM_INFO si; ZeroMemory(&si, sizeof(si));
    GetSystemInfo(&si);
    CHECK(si.dwPageSize == 4096 || si.dwNumberOfProcessors > 0, "GetSystemInfo through hook");

    MEMORYSTATUSEX ms; ZeroMemory(&ms, sizeof(ms)); ms.dwLength = sizeof(ms);
    BOOL msOk = GlobalMemoryStatusEx(&ms);
    CHECK(msOk && ms.ullTotalPhys > 0, "GlobalMemoryStatusEx through hook");

    WCHAR cname[64]; DWORD csz = 64;
    CHECK(GetComputerNameW(cname, &csz) != FALSE, "GetComputerNameW through hook");

    BOOL pf = IsProcessorFeaturePresent(PF_COMPARE_EXCHANGE_DOUBLE);
    CHECK(pf == TRUE || pf == FALSE, "IsProcessorFeaturePresent through hook");

    BYTE sbi[256]; ULONG retLen = 0;
    LONG st = StubNtQsi(0 /* SystemBasicInformation */, sbi, sizeof(sbi), &retLen);
    ShimLog("  NtQSI hooked   = 0x%08X, retLen=%u, first dword=0x%08X",
            (unsigned)st, (unsigned)retLen, *(unsigned*)sbi);
    CHECK(st == st0, "NtQuerySystemInformation: hooked result == unhooked baseline");

    CHECK(g_calls >= 8, "all 8 hooks were reached");
    ShimLog("  hook call count = %d", g_calls);

    /* ── 4. Install + immediately remove the risky hooks ────── */
    ShimLog("[4] patch/restore mechanics on remaining targets:");
    struct { const char* label; void* fn; } others[] = {
        { "SetupDiGetDeviceRegistryPropertyW", (void*)GetProcAddress(sa, "SetupDiGetDeviceRegistryPropertyW") },
        { "WinVerifyTrust",                    (void*)GetProcAddress(wt, "WinVerifyTrust") },
        { "CertVerifyCertificateChainPolicy",  (void*)GetProcAddress(cr, "CertVerifyCertificateChainPolicy") },
        { "GetAdaptersAddresses",              (void*)GetProcAddress(ip, "GetAdaptersAddresses") },
        { "CoCreateInstance",                  (void*)GetProcAddress(ol, "CoCreateInstance") },
        { "CreateDXGIFactory",                 (void*)GetProcAddress(dx, "CreateDXGIFactory") },
        { "CreateDXGIFactory1",                (void*)GetProcAddress(dx, "CreateDXGIFactory1") },
    };
    for (int i = 0; i < _countof(others); i++) {
        if (!others[i].fn) { ShimLog("  (skip %s — not found)", others[i].label); continue; }
        BYTE before[16]; SaveBytes(others[i].fn, before, 16);
        void* trampOut = NULL;
        int idx = InstallInlineHook(others[i].fn, (void*)Hook_IPFP, &trampOut, others[i].label);
        BOOL restored = FALSE;
        if (idx >= 0) {
            UninstallInlineHook(idx);
            restored = BytesEqual(others[i].fn, before, 16);
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "%s: install=%s restore=%s",
            others[i].label, idx >= 0 ? "ok" : "skipped", idx >= 0 ? (restored ? "exact" : "DIFFERS") : "n/a");
        CHECK(idx >= 0 && restored, msg);
    }

    /* ── 5. Unhook the callable APIs, verify exact restore ──── */
    ShimLog("[5] unhooking and verifying restore:");
    UninstallInlineHook(hNTQ);
    UninstallInlineHook(hIPFP);
    UninstallInlineHook(hGCN);
    UninstallInlineHook(hGMS);
    UninstallInlineHook(hGSI);
    UninstallInlineHook(hGPA);
    UninstallInlineHook(hLLW);
    UninstallInlineHook(hLLA);

    CHECK(BytesEqual((void*)GetProcAddress(k32, "GetProcAddress"), origGPA, 8),
          "GetProcAddress original bytes restored exactly");

    BYTE sbi2[256]; ULONG rl2 = 0;
    LONG st2 = StubNtQsi(0, sbi2, sizeof(sbi2), &rl2);
    CHECK(st2 == st0, "NtQuerySystemInformation: result after unhook == baseline");

    g_calls = 0;
    HMODULE v3 = LoadLibraryA("version.dll");
    CHECK(v3 == v1, "LoadLibraryA still works after unhook");
    CHECK(g_calls == 0, "hook no longer intercepts after unhook");

    /* ── 6. DRM watch targets: decode + install/restore ─────── */
    ShimLog("[6] DRM watch targets (decode + install/restore):");
    HMODULE ih = LoadLibraryA("imagehlp.dll");
    HMODULE ps = LoadLibraryA("psapi.dll");
    HMODULE adv = LoadLibraryA("advapi32.dll");
    struct DrmTarget { const char* label; void* fn; };
    DrmTarget drm[] = {
        { "kernel32!IsDebuggerPresent",          (void*)GetProcAddress(k32, "IsDebuggerPresent") },
        { "kernel32!CheckRemoteDebuggerPresent", (void*)GetProcAddress(k32, "CheckRemoteDebuggerPresent") },
        { "kernel32!CreateToolhelp32Snapshot",   (void*)GetProcAddress(k32, "CreateToolhelp32Snapshot") },
        { "kernel32!GetModuleFileNameW",         (void*)GetProcAddress(k32, "GetModuleFileNameW") },
        { "kernel32!QueryPerformanceCounter",    (void*)GetProcAddress(k32, "QueryPerformanceCounter") },
        { "kernel32!GetTickCount64",             (void*)GetProcAddress(k32, "GetTickCount64") },
        { "ntdll!NtQueryInformationProcess",     (void*)GetProcAddress(nt, "NtQueryInformationProcess") },
        { "imagehlp!MapFileAndCheckSumA",        ih ? (void*)GetProcAddress(ih, "MapFileAndCheckSumA") : NULL },
        { "imagehlp!MapFileAndCheckSumW",        ih ? (void*)GetProcAddress(ih, "MapFileAndCheckSumW") : NULL },
        { "imagehlp!CheckSumMappedFile",         ih ? (void*)GetProcAddress(ih, "CheckSumMappedFile") : NULL },
        { "advapi32!CryptVerifySignatureW",      adv ? (void*)GetProcAddress(adv, "CryptVerifySignatureW") : NULL },
        { "psapi!EnumProcessModules",            ps ? (void*)GetProcAddress(ps, "EnumProcessModules") : NULL },
    };
    for (int i = 0; i < _countof(drm); i++) {
        if (!drm[i].fn) { ShimLog("  (skip %s — not found)", drm[i].label); continue; }
        DecodeReport(drm[i].label, drm[i].fn);
        BYTE before[16]; SaveBytes(drm[i].fn, before, 16);
        void* trampOut = NULL;
        int idx = InstallInlineHook(drm[i].fn, (void*)Hook_IPFP, &trampOut, drm[i].label);
        BOOL hooked = (idx >= 0) && (*(BYTE volatile*)drm[i].fn == 0xE9);
        BOOL restored = FALSE;
        if (idx >= 0) {
            UninstallInlineHook(idx);
            restored = BytesEqual(drm[i].fn, before, 16);
        }
        char msg[176];
        snprintf(msg, sizeof(msg), "%s: install=%s hook-byte=%s restore=%s", drm[i].label,
            idx >= 0 ? "ok" : "skipped", hooked ? "E9" : "n/a",
            idx >= 0 ? (restored ? "exact" : "DIFFERS") : "n/a");
        CHECK(idx >= 0 && restored, msg);
    }

    /* ── 7. DRM hooks: call-through + trampoline sanity ─────── */
    ShimLog("[7] DRM hook call-through (debugger/timing/memory probes):");
    BOOL idpBaseline = IsDebuggerPresent();
    Real_DRM_IDP = (PFN_DRM_IDP)GetProcAddress(k32, "IsDebuggerPresent");
    Real_DRM_GTC = (PFN_DRM_GTC)GetProcAddress(k32, "GetTickCount64");
    Real_DRM_QPC = (PFN_DRM_QPC)GetProcAddress(k32, "QueryPerformanceCounter");
    Real_DRM_VP  = (PFN_DRM_VP) GetProcAddress(k32, "VirtualProtect");
    int hIdp = InstallInlineHook((void*)Real_DRM_IDP, (void*)DrmHook_IDP, (void**)&Real_DRM_IDP, "IsDebuggerPresent(drm)");
    int hGtc = InstallInlineHook((void*)Real_DRM_GTC, (void*)DrmHook_GTC, (void**)&Real_DRM_GTC, "GetTickCount64(drm)");
    int hQpc = InstallInlineHook((void*)Real_DRM_QPC, (void*)DrmHook_QPC, (void**)&Real_DRM_QPC, "QueryPerformanceCounter(drm)");
    int hVp  = InstallInlineHook((void*)Real_DRM_VP,  (void*)DrmHook_VP,  (void**)&Real_DRM_VP,  "VirtualProtect(drm)");

    CHECK(hIdp >= 0 && hGtc >= 0 && hQpc >= 0 && hVp >= 0, "DRM call-through hooks installed (incl. VirtualProtect self-hook)");
    g_calls = 0;
    BOOL idpNow = IsDebuggerPresent();
    ULONGLONG gtcNow = GetTickCount64();
    LARGE_INTEGER qpc = {}; BOOL qpcOk = QueryPerformanceCounter(&qpc);
    DWORD vpOld = 0; BOOL vpOk = VirtualProtect(&qpc, sizeof(qpc), PAGE_READWRITE, &vpOld);
    CHECK(idpNow == idpBaseline, "IsDebuggerPresent: hooked result == unhooked result");
    CHECK(gtcNow > 0, "GetTickCount64: returns a value through the hook");
    CHECK(qpcOk && qpc.QuadPart != 0, "QueryPerformanceCounter: works through the hook");
    CHECK(vpOk, "VirtualProtect: works through its own hook (self-hook reentrancy)");
    CHECK(g_calls >= 4, "all 4 DRM call-through hooks were reached");

    UninstallInlineHook(hVp);
    UninstallInlineHook(hQpc);
    UninstallInlineHook(hGtc);
    UninstallInlineHook(hIdp);

    /* ── 8. Sandbox policy engine: generated stubs ──────────── */
    ShimLog("[8] sandbox policy engine (observe + block stubs):");
    {
        g_PolicyTls = TlsAlloc();

        PolicyWireEntry rules[2] = {};
        if (!g_PolicyBlockBridge) g_PolicyBlockBridge = PolicyMakeBlockBridge();
        CHECK(g_PolicyBlockBridge != NULL, "block bridge generated");

        /* Rule 1: BLOCK selftest!_PolicyTargetAdd -> 0x7777 */
        rules[0].kind = POLICY_KIND_IMPORT;
        rules[0].action = POLICY_ACTION_BLOCK;
        rules[0].blockValue = 0x7777;
        strncpy_s(rules[0].module, "*", _TRUNCATE);
        strncpy_s(rules[0].function, "_PolicyTargetAdd", _TRUNCATE);

        /* Rule 2: OBSERVE selftest!_PolicyTargetMul (passthrough) */
        rules[1].kind = POLICY_KIND_IMPORT;
        rules[1].action = POLICY_ACTION_OBSERVE;
        strncpy_s(rules[1].module, "*", _TRUNCATE);
        strncpy_s(rules[1].function, "_PolicyTargetMul", _TRUNCATE);

        PolicyInstallAndApply(rules, 2);

        /* Install walks the real PEB loader list; this guards the offsets the
           module enumeration uses (a broken walk silently patches nothing). */
        CHECK(g_PolicyModulesSeen >= 3, "PEB walk enumerated the process modules");

        /* Simulate two IAT slots pointing at the targets. */
        void* slotAdd = (void*)&_PolicyTargetAdd;
        void* slotMul = (void*)&_PolicyTargetMul;
        PolicyMaybePatchSlot(&slotAdd, "selftest.exe", "_PolicyTargetAdd");
        PolicyMaybePatchSlot(&slotMul, "selftest.exe", "_PolicyTargetMul");

        CHECK(slotAdd != (void*)&_PolicyTargetAdd, "BLOCK rule replaced the call-site pointer");
        CHECK(slotMul != (void*)&_PolicyTargetMul, "OBSERVE rule replaced the call-site pointer");

        int beforeCalls = g_PolicyTargetCalls;
        int blockRet = ((int(*)(int, int))slotAdd)(7, 35);
        CHECK(blockRet == 0x7777, "BLOCK returns the controller value to the caller");
        CHECK(g_PolicyTargetCalls == beforeCalls, "BLOCK never reached the original function");

        int observeRet = ((int(*)(int, int))slotMul)(7, 35);
        CHECK(observeRet == 7 * 35, "OBSERVE passes through and returns the real result");
        CHECK(g_PolicyTargetCalls == beforeCalls + 1, "OBSERVE reached the original function");
        CHECK(observeRet == 245, "OBSERVE preserved both integer arguments (rcx/rdx)");

        /* Dynamic resolution interception. */
        FARPROC gtc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
        if (gtc) {
            PolicyWireEntry rule3 = {};
            rule3.kind = POLICY_KIND_IMPORT;
            rule3.action = POLICY_ACTION_OBSERVE;
            strncpy_s(rule3.module, "kernel32.dll", _TRUNCATE);
            strncpy_s(rule3.function, "GetTickCount", _TRUNCATE);
            PolicyInstallAndApply(&rule3, 1);
            FARPROC i0 = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
            FARPROC i1 = i0;
            BOOL intercepted = PolicyInterceptGetProcAddress(
                GetModuleHandleA("kernel32.dll"), "GetTickCount", &i1);
            CHECK(intercepted && i1 != i0, "GetProcAddress interception hands out the stub");
            if (intercepted) {
                DWORD ticks = ((DWORD(WINAPI*)(void))i1)();
                CHECK(ticks > 0, "OBSERVE stub passthrough calls the real GetTickCount");
            }
        } else {
            ShimLog("  (skip GetProcAddress interception — GetTickCount not found)");
        }

        /* Restore must put the original pointers back. */
        void* savedAdd = (void*)&_PolicyTargetAdd;
        void* savedMul = (void*)&_PolicyTargetMul;
        PolicyRestore();
        CHECK(slotAdd == savedAdd, "restore put the BLOCK call-site back");
        CHECK(slotMul == savedMul, "restore put the OBSERVE call-site back");
    }

    ShimLog("=== RESULT: %d pass, %d fail ===", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
