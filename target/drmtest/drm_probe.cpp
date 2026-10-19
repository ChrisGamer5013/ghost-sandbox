/*
   Ghost Sandbox — DRM probe test target.
   Exercises the shim's DRM/anti-tamper watch list so EVT_DRM events can be
   verified end-to-end: debugger checks, module scans, self-integrity
   (checksums/signatures), memory protection flips, timing probes and
   CPUID hypervisor detection.

   Prints every result to stdout AND to <exe>_out.txt (next to the exe) so
   the values can be compared against the GUI's "returned" column.

   Build: build_probe.cmd (MSVC).  (c) 2026 Ghost Project
*/
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")

static FILE* g_out = NULL;

static void P(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (g_out) {
        va_start(ap, fmt);
        vfprintf(g_out, fmt, ap);
        va_end(ap);
        fflush(g_out);
    }
    fflush(stdout);
}

static void LogFilePath(WCHAR* out, DWORD cch) {
    WCHAR self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, self, MAX_PATH);
    wcsncpy_s(out, cch, self, _TRUNCATE);
    WCHAR* dot = wcsrchr(out, L'.');
    if (dot) {
        size_t remaining = (size_t)cch - (size_t)(dot - out);
        if (remaining >= 10) {
            wcscpy_s(dot, remaining, L"_out.txt");
        }
    }
}

static void OpenLog() {
    WCHAR path[MAX_PATH] = {0};
    LogFilePath(path, MAX_PATH);
    _wfopen_s(&g_out, path, L"w");
}

/* Crash diagnostics: writes the exception code + faulting module/RVA to
   <exe>_out.txt even if the CRT file handle is gone. */
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
    char msg[640] = {0};
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void* addr = ep->ExceptionRecord->ExceptionAddress;
    HMODULE mod = NULL;
    char modName[MAX_PATH] = "?";
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)addr, &mod);
    if (mod) GetModuleFileNameA(mod, modName, MAX_PATH);
    int n = snprintf(msg, sizeof(msg),
        "\r\n[CRASH] code=0x%08X at %s+0x%llX (raw=%p)\r\n",
        (unsigned)code, modName,
        mod ? (unsigned long long)((BYTE*)addr - (BYTE*)mod) : 0ULL, addr);
    if (g_out) { fwrite(msg, 1, (size_t)n, g_out); fflush(g_out); }
    WCHAR path[MAX_PATH] = {0};
    LogFilePath(path, MAX_PATH);
    HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(f, msg, (DWORD)n, &wr, NULL);
        CloseHandle(f);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

/* ── Individual probes ─────────────────────────────────────── */

static void ProbeDebugger() {
    P("[probe] IsDebuggerPresent() = %d\n", IsDebuggerPresent());

    BOOL remote = FALSE;
    BOOL ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    P("[probe] CheckRemoteDebuggerPresent() = %d, present = %d\n", ok, remote);
}

static void ProbeNtQueryInformationProcess() {
    typedef LONG (NTAPI *PFN_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    PFN_NtQIP ntqip = nt ? (PFN_NtQIP)GetProcAddress(nt, "NtQueryInformationProcess") : NULL;
    if (!ntqip) { P("[probe] NtQueryInformationProcess unavailable\n"); return; }

    ULONG_PTR dbgPort = 0;
    ULONG rl = 0;
    LONG st = ntqip(GetCurrentProcess(), 7 /*ProcessDebugPort*/, &dbgPort, sizeof(dbgPort), &rl);
    P("[probe] NtQIP(ProcessDebugPort) status=0x%08X port=0x%llX\n",
        (unsigned)st, (unsigned long long)dbgPort);

    ULONG_PTR dbgObj = 0;
    rl = 0;
    st = ntqip(GetCurrentProcess(), 0x1E /*ProcessDebugObjectHandle*/, &dbgObj, sizeof(dbgObj), &rl);
    P("[probe] NtQIP(ProcessDebugObjectHandle) status=0x%08X handle=0x%llX\n",
        (unsigned)st, (unsigned long long)dbgObj);

    ULONG dbgFlags = 0;
    rl = 0;
    st = ntqip(GetCurrentProcess(), 0x1F /*ProcessDebugFlags*/, &dbgFlags, sizeof(dbgFlags), &rl);
    P("[probe] NtQIP(ProcessDebugFlags) status=0x%08X flags=%lu\n", (unsigned)st, dbgFlags);
}

static void ProbeModuleScan() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = {0};
        me.dwSize = sizeof(me);
        int n = 0;
        if (Module32FirstW(snap, &me)) {
            do { n++; } while (Module32NextW(snap, &me));
        }
        P("[probe] toolhelp32 module scan = %d modules\n", n);
        CloseHandle(snap);
    } else {
        P("[probe] CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
    }

    HMODULE mods[512] = {0};
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        P("[probe] EnumProcessModules = %lu modules\n",
            (unsigned long)(needed / sizeof(HMODULE)));
    } else {
        P("[probe] EnumProcessModules failed (%lu)\n", GetLastError());
    }

    WCHAR self[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    P("[probe] GetModuleFileNameW(NULL) = %lu chars: %ls\n", n, self);
}

static void ProbeIntegrity() {
    WCHAR self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, self, MAX_PATH);

    /* Self-checksum via imagehlp (classic anti-tamper). */
    HMODULE ih = LoadLibraryA("imagehlp.dll");
    if (ih) {
        typedef DWORD (WINAPI *PFN_MFCSW)(PCWSTR, PDWORD, PDWORD);
        typedef PIMAGE_NT_HEADERS (WINAPI *PFN_CSMF)(PVOID, DWORD, PDWORD, PDWORD);
        PFN_MFCSW mfcs = (PFN_MFCSW)GetProcAddress(ih, "MapFileAndCheckSumW");
        if (mfcs) {
            DWORD hdrSum = 0, checkSum = 0;
            DWORD r = mfcs(self, &hdrSum, &checkSum);
            P("[probe] MapFileAndCheckSumW = %lu, headerSum=0x%08X, checkSum=0x%08X\n",
                (unsigned long)r, hdrSum, checkSum);
        }

        PFN_CSMF csmf = (PFN_CSMF)GetProcAddress(ih, "CheckSumMappedFile");
        if (csmf) {
            HANDLE f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD sz = GetFileSize(f, NULL);
                if (sz > 0 && sz < (64u << 20)) {
                    BYTE* buf = (BYTE*)malloc(sz);
                    DWORD rd = 0;
                    if (buf && ReadFile(f, buf, sz, &rd, NULL) && rd == sz) {
                        DWORD h2 = 0, c2 = 0;
                        PIMAGE_NT_HEADERS nth = csmf(buf, sz, &h2, &c2);
                        P("[probe] CheckSumMappedFile = %s, headerSum=0x%08X, checkSum=0x%08X\n",
                            nth ? "ok" : "null", h2, c2);
                    }
                    free(buf);
                }
                CloseHandle(f);
            }
        }
    } else {
        P("[probe] imagehlp.dll unavailable\n");
    }

    /* Authenticode trust verification on our own image. */
    WINTRUST_FILE_INFO wfi = {0};
    wfi.cbStruct = sizeof(wfi);
    wfi.pcwszFilePath = self;

    WINTRUST_DATA wtd = {0};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &wfi;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG wv = WinVerifyTrust(NULL, &action, &wtd);
    P("[probe] WinVerifyTrust = 0x%08X (%s)\n", (unsigned)wv,
        wv == ERROR_SUCCESS ? "trusted" : "not trusted/unsigned");

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wtd);
}

/* One sign -> verify roundtrip on the given provider. Returns TRUE when the
   signature verified (the API still gets called on failure — that is also a
   legitimate anti-tamper probe). */
static BOOL TrySignVerify(HCRYPTPROV prov, ALG_ID alg, DWORD bits, BOOL keyed,
                          const char* name) {
    static const BYTE data[] = "ghost-probe-data";
    HCRYPTKEY key = 0;

    if (!CryptGenKey(prov, AT_SIGNATURE, bits << 16, &key)) {
        P("[probe] CryptGenKey(%s) failed (%lu)\n", name, GetLastError());
        return FALSE;
    }

    HCRYPTHASH h = 0;
    if (!CryptCreateHash(prov, alg, keyed ? key : 0, 0, &h)) {
        P("[probe] CryptCreateHash(%s) failed (%lu)\n", name, GetLastError());
        CryptDestroyKey(key);
        return FALSE;
    }
    CryptHashData(h, data, sizeof(data) - 1, 0);

    DWORD sigLen = 0;
    BYTE* sig = NULL;
    BOOL signOk = FALSE;
    if (CryptSignHashA(h, AT_SIGNATURE, NULL, 0, NULL, &sigLen) && sigLen > 0) {
        sig = (BYTE*)malloc(sigLen);
        signOk = sig && CryptSignHashA(h, AT_SIGNATURE, NULL, 0, sig, &sigLen);
    }
    if (!signOk) P("[probe] CryptSignHash(%s) failed (%lu)\n", name, GetLastError());

    BOOL verified = FALSE;
    if (signOk) {
        HCRYPTHASH h2 = 0;
        if (CryptCreateHash(prov, alg, keyed ? key : 0, 0, &h2)) {
            CryptHashData(h2, data, sizeof(data) - 1, 0);
            verified = CryptVerifySignatureW(h2, sig, sigLen, key,
                                             L"ghost probe signature", 0);
            DWORD verr = GetLastError();
            P("[probe] CryptVerifySignatureW = %d [%s]%s\n", verified, name,
                verified ? "  (roundtrip verified)"
                         : "  (probe call)");
            if (!verified) P("[probe]   verify GetLastError=0x%08X\n", (unsigned)verr);
            CryptDestroyHash(h2);
        }

        if (!verified && sigLen > 1) {
            /* Some CSPs emit RSA signatures little-endian; retry reversed. */
            for (DWORD i = 0; i < sigLen / 2; i++) {
                BYTE t = sig[i];
                sig[i] = sig[sigLen - 1 - i];
                sig[sigLen - 1 - i] = t;
            }
            HCRYPTHASH h3 = 0;
            if (CryptCreateHash(prov, alg, keyed ? key : 0, 0, &h3)) {
                CryptHashData(h3, data, sizeof(data) - 1, 0);
                BOOL rvs = CryptVerifySignatureW(h3, sig, sigLen, key,
                                                 L"ghost probe signature", 0);
                DWORD rerr = GetLastError();
                P("[probe] CryptVerifySignatureW(reversed) = %d [%s]\n", rvs, name);
                if (!rvs) P("[probe]   reversed GetLastError=0x%08X\n", (unsigned)rerr);
                CryptDestroyHash(h3);
                if (rvs) verified = TRUE;
            }
        }
    }

    free(sig);
    if (h) CryptDestroyHash(h);
    CryptDestroyKey(key);
    return verified;
}

static void ProbeCryptoVerify() {
    /* Canonical CryptoAPI sign -> verify roundtrip: generate a signature key
       in a temporary key container (CRYPT_VERIFYCONTEXT keys cannot be used
       for keyed hashing), fall back to ephemeral attempts for hook coverage. */
    static const WCHAR* kTmpContainer = L"GhostProbeTmp";
    HCRYPTPROV prov = 0;

    if (!CryptAcquireContextW(&prov, kTmpContainer, MS_ENH_RSA_AES_PROV_W,
                              PROV_RSA_AES, CRYPT_NEWKEYSET)) {
        if (!CryptAcquireContextW(&prov, kTmpContainer, MS_ENH_RSA_AES_PROV_W,
                                  PROV_RSA_AES, 0)) {
            P("[probe] CryptAcquireContext(tmp container) failed (%lu)\n", GetLastError());
        }
    }

    if (prov) {
        if (TrySignVerify(prov, CALG_SHA1, 1024, FALSE, "container/SHA1/1024") ||
            TrySignVerify(prov, CALG_MD5, 1024, FALSE, "container/MD5/1024")) {
            CryptReleaseContext(prov, 0);
            HCRYPTPROV del = 0;
            CryptAcquireContextW(&del, kTmpContainer, MS_ENH_RSA_AES_PROV_W,
                                 PROV_RSA_AES, CRYPT_DELETEKEYSET);
            return;
        }
        CryptReleaseContext(prov, 0);
    }

    /* Fallback: ephemeral keys on the legacy base provider (still calls the
       watched API even when the roundtrip cannot verify). */
    if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        TrySignVerify(prov, CALG_MD5, 1024, FALSE, "base/MD5/1024 unkeyed");
        CryptReleaseContext(prov, 0);
    } else {
        P("[probe] CryptAcquireContext failed (%lu)\n", GetLastError());
    }
}

static void ProbeMemoryProtection() {
    LPVOID buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { P("[probe] VirtualAlloc failed\n"); return; }

    DWORD old = 0;
    BOOL ok = VirtualProtect(buf, 4096, PAGE_EXECUTE_READWRITE, &old);
    P("[probe] VirtualProtect(RWX) = %d, oldProtect=0x%X\n", ok, old);

    VirtualProtect(buf, 4096, PAGE_READWRITE, &old);
    VirtualFree(buf, 0, MEM_RELEASE);
}

static void ProbeTiming() {
    LARGE_INTEGER a = {0}, b = {0};
    QueryPerformanceCounter(&a);
    volatile ULONGLONG sink = 0;
    for (int i = 0; i < 2000; i++) {
        sink += GetTickCount64() & 1;
    }
    QueryPerformanceCounter(&b);
    P("[probe] QPC delta = %lld ticks (anti-debug timing loop)\n",
        (long long)(b.QuadPart - a.QuadPart));
}

static void ProbeCpuid() {
    int info[4] = {0};
    __cpuid(info, 0x40000000);
    P("[probe] CPUID 0x40000000 = %08X %08X %08X %08X%s\n",
        info[0], info[1], info[2], info[3],
        (info[0] || info[1] || info[2] || info[3]) ? "  [hypervisor vendor]" : "  [none]");

    int l1[4] = {0};
    __cpuid(l1, 1);
    P("[probe] CPUID leaf 1: ECX=0x%08X hypervisor-bit=%d\n",
        l1[2], (l1[2] & 0x80000000) ? 1 : 0);
}

static void ProbeHostFingerprint() {
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        WCHAR guid[128] = {0};
        DWORD cb = sizeof(guid), type = 0;
        if (RegQueryValueExW(key, L"MachineGuid", NULL, &type, (LPBYTE)guid, &cb) == ERROR_SUCCESS) {
            P("[probe] Registry MachineGuid = %ls\n", guid);
        }
        RegCloseKey(key);
    }

    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &size) == ERROR_BUFFER_OVERFLOW && size > 0) {
        IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)malloc(size);
        if (addrs && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, addrs, &size) == NO_ERROR) {
            int n = 0;
            for (IP_ADAPTER_ADDRESSES* a = addrs; a && n < 8; a = a->Next) {
                if (a->PhysicalAddressLength == 6) {
                    P("[probe] adapter %d MAC = %02X-%02X-%02X-%02X-%02X-%02X\n", n,
                        a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                        a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
                }
                n++;
            }
        }
        free(addrs);
    }
}

static void RunBattery(int pass) {
    P("\n===== DRM probe battery, pass %d (PID %lu) =====\n",
        pass, (unsigned long)GetCurrentProcessId());
    P("[mark] debugger\n"); ProbeDebugger();
    P("[mark] ntqip\n"); ProbeNtQueryInformationProcess();
    P("[mark] modulescan\n"); ProbeModuleScan();
    P("[mark] integrity\n"); ProbeIntegrity();
    P("[mark] crypto\n"); ProbeCryptoVerify();
    P("[mark] memprot\n"); ProbeMemoryProtection();
    P("[mark] timing\n"); ProbeTiming();
    P("[mark] cpuid\n"); ProbeCpuid();
    P("[mark] hostfingerprint\n"); ProbeHostFingerprint();
    P("===== pass %d complete =====\n", pass);
}

int main(int argc, char** argv) {
    SetUnhandledExceptionFilter(CrashFilter);
    OpenLog();
    P("[mark] log opened\n");

    if (argc > 1 && strcmp(argv[1], "crypto-only") == 0) {
        P("[probe] crypto-only self-test\n");
        ProbeCryptoVerify();
        if (g_out) fclose(g_out);
        return 0;
    }

    P("[probe] DRM probe started (PID %lu)\n", (unsigned long)GetCurrentProcessId());

    RunBattery(1);
    Sleep(6000);   /* keep the shim + GUI busy long enough to observe */
    RunBattery(2);

    P("[probe] done — exiting\n");
    if (g_out) fclose(g_out);
    return 0;
}
