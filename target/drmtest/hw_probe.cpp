/*
   Ghost Sandbox — hardware identity probe test target.
   Queries every hardware-identity source the sandbox claims to spoof
   (registry CPU/BIOS keys, CPUID, SMBIOS, topology APIs, memory, power,
   network adapters, volume serial, WMI) and prints machine-readable
   "key=value" lines to stdout AND to <exe>_out.txt (next to the exe).

   The e2e "hw" suite injects this binary under the shim with a published
   profile and asserts the fake identity; running it un-injected gives the
   real-host ground truth for the differential checks.

   Build: ghost_lab build hwprobe   (c) 2026 Ghost Project
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#include <winsock2.h>
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

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

static void OpenLog() {
    WCHAR self[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, self, MAX_PATH);
    WCHAR* dot = wcsrchr(self, L'.');
    if (dot) wcscpy_s(dot, MAX_PATH - (dot - self), L"_out.txt");
    _wfopen_s(&g_out, self, L"w");
}

static void WideToUtf8(const wchar_t* w, char* out, int cb) {
    out[0] = 0;
    if (!w) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cb, NULL, NULL);
    out[cb - 1] = 0;
}

/* Trims leading/trailing whitespace in place. */
static char* Trim(char* s) {
    while (*s == ' ' || *s == '\t') s++;
    char* end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
    return s;
}

/* ═══════════════════════════════════════════════════════════
   Registry identity
   ═══════════════════════════════════════════════════════════ */

static void RegPrintStr(const char* label, HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        P("[hw] %s=<key-missing>\n", label);
        return;
    }
    DWORD type = 0, cb = 0;
    LSTATUS st = RegQueryValueExW(hk, val, NULL, &type, NULL, &cb);
    if (st != ERROR_SUCCESS || cb == 0 || cb > 4096) {
        RegCloseKey(hk);
        P("[hw] %s=<missing>\n", label);
        return;
    }
    BYTE* buf = (BYTE*)malloc(cb + 4);
    DWORD cb2 = cb;
    st = RegQueryValueExW(hk, val, NULL, &type, buf, &cb2);
    RegCloseKey(hk);
    if (st != ERROR_SUCCESS) {
        free(buf);
        P("[hw] %s=<err %ld>\n", label, (long)st);
        return;
    }
    if (type == REG_DWORD && cb2 >= 4) {
        DWORD v = 0;
        memcpy(&v, buf, 4);
        P("[hw] %s=%lu\n", label, (unsigned long)v);
    } else if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        char utf8[1024];
        WideToUtf8((const wchar_t*)buf, utf8, sizeof(utf8));
        P("[hw] %s=%s\n", label, Trim(utf8));
    } else {
        P("[hw] %s=<type %lu, %lu bytes>\n", label, (unsigned long)type, (unsigned long)cb2);
    }
    free(buf);
}

static void ProbeRegistry() {
    const wchar_t* CPUKEY = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    const wchar_t* BIOSKEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    const wchar_t* SYSINFO = L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation";

    RegPrintStr("reg.cpu.name", HKEY_LOCAL_MACHINE, CPUKEY, L"ProcessorNameString");
    RegPrintStr("reg.cpu.vendor", HKEY_LOCAL_MACHINE, CPUKEY, L"VendorIdentifier");
    RegPrintStr("reg.cpu.identifier", HKEY_LOCAL_MACHINE, CPUKEY, L"Identifier");
    RegPrintStr("reg.cpu.mhz", HKEY_LOCAL_MACHINE, CPUKEY, L"~MHz");

    RegPrintStr("reg.bios.system_manufacturer", HKEY_LOCAL_MACHINE, BIOSKEY, L"SystemManufacturer");
    RegPrintStr("reg.bios.system_product", HKEY_LOCAL_MACHINE, BIOSKEY, L"SystemProductName");
    RegPrintStr("reg.bios.baseboard_product", HKEY_LOCAL_MACHINE, BIOSKEY, L"BaseBoardProduct");
    RegPrintStr("reg.bios.vendor", HKEY_LOCAL_MACHINE, BIOSKEY, L"BIOSVendor");
    RegPrintStr("reg.bios.version", HKEY_LOCAL_MACHINE, BIOSKEY, L"BIOSVersion");
    RegPrintStr("reg.bios.date", HKEY_LOCAL_MACHINE, BIOSKEY, L"BIOSReleaseDate");

    RegPrintStr("reg.sysinfo.manufacturer", HKEY_LOCAL_MACHINE, SYSINFO, L"SystemManufacturer");
    RegPrintStr("reg.sysinfo.product", HKEY_LOCAL_MACHINE, SYSINFO, L"SystemProductName");

    RegPrintStr("reg.machine_guid", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    RegPrintStr("reg.hostname", HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName");
    RegPrintStr("reg.product_id", HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId");
    RegPrintStr("reg.registered_owner", HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOwner");
}

/* ═══════════════════════════════════════════════════════════
   CPUID
   ═══════════════════════════════════════════════════════════ */

static void ProbeCpuid() {
    int r[4] = {0,0,0,0};

    __cpuidex(r, 0, 0);
    char vendor[13] = {0};
    memcpy(vendor + 0, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    P("[hw] cpuid.vendor=%s\n", vendor);
    P("[hw] cpuid.max_basic_leaf=0x%08X\n", r[0]);

    __cpuidex(r, 1, 0);
    P("[hw] cpuid.leaf1.eax=0x%08X\n", r[0]);
    P("[hw] cpuid.hypervisor_bit=%d\n", (r[2] >> 31) & 1);

    __cpuidex(r, 0x40000000, 0);
    char hv[13] = {0};
    memcpy(hv + 0, &r[1], 4);
    memcpy(hv + 4, &r[2], 4);
    memcpy(hv + 8, &r[3], 4);
    P("[hw] cpuid.hypervisor_vendor=%s\n", hv);
    P("[hw] cpuid.hypervisor_max_leaf=0x%08X\n", r[0]);

    char brand[49] = {0};
    __cpuidex(r, 0x80000002, 0);
    memcpy(brand + 0, r, 16);
    __cpuidex(r, 0x80000003, 0);
    memcpy(brand + 16, r, 16);
    __cpuidex(r, 0x80000004, 0);
    memcpy(brand + 32, r, 16);
    P("[hw] cpuid.brand=%s\n", Trim(brand));

    __cpuidex(r, 0x16, 0);
    P("[hw] cpuid.leaf16.base_mhz=%u max_mhz=%u\n",
        (unsigned)r[0], (unsigned)r[1]);
}

/* ═══════════════════════════════════════════════════════════
   System / topology / memory
   ═══════════════════════════════════════════════════════════ */

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtPowerInformation)(ULONG, PVOID, ULONG, PVOID, ULONG);

static void ProbeSystemInfo() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    P("[hw] sysinfo.native.cores=%lu arch=%u level=%u rev=0x%04X\n",
        (unsigned long)si.dwNumberOfProcessors, si.wProcessorArchitecture,
        si.wProcessorLevel, si.wProcessorRevision);
    GetSystemInfo(&si);
    P("[hw] sysinfo.cores=%lu\n", (unsigned long)si.dwNumberOfProcessors);

    /* GetLogicalProcessorInformation (legacy array) */
    DWORD len = 0;
    GetLogicalProcessorInformation(NULL, &len);
    if (len > 0 && len < 1024 * 1024) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buf =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(len);
        if (buf && GetLogicalProcessorInformation(buf, &len)) {
            DWORD cores = 0;
            DWORD l1 = 0, l2 = 0, l3 = 0;
            DWORD n = len / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
            for (DWORD i = 0; i < n; i++) {
                if (buf[i].Relationship == RelationProcessorCore) cores++;
                else if (buf[i].Relationship == RelationCache) {
                    DWORD size = buf[i].Cache.Size;
                    switch (buf[i].Cache.Level) {
                        case 1: l1 += size; break;
                        case 2: l2 += size; break;
                        case 3: l3 += size; break;
                    }
                }
            }
            P("[hw] glpi.cores=%lu\n", (unsigned long)cores);
            P("[hw] glpi.l1kb=%lu\n", (unsigned long)(l1 / 1024));
            P("[hw] glpi.l2kb=%lu\n", (unsigned long)(l2 / 1024));
            P("[hw] glpi.l3kb=%lu\n", (unsigned long)(l3 / 1024));
        }
        free(buf);
    }

    /* GetLogicalProcessorInformationEx */
    len = 0;
    GetLogicalProcessorInformationEx(RelationAll, NULL, &len);
    if (len > 0 && len < 1024 * 1024) {
        BYTE* buf = (BYTE*)malloc(len);
        if (buf && GetLogicalProcessorInformationEx(RelationAll,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf, &len)) {
            DWORD cores = 0, packages = 0, groups = 0;
            DWORD l3 = 0;
            BYTE groupProcessors = 0;
            DWORD off = 0;
            while (off + 8 <= len) {
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* rec =
                    (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)(buf + off);
                if (rec->Size < 8 || off + rec->Size > len) break;
                switch (rec->Relationship) {
                    case RelationProcessorCore:
                        cores++;
                        break;
                    case RelationProcessorPackage:
                        packages++;
                        break;
                    case RelationCache:
                        if (rec->Cache.Level == 3) l3 += rec->Cache.CacheSize;
                        break;
                    case RelationGroup:
                        groups += rec->Group.ActiveGroupCount;
                        if (rec->Group.ActiveGroupCount > 0) {
                            groupProcessors = rec->Group.GroupInfo[0].ActiveProcessorCount;
                        }
                        break;
                    default:
                        break;
                }
                off += rec->Size;
            }
            P("[hw] glpie.cores=%lu\n", (unsigned long)cores);
            P("[hw] glpie.packages=%lu\n", (unsigned long)packages);
            P("[hw] glpie.groups=%lu\n", (unsigned long)groups);
            P("[hw] glpie.group_procs=%u\n", (unsigned)groupProcessors);
            P("[hw] glpie.l3kb=%lu\n", (unsigned long)(l3 / 1024));
        }
        free(buf);
    }
}

static void ProbeMemory() {
    ULONGLONG physKb = 0;
    if (GetPhysicallyInstalledSystemMemory(&physKb)) {
        P("[hw] mem.phys_kb=%llu\n", (unsigned long long)physKb);
    } else {
        P("[hw] mem.phys_kb=<failed %lu>\n", (unsigned long)GetLastError());
    }

    MEMORYSTATUSEX ms;
    memset(&ms, 0, sizeof(ms));
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        P("[hw] mem.total_gb=%llu avail_gb=%llu\n",
            (unsigned long long)(ms.ullTotalPhys >> 30),
            (unsigned long long)(ms.ullAvailPhys >> 30));
    }

    /* NtQuerySystemInformation(SystemBasicInformation) */
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    PFN_NtQuerySystemInformation ntqsi = nt
        ? (PFN_NtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation")
        : NULL;
    if (ntqsi) {
        struct {
            ULONG reserved, timerResolution, pageSize, numberOfPhysicalPages;
            ULONG lowestPhysicalPage, highestPhysicalPage, allocationGranularity;
            ULONG pad;
            ULONG_PTR minimumUserModeAddress, maximumUserModeAddress;
            ULONG_PTR activeProcessorsAffinityMask;
            BYTE numberOfProcessors;
        } bi;
        memset(&bi, 0, sizeof(bi));
        ULONG ret = 0;
        if (ntqsi(0, &bi, sizeof(bi), &ret) == 0) {
            P("[hw] ntqsi.pages=%lu num_procs=%u affinity=0x%llX\n",
                (unsigned long)bi.numberOfPhysicalPages, (unsigned)bi.numberOfProcessors,
                (unsigned long long)bi.activeProcessorsAffinityMask);
        } else {
            P("[hw] ntqsi.pages=<status 0x%08X>\n", (unsigned)ret);
        }
    }

    /* NtPowerInformation(ProcessorInformation = 11) */
    PFN_NtPowerInformation ntp = nt
        ? (PFN_NtPowerInformation)GetProcAddress(nt, "NtPowerInformation")
        : NULL;
    if (ntp) {
        struct PPI { ULONG Number, MaxMhz, CurrentMhz, MhzLimit, MaxIdleState, CurrentIdleState; };
        PPI ppi[64];
        memset(ppi, 0, sizeof(ppi));
        if (ntp(11, NULL, 0, ppi, (ULONG)sizeof(ppi)) == 0) {
            P("[hw] power.cpu0.max_mhz=%u current_mhz=%u\n",
                (unsigned)ppi[0].MaxMhz, (unsigned)ppi[0].CurrentMhz);
        }
    }
}

/* ═══════════════════════════════════════════════════════════
   SMBIOS (GetSystemFirmwareTable 'RSMB')
   ═══════════════════════════════════════════════════════════ */

static const char* SmbiosString(const BYTE* sh, int index) {
    if (index == 0) return "";
    const BYTE* p = sh + sh[1];
    for (int i = 1; i < index; i++) {
        if (!*p) return "";
        while (*p) p++;
        p++;
    }
    return (const char*)p;
}

static void ProbeSmbios() {
    UINT size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    P("[hw] smbios.size=%u\n", size);
    if (size == 0 || size > 1024 * 1024) return;

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) return;
    UINT got = GetSystemFirmwareTable('RSMB', 0, buf, size);
    if (got == 0) {
        free(buf);
        P("[hw] smbios.data=<failed %lu>\n", (unsigned long)GetLastError());
        return;
    }
    if (got < 8) {
        free(buf);
        P("[hw] smbios.data=<short %u>\n", got);
        return;
    }
    /* The RSMB provider returns a RawSMBIOSData header (4 bytes) plus the
       structure-table length (DWORD) before the actual SMBIOS table. */
    P("[hw] smbios.ver=%u.%u table_len=%u\n", (unsigned)buf[1], (unsigned)buf[2],
        (unsigned)(*(DWORD*)(buf + 4)));

    int memDevices = 0;
    int memIdx = 0;
    int structs = 0;
    P("[hw] smbios.head=");
    for (UINT i = 0; i < (got < 64 ? got : 64); i++) P("%02X", buf[i]);
    P("\n");
    const BYTE* p = buf + 8;             /* skip the RawSMBIOSData header */
    const BYTE* end = buf + got;
    while (p + 4 <= end && p[0] != 0x7F) {
        BYTE type = p[0];
        BYTE len = p[1];
        if (len < 4 || p + len > end) break;
        structs++;

        switch (type) {
            case 0:
                P("[hw] smbios.bios.vendor=%s\n", SmbiosString(p, p[4]));
                P("[hw] smbios.bios.version=%s\n", SmbiosString(p, p[5]));
                P("[hw] smbios.bios.date=%s\n", SmbiosString(p, p[8]));
                break;
            case 1:
                P("[hw] smbios.sys.manufacturer=%s\n", SmbiosString(p, p[4]));
                P("[hw] smbios.sys.product=%s\n", SmbiosString(p, p[5]));
                P("[hw] smbios.sys.version=%s\n", SmbiosString(p, p[6]));
                P("[hw] smbios.sys.serial=%s\n", SmbiosString(p, p[7]));
                break;
            case 2:
                P("[hw] smbios.board.product=%s\n", SmbiosString(p, p[5]));
                break;
            case 4: {
                const char* socket = SmbiosString(p, p[4]);
                const char* brand = (len > 16) ? SmbiosString(p, p[16]) : "";
                P("[hw] smbios.cpu.socket=%s\n", socket);
                P("[hw] smbios.cpu.brand=%s\n", brand);
                if (len > 0x25) {
                    P("[hw] smbios.cpu.cores=%u threads=%u max_mhz=%u\n",
                        (unsigned)p[0x23], (unsigned)p[0x25],
                        (unsigned)(*(WORD*)(p + 0x14)));
                }
                break;
            }
            case 16:
                if (len >= 0x0F) {
                    P("[hw] smbios.mem.array_max_kb=%lu devices=%u\n",
                        (unsigned long)(*(DWORD*)(p + 7)), (unsigned)(*(WORD*)(p + 13)));
                }
                break;
            case 17:
                if (len >= 0x28 && memIdx < 4) {
                    P("[hw] smbios.mem%d.speed=%u type=0x%02X part=%s\n",
                        memIdx, (unsigned)(*(WORD*)(p + 0x15)), (unsigned)p[0x12],
                        SmbiosString(p, p[26]));
                    memIdx++;
                }
                if (len >= 0x0F) memDevices++;
                break;
            default:
                break;
        }

        /* advance: formatted area, then string set (double NUL) */
        p += len;
        if (p + 1 >= end) break;
        while (p + 1 < end && !(p[0] == 0 && p[1] == 0)) p++;
        p += 2;
    }
    P("[hw] smbios.mem.devices=%d structs=%d\n", memDevices, structs);
    free(buf);
}

/* ═══════════════════════════════════════════════════════════
   Network adapters / volume serial
   ═══════════════════════════════════════════════════════════ */

static void ProbeAdapters() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (size > 0 && size < 1024 * 1024) {
        PIP_ADAPTER_ADDRESSES buf = (PIP_ADAPTER_ADDRESSES)malloc(size);
        if (buf && GetAdaptersAddresses(AF_UNSPEC, 0, NULL, buf, &size) == NO_ERROR) {
            int idx = 0;
            for (PIP_ADAPTER_ADDRESSES a = buf; a && idx < 4; a = a->Next) {
                if (a->IfType != IF_TYPE_ETHERNET_CSMACD &&
                    a->IfType != IF_TYPE_IEEE80211) continue;
                char mac[32] = "";
                if (a->PhysicalAddressLength == 6) {
                    sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        a->PhysicalAddress[0], a->PhysicalAddress[1],
                        a->PhysicalAddress[2], a->PhysicalAddress[3],
                        a->PhysicalAddress[4], a->PhysicalAddress[5]);
                }
                char name[160];
                WideToUtf8(a->FriendlyName, name, sizeof(name));
                char desc[192];
                WideToUtf8(a->Description, desc, sizeof(desc));
                P("[hw] nic%d.mac=%s name=%s desc=%s\n", idx, mac, name, desc);
                idx++;
            }
        }
        free(buf);
    }

    ULONG sz = 0;
    if (GetAdaptersInfo(NULL, &sz) == ERROR_BUFFER_OVERFLOW && sz > 0 && sz < 1024 * 1024) {
        PIP_ADAPTER_INFO buf = (PIP_ADAPTER_INFO)malloc(sz);
        if (buf && GetAdaptersInfo(buf, &sz) == ERROR_SUCCESS && buf) {
            PIP_ADAPTER_INFO a = buf;
            char mac[32] = "";
            if (a->AddressLength >= 6) {
                sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                    a->Address[0], a->Address[1], a->Address[2],
                    a->Address[3], a->Address[4], a->Address[5]);
            }
            P("[hw] nicinfo0.mac=%s desc=%s\n", mac, a->Description);
        }
        free(buf);
    }

    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        P("[hw] volume.c_serial=%08X\n", (unsigned)serial);
    } else {
        P("[hw] volume.c_serial=<failed>\n");
    }
}

/* ═══════════════════════════════════════════════════════════
   WMI
   ═══════════════════════════════════════════════════════════ */

static void Vstr(IWbemClassObject* o, const wchar_t* name, char* out, int cb) {
    out[0] = 0;
    VARIANT v;
    VariantInit(&v);
    if (SUCCEEDED(o->Get(name, 0, &v, NULL, NULL)) && v.vt == VT_BSTR) {
        WideToUtf8(v.bstrVal, out, cb);
    }
    VariantClear(&v);
}

static unsigned long long Vnum(IWbemClassObject* o, const wchar_t* name) {
    unsigned long long r = 0;
    VARIANT v;
    VariantInit(&v);
    if (SUCCEEDED(o->Get(name, 0, &v, NULL, NULL))) {
        switch (v.vt) {
            case VT_I4: r = (unsigned long long)v.lVal; break;
            case VT_UI4: r = (unsigned long long)v.ulVal; break;
            case VT_I8: r = (unsigned long long)v.llVal; break;
            case VT_UI8: r = (unsigned long long)v.ullVal; break;
            case VT_BSTR: r = _wcstoui64(v.bstrVal, NULL, 10); break;
            default: break;
        }
    }
    VariantClear(&v);
    return r;
}

typedef void (*WmiRowFn)(IWbemClassObject* obj, int row, void* ctx);

static void WmiRun(IWbemLocator* loc, const wchar_t* wql, WmiRowFn fn, void* ctx, int maxRows) {
    IWbemServices* svc = NULL;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    if (!ns) return;
    HRESULT hr = loc->ConnectServer(ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    SysFreeString(ns);
    if (FAILED(hr) || !svc) return;

    hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        svc->Release();
        return;
    }

    BSTR lang = SysAllocString(L"WQL");
    BSTR q = SysAllocString(wql);
    IEnumWbemClassObject* en = NULL;
    hr = svc->ExecQuery(lang, q,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
    SysFreeString(lang);
    SysFreeString(q);
    if (SUCCEEDED(hr) && en) {
        int row = 0;
        while (row < maxRows) {
            IWbemClassObject* obj = NULL;
            ULONG got = 0;
            HRESULT nhr = en->Next(500, 1, &obj, &got);
            if (nhr != S_OK || got == 0 || !obj) break;
            fn(obj, row, ctx);
            obj->Release();
            row++;
        }
        en->Release();
    }
    svc->Release();
}

static void RowCpu(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char name[160], socket[64], vendor[64];
    Vstr(o, L"Name", name, sizeof(name));
    Vstr(o, L"SocketDesignation", socket, sizeof(socket));
    Vstr(o, L"Manufacturer", vendor, sizeof(vendor));
    P("[hw] wmi.cpu.name=%s socket=%s vendor=%s cores=%llu lcores=%llu maxmhz=%llu\n",
        name, socket, vendor,
        Vnum(o, L"NumberOfCores"), Vnum(o, L"NumberOfLogicalProcessors"),
        Vnum(o, L"MaxClockSpeed"));
}

static void RowRam(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char part[96], man[96];
    Vstr(o, L"PartNumber", part, sizeof(part));
    Vstr(o, L"Manufacturer", man, sizeof(man));
    P("[hw] wmi.ram0.speed=%llu capacity_gb=%llu type=%llu part=%s man=%s\n",
        Vnum(o, L"Speed"), Vnum(o, L"Capacity") >> 30,
        Vnum(o, L"SMBIOSMemoryType"), part, man);
}

static void RowBoard(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char product[160], man[96];
    Vstr(o, L"Product", product, sizeof(product));
    Vstr(o, L"Manufacturer", man, sizeof(man));
    P("[hw] wmi.board.product=%s man=%s\n", product, man);
}

static void RowSystem(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char model[160], man[96], name[96];
    Vstr(o, L"Model", model, sizeof(model));
    Vstr(o, L"Manufacturer", man, sizeof(man));
    Vstr(o, L"Name", name, sizeof(name));
    P("[hw] wmi.system.model=%s man=%s name=%s total_gb=%llu\n",
        model, man, name, Vnum(o, L"TotalPhysicalMemory") >> 30);
}

static void RowDisk(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char model[160], serial[96];
    Vstr(o, L"Model", model, sizeof(model));
    Vstr(o, L"SerialNumber", serial, sizeof(serial));
    P("[hw] wmi.disk0.model=%s serial=%s\n", model, serial);
}

static void RowBios(IWbemClassObject* o, int row, void*) {
    if (row > 0) return;
    char man[96], ver[96];
    Vstr(o, L"Manufacturer", man, sizeof(man));
    Vstr(o, L"SMBIOSBIOSVersion", ver, sizeof(ver));
    P("[hw] wmi.bios.man=%s version=%s\n", man, ver);
}

static void ProbeWmi() {
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        P("[hw] wmi.errors=coinitialize_failed\n");
        return;
    }
    IWbemLocator* loc = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr) || !loc) {
        P("[hw] wmi.errors=locator_failed 0x%08X\n", (unsigned)hr);
        CoUninitialize();
        return;
    }

    WmiRun(loc, L"SELECT Name, SocketDesignation, Manufacturer, NumberOfCores, "
        L"NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor", RowCpu, NULL, 1);
    WmiRun(loc, L"SELECT Speed, Capacity, SMBIOSMemoryType, PartNumber, Manufacturer "
        L"FROM Win32_PhysicalMemory", RowRam, NULL, 1);
    WmiRun(loc, L"SELECT Product, Manufacturer FROM Win32_BaseBoard", RowBoard, NULL, 1);
    WmiRun(loc, L"SELECT Model, Manufacturer, Name, TotalPhysicalMemory "
        L"FROM Win32_ComputerSystem", RowSystem, NULL, 1);
    WmiRun(loc, L"SELECT Model, SerialNumber FROM Win32_DiskDrive", RowDisk, NULL, 1);
    WmiRun(loc, L"SELECT Manufacturer, SMBIOSBIOSVersion FROM Win32_BIOS", RowBios, NULL, 1);

    loc->Release();
    CoUninitialize();
}

/* ═══════════════════════════════════════════════════════════
   Main
   ═══════════════════════════════════════════════════════════ */

int main() {
    OpenLog();
    P("[hw] probe.start pid=%lu\n", (unsigned long)GetCurrentProcessId());

    ProbeRegistry();
    ProbeCpuid();
    ProbeSystemInfo();
    ProbeMemory();
    ProbeSmbios();
    ProbeAdapters();
    ProbeWmi();

    P("[hw] probe.done\n");
    if (g_out) fclose(g_out);
    return 0;
}
