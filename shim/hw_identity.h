/*
   Ghost Sandbox — Hardware Identity Engine
   Registry-side and API-side identity spoofing used by the hooks in
   sandbox_shim.cpp:

     - Processor / BIOS / system registry values (Task Manager's CPU name,
       BIOS strings, system model, product id, computer name)
     - Synthetic SMBIOS firmware table (GetSystemFirmwareTable 'RSMB')
     - Processor topology (GetLogicalProcessorInformation / ...Ex)
     - NtQuerySystemInformation field patching (RAM size, core counts)
     - NtPowerInformation processor clock values
     - Legacy GetAdaptersInfo MAC spoof

   Everything here is read-only spoofing: the shim never writes to the
   host. (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trace_format.h"
#include "hw_spoofer.h"

#define HW_MIN(a, b) ((a) < (b) ? (a) : (b))
#define HW_MAX(a, b) ((a) > (b) ? (a) : (b))

/* ════════════════════════════════════════════════════════════
   Small helpers
   ════════════════════════════════════════════════════════════ */

static void HwUtf8ToWide(const char* utf8, wchar_t* out, DWORD cchOut) {
    if (!out || cchOut == 0) return;
    out[0] = 0;
    if (!utf8) return;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, cchOut);
    out[cchOut - 1] = 0;
}

static BOOL HwContainsCI(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle) return FALSE;
    size_t nl = wcslen(needle);
    if (nl == 0) return TRUE;
    for (const wchar_t* p = hay; *p; ++p) {
        if (_wcsnicmp(p, needle, nl) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL HwEndsWithCI(const wchar_t* s, const wchar_t* suffix) {
    if (!s || !suffix) return FALSE;
    size_t ls = wcslen(s), lf = wcslen(suffix);
    if (lf > ls) return FALSE;
    return _wcsicmp(s + (ls - lf), suffix) == 0;
}

/* ════════════════════════════════════════════════════════════
   Registry key-path resolution (NtQueryKey)
   ════════════════════════════════════════════════════════════ */

typedef NTSTATUS (NTAPI *PFN_NtQueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
#define HW_KEY_NAME_INFORMATION 3

/* Map the predefined root keys (pseudo handles) to REGISTRY paths. */
static const wchar_t* HwPseudoRootPath(HKEY hKey) {
    ULONG_PTR k = (ULONG_PTR)hKey;
    ULONG high = (ULONG)(k >> 32);
    if (high != 0 && high != 0xFFFFFFFF) return NULL;
    switch ((DWORD)k) {
        case 0x80000000: return L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"; // HKEY_CLASSES_ROOT
        case 0x80000001: return L"\\REGISTRY\\USER";                       // HKEY_CURRENT_USER
        case 0x80000002: return L"\\REGISTRY\\MACHINE";                    // HKEY_LOCAL_MACHINE
        case 0x80000003: return L"\\REGISTRY\\USER";                       // HKEY_USERS
        case 0x80000004: return L"\\REGISTRY\\PERFORMANCE";                // HKEY_PERFORMANCE_DATA
        case 0x80000005: return L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";
        default: return NULL;
    }
}

/* Full key path for a handle, e.g. "\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\...". */
static BOOL HwGetKeyPath(HKEY hKey, wchar_t* out, DWORD cchOut) {
    if (!out || cchOut == 0) return FALSE;
    out[0] = 0;

    const wchar_t* root = HwPseudoRootPath(hKey);
    if (root) {
        wcsncpy_s(out, cchOut, root, _TRUNCATE);
        return TRUE;
    }

    static PFN_NtQueryKey s_pfn = NULL;
    if (!s_pfn) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) return FALSE;
        s_pfn = (PFN_NtQueryKey)GetProcAddress(nt, "NtQueryKey");
        if (!s_pfn) return FALSE;
    }

    /* KEY_NAME_INFORMATION { ULONG NameLength; WCHAR Name[1]; } */
    struct { ULONG NameLength; WCHAR Name[512]; } info;
    memset(&info, 0, sizeof(info));
    ULONG retLen = 0;
    NTSTATUS st = s_pfn((HANDLE)hKey, HW_KEY_NAME_INFORMATION, &info,
                        sizeof(info), &retLen);
    if (st != 0) return FALSE;

    DWORD chars = info.NameLength / sizeof(WCHAR);
    if (chars >= 512) chars = 511;
    if (chars >= cchOut) chars = cchOut - 1;
    memcpy(out, info.Name, chars * sizeof(WCHAR));
    out[chars] = 0;
    return out[0] != 0;
}

/* ════════════════════════════════════════════════════════════
   Registry value spoofing
   ════════════════════════════════════════════════════════════ */

#define HW_VAL_MAX 640

typedef struct HwSpoofValue {
    DWORD type;         // REG_SZ / REG_EXPAND_SZ / REG_DWORD / REG_MULTI_SZ
    DWORD dataBytes;
    BYTE  data[HW_VAL_MAX];
} HwSpoofValue;

static void HwSetStr(HwSpoofValue* v, const wchar_t* s, DWORD type) {
    memset(v->data, 0, sizeof(v->data));
    if (!s) s = L"";
    DWORD bytes = ((DWORD)wcslen(s) + 1) * sizeof(wchar_t);
    if (bytes > HW_VAL_MAX) bytes = HW_VAL_MAX;
    memcpy(v->data, s, bytes);
    v->type = type;
    v->dataBytes = bytes;
}

static void HwSetMultiSz(HwSpoofValue* v, const wchar_t** strings, int count) {
    memset(v->data, 0, sizeof(v->data));
    DWORD off = 0;
    for (int i = 0; i < count; i++) {
        const wchar_t* s = strings[i] ? strings[i] : L"";
        DWORD bytes = ((DWORD)wcslen(s) + 1) * sizeof(wchar_t);
        if (off + bytes + sizeof(wchar_t) > HW_VAL_MAX) break;
        memcpy(v->data + off, s, bytes);
        off += bytes;
    }
    if (off + sizeof(wchar_t) > HW_VAL_MAX) off = HW_VAL_MAX - sizeof(wchar_t);
    *(wchar_t*)(v->data + off) = L'\0';   // second NUL terminates MULTI_SZ
    off += sizeof(wchar_t);
    v->type = REG_MULTI_SZ;
    v->dataBytes = off;
}

static void HwSetDword(HwSpoofValue* v, DWORD d) {
    memset(v->data, 0, sizeof(v->data));
    memcpy(v->data, &d, sizeof(DWORD));
    v->type = REG_DWORD;
    v->dataBytes = sizeof(DWORD);
}

static void HwBuildCpuIdentifier(wchar_t* out, DWORD cch) {
    const wchar_t* family = L"x86-64";
    char man[64];
    strncpy_s(man, sizeof(man), g_Profile.cpu.manufacturer, _TRUNCATE);
    wchar_t wman[64];
    HwUtf8ToWide(man, wman, 64);
    if (wcsstr(wman, L"Intel")) family = L"Intel64";
    else if (wcsstr(wman, L"AMD")) family = L"AMD64";
    swprintf_s(out, cch, L"%s Family %u Model %u Stepping %u",
        family, g_Profile.cpu.family, g_Profile.cpu.model, g_Profile.cpu.stepping);
}

/*
   Decide whether (keyPath, valueName) is a hardware identity value that
   should be rewritten from the profile. Returns TRUE and fills `out`.
*/
static BOOL HwSpoofRegistryValuePath(const wchar_t* path, const wchar_t* valueName,
                                     HwSpoofValue* out) {
    if (!g_ProfileLoaded || !valueName || !out || !path) return FALSE;

    memset(out, 0, sizeof(*out));

    /* MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography) — name match only,
       matching the historical behaviour. */
    if (_wcsicmp(valueName, L"MachineGuid") == 0) {
        wchar_t guid[80];
        HwUtf8ToWide(g_Profile.identity.machine_guid, guid, 80);
        HwSetStr(out, guid, REG_SZ);
        return TRUE;
    }

    /* ── CPU identity: HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\<n> */
    if (HwContainsCI(path, L"\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\")) {
        if (_wcsicmp(valueName, L"ProcessorNameString") == 0) {
            wchar_t brand[128];
            HwUtf8ToWide(g_Profile.cpu.brand_string, brand, 128);
            HwSetStr(out, brand, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"VendorIdentifier") == 0) {
            wchar_t man[64];
            HwUtf8ToWide(g_Profile.cpu.manufacturer, man, 64);
            HwSetStr(out, man, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"Identifier") == 0) {
            wchar_t id[128];
            HwBuildCpuIdentifier(id, 128);
            HwSetStr(out, id, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"~MHz") == 0) {
            HwSetDword(out, g_Profile.cpu.base_clock_mhz);
            return TRUE;
        }
        return FALSE;
    }

    /* ── BIOS / motherboard: HKLM\HARDWARE\DESCRIPTION\System\BIOS */
    if (HwEndsWithCI(path, L"\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS")) {
        wchar_t v[128];
        if (_wcsicmp(valueName, L"SystemManufacturer") == 0 ||
            _wcsicmp(valueName, L"BaseBoardManufacturer") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.manufacturer, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"SystemProductName") == 0 ||
            _wcsicmp(valueName, L"BaseBoardProduct") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.product, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"SystemVersion") == 0 ||
            _wcsicmp(valueName, L"BaseBoardVersion") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.version, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"SystemFamily") == 0 ||
            _wcsicmp(valueName, L"SystemSKU") == 0) {
            HwSetStr(out, L"", REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"BIOSVendor") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.bios_vendor, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"BIOSVersion") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.bios_version, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"BIOSReleaseDate") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.bios_date, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    /* ── System: HKLM\HARDWARE\DESCRIPTION\System (SystemBiosVersion/Date) */
    if (HwEndsWithCI(path, L"\\HARDWARE\\DESCRIPTION\\SYSTEM")) {
        if (_wcsicmp(valueName, L"SystemBiosVersion") == 0) {
            wchar_t vendor[64], version[64];
            HwUtf8ToWide(g_Profile.motherboard.bios_vendor, vendor, 64);
            HwUtf8ToWide(g_Profile.motherboard.bios_version, version, 64);
            const wchar_t* strings[3] = { vendor, version, L"" };
            HwSetMultiSz(out, strings, 3);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"SystemBiosDate") == 0) {
            wchar_t v[64];
            HwUtf8ToWide(g_Profile.motherboard.bios_date, v, 64);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    /* ── Win10+ system information: ...\Control\SystemInformation */
    if (HwEndsWithCI(path, L"\\CONTROL\\SYSTEMINFORMATION")) {
        wchar_t v[128];
        if (_wcsicmp(valueName, L"SystemManufacturer") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.manufacturer, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"SystemProductName") == 0) {
            HwUtf8ToWide(g_Profile.motherboard.product, v, 128);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    /* ── Windows version identity */
    if (HwEndsWithCI(path, L"\\WINDOWS NT\\CURRENTVERSION") ||
        HwEndsWithCI(path, L"\\WINDOWS\\CURRENTVERSION")) {
        if (_wcsicmp(valueName, L"ProductId") == 0) {
            wchar_t v[64];
            HwUtf8ToWide(g_Profile.identity.product_id, v, 64);
            HwSetStr(out, v, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"RegisteredOwner") == 0) {
            HwSetStr(out, g_Profile.identity.user_name, REG_SZ);
            return TRUE;
        }
        if (_wcsicmp(valueName, L"RegisteredOrganization") == 0) {
            HwSetStr(out, L"", REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    /* ── Computer name */
    if (HwEndsWithCI(path, L"\\CONTROL\\COMPUTERNAME\\COMPUTERNAME") ||
        HwEndsWithCI(path, L"\\CONTROL\\COMPUTERNAME\\ACTIVECOMPUTERNAME")) {
        if (_wcsicmp(valueName, L"ComputerName") == 0 ||
            _wcsicmp(valueName, L"ActiveComputerName") == 0) {
            HwSetStr(out, g_Profile.identity.computer_name, REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    /* ── TCP/IP host name */
    if (HwEndsWithCI(path, L"\\SERVICES\\TCPIP\\PARAMETERS")) {
        if (_wcsicmp(valueName, L"Hostname") == 0 ||
            _wcsicmp(valueName, L"NV Hostname") == 0) {
            HwSetStr(out, g_Profile.identity.computer_name, REG_SZ);
            return TRUE;
        }
        return FALSE;
    }

    return FALSE;
}

/* Resolve the key handle, then apply the spoof rules. */
static BOOL HwSpoofRegistryValue(HKEY hKey, const wchar_t* valueName, HwSpoofValue* out) {
    wchar_t path[640];
    if (!HwGetKeyPath(hKey, path, 640)) return FALSE;
    return HwSpoofRegistryValuePath(path, valueName, out);
}

/*
   Apply a spoofed value to a RegQueryValueEx/RegGetValue-style call.
   `callerCb` is the caller's buffer size in bytes as passed in (0 when the
   caller only asked for the required size). Returns the hook's status:
   the real API is not consulted again — the profile is authoritative.
*/
static LSTATUS HwApplyRegValue(const HwSpoofValue* sv, LPDWORD lpType,
                               LPBYTE lpData, LPDWORD lpcbData, DWORD callerCb) {
    if (lpType) *lpType = sv->type;
    if (!lpData) {
        if (lpcbData) *lpcbData = sv->dataBytes;
        return ERROR_SUCCESS;
    }
    if (!lpcbData || callerCb < sv->dataBytes) {
        if (lpcbData) *lpcbData = sv->dataBytes;
        return ERROR_MORE_DATA;
    }
    memcpy(lpData, sv->data, sv->dataBytes);
    *lpcbData = sv->dataBytes;
    return ERROR_SUCCESS;
}

typedef struct HwSmbiosWriter {
    BYTE* buf;
    DWORD cap;
    DWORD off;
    DWORD strings;   /* strings written since the last HwSmbiosStrEnd */
} HwSmbiosWriter;

static void HwSmbiosWrite(HwSmbiosWriter* w, const void* data, DWORD len) {
    if (w->buf && w->off + len <= w->cap) {
        memcpy(w->buf + w->off, data, len);
    }
    w->off += len;
}

static void HwSmbiosString(HwSmbiosWriter* w, const wchar_t* s) {
    /* Empty strings are omitted entirely: an interior NUL-only entry would
       be misread by parsers as the end of the string set. Callers assign
       string indices with HwSmbiosIdx() so numbering stays consistent. */
    if (!s || !s[0]) return;
    char a[256];
    a[0] = 0;
    WideCharToMultiByte(CP_ACP, 0, s, -1, a, sizeof(a), NULL, NULL);
    DWORD len = (DWORD)strlen(a) + 1;
    HwSmbiosWrite(w, a, len);
    w->strings++;
}

/*
   SMBIOS string index helper: returns the 1-based index for a non-empty
   string and advances the running counter; empty strings return 0
   ("not provided") and are skipped by HwSmbiosString().
*/
static BYTE HwSmbiosIdx(DWORD* next, const wchar_t* s) {
    if (!s || !s[0]) return 0;
    return (BYTE)((*next)++);
}

static void HwSmbiosStrEnd(HwSmbiosWriter* w) {
    /* The unformatted (string) section is terminated by two NUL bytes.
       With strings present the last string's NUL is the first of the two;
       with no strings both NULs must be written. */
    BYTE z[2] = { 0, 0 };
    HwSmbiosWrite(w, z, w->strings ? 1 : 2);
    w->strings = 0;
}

static BYTE HwSmbiosMemoryType(const char* type) {
    if (!type) return 0x02;
    if (_stricmp(type, "DDR5") == 0)   return 0x22;
    if (_stricmp(type, "DDR4") == 0)   return 0x1A;
    if (_stricmp(type, "DDR3") == 0)   return 0x18;
    if (_stricmp(type, "DDR2") == 0)   return 0x12;
    if (_stricmp(type, "LPDDR5") == 0) return 0x23;
    if (_stricmp(type, "LPDDR4") == 0) return 0x1E;
    return 0x02; /* unknown */
}

/* WORD cache-size encoding: bit15 = 64KB granularity. */
static WORD HwSmbiosCacheWord(DWORD kb) {
    if (kb == 0) return 0xFFFF; /* unknown */
    if (kb > 0x7FFF) {
        DWORD units = kb / 64;
        if (units > 0x7FFF) units = 0x7FFF;
        return (WORD)(0x8000 | units);
    }
    return (WORD)kb;
}

/* DWORD cache-size encoding (SMBIOS 3.1): bit31 = 64KB granularity. */
static DWORD HwSmbiosCacheDword(DWORD kb) {
    if (kb == 0) return 0xFFFFFFFF;
    DWORD units = kb;
    DWORD gran = 0;
    if (kb > 0x7FFF) {
        units = kb / 64;
        gran = 0x80000000;
    }
    return gran | (units & 0x7FFFFFFF);
}

static void HwParseGuidToUuid(const char* guid, BYTE uuid[16]) {
    memset(uuid, 0, 16);
    int out = 0;
    for (const char* p = guid; *p && out < 32; ++p) {
        int nib = -1;
        if (*p >= '0' && *p <= '9') nib = *p - '0';
        else if (*p >= 'a' && *p <= 'f') nib = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') nib = *p - 'A' + 10;
        if (nib < 0) continue;
        if ((out & 1) == 0) uuid[out >> 1] = (BYTE)(nib << 4);
        else uuid[out >> 1] |= (BYTE)nib;
        out++;
    }
}

/*
   Build a synthetic SMBIOS table matching the profile.
   If `out` is NULL, only the required size is computed.
*/
static DWORD HwBuildSmbios(BYTE* out, DWORD cap) {
    if (!g_ProfileLoaded) return 0;

    const SharedCpuProfile* cpu = &g_Profile.cpu;
    const SharedMotherboardProfile* mb = &g_Profile.motherboard;
    const SharedMemoryProfile* mem = &g_Profile.memory;

    DWORD phys = cpu->cores_physical ? cpu->cores_physical : 1;
    DWORD logical = cpu->cores_logical ? cpu->cores_logical : phys;
    DWORD dimms = mem->dimm_count ? mem->dimm_count : 2;
    if (dimms < 1) dimms = 1;
    if (dimms > 4) dimms = 4;
    DWORD memTotalKb = mem->total_gb * 1024 * 1024;
    DWORD perDimmMb = mem->total_gb * 1024 / dimms;

    HwSmbiosWriter w = { out, cap, 0, 0 };

    /* ── RawSMBIOSData header ─────────────────────────────
       The RSMB provider returns the WMI header struct followed by the
       SMBIOS structure table; the 8-byte header carries the SMBIOS
       version and the structure-table length (backfilled below). */
    {
        BYTE hdr[8];
        memset(hdr, 0, sizeof(hdr));
        hdr[0] = 0x00;                        // Used20CallingMethod
        hdr[1] = 0x03;                        // SMBIOS major version
        hdr[2] = 0x05;                        // SMBIOS minor version
        hdr[3] = 0x00;                        // DMI revision
        HwSmbiosWrite(&w, hdr, sizeof(hdr));
    }

    /* ── Type 0: BIOS Information ─────────────────────────── */
    {
        wchar_t vendor[64], version[64], date[64];
        HwUtf8ToWide(mb->bios_vendor, vendor, 64);
        HwUtf8ToWide(mb->bios_version, version, 64);
        HwUtf8ToWide(mb->bios_date, date, 64);
        DWORD n = 1;

        BYTE s[0x14];
        memset(&s, 0, sizeof(s));
        s[0] = 0x00; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x0000;
        s[4] = HwSmbiosIdx(&n, vendor);       // BIOS vendor string
        s[5] = HwSmbiosIdx(&n, version);      // BIOS version string
        *(WORD*)(s + 6) = 0xF000;             // starting segment
        s[8] = HwSmbiosIdx(&n, date);         // release date string
        s[9] = 0xFF;                          // ROM size (16 MB)
        *(DWORD*)(s + 10) = 0x0000000F;       // characteristics
        *(WORD*)(s + 14) = 0x0001;            // characteristics ext
        s[16] = 3; s[17] = 5;                 // SMBIOS 3.5
        s[18] = 0xFF; s[19] = 0xFF;           // EC firmware
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosString(&w, vendor);
        HwSmbiosString(&w, version);
        HwSmbiosString(&w, date);
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 1: System Information ───────────────────────── */
    {
        wchar_t man[64], prod[128], ver[64], serial[64];
        HwUtf8ToWide(mb->manufacturer, man, 64);
        HwUtf8ToWide(mb->product, prod, 128);
        HwUtf8ToWide(mb->version, ver, 64);
        HwUtf8ToWide(mb->serial, serial, 64);
        DWORD n = 1;

        BYTE s[0x1B];
        memset(&s, 0, sizeof(s));
        s[0] = 0x01; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x0100;
        s[4] = HwSmbiosIdx(&n, man);
        s[5] = HwSmbiosIdx(&n, prod);
        s[6] = HwSmbiosIdx(&n, ver);
        s[7] = HwSmbiosIdx(&n, serial);
        HwParseGuidToUuid(g_Profile.identity.machine_guid, s + 8);
        s[24] = 0x06;                         // wake-up type: power switch
        s[25] = 0; s[26] = 0;                 // SKU / family (none)
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosString(&w, man);
        HwSmbiosString(&w, prod);
        HwSmbiosString(&w, ver);
        HwSmbiosString(&w, serial);
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 2: Baseboard ────────────────────────────────── */
    {
        wchar_t man[64], prod[128], ver[64], serial[64];
        HwUtf8ToWide(mb->manufacturer, man, 64);
        HwUtf8ToWide(mb->product, prod, 128);
        HwUtf8ToWide(mb->version, ver, 64);
        HwUtf8ToWide(mb->serial, serial, 64);
        DWORD n = 1;

        BYTE s[0x0F];
        memset(&s, 0, sizeof(s));
        s[0] = 0x02; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x0200;
        s[4] = HwSmbiosIdx(&n, man);
        s[5] = HwSmbiosIdx(&n, prod);
        s[6] = HwSmbiosIdx(&n, ver);
        s[7] = HwSmbiosIdx(&n, serial);
        s[8] = 0;                             // asset tag (none)
        s[9] = 0x09;                          // hosting board + replaceable
        *(WORD*)(s + 10) = 0x0300;            // chassis handle
        s[12] = 0x0A;                         // board type: motherboard
        s[13] = 0; s[14] = 0;
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosString(&w, man);
        HwSmbiosString(&w, prod);
        HwSmbiosString(&w, ver);
        HwSmbiosString(&w, serial);
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 3: Chassis ──────────────────────────────────── */
    {
        wchar_t man[64];
        HwUtf8ToWide(mb->manufacturer, man, 64);
        DWORD n = 1;

        BYTE s[0x15];
        memset(&s, 0, sizeof(s));
        s[0] = 0x03; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x0300;
        s[4] = HwSmbiosIdx(&n, man);          // manufacturer string
        s[5] = 0x03;                          // type: desktop
        s[9] = 0x03;                          // boot-up state: safe
        s[10] = 0x03;                         // power supply: safe
        s[11] = 0x03;                         // thermal: safe
        s[12] = 0x03;                         // security: none
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosString(&w, man);
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 4: Processor ────────────────────────────────── */
    {
        wchar_t socket[24], man[64], brand[128];
        HwUtf8ToWide(cpu->socket, socket, 24);
        HwUtf8ToWide(cpu->manufacturer, man, 64);
        HwUtf8ToWide(cpu->brand_string, brand, 128);
        DWORD n = 1;

        BYTE s[0x30];
        memset(&s, 0, sizeof(s));
        s[0] = 0x04; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x0400;
        s[4] = HwSmbiosIdx(&n, socket);       // socket designation
        s[5] = 0x03;                          // processor type: CPU
        s[6] = 0xCD;                          // family: Intel Core
        s[7] = HwSmbiosIdx(&n, man);          // manufacturer string
        /* Processor ID: EDX:EAX of CPUID leaf 1 built from profile */
        DWORD base_family = (cpu->family <= 0x0F) ? cpu->family : 0x0F;
        DWORD ext_family = (cpu->family > 0x0F) ? (cpu->family - 0x0F) : 0;
        DWORD base_model = cpu->model & 0x0F;
        DWORD ext_model = (cpu->model >> 4) & 0x0F;
        DWORD eax = (cpu->stepping & 0x0F) | ((base_model & 0x0F) << 4) |
                    ((base_family & 0x0F) << 8) | ((ext_model & 0x0F) << 16) |
                    ((ext_family & 0xFF) << 20);
        DWORD edx = 0xBFEBFBFF;
        *(DWORD*)(s + 8) = eax;
        *(DWORD*)(s + 12) = edx;
        s[16] = HwSmbiosIdx(&n, brand);       // version string (brand)
        s[17] = 0;                            // voltage
        *(WORD*)(s + 18) = 100;               // external clock
        *(WORD*)(s + 20) = (WORD)HW_MIN(cpu->max_clock_mhz, 0xFFFF);
        *(WORD*)(s + 22) = (WORD)HW_MIN(cpu->base_clock_mhz, 0xFFFF);
        s[24] = 0x41;                         // populated + enabled
        s[25] = 0x01;                         // upgrade: other
        *(WORD*)(s + 26) = 0x0700;            // L1 handle
        *(WORD*)(s + 28) = 0x0701;            // L2 handle
        *(WORD*)(s + 30) = 0x0702;            // L3 handle
        s[32] = 0; s[33] = 0; s[34] = 0;      // serial / asset / part
        s[35] = (BYTE)HW_MIN(phys, 255);         // core count
        s[36] = (BYTE)HW_MIN(phys, 255);         // core enabled
        s[37] = (BYTE)HW_MIN(logical, 255);      // thread count (low byte of the WORD at 0x25)
        *(WORD*)(s + 39) = 0x000E;            // characteristics: 64-bit + hw threads + multi-core
        *(WORD*)(s + 41) = 0;                 // processor family 2 (SMBIOS 3.0+)
        *(WORD*)(s + 43) = (WORD)HW_MIN(phys, 0xFFFF);    // core count 2
        *(WORD*)(s + 45) = (WORD)HW_MIN(logical, 0xFFFF); // thread count 2
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosString(&w, socket);
        HwSmbiosString(&w, man);
        HwSmbiosString(&w, brand);
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 7: Cache ×3 ─────────────────────────────────── */
    {
        struct { WORD handle; const wchar_t* name; BYTE level;
                 DWORD sizeKb; BYTE cacheType; BYTE assoc; } caches[3];
        DWORD l3 = cpu->l3_cache_kb ? cpu->l3_cache_kb : 1;
        caches[0].handle = 0x0700; caches[0].name = L"L1 Cache";
        caches[0].level = 1; caches[0].sizeKb = cpu->l1_cache_kb ? HW_MAX((DWORD)16, cpu->l1_cache_kb / phys) : 0;
        caches[0].cacheType = 4; caches[0].assoc = 7;
        caches[1].handle = 0x0701; caches[1].name = L"L2 Cache";
        caches[1].level = 2; caches[1].sizeKb = cpu->l2_cache_kb ? HW_MAX((DWORD)128, cpu->l2_cache_kb / phys) : 0;
        caches[1].cacheType = 5; caches[1].assoc = 8;
        caches[2].handle = 0x0702; caches[2].name = L"L3 Cache";
        caches[2].level = 3; caches[2].sizeKb = l3;
        caches[2].cacheType = 5; caches[2].assoc = 8;
        for (int i = 0; i < 3; i++) {
            BYTE s[0x1B];
            memset(&s, 0, sizeof(s));
            s[0] = 0x07; s[1] = sizeof(s);
            *(WORD*)(s + 2) = caches[i].handle;
            s[4] = 1;                          // socket designation string
            *(WORD*)(s + 5) = (WORD)(0x0080 | (caches[i].level & 0x07));
            *(WORD*)(s + 7) = HwSmbiosCacheWord(caches[i].sizeKb);
            *(WORD*)(s + 9) = HwSmbiosCacheWord(caches[i].sizeKb);
            *(WORD*)(s + 11) = 0x0020;         // supported SRAM type
            *(WORD*)(s + 13) = 0x0020;         // current SRAM type
            s[15] = 0;                          // speed
            s[16] = 0x05;                       // error correction: single-bit ECC
            s[17] = caches[i].cacheType;
            s[18] = caches[i].assoc;
            *(DWORD*)(s + 19) = HwSmbiosCacheDword(caches[i].sizeKb);
            *(DWORD*)(s + 23) = HwSmbiosCacheDword(caches[i].sizeKb);
            HwSmbiosWrite(&w, s, sizeof(s));
            HwSmbiosString(&w, caches[i].name);
            HwSmbiosStrEnd(&w);
        }
    }

    /* ── Type 16: Physical Memory Array ───────────────────── */
    {
        BYTE s[0x17];
        memset(&s, 0, sizeof(s));
        s[0] = 0x10; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x1000;
        s[4] = 0x03;                          // location: system board
        s[5] = 0x03;                          // use: system memory
        s[6] = 0x03;                          // ECC: none
        *(DWORD*)(s + 7) = memTotalKb;
        *(WORD*)(s + 11) = 0xFFFE;            // error info handle: none
        *(WORD*)(s + 13) = (WORD)dimms;
        *(ULONGLONG*)(s + 15) = (ULONGLONG)mem->total_gb * 1024ULL * 1024ULL * 1024ULL;
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 17: Memory Device × dimms ───────────────────── */
    {
        BYTE memType = HwSmbiosMemoryType(mem->mm_type);
        wchar_t mmMan[32], mmPart[64];
        HwUtf8ToWide(mem->mm_manufacturer, mmMan, 32);
        HwUtf8ToWide(mem->mm_part, mmPart, 64);
        for (DWORD i = 0; i < dimms; i++) {
            wchar_t locator[16], bank[16];
            swprintf_s(locator, L"DIMM_%c1", L'A' + (i % 4));
            swprintf_s(bank, L"BANK %u", i / 4);
            DWORD n = 1;

            BYTE s[0x28];
            memset(&s, 0, sizeof(s));
            s[0] = 0x11; s[1] = sizeof(s);
            *(WORD*)(s + 2) = (WORD)(0x1100 + i);
            *(WORD*)(s + 4) = 0x1000;         // physical memory array handle
            *(WORD*)(s + 6) = 0xFFFE;         // memory error info handle
            *(WORD*)(s + 8) = 64;             // total width
            *(WORD*)(s + 10) = 64;            // data width
            *(WORD*)(s + 12) = 0x7FFF;        // size: see extended size
            s[14] = 0; s[15] = 0;             // device set
            s[16] = HwSmbiosIdx(&n, locator); // device locator string
            s[17] = HwSmbiosIdx(&n, bank);    // bank locator string
            s[18] = memType;
            *(WORD*)(s + 19) = 0x0080;        // type detail: synchronous
            *(WORD*)(s + 21) = (WORD)HW_MIN(mem->speed_mhz, 0xFFFF);
            s[23] = HwSmbiosIdx(&n, mmMan);   // manufacturer string
            s[24] = 0;                        // serial number (not reported)
            s[25] = 0;                        // asset tag (none)
            s[26] = HwSmbiosIdx(&n, mmPart);  // part number string
            s[27] = 0x02;                     // attributes: rank 2
            *(DWORD*)(s + 28) = perDimmMb;    // extended size (MB)
            *(WORD*)(s + 32) = (WORD)HW_MIN(mem->speed_mhz, 0xFFFF); // configured speed
            *(WORD*)(s + 34) = 1200;          // min voltage (mV)
            *(WORD*)(s + 36) = 1200;          // max voltage
            *(WORD*)(s + 38) = 1200;          // configured voltage
            HwSmbiosWrite(&w, s, sizeof(s));
            HwSmbiosString(&w, locator);
            HwSmbiosString(&w, bank);
            HwSmbiosString(&w, mmMan);
            HwSmbiosString(&w, mmPart);
            HwSmbiosStrEnd(&w);
        }
    }

    /* ── Type 32: System Boot Information ─────────────────── */
    {
        BYTE s[0x0B];
        memset(&s, 0, sizeof(s));
        s[0] = 0x20; s[1] = sizeof(s);
        *(WORD*)(s + 2) = 0x2000;
        HwSmbiosWrite(&w, s, sizeof(s));
        HwSmbiosStrEnd(&w);
    }

    /* ── Type 127: End of table ───────────────────────────── */
    {
        BYTE s[4] = { 0x7F, 0x04, 0x00, 0x7F };
        HwSmbiosWrite(&w, s, sizeof(s));
        BYTE z[2] = { 0, 0 };
        HwSmbiosWrite(&w, z, sizeof(z));
    }

    /* Backfill the structure-table length in the RawSMBIOSData header. */
    if (w.buf && w.cap >= 8) {
        DWORD tableLen = w.off - 8;
        memcpy(w.buf + 4, &tableLen, sizeof(tableLen));
    }

    return w.off;
}

/* ════════════════════════════════════════════════════════════
   Processor topology (GetLogicalProcessorInformation / ...Ex)
   ════════════════════════════════════════════════════════════ */

static DWORD HwThreadsPerCore(void) {
    DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : 1;
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : phys;
    if (logical < phys) logical = phys;
    return logical / phys;
}

static ULONG_PTR HwAllThreadMask(void) {
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 1;
    if (logical >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return (((ULONG_PTR)1) << logical) - 1;
}

typedef struct HwGlpiCache {
    BYTE level;
    BYTE associativity;
    DWORD sizeKb;
    PROCESSOR_CACHE_TYPE type;
} HwGlpiCache;

static DWORD HwGlpiCacheCount(void) { return 3; }

/* Distribute a total cache size over the physical cores, keeping the sum
   exact (the remainder goes to the first core). */
static DWORD HwGlpiCachePerCore(DWORD totalKb, DWORD phys, DWORD coreIndex) {
    if (totalKb == 0) return 0;
    if (phys == 0) phys = 1;
    DWORD v = totalKb / phys + (coreIndex == 0 ? totalKb % phys : 0);
    return HW_MAX((DWORD)16, v);
}

static HwGlpiCache HwGlpiCacheAt(DWORD index) {
    HwGlpiCache c = { 0, 0, 0, CacheUnified };
    switch (index) {
        case 0:
            c.level = 1; c.associativity = 8; c.type = CacheData;
            c.sizeKb = g_Profile.cpu.l1_cache_kb;    // total, split per core
            break;
        case 1:
            c.level = 2; c.associativity = 16; c.type = CacheUnified;
            c.sizeKb = g_Profile.cpu.l2_cache_kb;    // total, split per core
            break;
        default:
            c.level = 3; c.associativity = 16; c.type = CacheUnified;
            c.sizeKb = g_Profile.cpu.l3_cache_kb ? g_Profile.cpu.l3_cache_kb : 0;
            break;
    }
    return c;
}

static DWORD HwGlpiCount(DWORD relationship) {
    DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : 1;
    DWORD n = 0;
    if (relationship == RelationAll || relationship == RelationProcessorCore) n += phys;
    if (relationship == RelationAll || relationship == RelationCache)
        n += phys * 2 + 1;   /* L1 + L2 per core, single shared L3 */
    if (relationship == RelationAll || relationship == RelationProcessorPackage) n += 1;
    if (relationship == RelationAll || relationship == RelationNumaNode) n += 1;
    return n;
}

static BOOL HwBuildGlpi(DWORD relationship, void* out, DWORD capBytes, DWORD* needed) {
    if (!g_ProfileLoaded) return FALSE;
    DWORD entrySize = sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    DWORD total = HwGlpiCount(relationship) * entrySize;
    if (needed) *needed = total;
    if (!out || capBytes < total) return FALSE;

    BYTE* p = (BYTE*)out;
    DWORD off = 0;
    DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : 1;
    DWORD threads = HwThreadsPerCore();
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : phys;

#define HW_GLPI_PUSH(entry) do { \
        memcpy(p + off, &(entry), entrySize); off += entrySize; } while (0)

    if (relationship == RelationAll || relationship == RelationProcessorCore) {
        for (DWORD i = 0; i < phys && (i * threads) < 64; i++) {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION e;
            memset(&e, 0, sizeof(e));
            ULONG_PTR mask = 0;
            for (DWORD t = 0; t < threads && (i * threads + t) < 64; t++) {
                mask |= ((ULONG_PTR)1) << (i * threads + t);
            }
            e.ProcessorMask = mask;
            e.Relationship = RelationProcessorCore;
            e.ProcessorCore.Flags = 1;
            HW_GLPI_PUSH(e);
        }
    }

    if (relationship == RelationAll || relationship == RelationCache) {
        if (logical > 64) { /* fall back to a single logical group */ }
        for (DWORD ci = 0; ci < HwGlpiCacheCount(); ci++) {
            HwGlpiCache c = HwGlpiCacheAt(ci);
            if (c.level == 3) {
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION e;
                memset(&e, 0, sizeof(e));
                e.ProcessorMask = HwAllThreadMask();
                e.Relationship = RelationCache;
                e.Cache.Level = (BYTE)c.level;
                e.Cache.Associativity = c.associativity;
                e.Cache.LineSize = 64;
                e.Cache.Size = c.sizeKb * 1024;
                e.Cache.Type = c.type;
                HW_GLPI_PUSH(e);
            } else {
                for (DWORD i = 0; i < phys && (i * threads) < 64; i++) {
                    SYSTEM_LOGICAL_PROCESSOR_INFORMATION e;
                    memset(&e, 0, sizeof(e));
                    ULONG_PTR mask = 0;
                    for (DWORD t = 0; t < threads && (i * threads + t) < 64; t++) {
                        mask |= ((ULONG_PTR)1) << (i * threads + t);
                    }
                    e.ProcessorMask = mask;
                    e.Relationship = RelationCache;
                    e.Cache.Level = (BYTE)c.level;
                    e.Cache.Associativity = c.associativity;
                    e.Cache.LineSize = 64;
                    e.Cache.Size = HwGlpiCachePerCore(c.sizeKb, phys, i) * 1024;
                    e.Cache.Type = c.type;
                    HW_GLPI_PUSH(e);
                }
            }
        }
    }

    if (relationship == RelationAll || relationship == RelationProcessorPackage) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION e;
        memset(&e, 0, sizeof(e));
        e.ProcessorMask = HwAllThreadMask();
        e.Relationship = RelationProcessorPackage;
        HW_GLPI_PUSH(e);
    }

    if (relationship == RelationAll || relationship == RelationNumaNode) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION e;
        memset(&e, 0, sizeof(e));
        e.ProcessorMask = HwAllThreadMask();
        e.Relationship = RelationNumaNode;
        e.NumaNode.NodeNumber = 0;
        HW_GLPI_PUSH(e);
    }

#undef HW_GLPI_PUSH
    return TRUE;
}

/* ── Variable-size records for GetLogicalProcessorInformationEx ── */

typedef struct HwProcRel {
    DWORD relationship;
    DWORD size;
    BYTE flags;
    BYTE efficiencyClass;
    BYTE reserved[20];
    WORD groupCount;
    GROUP_AFFINITY group;
} HwProcRel;

typedef struct HwCacheRel {
    DWORD relationship;
    DWORD size;
    BYTE level;
    BYTE associativity;
    WORD lineSize;
    DWORD cacheSize;
    PROCESSOR_CACHE_TYPE type;
    BYTE reserved[18];
    WORD groupCount;
    GROUP_AFFINITY group;
} HwCacheRel;

typedef struct HwNumaRel {
    DWORD relationship;
    DWORD size;
    DWORD nodeNumber;
    BYTE reserved[18];
    WORD groupCount;
    GROUP_AFFINITY group;
} HwNumaRel;

typedef struct HwGroupRel {
    DWORD relationship;
    DWORD size;
    WORD maximumGroupCount;
    WORD activeGroupCount;
    BYTE reserved[20];
    BYTE maximumProcessorCount;
    BYTE activeProcessorCount;
    BYTE reserved2[38];
    ULONG_PTR activeProcessorMask;
} HwGroupRel;

/* Total byte size of the record set for one relationship (RelationAll sums
   every record type). */
static DWORD HwGlpieTotalSize(DWORD relationship) {
    DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : 1;
    DWORD total = 0;
    if (relationship == RelationAll || relationship == RelationProcessorCore)
        total += phys * sizeof(HwProcRel);
    if (relationship == RelationAll || relationship == RelationCache)
        total += (phys * 2 + 1) * sizeof(HwCacheRel);
    if (relationship == RelationAll || relationship == RelationProcessorPackage)
        total += sizeof(HwProcRel);
    if (relationship == RelationAll || relationship == RelationNumaNode)
        total += sizeof(HwNumaRel);
    if (relationship == RelationAll || relationship == RelationGroup)
        total += sizeof(HwGroupRel);
    return total;
}

static BOOL HwBuildGlpie(DWORD relationship, void* out, DWORD capBytes, DWORD* needed) {
    if (!g_ProfileLoaded) return FALSE;
    DWORD total = HwGlpieTotalSize(relationship);
    if (needed) *needed = total;
    if (out && capBytes < total) return FALSE;
    if (!out) return TRUE;

    BYTE* p = (BYTE*)out;
    DWORD off = 0;
    DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : 1;
    DWORD threads = HwThreadsPerCore();
    GROUP_AFFINITY all = {};
    all.Mask = HwAllThreadMask();
    all.Group = 0;

#define HW_GLPIE_PUSH(type, rec) do { \
        memcpy(p + off, &(rec), sizeof(type)); off += sizeof(type); } while (0)

    if (relationship == RelationAll || relationship == RelationProcessorCore) {
        for (DWORD i = 0; i < phys && (i * threads) < 64; i++) {
            HwProcRel r;
            memset(&r, 0, sizeof(r));
            r.relationship = RelationProcessorCore;
            r.size = sizeof(r);
            r.flags = 1;
            r.groupCount = 1;
            r.group.Mask = 0;
            for (DWORD t = 0; t < threads && (i * threads + t) < 64; t++) {
                r.group.Mask |= ((ULONG_PTR)1) << (i * threads + t);
            }
            HW_GLPIE_PUSH(HwProcRel, r);
        }
    }

    if (relationship == RelationAll || relationship == RelationCache) {
        for (DWORD ci = 0; ci < HwGlpiCacheCount(); ci++) {
            HwGlpiCache c = HwGlpiCacheAt(ci);
            if (c.level == 3) {
                HwCacheRel r;
                memset(&r, 0, sizeof(r));
                r.relationship = RelationCache;
                r.size = sizeof(r);
                r.level = (BYTE)c.level;
                r.associativity = c.associativity;
                r.lineSize = 64;
                r.cacheSize = c.sizeKb * 1024;
                r.type = c.type;
                r.groupCount = 1;
                r.group = all;
                HW_GLPIE_PUSH(HwCacheRel, r);
            } else {
                for (DWORD i = 0; i < phys && (i * threads) < 64; i++) {
                    HwCacheRel r;
                    memset(&r, 0, sizeof(r));
                    r.relationship = RelationCache;
                    r.size = sizeof(r);
                    r.level = (BYTE)c.level;
                    r.associativity = c.associativity;
                    r.lineSize = 64;
                    r.cacheSize = HwGlpiCachePerCore(c.sizeKb, phys, i) * 1024;
                    r.type = c.type;
                    r.groupCount = 1;
                    r.group.Mask = 0;
                    for (DWORD t = 0; t < threads && (i * threads + t) < 64; t++) {
                        r.group.Mask |= ((ULONG_PTR)1) << (i * threads + t);
                    }
                    HW_GLPIE_PUSH(HwCacheRel, r);
                }
            }
        }
    }

    if (relationship == RelationAll || relationship == RelationProcessorPackage) {
        HwProcRel r;
        memset(&r, 0, sizeof(r));
        r.relationship = RelationProcessorPackage;
        r.size = sizeof(r);
        r.flags = 1;
        r.groupCount = 1;
        r.group = all;
        HW_GLPIE_PUSH(HwProcRel, r);
    }

    if (relationship == RelationAll || relationship == RelationNumaNode) {
        HwNumaRel r;
        memset(&r, 0, sizeof(r));
        r.relationship = RelationNumaNode;
        r.size = sizeof(r);
        r.nodeNumber = 0;
        r.groupCount = 1;
        r.group = all;
        HW_GLPIE_PUSH(HwNumaRel, r);
    }

    if (relationship == RelationAll || relationship == RelationGroup) {
        HwGroupRel r;
        memset(&r, 0, sizeof(r));
        r.relationship = RelationGroup;
        r.size = sizeof(r);
        r.maximumGroupCount = 1;
        r.activeGroupCount = 1;
        r.maximumProcessorCount = 64;
        DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 1;
        r.activeProcessorCount = (BYTE)HW_MIN(logical, 64);
        r.activeProcessorMask = HwAllThreadMask();
        HW_GLPIE_PUSH(HwGroupRel, r);
    }

#undef HW_GLPIE_PUSH
    return TRUE;
}

/* ════════════════════════════════════════════════════════════
   NtQuerySystemInformation field patching
   ════════════════════════════════════════════════════════════ */

/* Matches the x64 SYSTEM_BASIC_INFORMATION layout. */
typedef struct HwSystemBasicInformation {
    ULONG reserved;
    ULONG timerResolution;
    ULONG pageSize;
    ULONG numberOfPhysicalPages;
    ULONG lowestPhysicalPageNumber;
    ULONG highestPhysicalPageNumber;
    ULONG allocationGranularity;
    ULONG_PTR minimumUserModeAddress;
    ULONG_PTR maximumUserModeAddress;
    ULONG_PTR activeProcessorsAffinityMask;
    BYTE numberOfProcessors;
} HwSystemBasicInformation;

static ULONGLONG HwProfilePageCount(void) {
    ULONGLONG bytes = (ULONGLONG)g_Profile.memory.total_gb * 1024ULL * 1024ULL * 1024ULL;
    return bytes / 4096ULL;
}

static void HwPatchBasicInformation(PVOID info, ULONG len) {
    if (len < sizeof(HwSystemBasicInformation)) return;
    HwSystemBasicInformation* b = (HwSystemBasicInformation*)info;
    ULONGLONG pages = HwProfilePageCount();
    if (pages == 0) return;
    b->numberOfPhysicalPages = (ULONG)pages;
    b->highestPhysicalPageNumber = (ULONG)(pages - 1);
    b->activeProcessorsAffinityMask = HwAllThreadMask();
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 1;
    b->numberOfProcessors = (BYTE)HW_MIN(logical, 64);
}

typedef struct HwSystemProcessorInformation {
    USHORT processorArchitecture;
    USHORT processorLevel;
    USHORT processorRevision;
    USHORT maximumProcessors;
    ULONG processorFeatureBits;
} HwSystemProcessorInformation;

static void HwPatchProcessorInformation(PVOID info, ULONG len) {
    if (len < sizeof(HwSystemProcessorInformation)) return;
    HwSystemProcessorInformation* p = (HwSystemProcessorInformation*)info;
    p->processorArchitecture = 9;   /* PROCESSOR_ARCHITECTURE_AMD64 */
    p->processorLevel = (USHORT)g_Profile.cpu.family;
    p->processorRevision = (USHORT)((g_Profile.cpu.model << 8) | (g_Profile.cpu.stepping & 0xFF));
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 1;
    p->maximumProcessors = (USHORT)HW_MIN(logical, 0xFFFF);
}

/* SYSTEM_PERFORMANCE_INFORMATION — only the memory-related ULONGs are patched. */
static void HwPatchPerformanceInformation(PVOID info, ULONG len) {
    BYTE* b = (BYTE*)info;
    ULONGLONG pages = HwProfilePageCount();
    if (pages == 0) return;
    /* AvailablePages @44, CommittedPages @48, CommitLimit @52, PeakCommitment @56 */
    if (len >= 60) {
        ULONG avail = (ULONG)(pages * 30 / 100);
        ULONG commitLimit = (ULONG)(pages * 3 / 2);
        ULONG committed = (ULONG)(pages * 40 / 100);
        ULONG peak = (ULONG)(committed * 11 / 10);
        memcpy(b + 44, &avail, 4);
        memcpy(b + 48, &committed, 4);
        memcpy(b + 52, &commitLimit, 4);
        memcpy(b + 56, &peak, 4);
    }
}

/* SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION array (class 8). */
#define HW_PPI_SIZE 48   /* 5 × LARGE_INTEGER + ULONG + padding, x64 */

static NTSTATUS HwPatchProcessorPerformanceInformation(PVOID info, ULONG len, PULONG plen) {
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 0;
    if (logical == 0 || !info) return 0; /* STATUS_SUCCESS — nothing to do */
    DWORD have = plen ? (*plen / HW_PPI_SIZE) : (len / HW_PPI_SIZE);
    if (have == 0) return 0;
    if (logical > have) {
        /* Caller buffer too small for the profiled processor count. */
        if (plen) *plen = logical * HW_PPI_SIZE;
        return (NTSTATUS)0xC0000004L; /* STATUS_INFO_LENGTH_MISMATCH */
    }
    if (logical < have) {
        /* Truncate the array so the caller sees the profiled count. */
        if (plen) *plen = logical * HW_PPI_SIZE;
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════
   NtPowerInformation (processor clocks)
   ════════════════════════════════════════════════════════════ */

static void HwFillProcessorPowerInformation(PVOID buf, ULONG len) {
    if (!buf) return;
    DWORD count = len / 24;
    DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 0;
    if (logical == 0) return;
    if (count > logical) count = logical;
    for (DWORD i = 0; i < count; i++) {
        ULONG* v = (ULONG*)((BYTE*)buf + i * 24);
        v[0] = i;                                            /* Number */
        v[1] = g_Profile.cpu.max_clock_mhz;                  /* MaxMhz */
        v[2] = g_Profile.cpu.base_clock_mhz;                 /* CurrentMhz */
        v[3] = g_Profile.cpu.max_clock_mhz;                  /* MhzLimit */
        v[4] = 5;                                            /* MaxIdleState */
        v[5] = 0;                                            /* CurrentIdleState */
    }
}

/* ════════════════════════════════════════════════════════════
   Volume serial / MAC helpers
   ════════════════════════════════════════════════════════════ */

static BOOL HwParseVolumeSerial(const char* s, DWORD* out) {
    if (!s || !out) return FALSE;
    char hex[9];
    int j = 0;
    for (const char* p = s; *p && j < 8; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
            (*p >= 'A' && *p <= 'F')) {
            hex[j++] = *p;
        }
    }
    if (j != 8) return FALSE;
    hex[8] = 0;
    *out = (DWORD)strtoul(hex, NULL, 16);
    return TRUE;
}

static void HwDeriveMac(DWORD index, BYTE out[6]) {
    memcpy(out, g_Profile.network.mac, 6);
    if (index > 0) {
        out[5] = (BYTE)(out[5] + (index & 0x3F));
        if ((out[5] & 0x01) == 0) out[5] |= 0x02; /* keep unicast + local */
    }
}
