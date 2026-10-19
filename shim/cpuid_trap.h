/*
   Ghost Sandbox — CPUID Instruction Interceptor
   Patches CPUID (0F A2) occurrences in executable sections to UD2 (0F 0B)
   and emulates the instruction in a vectored exception handler, returning
   the profile's CPU identity. Without a profile the real CPUID values are
   returned (transparent passthrough).

   Notes:
     - Only the second opcode byte is written (A2 -> 0B), so the instruction
       stream is valid at every instant, even for threads executing the site.
     - The shim's own module is never patched (its CPUID emulation uses
       __cpuidex, which must not re-enter the handler).
     - JIT-generated code outside image sections is not patched (v1 limit).
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include "trace_format.h"

/* ─── Forward declarations (defined in sandbox_shim.cpp) ── */
extern PipeClient g_Pipe;
extern BOOL g_TracingPaused;
extern HMODULE g_hSelf;

/* ─── CPUID Trap State ───────────────────────────────────── */
static PVOID g_CpuidVehHandle = NULL;
static volatile BOOL g_CpuidTrapEnabled = FALSE;

/* Patched CPUID sites: 0F A2 replaced by 0F 0B. */
#define CPUID_MAX_SITES 2048
static volatile LONG g_CpuidSiteCount = 0;
static void* g_CpuidSites[CPUID_MAX_SITES];

/* Only emit the first N EVT_CPUID_TRAP events (hot loops stay quiet). */
static volatile LONG g_CpuidTraceBudget = 64;

/* ─── CPUID Opcode Detection ────────────────────────────── */
#define CPUID_OPCODE_BYTE1 0x0F
#define CPUID_OPCODE_BYTE2 0xA2
#define UD2_OPCODE_BYTE2   0x0B

static LONG CpuidRecordSite(void* addr) {
    LONG idx = InterlockedIncrement(&g_CpuidSiteCount) - 1;
    if (idx < CPUID_MAX_SITES) {
        g_CpuidSites[idx] = addr;
        return idx;
    }
    InterlockedDecrement(&g_CpuidSiteCount);
    return -1;
}

static BOOL CpuidIsPatchedSite(void* addr) {
    LONG n = g_CpuidSiteCount;
    if (n > CPUID_MAX_SITES) n = CPUID_MAX_SITES;
    for (LONG i = 0; i < n; i++) {
        if (g_CpuidSites[i] == addr) return TRUE;
    }
    return FALSE;
}

/* ─── Module patching ────────────────────────────────────── */

typedef struct HwUnicodeStringLite {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} HwUnicodeStringLite;

typedef struct HwLdrEntryLite {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    HwUnicodeStringLite FullDllName;
    HwUnicodeStringLite BaseDllName;
} HwLdrEntryLite;

typedef struct HwPebLdrLite {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} HwPebLdrLite;

typedef struct HwPebLite {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    HwPebLdrLite* Ldr;
} HwPebLite;

/* Patch every CPUID in the executable sections of one module. */
static void CpuidPatchModule(HMODULE hMod) {
    if (!hMod || hMod == g_hSelf || !g_CpuidTrapEnabled) return;
    if (g_CpuidSiteCount >= CPUID_MAX_SITES) return;

    BYTE* base = (BYTE*)hMod;
    __try {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (sec->SizeOfRawData == 0) continue;
            DWORD size = sec->SizeOfRawData;
            if (sec->Misc.VirtualSize && sec->Misc.VirtualSize < size) {
                size = sec->Misc.VirtualSize;
            }
            BYTE* p = base + sec->VirtualAddress;
            for (DWORD off = 0; off + 2 <= size; off++) {
                if (p[off] != CPUID_OPCODE_BYTE1 || p[off + 1] != CPUID_OPCODE_BYTE2) {
                    continue;
                }
                BYTE* site = p + off;
                if (CpuidRecordSite(site) < 0) return; /* table full */
                DWORD oldProtect = 0;
                if (VirtualProtect(site, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    /* Only the second byte changes: 0F A2 -> 0F 0B (UD2).
                       The two-byte sequence stays valid throughout. */
                    site[1] = UD2_OPCODE_BYTE2;
                    DWORD restore = 0;
                    VirtualProtect(site, 2, oldProtect, &restore);
                }
                if (g_CpuidSiteCount >= CPUID_MAX_SITES) return;
            }
        }
        FlushInstructionCache(GetCurrentProcess(), base, nt->OptionalHeader.SizeOfImage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Malformed image or unreadable section — skip. */
    }
}

/* Patch every module currently loaded in this process. */
static void CpuidPatchAllModules(void) {
    __try {
        HwPebLite* peb = (HwPebLite*)__readgsqword(0x60);
        if (!peb || !peb->Ldr) return;
        LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
        for (LIST_ENTRY* e = head->Flink; e && e != head; e = e->Flink) {
            HwLdrEntryLite* mod = (HwLdrEntryLite*)e;
            if (mod->DllBase) CpuidPatchModule((HMODULE)mod->DllBase);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/* ─── Helper: Pack brand string into registers ───────────── */
// Brand string is 48 bytes across leaves 0x80000002-0x80000004
// Each leaf returns 16 bytes (EAX:EBX:ECX:EDX, 4 bytes each)
static void PackBrandStringRegisters(const char* brandString, DWORD leaf,
                                      DWORD* eax, DWORD* ebx, DWORD* ecx, DWORD* edx) {
    char padded[48];
    memset(padded, 0, sizeof(padded));
    strncpy_s(padded, brandString, _TRUNCATE);

    // Leaf 0x80000002 = bytes 0..15
    // Leaf 0x80000003 = bytes 16..31
    // Leaf 0x80000004 = bytes 32..47
    int offset = (leaf - 0x80000002) * 16;
    if (offset < 0 || offset >= 48) {
        *eax = *ebx = *ecx = *edx = 0;
        return;
    }

    memcpy(eax, &padded[offset + 0], 4);
    memcpy(ebx, &padded[offset + 4], 4);
    memcpy(ecx, &padded[offset + 8], 4);
    memcpy(edx, &padded[offset + 12], 4);
}

/* ─── Helper: Pack vendor string ─────────────────────────── */
// Vendor string (e.g. "GenuineIntel") is returned in EBX:EDX:ECX order
static void PackVendorString(const char* vendor, DWORD* ebx, DWORD* edx, DWORD* ecx) {
    char padded[12];
    memset(padded, 0, sizeof(padded));
    if (vendor) {
        size_t len = strlen(vendor);
        if (len > sizeof(padded)) len = sizeof(padded);
        memcpy(padded, vendor, len);          // exactly 12 bytes, no forced NUL
    }

    memcpy(ebx, &padded[0], 4);
    memcpy(edx, &padded[4], 4);
    memcpy(ecx, &padded[8], 4);
}

/* ─── Helper: Build feature flags for CPUID leaf 1 ──────── */
static void BuildFeatureFlags(const SharedCpuFeatures* f, DWORD* ecx_out, DWORD* edx_out) {
    DWORD ecx = 0, edx = 0;

    // EDX feature flags (leaf 1)
    if (f->sse)    edx |= (1 << 25);   // SSE
    if (f->sse2)   edx |= (1 << 26);   // SSE2
    edx |= (1 << 0);   // FPU
    edx |= (1 << 4);   // TSC
    edx |= (1 << 5);   // MSR
    edx |= (1 << 8);   // CX8
    edx |= (1 << 15);  // CMOV
    edx |= (1 << 23);  // MMX
    edx |= (1 << 24);  // FXSR

    // ECX feature flags (leaf 1)
    if (f->sse3)     ecx |= (1 << 0);    // SSE3
    if (f->clmul)    ecx |= (1 << 1);    // PCLMULQDQ
    if (f->ssse3)    ecx |= (1 << 9);    // SSSE3
    if (f->fma)      ecx |= (1 << 12);   // FMA
    if (f->sse4_1)   ecx |= (1 << 19);   // SSE4.1
    if (f->sse4_2)   ecx |= (1 << 20);   // SSE4.2
    if (f->movbe)    ecx |= (1 << 22);   // MOVBE
    if (f->popcnt)   ecx |= (1 << 23);   // POPCNT
    if (f->aes_ni)   ecx |= (1 << 25);   // AES-NI
    if (f->avx)      ecx |= (1 << 28);   // AVX
    if (f->f16c)     ecx |= (1 << 29);   // F16C
    if (f->rdrand)   ecx |= (1 << 30);   // RDRAND
    ecx |= (1 << 13);  // CX16

    *ecx_out = ecx;
    *edx_out = edx;
}

static DWORD CpuidFlog2(DWORD v) {
    DWORD shift = 0;
    while ((v >>= 1) != 0) shift++;
    return shift;
}

/* ─── VEH Handler ────────────────────────────────────────── */
static LONG CALLBACK CpuidExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (!g_CpuidTrapEnabled) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PEXCEPTION_RECORD rec = ExceptionInfo->ExceptionRecord;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    if (rec->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* Only handle exceptions raised at sites we patched (0F 0B). */
    void* site = (void*)rec->ExceptionAddress;
    if (!CpuidIsPatchedSite(site)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    BYTE* rip = (BYTE*)ctx->Rip;
    __try {
        if (rip[0] != CPUID_OPCODE_BYTE1 || rip[1] != UD2_OPCODE_BYTE2) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD leaf = (DWORD)ctx->Rax;
    DWORD subleaf = (DWORD)ctx->Rcx;
    void* cpuidAddr = (void*)ctx->Rip;   // application code address (for attribution)

    /* No profile: transparently return the real CPUID values. */
    if (!g_ProfileLoaded) {
        int regs[4] = { 0, 0, 0, 0 };
        __cpuidex(regs, (int)leaf, (int)subleaf);
        ctx->Rax = (DWORD)regs[0];
        ctx->Rbx = (DWORD)regs[1];
        ctx->Rcx = (DWORD)regs[2];
        ctx->Rdx = (DWORD)regs[3];
        ctx->Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    DWORD eax = 0, ebx = 0, ecx = 0, edx = 0;

    switch (leaf) {
        case 0x00:
            // Vendor string
            eax = 0x20;  // Max supported leaf
            PackVendorString(g_Profile.cpu.manufacturer, &ebx, &edx, &ecx);
            break;

        case 0x01: {
            // Family/model/stepping + features
            // EAX = stepping[3:0] | model[7:4] | family[11:8] | type[13:12] | ext_model[19:16] | ext_family[27:20]
            DWORD family = g_Profile.cpu.family;
            DWORD model = g_Profile.cpu.model;
            DWORD stepping = g_Profile.cpu.stepping;

            DWORD base_family = (family <= 0x0F) ? family : 0x0F;
            DWORD ext_family = (family > 0x0F) ? (family - 0x0F) : 0;
            DWORD base_model = model & 0x0F;
            DWORD ext_model = (model >> 4) & 0x0F;

            eax = (stepping & 0x0F)
                | ((base_model & 0x0F) << 4)
                | ((base_family & 0x0F) << 8)
                | ((ext_model & 0x0F) << 16)
                | ((ext_family & 0xFF) << 20);

            // EBX: APIC ID, logical processors, etc.
            ebx = (g_Profile.cpu.cores_logical << 16) | 0x00000800;

            BuildFeatureFlags(&g_Profile.cpu.features, &ecx, &edx);
            break;
        }

        case 0x04: {
            // Cache info (simplified: just report L1/L2/L3 sizes)
            switch (subleaf) {
                case 0: // L1 Data
                    eax = 0x04000121;
                    ebx = ((64 - 1) << 22) | ((8 - 1) << 12) | (64 - 1);
                    ecx = (g_Profile.cpu.l1_cache_kb * 1024 / (64 * 8 * 64)) - 1;
                    edx = 0;
                    break;
                case 2: // L2
                    eax = 0x04000143;
                    ebx = ((64 - 1) << 22) | ((16 - 1) << 12) | (64 - 1);
                    ecx = (g_Profile.cpu.l2_cache_kb * 1024 / (64 * 16 * 64)) - 1;
                    edx = 0;
                    break;
                case 3: // L3
                    eax = 0x04000163;
                    ebx = ((64 - 1) << 22) | ((16 - 1) << 12) | (64 - 1);
                    ecx = (g_Profile.cpu.l3_cache_kb * 1024 / (64 * 16 * 64)) - 1;
                    edx = 0;
                    break;
                default:
                    eax = ebx = ecx = edx = 0;
                    break;
            }
            break;
        }

        case 0x07: {
            // Structured Extended Feature Flags (subleaf 0)
            if (subleaf == 0) {
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;

                if (g_Profile.cpu.features.bmi1)   ebx |= (1 << 3);
                if (g_Profile.cpu.features.avx2)   ebx |= (1 << 5);
                if (g_Profile.cpu.features.bmi2)   ebx |= (1 << 8);
                if (g_Profile.cpu.features.avx512f) ebx |= (1 << 16);
                if (g_Profile.cpu.features.avx512bw) ebx |= (1 << 30);
                if (g_Profile.cpu.features.avx512vl) ebx |= (1 << 31);
                if (g_Profile.cpu.features.sha)    ebx |= (1 << 29);
                if (g_Profile.cpu.features.rdseed) ebx |= (1 << 18);
                if (g_Profile.cpu.features.adx)    ebx |= (1 << 19);
                if (g_Profile.cpu.features.vaes)   ecx |= (1 << 9);
                if (g_Profile.cpu.features.vpclmulqdq) ecx |= (1 << 10);
                if (g_Profile.cpu.features.avx_vnni) eax |= (1 << 4); // In subleaf 1 normally
            }
            break;
        }

        case 0x0B: {
            // Extended topology enumeration (SMT / core levels)
            DWORD logical = g_Profile.cpu.cores_logical ? g_Profile.cpu.cores_logical : 1;
            DWORD phys = g_Profile.cpu.cores_physical ? g_Profile.cpu.cores_physical : logical;
            DWORD threads = (logical >= phys) ? (logical / phys) : 1;
            if (subleaf == 0 && threads > 1) {
                eax = CpuidFlog2(threads);
                ebx = logical;
                ecx = 0x0100 | 1;   // level 1, type SMT
                edx = 0;
            } else if (subleaf <= 1) {
                eax = CpuidFlog2(logical);
                ebx = logical;
                ecx = 0x0200 | (DWORD)(subleaf + 1);
                edx = 0;
            } else {
                eax = ebx = ecx = edx = 0;  // invalid level
            }
            break;
        }

        case 0x16: {
            // Processor frequency information (MHz)
            eax = g_Profile.cpu.base_clock_mhz;
            ebx = g_Profile.cpu.max_clock_mhz;
            ecx = 100;   // bus clock
            edx = 0;
            break;
        }

        case 0x80000000:
            // Max extended function number
            eax = 0x80000008;
            ebx = ecx = edx = 0;
            break;

        case 0x80000001:
            // Extended feature flags
            ecx = 0;
            edx = 0;
            if (g_Profile.cpu.features.lzcnt) ecx |= (1 << 5);
            if (g_Profile.cpu.features.abm)   ecx |= (1 << 5);  // ABM = LZCNT + POPCNT
            edx |= (1 << 29);  // Long mode (x86-64)
            break;

        case 0x80000002:
        case 0x80000003:
        case 0x80000004:
            // Brand string (48 bytes across 3 leaves)
            PackBrandStringRegisters(g_Profile.cpu.brand_string, leaf, &eax, &ebx, &ecx, &edx);
            break;

        case 0x80000006: {
            // Extended cache information: L2/L3 in KB
            ecx = (g_Profile.cpu.l2_cache_kb << 16) | 0x0800;
            edx = (g_Profile.cpu.l3_cache_kb << 16) | 0x1000;
            break;
        }

        case 0x80000008:
            // Address sizes
            eax = 0x00003028;  // 48-bit virtual, 40-bit physical
            ebx = ecx = edx = 0;
            ecx = g_Profile.cpu.cores_logical - 1;
            break;

        default:
            // Hypervisor leaves (0x40000000/0x40000001) and anything else the
            // profile does not define: report "not supported" (all zeros) so
            // no host/hypervisor identity leaks through.
            eax = ebx = ecx = edx = 0;
            break;
    }

    // Set the output registers
    ctx->Rax = eax;
    ctx->Rbx = ebx;
    ctx->Rcx = ecx;
    ctx->Rdx = edx;

    // Skip past the patched instruction (0F 0B)
    ctx->Rip += 2;

    // Send trace event (bounded so hot loops do not flood the pipe)
    if (!g_TracingPaused && InterlockedDecrement(&g_CpuidTraceBudget) >= 0) {
        TraceEventCpuidTrap evt = {};
        evt.header.type = EVT_CPUID_TRAP;
        evt.header.size = sizeof(evt);
        QueryPerformanceCounter(&evt.header.timestamp);
        evt.header.threadId = GetCurrentThreadId();
        evt.leaf = leaf;
        evt.subleaf = subleaf;
        evt.eax = eax;
        evt.ebx = ebx;
        evt.ecx = ecx;
        evt.edx = edx;
        g_Pipe.SendEvent(&evt, sizeof(evt));
    }

    /* DRM watch: VM-detection CPUID probes (hypervisor bit / hypervisor vendor). */
    if (g_DrmEnabled && (leaf == 0x01 || leaf == 0x40000000)) {
        static LONG s_thrCpuid = 0;
        char det[160], ret[224];
        snprintf(det, sizeof(det), "leaf=0x%08X, subleaf=0x%08X%s", leaf, subleaf,
            (leaf == 0x40000000)
                ? " (hypervisor vendor probe - VM detection)"
                : " (CPU signature/feature probe)");
        snprintf(ret, sizeof(ret),
            "EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X%s", eax, ebx, ecx, edx,
            (leaf == 0x01 && (ecx & 0x80000000)) ? " [hypervisor bit SET]" : "");
        DrmEmit(cpuidAddr, &s_thrCpuid, 10, 500,
            DRM_CAT_ENVIRONMENT, (leaf == 0x40000000) ? DRM_SEV_CRIT : DRM_SEV_INFO,
            DRM_VERDICT_UNKNOWN, "CPUID", "cpu",
            (leaf == 0x40000000) ? "no hypervisor vendor string (bare-metal CPU)"
                                 : "profiled CPU identity (hypervisor bit clear)",
            ret, det, ((ULONGLONG)leaf << 32) | subleaf);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ─── Install/Uninstall ──────────────────────────────────── */

static void InstallCpuidTrap() {
    if (!g_CpuidVehHandle) {
        g_CpuidVehHandle = AddVectoredExceptionHandler(1, CpuidExceptionHandler);
    }
    g_CpuidTrapEnabled = TRUE;
    CpuidPatchAllModules();
}

static void UninstallCpuidTrap() {
    g_CpuidTrapEnabled = FALSE;
    if (g_CpuidVehHandle) {
        RemoveVectoredExceptionHandler(g_CpuidVehHandle);
        g_CpuidVehHandle = NULL;
    }
}
