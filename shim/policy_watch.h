/*
   Ghost Sandbox — Import / Export Policy Engine
   ──────────────────────────────────────────────
   Implements the sample-sandbox service: the controller drops a DLL/EXE,
   inspects its imports/exports, and ships a policy that decides what the
   instrumented process may CALL (imports) and what its loaded modules
   EXPOSE (exports):

     Observe — every call is reported (caller module + RVA), and the call
               is passed through to the real target untouched.
     Block   — the call is swallowed, a controller-chosen value is
               returned, and the event is reported.

   Mechanism (no trampoline per call site):
     For every targeted call site a tiny x64 stub is generated into an
     RWX pool:
        observe : save arg regs, call dispatcher(idx, callerRet) which
                  returns the real function, restore, tail-jmp into it.
        block   : call the block bridge (returns the fake value), then ret
                  straight back to the original caller.
     Import rules patch IAT slots (in every loaded module); export rules
     inline-hook the module's export via the trampoline engine. Dynamic
     resolution through GetProcAddress is intercepted as well.

   Delivery:
     * shared memory "GhostSandboxPolicy" (read in DllMain — in force
       before the target's entry point runs), and
     * CMD_POLICY frames for live updates (full replace, with restore).

   Safety:
     * the shim's own module is never patched,
     * GetLastError is preserved around every emission,
     * per-entry emission throttling + a global event cap,
     * all PE walking is SEH-guarded against malformed headers.

   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include "trace_format.h"
#include "drm_watch.h"   /* caller attribution + throttle helpers */

/* ─── State ──────────────────────────────────────────────── */
class PipeClient;
static PipeClient* g_PolicyPipe = NULL;

#define GHOST_POLICY_MAX_RUNTIME (GHOST_POLICY_MAX_ENTRIES + 96)
#define GHOST_POLICY_MAX_EVENTS  50000
#define GHOST_POLICY_POOL_SIZE   0x10000  /* 64 KiB of RWX for stubs/bridges */
                                          /* (never reused: GetProcAddress */
                                          /*  results may outlive a policy) */

static volatile LONG g_PolicySent     = 0;   /* global event cap        */
static volatile LONG g_PolicySlotsPatched = 0;
static volatile LONG g_PolicyExportHooks  = 0;

struct PolicyEntry {
    DWORD kind;                  /* PolicyKind                       */
    DWORD action;                /* PolicyAction                     */
    ULONGLONG blockValue;        /* fake return for BLOCK            */
    char module[64];             /* rule pattern (from controller)   */
    char function[96];           /* rule pattern (from controller)   */
    char resolvedModule[64];     /* module owning the function       */
    ULONGLONG realAddr;          /* passthrough target (observe)     */
    BYTE* stub;                  /* generated entry stub             */
    DWORD ruleIndex;             /* rule id for reporting            */
    LONG  hits;                  /* call counter (always bumped)     */
    LONG  emitted;               /* emission throttle counter        */
    int   hookIdx;               /* inline hook index (export rules) */
    BOOL  active;
};

static PolicyEntry g_Policy[GHOST_POLICY_MAX_RUNTIME];
static int        g_PolicyCount = 0;

/* Restore bookkeeping. */
struct PolicySlotPatch { void** slot; ULONGLONG saved; };
static PolicySlotPatch g_PolicySlots[512];
static int             g_PolicySlotCount = 0;
static int             g_PolicyHookIdx[GHOST_POLICY_MAX_RUNTIME + 64];
static int             g_PolicyHookCount = 0;

/* RWX stub pool. */
static BYTE* g_PolicyPool = NULL;
static DWORD g_PolicyPoolUsed = 0;

/* Re-entrancy guard for dispatchers (TLS). */
static DWORD g_PolicyTls = TLS_OUT_OF_INDEXES;

/* ─── Small helpers ──────────────────────────────────────── */

/* Pattern match: "" or "*" = any; trailing '*' = prefix match;
   otherwise case-insensitive equality (module/function names). */
static BOOL PolicyMatchName(const char* pattern, const char* name) {
    if (!pattern || !name) return FALSE;
    if (!pattern[0] || strcmp(pattern, "*") == 0) return TRUE;
    size_t plen = strlen(pattern);
    if (pattern[plen - 1] == '*')
        return _strnicmp(pattern, name, plen - 1) == 0;
    return _stricmp(pattern, name) == 0;
}

static void PolicyBaseName(const char* path, char* out, int outLen) {
    const char* base = path ? strrchr(path, '\\') : NULL;
    base = base ? base + 1 : (path ? path : "");
    strncpy_s(out, outLen, base, _TRUNCATE);
}

static void PolicyModuleName(HMODULE mod, char* out, int outLen) {
    out[0] = 0;
    if (!mod) { strncpy_s(out, outLen, "?", _TRUNCATE); return; }
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(mod, path, MAX_PATH);
    PolicyBaseName(path, out, outLen);
}

static BYTE* PolicyPoolAlloc(DWORD size) {
    if (!g_PolicyPool) {
        g_PolicyPool = (BYTE*)VirtualAlloc(NULL, GHOST_POLICY_POOL_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!g_PolicyPool) return NULL;
    }
    size = (size + 15) & ~15u;
    if (g_PolicyPoolUsed + size > GHOST_POLICY_POOL_SIZE) return NULL;
    BYTE* p = g_PolicyPool + g_PolicyPoolUsed;
    g_PolicyPoolUsed += size;
    memset(p, 0xCC, size);      /* int3 fill: a mistake traps loudly */
    return p;
}

/* ─── x64 stub emission ──────────────────────────────────── */
/* Layout note (stack, X = rsp at stub entry — original return address at [X]):

   observe stub: 4 pushes (rsp = X-32) + sub 0x28 (rsp = X-72)
                  -> caller return address is [rsp+0x48]
   block bridge: sub 0x28 (rsp = X-40)
                  -> caller return address is [rsp+0x28]

   Alignment: entry rsp % 16 == 8; observe: -32 -40 = -72  => % 16 == 0 before
   call. block: -40 => % 16 == 0 before call. Both correct for the C++ ABI. */

static void PolicyEmitByte(BYTE*& p, BYTE b)      { *p++ = b; }
static void PolicyEmitU32(BYTE*& p, DWORD v)      { memcpy(p, &v, 4); p += 4; }
static void PolicyEmitU64(BYTE*& p, ULONGLONG v)  { memcpy(p, &v, 8); p += 8; }

extern "C" ULONGLONG PolicyDispatchObserve(ULONG idx, void* callerRet);
extern "C" ULONGLONG PolicyDispatchBlock(ULONG idx, void* callerRet);

/* mov r10d, idx / mov rax, <target> / jmp rax */
static BYTE* PolicyMakeBlockStub(ULONG idx, void* bridge) {
    BYTE* s = PolicyPoolAlloc(32);
    if (!s) return NULL;
    BYTE* p = s;
    PolicyEmitByte(p, 0x41); PolicyEmitByte(p, 0xBA); PolicyEmitU32(p, idx); /* mov r10d, idx */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0xB8); PolicyEmitU64(p, (ULONGLONG)bridge);
    PolicyEmitByte(p, 0xFF); PolicyEmitByte(p, 0xE0);                        /* jmp rax */
    return s;
}

/* Save arg regs, read caller ret, call dispatcher -> real addr, restore, jmp */
static BYTE* PolicyMakeObserveStub(ULONG idx) {
    BYTE* s = PolicyPoolAlloc(64);
    if (!s) return NULL;
    BYTE* p = s;
    PolicyEmitByte(p, 0x51);                            /* push rcx */
    PolicyEmitByte(p, 0x52);                            /* push rdx */
    PolicyEmitByte(p, 0x41); PolicyEmitByte(p, 0x50);   /* push r8  */
    PolicyEmitByte(p, 0x41); PolicyEmitByte(p, 0x51);   /* push r9  */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x83); PolicyEmitByte(p, 0xEC); PolicyEmitByte(p, 0x28); /* sub rsp,28h */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x8B); PolicyEmitByte(p, 0x54); PolicyEmitByte(p, 0x24); PolicyEmitByte(p, 0x48); /* mov rdx,[rsp+48h] */
    PolicyEmitByte(p, 0xB9); PolicyEmitU32(p, idx);     /* mov ecx, idx */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0xB8); PolicyEmitU64(p, (ULONGLONG)&PolicyDispatchObserve);
    PolicyEmitByte(p, 0xFF); PolicyEmitByte(p, 0xD0);   /* call rax */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x83); PolicyEmitByte(p, 0xC4); PolicyEmitByte(p, 0x28); /* add rsp,28h */
    PolicyEmitByte(p, 0x41); PolicyEmitByte(p, 0x59);   /* pop r9  */
    PolicyEmitByte(p, 0x41); PolicyEmitByte(p, 0x58);   /* pop r8  */
    PolicyEmitByte(p, 0x5A);                            /* pop rdx */
    PolicyEmitByte(p, 0x59);                            /* pop rcx */
    PolicyEmitByte(p, 0xFF); PolicyEmitByte(p, 0xE0);   /* jmp rax -> real */
    return s;
}

/* The block bridge: idx in r10d; returns the entry's fake value to the
   ORIGINAL caller (straight through the stub's ret). */
static BYTE* PolicyMakeBlockBridge() {
    BYTE* s = PolicyPoolAlloc(48);
    if (!s) return NULL;
    BYTE* p = s;
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x83); PolicyEmitByte(p, 0xEC); PolicyEmitByte(p, 0x28); /* sub rsp,28h */
    PolicyEmitByte(p, 0x44); PolicyEmitByte(p, 0x89); PolicyEmitByte(p, 0xD1);   /* mov ecx, r10d */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x8B); PolicyEmitByte(p, 0x54); PolicyEmitByte(p, 0x24); PolicyEmitByte(p, 0x28); /* mov rdx,[rsp+28h] */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0xB8); PolicyEmitU64(p, (ULONGLONG)&PolicyDispatchBlock);
    PolicyEmitByte(p, 0xFF); PolicyEmitByte(p, 0xD0);   /* call rax */
    PolicyEmitByte(p, 0x48); PolicyEmitByte(p, 0x83); PolicyEmitByte(p, 0xC4); PolicyEmitByte(p, 0x28); /* add rsp,28h */
    PolicyEmitByte(p, 0xC3);                            /* ret -> original caller */
    return s;
}
static BYTE* g_PolicyBlockBridge = NULL;

/* ─── Event emission ─────────────────────────────────────── */

static void PolicyEmitHit(PolicyEntry* e, void* callerRet, ULONGLONG retValue,
                          BOOL blocked, const char* detail) {
    DWORD callerLastError = GetLastError();

    LONG n = InterlockedIncrement(&e->emitted);
    if (n > 20 && (n % 50) != 0) { SetLastError(callerLastError); return; }
    if (InterlockedIncrement(&g_PolicySent) > GHOST_POLICY_MAX_EVENTS) {
        SetLastError(callerLastError);
        return;
    }

    TraceEventPolicyHit ev = {};
    ev.header.type = EVT_POLICY_HIT;
    ev.header.size = sizeof(ev);
    LARGE_INTEGER ts; ts.QuadPart = (LONGLONG)__rdtsc();
    ev.header.timestamp = ts;
    ev.header.threadId = GetCurrentThreadId();
    ev.kind = e->kind;
    ev.action = e->action;
    ev.blocked = blocked;
    ev.retValue = retValue;
    strncpy_s(ev.module, e->resolvedModule[0] ? e->resolvedModule : e->module, _TRUNCATE);
    strncpy_s(ev.function, e->function, _TRUNCATE);

    ULONGLONG rva = 0;
    HMODULE caller = DrmCallerModule(callerRet, &rva);
    DrmModuleBaseName(caller, ev.callerModule, sizeof(ev.callerModule));
    ev.callerRva = rva;
    strncpy_s(ev.detail, detail, _TRUNCATE);

    if (g_PolicyPipe) g_PolicyPipe->SendEvent(&ev, sizeof(ev));
    SetLastError(callerLastError);
}

/* One-line engine status (apply / clear) — kind 0, action 0. */
static void PolicyEmitSummary(const char* function, const char* detail, ULONGLONG value) {
    if (!g_PolicyPipe) return;
    TraceEventPolicyHit ev = {};
    ev.header.type = EVT_POLICY_HIT;
    ev.header.size = sizeof(ev);
    LARGE_INTEGER ts; ts.QuadPart = (LONGLONG)__rdtsc();
    ev.header.timestamp = ts;
    ev.header.threadId = GetCurrentThreadId();
    ev.kind = 0;
    ev.action = 0;
    ev.blocked = 0;
    ev.retValue = value;
    strncpy_s(ev.module, "sandbox_shim.dll", _TRUNCATE);
    strncpy_s(ev.function, function, _TRUNCATE);
    strncpy_s(ev.callerModule, "sandbox_shim.dll", _TRUNCATE);
    strncpy_s(ev.detail, detail, _TRUNCATE);
    g_PolicyPipe->SendEvent(&ev, sizeof(ev));
}

/* ─── Dispatchers (called from generated stubs) ──────────── */

extern "C" ULONGLONG PolicyDispatchObserve(ULONG idx, void* callerRet) {
    if (idx >= (ULONG)GHOST_POLICY_MAX_RUNTIME) return 0;
    PolicyEntry* e = &g_Policy[idx];

    BOOL guardOk = TRUE;
    if (g_PolicyTls != TLS_OUT_OF_INDEXES) {
        guardOk = (TlsGetValue(g_PolicyTls) == NULL);
        if (guardOk) TlsSetValue(g_PolicyTls, (LPVOID)1);
    }
    if (guardOk) {
        InterlockedIncrement(&e->hits);
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "call passed through to 0x%llX (rule %u)", e->realAddr, e->ruleIndex);
        PolicyEmitHit(e, callerRet, 0, FALSE, detail);
        if (g_PolicyTls != TLS_OUT_OF_INDEXES) TlsSetValue(g_PolicyTls, NULL);
    }
    return e->realAddr;
}

extern "C" ULONGLONG PolicyDispatchBlock(ULONG idx, void* callerRet) {
    if (idx >= (ULONG)GHOST_POLICY_MAX_RUNTIME) return 0;
    PolicyEntry* e = &g_Policy[idx];

    BOOL guardOk = TRUE;
    if (g_PolicyTls != TLS_OUT_OF_INDEXES) {
        guardOk = (TlsGetValue(g_PolicyTls) == NULL);
        if (guardOk) TlsSetValue(g_PolicyTls, (LPVOID)1);
    }
    if (guardOk) {
        InterlockedIncrement(&e->hits);
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "call blocked, returned 0x%llX (rule %u)", e->blockValue, e->ruleIndex);
        PolicyEmitHit(e, callerRet, e->blockValue, TRUE, detail);
        if (g_PolicyTls != TLS_OUT_OF_INDEXES) TlsSetValue(g_PolicyTls, NULL);
    }
    return e->blockValue;
}

/* ─── Rule table management ──────────────────────────────── */

/* Find a runtime entry for (rule, resolvedModule, realAddr), cloning the
   rule when a call site has a different passthrough target or lives in a
   different owning module. Returns -1 when full. */
static int PolicyFindOrClone(int ruleIdx, const char* resolvedModule, ULONGLONG realAddr) {
    PolicyEntry* rule = &g_Policy[ruleIdx];
    for (int i = 0; i < g_PolicyCount; i++) {
        PolicyEntry* e = &g_Policy[i];
        if (e->active &&
            e->ruleIndex == rule->ruleIndex &&
            e->kind == rule->kind && e->action == rule->action &&
            e->realAddr == realAddr &&
            _stricmp(e->resolvedModule, resolvedModule) == 0 &&
            strcmp(e->function, rule->function) == 0) {
            return i;
        }
    }
    if (g_PolicyCount >= GHOST_POLICY_MAX_RUNTIME) return -1;
    int idx = g_PolicyCount++;
    PolicyEntry* e = &g_Policy[idx];
    *e = *rule;                          /* copy rule fields (pattern, value) */
    e->ruleIndex = rule->ruleIndex;
    strncpy_s(e->resolvedModule, resolvedModule, _TRUNCATE);
    e->realAddr = realAddr;
    e->stub = (e->action == POLICY_ACTION_BLOCK)
        ? PolicyMakeBlockStub((ULONG)idx, g_PolicyBlockBridge)
        : PolicyMakeObserveStub((ULONG)idx);
    e->hookIdx = -1;
    e->hits = 0;
    e->emitted = 0;
    e->active = (e->stub != NULL);
    return e->active ? idx : -1;
}

static void PolicySlotRecord(void** slot) {
    if (g_PolicySlotCount < 512) {
        /* remember the pre-patch value for restores */
        g_PolicySlots[g_PolicySlotCount].slot = slot;
        g_PolicySlots[g_PolicySlotCount].saved = *(ULONGLONG*)slot;
        g_PolicySlotCount++;
    }
}

/* Patch one IAT slot when a rule matches. */
static void PolicyMaybePatchSlot(void** slot, const char* ownerModule,
                                 const char* funcName) {
    if (!slot || !*slot) return;
    ULONGLONG cur = *(ULONGLONG*)slot;
    /* never re-patch our own stubs */
    if (g_PolicyPool && cur >= (ULONGLONG)g_PolicyPool &&
        cur < (ULONGLONG)g_PolicyPool + GHOST_POLICY_POOL_SIZE) return;

    for (int i = 0; i < g_PolicyCount; i++) {
        PolicyEntry* rule = &g_Policy[i];
        if (!rule->active || rule->kind != POLICY_KIND_IMPORT) continue;
        if (!PolicyMatchName(rule->module, ownerModule)) continue;
        if (!PolicyMatchName(rule->function, funcName)) continue;

        ULONGLONG real = (rule->action == POLICY_ACTION_OBSERVE) ? cur : 0;
        int idx = PolicyFindOrClone(i, ownerModule, real);
        if (idx < 0) return;

        DWORD oldProtect;
        if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            PolicySlotRecord(slot);
            *slot = g_Policy[idx].stub;
            VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
            InterlockedIncrement(&g_PolicySlotsPatched);
        }
        return;    /* first matching rule wins */
    }
}

/* Walk one module's IAT and apply import rules. */
static void PolicyApplyToModuleIAT(HMODULE hMod) {
    if (!hMod || hMod == DrmSelfModule()) return;
    BYTE* base = (BYTE*)hMod;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        DWORD impVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!impVA) return;

        PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + impVA);
        while (desc->Name) {
            char owner[64];
            PolicyBaseName((const char*)(base + desc->Name), owner, sizeof(owner));

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
            PIMAGE_THUNK_DATA orig  = desc->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk) : NULL;
            while (thunk->u1.Function) {
                if (orig && !(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME ibn =
                        (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData);
                    PolicyMaybePatchSlot((void**)&thunk->u1.Function, owner, (const char*)ibn->Name);
                }
                thunk++;
                if (orig) orig++;
            }
            desc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* malformed PE — leave the module unpatched */
    }
}

/* Apply export rules to a (newly) loaded module: resolve the export and
   inline-hook it through the normal trampoline engine; the generated
   observe stub tail-jumps into the trampoline. */
static void PolicyApplyToModuleExports(HMODULE hMod) {
    if (!hMod || hMod == DrmSelfModule()) return;
    char modName[64];
    PolicyModuleName(hMod, modName, sizeof(modName));

    for (int i = 0; i < g_PolicyCount; i++) {
        PolicyEntry* rule = &g_Policy[i];
        if (!rule->active || rule->kind != POLICY_KIND_EXPORT) continue;
        if (!PolicyMatchName(rule->module, modName)) continue;

        FARPROC fn = GetProcAddress(hMod, rule->function);
        if (!fn) continue;

        void* tramp = NULL;
        int idx = PolicyFindOrClone(i, modName,
            /* observe passthrough is the trampoline (set below) */ 0);
        /* PolicyFindOrClone made the stub with realAddr 0; fix it after we
           know the trampoline. For export rules we need the trampoline FIRST,
           so hook via the engine directly instead. */
        if (idx < 0) continue;

        int hookIdx = InstallInlineHook((void*)fn, (void*)g_Policy[idx].stub,
                                        &tramp, rule->function);
        if (hookIdx < 0) continue;
        g_Policy[idx].realAddr = (ULONGLONG)tramp;
        g_Policy[idx].hookIdx = hookIdx;
        if (g_PolicyHookCount < (int)(sizeof(g_PolicyHookIdx) / sizeof(int)))
            g_PolicyHookIdx[g_PolicyHookCount++] = hookIdx;
        InterlockedIncrement(&g_PolicyExportHooks);
    }
}

static void PolicyApplyToModule(HMODULE hMod) {
    if (g_PolicyCount == 0) return;
    PolicyApplyToModuleIAT(hMod);
    PolicyApplyToModuleExports(hMod);
}

/* ─── Module enumeration ─────────────────────────────────── */

/* Walk the PEB loader list. Safe under the loader lock (DllMain), unlike
   CreateToolhelp32Snapshot which can deadlock there. x64 offsets:
   PEB->Ldr 0x18; PEB_LDR_DATA: Length(0x00) Initialized(0x04) SsHandle(0x08)
   InLoadOrderModuleList(0x10) InMemoryOrderModuleList(0x20)
   InInitializationOrderModuleList(0x30); LDR_DATA_TABLE_ENTRY:
   InLoadOrderLinks(0x00) InMemoryOrderLinks(0x10) InInitializationOrder(0x20)
   DllBase(0x30) … (stable for x64 Windows). */
typedef struct _GSP_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } FullDllName;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } BaseDllName;
} GSP_LDR_ENTRY;

/* Modules enumerated by the last PolicyApplyToAllModules() call (diagnostic,
   surfaced in the PolicyApply summary detail). */
static volatile LONG g_PolicyModulesSeen = 0;

static void PolicyApplyToAllModules() {
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    if (!peb) return;
    BYTE* ldr = *(BYTE**)(peb + 0x18);
    if (!ldr) return;
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x20);   /* InMemoryOrderModuleList */
    LIST_ENTRY* e = head->Flink;
    __try {
        while (e && e != head) {
            GSP_LDR_ENTRY* ent = CONTAINING_RECORD(e, GSP_LDR_ENTRY, InMemoryOrderLinks);
            if (ent->DllBase) {
                InterlockedIncrement(&g_PolicyModulesSeen);
                PolicyApplyToModule((HMODULE)ent->DllBase);
            }
            e = e->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* loader list torn down mid-walk (process exit) — keep what we got */
    }
}

/* ─── Dynamic resolution interception ────────────────────── */

/* TRUE when the controller wants this (module, proc) resolution replaced;
   *inout receives the stub. Called from Hooked_GetProcAddress. */
static BOOL PolicyInterceptGetProcAddress(HMODULE hModule, LPCSTR lpProcName,
                                          FARPROC* inout) {
    if (!inout || !*inout) return FALSE;
    if ((ULONGLONG)lpProcName <= 0xFFFF) return FALSE;   /* ordinal: no name */

    char modName[64];
    PolicyModuleName(hModule, modName, sizeof(modName));

    for (int i = 0; i < g_PolicyCount; i++) {
        PolicyEntry* rule = &g_Policy[i];
        if (!rule->active || rule->kind != POLICY_KIND_IMPORT) continue;
        if (!PolicyMatchName(rule->module, modName)) continue;
        if (!PolicyMatchName(rule->function, lpProcName)) continue;

        ULONGLONG real = (rule->action == POLICY_ACTION_OBSERVE)
            ? (ULONGLONG)(*inout) : 0;
        int idx = PolicyFindOrClone(i, modName, real);
        if (idx < 0) return FALSE;
        *inout = (FARPROC)g_Policy[idx].stub;
        InterlockedIncrement(&g_PolicySlotsPatched);
        return TRUE;
    }
    return FALSE;
}

/* ─── Restore / reapply ──────────────────────────────────── */

static void PolicyRestore() {
    for (int i = 0; i < g_PolicySlotCount; i++) {
        void** slot = g_PolicySlots[i].slot;
        DWORD oldProtect;
        if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            *(ULONGLONG*)slot = g_PolicySlots[i].saved;
            VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
        }
    }
    g_PolicySlotCount = 0;
    for (int i = 0; i < g_PolicyHookCount; i++) {
        UninstallInlineHook(g_PolicyHookIdx[i]);
    }
    g_PolicyHookCount = 0;

    memset(g_Policy, 0, sizeof(g_Policy));
    g_PolicyCount = 0;
    /* NOTE: the stub pool is deliberately NOT rewound — a stub may have been
       handed to the target through GetProcAddress interception and can be
       called after the policy that created it is gone. */
    InterlockedExchange(&g_PolicySlotsPatched, 0);
    InterlockedExchange(&g_PolicyExportHooks, 0);
    InterlockedExchange(&g_PolicyModulesSeen, 0);
}

/* Install `rules` (count entries) and apply them to everything already
   loaded. Performs a full restore first (live-update semantics). */
static void PolicyInstallAndApply(const PolicyWireEntry* rules, DWORD count) {
    PolicyRestore();

    if (count > GHOST_POLICY_MAX_ENTRIES) count = GHOST_POLICY_MAX_ENTRIES;
    for (DWORD i = 0; i < count; i++) {
        PolicyEntry* e = &g_Policy[g_PolicyCount];
        e->kind = rules[i].kind;
        e->action = rules[i].action;
        e->blockValue = rules[i].blockValue;
        strncpy_s(e->module, rules[i].module, _TRUNCATE);
        strncpy_s(e->function, rules[i].function, _TRUNCATE);
        e->resolvedModule[0] = 0;
        e->realAddr = 0;
        e->stub = NULL;
        e->ruleIndex = i + 1;
        e->hits = 0;
        e->emitted = 0;
        e->hookIdx = -1;
        e->active = TRUE;
        if (!g_PolicyBlockBridge) g_PolicyBlockBridge = PolicyMakeBlockBridge();
        g_PolicyCount++;
    }

    PolicyApplyToAllModules();

    char detail[128];
    snprintf(detail, sizeof(detail),
             "%u rules installed: %ld IAT slots patched, %ld export hooks, %ld modules scanned",
             count, g_PolicySlotsPatched, g_PolicyExportHooks, g_PolicyModulesSeen);
    PolicyEmitSummary("PolicyApply", detail, count);
}

/* ─── Delivery paths ─────────────────────────────────────── */

static BOOL PolicyReadSharedMemory(PolicyWireEntry* out, DWORD* outCount) {
    *outCount = 0;
    HANDLE h = OpenFileMappingA(FILE_MAP_READ, FALSE, GHOST_SANDBOX_POLICY_NAME);
    if (!h) return FALSE;
    const SharedPolicy* sp = (const SharedPolicy*)MapViewOfFile(
        h, FILE_MAP_READ, 0, 0, sizeof(SharedPolicy));
    if (sp) {
        if (sp->magic == GHOST_POLICY_MAGIC &&
            sp->version == GHOST_POLICY_SHM_VERSION &&
            sp->count <= GHOST_POLICY_MAX_ENTRIES) {
            memcpy(out, sp->entries, sizeof(PolicyWireEntry) * sp->count);
            *outCount = sp->count;
        }
        UnmapViewOfFile((LPCVOID)sp);
    }
    CloseHandle(h);
    return TRUE;
}

static void PolicyInit(PipeClient* pipe) {
    g_PolicyPipe = pipe;
    if (g_PolicyTls == TLS_OUT_OF_INDEXES) g_PolicyTls = TlsAlloc();

    PolicyWireEntry rules[GHOST_POLICY_MAX_ENTRIES];
    DWORD count = 0;
    if (PolicyReadSharedMemory(rules, &count) && count > 0) {
        PolicyInstallAndApply(rules, count);
        ShimLog("[policy] startup policy applied (%u rules)", count);
    }
}

/* Live update via CMD_POLICY. */
static void PolicyApplyFromCommand(const CommandPolicy* cmd, DWORD cmdSize) {
    DWORD count = cmd->count;
    if (count > GHOST_POLICY_MAX_ENTRIES) count = GHOST_POLICY_MAX_ENTRIES;
    DWORD need = 9 + (DWORD)sizeof(PolicyWireEntry) * count;
    if (cmdSize < need) {
        ShimLog("[policy] CMD_POLICY too small (%u < %u) — ignored", cmdSize, need);
        return;
    }
    PolicyInstallAndApply(cmd->entries, count);
    ShimLog("[policy] live update: %u rules", count);
}
