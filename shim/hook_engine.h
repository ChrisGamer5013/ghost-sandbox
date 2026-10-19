/*
   Ghost Sandbox — Hook Engine  (v2 — relocating trampolines)
   Inline trampoline and IAT hooking primitives for x86-64.

   WHY v2 EXISTS — v1 patched targets by blindly copying a fixed 14 bytes
   into a trampoline allocated elsewhere and appending a jmp back. That is
   broken for real Windows system DLLs in two ways:

     1. kernel32 forwarder stubs are RIP-relative jumps, e.g.
           48 FF 25 <disp32>      jmp qword ptr [rip+disp32]
        The displacement only resolves correctly at the ORIGINAL address.
        Copied verbatim into a trampoline at a different address, the jump
        reads a garbage address and the process takes an access violation
        the first time anything calls the "original" function through the
        trampoline.

     2. Even position-independent code breaks when the copy length (14)
        does not fall on an instruction boundary — the trampoline then
        starts with half an instruction and executes garbage.

   v2 therefore:
     - decodes real instruction boundaries (mini x86-64 length decoder),
     - copies only whole instructions (minimum 5 bytes),
     - relocates every relative operand (RIP-relative disp32, rel32 calls
       and jumps, rel8 short branches) by the trampoline-vs-target delta,
     - patches the target with a 5-byte `E9 rel32` to a near "gateway"
       (absolute jmp to the hook), so we never overwrite more bytes than
       the decoded instructions actually occupy,
     - refuses (skips) any hook whose prologue cannot be decoded, instead
       of crashing the host process.

   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Optional logging hook: the including .cpp may `#define HOOK_LOG(...)`
   before including this header (sandbox_shim.cpp maps it to ShimLog). */
#ifndef HOOK_LOG
#define HOOK_LOG(...) ((void)0)
#endif

/* ─── Constants ──────────────────────────────────────────── */
#define MAX_HOOKS 256
#define HOOK_ALLOC_SIZE 128       /* bytes per hook allocation (trampoline + gateway) */
#define HOOK_GATEWAY_OFF 64       /* gateway sits at alloc + 64 */
#define HOOK_MIN_PATCH 5          /* E9 rel32 at the target */
#define HOOK_MAX_COPY 24          /* max original bytes copied into trampoline */

/* ─── Hook Record ────────────────────────────────────────── */
struct HookRecord {
    BOOL active;
    void* targetAddr;         // Original function address
    void* hookFunc;           // Our replacement function
    void* trampolineAddr;     // Allocation base; calling this calls the original
    void* gatewayAddr;        // Near-target absolute jump to hookFunc
    BYTE originalBytes[HOOK_MAX_COPY]; // Saved original bytes (whole instructions)
    DWORD originalBytesLen;   // How many bytes we overwrote
    char name[64];            // For debugging
};

/* ─── Global Hook Table ──────────────────────────────────── */
static HookRecord g_Hooks[MAX_HOOKS];
static int g_HookCount = 0;
static CRITICAL_SECTION g_HookLock;
static BOOL g_HookLockInit = FALSE;

static void InitHookEngine() {
    if (!g_HookLockInit) {
        InitializeCriticalSection(&g_HookLock);
        g_HookLockInit = TRUE;
        memset(g_Hooks, 0, sizeof(g_Hooks));
    }
}

/* ══════════════════════════════════════════════════════════
   Mini x86-64 instruction decoder
   Only needs to be correct for a few dozen bytes of function
   prologues. Anything unusual (VEX/EVEX, x87, string ops,
   address-size overrides) is rejected so the hook is skipped
   rather than mis-patched.
   ══════════════════════════════════════════════════════════ */

#define MAX_RELOCS 4

struct InsnInfo {
    int len;
    int nRelocs;
    struct { int off; int size; } relocs[MAX_RELOCS];  // relative operands
};

static void AddReloc(InsnInfo* info, int off, int size) {
    if (info->nRelocs < MAX_RELOCS) {
        info->relocs[info->nRelocs].off = off;
        info->relocs[info->nRelocs].size = size;
        info->nRelocs++;
    }
}

/* Parse a ModRM byte (+SIB +displacement). Returns new offset or -1.
   Records a RIP-relative disp32 as a relocation. */
static int DecodeModRM(const BYTE* c, int i, int maxLen, InsnInfo* info) {
    if (i >= maxLen) return -1;
    BYTE m = c[i++];
    int mod = (m >> 6) & 3;
    int rm = m & 7;

    if (mod == 3) return i;  // register direct

    if (rm == 4) {
        // SIB byte
        if (i >= maxLen) return -1;
        BYTE sib = c[i++];
        int base = sib & 7;
        if (mod == 0) {
            if (base == 5) i += 4;       // disp32, no base (absolute)
        } else if (mod == 1) {
            i += 1;
        } else {
            i += 4;
        }
    } else {
        if (mod == 0) {
            if (rm == 5) {
                AddReloc(info, i, 4);    // RIP-relative disp32
                i += 4;
            }
        } else if (mod == 1) {
            i += 1;
        } else {
            i += 4;
        }
    }
    return (i <= maxLen) ? i : -1;
}

/* Decode one instruction. Returns its length, or -1 if unsupported. */
static int DecodeInsn64(const BYTE* c, int maxLen, InsnInfo* info) {
    memset(info, 0, sizeof(*info));
    int i = 0;
    int opsize16 = 0;
    int rexW = 0;

    // Legacy prefixes
    for (;;) {
        if (i >= maxLen) return -1;
        BYTE b = c[i];
        if (b == 0x66) { opsize16 = 1; i++; }
        else if (b == 0x67) { return -1; }   // address-size override: bail
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65) { i++; }
        else break;
        if (i > 5) return -1;
    }

    // REX
    if (i < maxLen && (c[i] & 0xF0) == 0x40) {
        rexW = (c[i] >> 3) & 1;
        i++;
    }

    if (i >= maxLen) return -1;
    BYTE op = c[i++];
    int imm = 0;
    int needModRM = 0;
    int group3 = 0;     // F6/F7: immediate depends on ModRM.reg
    int rel = 0;        // relative operand size (1 or 4)

    if (op == 0x0F) {
        if (i >= maxLen) return -1;
        BYTE o2 = c[i++];
        if (o2 >= 0x80 && o2 <= 0x8F) {
            rel = 4;                                   // jcc rel32
        } else {
            switch (o2) {
            // no operands
            case 0x05: case 0x09: case 0x0B: case 0x30: case 0x31:
            case 0x32: case 0x33: case 0x37: case 0x77: case 0xA2: case 0xAA:
                break;
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF:
                break;                                 // bswap reg
            // ModRM, no immediate
            case 0x01: case 0x02: case 0x03: case 0x0D:
            case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
            case 0x16: case 0x17:
            case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D:
            case 0x1E: case 0x1F:
            case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
            case 0x2E: case 0x2F:
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
            case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
            case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
            case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0x74: case 0x75: case 0x76:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            case 0xA3: case 0xAB: case 0xAF:
            case 0xB0: case 0xB1: case 0xB3: case 0xB6: case 0xB7: case 0xB8:
            case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            case 0xC0: case 0xC1: case 0xC7:
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
            case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            case 0xE7: case 0xEF:
            case 0xF7: case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC:
            case 0xFD: case 0xFE:
                needModRM = 1;
                break;
            // ModRM + imm8
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0xA4: case 0xA5: case 0xAC: case 0xAD:
            case 0xBA:
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                needModRM = 1;
                imm = 1;
                break;
            default:
                return -1;   // includes 0x38/0x3A (3-byte opcodes) etc.
            }
        }
    } else {
        switch (op) {
        // ── ModRM, no immediate ─────────────────────────────
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x63:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D:
        case 0x8E: case 0x8F:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xFE: case 0xFF:
            needModRM = 1;
            break;
        // ── AL/eAX, imm ─────────────────────────────────────
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
            imm = 1;
            break;
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
            imm = opsize16 ? 2 : 4;
            break;
        // ── push/pop reg ────────────────────────────────────
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            break;
        // ── push imm ────────────────────────────────────────
        case 0x68:
            imm = opsize16 ? 2 : 4;
            break;
        case 0x69: needModRM = 1; imm = opsize16 ? 2 : 4; break;
        case 0x6A: imm = 1; break;
        case 0x6B: needModRM = 1; imm = 1; break;
        // ── jcc rel8 ────────────────────────────────────────
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            rel = 1;
            break;
        // ── group 1/2 imm ───────────────────────────────────
        case 0x80: needModRM = 1; imm = 1; break;
        case 0x81: needModRM = 1; imm = opsize16 ? 2 : 4; break;
        case 0x83: needModRM = 1; imm = 1; break;
        // ── misc 1-byte, no operands ────────────────────────
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9B: case 0x9C:
        case 0x9D: case 0x9E: case 0x9F:
        case 0xC3: case 0xC9: case 0xCC:
        case 0xF1: case 0xF4: case 0xF5:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
            break;
        // ── test AL/eAX, imm ────────────────────────────────
        case 0xA8: imm = 1; break;
        case 0xA9: imm = opsize16 ? 2 : 4; break;
        // ── in/out imm8 ─────────────────────────────────────
        case 0xE4: case 0xE5: case 0xE6: case 0xE7: imm = 1; break;
        // ── loop/jrcxz rel8 ─────────────────────────────────
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: rel = 1; break;
        // ── call/jmp rel32 ──────────────────────────────────
        case 0xE8: case 0xE9: rel = 4; break;
        // ── jmp rel8 ────────────────────────────────────────
        case 0xEB: rel = 1; break;
        // ── in/out dx ───────────────────────────────────────
        case 0xEC: case 0xED: case 0xEE: case 0xEF: break;
        // ── mov r8, imm8 ────────────────────────────────────
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            imm = 1;
            break;
        // ── mov r, imm ──────────────────────────────────────
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            imm = rexW ? 8 : (opsize16 ? 2 : 4);
            break;
        // ── shifts/misc ModRM + imm8 ────────────────────────
        case 0xC0: case 0xC1: needModRM = 1; imm = 1; break;
        // ── ret/enter ───────────────────────────────────────
        case 0xC2: imm = 2; break;
        // ── mov r/m, imm ────────────────────────────────────
        case 0xC6: needModRM = 1; imm = 1; break;
        case 0xC7: needModRM = 1; imm = opsize16 ? 2 : 4; break;
        // ── int imm8 ────────────────────────────────────────
        case 0xCD: imm = 1; break;
        // ── group 3 (test/not/neg/mul/...) ──────────────────
        case 0xF6: needModRM = 1; group3 = 1; break;
        case 0xF7: needModRM = 1; group3 = 1; break;
        // ── moffs64 (absolute address) ──────────────────────
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: imm = 8; break;
        default:
            return -1;
        }
    }

    if (needModRM) {
        if (group3) {
            if (i >= maxLen) return -1;
            int reg = (c[i] >> 3) & 7;
            i = DecodeModRM(c, i, maxLen, info);
            if (i < 0) return -1;
            if (reg == 0 || reg == 1) {          // test r/m, imm
                i += (op == 0xF6) ? 1 : (opsize16 ? 2 : 4);
            }
        } else {
            i = DecodeModRM(c, i, maxLen, info);
            if (i < 0) return -1;
        }
    }

    if (rel) {
        AddReloc(info, i, rel);
        i += rel;
    }

    i += imm;
    if (i > maxLen || i > 15) return -1;   // x86-64 max instruction length is 15
    info->len = i;
    return i;
}

/* ══════════════════════════════════════════════════════════
   Trampoline / gateway allocation
   ══════════════════════════════════════════════════════════ */

/* Allocate HOOK_ALLOC_SIZE bytes of RWX memory within +/- ~1.75GB of nearAddr. */
static void* AllocateHookBlock(void* nearAddr) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    ULONGLONG base = (ULONGLONG)nearAddr;
    ULONGLONG gran = (ULONGLONG)si.dwAllocationGranularity;
    ULONGLONG span = 0x70000000ULL;   // 1.75GB: keeps rel32 fixes well in range
    ULONGLONG lo = (base > span) ? (base - span) : 0x10000ULL;
    ULONGLONG hi = base + span;

    // Align start up to allocation granularity
    ULONGLONG start = (base + gran - 1) & ~(gran - 1);

    // Scan upward from the target
    for (ULONGLONG a = start; a < hi; a += gran) {
        void* m = VirtualAlloc((void*)a, HOOK_ALLOC_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (m) return m;
    }
    // Scan downward
    for (ULONGLONG a = (base & ~(gran - 1)); a > lo; a -= gran) {
        void* m = VirtualAlloc((void*)a, HOOK_ALLOC_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (m) return m;
    }
    return NULL;
}

/* Write `FF 25 00 00 00 00 <abs64>` — jmp qword ptr [rip+0] at p. */
static void WriteAbsJmp(BYTE* p, void* dest) {
    p[0] = 0xFF;
    p[1] = 0x25;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    ULONGLONG d = (ULONGLONG)dest;
    memcpy(p + 6, &d, 8);
}

/* ══════════════════════════════════════════════════════════
   Inline Hook Installation
   ══════════════════════════════════════════════════════════ */

/*
   InstallInlineHook: Redirect a function via an inline trampoline.

   targetAddr   - The function to hook (e.g. address of LoadLibraryW)
   hookFunc     - Our replacement function
   ppOriginal   - Receives the trampoline (calling it calls the original)
   name         - Debug name for logging

   Returns: Hook index, or -1 on failure (hook skipped, target untouched).
*/
static int InstallInlineHook(void* targetAddr, void* hookFunc, void** ppOriginal, const char* name) {
    InitHookEngine();
    EnterCriticalSection(&g_HookLock);

    if (g_HookCount >= MAX_HOOKS) {
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }

    // ── 1. Snapshot + decode whole instructions covering >= HOOK_MIN_PATCH bytes
    BYTE code[32];
    memcpy(code, targetAddr, sizeof(code));

    struct { int off; int len; } insns[8];
    struct { int off; int size; } relocs[8];
    int nInsns = 0, nRelocs = 0;
    int copyLen = 0;

    while (copyLen < HOOK_MIN_PATCH) {
        if (nInsns >= 8 || copyLen > HOOK_MAX_COPY) {
            HOOK_LOG("Hook %s: SKIPPED (prologue too complex)", name);
            LeaveCriticalSection(&g_HookLock);
            return -1;
        }
        InsnInfo ii;
        int len = DecodeInsn64(code + copyLen, (int)sizeof(code) - copyLen, &ii);
        if (len <= 0) {
            HOOK_LOG("Hook %s: SKIPPED (undecodable prologue at +%d)", name, copyLen);
            LeaveCriticalSection(&g_HookLock);
            return -1;
        }
        insns[nInsns].off = copyLen;
        insns[nInsns].len = len;
        nInsns++;
        for (int r = 0; r < ii.nRelocs; r++) {
            if (nRelocs < 8) {
                relocs[nRelocs].off = copyLen + ii.relocs[r].off;
                relocs[nRelocs].size = ii.relocs[r].size;
                nRelocs++;
            }
        }
        copyLen += len;
    }

    if (copyLen > HOOK_MAX_COPY) {
        HOOK_LOG("Hook %s: SKIPPED (prologue %d bytes > %d)", name, copyLen, HOOK_MAX_COPY);
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }

    // ── 2. Allocate trampoline + gateway near the target
    BYTE* block = (BYTE*)AllocateHookBlock(targetAddr);
    if (!block) {
        HOOK_LOG("Hook %s: SKIPPED (no near memory)", name);
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }
    BYTE* tramp = block;
    BYTE* gate = block + HOOK_GATEWAY_OFF;

    // ── 3. Relocate: every relative operand shifts by (tramp - target)
    INT64 delta = (INT64)((BYTE*)tramp - (BYTE*)targetAddr);
    if (delta > 0x70000000LL || delta < -0x70000000LL) {
        VirtualFree(block, 0, MEM_RELEASE);
        HOOK_LOG("Hook %s: SKIPPED (trampoline out of range)", name);
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }

    memcpy(tramp, code, copyLen);
    for (int r = 0; r < nRelocs; r++) {
        int off = relocs[r].off;
        INT64 fixed;
        if (relocs[r].size == 1) {
            fixed = (INT64)(*(INT8*)(code + off)) - delta;
            if (fixed < -128 || fixed > 127) {
                VirtualFree(block, 0, MEM_RELEASE);
                HOOK_LOG("Hook %s: SKIPPED (rel8 relocation out of range)", name);
                LeaveCriticalSection(&g_HookLock);
                return -1;
            }
            *(INT8*)(tramp + off) = (INT8)fixed;
        } else {
            fixed = (INT64)(*(INT32*)(code + off)) - delta;
            if (fixed < -0x80000000LL || fixed > 0x7FFFFFFFLL) {
                VirtualFree(block, 0, MEM_RELEASE);
                HOOK_LOG("Hook %s: SKIPPED (rel32 relocation out of range)", name);
                LeaveCriticalSection(&g_HookLock);
                return -1;
            }
            *(INT32*)(tramp + off) = (INT32)fixed;
        }
    }

    // ── 4. Trampoline tail: absolute jump back to target + copyLen
    WriteAbsJmp(tramp + copyLen, (BYTE*)targetAddr + copyLen);

    // ── 5. Gateway: absolute jump to our hook function
    WriteAbsJmp(gate, hookFunc);

    // ── 6. Patch the target: E9 rel32 -> gateway, NOP the rest
    INT64 relToGate = (INT64)(gate - ((BYTE*)targetAddr + HOOK_MIN_PATCH));
    if (relToGate < -0x80000000LL || relToGate > 0x7FFFFFFFLL) {
        VirtualFree(block, 0, MEM_RELEASE);
        HOOK_LOG("Hook %s: SKIPPED (gateway out of range)", name);
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }

    DWORD oldProtect;
    if (!VirtualProtect(targetAddr, copyLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(block, 0, MEM_RELEASE);
        HOOK_LOG("Hook %s: SKIPPED (VirtualProtect failed)", name);
        LeaveCriticalSection(&g_HookLock);
        return -1;
    }

    BYTE* t = (BYTE*)targetAddr;
    t[0] = 0xE9;
    *(INT32*)(t + 1) = (INT32)relToGate;
    for (int i = HOOK_MIN_PATCH; i < copyLen; i++) t[i] = 0x90;

    // Publish the trampoline BEFORE restoring page protection: when the
    // target being hooked is VirtualProtect itself, the restore call below
    // re-enters through the fresh hook and needs a working original.
    if (ppOriginal) *ppOriginal = tramp;

    VirtualProtect(targetAddr, copyLen, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetAddr, copyLen);

    // ── 7. Record + publish original pointer
    int idx = g_HookCount;
    HookRecord* hook = &g_Hooks[idx];
    hook->targetAddr = targetAddr;
    hook->hookFunc = hookFunc;
    hook->trampolineAddr = tramp;
    hook->gatewayAddr = gate;
    memcpy(hook->originalBytes, code, copyLen);
    hook->originalBytesLen = (DWORD)copyLen;
    strncpy_s(hook->name, name, _TRUNCATE);
    hook->active = TRUE;
    g_HookCount++;

    *ppOriginal = tramp;

    FlushInstructionCache(GetCurrentProcess(), tramp, copyLen + 14);
    FlushInstructionCache(GetCurrentProcess(), gate, 14);

    HOOK_LOG("Hook %s: patched %d bytes at %p (tramp %p, gate %p)",
             name, copyLen, targetAddr, tramp, gate);

    LeaveCriticalSection(&g_HookLock);
    return idx;
}

/* ─── IAT Hook Installation ──────────────────────────────── */

/*
   InstallIATHook: Redirect a function via Import Address Table patching.

   moduleName   - The DLL whose imports to patch (e.g. "kernel32.dll")
   funcName     - The function name to intercept (e.g. "LoadLibraryW")
   hookFunc     - Our replacement function
   ppOriginal   - Receives the original function pointer

   Returns: TRUE on success
*/
static BOOL InstallIATHook(const char* moduleName, const char* funcName,
                           void* hookFunc, void** ppOriginal) {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (!hExe) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD importVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importVA) return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dos + importVA);

    while (importDesc->Name) {
        char* modName = (char*)((BYTE*)dos + importDesc->Name);

        if (_stricmp(modName, moduleName) == 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)dos + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = importDesc->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)((BYTE*)dos + importDesc->OriginalFirstThunk)
                : NULL;

            while (thunk->u1.Function) {
                BOOL matchByName = FALSE;

                if (origThunk && !(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName =
                        (PIMAGE_IMPORT_BY_NAME)((BYTE*)dos + origThunk->u1.AddressOfData);
                    if (strcmp((const char*)importByName->Name, funcName) == 0) {
                        matchByName = TRUE;
                    }
                }

                if (matchByName) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*),
                        PAGE_READWRITE, &oldProtect);

                    *ppOriginal = (void*)thunk->u1.Function;
                    thunk->u1.Function = (ULONGLONG)hookFunc;

                    VirtualProtect(&thunk->u1.Function, sizeof(void*),
                        oldProtect, &oldProtect);

                    return TRUE;
                }

                thunk++;
                if (origThunk) origThunk++;
            }
        }
        importDesc++;
    }

    return FALSE;
}

/* ─── Uninstall Hook ─────────────────────────────────────── */

static void UninstallInlineHook(int hookIdx) {
    if (hookIdx < 0 || hookIdx >= g_HookCount) return;

    HookRecord* hook = &g_Hooks[hookIdx];
    if (!hook->active) return;

    EnterCriticalSection(&g_HookLock);

    // Restore original bytes
    DWORD oldProtect;
    VirtualProtect(hook->targetAddr, hook->originalBytesLen,
        PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hook->targetAddr, hook->originalBytes, hook->originalBytesLen);
    VirtualProtect(hook->targetAddr, hook->originalBytesLen,
        oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), hook->targetAddr, hook->originalBytesLen);

    // Free trampoline + gateway block
    if (hook->trampolineAddr) {
        VirtualFree(hook->trampolineAddr, 0, MEM_RELEASE);
        hook->trampolineAddr = NULL;
        hook->gatewayAddr = NULL;
    }

    hook->active = FALSE;

    LeaveCriticalSection(&g_HookLock);
}
