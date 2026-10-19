/*
   Ghost Sandbox — Trace Event Format
   Binary format for communication between shim DLL and controller.
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma pack(push, 1)

/* ─── Event Types ────────────────────────────────────────── */
enum TraceEventType : BYTE {
    EVT_TRACE        = 1,   // A hooked function was called
    EVT_SPOOF        = 2,   // Hardware query answered from profile
    EVT_DLL_LOAD     = 3,   // New DLL loaded
    EVT_DLL_UNLOAD   = 4,   // DLL unloaded
    EVT_EXCEPTION    = 5,   // Exception in target
    EVT_PATCH_ACK    = 6,   // Memory patch applied
    EVT_CPUID_TRAP   = 7,   // CPUID instruction intercepted
    EVT_VTABLE_MOD   = 8,   // VTable was modified
    EVT_CONNECTED    = 9,   // Shim connected
    EVT_MEMORY_DUMP  = 10,  // Memory dump response
    EVT_REGISTERS    = 11,  // Register snapshot
    EVT_MODULE_LIST  = 12,  // Full module list
    EVT_DRM          = 13,  // DRM / anti-tamper detection event
    EVT_POLICY_HIT   = 14,  // Import/export policy hit (observe/block)
    EVT_MALWARE_OP   = 15,  // Malware-analysis behaviour (observe/shadow/block/approval)
};

/* ─── Command Types ──────────────────────────────────────── */
enum CommandType : BYTE {
    CMD_PATCH          = 1,   // Write raw bytes at address
    CMD_PATCH_JMP      = 2,   // Replace conditional with JMP
    CMD_PATCH_NOP      = 3,   // NOP out N bytes
    CMD_RULE_ADD       = 4,   // Add return value override
    CMD_RULE_DEL       = 5,   // Remove a rule
    CMD_VTABLE_WATCH   = 6,   // Watch a vtable
    CMD_TRACE_FILTER   = 7,   // Filter by module
    CMD_TRACE_PAUSE    = 8,   // Pause tracing
    CMD_TRACE_RESUME   = 9,   // Resume tracing
    CMD_DUMP           = 10,  // Dump memory
    CMD_DISASM         = 11,  // Disassemble
    CMD_GET_REGS       = 12,  // Get registers
    CMD_LIST_MODULES   = 13,  // List modules
    CMD_PROFILE_RELOAD = 14,  // Reload profile
    CMD_DRM_MODE       = 15,  // Enable/disable DRM / anti-tamper watch mode
    CMD_POLICY         = 16,  // Replace the import/export policy (live update)
    CMD_MALWARE_VERDICT= 17,  // Verdict for a pending malware-analysis operation
};

/* ─── Event Header (all events start with this) ──────────── */
struct TraceEventHeader {
    TraceEventType type;
    DWORD size;             // Total size including header
    LARGE_INTEGER timestamp;
    DWORD threadId;
};

/* ─── Trace Event: Function Call ─────────────────────────── */
struct TraceEventTrace {
    TraceEventHeader header;
    char functionName[128];
    char moduleName[256];
    char params[512];
    char returnValue[128];
    ULONGLONG durationUs;
    BYTE spoofed;
    // Register state at entry point
    ULONGLONG rax, rcx, rdx, r8, r9, rsp, rip;
};

/* ─── Trace Event: DLL Load ──────────────────────────────── */
struct TraceEventDllLoad {
    TraceEventHeader header;
    char dllName[260];
    ULONGLONG baseAddress;
    ULONGLONG size;
};

/* ─── Trace Event: DLL Unload ────────────────────────────── */
struct TraceEventDllUnload {
    TraceEventHeader header;
    char dllName[260];
};

/* ─── Trace Event: Exception ─────────────────────────────── */
struct TraceEventException {
    TraceEventHeader header;
    DWORD exceptionCode;
    ULONGLONG address;
};

/* ─── Trace Event: Patch Acknowledgement ─────────────────── */
struct TraceEventPatchAck {
    TraceEventHeader header;
    ULONGLONG address;
    BYTE success;
};

/* ─── Trace Event: CPUID Trap ────────────────────────────── */
struct TraceEventCpuidTrap {
    TraceEventHeader header;
    DWORD leaf;
    DWORD subleaf;
    DWORD eax, ebx, ecx, edx;
};

/* ─── Trace Event: VTable Modification ───────────────────── */
struct TraceEventVTableMod {
    TraceEventHeader header;
    ULONGLONG address;
    DWORD index;
    ULONGLONG oldValue;
    ULONGLONG newValue;
};

/* ─── Trace Event: Memory Dump ───────────────────────────── */
struct TraceEventMemoryDump {
    TraceEventHeader header;
    ULONGLONG address;
    DWORD length;
    BYTE data[4096];     // Max dump size
};

/* ─── Trace Event: Registers ─────────────────────────────── */
struct TraceEventRegisters {
    TraceEventHeader header;
    ULONGLONG rax, rbx, rcx, rdx;
    ULONGLONG rsi, rdi, rsp, rbp;
    ULONGLONG r8, r9, r10, r11;
    ULONGLONG r12, r13, r14, r15;
    ULONGLONG rip, rflags;
};

/* ─── Trace Event: DRM / Anti-Tamper ─────────────────────── */
/* Categories (EVT_DRM.category) */
enum DrmCategory : DWORD {
    DRM_CAT_INTEGRITY    = 1,   // signature/checksum/trust verification
    DRM_CAT_DEBUGGER     = 2,   // debugger detection
    DRM_CAT_TIMING       = 3,   // timing-based anti-debug probes
    DRM_CAT_MODULE_SCAN  = 4,   // loaded-module / process scanning
    DRM_CAT_DEVICE       = 5,   // CD/DVD/device integrity probes
    DRM_CAT_CRYPTO       = 6,   // crypto verification
    DRM_CAT_ENVIRONMENT  = 7,   // VM/hardware identity probing
    DRM_CAT_MEMORY       = 8,   // memory protection / self-modification
};
/* Severity (EVT_DRM.severity) */
enum DrmSeverity : DWORD {
    DRM_SEV_INFO = 1,
    DRM_SEV_WARN = 2,
    DRM_SEV_CRIT = 3,
};
/* Verdict: did the call reveal the target to the checker? */
enum DrmVerdict : DWORD {
    DRM_VERDICT_BENIGN   = 0,   // result matches the "clean" expectation
    DRM_VERDICT_DETECTED = 1,   // result exposes tampering/debugging
    DRM_VERDICT_UNKNOWN  = 2,   // cannot classify (informational)
};

struct TraceEventDrm {
    TraceEventHeader header;
    DWORD category;             // DrmCategory
    DWORD severity;             // DrmSeverity
    DWORD verdict;              // DrmVerdict
    char api[64];               // e.g. "IsDebuggerPresent"
    char apiModule[64];         // module implementing the API
    char callerModule[64];      // module that CALLED the API (attribution)
    ULONGLONG callerRva;        // caller return address - module base
    ULONGLONG retValue;         // raw return value / status code
    char expected[128];         // what a benign environment would produce
    char returned[128];         // what the target actually received
    char detail[256];           // decoded arguments / extra context
};

/* ─── Command Header ─────────────────────────────────────── */
struct CommandHeader {
    CommandType type;
    DWORD size;             // Total size including header
};

/* ─── Command: Patch Bytes ───────────────────────────────── */
struct CommandPatch {
    CommandHeader header;
    ULONGLONG address;
    DWORD length;
    BYTE data[256];
};

/* ─── Command: Patch JMP ─────────────────────────────────── */
struct CommandPatchJmp {
    CommandHeader header;
    ULONGLONG address;
};

/* ─── Command: Patch NOP ─────────────────────────────────── */
struct CommandPatchNop {
    CommandHeader header;
    ULONGLONG address;
    DWORD length;
};

/* ─── Command: Rule Add ──────────────────────────────────── */
struct CommandRuleAdd {
    CommandHeader header;
    char hookName[128];
    char action[64];
    char value[128];
};

/* ─── Command: Rule Delete ───────────────────────────────── */
struct CommandRuleDel {
    CommandHeader header;
    char hookName[128];
};

/* ─── Command: Dump Memory ───────────────────────────────── */
struct CommandDump {
    CommandHeader header;
    ULONGLONG address;
    DWORD length;
};

/* ─── Command: Get Registers ─────────────────────────────── */
struct CommandGetRegs {
    CommandHeader header;
    DWORD threadId;             // 0 = pick the process's main thread
};

/* ─── Event: Module list (EVT_MODULE_LIST) ───────────────── */
/* header.size = sizeof(TraceEventHeader) + 4 + count * sizeof(ModuleWireEntry) */
struct ModuleWireEntry {
    char name[260];             // full path when available
    ULONGLONG baseAddress;
    ULONGLONG size;
    ULONGLONG entryPoint;
    DWORD numExports;
    DWORD numImports;
};

/* ─── Import / Export Policy (sandbox service) ───────────── */
/* What a policy entry targets. */
enum PolicyKind : DWORD {
    POLICY_KIND_IMPORT = 1,   // IAT entry of a module (block/observe the call)
    POLICY_KIND_EXPORT = 2,   // export of a loaded module (inline hook)
};
/* What happens when the targeted function is called. */
enum PolicyAction : DWORD {
    POLICY_ACTION_OBSERVE = 1,  // emit event, pass the call through unchanged
    POLICY_ACTION_BLOCK   = 2,  // emit event, return `blockValue` without calling
};

struct TraceEventPolicyHit {
    TraceEventHeader header;
    DWORD kind;                 // PolicyKind
    DWORD action;               // PolicyAction
    DWORD blocked;              // 1 when the call did not reach the original
    ULONGLONG retValue;         // value handed back to the caller
    char module[64];            // module owning the targeted function
    char function[96];          // function / export name
    char callerModule[64];      // module that called it (attribution)
    ULONGLONG callerRva;        // caller return address - module base
    char detail[128];           // decoded context (real target, rule id, ...)
};

/* ─── Malware Analysis: Behaviour Event (EVT_MALWARE_OP) ── */
/* What class of host state a sample tried to touch. */
enum MalwareCategory : DWORD {
    MW_CAT_FILE     = 1,   // file system
    MW_CAT_REGISTRY = 2,   // registry / settings
    MW_CAT_PROCESS  = 3,   // process execution / shell
    MW_CAT_NETWORK  = 4,   // TCP/HTTP/URL traffic
    MW_CAT_DNS      = 5,   // name resolution
    MW_CAT_SYSTEM   = 6,   // other system state
};
/* What the sample tried to do. */
enum MalwareAction : DWORD {
    MW_ACT_READ     = 1,
    MW_ACT_WRITE    = 2,
    MW_ACT_DELETE   = 3,
    MW_ACT_MOVE     = 4,
    MW_ACT_COPY     = 5,
    MW_ACT_EXEC     = 6,
    MW_ACT_CONNECT  = 7,
    MW_ACT_DNS      = 8,
    MW_ACT_DOWNLOAD = 9,
    MW_ACT_KEY      = 10,  // registry key create/delete/open
    MW_ACT_VALUE    = 11,  // registry value set/delete/query
};
/* Outcome of an operation. */
enum MalwareVerdict : DWORD {
    MW_VERDICT_OBSERVED = 0,  // logged only (real call, no enforcement)
    MW_VERDICT_ALLOWED  = 1,  // user/auto approved — real call performed
    MW_VERDICT_SHADOWED = 2,  // redirected into the shadow store (fake success)
    MW_VERDICT_FAKED    = 3,  // fake success returned, no real side effect
    MW_VERDICT_BLOCKED  = 4,  // call refused (error code returned)
    MW_VERDICT_TIMEOUT  = 5,  // approval timed out — treated as denied
};
/* Mode flags (delivered to the shim through the GHOST_MW_ENV_* vars). */
enum MalwareFlag : DWORD {
    MWF_ACTIVE          = 0x0001, // malware analysis mode is on
    MWF_APPROVAL        = 0x0002, // ask the controller before privileged ops
    MWF_ALLOW_FILE      = 0x0004, // auto-approve file writes
    MWF_ALLOW_REGISTRY  = 0x0008, // auto-approve registry writes
    MWF_ALLOW_EXEC      = 0x0010, // auto-approve process execution
    MWF_ALLOW_NETWORK   = 0x0020, // allow real network traffic
    MWF_SHADOW_FILES    = 0x0040, // denied file writes go to the shadow store
    MWF_FAKE_NETWORK    = 0x0080, // connect()/DNS fake success (sinkhole)
    MWF_OBSERVE_READS   = 0x0100, // log reads of sensitive paths
    MWF_UNTRUSTED_TOKEN = 0x0200, // informational: low-IL token in use
};

struct TraceEventMalwareOp {
    TraceEventHeader header;
    DWORD opId;                 // unique id (echoed back in CMD_MALWARE_VERDICT)
    DWORD category;             // MalwareCategory
    DWORD action;               // MalwareAction
    DWORD flags;                // MalwareFlag snapshot
    DWORD verdict;              // MalwareVerdict
    DWORD pending;              // 1 = awaiting a controller verdict
    ULONGLONG callerRva;        // caller return address - module base
    char callerModule[64];      // module that called the API
    char api[64];               // API / hook that saw the operation
    char target[512];           // path / key / command line / URL (UTF-8)
    char detail[256];           // extra context (shadow path, value data, ...)
};

/* Env vars the controller sets for confined processes.
   (Env is used instead of shared memory so the config survives even when the
   target runs under a low-integrity token that cannot map the policy shmem.) */
#define GHOST_MW_ENV_ACTIVE  "GHOST_MALWARE"      /* "1" = mode on            */
#define GHOST_MW_ENV_FLAGS   "GHOST_MW_FLAGS"     /* decimal u32 (MalwareFlag)*/
#define GHOST_MW_ENV_SHADOW  "GHOST_MW_SHADOW"    /* shadow store root dir    */
#define GHOST_MW_ENV_TIMEOUT "GHOST_MW_TIMEOUT"   /* approval timeout, ms     */
#define GHOST_MW_ENV_LEVEL   "GHOST_MW_LEVEL"     /* guest|untrusted|none     */

/* One policy rule as shipped over the wire / in shared memory. */
struct PolicyWireEntry {
    DWORD kind;                 // PolicyKind
    DWORD action;               // PolicyAction
    ULONGLONG blockValue;       // return value used by POLICY_ACTION_BLOCK
    char module[64];            // target module name (case-insensitive; "*" = any)
    char function[96];          // function name (exact; "*" = any)
};

#define GHOST_POLICY_MAX_ENTRIES 64

struct CommandPolicy {
    CommandHeader header;       // size = 9 + 176*count
    DWORD count;
    PolicyWireEntry entries[1]; // count entries follow
};

/* ─── Command: Malware verdict (CMD_MALWARE_VERDICT) ─────── */
struct CommandMalwareVerdict {
    CommandHeader header;       // size = 13
    DWORD opId;                 // TraceEventMalwareOp.opId of the pending op
    DWORD allow;                // 1 = run the real operation, 0 = deny
};

/* ─── Shared Memory: Startup Policy ──────────────────────── */
/* The controller writes this mapping before launching so the policy is in
   force before the target's entry point runs (no race with DllMain). */
#define GHOST_SANDBOX_POLICY_NAME "GhostSandboxPolicy"
#define GHOST_POLICY_MAGIC 0x4C505347u   /* 'GSPL' */
#define GHOST_POLICY_SHM_VERSION 1

struct SharedPolicy {
    DWORD magic;                // GHOST_POLICY_MAGIC
    DWORD version;              // GHOST_POLICY_SHM_VERSION
    DWORD count;                // active entries (0..GHOST_POLICY_MAX_ENTRIES)
    DWORD reserved;
    PolicyWireEntry entries[GHOST_POLICY_MAX_ENTRIES];
};

#pragma pack(pop)

/* ─── Shared Memory Profile Name ─────────────────────────── */
#define GHOST_SANDBOX_PIPE_NAME "\\\\.\\pipe\\GhostSandbox"
#define GHOST_SANDBOX_SHMEM_NAME "GhostSandboxProfile"
#define GHOST_SANDBOX_LOG_FILE "ghost_sandbox_shim.log"
