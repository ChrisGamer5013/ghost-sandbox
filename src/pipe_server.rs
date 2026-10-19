/*
   Ghost Sandbox — Named Pipe Server
   Controller side of the \\.\pipe\GhostSandbox control channel.

   Wire format matches the injected shim (shim/trace_format.h, #pragma pack(1)):

     Event frames (shim -> controller) arrive as a raw byte stream and are
     re-assembled by the server using the frame header:
       TraceEventHeader { u8 type; u32 size; i64 qpc_timestamp; u32 thread_id; }
     where `size` is the TOTAL frame size (header included).

     Command frames (controller -> shim):
       CommandHeader { u8 type; u32 size; } + payload.
     The shim's receive thread processes one WriteFile per ReadFile, so
     commands are written one at a time.
*/

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe,
};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::{
    GetNamedPipeClientProcessId, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use winapi::um::winnt::HANDLE;

/// Pipe name shared with the shim (GHOST_SANDBOX_PIPE_NAME in trace_format.h).
const PIPE_NAME: &str = "\\\\.\\pipe\\GhostSandbox";

/// TraceEventHeader size (packed): u8 + u32 + i64 + u32 = 17 bytes.
const HEADER_SIZE: usize = 17;
/// Upper bound for a single frame (largest is EVT_MEMORY_DUMP at ~4 KB).
const MAX_FRAME: usize = 1 << 20;
/// ERROR_PIPE_CONNECTED: ConnectNamedPipe reports this when the client
/// connected between CreateNamedPipe and ConnectNamedPipe.
const ERROR_PIPE_CONNECTED_CODE: DWORD = 535;

// ─── Event type ids (trace_format.h) ────────────────────────
const EVT_TRACE: u8 = 1;
const EVT_SPOOF: u8 = 2;
const EVT_DLL_LOAD: u8 = 3;
const EVT_DLL_UNLOAD: u8 = 4;
const EVT_EXCEPTION: u8 = 5;
const EVT_PATCH_ACK: u8 = 6;
const EVT_CPUID_TRAP: u8 = 7;
const EVT_VTABLE_MOD: u8 = 8;
const EVT_CONNECTED: u8 = 9;
const EVT_MEMORY_DUMP: u8 = 10;
const EVT_REGISTERS: u8 = 11;
const EVT_MODULE_LIST: u8 = 12;
const EVT_DRM: u8 = 13;
const EVT_POLICY_HIT: u8 = 14;
const EVT_MALWARE_OP: u8 = 15;

// ─── Command type ids (trace_format.h) ──────────────────────
const CMD_PATCH: u8 = 1;
const CMD_PATCH_JMP: u8 = 2;
const CMD_PATCH_NOP: u8 = 3;
const CMD_RULE_ADD: u8 = 4;
const CMD_RULE_DEL: u8 = 5;
const CMD_VTABLE_WATCH: u8 = 6;
const CMD_TRACE_PAUSE: u8 = 8;
const CMD_TRACE_RESUME: u8 = 9;
const CMD_DUMP: u8 = 10;
// Protocol command id from shim/trace_format.h; kept for completeness.
#[allow(dead_code)]
const CMD_DISASM: u8 = 11;
const CMD_GET_REGS: u8 = 12;
const CMD_LIST_MODULES: u8 = 13;
const CMD_PROFILE_RELOAD: u8 = 14;
const CMD_DRM_MODE: u8 = 15;
const CMD_POLICY: u8 = 16;
const CMD_MALWARE_VERDICT: u8 = 17;

// ─── Packed struct sizes (trace_format.h) ───────────────────
const SZ_TRACE: usize = HEADER_SIZE + 128 + 256 + 512 + 128 + 8 + 1 + 7 * 8; // 1106
const SZ_DLL_LOAD: usize = HEADER_SIZE + 260 + 8 + 8; // 293
const SZ_DLL_UNLOAD: usize = HEADER_SIZE + 260; // 277
const SZ_EXCEPTION: usize = HEADER_SIZE + 4 + 8; // 29
const SZ_PATCH_ACK: usize = HEADER_SIZE + 8 + 1; // 26
const SZ_CPUID_TRAP: usize = HEADER_SIZE + 6 * 4; // 41
const SZ_VTABLE_MOD: usize = HEADER_SIZE + 8 + 4 + 8 + 8; // 45
const SZ_REGISTERS: usize = HEADER_SIZE + 18 * 8; // 161
const SZ_MODULE_ENTRY: usize = 260 + 8 + 8 + 8 + 4 + 4; // 292
/// EVT_DRM: header + 3*u32 + 3*64-char + 2*u64 + 2*128-char + 256-char fields.
const SZ_DRM: usize = HEADER_SIZE + 3 * 4 + 3 * 64 + 2 * 8 + 2 * 128 + 256; // 749
/// EVT_POLICY_HIT: header + 3*u32 + u64 + 64 + 96 + 64 + u64 + 128.
const SZ_POLICY_HIT: usize = HEADER_SIZE + 3 * 4 + 8 + 64 + 96 + 64 + 8 + 128; // 397
/// EVT_MALWARE_OP: header + 6*u32 + u64 + 64 + 64 + 512 + 256.
const SZ_MALWARE_OP: usize = HEADER_SIZE + 6 * 4 + 8 + 64 + 64 + 512 + 256; // 945

/// Messages received from the shim DLL.
#[derive(Debug, Clone)]
pub enum PipeMessage {
    /// A hooked function was called
    Trace {
        thread_id: u32,
        function: String,
        module: String,
        params: String,
        return_value: String,
        duration_us: u64,
        spoofed: bool,
    },
    /// A new DLL was loaded
    DllLoad { name: String, base_address: u64, size: u64 },
    /// A DLL was unloaded
    DllUnload { name: String },
    /// An exception occurred
    Exception { code: u32, address: u64 },
    /// Memory patch was applied
    PatchAck { address: u64, success: bool },
    /// CPUID was intercepted
    CpuidTrap { leaf: u32, subleaf: u32, eax: u32, ebx: u32, ecx: u32, edx: u32 },
    /// VTable was modified
    VTableMod { address: u64, index: u32, old_value: u64, new_value: u64 },
    /// A shim connected to the pipe (pid resolved by the server)
    Connected { pid: u32, name: String },
    /// Shim disconnected
    Disconnected,
    /// Memory dump response
    MemoryDump { address: u64, data: Vec<u8> },
    /// Register snapshot
    Registers {
        rax: u64, rbx: u64, rcx: u64, rdx: u64,
        rsi: u64, rdi: u64, rsp: u64, rbp: u64,
        r8: u64, r9: u64, r10: u64, r11: u64,
        r12: u64, r13: u64, r14: u64, r15: u64,
        rip: u64, rflags: u64,
    },
    /// Module list response
    ModuleList { modules: Vec<ModuleEntry> },
    /// DRM / anti-tamper detection event (EVT_DRM)
    Drm {
        category: u32,
        severity: u32,
        verdict: u32,
        api: String,
        api_module: String,
        caller_module: String,
        caller_rva: u64,
        ret_value: u64,
        expected: String,
        returned: String,
        detail: String,
    },
    /// Import/export policy hit (EVT_POLICY_HIT). `kind`/`action` are 0 for
    /// engine status messages ("PolicyApply" / "PolicyClear").
    PolicyHit {
        kind: u32,
        action: u32,
        blocked: bool,
        ret_value: u64,
        module: String,
        function: String,
        caller_module: String,
        caller_rva: u64,
        detail: String,
    },
    /// Malware-analysis behaviour event (EVT_MALWARE_OP).
    MalwareOp {
        op_id: u32,
        category: u32,
        action: u32,
        flags: u32,
        verdict: u32,
        pending: bool,
        caller_module: String,
        caller_rva: u64,
        api: String,
        target: String,
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
    pub entry_point: u64,
    pub num_exports: u32,
    pub num_imports: u32,
}

/// Commands sent to the shim DLL.
#[derive(Debug, Clone)]
pub enum PipeCommand {
    /// Write raw bytes at address
    Patch { address: u64, bytes: Vec<u8> },
    /// Replace conditional jump with unconditional JMP
    PatchJmp { address: u64 },
    /// NOP out N bytes at address
    PatchNop { address: u64, length: u32 },
    /// Add a return value override rule
    RuleAdd { hook_name: String, action: String, value: String },
    /// Remove a rule
    RuleDel { hook_name: String },
    /// Watch a vtable address (not yet handled by the shim)
    #[allow(dead_code)]
    VTableWatch { address: u64 },
    /// Pause/resume tracing
    TracePause,
    TraceResume,
    /// Dump memory at address
    Dump { address: u64, length: u32 },
    /// Disassemble at address (not yet handled by the shim)
    #[allow(dead_code)]
    Disasm { address: u64, length: u32 },
    /// Get registers for thread (not yet handled by the shim)
    #[allow(dead_code)]
    GetRegisters { thread_id: u32 },
    /// List all loaded modules (not yet handled by the shim)
    #[allow(dead_code)]
    ListModules,
    /// Reload the hardware profile from shared memory
    ProfileReload,
    /// Enable/disable the shim's DRM / anti-tamper watch mode
    DrmMode { enabled: bool },
    /// Replace the sandbox import/export policy (live update)
    Policy { entries: Vec<crate::policy::WireEntry> },
    /// Verdict for a pending malware-analysis operation (CMD_MALWARE_VERDICT)
    MalwareVerdict { op_id: u32, allow: bool },
}

/// The pipe server manages the named pipe connection. It is created with
/// `PipeServer::new()`, which immediately spawns the listener thread.
pub struct PipeServer {
    /// Events streamed in from the shim (consumed by the app's pump thread).
    pub rx: Receiver<PipeMessage>,
    cmd_tx: Sender<PipeCommand>,
    _handle: Option<std::thread::JoinHandle<()>>,
}

impl PipeServer {
    /// Create the pipe server and start listening in a background thread.
    pub fn new() -> Self {
        Self::new_with_name(PIPE_NAME)
    }

    /// Create the pipe server bound to a specific pipe name (tests use a
    /// private name so they never collide with a live app instance).
    fn new_with_name(pipe_name: &str) -> Self {
        let (msg_tx, msg_rx) = bounded::<PipeMessage>(10000);
        let (cmd_tx, cmd_rx) = bounded::<PipeCommand>(1000);

        let name = pipe_name.to_string();
        let handle = std::thread::Builder::new()
            .name("ghost-pipe-listener".into())
            .spawn(move || Self::listener_loop(msg_tx, cmd_rx, name))
            .ok();

        Self {
            rx: msg_rx,
            cmd_tx,
            _handle: handle,
        }
    }

    /// Send a command to the connected shim.
    pub fn send_command(&self, cmd: PipeCommand) -> Result<(), String> {
        self.cmd_tx
            .send(cmd)
            .map_err(|e| format!("Failed to send command: {}", e))
    }

    // ─── Listener ───────────────────────────────────────────

    fn listener_loop(msg_tx: Sender<PipeMessage>, cmd_rx: Receiver<PipeCommand>, pipe_name_str: String) {
        let pipe_name: Vec<u16> = pipe_name_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // The pipe must be reachable even from a confined target that runs
        // under a low-integrity token (malware analysis "untrusted" mode).
        // The DACL grants the object owner (OW), SYSTEM and Administrators
        // full access; the low mandatory label lifts the no-read-up block so
        // same-user low-IL subjects may connect. Other users stay locked out.
        let sddl: Vec<u16> = "D:(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;LW)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: winapi::um::winnt::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut sa: winapi::um::minwinbase::SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
        let mut sa_ptr: *mut winapi::um::minwinbase::SECURITY_ATTRIBUTES = std::ptr::null_mut();
        unsafe {
            if winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1, // SDDL_REVISION_1
                &mut sd,
                std::ptr::null_mut(),
            ) != 0
            {
                sa.nLength = std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32;
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = 0;
                sa_ptr = &mut sa;
            } else {
                tracing::warn!(
                    "pipe SDDL rejected ({}) — falling back to default security",
                    std::io::Error::last_os_error()
                );
            }
        }

        loop {
            let h = unsafe {
                CreateNamedPipeW(
                    pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    sa_ptr,
                )
            };

            if h == INVALID_HANDLE_VALUE {
                tracing::error!(
                    "CreateNamedPipe failed: {}",
                    std::io::Error::last_os_error()
                );
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }

            // Wait for a client (the shim, connecting from DllMain).
            let connected = unsafe {
                if ConnectNamedPipe(h, std::ptr::null_mut()) != 0 {
                    true
                } else {
                    GetLastError() == ERROR_PIPE_CONNECTED_CODE
                }
            };

            if !connected {
                unsafe { CloseHandle(h); }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // Identify the client process.
            let mut pid: DWORD = 0;
            unsafe { GetNamedPipeClientProcessId(h, &mut pid); }
            let name = process_name(pid);
            tracing::info!("Shim connected (PID {} — {})", pid, name);

            if msg_tx.send(PipeMessage::Connected { pid, name }).is_err() {
                return; // UI gone
            }

            // Writer thread pumps queued commands into this connection.
            let stop = Arc::new(AtomicBool::new(false));
            let writer = {
                let stop = stop.clone();
                let cmd_rx = cmd_rx.clone();
                let pipe = h as usize;
                std::thread::Builder::new()
                    .name("ghost-pipe-writer".into())
                    .spawn(move || Self::writer_loop(pipe as HANDLE, cmd_rx, stop))
                    .ok()
            };

            // Blocking read loop — runs until the pipe breaks (target exits).
            Self::read_loop(h, &msg_tx);

            if let Some(w) = writer {
                stop.store(true, Ordering::SeqCst);
                let _ = w.join();
            }

            tracing::info!("Shim disconnected");
            if msg_tx.send(PipeMessage::Disconnected).is_err() {
                return;
            }

            unsafe {
                FlushFileBuffers(h);
                DisconnectNamedPipe(h);
                CloseHandle(h);
            }
        }
    }

    // ─── Reader ─────────────────────────────────────────────

    fn read_loop(h: HANDLE, msg_tx: &Sender<PipeMessage>) {
        let mut buf = vec![0u8; 65536];
        let mut pending: Vec<u8> = Vec::with_capacity(65536);

        loop {
            // IMPORTANT: do not park a blocking ReadFile on an idle pipe.
            // A pending synchronous read blocks writes on the same handle, so
            // the command writer would deadlock inside WriteFile. Poll with
            // PeekNamedPipe and issue ReadFile only when bytes are queued —
            // it then returns immediately.
            let mut avail: DWORD = 0;
            let peeked = unsafe {
                PeekNamedPipe(
                    h,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                )
            };
            if peeked == 0 {
                break; // pipe closed / target exited
            }
            if avail == 0 {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }

            let mut read: DWORD = 0;
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr() as LPVOID,
                    buf.len() as DWORD,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };

            if ok == 0 || read == 0 {
                break; // broken pipe / target exited
            }

            pending.extend_from_slice(&buf[..read as usize]);

            // Re-assemble frames using header.size (total frame size).
            loop {
                if pending.len() < HEADER_SIZE {
                    break;
                }
                let size = rd_u32(&pending, 1) as usize;
                if size < HEADER_SIZE || size > MAX_FRAME {
                    tracing::warn!("Pipe frame desync (size={}), dropping buffer", size);
                    pending.clear();
                    break;
                }
                if pending.len() < size {
                    break;
                }
                let frame: Vec<u8> = pending.drain(..size).collect();
                if let Some(msg) = parse_event(&frame) {
                    if msg_tx.send(msg).is_err() {
                        return; // UI gone
                    }
                }
            }

            // Safety valve against pathological desync growth.
            if pending.len() > (4 << 20) {
                pending.clear();
            }
        }
    }

    // ─── Writer ─────────────────────────────────────────────

    fn writer_loop(h: HANDLE, cmd_rx: Receiver<PipeCommand>, stop: Arc<AtomicBool>) {
        while !stop.load(Ordering::SeqCst) {
            match cmd_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(cmd) => {
                    let bytes = match serialize_command(&cmd) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!("{}", e);
                            continue;
                        }
                    };
                    let mut written: DWORD = 0;
                    let ok = unsafe {
                        WriteFile(
                            h,
                            bytes.as_ptr() as LPVOID,
                            bytes.len() as DWORD,
                            &mut written,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 {
                        tracing::warn!(
                            "Command write failed: {}",
                            std::io::Error::last_os_error()
                        );
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
}

// ─── Event parsing ──────────────────────────────────────────

fn parse_event(f: &[u8]) -> Option<PipeMessage> {
    if f.len() < HEADER_SIZE {
        return None;
    }
    let ty = f[0];
    let tid = rd_u32(f, 13);

    match ty {
        EVT_TRACE | EVT_SPOOF => {
            if f.len() < SZ_TRACE {
                return None;
            }
            Some(PipeMessage::Trace {
                thread_id: tid,
                function: rd_str(f, 17, 128),
                module: rd_str(f, 145, 256),
                params: rd_str(f, 401, 512),
                return_value: rd_str(f, 913, 128),
                duration_us: rd_u64(f, 1041),
                spoofed: ty == EVT_SPOOF || f[1049] != 0,
            })
        }
        EVT_DLL_LOAD => {
            if f.len() < SZ_DLL_LOAD {
                return None;
            }
            Some(PipeMessage::DllLoad {
                name: rd_str(f, 17, 260),
                base_address: rd_u64(f, 277),
                size: rd_u64(f, 285),
            })
        }
        EVT_DLL_UNLOAD => {
            if f.len() < SZ_DLL_UNLOAD {
                return None;
            }
            Some(PipeMessage::DllUnload {
                name: rd_str(f, 17, 260),
            })
        }
        EVT_EXCEPTION => {
            if f.len() < SZ_EXCEPTION {
                return None;
            }
            Some(PipeMessage::Exception {
                code: rd_u32(f, 17),
                address: rd_u64(f, 21),
            })
        }
        EVT_PATCH_ACK => {
            if f.len() < SZ_PATCH_ACK {
                return None;
            }
            Some(PipeMessage::PatchAck {
                address: rd_u64(f, 17),
                success: f[25] != 0,
            })
        }
        EVT_CPUID_TRAP => {
            if f.len() < SZ_CPUID_TRAP {
                return None;
            }
            Some(PipeMessage::CpuidTrap {
                leaf: rd_u32(f, 17),
                subleaf: rd_u32(f, 21),
                eax: rd_u32(f, 25),
                ebx: rd_u32(f, 29),
                ecx: rd_u32(f, 33),
                edx: rd_u32(f, 37),
            })
        }
        EVT_CONNECTED => None, // the server already reported the connection
        EVT_VTABLE_MOD => {
            if f.len() < SZ_VTABLE_MOD {
                return None;
            }
            Some(PipeMessage::VTableMod {
                address: rd_u64(f, 17),
                index: rd_u32(f, 25),
                old_value: rd_u64(f, 29),
                new_value: rd_u64(f, 37),
            })
        }
        EVT_MEMORY_DUMP => {
            if f.len() < HEADER_SIZE + 12 {
                return None;
            }
            let address = rd_u64(f, 17);
            let len = (rd_u32(f, 25) as usize).min(4096);
            let avail = f.len().saturating_sub(29).min(len);
            Some(PipeMessage::MemoryDump {
                address,
                data: f[29..29 + avail].to_vec(),
            })
        }
        EVT_REGISTERS => {
            if f.len() < SZ_REGISTERS {
                return None;
            }
            let mut v = [0u64; 18];
            for (i, slot) in v.iter_mut().enumerate() {
                *slot = rd_u64(f, 17 + i * 8);
            }
            Some(PipeMessage::Registers {
                rax: v[0], rbx: v[1], rcx: v[2], rdx: v[3],
                rsi: v[4], rdi: v[5], rsp: v[6], rbp: v[7],
                r8: v[8], r9: v[9], r10: v[10], r11: v[11],
                r12: v[12], r13: v[13], r14: v[14], r15: v[15],
                rip: v[16], rflags: v[17],
            })
        }
        EVT_MODULE_LIST => {
            if f.len() < HEADER_SIZE + 4 {
                return None;
            }
            let count = rd_u32(f, 17) as usize;
            let needed = HEADER_SIZE + 4 + count * SZ_MODULE_ENTRY;
            if f.len() < needed {
                return None;
            }
            let mut modules = Vec::with_capacity(count);
            let mut off = HEADER_SIZE + 4;
            for _ in 0..count {
                modules.push(ModuleEntry {
                    name: rd_str(f, off, 260),
                    base_address: rd_u64(f, off + 260),
                    size: rd_u64(f, off + 268),
                    entry_point: rd_u64(f, off + 276),
                    num_exports: rd_u32(f, off + 284),
                    num_imports: rd_u32(f, off + 288),
                });
                off += SZ_MODULE_ENTRY;
            }
            Some(PipeMessage::ModuleList { modules })
        }
        EVT_DRM => {
            if f.len() < SZ_DRM {
                return None;
            }
            Some(PipeMessage::Drm {
                category: rd_u32(f, 17),
                severity: rd_u32(f, 21),
                verdict: rd_u32(f, 25),
                api: rd_str(f, 29, 64),
                api_module: rd_str(f, 93, 64),
                caller_module: rd_str(f, 157, 64),
                caller_rva: rd_u64(f, 221),
                ret_value: rd_u64(f, 229),
                expected: rd_str(f, 237, 128),
                returned: rd_str(f, 365, 128),
                detail: rd_str(f, 493, 256),
            })
        }
        EVT_POLICY_HIT => {
            if f.len() < SZ_POLICY_HIT {
                return None;
            }
            Some(PipeMessage::PolicyHit {
                kind: rd_u32(f, 17),
                action: rd_u32(f, 21),
                blocked: rd_u32(f, 25) != 0,
                ret_value: rd_u64(f, 29),
                module: rd_str(f, 37, 64),
                function: rd_str(f, 101, 96),
                caller_module: rd_str(f, 197, 64),
                caller_rva: rd_u64(f, 261),
                detail: rd_str(f, 269, 128),
            })
        }
        EVT_MALWARE_OP => {
            if f.len() < SZ_MALWARE_OP {
                return None;
            }
            Some(PipeMessage::MalwareOp {
                op_id: rd_u32(f, 17),
                category: rd_u32(f, 21),
                action: rd_u32(f, 25),
                flags: rd_u32(f, 29),
                verdict: rd_u32(f, 33),
                pending: rd_u32(f, 37) != 0,
                caller_rva: rd_u64(f, 41),
                caller_module: rd_str(f, 49, 64),
                api: rd_str(f, 113, 64),
                target: rd_str(f, 177, 512),
                detail: rd_str(f, 689, 256),
            })
        }
        _ => None,
    }
}

// ─── Command serialization ──────────────────────────────────

fn serialize_command(cmd: &PipeCommand) -> Result<Vec<u8>, String> {
    let mut b: Vec<u8> = Vec::with_capacity(352);

    match cmd {
        PipeCommand::Patch { address, bytes } => {
            if bytes.len() > 256 {
                return Err(format!(
                    "Patch too large: {} bytes (shim limit is 256)",
                    bytes.len()
                ));
            }
            push_u8(&mut b, CMD_PATCH);
            push_u32(&mut b, (5 + 8 + 4 + 256) as u32);
            push_u64(&mut b, *address);
            push_u32(&mut b, bytes.len() as u32);
            b.extend_from_slice(bytes);
            b.resize(5 + 8 + 4 + 256, 0);
        }
        PipeCommand::PatchJmp { address } => {
            push_u8(&mut b, CMD_PATCH_JMP);
            push_u32(&mut b, (5 + 8) as u32);
            push_u64(&mut b, *address);
        }
        PipeCommand::PatchNop { address, length } => {
            push_u8(&mut b, CMD_PATCH_NOP);
            push_u32(&mut b, (5 + 8 + 4) as u32);
            push_u64(&mut b, *address);
            push_u32(&mut b, *length);
        }
        PipeCommand::RuleAdd { hook_name, action, value } => {
            push_u8(&mut b, CMD_RULE_ADD);
            push_u32(&mut b, (5 + 128 + 64 + 128) as u32);
            push_fixed(&mut b, hook_name, 128);
            push_fixed(&mut b, action, 64);
            push_fixed(&mut b, value, 128);
        }
        PipeCommand::RuleDel { hook_name } => {
            push_u8(&mut b, CMD_RULE_DEL);
            push_u32(&mut b, (5 + 128) as u32);
            push_fixed(&mut b, hook_name, 128);
        }
        PipeCommand::VTableWatch { address } => {
            push_u8(&mut b, CMD_VTABLE_WATCH);
            push_u32(&mut b, (5 + 8) as u32);
            push_u64(&mut b, *address);
        }
        PipeCommand::TracePause => {
            push_u8(&mut b, CMD_TRACE_PAUSE);
            push_u32(&mut b, 5);
        }
        PipeCommand::TraceResume => {
            push_u8(&mut b, CMD_TRACE_RESUME);
            push_u32(&mut b, 5);
        }
        PipeCommand::Dump { address, length } => {
            push_u8(&mut b, CMD_DUMP);
            push_u32(&mut b, (5 + 8 + 4) as u32);
            push_u64(&mut b, *address);
            push_u32(&mut b, *length);
        }
        PipeCommand::GetRegisters { thread_id } => {
            push_u8(&mut b, CMD_GET_REGS);
            push_u32(&mut b, (5 + 4) as u32);
            push_u32(&mut b, *thread_id);
        }
        PipeCommand::ListModules => {
            push_u8(&mut b, CMD_LIST_MODULES);
            push_u32(&mut b, 5);
        }
        PipeCommand::ProfileReload => {
            push_u8(&mut b, CMD_PROFILE_RELOAD);
            push_u32(&mut b, 5);
        }
        PipeCommand::DrmMode { enabled } => {
            // CommandHeader(5) + u8 enabled = 6 bytes total.
            push_u8(&mut b, CMD_DRM_MODE);
            push_u32(&mut b, 6);
            push_u8(&mut b, if *enabled { 1 } else { 0 });
        }
        PipeCommand::Policy { entries } => {
            if entries.len() > crate::policy::MAX_ENTRIES {
                return Err(format!(
                    "Policy has {} entries (shim max {})",
                    entries.len(),
                    crate::policy::MAX_ENTRIES
                ));
            }
            // CommandHeader(5) + u32 count + 176 bytes per entry.
            let size = 5 + 4 + crate::policy::WIRE_ENTRY_SIZE * entries.len();
            push_u8(&mut b, CMD_POLICY);
            push_u32(&mut b, size as u32);
            push_u32(&mut b, entries.len() as u32);
            for e in entries {
                e.encode(&mut b);
            }
            debug_assert_eq!(b.len(), size);
        }
        PipeCommand::MalwareVerdict { op_id, allow } => {
            // CommandHeader(5) + u32 opId + u32 allow = 13 bytes.
            push_u8(&mut b, CMD_MALWARE_VERDICT);
            push_u32(&mut b, 13);
            push_u32(&mut b, *op_id);
            push_u32(&mut b, if *allow { 1 } else { 0 });
        }
        PipeCommand::Disasm { .. } => {
            return Err("Disassembly is served client-side (Memory Editor decodes dumps)".to_string());
        }
    }

    Ok(b)
}

// ─── Helpers ────────────────────────────────────────────────

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Read a fixed-size, NUL-terminated C string field.
fn rd_str(b: &[u8], off: usize, max: usize) -> String {
    let field = &b[off..off + max];
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn push_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// Push a NUL-padded fixed-size char array (truncating if necessary).
fn push_fixed(b: &mut Vec<u8>, s: &str, len: usize) {
    let mut tmp = s.as_bytes().to_vec();
    tmp.truncate(len.saturating_sub(1));
    tmp.resize(len, 0);
    b.extend_from_slice(&tmp);
}

/// Resolve a process id to its executable name.
fn process_name(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return String::new();
        }
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let mut name = String::new();
        if Process32First(snap, &mut pe) != 0 {
            loop {
                if pe.th32ProcessID == pid {
                    let bytes: Vec<u8> = pe
                        .szExeFile
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect();
                    name = String::from_utf8_lossy(&bytes).into_owned();
                    break;
                }
                if Process32Next(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        name
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};

    /// Private pipe name so the test never collides with a live app instance.
    const TEST_PIPE: &str = "\\\\.\\pipe\\GhostSandboxTest";

    /// Connect to the test pipe as a client (mimics the shim's CreateFileA).
    fn connect_client() -> HANDLE {
        let name: Vec<u8> = TEST_PIPE
            .as_bytes()
            .iter()
            .cloned()
            .chain(std::iter::once(0))
            .collect();
        let start = Instant::now();
        loop {
            let h = unsafe {
                CreateFileA(
                    name.as_ptr() as *const i8,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                return h;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "test pipe never appeared"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn client_write_all(h: HANDLE, mut data: &[u8]) {
        while !data.is_empty() {
            let mut written: DWORD = 0;
            let ok = unsafe {
                WriteFile(
                    h,
                    data.as_ptr() as LPVOID,
                    data.len() as DWORD,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "client WriteFile failed");
            data = &data[written as usize..];
        }
    }

    fn client_read_exact(h: HANDLE, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut have = 0usize;
        while have < len {
            let mut got: DWORD = 0;
            let ok = unsafe {
                ReadFile(
                    h,
                    out[have..].as_mut_ptr() as LPVOID,
                    (len - have) as DWORD,
                    &mut got,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "client ReadFile failed");
            have += got as usize;
        }
        out
    }

    /// Build a packed TRACE event frame (matches TraceEventTrace in trace_format.h).
    fn trace_frame(function: &str) -> Vec<u8> {
        let mut f = vec![0u8; SZ_TRACE];
        f[0] = EVT_TRACE;
        f[1..5].copy_from_slice(&(SZ_TRACE as u32).to_le_bytes());
        f[5..13].copy_from_slice(&1234i64.to_le_bytes());
        f[13..17].copy_from_slice(&42u32.to_le_bytes());
        let name = function.as_bytes();
        f[17..17 + name.len()].copy_from_slice(name);
        f[145..145 + 8].copy_from_slice(b"test.dll");
        f[1041..1049].copy_from_slice(&7u64.to_le_bytes());
        f
    }

    /// Build a packed EVT_DRM frame (matches TraceEventDrm in trace_format.h).
    fn drm_frame() -> Vec<u8> {
        let mut f = vec![0u8; SZ_DRM];
        f[0] = EVT_DRM;
        f[1..5].copy_from_slice(&(SZ_DRM as u32).to_le_bytes());
        f[5..13].copy_from_slice(&1234i64.to_le_bytes());
        f[13..17].copy_from_slice(&7u32.to_le_bytes());
        f[17..21].copy_from_slice(&2u32.to_le_bytes()); // category: debugger
        f[21..25].copy_from_slice(&3u32.to_le_bytes()); // severity: critical
        f[25..29].copy_from_slice(&1u32.to_le_bytes()); // verdict: detected
        f[29..29 + 17].copy_from_slice(b"IsDebuggerPresent");
        f[93..93 + 12].copy_from_slice(b"kernel32.dll");
        f[157..157 + 8].copy_from_slice(b"game.exe");
        f[221..229].copy_from_slice(&0x1A2Bu64.to_le_bytes());
        f[229..237].copy_from_slice(&1u64.to_le_bytes());
        f[237..237 + 28].copy_from_slice(b"FALSE (no debugger attached)");
        f[365..365 + 4].copy_from_slice(b"TRUE");
        f[493..493 + 6].copy_from_slice(b"detail");
        f
    }

    /// Full duplex round-trip over a real named pipe:
    /// client → server event parsing, then server → client command writing.
    /// The command write used to deadlock behind a parked blocking ReadFile
    /// on the same synchronous handle; this test guards that regression.
    #[test]
    fn duplex_event_and_command_roundtrip() {
        let server = PipeServer::new_with_name(TEST_PIPE);

        // Connect like the shim does; give the server a moment to spin up its
        // reader/writer loops for this connection.
        let h = connect_client();
        std::thread::sleep(Duration::from_millis(300));

        // 1) Client → server: a TRACE event must surface on the message channel.
        client_write_all(h, &trace_frame("LoadLibraryW"));

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut trace_fn = None;
        while Instant::now() < deadline {
            match server.rx.try_recv() {
                Ok(PipeMessage::Trace { function, .. }) => {
                    trace_fn = Some(function);
                    break;
                }
                Ok(_) => continue, // e.g. Connected
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        assert_eq!(trace_fn.as_deref(), Some("LoadLibraryW"), "TRACE event lost");

        // 2) Client → server: an EVT_DRM event must parse with all fields.
        client_write_all(h, &drm_frame());

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut drm = None;
        while Instant::now() < deadline {
            match server.rx.try_recv() {
                Ok(PipeMessage::Drm { category, severity, verdict, api, api_module, caller_module, caller_rva, ret_value, expected, returned, detail }) => {
                    drm = Some((category, severity, verdict, api, api_module, caller_module, caller_rva, ret_value, expected, returned, detail));
                    break;
                }
                Ok(_) => continue,
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let (category, severity, verdict, api, api_module, caller, rva, ret_value, expected, returned, detail) =
            drm.expect("DRM event lost");
        assert_eq!(category, 2);
        assert_eq!(severity, 3);
        assert_eq!(verdict, 1);
        assert_eq!(api, "IsDebuggerPresent");
        assert_eq!(api_module, "kernel32.dll");
        assert_eq!(caller, "game.exe");
        assert_eq!(rva, 0x1A2B);
        assert_eq!(ret_value, 1);
        assert_eq!(expected, "FALSE (no debugger attached)");
        assert_eq!(returned, "TRUE");
        assert_eq!(detail, "detail");

        // 3) Server → client: send_command must reach the wire (client reads
        //    the exact serialized bytes).
        server
            .send_command(PipeCommand::TracePause)
            .expect("send_command failed");
        let cmd = client_read_exact(h, 5);
        assert_eq!(cmd, vec![CMD_TRACE_PAUSE, 5, 0, 0, 0]);

        // 4) A second round-trip keeps working (no lingering blockage).
        server
            .send_command(PipeCommand::TraceResume)
            .expect("send_command failed");
        let cmd = client_read_exact(h, 5);
        assert_eq!(cmd, vec![CMD_TRACE_RESUME, 5, 0, 0, 0]);

        // 5) DRM mode toggle serializes as [15][size=6][enabled].
        server
            .send_command(PipeCommand::DrmMode { enabled: true })
            .expect("send_command failed");
        let cmd = client_read_exact(h, 6);
        assert_eq!(cmd, vec![CMD_DRM_MODE, 6, 0, 0, 0, 1]);

        server
            .send_command(PipeCommand::DrmMode { enabled: false })
            .expect("send_command failed");
        let cmd = client_read_exact(h, 6);
        assert_eq!(cmd, vec![CMD_DRM_MODE, 6, 0, 0, 0, 0]);

        // 6) Client → server: an EVT_POLICY_HIT event must parse fully.
        client_write_all(h, &policy_hit_frame());

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut hit = None;
        while Instant::now() < deadline {
            match server.rx.try_recv() {
                Ok(PipeMessage::PolicyHit { kind, action, blocked, ret_value, module, function, caller_module, caller_rva, detail }) => {
                    hit = Some((kind, action, blocked, ret_value, module, function, caller_module, caller_rva, detail));
                    break;
                }
                Ok(_) => continue,
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let (kind, action, blocked, ret_value, module, function, caller, rva, detail) =
            hit.expect("policy hit event lost");
        assert_eq!(kind, 1); // import
        assert_eq!(action, 2); // block
        assert!(blocked);
        assert_eq!(ret_value, 0x1);
        assert_eq!(module, "kernel32.dll");
        assert_eq!(function, "IsDebuggerPresent");
        assert_eq!(caller, "game.exe");
        assert_eq!(rva, 0x1BEEF);
        assert_eq!(detail, "call blocked, returned 0x1 (rule 1)");

        // 7) CMD_POLICY serialization: [16][size][count][entries...].
        let entries = vec![
            crate::policy::WireEntry {
                kind: crate::policy::KIND_IMPORT,
                action: crate::policy::ACTION_BLOCK,
                block_value: 1,
                module: "kernel32.dll".into(),
                function: "IsDebuggerPresent".into(),
            },
            crate::policy::WireEntry {
                kind: crate::policy::KIND_EXPORT,
                action: crate::policy::ACTION_OBSERVE,
                block_value: 0,
                module: "sample.dll".into(),
                function: "ExportedFn".into(),
            },
        ];
        server
            .send_command(PipeCommand::Policy { entries: entries.clone() })
            .expect("send_command failed");
        let expected_size = 9 + 176 * 2;
        let cmd = client_read_exact(h, expected_size);
        assert_eq!(cmd[0], CMD_POLICY);
        assert_eq!(u32::from_le_bytes([cmd[1], cmd[2], cmd[3], cmd[4]]) as usize, expected_size);
        assert_eq!(u32::from_le_bytes([cmd[5], cmd[6], cmd[7], cmd[8]]), 2);
        // first entry header: kind=1 action=2 value=1
        assert_eq!(&cmd[9..13], &1u32.to_le_bytes());
        assert_eq!(&cmd[13..17], &2u32.to_le_bytes());
        assert_eq!(&cmd[17..25], &1u64.to_le_bytes());
        // function name lives at entry base + 80 (4+4+8 value + 64 module)
        assert_eq!(&cmd[9 + 80..9 + 80 + 17], b"IsDebuggerPresent");
        // second entry is an export observe
        let e2 = 9 + 176;
        assert_eq!(&cmd[e2..e2 + 4], &2u32.to_le_bytes());
        assert_eq!(&cmd[e2 + 4..e2 + 8], &1u32.to_le_bytes());
        assert_eq!(&cmd[e2 + 80..e2 + 80 + 10], b"ExportedFn");

        // 8) Empty policy (clear) is a valid frame too.
        server
            .send_command(PipeCommand::Policy { entries: vec![] })
            .expect("send_command failed");
        let cmd = client_read_exact(h, 9);
        assert_eq!(cmd, vec![CMD_POLICY, 9, 0, 0, 0, 0, 0, 0, 0]);

        unsafe { CloseHandle(h) };
    }

    /// Build a packed EVT_POLICY_HIT frame (matches TraceEventPolicyHit).
    fn policy_hit_frame() -> Vec<u8> {
        let mut f = vec![0u8; SZ_POLICY_HIT];
        f[0] = EVT_POLICY_HIT;
        f[1..5].copy_from_slice(&(SZ_POLICY_HIT as u32).to_le_bytes());
        f[5..13].copy_from_slice(&1234i64.to_le_bytes());
        f[13..17].copy_from_slice(&9u32.to_le_bytes());
        f[17..21].copy_from_slice(&1u32.to_le_bytes()); // kind: import
        f[21..25].copy_from_slice(&2u32.to_le_bytes()); // action: block
        f[25..29].copy_from_slice(&1u32.to_le_bytes()); // blocked
        f[29..37].copy_from_slice(&1u64.to_le_bytes()); // ret value
        f[37..37 + 12].copy_from_slice(b"kernel32.dll");
        f[101..101 + 17].copy_from_slice(b"IsDebuggerPresent");
        f[197..197 + 8].copy_from_slice(b"game.exe");
        f[261..269].copy_from_slice(&0x1BEEFu64.to_le_bytes());
        let detail = b"call blocked, returned 0x1 (rule 1)";
        f[269..269 + detail.len()].copy_from_slice(detail);
        f
    }
}
