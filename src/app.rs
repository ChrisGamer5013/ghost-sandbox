/*
   Ghost Sandbox — Application Shell
   Main egui App struct with sidebar navigation and view routing.
*/

use eframe::egui;
use std::sync::{Arc, Mutex};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

use crate::pipe_server::{PipeCommand, PipeServer};
use crate::profile::HardwareProfile;
use crate::views;

// ─── Accent Colors ──────────────────────────────────────────
pub const CYAN: egui::Color32 = egui::Color32::from_rgb(0x00, 0xd4, 0xff);
pub const RED_ORANGE: egui::Color32 = egui::Color32::from_rgb(0xe9, 0x45, 0x60);
pub const GREEN: egui::Color32 = egui::Color32::from_rgb(0x53, 0xd7, 0x69);
pub const YELLOW: egui::Color32 = egui::Color32::from_rgb(0xf3, 0x9c, 0x12);
pub const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(0x11, 0x18, 0x27);
pub const CARD_BG: egui::Color32 = egui::Color32::from_rgb(0x16, 0x21, 0x3e);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(0x1e, 0x29, 0x3b);
pub const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(0x94, 0xa3, 0xb8);
pub const TEXT_BRIGHT: egui::Color32 = egui::Color32::from_rgb(0xe2, 0xe8, 0xf0);

// ─── View Enum ──────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    TraceViewer,
    DrmMonitor,
    Sandbox,
    Malware,
    Integrations,
    HardwareProfile,
    MemoryEditor,
    Modules,
    Rules,
}

impl View {
    pub fn label(&self) -> &str {
        match self {
            View::Dashboard => "Dashboard",
            View::TraceViewer => "Trace Viewer",
            View::DrmMonitor => "Anti-Tamper",
            View::Sandbox => "Sandbox",
            View::Malware => "Malware Analysis",
            View::Integrations => "Integrations",
            View::HardwareProfile => "Hardware Profile",
            View::MemoryEditor => "Memory Editor",
            View::Modules => "Modules",
            View::Rules => "Rules",
        }
    }
}

/// Every navigable view in sidebar order.
pub const VIEW_ORDER: [View; 10] = [
    View::Dashboard,
    View::TraceViewer,
    View::DrmMonitor,
    View::Sandbox,
    View::Malware,
    View::Integrations,
    View::HardwareProfile,
    View::MemoryEditor,
    View::Modules,
    View::Rules,
];

// ─── Trace Event ────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize)]
pub struct TraceEvent {
    pub timestamp: String,
    pub thread_id: u32,
    pub function: String,
    pub module: String,
    pub params: String,
    pub return_value: String,
    pub duration_us: u64,
    pub spoofed: bool,
}

// ─── Module Info ────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
    pub entry_point: u64,
    pub num_exports: u32,
    pub num_imports: u32,
    pub signed: bool,
    /// Full path when the shim reported one (used for external-tool handoff).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

// ─── DRM / Anti-Tamper Event ────────────────────────────────
/// One intercepted integrity/verification/anti-debug probe reported by the
/// shim's DRM watch mode (mirrors TraceEventDrm in trace_format.h).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DrmEvent {
    /// Arrival time (HH:MM:SS.mmm).
    pub timestamp: String,
    /// DrmCategory (1 = integrity ... 8 = memory).
    pub category: u32,
    /// DrmSeverity (1 info, 2 warn, 3 critical).
    pub severity: u32,
    /// DrmVerdict (0 benign, 1 detected, 2 unknown).
    pub verdict: u32,
    pub api: String,
    pub api_module: String,
    /// Module that CALLED the API (attribution) + offset from its base.
    pub caller_module: String,
    pub caller_rva: u64,
    /// Raw return value / status code.
    pub ret_value: u64,
    /// What a benign (uninstrumented) environment would have returned.
    pub expected: String,
    /// What the caller actually received.
    pub returned: String,
    pub detail: String,
}

/// Human-readable DRM category names (mirror DrmCategory in trace_format.h).
pub fn drm_category_name(c: u32) -> &'static str {
    match c {
        1 => "Integrity",
        2 => "Debugger",
        3 => "Timing",
        4 => "Module Scan",
        5 => "Device",
        6 => "Crypto",
        7 => "Environment",
        8 => "Memory",
        _ => "Other",
    }
}

pub fn drm_severity_name(s: u32) -> &'static str {
    match s {
        1 => "Info",
        2 => "Warn",
        3 => "Critical",
        _ => "?",
    }
}

pub fn drm_verdict_name(v: u32) -> &'static str {
    match v {
        0 => "Benign",
        1 => "DETECTED",
        2 => "Unknown",
        _ => "?",
    }
}

// ─── Import / Export Policy Hit ─────────────────────────────
/// One import/export policy hit reported by the shim's policy engine
/// (mirrors TraceEventPolicyHit in trace_format.h). kind 0 = engine status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyHitEvent {
    pub timestamp: String,
    /// 0 = engine message, 1 = import, 2 = export.
    pub kind: u32,
    /// 0 = engine message, 1 = observe, 2 = block.
    pub action: u32,
    pub blocked: bool,
    pub ret_value: u64,
    pub module: String,
    pub function: String,
    pub caller_module: String,
    pub caller_rva: u64,
    pub detail: String,
}

pub fn policy_kind_name(k: u32) -> &'static str {
    match k {
        0 => "Engine",
        1 => "Import",
        2 => "Export",
        _ => "?",
    }
}

pub fn policy_action_name(a: u32) -> &'static str {
    match a {
        0 => "status",
        1 => "observe",
        2 => "block",
        _ => "?",
    }
}

// ─── Malware Analysis Operation ─────────────────────────────
/// One host-state change a sample attempted, as mediated by the shim's
/// malware guard (mirrors TraceEventMalwareOp in trace_format.h).
#[derive(Debug, Clone)]
pub struct MalwareOpEvent {
    pub timestamp: String,
    /// Unique operation id (pending + final records share one id).
    pub op_id: u32,
    /// MalwareCategory (1 file, 2 registry, 3 process, 4 network, 5 dns, 6 system).
    pub category: u32,
    /// MalwareAction (1 read ... 11 value).
    pub action: u32,
    /// MalwareFlag snapshot reported by the shim.
    pub flags: u32,
    /// MalwareVerdict (0 observed, 1 allowed, 2 shadowed, 3 faked, 4 blocked, 5 timeout).
    pub verdict: u32,
    /// True while the operation waits for a user verdict.
    pub pending: bool,
    pub caller_module: String,
    pub caller_rva: u64,
    pub api: String,
    pub target: String,
    pub detail: String,
}

/// Reports are read by humans first: category/action/verdict serialise to
/// their names, with the raw ids alongside for machines.
impl serde::Serialize for MalwareOpEvent {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("malware_op", 15)?;
        st.serialize_field("timestamp", &self.timestamp)?;
        st.serialize_field("op_id", &self.op_id)?;
        st.serialize_field("category", mw_category_name(self.category))?;
        st.serialize_field("category_id", &self.category)?;
        st.serialize_field("action", mw_action_name(self.action))?;
        st.serialize_field("action_id", &self.action)?;
        st.serialize_field("flags", &self.flags)?;
        st.serialize_field("verdict", mw_verdict_name(self.verdict))?;
        st.serialize_field("verdict_id", &self.verdict)?;
        st.serialize_field("pending", &self.pending)?;
        st.serialize_field("caller_module", &self.caller_module)?;
        st.serialize_field("caller_rva", &self.caller_rva)?;
        st.serialize_field("api", &self.api)?;
        st.serialize_field("target", &self.target)?;
        st.serialize_field("detail", &self.detail)?;
        st.end()
    }
}

pub fn mw_category_name(c: u32) -> &'static str {
    match c {
        1 => "File",
        2 => "Registry",
        3 => "Process",
        4 => "Network",
        5 => "DNS",
        6 => "System",
        _ => "?",
    }
}

pub fn mw_action_name(a: u32) -> &'static str {
    match a {
        1 => "read",
        2 => "write",
        3 => "delete",
        4 => "move",
        5 => "copy",
        6 => "execute",
        7 => "connect",
        8 => "dns",
        9 => "download",
        10 => "key",
        11 => "value",
        _ => "?",
    }
}

pub fn mw_verdict_name(v: u32) -> &'static str {
    match v {
        0 => "Observed",
        1 => "Allowed",
        2 => "Shadowed",
        3 => "Fake success",
        4 => "Blocked",
        5 => "Timeout",
        _ => "?",
    }
}

/// MalwareFlag bits (mirror MalwareFlag in trace_format.h).
pub mod mw_flags {
    pub const ACTIVE: u32 = 0x0001;
    pub const APPROVAL: u32 = 0x0002;
    pub const ALLOW_FILE: u32 = 0x0004;
    pub const ALLOW_REGISTRY: u32 = 0x0008;
    pub const ALLOW_EXEC: u32 = 0x0010;
    pub const ALLOW_NETWORK: u32 = 0x0020;
    pub const SHADOW_FILES: u32 = 0x0040;
    pub const FAKE_NETWORK: u32 = 0x0080;
    pub const OBSERVE_READS: u32 = 0x0100;
    pub const UNTRUSTED_TOKEN: u32 = 0x0200;
}

/// Hex/decimal helper shared by the malware views.
pub fn parse_u64_auto(s: &str) -> Option<u64> {
    let t = s.trim();
    let t2 = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t2, 16)
        .or_else(|_| t.parse::<u64>())
        .ok()
}

// ─── Rule ───────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: usize,
    pub hook_name: String,
    pub action: RuleAction,
    pub value: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Trace,
    OverrideReturn,
    ModifyParam,
    ForcePath,
    NopInstruction,
}

impl RuleAction {
    pub fn label(&self) -> &str {
        match self {
            RuleAction::Trace => "Trace Only",
            RuleAction::OverrideReturn => "Override Return",
            RuleAction::ModifyParam => "Modify Parameter",
            RuleAction::ForcePath => "Force Path",
            RuleAction::NopInstruction => "NOP Instruction",
        }
    }

    /// Action string used on the wire / in preset TOML files.
    pub fn wire_name(&self) -> &str {
        match self {
            RuleAction::Trace => "trace",
            RuleAction::OverrideReturn => "override_return",
            RuleAction::ModifyParam => "modify_param",
            RuleAction::ForcePath => "force_path",
            RuleAction::NopInstruction => "nop",
        }
    }

    /// Parse an action string from a preset file.
    pub fn from_wire(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "override_return"=> RuleAction::OverrideReturn,
            "modify_param"=> RuleAction::ModifyParam,
            "force_path"=> RuleAction::ForcePath,
            "nop"| "nop_instruction"=> RuleAction::NopInstruction,
            _ => RuleAction::Trace,
        }
    }
}

// ─── Register State ─────────────────────────────────────────
#[derive(Debug, Clone, Default)]
pub struct RegisterState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// ─── Shared Application State ───────────────────────────────
pub struct AppState {
    // Connection
    pub connected: bool,
    pub target_name: String,
    pub target_pid: u32,
    
    // Statistics
    pub total_api_calls: u64,
    pub total_spoofed: u64,
    pub active_hooks: u32,
    pub memory_patches: u32,
    pub api_calls_per_sec: VecDeque<f64>,
    
    // Trace events
    pub trace_events: VecDeque<TraceEvent>,
    pub max_trace_events: usize,
    
    // DRM / anti-tamper events
    pub drm_events: VecDeque<DrmEvent>,
    pub max_drm_events: usize,
    pub drm_total: u64,
    pub drm_detections: u64,
    /// Mirrors the shim's DRM watch mode (toggled via PipeCommand::DrmMode).
    pub drm_enabled: bool,
    /// Last high-severity finding (status-bar alert).
    pub drm_last_alert: Option<String>,
    
    // Modules
    pub modules: Vec<ModuleInfo>,
    /// True once the shim has sent its full module list (EVT_MODULE_LIST).
    /// Symbolic addresses (e.g. "main+0x40") should wait for this.
    pub module_list_seen: bool,
    
    // Rules
    pub rules: Vec<Rule>,
    pub next_rule_id: usize,
    
    // Registers
    pub registers: RegisterState,
    
    // Hardware profile
    pub profile: HardwareProfile,
    pub profile_path: String,
    /// Handle to the "GhostSandboxProfile" file mapping (0 = none yet).
    pub profile_shmem: isize,

    // Memory editor state
    pub memory_address: u64,
    pub memory_data: Vec<u8>,

    // Runtime status
    pub tracing_paused: bool,
    pub status_message: String,
    /// Distinct hooked functions observed in the trace stream.
    pub hooked_functions: HashSet<String>,

    // Sandbox policy (import/export control)
    /// Import/export policy hits reported by the shim.
    pub policy_hits: VecDeque<PolicyHitEvent>,
    pub max_policy_hits: usize,
    pub policy_blocked: u64,
    pub policy_observed: u64,
    /// Handle to the "GhostSandboxPolicy" file mapping (0 = none yet).
    pub policy_shmem: isize,
    /// Last engine status line ("PolicyApply: 3 rules ...").
    pub policy_last_status: String,

    // Malware analysis (behaviour mediation + shadow store)
    /// Behaviour events reported by the shim's malware guard.
    pub malware_ops: VecDeque<MalwareOpEvent>,
    pub max_malware_ops: usize,
    pub malware_allowed: u64,
    pub malware_shadowed: u64,
    pub malware_faked: u64,
    pub malware_blocked: u64,
    /// Approvals still waiting for a user verdict.
    pub malware_pending: u64,
    /// True once the shim reported malware analysis mode for this target.
    pub malware_mode_active: bool,
    /// Shadow store root used for this run (also shown in the view).
    pub shadow_dir: String,
}

impl AppState {
    pub fn new() -> Self {
        let mut api_history = VecDeque::new();
        for _ in 0..120 {
            api_history.push_back(0.0);
        }
        
        Self {
            connected: false,
            target_name: String::new(),
            target_pid: 0,
            total_api_calls: 0,
            total_spoofed: 0,
            active_hooks: 0,
            memory_patches: 0,
            api_calls_per_sec: api_history,
            trace_events: VecDeque::new(),
            max_trace_events: 50_000,
            drm_events: VecDeque::new(),
            max_drm_events: 20_000,
            drm_total: 0,
            drm_detections: 0,
            drm_enabled: true,
            drm_last_alert: None,
            modules: Vec::new(),
            module_list_seen: false,
            rules: Vec::new(),
            next_rule_id: 1,
            registers: RegisterState::default(),
            profile: HardwareProfile::default(),
            profile_path: String::from("profiles/default.toml"),
            profile_shmem: 0,
            memory_address: 0,
            memory_data: Vec::new(),
            tracing_paused: false,
            status_message: String::new(),
            hooked_functions: HashSet::new(),
            policy_hits: VecDeque::new(),
            max_policy_hits: 20_000,
            policy_blocked: 0,
            policy_observed: 0,
            policy_shmem: 0,
            policy_last_status: String::new(),
            malware_ops: VecDeque::new(),
            max_malware_ops: 20_000,
            malware_allowed: 0,
            malware_shadowed: 0,
            malware_faked: 0,
            malware_blocked: 0,
            malware_pending: 0,
            malware_mode_active: false,
            shadow_dir: String::new(),
        }
    }
}

// ─── Main App ───────────────────────────────────────────────
pub struct SandboxApp {
    pub current_view: View,
    pub state: Arc<Mutex<AppState>>,
    pub pipe: PipeServer,

    // Sandbox service (import/export control) view state
    pub sandbox: views::sandbox_view::SandboxState,
    // Malware analysis view state
    pub malware: views::malware_view::MalwareState,
    // External tool handoff view state
    pub integrations: views::integrations_view::IntegrationsState,

    /// One-time Malware Analysis disclaimer gate (shares its record with the
    /// CLI's `--accept-disclaimer` flag through crate::disclaimer).
    pub mw_disclaimer: crate::widgets::mw_disclaimer::MwDisclaimer,

    /// About / legal dialog — keeps the disclaimer and licence reachable
    /// after the one-time acknowledgement has been recorded.
    pub about: crate::widgets::about_dialog::AboutDialog,

    /// Automation hook (`GHOST_MEM_ADDR`): true once the one-shot memory
    /// dump + register capture has been issued (or was not requested).
    pub automation_mem_done: bool,

    // api-calls/sec sampling
    rate_tick: Instant,
    rate_last_total: u64,

    // View-specific state
    pub trace_filter: String,
    pub trace_filter_module: String,
    pub trace_show_spoofed_only: bool,
    /// Module+function picked in the trace table for external-tool handoff.
    pub trace_selected_module: Option<(String, String)>,
    pub drm_filter: String,
    pub drm_filter_caller: String,
    pub drm_show_detections_only: bool,
    /// 0 = all categories, otherwise a DrmCategory id.
    pub drm_category_filter: u32,
    /// Caller picked in the DRM table for external-tool handoff
    /// (module, RVA, API name).
    pub drm_selected_caller: Option<(String, u64, String)>,
    pub module_search_input: String,
    pub memory_addr_input: String,
    pub memory_patch_input: String,
    pub hex_bytes_input: String,
    /// Bytes per dump in the Memory Editor (text field, 16..4096).
    pub memory_dump_len: String,
    /// Pattern search inside the current dump (hex bytes or ASCII text).
    pub memory_search: String,
    pub new_rule_hook: String,
    pub new_rule_action: RuleAction,
    pub new_rule_value: String,
}

impl SandboxApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut initial = AppState::new();

        // Load the startup hardware profile and publish it to shared memory
        // so the shim can pick it up when it attaches to a target.
        match HardwareProfile::load_from_file(&initial.profile_path) {
            Ok(p) => initial.profile = p,
            Err(e) => {
                initial.status_message = format!("Using built-in profile ({})", e);
            }
        }
        match crate::shared_profile::publish(&initial.profile, 0) {
            Ok(h) => initial.profile_shmem = h,
            Err(e) => {
                initial.status_message = format!("Profile shared memory: {}", e);
            }
        }

        let state = Arc::new(Mutex::new(initial));

        // Start the pipe server and pump shim events into the app state.
        let pipe = PipeServer::new();
        crate::pump::spawn(state.clone(), pipe.rx.clone());

        let mut app = Self {
            current_view: match std::env::var("GHOST_START_VIEW").as_deref() {
                Ok("drm") => View::DrmMonitor,
                Ok("sandbox") => View::Sandbox,
                Ok("malware") => View::Malware,
                Ok("integrations") => View::Integrations,
                Ok("memory") => View::MemoryEditor,
                Ok("modules") => View::Modules,
                Ok("trace") => View::TraceViewer,
                _ => View::Dashboard,
            },
            state,
            pipe,
            sandbox: views::sandbox_view::SandboxState::new(),
            malware: views::malware_view::MalwareState::new(),
            integrations: views::integrations_view::IntegrationsState::new(),
            rate_tick: Instant::now(),
            rate_last_total: 0,
            trace_filter: String::new(),
            trace_filter_module: String::new(),
            trace_show_spoofed_only: false,
            trace_selected_module: None,
            drm_filter: String::new(),
            drm_filter_caller: String::new(),
            drm_show_detections_only: false,
            drm_category_filter: 0,
            drm_selected_caller: None,
            module_search_input: String::new(),
            memory_addr_input: String::from("0x7FF800000000"),
            memory_patch_input: String::from("1"),
            hex_bytes_input: String::new(),
            memory_dump_len: String::from("4096"),
            memory_search: String::new(),
            new_rule_hook: String::new(),
            new_rule_action: RuleAction::Trace,
            new_rule_value: String::new(),
            mw_disclaimer: crate::widgets::mw_disclaimer::MwDisclaimer::new(),
            about: crate::widgets::about_dialog::AboutDialog::new(),
            automation_mem_done: false,
        };

        // First-run gate: if automation asked for the Malware view but the
        // terms are not acknowledged yet, start with the dialog over it.
        if app.current_view == View::Malware && !app.mw_disclaimer.acknowledged {
            app.mw_disclaimer.open = true;
        }
        // Automation hook for screenshots of the About / legal dialog.
        if matches!(std::env::var("GHOST_OPEN_ABOUT").as_deref(), Ok("1")) {
            app.about.open = true;
        }
        app
    }

    /// Navigate to a view, honouring the one-time Malware Analysis
    /// disclaimer gate (the GUI twin of the CLI `--accept-disclaimer`).
    fn open_view(&mut self, view: View) {
        if view == View::Malware && !self.mw_disclaimer.acknowledged {
            self.mw_disclaimer.open = true;
            return;
        }
        self.current_view = view;
    }

    /// Automation hooks used by the E2E harnesses / agent workflows:
    /// `GHOST_AUTORUN=1` runs the preloaded sample from any view, and
    /// `GHOST_MEM_ADDR=ADDR[:LEN]` (absolute, or `module+offset` / `main+…`)
    /// dumps memory and captures registers once the target is up.
    fn automation_tick(&mut self) {
        // Run the preloaded sample regardless of the view on screen — except
        // when the malware view owns the run (its launch path is different).
        if self.current_view != View::Malware {
            if let Some(deadline) = self.sandbox.autorun_deadline {
                if Instant::now() >= deadline {
                    self.sandbox.autorun_deadline = None;
                    if self.sandbox.inspection.is_some() {
                        views::sandbox_view::run_sample(self);
                    }
                }
            }
        }

        // Malware-view automation: GHOST_AUTORUN=1 + sample preloaded for the
        // malware view launches it confined with the currently selected flags.
        // Containment `none` still stops at the confirmation dialog.
        if let Some(deadline) = self.malware.autorun_deadline {
            if Instant::now() >= deadline {
                self.malware.autorun_deadline = None;
                if !self.malware.sample_path.trim().is_empty() {
                    views::malware_view::request_launch(self);
                }
            }
        }

        // One-shot memory dump + register snapshot for the memory-view E2E.
        if self.automation_mem_done {
            return;
        }
        let Ok(spec) = std::env::var("GHOST_MEM_ADDR") else {
            self.automation_mem_done = true;
            return;
        };
        if spec.trim().is_empty() {
            self.automation_mem_done = true;
            return;
        }
        let (addr_s, len_s) = match spec.split_once(':') {
            Some((a, l)) => (a, l),
            None => (spec.as_str(), "512"),
        };
        let len = len_s.trim().parse::<u32>().unwrap_or(512).clamp(16, 4096);

        // Wait for a live target with its module list (needed for main+N).
        let (connected, list_seen) = {
            let st = self.state.lock().unwrap();
            (st.connected, st.module_list_seen)
        };
        if !(connected && list_seen) {
            static WAIT_LOGGED: std::sync::Once = std::sync::Once::new();
            WAIT_LOGGED.call_once(|| {
                tracing::info!(
                    "GHOST_MEM_ADDR={} — waiting for a live target + module list",
                    spec
                );
            });
            return;
        }
        let main_name = std::path::Path::new(&self.sandbox.sample_path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let resolved = {
            let st = self.state.lock().unwrap();
            views::memory_editor::resolve_target_addr(addr_s, &st, &main_name)
        };
        let Some(address) = resolved else {
            static RESOLVE_LOGGED: std::sync::Once = std::sync::Once::new();
            RESOLVE_LOGGED.call_once(|| {
                tracing::info!("GHOST_MEM_ADDR={} — module not in the list yet, retrying", spec)
            });
            return; // module not loaded yet — retry next frame
        };

        self.memory_addr_input = format!("0x{:016X}", address);
        match self
            .pipe
            .send_command(crate::pipe_server::PipeCommand::Dump { address, length: len })
        {
            Ok(()) => tracing::info!(
                "Automation: requested dump of {} bytes at 0x{:016X}",
                len,
                address
            ),
            Err(e) => tracing::error!("Automation: dump request failed: {}", e),
        }
        let _ = self.pipe.send_command(
            crate::pipe_server::PipeCommand::GetRegisters { thread_id: 0 },
        );
        self.state.lock().unwrap().status_message =
            format!("Automation: dumped {} bytes at 0x{:016X}", len, address);
        self.automation_mem_done = true;
    }

    fn launch_target(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Executables", &["exe"])
            .pick_file()
        else {
            return;
        };

        let target_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        // sandbox_shim.dll sits next to the ghost_sandbox executable
        // (build.rs copies it there after every build).
        let shim_path = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("."))
            .parent()
            .map(|p| p.join("sandbox_shim.dll"))
            .unwrap_or_else(|| PathBuf::from("sandbox_shim.dll"));

        // Re-publish the current profile so this target sees the latest
        // hardware identity (including edits made since startup).
        self.publish_profile();

        match crate::injector::inject(
            &path.to_string_lossy(),
            &shim_path.to_string_lossy(),
            &[],
        ) {
            Ok(injected) => {
                {
                    let mut s = self.state.lock().unwrap();
                    s.target_name = target_name.clone();
                    s.target_pid = injected.pid;
                    s.status_message = format!(
                        "Injected shim into {} (PID {}) — waiting for connection…",
                        target_name, injected.pid
                    );
                }
                if let Err(e) = injected.resume() {
                    self.state.lock().unwrap().status_message =
                        format!("Resume failed: {}", e);
                }
            }
            Err(e) => {
                self.state.lock().unwrap().status_message =
                    format!("Injection failed: {}", e);
            }
        }
    }

    /// Re-publish the hardware profile to shared memory. Called before every
    /// injection so freshly launched targets always see the latest identity
    /// (edits made in the Hardware Profile view apply from the next launch).
    pub fn publish_profile(&mut self) {
        let mut s = self.state.lock().unwrap();
        let profile = s.profile.clone();
        match crate::shared_profile::publish(&profile, s.profile_shmem) {
            Ok(h) => s.profile_shmem = h,
            Err(e) => s.status_message = format!("Hardware profile publish failed: {}", e),
        }
    }

    fn toggle_tracing(&mut self) {
        let (paused_now, cmd) = {
            let mut s = self.state.lock().unwrap();
            let want_pause = !s.tracing_paused;
            s.tracing_paused = want_pause;
            (
                want_pause,
                if want_pause {
                    PipeCommand::TracePause
                } else {
                    PipeCommand::TraceResume
                },
            )
        };

        let mut s = self.state.lock().unwrap();
        match self.pipe.send_command(cmd) {
            Ok(()) => {
                s.status_message = if paused_now {
                    "Tracing paused".into()
                } else {
                    "Tracing resumed".into()
                }
            }
            Err(e) => s.status_message = format!("Command failed: {}", e),
        }
    }

    fn export_traces(&mut self) {
        match views::trace_viewer::export_csv(&self.state) {
            Ok(path) => {
                self.state.lock().unwrap().status_message =
                    format!("Exported trace to {}", path);
            }
            Err(e) if e == "Export cancelled"=> {}
            Err(e) => {
                self.state.lock().unwrap().status_message = e;
            }
        }
    }

    /// Push a once-per-second sample of the API call rate.
    fn sample_call_rate(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.rate_tick);
        if elapsed < std::time::Duration::from_secs(1) {
            return;
        }

        let total = self.state.lock().unwrap().total_api_calls;
        let rate = total.saturating_sub(self.rate_last_total) as f64 / elapsed.as_secs_f64();

        let mut s = self.state.lock().unwrap();
        if s.api_calls_per_sec.len() >= 120 {
            s.api_calls_per_sec.pop_front();
        }
        s.api_calls_per_sec.push_back(rate);
        drop(s);

        self.rate_last_total = total;
        self.rate_tick = now;
    }
}

impl eframe::App for SandboxApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request continuous repaints for live data
        ctx.request_repaint_after(std::time::Duration::from_millis(100));

        self.sample_call_rate();
        self.automation_tick();

        let mut launch_clicked = false;
        let mut export_clicked = false;
        let mut pause_clicked = false;
        let mut clear_trace_clicked = false;

        // ─── Top Status Bar ─────────────────────────────────
        egui::TopBottomPanel::top("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("GHOST SANDBOX").color(CYAN).strong());
                ui.separator();

                {
                    let state = self.state.lock().unwrap();

                    // Connection status
                    let (status_color, status_text) = if state.connected {
                        (GREEN, format!("● Connected — {} (PID {})", state.target_name, state.target_pid))
                    } else {
                        (RED_ORANGE, "● Disconnected".to_string())
                    };
                    ui.label(egui::RichText::new(status_text).color(status_color));

                    if state.tracing_paused {
                        ui.label(egui::RichText::new("PAUSED").color(YELLOW));
                    }

                    if state.drm_enabled {
                        ui.label(egui::RichText::new("DRM").color(CYAN).size(12.0));
                    }

                    if state.drm_detections > 0 {
                        ui.label(
                            egui::RichText::new(format!("⚠ {} DRM detections", state.drm_detections))
                                .color(RED_ORANGE)
                                .strong(),
                        );
                    }

                    if state.policy_blocked > 0 {
                        ui.label(
                            egui::RichText::new(format!("{} blocked calls", state.policy_blocked))
                                .color(RED_ORANGE)
                                .strong(),
                        );
                    } else if state.policy_observed > 0 {
                        ui.label(
                            egui::RichText::new(format!("{} observed calls", state.policy_observed))
                                .color(CYAN)
                                .size(12.0),
                        );
                    }

                    // Last status message (injection results, command acks, ...)
                    if !state.status_message.is_empty() {
                        ui.separator();
                        let msg = &state.status_message;
                        let short: String = if msg.chars().count() > 70 {
                            format!("{}…", msg.chars().take(70).collect::<String>())
                        } else {
                            msg.clone()
                        };
                        ui.label(egui::RichText::new(short).color(TEXT_DIM).size(12.0));
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() {
                        export_clicked = true;
                    }

                    let paused = self.state.lock().unwrap().tracing_paused;
                    if ui.button(if paused { "Resume"} else { "Pause"}).clicked() {
                        pause_clicked = true;
                    }

                    if ui.button("Launch Target").clicked() {
                        launch_clicked = true;
                    }

                    if ui.button("Clear Trace").clicked() {
                        clear_trace_clicked = true;
                    }
                });
            });
        });

        if launch_clicked {
            self.launch_target();
        }
        if pause_clicked {
            self.toggle_tracing();
        }
        if export_clicked {
            self.export_traces();
        }
        if clear_trace_clicked {
            self.state.lock().unwrap().trace_events.clear();
        }
        
        // ─── Left Sidebar ───────────────────────────────────
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(180.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                
                for view in VIEW_ORDER {
                    let selected = self.current_view == view;
                    let text = view.label().to_string();
                    
                    let button = egui::Button::new(
                        egui::RichText::new(&text)
                            .color(if selected { CYAN } else { TEXT_DIM })
                            .size(14.0)
                    )
                    .fill(if selected { CARD_BG } else { egui::Color32::TRANSPARENT })
                    .stroke(if selected {
                        egui::Stroke::new(1.0_f32, CYAN)
                    } else {
                        egui::Stroke::NONE
                    })
                    .min_size(egui::vec2(164.0, 36.0));
                    
                    if ui.add(button).clicked() {
                        self.open_view(view);
                    }
                    ui.add_space(2.0);
                }
                
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("v1.0.0").color(TEXT_DIM).size(11.0));
                    ui.label(egui::RichText::new("Ghost Sandbox").color(TEXT_DIM).size(11.0));
                    let about = egui::Button::new(
                        egui::RichText::new("About & legal").color(TEXT_DIM).size(11.0),
                    )
                    .fill(egui::Color32::TRANSPARENT)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER))
                    .min_size(egui::vec2(140.0, 22.0));
                    if ui.add(about).clicked() {
                        self.about.open = true;
                    }
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Experimental · AGPL-3.0 · no warranty")
                            .color(TEXT_DIM)
                            .size(10.0),
                    );
                });
            });
        
        // ─── Main Content ───────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_view {
                View::Dashboard => views::dashboard::show(ui, self),
                View::TraceViewer => views::trace_viewer::show(ui, self),
                View::DrmMonitor => views::drm_view::show(ui, self),
                View::Sandbox => views::sandbox_view::show(ui, self),
                View::Malware => views::malware_view::show(ui, self),
                View::Integrations => views::integrations_view::show(ui, self),
                View::HardwareProfile => views::hardware_profile::show(ui, self),
                View::MemoryEditor => views::memory_editor::show(ui, self),
                View::Modules => views::modules::show(ui, self),
                View::Rules => views::rules::show(ui, self),
            }
        });

        // About / legal dialog - the disclaimer and licence stay reachable
        // after the one-time acknowledgement, and the gate can be re-opened.
        self.about.show(ctx);
        if self.about.reopen_gate {
            self.about.reopen_gate = false;
            self.mw_disclaimer.open = true;
        }

        // One-time Malware Analysis acknowledgement gate: modal overlay that
        // blocks the view until the terms are accepted (same record as the
        // CLI flag, shared with it for this user).
        if self.mw_disclaimer.show(ctx) {
            self.current_view = View::Malware;
        }
    }
}
