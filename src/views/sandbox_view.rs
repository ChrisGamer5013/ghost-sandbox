/*
   Ghost Sandbox — Sandbox view (sample service)
   Drop an EXE or DLL to get a Joe-Sandbox-style workflow:
     * static inspection (PE headers, sections, imports, exports, hashes),
     * per-import / per-export control (allow / observe / block + return value),
     * run the sample instrumented — policy enforced in the shim before the
       first instruction of the entry point executes,
     * live hit feed with caller attribution,
     * JSON report export (same schema as the CLI).
*/

use egui::{Align, Layout, RichText};
use egui_extras::{Column, TableBuilder};

use crate::app::{
    policy_action_name, policy_kind_name, SandboxApp, CARD_BG, CYAN, GREEN, RED_ORANGE, TEXT_DIM,
    YELLOW,
};
use crate::pe_inspect::{self, PeInfo};
use crate::pipe_server::PipeCommand;
use crate::policy::{PolicyAction, PolicyKind, PolicySet};
use crate::report::{OutputFormat, SessionReport};
use crate::tools::ToolContext;
use crate::views::integrations_view::tool_menu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTab {
    Overview,
    Imports,
    Exports,
    Hits,
}

pub struct RunInfo {
    pub pid: u32,
    pub host: String,
    pub time: String,
    pub rules: usize,
}

pub struct SandboxState {
    pub sample_path: String,
    pub inspection: Option<PeInfo>,
    pub inspect_error: Option<String>,
    pub policy: PolicySet,
    pub tab: SandboxTab,
    pub import_filter: String,
    pub export_filter: String,
    pub hits_filter: String,
    pub hits_blocked_only: bool,
    pub show_ruled_only: bool,
    pub target_args: String,
    /// Export to invoke when hosting a DLL (""= load only).
    pub dll_export: String,
    pub last_run: Option<RunInfo>,
    pub sha256_copy_hint: String,
    /// Caller picked in the Live Hits table (module, RVA, target) for handoff.
    pub hits_selected_caller: Option<(String, u64, String)>,
    /// Automation hook: `GHOST_AUTORUN=1` runs the preloaded sample once the
    /// pipe server has had time to bind (deadline in the past = now).
    pub autorun_deadline: Option<std::time::Instant>,
}

impl SandboxState {
    pub fn new() -> Self {
        let mut st = SandboxState {
            sample_path: String::new(),
            inspection: None,
            inspect_error: None,
            policy: PolicySet::new(),
            tab: SandboxTab::Overview,
            import_filter: String::new(),
            export_filter: String::new(),
            hits_filter: String::new(),
            hits_blocked_only: false,
            show_ruled_only: false,
            target_args: String::new(),
            dll_export: String::new(),
            last_run: None,
            sha256_copy_hint: String::new(),
            hits_selected_caller: None,
            autorun_deadline: if std::env::var("GHOST_AUTORUN").map(|v| v == "1").unwrap_or(false)
            {
                Some(std::time::Instant::now() + std::time::Duration::from_millis(1500))
            } else {
                None
            },
        };
        // Automation hook (tests / agent workflows): preload a sample.
        if let Ok(p) = std::env::var("GHOST_SAMPLE") {
            if !p.is_empty() {
                st.load_sample(std::path::Path::new(&p));
            }
        }
        // Automation hook: preload a policy file (used with GHOST_SAMPLE /
        // GHOST_AUTORUN so scripted runs arm rules before the sample starts).
        if let Ok(p) = std::env::var("GHOST_POLICY") {
            if !p.is_empty() {
                match crate::policy::PolicySet::load_from_file(&p) {
                    Ok(set) => st.policy = set,
                    Err(e) => st.inspect_error = Some(format!("policy {}: {}", p, e)),
                }
            }
        }
        st
    }

    /// Inspect a dropped / picked sample and reset the policy for it.
    pub fn load_sample(&mut self, path: &std::path::Path) {
        self.inspection = None;
        self.inspect_error = None;
        self.last_run = None;
        match pe_inspect::inspect_file(path) {
            Ok(info) => {
                self.sample_path = path.display().to_string();
                self.inspection = Some(info);
                self.policy.clear();
                self.tab = SandboxTab::Overview;
            }
            Err(e) => {
                self.sample_path = path.display().to_string();
                self.inspect_error = Some(e);
            }
        }
    }

    pub fn is_dll(&self) -> bool {
        self.inspection.as_ref().map(|i| i.is_dll).unwrap_or(false)
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    // ── Drag & drop ─────────────────────────────────────
    let dropped: Vec<std::path::PathBuf> = ui.ctx().input(|i| {
        i.raw
            .dropped_files
            .iter()
            .filter_map(|f| f.path.clone())
            .collect()
    });
    if let Some(p) = dropped.first() {
        app.sandbox.load_sample(p);
        app.state.lock().unwrap().status_message = format!("Sample loaded: {}", p.display());
    }
    let hovering_files = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());

    // (GHOST_AUTORUN is handled globally in SandboxApp::automation_tick so the
    // sample can run while any view — e.g. the memory editor — is on screen.)

    // ── Header ──────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading(RichText::new("Sandbox — Sample Analysis").color(CYAN));
        ui.add_space(12.0);
        if ui.button("Open sample (EXE / DLL)…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Windows binaries", &["exe", "dll", "sys", "ocx"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                app.sandbox.load_sample(&path);
            }
        }
        if !app.sandbox.sample_path.is_empty() && ui.button("✖ Clear").clicked() {
            app.sandbox = SandboxState::new_cleared();
        }

        // Open-with handoff for the whole sample
        if let Some(info) = &app.sandbox.inspection {
            ui.separator();
            let ctx = ToolContext {
                file: info.path.clone(),
                name: info.file_name.clone(),
                ..Default::default()
            };
            ui.label(RichText::new("Open sample in:").color(TEXT_DIM).size(12.0));
            tool_menu(ui, app, crate::tools::ToolStage::Disassemble, &ctx, "Disassemble");
            tool_menu(ui, app, crate::tools::ToolStage::Decompile, &ctx, "Decompile");
            tool_menu(ui, app, crate::tools::ToolStage::InspectPe, &ctx, "Inspect PE");
            tool_menu(ui, app, crate::tools::ToolStage::Strings, &ctx, "Strings");
        }
    });

    ui.label(
        RichText::new(
            "Drop an EXE or DLL anywhere on this view. Ghost Sandbox inspects it statically, \
             lets you control every import (what the sample calls) and export (what a DLL \
             provides) — allow, observe, or block with a chosen return value — then runs it \
             instrumented with the policy enforced before the entry point executes.",
        )
        .color(TEXT_DIM)
        .size(12.0),
    );

    if hovering_files {
        ui.add_space(4.0);
        ui.label(RichText::new("Drop the sample to analyze it").color(YELLOW).strong());
    }
    ui.add_space(6.0);

    // ── Empty state ─────────────────────────────────────
    if app.sandbox.inspection.is_none() && app.sandbox.inspect_error.is_none() {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Drop an EXE or DLL here — or use \"Open sample\".")
                    .size(16.0)
                    .color(TEXT_DIM),
            );
            ui.label(
                RichText::new(
                    "You will get hashes, sections, imports and exports, per-function control, \
                     and a live hit feed once the sample runs.",
                )
                .color(TEXT_DIM)
                .size(12.0),
            );
        });
        return;
    }
    if let Some(err) = &app.sandbox.inspect_error {
        ui.colored_label(RED_ORANGE, format!("⚠ {}", err));
        return;
    }

    // ── Tabs ────────────────────────────────────────────
    ui.horizontal(|ui| {
        let info = app.sandbox.inspection.as_ref().unwrap();
        for (tab, label) in [
            (SandboxTab::Overview, "Overview"),
            (SandboxTab::Imports, "Imports"),
            (SandboxTab::Exports, "Exports"),
            (SandboxTab::Hits, "Live Hits"),
        ] {
            let count = match tab {
                SandboxTab::Imports => format!("({})", info.total_imports),
                SandboxTab::Exports => format!("({})", info.exports.len()),
                SandboxTab::Hits => {
                    let n = app.state.lock().unwrap().policy_hits.len();
                    if n > 0 {
                        format!("({})", n)
                    } else {
                        String::new()
                    }
                }
                _ => String::new(),
            };
            let selected = app.sandbox.tab == tab;
            if ui
                .selectable_label(selected, RichText::new(format!("{}{}", label, count)).size(14.0))
                .clicked()
            {
                app.sandbox.tab = tab;
            }
        }
        ui.separator();
        let (_, active) = app.sandbox.policy.counts();
        ui.label(
            RichText::new(format!("{} active rules", active))
                .color(if active > 0 { CYAN } else { TEXT_DIM })
                .size(12.0),
        );
    });
    ui.add_space(6.0);

    match app.sandbox.tab {
        SandboxTab::Overview => show_overview(ui, app),
        SandboxTab::Imports => show_imports(ui, app),
        SandboxTab::Exports => show_exports(ui, app),
        SandboxTab::Hits => show_hits(ui, app),
    }
}

impl SandboxState {
    fn new_cleared() -> Self {
        let mut s = SandboxState {
            sample_path: String::new(),
            inspection: None,
            inspect_error: None,
            policy: PolicySet::new(),
            tab: SandboxTab::Overview,
            import_filter: String::new(),
            export_filter: String::new(),
            hits_filter: String::new(),
            hits_blocked_only: false,
            show_ruled_only: false,
            target_args: String::new(),
            dll_export: String::new(),
            last_run: None,
            sha256_copy_hint: String::new(),
            hits_selected_caller: None,
            autorun_deadline: None,
        };
        s.sha256_copy_hint.clear();
        s
    }
}

// ─── Overview tab ───────────────────────────────────────────

fn show_overview(ui: &mut egui::Ui, app: &mut SandboxApp) {
    let info = app.sandbox.inspection.as_ref().unwrap().clone();

    egui::ScrollArea::vertical().show(ui, |ui| {
        // Summary card
        egui::Frame::new()
            .fill(CARD_BG)
            .inner_margin(10.0)
            .corner_radius(6.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(RichText::new(&info.file_name).size(16.0).color(CYAN));
                    ui.label(RichText::new(format!("{} bytes", info.size)).color(TEXT_DIM));
                    ui.label(
                        RichText::new(format!(
                            "{} {}-bit {} · {}",
                            info.machine_name,
                            if info.is_64bit { 64 } else { 32 },
                            if info.is_dll { "DLL"} else { "EXE"},
                            info.subsystem_name
                        ))
                        .color(TEXT_DIM),
                    );
                    if info.has_certificate {
                        ui.label(RichText::new("signed (certificate present)").color(GREEN));
                    } else {
                        ui.label(RichText::new("unsigned").color(YELLOW));
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("sha256:");
                    ui.monospace(
                        RichText::new(&info.sha256)
                            .color(TEXT_DIM)
                            .size(11.0),
                    );
                    if ui.small_button("copy").clicked() {
                        ui.ctx().copy_text(info.sha256.clone());
                        app.state.lock().unwrap().status_message = "sha256 copied".into();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} imports across {} DLLs · {} exports · max section entropy {:.2}",
                            info.total_imports,
                            info.imports.len(),
                            info.exports.len(),
                            info.max_entropy
                        ))
                        .color(TEXT_DIM)
                        .size(12.0),
                    );
                });
                if !info.packer_hints.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Heuristics:").color(YELLOW).size(12.0));
                        for h in &info.packer_hints {
                            ui.label(RichText::new(h).color(YELLOW).size(12.0));
                        }
                    });
                }
            });

        ui.add_space(8.0);

        // Run controls
        egui::Frame::new()
            .fill(CARD_BG)
            .inner_margin(10.0)
            .corner_radius(6.0)
            .show(ui, |ui| {
                ui.strong(RichText::new("Run sample instrumented").color(GREEN));
                ui.horizontal(|ui| {
                    if info.is_dll {
                        ui.label("Host mode:");
                        ui.label(
                            RichText::new("ghost_host.exe loads the DLL (DllMain) — pick an export to call after load")
                                .color(TEXT_DIM)
                                .size(12.0),
                        );
                    } else {
                        ui.label("Arguments:");
                        ui.add(
                            egui::TextEdit::singleline(&mut app.sandbox.target_args)
                                .desired_width(360.0)
                                .hint_text("command line arguments passed to the sample"),
                        );
                    }
                });
                if info.is_dll {
                    ui.horizontal(|ui| {
                        ui.label("Call export:");
                        egui::ComboBox::from_id_salt("sandbox_dll_export")
                            .selected_text(if app.sandbox.dll_export.is_empty() {
                                "(load only — DllMain)".to_string()
                            } else {
                                app.sandbox.dll_export.clone()
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut app.sandbox.dll_export,
                                    String::new(),
                                    "(load only — DllMain)",
                                );
                                for e in info.exports.iter().filter(|e| !e.forwarded) {
                                    ui.selectable_value(
                                        &mut app.sandbox.dll_export,
                                        e.name.clone(),
                                        &e.name,
                                    );
                                }
                            });
                    });
                }

                ui.horizontal(|ui| {
                    let (_, active) = app.sandbox.policy.counts();
                    let run_label = if info.is_dll {
                        "Load DLL under Ghost Sandbox"
                    } else {
                        "Run under Ghost Sandbox"
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(run_label).color(GREEN).strong()),
                        )
                        .on_hover_text(format!(
                            "Publishes {} active policy rules to shared memory, injects \
                             sandbox_shim.dll before the entry point and resumes the process",
                            active
                        ))
                        .clicked()
                    {
                        run_sample(app);
                    }

                    if ui
                        .button("Export report (JSON)")
                        .on_hover_text("Static analysis + policy + live hits — same schema as the CLI")
                        .clicked()
                    {
                        export_report(app);
                    }

                    if let Some(run) = &app.sandbox.last_run {
                        ui.label(
                            RichText::new(format!(
                                "last run: PID {} via {} · {} ({} rules)",
                                run.pid, run.host, run.time, run.rules
                            ))
                            .color(TEXT_DIM)
                            .size(12.0),
                        );
                    }
                });
            });

        ui.add_space(8.0);

        // Sections
        ui.strong("Sections");
        TableBuilder::new(ui)
            .striped(true)
            .id_salt("sandbox_sections")
            .column(Column::initial(120.0))
            .column(Column::initial(90.0))
            .column(Column::initial(90.0))
            .column(Column::initial(90.0))
            .column(Column::initial(80.0))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                h.col(|ui| { ui.strong("Name"); });
                h.col(|ui| { ui.strong("RVA"); });
                h.col(|ui| { ui.strong("Virt size"); });
                h.col(|ui| { ui.strong("Raw size"); });
                h.col(|ui| { ui.strong("Entropy"); });
                h.col(|ui| { ui.strong("Flags"); });
            })
            .body(|mut body| {
                for s in &info.sections {
                    body.row(20.0, |mut row| {
                        row.col(|ui| { ui.monospace(&s.name); });
                        row.col(|ui| { ui.monospace(format!("0x{:X}", s.rva)); });
                        row.col(|ui| { ui.monospace(format!("{}", s.virtual_size)); });
                        row.col(|ui| { ui.monospace(format!("{}", s.raw_size)); });
                        row.col(|ui| {
                            let color = if s.entropy > 7.2 { RED_ORANGE } else { TEXT_DIM };
                            ui.label(RichText::new(format!("{:.2}", s.entropy)).color(color));
                        });
                        row.col(|ui| {
                            let mut flags = Vec::new();
                            if s.executable { flags.push("X"); }
                            if s.writable { flags.push("W"); }
                            if s.characteristics & 0x4000_0000 != 0 { flags.push("I"); }
                            ui.monospace(flags.join(""));
                        });
                    });
                }
            });
    });
}

// ─── Imports tab ────────────────────────────────────────────

fn show_imports(ui: &mut egui::Ui, app: &mut SandboxApp) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut app.sandbox.import_filter)
                .desired_width(220.0)
                .hint_text("function or DLL name"),
        );
        ui.checkbox(&mut app.sandbox.show_ruled_only, "Ruled only");
        if ui.button("Clear rules").clicked() {
            app.sandbox.policy.clear();
        }
        ui.label(
            RichText::new(
                "Set a per-function action — Observe reports every call and passes it through; \
                 Block answers the call with your value without executing the function.",
            )
            .color(TEXT_DIM)
            .size(12.0),
        );
    });
    ui.add_space(4.0);

    let filter = app.sandbox.import_filter.to_lowercase();
    let ruled_only = app.sandbox.show_ruled_only;

    let SandboxState {
        inspection,
        policy,
        ..
    } = &mut app.sandbox;
    let Some(info) = inspection.as_ref() else { return };

    egui::ScrollArea::vertical().show(ui, |ui| {
        for dll in &info.imports {
            let mut matching: Vec<&String> = dll
                .functions
                .iter()
                .filter(|f| {
                    if !filter.is_empty()
                        && !f.to_lowercase().contains(&filter)
                        && !dll.name.to_lowercase().contains(&filter)
                    {
                        return false;
                    }
                    if ruled_only {
                        let ruled = policy
                            .get(PolicyKind::Import, &dll.name, f)
                            .map(|r| r.action != PolicyAction::Allow)
                            .unwrap_or(false);
                        return ruled;
                    }
                    true
                })
                .collect();
            if matching.is_empty() && !filter.is_empty() {
                continue;
            }
            matching.truncate(2000);

            let title = format!(
                "{}  —  {}{}",
                dll.name,
                dll.functions.len(),
                if dll.delayed { "(delay-loaded)"} else { ""}
            );
            egui::CollapsingHeader::new(RichText::new(title).color(CYAN))
                .id_salt(format!("imp_{}", dll.name))
                .default_open(!filter.is_empty() && matching.len() < 30)
                .show(ui, |ui| {
                    for f in matching {
                        ui.horizontal(|ui| {
                            ui.monospace(
                                RichText::new(format!("{:<44}", f)).size(12.0),
                            );
                            let rule = policy.rule_mut(PolicyKind::Import, &dll.name, f);
                            action_editor(ui, rule, &format!("imp_{}_{}", dll.name, f));
                        });
                    }
                });
        }
    });
}

// ─── Exports tab ────────────────────────────────────────────

fn show_exports(ui: &mut egui::Ui, app: &mut SandboxApp) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut app.sandbox.export_filter)
                .desired_width(220.0)
                .hint_text("export name"),
        );
        ui.checkbox(&mut app.sandbox.show_ruled_only, "Ruled only");
        ui.label(
            RichText::new(
                "Export rules attach to the loaded module: Observe reports calls into the \
                 export, Block makes it return your value (the DLL is not executed for that call).",
            )
            .color(TEXT_DIM)
            .size(12.0),
        );
    });
    ui.add_space(4.0);

    let filter = app.sandbox.export_filter.to_lowercase();
    let ruled_only = app.sandbox.show_ruled_only;

    let mode = if app.sandbox.is_dll() { "DLL"} else { "EXE"};
    let SandboxState {
        inspection,
        policy,
        ..
    } = &mut app.sandbox;
    let Some(info) = inspection.as_ref() else { return };

    if info.exports.is_empty() {
        ui.label(
            RichText::new(format!("This {} has no exports.", mode))
                .color(TEXT_DIM),
        );
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for e in &info.exports {
            if !filter.is_empty() && !e.name.to_lowercase().contains(&filter) {
                continue;
            }
            if ruled_only {
                let ruled = policy
                    .get(PolicyKind::Export, &info.file_name, &e.name)
                    .map(|r| r.action != PolicyAction::Allow)
                    .unwrap_or(false);
                if !ruled {
                    continue;
                }
            }
            ui.horizontal(|ui| {
                ui.monospace(RichText::new(format!("{:<44}", e.name)).size(12.0));
                ui.label(
                    RichText::new(format!("ord {}", e.ordinal))
                        .color(TEXT_DIM)
                        .size(11.0),
                );
                if e.forwarded && !e.forwarder.is_empty() {
                    ui.label(
                        RichText::new(format!("→ {}", e.forwarder))
                            .color(TEXT_DIM)
                            .size(11.0),
                    );
                }
                let rule = policy.rule_mut(PolicyKind::Export, &info.file_name, &e.name);
                action_editor(ui, rule, &format!("exp_{}", e.name));
            });
        }
    });
}

// ─── Hits tab ───────────────────────────────────────────────

fn show_hits(ui: &mut egui::Ui, app: &mut SandboxApp) {
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut app.sandbox.hits_filter)
                .desired_width(200.0)
                .hint_text("function / module / caller"),
        );
        ui.checkbox(&mut app.sandbox.hits_blocked_only, "Blocked only");
        if ui.button("Clear").clicked() {
            let mut s = app.state.lock().unwrap();
            s.policy_hits.clear();
            s.policy_blocked = 0;
            s.policy_observed = 0;
        }
        if ui
            .button("Export report (JSON)")
            .clicked()
        {
            export_report(app);
        }

        // Handoff for the caller picked in the table below.
        if let Some((module, rva, target)) = app.sandbox.hits_selected_caller.clone() {
            ui.separator();
            ui.label(
                RichText::new(format!("{}+0x{:X}", module, rva))
                    .color(CYAN)
                    .size(11.0),
            )
            .on_hover_text(format!("Selected caller of {}", target));
            let ctx =
                crate::views::integrations_view::caller_context(app, &module, rva, &target);
            tool_menu(ui, app, crate::tools::ToolStage::Disassemble, &ctx, "Disassemble");
            tool_menu(ui, app, crate::tools::ToolStage::Debug, &ctx, "Debug");
            if ui.small_button("✖").on_hover_text("Clear selection").clicked() {
                app.sandbox.hits_selected_caller = None;
            }
        }
    });
    ui.add_space(4.0);

    // Row clicks are collected here and applied once the state lock drops.
    let mut open_click: Option<(String, u64, String)> = None;
    {
    let state = app.state.lock().unwrap();
    let filter = app.sandbox.hits_filter.to_lowercase();
    let blocked_only = app.sandbox.hits_blocked_only;

    let filtered: Vec<&crate::app::PolicyHitEvent> = state
        .policy_hits
        .iter()
        .filter(|h| {
            if blocked_only && !h.blocked {
                return false;
            }
            if !filter.is_empty() {
                let hay = format!("{} {} {} {}", h.function, h.module, h.caller_module, h.detail)
                    .to_lowercase();
                if !hay.contains(&filter) {
                    return false;
                }
            }
            true
        })
        .collect();

    ui.label(
        RichText::new(format!(
            "{} hits · {} blocked · {} observed · engine: {}",
            state.policy_hits.len(),
            state.policy_blocked,
            state.policy_observed,
            if state.policy_last_status.is_empty() {
                "—"
            } else {
                &state.policy_last_status
            }
        ))
        .color(TEXT_DIM)
        .size(12.0),
    );
    ui.add_space(4.0);

    TableBuilder::new(ui)
        .striped(true)
        .id_salt("sandbox_hits")
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(76.0))  // Time
        .column(Column::initial(56.0))  // Kind
        .column(Column::initial(66.0))  // Action
        .column(Column::initial(64.0))  // Result
        .column(Column::initial(170.0)) // Module!Function
        .column(Column::initial(150.0)) // Caller
        .column(Column::remainder())    // Detail
        .header(24.0, |mut header| {
            header.col(|ui| { ui.strong("Time"); });
            header.col(|ui| { ui.strong("Kind"); });
            header.col(|ui| { ui.strong("Action"); });
            header.col(|ui| { ui.strong("Result"); });
            header.col(|ui| { ui.strong("Target"); });
            header.col(|ui| { ui.strong("Caller"); });
            header.col(|ui| { ui.strong("Detail"); });
        })
        .body(|body| {
            body.rows(20.0, filtered.len(), |mut row| {
                let h = filtered[row.index()];
                row.col(|ui| { ui.label(&h.timestamp); });
                row.col(|ui| { ui.label(policy_kind_name(h.kind)); });
                row.col(|ui| {
                    let color = match h.action {
                        2 => RED_ORANGE,
                        1 => CYAN,
                        _ => TEXT_DIM,
                    };
                    ui.label(RichText::new(policy_action_name(h.action)).color(color));
                });
                row.col(|ui| {
                    if h.kind == 0 {
                        ui.label(RichText::new("—").color(TEXT_DIM));
                    } else if h.blocked {
                        ui.label(
                            RichText::new(format!("blocked → 0x{:X}", h.ret_value))
                                .color(RED_ORANGE)
                                .strong(),
                        );
                    } else {
                        ui.label(RichText::new("passed").color(GREEN));
                    }
                });
                row.col(|ui| {
                    ui.label(format!("{}!{}", h.module, h.function)).on_hover_text(&h.detail);
                });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}+0x{:X}", h.caller_module, h.caller_rva));
                        if h.caller_rva != 0
                            && ui
                                .small_button("◎")
                                .on_hover_text(
                                    "Select this caller — then open it in the Memory Editor or an external tool",
                                )
                                .clicked()
                        {
                            open_click = Some((
                                h.caller_module.clone(),
                                h.caller_rva,
                                format!("{}!{}", h.module, h.function),
                            ));
                        }
                    });
                });
                row.col(|ui| {
                    ui.label(RichText::new(&h.detail).color(TEXT_DIM).size(11.0));
                });
            });
        });
    }

    if let Some(sel) = open_click {
        app.sandbox.hits_selected_caller = Some(sel);
    }
}

// ─── Widget helpers ─────────────────────────────────────────

/// Allow / Observe / Block editor for one import/export row.
fn action_editor(ui: &mut egui::Ui, rule: &mut crate::policy::PolicyRule, id: &str) {
    egui::ComboBox::from_id_salt(format!("act_{}", id))
        .selected_text(rule.action.label())
        .width(84.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(&mut rule.action, PolicyAction::Allow, "Allow");
            ui.selectable_value(&mut rule.action, PolicyAction::Observe, "Observe");
            ui.selectable_value(&mut rule.action, PolicyAction::Block, "Block");
        });
    if rule.action == PolicyAction::Block {
        ui.label(RichText::new("returns").color(TEXT_DIM).size(11.0));
        hex_drag(ui, &mut rule.value);
    }
    if rule.action != PolicyAction::Allow {
        ui.label(RichText::new("● active").color(GREEN).size(10.0));
    }
}

/// u64 drag value displayed/parsed in hex (0x1, 0x80070005, ...).
pub fn hex_drag(ui: &mut egui::Ui, v: &mut u64) -> egui::Response {
    ui.add(
        egui::DragValue::new(v)
            .speed(1.0)
            .custom_formatter(|n, _| format!("0x{:X}", n.max(0.0) as u64))
            .custom_parser(|s| {
                let t = s.trim();
                let t2 = t
                    .strip_prefix("0x")
                    .or_else(|| t.strip_prefix("0X"))
                    .unwrap_or(t);
                u64::from_str_radix(t2, 16)
                    .or_else(|_| t.parse::<u64>())
                    .ok()
                    .map(|x| x as f64)
            }),
    )
    .on_hover_text("Return value handed to the caller (hex or decimal)")
}

// ─── Actions ────────────────────────────────────────────────

/// Run the loaded sample instrumented: publish the policy, inject the shim,
/// resume, and queue a live policy refresh for the shim to pick up.
pub(crate) fn run_sample(app: &mut SandboxApp) {
    let Some(info) = app.sandbox.inspection.clone() else { return };

    // 1) Publish the policy to shared memory BEFORE the target starts.
    let entries = match app.sandbox.policy.wire_entries() {
        Ok(e) => e,
        Err(e) => {
            app.state.lock().unwrap().status_message = e;
            return;
        }
    };
    let rules = entries.len();
    let mut s = app.state.lock().unwrap();
    match crate::shared_policy::publish(&entries, s.policy_shmem) {
        Ok(h) => s.policy_shmem = h,
        Err(e) => {
            s.status_message = format!("Policy shared memory: {}", e);
            return;
        }
    }
    drop(s);

    // 2) Pick the host process.
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let shim_path = exe_dir.join("sandbox_shim.dll");

    let (target, args, host_label): (String, Vec<String>, String) = if info.is_dll {
        let host = exe_dir.join("ghost_host.exe");
        if host.exists() {
            let mut args = vec![info.path.clone()];
            if !app.sandbox.dll_export.is_empty() {
                args.push(app.sandbox.dll_export.clone());
            }
            args.push("--seconds".into());
            args.push("120".into());
            (host.display().to_string(), args, "ghost_host.exe".into())
        } else {
            // Fallback: rundll32 hosts the DLL (DllMain + optional export).
            let rundll = std::env::var("SystemRoot")
                .unwrap_or_else(|_| "C:\\Windows".into())
                + "\\System32\\rundll32.exe";
            let export = if app.sandbox.dll_export.is_empty() {
                "DllMain"
            } else {
                app.sandbox.dll_export.as_str()
            };
            (
                rundll,
                vec![info.path.clone(), export.to_string()],
                "rundll32.exe (fallback)".into(),
            )
        }
    } else {
        (
            info.path.clone(),
            crate::tools::split_args(&app.sandbox.target_args),
            "direct".into(),
        )
    };

    // 3) Publish the latest hardware profile, then inject + resume.
    app.publish_profile();
    match crate::injector::inject(&target, &shim_path.display().to_string(), &args) {
        Ok(injected) => {
            let pid = injected.pid;
            if let Err(e) = injected.resume() {
                app.state.lock().unwrap().status_message = format!("Resume failed: {}", e);
                return;
            }
            // 4) Belt & braces: also push the policy live once the pipe is up.
            let _ = app.pipe.send_command(PipeCommand::Policy { entries });

            let time = chrono::Local::now().format("%H:%M:%S").to_string();
            app.sandbox.last_run = Some(RunInfo {
                pid,
                host: host_label.clone(),
                time: time.clone(),
                rules,
            });
            let mut s = app.state.lock().unwrap();
            s.target_pid = pid;
            s.target_name = info.file_name.clone();
            s.status_message = format!(
                "{} started via {} (PID {}) — {} policy rules applied before entry point",
                info.file_name, host_label, pid, rules
            );
            s.policy_hits.clear();
            s.policy_blocked = 0;
            s.policy_observed = 0;
            app.sandbox.tab = SandboxTab::Hits;
        }
        Err(e) => {
            app.state.lock().unwrap().status_message = format!("Injection failed: {}", e);
        }
    }
}

/// Export a JSON report (static analysis + policy + live events).
fn export_report(app: &mut SandboxApp) {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name("sandbox_report.json")
        .add_filter("JSON", &["json"])
        .add_filter("Markdown", &["md"])
        .save_file()
    else {
        return;
    };

    let format = if path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("md"))
        .unwrap_or(false)
    {
        OutputFormat::Markdown
    } else {
        OutputFormat::Json
    };

    let report = build_report(app);
    match report.save(&path.display().to_string(), format) {
        Ok(()) => {
            app.state.lock().unwrap().status_message =
                format!("Report exported to {}", path.display());
        }
        Err(e) => app.state.lock().unwrap().status_message = e,
    }
}

/// Build the unified session report from current app state.
pub fn build_report(app: &SandboxApp) -> SessionReport {
    let state = app.state.lock().unwrap();
    let mut report = SessionReport::empty("sandbox-run");
    report.status = state.status_message.clone();
    if state.connected || state.target_pid != 0 {
        report.target = Some(crate::report::TargetInfo {
            pid: state.target_pid,
            name: state.target_name.clone(),
            connected: state.connected,
        });
    }
    report.sample = app.sandbox.inspection.clone();
    report = report.with_policy(&app.sandbox.policy);
    report.counts = crate::report::Counts {
        trace_events: state.trace_events.len(),
        api_calls_total: state.total_api_calls,
        spoofed_total: state.total_spoofed,
        drm_events: state.drm_events.len(),
        drm_detections: state.drm_detections,
        policy_hits: state.policy_hits.len(),
        policy_blocked: state.policy_blocked,
        policy_observed: state.policy_observed,
        modules: state.modules.len(),
        memory_patches: state.memory_patches,
        malware_ops: state.malware_ops.len(),
        malware_allowed: state.malware_allowed,
        malware_shadowed: state.malware_shadowed,
        malware_faked: state.malware_faked,
        malware_blocked: state.malware_blocked,
    };
    report.modules = state.modules.clone();
    report.policy_hits = state.policy_hits.iter().cloned().collect();
    report.drm_events = state.drm_events.iter().cloned().collect();
    report.malware_ops = state.malware_ops.iter().cloned().collect();
    report.shadow_dir = if state.shadow_dir.is_empty() {
        app.malware.shadow_dir.clone()
    } else {
        state.shadow_dir.clone()
    };
    report.trace = state.trace_events.iter().rev().take(2000).cloned().collect();
    drop(state);

    // Hash the captured files (read-only, bounded) so reports are
    // self-contained even if the UI never opened the shadow panel.
    if !report.shadow_dir.is_empty() {
        report.shadow_files = crate::views::malware_view::shadow_file_records(&report.shadow_dir);
    }
    report
}
