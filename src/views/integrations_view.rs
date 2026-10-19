/*
   Ghost Sandbox — Integrations view
   Every analysis stage can be served by Ghost Sandbox itself or handed off
   to an external tool (IDA, Ghidra, x64dbg, WinDbg, Cheat Engine, HxD, ...)
   with the full context (pid, address, module, RVA, file) passed on the
   command line — so the external program opens exactly where you are.

   This view manages tools.toml and offers a test-context preview showing
   the exact resolved command line before you launch anything.
*/

use egui::{RichText};
use egui_extras::{Column, TableBuilder};

use crate::app::{SandboxApp, View, CARD_BG, CYAN, GREEN, RED_ORANGE, TEXT_DIM};
use crate::tools::{split_args, ToolContext, ToolDef, ToolStage, ToolsConfig};

pub struct IntegrationsState {
    pub config: ToolsConfig,
    pub file_path: String,
    pub dirty: bool,
    pub selected: Option<usize>,
    /// Test context (editable so you can preview the exact handoff arguments).
    pub ctx_addr: String,
    pub ctx_module: String,
    pub ctx_rva: String,
    pub ctx_file: String,
    pub last_launch: String,
}

impl IntegrationsState {
    pub fn new() -> Self {
        let file_path = std::env::var("GHOST_TOOLS_FILE")
            .unwrap_or_else(|_| "tools.toml".to_string());
        let config = ToolsConfig::load_or_builtin(&file_path);
        IntegrationsState {
            config,
            file_path,
            dirty: false,
            selected: None,
            ctx_addr: String::from("0x0"),
            ctx_module: String::new(),
            ctx_rva: String::from("0x0"),
            ctx_file: String::new(),
            last_launch: String::new(),
        }
    }

    pub fn save(&mut self) -> Result<(), String> {
        self.config.save_to_file(&self.file_path)?;
        self.dirty = false;
        Ok(())
    }

    pub fn reload(&mut self) {
        self.config = ToolsConfig::load_or_builtin(&self.file_path);
        self.dirty = false;
    }
}

pub fn parse_hex(s: &str) -> u64 {
    let t = s.trim();
    let t2 = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t2.is_empty() {
        return 0;
    }
    u64::from_str_radix(t2, 16)
        .or_else(|_| t.parse::<u64>())
        .unwrap_or(0)
}

/// Build the handoff context from the live app state.
pub fn context_for(app: &SandboxApp, addr: u64, module: &str, rva: u64, func: &str) -> ToolContext {
    let st = app.state.lock().unwrap();
    let file = if !app.sandbox.sample_path.is_empty() && module.is_empty() {
        app.sandbox.sample_path.clone()
    } else if !module.is_empty() {
        // Prefer the module's full path when it is loaded in the target.
        st.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(module))
            .map(|m| if m.path.is_empty() { m.name.clone() } else { m.path.clone() })
            .unwrap_or_default()
    } else {
        app.sandbox.sample_path.clone()
    };
    let base = st
        .modules
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(module))
        .map(|m| m.base_address)
        .unwrap_or(0);
    ToolContext {
        file,
        pid: st.target_pid,
        addr,
        module: module.to_string(),
        rva,
        base,
        func: func.to_string(),
        bytes: String::new(),
        name: if func.is_empty() {
            module.to_string()
        } else {
            format!("{}!{}", module, func)
        },
    }
}

/// Base address of a loaded module, if the shim reported the module list.
pub fn module_base(app: &SandboxApp, module: &str) -> Option<u64> {
    let st = app.state.lock().unwrap();
    st.modules
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(module))
        .map(|m| m.base_address)
        .filter(|b| *b != 0)
}

/// Context for a caller (module + RVA) reported by the shim: resolves the
/// absolute address from the live module list when possible.
pub fn caller_context(app: &SandboxApp, module: &str, rva: u64, func: &str) -> ToolContext {
    let base = module_base(app, module).unwrap_or(0);
    let addr = if base != 0 { base + rva } else { rva };
    context_for(app, addr, module, rva, func)
}

/// The "Open with…" menu: Ghost-internal option + every configured tool of
/// the stage. Renders the resolved command line into the status bar.
pub fn tool_menu(
    ui: &mut egui::Ui,
    app: &mut SandboxApp,
    stage: ToolStage,
    ctx: &ToolContext,
    label: &str,
) {
    let tools: Vec<(String, String)> = app
        .integrations
        .config
        .for_stage(stage)
        .iter()
        .map(|t| (t.name.clone(), t.path.clone()))
        .collect();

    let menu_label = format!("{} ▾", label);
    ui.menu_button(menu_label, |ui| {
        // Ghost-internal handoff: live addresses open in the Memory Editor.
        if ctx.addr != 0 || ctx.pid != 0 {
            if ui
                .button("Open in Memory Editor")
                .on_hover_text("Use Ghost Sandbox itself: dump and inspect this address")
                .clicked()
            {
                {
                    let mut st = app.state.lock().unwrap();
                    st.memory_address = ctx.addr;
                    st.status_message = format!(
                        "Memory Editor → 0x{:X} ({})",
                        ctx.addr,
                        if ctx.name.is_empty() { "address"} else { &ctx.name }
                    );
                }
                let _ = app.pipe.send_command(crate::pipe_server::PipeCommand::Dump {
                    address: ctx.addr,
                    length: 256,
                });
                app.current_view = View::MemoryEditor;
                ui.close_menu();
            }
        }
        if !ctx.file.is_empty() {
            let reveal_ctx = ctx.clone();
            if ui.button("Reveal file in Explorer").clicked() {
                let t = ToolDef {
                    name: "explorer".into(),
                    stage: ToolStage::Custom,
                    path: "explorer.exe".into(),
                    args: "/select,\"{file}\"".into(),
                    enabled: true,
                    note: String::new(),
                };
                match crate::tools::launch(&t, &reveal_ctx) {
                    Ok(cmd) => app.state.lock().unwrap().status_message = format!("Launched: {}", cmd),
                    Err(e) => app.state.lock().unwrap().status_message = e,
                }
                ui.close_menu();
            }
        }
        ui.separator();
        if tools.is_empty() {
            ui.label(RichText::new("no external tools configured for this stage").color(TEXT_DIM).size(11.0));
        }
        for (name, path) in &tools {
            let resp = ui.button(name);
            if resp.clicked() {
                let tool = app
                    .integrations
                    .config
                    .tools
                    .iter()
                    .find(|t| &t.name == name && &t.path == path)
                    .cloned();
                if let Some(tool) = tool {
                    match crate::tools::launch(&tool, ctx) {
                        Ok(cmd) => {
                            app.integrations.last_launch = cmd.clone();
                            app.state.lock().unwrap().status_message =
                                format!("Launched external tool: {}", cmd);
                        }
                        Err(e) => app.state.lock().unwrap().status_message = e,
                    }
                }
                ui.close_menu();
            }
            if resp.hovered() {
                resp.on_hover_text(format!("{}: {}", name, path));
            }
        }
        ui.separator();
        if ui.button("Configure integrations…").clicked() {
            app.current_view = View::Integrations;
            ui.close_menu();
        }
    });
}

// ─── The Integrations view ──────────────────────────────────

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    ui.horizontal(|ui| {
        ui.heading(RichText::new("Integrations — external tool handoff").color(CYAN));
        ui.add_space(12.0);
        ui.label("Config:");
        ui.add(egui::TextEdit::singleline(&mut app.integrations.file_path).desired_width(180.0));
        if ui.button("Load").clicked() {
            app.integrations.reload();
            app.state.lock().unwrap().status_message = "Integrations reloaded".into();
        }
        if ui.button("Save").clicked() {
            match app.integrations.save() {
                Ok(()) => app.state.lock().unwrap().status_message = format!(
                    "Integrations saved to {}",
                    app.integrations.file_path
                ),
                Err(e) => app.state.lock().unwrap().status_message = e,
            }
        }
        if app.integrations.dirty {
            ui.label(RichText::new("● unsaved").color(RED_ORANGE).size(11.0));
        }
        if ui
            .button("↺ Built-in defaults")
            .on_hover_text("Restore the shipped preset catalogue (not saved until you hit Save)")
            .clicked()
        {
            app.integrations.config = ToolsConfig::builtin();
            app.integrations.dirty = true;
        }
    });

    ui.label(
        RichText::new(
            "These tools appear in every \"Open with\" menu (Sandbox, Anti-Tamper, Memory \
             Editor, Modules). Ghost passes the full context — {pid} {addr} {module} {rva} \
             {base} {file} {func} — so IDA/Ghidra/x64dbg/WinDbg open exactly at the call site \
             you clicked.",
        )
        .color(TEXT_DIM)
        .size(12.0),
    );
    ui.add_space(6.0);

    // ── Tool table ──────────────────────────────────────
    let mut remove: Option<usize> = None;
    let mut launch_now: Option<usize> = None;

    let tools_len = app.integrations.config.tools.len();
    TableBuilder::new(ui)
        .striped(true)
        .id_salt("integrations_table")
        .column(Column::initial(30.0))   // enabled
        .column(Column::initial(150.0))  // name
        .column(Column::initial(120.0))  // stage
        .column(Column::initial(260.0))  // path
        .column(Column::initial(220.0))  // args
        .column(Column::remainder())     // actions
        .header(24.0, |mut h| {
            h.col(|ui| { ui.strong("On"); });
            h.col(|ui| { ui.strong("Name"); });
            h.col(|ui| { ui.strong("Stage"); });
            h.col(|ui| { ui.strong("Executable"); });
            h.col(|ui| { ui.strong("Arguments template"); });
            h.col(|ui| { ui.strong("Actions"); });
        })
        .body(|mut body| {
            for i in 0..tools_len {
                body.row(24.0, |mut row| {
                    // SAFETY of indexing: we mutate only through retain later.
                    let tools = &mut app.integrations.config.tools;
                    let t = &mut tools[i];
                    row.col(|ui| {
                        if ui.checkbox(&mut t.enabled, "").changed() {
                            app.integrations.dirty = true;
                        }
                    });
                    row.col(|ui| {
                        if ui.add(egui::TextEdit::singleline(&mut t.name).desired_width(140.0)).changed() {
                            app.integrations.dirty = true;
                        }
                    });
                    row.col(|ui| {
                        egui::ComboBox::from_id_salt(format!("stage_{}", i))
                            .selected_text(t.stage.label())
                            .width(110.0)
                            .show_ui(ui, |ui| {
                                for s in ToolStage::all() {
                                    if ui.selectable_value(&mut t.stage, s, s.label()).clicked() {
                                        app.integrations.dirty = true;
                                    }
                                }
                            });
                    });
                    row.col(|ui| {
                        if ui.add(egui::TextEdit::singleline(&mut t.path).desired_width(250.0)).changed() {
                            app.integrations.dirty = true;
                        }
                    });
                    row.col(|ui| {
                        if ui.add(egui::TextEdit::singleline(&mut t.args).desired_width(210.0)).changed() {
                            app.integrations.dirty = true;
                        }
                    });
                    row.col(|ui| {
                        if ui.small_button("Test").clicked() {
                            launch_now = Some(i);
                        }
                        if ui.small_button("✖").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
        });

    if let Some(i) = remove {
        if i < app.integrations.config.tools.len() {
            app.integrations.config.tools.remove(i);
            app.integrations.dirty = true;
        }
    }
    if let Some(i) = launch_now {
        test_launch(app, i);
    }

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if ui.button("Add tool").clicked() {
            app.integrations.config.tools.push(ToolDef {
                name: "New tool".into(),
                stage: ToolStage::Custom,
                path: String::new(),
                args: String::new(),
                enabled: true,
                note: String::new(),
            });
            app.integrations.dirty = true;
        }
        ui.label(
            RichText::new(
                "Test launches use the context below — check the resolved command line first.",
            )
            .color(TEXT_DIM)
            .size(11.0),
        );
    });

    ui.add_space(8.0);

    // ── Test context preview ────────────────────────────
    egui::Frame::new()
        .fill(CARD_BG)
        .inner_margin(10.0)
        .corner_radius(6.0)
        .show(ui, |ui| {
            ui.strong(RichText::new("Test / handoff context preview").color(GREEN));
            ui.horizontal(|ui| {
                let (pid, target) = {
                    let st = app.state.lock().unwrap();
                    (st.target_pid, st.target_name.clone())
                };
                ui.label(format!("pid: {} ({})", pid, if target.is_empty() { "—"} else { &target }));
                ui.separator();
                ui.label("addr:");
                ui.add(egui::TextEdit::singleline(&mut app.integrations.ctx_addr).desired_width(120.0));
                ui.label("module:");
                ui.add(egui::TextEdit::singleline(&mut app.integrations.ctx_module).desired_width(140.0));
                ui.label("rva:");
                ui.add(egui::TextEdit::singleline(&mut app.integrations.ctx_rva).desired_width(90.0));
                ui.label("file:");
                let mut f = app.integrations.ctx_file.clone();
                if f.is_empty() {
                    f = app.sandbox.sample_path.clone();
                }
                if ui.add(egui::TextEdit::singleline(&mut f).desired_width(260.0)).changed() {
                    app.integrations.ctx_file = f;
                }
            });

            // Resolved command line preview for the first tool of each stage.
            let ctx = context_for(
                app,
                parse_hex(&app.integrations.ctx_addr),
                &app.integrations.ctx_module.clone(),
                parse_hex(&app.integrations.ctx_rva),
                "",
            );
            ui.add_space(4.0);
            ui.label(RichText::new(format!(
                "{pid} {addr} {base} {module} {rva} {file} {func}",
                pid = ctx.pid,
                addr = format!("0x{:X}", ctx.addr),
                base = format!("0x{:X}", ctx.base),
                module = if ctx.module.is_empty() { "-"} else { &ctx.module },
                rva = format!("0x{:X}", ctx.rva),
                file = if ctx.file.is_empty() { "-"} else { &ctx.file },
                func = "-",
            )).color(TEXT_DIM).size(11.0).monospace());

            ui.add_space(4.0);
            ui.label(RichText::new("Resolved commands for the preview context:").color(TEXT_DIM).size(11.0));
            for t in app.integrations.config.tools.iter().take(6) {
                let cmd = crate::tools::resolve(t, &ctx);
                ui.label(RichText::new(cmd.command_line()).monospace().size(11.0));
            }
            if !app.integrations.last_launch.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("last launch: {}", app.integrations.last_launch)).color(GREEN).size(11.0));
            }
            let _ = split_args; // (helper re-exported for callers)
        });
}

fn test_launch(app: &mut SandboxApp, i: usize) {
    let Some(tool) = app.integrations.config.tools.get(i).cloned() else { return };
    let ctx = context_for(
        app,
        parse_hex(&app.integrations.ctx_addr),
        &app.integrations.ctx_module.clone(),
        parse_hex(&app.integrations.ctx_rva),
        "",
    );
    match crate::tools::launch(&tool, &ctx) {
        Ok(cmd) => {
            app.integrations.last_launch = cmd.clone();
            app.state.lock().unwrap().status_message = format!("Launched: {}", cmd);
        }
        Err(e) => app.state.lock().unwrap().status_message = e,
    }
}
