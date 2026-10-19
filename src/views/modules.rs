// Ghost Sandbox — Modules view
// Snapshot the loaded-module list; every module row can be handed off to
// Ghost Sandbox itself or an external tool (IDA/Ghidra/…) with its base
// address, path and PID filled in.

use egui::{Align, Layout, RichText};
use egui_extras::{Column, TableBuilder};

use crate::app::{ModuleInfo, SandboxApp, GREEN, RED_ORANGE};
use crate::tools::{ToolContext, ToolStage};
use crate::views::integrations_view::tool_menu;

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.text_edit_singleline(&mut app.module_search_input);
        if ui.button("Clear").clicked() {
            app.module_search_input.clear();
        }
        if ui
            .button("⟳ Refresh")
            .on_hover_text("Ask the shim for the live module list (full paths + PE stats)")
            .clicked()
        {
            match app
                .pipe
                .send_command(crate::pipe_server::PipeCommand::ListModules)
            {
                Ok(()) => {
                    app.state.lock().unwrap().status_message = "Module list requested…".into()
                }
                Err(e) => app.state.lock().unwrap().status_message = e,
            }
        }
        ui.separator();
        let total = app.state.lock().unwrap().modules.len();
        ui.label(RichText::new(format!("{} modules loaded", total)).color(crate::app::TEXT_DIM));
    });

    ui.add_space(8.0);

    // Snapshot the rows so the table body can call back into `app` for the
    // external-tool menus (the state lock must not be held while doing that).
    let (pid, rows): (u32, Vec<ModuleInfo>) = {
        let state = app.state.lock().unwrap();
        let query = app.module_search_input.to_lowercase();
        let rows = state
            .modules
            .iter()
            .filter(|m| query.is_empty() || m.name.to_lowercase().contains(&query))
            .cloned()
            .collect();
        (state.target_pid, rows)
    };

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(150.0)) // Name
        .column(Column::initial(150.0)) // Base Addr
        .column(Column::initial(80.0))  // Size
        .column(Column::initial(150.0)) // Entry Point
        .column(Column::initial(60.0))  // Exports
        .column(Column::initial(60.0))  // Imports
        .column(Column::initial(60.0))  // Signed
        .column(Column::remainder())    // Actions
        .header(24.0, |mut header| {
            header.col(|ui| { ui.strong("Name"); });
            header.col(|ui| { ui.strong("Base Address"); });
            header.col(|ui| { ui.strong("Size"); });
            header.col(|ui| { ui.strong("Entry Point"); });
            header.col(|ui| { ui.strong("Exports"); });
            header.col(|ui| { ui.strong("Imports"); });
            header.col(|ui| { ui.strong("Signed?"); });
            header.col(|ui| { ui.strong("Open with"); });
        })
        .body(|body| {
            body.rows(20.0, rows.len(), |mut row| {
                let m = &rows[row.index()];
                row.col(|ui| { ui.label(&m.name); });
                row.col(|ui| { ui.label(format!("0x{:016X}", m.base_address)); });
                row.col(|ui| { ui.label(m.size.to_string()); });
                row.col(|ui| { ui.label(format!("0x{:016X}", m.entry_point)); });
                row.col(|ui| { ui.label(m.num_exports.to_string()); });
                row.col(|ui| { ui.label(m.num_imports.to_string()); });
                row.col(|ui| {
                    if m.signed {
                        ui.label(RichText::new("✔").color(GREEN));
                    } else {
                        ui.label(RichText::new("✘").color(RED_ORANGE));
                    }
                });
                row.col(|ui| {
                    ui.push_id(m.base_address, |ui| {
                        let ctx = ToolContext {
                            file: if m.path.is_empty() {
                                m.name.clone()
                            } else {
                                m.path.clone()
                            },
                            pid,
                            addr: if m.base_address != 0 {
                                m.base_address
                            } else {
                                m.entry_point
                            },
                            module: m.name.clone(),
                            rva: 0,
                            base: m.base_address,
                            func: String::new(),
                            bytes: String::new(),
                            name: m.name.clone(),
                        };
                        tool_menu(ui, app, ToolStage::Disassemble, &ctx, "Disassemble");
                        tool_menu(ui, app, ToolStage::InspectPe, &ctx, "Inspect");
                    });
                });
            });
        });
}
