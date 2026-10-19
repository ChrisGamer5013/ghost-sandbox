/*
   Ghost Sandbox — DRM / Anti-Tamper Monitor view.
   Renders EVT_DRM events: integrity checks, verification calls, anti-debug
   probes and fingerprinting, with caller attribution, the benign expectation
   versus what the target actually received, and a verdict per event.
*/

use egui::{Align, Layout, RichText};
use egui_extras::{Column, TableBuilder};

use crate::app::{
    drm_category_name, drm_severity_name, drm_verdict_name, DrmEvent, SandboxApp,
    CYAN, GREEN, RED_ORANGE, TEXT_DIM, TEXT_BRIGHT, YELLOW,
};
use crate::pipe_server::PipeCommand;
use crate::tools::ToolStage;
use crate::views::integrations_view::{caller_context, tool_menu};

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    // ── Header: mode toggle ─────────────────────────────
    ui.horizontal(|ui| {
        ui.heading(RichText::new("Anti-Tamper / DRM Monitor").color(CYAN));
        ui.add_space(12.0);

        let mut enabled = app.state.lock().unwrap().drm_enabled;
        if ui
            .checkbox(&mut enabled, "DRM Mode")
            .on_hover_text("Toggle the shim's DRM/anti-tamper watch hooks")
            .changed()
        {
            let msg = set_drm_mode(app, enabled);
            app.state.lock().unwrap().status_message = msg;
        }
    });

    ui.label(
        RichText::new(
            "Catches integrity checks, signature/checksum verification, debugger probes, \
             module scans, timing checks and host-fingerprint queries. Every hit reports \
             which module called it, the benign expectation and what was actually returned.",
        )
        .color(TEXT_DIM)
        .size(12.0),
    );
    ui.add_space(6.0);

    // ── Filter bar ──────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label("Category:");
        egui::ComboBox::from_id_salt("drm_category_combo")
            .selected_text(category_filter_label(app.drm_category_filter))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.drm_category_filter, 0, "All");
                for c in 1..=8u32 {
                    ui.selectable_value(
                        &mut app.drm_category_filter,
                        c,
                        drm_category_name(c),
                    );
                }
            });

        ui.checkbox(&mut app.drm_show_detections_only, "Detections only");

        ui.label("Search:");
        ui.text_edit_singleline(&mut app.drm_filter);

        ui.label("Caller:");
        ui.text_edit_singleline(&mut app.drm_filter_caller);

        if ui.button("Clear").clicked() {
            let mut s = app.state.lock().unwrap();
            s.drm_events.clear();
            s.drm_total = 0;
            s.drm_detections = 0;
            s.drm_last_alert = None;
        }
        if ui
            .button("Export Report")
            .on_hover_text("Write a JSON analysis report (summary + all events)")
            .clicked()
        {
            match export_report(app) {
                Ok(path) => {
                    app.state.lock().unwrap().status_message =
                        format!("DRM report exported to {}", path);
                }
                Err(e) if e == "Export cancelled"=> {}
                Err(e) => app.state.lock().unwrap().status_message = e,
            }
        }

        // External-tool handoff for the caller selected in the table.
        if let Some((module, rva, api)) = app.drm_selected_caller.clone() {
            ui.separator();
            ui.label(
                RichText::new(format!("{}+0x{:X}", module, rva))
                    .color(CYAN)
                    .size(11.0),
            )
            .on_hover_text(format!("Selected caller of {}", api));
            let ctx = caller_context(app, &module, rva, &api);
            tool_menu(ui, app, ToolStage::Disassemble, &ctx, "Disassemble");
            tool_menu(ui, app, ToolStage::Debug, &ctx, "Debug");
            if ui.small_button("✖").on_hover_text("Clear selection").clicked() {
                app.drm_selected_caller = None;
            }
        }
    });

    ui.add_space(8.0);

    // ── Locked snapshot for summary + table ─────────────
    // Row clicks are collected here and applied once the state lock drops.
    let mut open_click: Option<(String, u64, String)> = None;
    {
    let state = app.state.lock().unwrap();

    let mut cat_counts = [0u64; 9];
    for e in &state.drm_events {
        let idx = (e.category as usize).min(8);
        cat_counts[idx] += 1;
    }

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("Watched calls: {}", state.drm_total))
                .color(TEXT_BRIGHT)
                .strong(),
        );
        ui.separator();
        ui.label(
            RichText::new(format!("Detections: {}", state.drm_detections))
                .color(if state.drm_detections > 0 { RED_ORANGE } else { GREEN })
                .strong(),
        );
        ui.separator();
        for c in 1..=8u32 {
            let n = cat_counts[c as usize];
            if n > 0 {
                ui.label(
                    RichText::new(format!("{}: {}", drm_category_name(c), n))
                        .color(category_color(c))
                        .size(12.0),
                );
            }
        }
    });

    if let Some(alert) = &state.drm_last_alert {
        ui.label(RichText::new(format!("Last alert: {}", alert)).color(RED_ORANGE).size(12.0));
    }
    ui.add_space(6.0);

    let filtered: Vec<&DrmEvent> = state
        .drm_events
        .iter()
        .rev() // newest first
        .filter(|e| {
            if app.drm_category_filter != 0 && e.category != app.drm_category_filter {
                return false;
            }
            if app.drm_show_detections_only && e.verdict != 1 {
                return false;
            }
            if !app.drm_filter.is_empty() {
                let q = app.drm_filter.to_lowercase();
                if !e.api.to_lowercase().contains(&q)
                    && !e.expected.to_lowercase().contains(&q)
                    && !e.returned.to_lowercase().contains(&q)
                    && !e.detail.to_lowercase().contains(&q)
                {
                    return false;
                }
            }
            if !app.drm_filter_caller.is_empty()
                && !e
                    .caller_module
                    .to_lowercase()
                    .contains(&app.drm_filter_caller.to_lowercase())
            {
                return false;
            }
            true
        })
        .collect();

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(76.0))  // Time
        .column(Column::initial(86.0))  // Category
        .column(Column::initial(56.0))  // Severity
        .column(Column::initial(168.0)) // API
        .column(Column::initial(148.0)) // Caller
        .column(Column::initial(70.0))  // Verdict
        .column(Column::initial(210.0)) // Expected
        .column(Column::initial(170.0)) // Returned
        .column(Column::remainder())    // Detail
        .header(24.0, |mut header| {
            header.col(|ui| { ui.strong("Time"); });
            header.col(|ui| { ui.strong("Category"); });
            header.col(|ui| { ui.strong("Severity"); });
            header.col(|ui| { ui.strong("API"); });
            header.col(|ui| { ui.strong("Called By"); });
            header.col(|ui| { ui.strong("Verdict"); });
            header.col(|ui| { ui.strong("Expected"); });
            header.col(|ui| { ui.strong("Returned"); });
            header.col(|ui| { ui.strong("Detail"); });
        })
        .body(|body| {
            body.rows(20.0, filtered.len(), |mut row| {
                let e = filtered[row.index()];
                row.col(|ui| {
                    ui.label(&e.timestamp);
                });
                row.col(|ui| {
                    ui.label(
                        RichText::new(drm_category_name(e.category)).color(category_color(e.category)),
                    );
                });
                row.col(|ui| {
                    ui.label(
                        RichText::new(drm_severity_name(e.severity))
                            .color(severity_color(e.severity))
                            .size(12.0),
                    );
                });
                row.col(|ui| {
                    ui.label(&e.api).on_hover_text(format!(
                        "{}!{}\nraw return: 0x{:X}",
                        e.api_module, e.api, e.ret_value
                    ));
                });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}+0x{:X}", e.caller_module, e.caller_rva))
                            .on_hover_text(format!(
                                "Caller: {} at base+0x{:X}",
                                e.caller_module, e.caller_rva
                            ));
                        if ui
                            .small_button("◎")
                            .on_hover_text(
                                "Select this caller — then open it in the Memory Editor or an external tool",
                            )
                            .clicked()
                        {
                            open_click = Some((
                                e.caller_module.clone(),
                                e.caller_rva,
                                e.api.clone(),
                            ));
                        }
                    });
                });
                row.col(|ui| {
                    ui.label(
                        RichText::new(drm_verdict_name(e.verdict))
                            .color(verdict_color(e.verdict))
                            .strong(),
                    );
                });
                row.col(|ui| {
                    ui.label(trunc(&e.expected, 32)).on_hover_text(&e.expected);
                });
                row.col(|ui| {
                    ui.label(trunc(&e.returned, 24)).on_hover_text(&e.returned);
                });
                row.col(|ui| {
                    ui.label(trunc(&e.detail, 40)).on_hover_text(&e.detail);
                });
            });
        });
    }

    if let Some(sel) = open_click {
        app.drm_selected_caller = Some(sel);
    }
}

// ─── Helpers ────────────────────────────────────────────────

fn set_drm_mode(app: &mut SandboxApp, enabled: bool) -> String {
    let mut s = app.state.lock().unwrap();
    s.drm_enabled = enabled;

    if !s.connected {
        return "DRM mode set locally — shim not connected".to_string();
    }
    match app.pipe.send_command(PipeCommand::DrmMode { enabled }) {
        Ok(()) => {
            if enabled {
                "DRM / anti-tamper watch mode ENABLED".to_string()
            } else {
                "DRM / anti-tamper watch mode disabled".to_string()
            }
        }
        Err(e) => format!("Command failed: {}", e),
    }
}

fn category_filter_label(filter: u32) -> String {
    if filter == 0 {
        "All".to_string()
    } else {
        drm_category_name(filter).to_string()
    }
}

fn category_color(c: u32) -> egui::Color32 {
    match c {
        1 => RED_ORANGE, // Integrity
        2 => RED_ORANGE, // Debugger
        3 => TEXT_DIM,   // Timing
        4 => YELLOW,     // Module scan
        5 => CYAN,       // Device
        6 => YELLOW,     // Crypto
        7 => CYAN,       // Environment
        8 => YELLOW,     // Memory
        _ => TEXT_DIM,
    }
}

fn severity_color(s: u32) -> egui::Color32 {
    match s {
        3 => RED_ORANGE,
        2 => YELLOW,
        _ => TEXT_DIM,
    }
}

fn verdict_color(v: u32) -> egui::Color32 {
    match v {
        0 => GREEN,
        1 => RED_ORANGE,
        _ => TEXT_DIM,
    }
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Write a full JSON analysis report (summary + every captured event).
/// Returns the path on success, "Export cancelled" if no file was picked.
pub fn export_report(app: &SandboxApp) -> Result<String, String> {
    let path = rfd::FileDialog::new()
        .add_filter("DRM report (JSON)", &["json"])
        .set_file_name("ghost_drm_report.json")
        .save_file()
        .ok_or_else(|| "Export cancelled".to_string())?;

    let s = app.state.lock().unwrap();

    let mut by_category: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut by_caller: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for e in &s.drm_events {
        *by_category
            .entry(drm_category_name(e.category).to_string())
            .or_insert(0) += 1;
        *by_caller.entry(e.caller_module.clone()).or_insert(0) += 1;
    }

    let events: Vec<serde_json::Value> = s
        .drm_events
        .iter()
        .map(|e| {
            serde_json::json!({
                "time": e.timestamp,
                "category": drm_category_name(e.category),
                "severity": drm_severity_name(e.severity),
                "verdict": drm_verdict_name(e.verdict),
                "api": e.api,
                "api_module": e.api_module,
                "caller_module": e.caller_module,
                "caller_rva": format!("0x{:X}", e.caller_rva),
                "return_value": format!("0x{:X}", e.ret_value),
                "expected": e.expected,
                "returned": e.returned,
                "detail": e.detail,
            })
        })
        .collect();

    let report = serde_json::json!({
        "tool": "Ghost Sandbox",
        "mode": "DRM / Anti-Tamper",
        "generated": chrono::Local::now().to_rfc3339(),
        "target": {
            "name": s.target_name,
            "pid": s.target_pid,
        },
        "summary": {
            "total_events": s.drm_total,
            "detections": s.drm_detections,
            "drm_enabled": s.drm_enabled,
            "by_category": by_category,
            "by_caller": by_caller,
        },
        "events": events,
    });

    let body = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Report serialization failed: {}", e))?;
    std::fs::write(&path, body).map_err(|e| format!("Export failed: {}", e))?;
    Ok(path.display().to_string())
}
