use egui::{RichText, Layout, Align};
use egui_extras::{TableBuilder, Column};

use crate::app::{SandboxApp, TraceEvent, GREEN};
use crate::tools::ToolStage;
use crate::views::integrations_view::tool_menu;

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    // Top filter bar
    ui.horizontal(|ui| {
        ui.label("Function:");
        ui.text_edit_singleline(&mut app.trace_filter);
        
        ui.label("Module:");
        ui.text_edit_singleline(&mut app.trace_filter_module);
        
        ui.checkbox(&mut app.trace_show_spoofed_only, "Spoofed only");
        
        if ui.button("Clear").clicked() {
            let mut state = app.state.lock().unwrap();
            state.trace_events.clear();
            state.total_api_calls = 0;
            state.total_spoofed = 0;
        }
        if ui.button("Export").clicked() {
            match export_csv(&app.state) {
                Ok(path) => {
                    let msg = format!("Exported trace to {}", path);
                    app.state.lock().unwrap().status_message = msg;
                }
                Err(e) if e == "Export cancelled"=> {}
                Err(e) => {
                    app.state.lock().unwrap().status_message = e;
                }
            }
        }

        // External-tool handoff for the module/function picked in the table.
        if let Some((module, func)) = app.trace_selected_module.clone() {
            ui.separator();
            ui.label(
                RichText::new(format!("{}!{}", module, func))
                    .color(crate::app::CYAN)
                    .size(11.0),
            );
            let ctx = crate::views::integrations_view::context_for(app, 0, &module, 0, &func);
            tool_menu(ui, app, ToolStage::Disassemble, &ctx, "Disassemble");
            tool_menu(ui, app, ToolStage::Debug, &ctx, "Debug");
            if ui.small_button("✖").on_hover_text("Clear selection").clicked() {
                app.trace_selected_module = None;
            }
        }
    });

    ui.add_space(8.0);

    // Row clicks are collected here and applied once the state lock drops.
    let mut open_click: Option<(String, String)> = None;
    {
    let state = app.state.lock().unwrap();

    let filtered_events: Vec<&TraceEvent> = state.trace_events.iter()
        .filter(|e| {
            if !app.trace_filter.is_empty() && !e.function.to_lowercase().contains(&app.trace_filter.to_lowercase()) {
                return false;
            }
            if !app.trace_filter_module.is_empty() && !e.module.to_lowercase().contains(&app.trace_filter_module.to_lowercase()) {
                return false;
            }
            if app.trace_show_spoofed_only && !e.spoofed {
                return false;
            }
            true
        })
        .collect();

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(80.0)) // Timestamp
        .column(Column::initial(60.0)) // Thread
        .column(Column::initial(150.0)) // Function
        .column(Column::initial(100.0)) // Module
        .column(Column::initial(200.0)) // Parameters
        .column(Column::initial(100.0)) // Return Value
        .column(Column::initial(80.0))  // Duration
        .column(Column::remainder())    // Spoofed
        .header(24.0, |mut header| {
            header.col(|ui| { ui.strong("Timestamp"); });
            header.col(|ui| { ui.strong("Thread"); });
            header.col(|ui| { ui.strong("Function"); });
            header.col(|ui| { ui.strong("Source Module"); });
            header.col(|ui| { ui.strong("Parameters"); });
            header.col(|ui| { ui.strong("Return Value"); });
            header.col(|ui| { ui.strong("Duration µs"); });
            header.col(|ui| { ui.strong("Spoofed?"); });
        })
        .body(|body| {
            body.rows(20.0, filtered_events.len(), |mut row| {
                let ev = filtered_events[row.index()];
                row.col(|ui| { ui.label(&ev.timestamp); });
                row.col(|ui| { ui.label(&ev.thread_id.to_string()); });
                row.col(|ui| { ui.label(&ev.function); });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(&ev.module);
                        if ui
                            .small_button("◎")
                            .on_hover_text(
                                "Select this module/function — then open it in the Memory Editor or an external tool",
                            )
                            .clicked()
                        {
                            open_click = Some((ev.module.clone(), ev.function.clone()));
                        }
                    });
                });
                row.col(|ui| { 
                    let p = if ev.params.len() > 30 {
                        format!("{}...", &ev.params[..30])
                    } else {
                        ev.params.clone()
                    };
                    ui.label(p); 
                });
                row.col(|ui| { ui.label(&ev.return_value); });
                row.col(|ui| { ui.label(&ev.duration_us.to_string()); });
                row.col(|ui| {
                    if ev.spoofed {
                        ui.label(RichText::new("●").color(GREEN));
                    }
                });
            });
        });
    }

    if let Some(sel) = open_click {
        app.trace_selected_module = Some(sel);
    }
}

/// Write the (unfiltered) trace log to a CSV file chosen by the user.
/// Returns the path on success, "Export cancelled" if no file was picked.
pub fn export_csv(
    state: &std::sync::Arc<std::sync::Mutex<crate::app::AppState>>,
) -> Result<String, String> {
    let path = rfd::FileDialog::new()
        .add_filter("Trace CSV", &["csv"])
        .set_file_name("ghost_trace.csv")
        .save_file()
        .ok_or_else(|| "Export cancelled".to_string())?;

    let csv_body = {
        let s = state.lock().unwrap();
        let mut w = String::new();
        w.push_str("timestamp,thread,function,module,params,return_value,duration_us,spoofed\n");
        for ev in &s.trace_events {
            w.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                ev.timestamp,
                ev.thread_id,
                ev.function.replace(',', ";"),
                ev.module.replace(',', ";"),
                ev.params.replace(',', ";").replace('\n', ""),
                ev.return_value.replace(',', ";"),
                ev.duration_us,
                ev.spoofed as u8,
            ));
        }
        w
    };

    std::fs::write(&path, csv_body).map_err(|e| format!("Export failed: {}", e))?;
    Ok(path.display().to_string())
}
