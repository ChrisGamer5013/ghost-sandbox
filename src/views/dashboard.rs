use egui::{RichText, Layout, Align, Vec2, Frame, Margin};
use egui_plot::{Plot, Line, PlotPoints};
use egui_extras::{TableBuilder, Column};

use crate::app::{
    SandboxApp,
    CYAN, GREEN, CARD_BG, TEXT_DIM, TEXT_BRIGHT
};

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    let state = app.state.lock().unwrap();

    // Top row: 4 stat cards
    ui.horizontal(|ui| {
        let card_size = Vec2::new((ui.available_width() - 30.0) / 4.0, 80.0);
        
        let mut stat_card = |label: &str, value: u64| {
            Frame::NONE
                .fill(CARD_BG)
                .corner_radius(4)
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    ui.set_min_size(card_size);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(label).color(TEXT_DIM).size(14.0));
                        ui.add_space(8.0);
                        ui.label(RichText::new(value.to_string()).color(CYAN).size(24.0).strong());
                    });
                });
        };

        stat_card("API Calls", state.total_api_calls);
        stat_card("Spoofed Queries", state.total_spoofed);
        stat_card("Active Hooks", state.active_hooks as u64);
        stat_card("Memory Patches", state.memory_patches as u64);
    });

    ui.add_space(16.0);

    // Middle: Live graph
    ui.group(|ui| {
        ui.label(RichText::new("API Calls/sec").color(TEXT_BRIGHT).strong());
        ui.add_space(4.0);
        
        let points: PlotPoints = state.api_calls_per_sec.iter().enumerate().map(|(i, &v)| [i as f64, v as f64]).collect();
        let line = Line::new(points).color(CYAN).width(2.0_f32);
        Plot::new("api_calls_plot")
            .view_aspect(4.0)
            .allow_zoom(false)
            .allow_drag(false)
            .show(ui, |plot_ui| plot_ui.line(line));
    });

    ui.add_space(16.0);

    // Bottom split
    ui.horizontal(|ui| {
        let total_width = ui.available_width();
        
        ui.allocate_ui_with_layout(Vec2::new(total_width * 0.7, ui.available_height()), Layout::top_down(Align::Min), |ui| {
            ui.label(RichText::new("Recent Trace Events").strong().color(TEXT_BRIGHT));
            ui.add_space(8.0);
            
            TableBuilder::new(ui)
                .striped(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(80.0))
                .column(Column::initial(60.0))
                .column(Column::initial(150.0))
                .column(Column::initial(150.0))
                .column(Column::initial(100.0))
                .column(Column::remainder())
                .header(24.0, |mut header| {
                    header.col(|ui| { ui.strong("Time"); });
                    header.col(|ui| { ui.strong("Thread"); });
                    header.col(|ui| { ui.strong("Function"); });
                    header.col(|ui| { ui.strong("Module"); });
                    header.col(|ui| { ui.strong("Result"); });
                    header.col(|ui| { ui.strong("Spoofed?"); });
                })
                .body(|body| {
                    let recent_events: Vec<_> = state.trace_events.iter().rev().take(100).collect();
                    body.rows(20.0, recent_events.len(), |mut row| {
                        let ev = recent_events[row.index()];
                        row.col(|ui| { ui.label(&ev.timestamp); });
                        row.col(|ui| { ui.label(&ev.thread_id.to_string()); });
                        row.col(|ui| { ui.label(&ev.function); });
                        row.col(|ui| { ui.label(&ev.module); });
                        row.col(|ui| { ui.label(&ev.return_value); });
                        row.col(|ui| {
                            if ev.spoofed {
                                ui.label(RichText::new("●").color(GREEN));
                            }
                        });
                    });
                });
        });
        
        ui.allocate_ui_with_layout(Vec2::new(total_width * 0.28, ui.available_height()), Layout::top_down(Align::Min), |ui| {
            ui.label(RichText::new("Active Spoofing").strong().color(TEXT_BRIGHT));
            ui.add_space(8.0);
            
            Frame::NONE
                .fill(CARD_BG)
                .corner_radius(4)
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("CPU:").color(TEXT_DIM));
                        ui.label(RichText::new(&state.profile.cpu.brand_string).color(CYAN));
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("GPU:").color(TEXT_DIM));
                        ui.label(RichText::new(&state.profile.gpu.name).color(CYAN));
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("RAM Total:").color(TEXT_DIM));
                        ui.label(RichText::new(format!("{} GB", state.profile.memory.total_gb)).color(CYAN));
                    });
                });
        });
    });
}
