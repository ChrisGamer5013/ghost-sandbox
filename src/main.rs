/*
   Ghost Sandbox v1.0 — GUI Entry Point
   Dynamic Binary Instrumentation, Live Memory Editing, and
   Universal Hardware Identity Spoofing Framework
   
   (c) 2026 Ghost Project
*/

use ghost_sandbox::app::SandboxApp;

fn main() -> eframe::Result<()> {
    // Initialize tracing for debug logs
    tracing_subscriber::fmt()
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Ghost Sandbox v1.0")
            .with_inner_size([1600.0, 1000.0])
            .with_min_inner_size([1200.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Ghost Sandbox",
        native_options,
        Box::new(|cc| {
            // Configure custom fonts and visuals
            let mut style = (*cc.egui_ctx.style()).clone();
            
            // Dark theme colors
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(0x11, 0x18, 0x27);          // #111827
            visuals.window_fill = egui::Color32::from_rgb(0x0a, 0x0e, 0x17);         // #0a0e17
            visuals.extreme_bg_color = egui::Color32::from_rgb(0x06, 0x08, 0x10);    // #060810
            visuals.faint_bg_color = egui::Color32::from_rgb(0x16, 0x21, 0x3e);      // #16213e
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(0x11, 0x18, 0x27);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x1e, 0x29, 0x3b);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x0f, 0x34, 0x60);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0x00, 0xd4, 0xff);
            visuals.selection.bg_fill = egui::Color32::from_rgb(0x00, 0xd4, 0xff).gamma_multiply(0.3);
            visuals.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0x00, 0xd4, 0xff));
            
            style.visuals = visuals;
            
            // Increase spacing slightly for readability
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            
            cc.egui_ctx.set_style(style);
            
            Ok(Box::new(SandboxApp::new(cc)))
        }),
    )
}
