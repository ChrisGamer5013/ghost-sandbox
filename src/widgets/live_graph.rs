use std::collections::VecDeque;
use egui::{Color32, CornerRadius, Frame, Stroke, Vec2b};
use egui_plot::{Line, Plot, PlotPoints};
use crate::app::{CARD_BG, BORDER};

pub fn live_graph(ui: &mut egui::Ui, title: &str, data: &VecDeque<f64>, color: Color32) {
    let points: PlotPoints = data
        .iter()
        .enumerate()
        .map(|(i, &v)| [i as f64, v])
        .collect();
        
    let line = Line::new(points).color(color).width(2.0_f32);
    
    Frame::NONE
        .fill(CARD_BG)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(8.0)
        .show(ui, |ui| {
            Plot::new(title)
                .allow_drag(false)
                .allow_zoom(false)
                .auto_bounds(Vec2b::TRUE)
                .show_axes([true, true])
                .show(ui, |plot_ui| plot_ui.line(line));
        });
}
