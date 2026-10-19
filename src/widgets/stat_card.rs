use egui::{Color32, CornerRadius, Stroke, Vec2};
use crate::app::{CARD_BG, BORDER, TEXT_DIM};

pub fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    let size = Vec2::new(180.0, 80.0);
    let (rect, _response) = ui.allocate_exact_size(size, egui::Sense::hover());
    
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            CornerRadius::same(8),
            CARD_BG,
            Stroke::new(1.0_f32, BORDER),
            egui::StrokeKind::Middle,
        );
        
        let label_pos = rect.min + Vec2::new(10.0, 10.0);
        ui.painter().text(
            label_pos,
            egui::Align2::LEFT_TOP,
            label,
            egui::FontId::proportional(14.0),
            TEXT_DIM,
        );
        
        let value_pos = rect.min + Vec2::new(10.0, 35.0);
        ui.painter().text(
            value_pos,
            egui::Align2::LEFT_TOP,
            value,
            egui::FontId::proportional(24.0),
            color,
        );
    }
}
