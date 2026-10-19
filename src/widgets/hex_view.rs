use egui::{FontId, Label, RichText};
use crate::app::{TEXT_DIM, TEXT_BRIGHT, RED_ORANGE};

pub fn hex_view(ui: &mut egui::Ui, data: &[u8], base_address: u64, modified_offsets: &[usize]) -> Option<usize> {
    let mut clicked_offset = None;
    let font = FontId::monospace(13.0);
    
    egui::ScrollArea::vertical().show(ui, |ui| {
        for chunk_idx in 0..(data.len() + 15) / 16 {
            let start = chunk_idx * 16;
            let end = std::cmp::min(start + 16, data.len());
            let chunk = &data[start..end];
            let addr = base_address + start as u64;
            
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{:016X}  ", addr)).font(font.clone()).color(TEXT_DIM));
                
                for (i, &byte) in chunk.iter().enumerate() {
                    let offset = start + i;
                    let color = if modified_offsets.contains(&offset) { RED_ORANGE } else { TEXT_BRIGHT };
                    
                    if i == 8 {
                        ui.label(RichText::new(" ").font(font.clone()));
                    }
                    
                    let byte_text = format!("{:02X}", byte);
                    let response = ui.add(Label::new(RichText::new(&byte_text).font(font.clone()).color(color)).sense(egui::Sense::click()));
                    if response.clicked() {
                        clicked_offset = Some(offset);
                    }
                    
                    ui.label(RichText::new(" ").font(font.clone()));
                }
                
                let missing = 16 - chunk.len();
                if missing > 0 {
                    let padding_len = missing * 3 + if missing >= 8 { 1 } else { 0 };
                    ui.label(RichText::new(" ".repeat(padding_len)).font(font.clone()));
                }
                
                ui.label(RichText::new(" |").font(font.clone()).color(TEXT_DIM));
                
                for &byte in chunk.iter() {
                    let ascii = if (32..=126).contains(&byte) { byte as char } else { '.' };
                    ui.label(RichText::new(ascii.to_string()).font(font.clone()).color(TEXT_BRIGHT));
                }
                ui.label(RichText::new("|").font(font.clone()).color(TEXT_DIM));
            });
        }
    });
    
    clicked_offset
}
