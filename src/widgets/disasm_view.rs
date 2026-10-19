use egui::{Color32, FontId, RichText};
use crate::app::{CYAN, GREEN, YELLOW, TEXT_DIM, TEXT_BRIGHT};

pub enum DisasmAction {
    PatchToJmp(u64),
    PatchToNop(u64, usize),
}

pub fn disasm_view(ui: &mut egui::Ui, instructions: &[crate::disasm::Instruction]) -> Option<DisasmAction> {
    let mut action = None;
    let font = FontId::monospace(13.0);
    
    egui::ScrollArea::vertical().show(ui, |ui| {
        for inst in instructions {
            ui.horizontal(|ui| {
                let mut bg_color = Color32::TRANSPARENT;
                
                if inst.is_conditional_jump {
                    bg_color = YELLOW.linear_multiply(0.2);
                }
                
                let addr_str = format!("{:016X}", inst.address);
                ui.label(RichText::new(addr_str).font(font.clone()).color(TEXT_DIM));
                ui.label(RichText::new(" | ").font(font.clone()).color(TEXT_DIM));
                
                let mut bytes_str = String::new();
                for b in &inst.bytes {
                    bytes_str.push_str(&format!("{:02X} ", b));
                }
                let pad = 3 * 15 - bytes_str.len();
                if pad > 0 {
                    bytes_str.push_str(&" ".repeat(pad));
                }
                ui.label(RichText::new(bytes_str).font(font.clone()).color(TEXT_DIM));
                ui.label(RichText::new(" | ").font(font.clone()).color(TEXT_DIM));
                
                let mut fg_color = TEXT_BRIGHT;
                if inst.is_call { fg_color = CYAN; }
                else if inst.is_jump && !inst.is_conditional_jump { fg_color = GREEN; }
                
                let text = format!("{} {}", inst.mnemonic, inst.operands);
                let label_text = RichText::new(text).font(font.clone()).color(fg_color).background_color(bg_color);
                
                ui.label(label_text);
                
                if inst.is_conditional_jump {
                    if ui.button("→ JMP").clicked() {
                        action = Some(DisasmAction::PatchToJmp(inst.address));
                    }
                }
            });
        }
    });
    
    action
}
