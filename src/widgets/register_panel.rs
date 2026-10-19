use egui::{FontId, RichText};
use crate::app::{CYAN, YELLOW, TEXT_DIM};

pub fn register_panel(ui: &mut egui::Ui, regs: &crate::app::RegisterState, prev_regs: Option<&crate::app::RegisterState>) {
    let font = FontId::monospace(13.0);
    
    let reg_names = [
        "RAX", "RBX", "RCX", "RDX",
        "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11",
        "R12", "R13", "R14", "R15",
        "RIP", "RFLAGS"
    ];
    
    let get_val = |r: &crate::app::RegisterState, name: &str| -> u64 {
        match name {
            "RAX" => r.rax, "RBX" => r.rbx, "RCX" => r.rcx, "RDX" => r.rdx,
            "RSI" => r.rsi, "RDI" => r.rdi, "RBP" => r.rbp, "RSP" => r.rsp,
            "R8" => r.r8, "R9" => r.r9, "R10" => r.r10, "R11" => r.r11,
            "R12" => r.r12, "R13" => r.r13, "R14" => r.r14, "R15" => r.r15,
            "RIP" => r.rip, "RFLAGS" => r.rflags,
            _ => 0,
        }
    };
    
    egui::Grid::new("register_grid").num_columns(4).show(ui, |ui| {
        for (i, &name) in reg_names.iter().enumerate() {
            let val = get_val(regs, name);
            let prev_val = prev_regs.map(|pr| get_val(pr, name)).unwrap_or(val);
            
            let changed = val != prev_val;
            let val_color = if changed { YELLOW } else { CYAN };
            
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{:6}", name)).font(font.clone()).color(TEXT_DIM));
                ui.label(RichText::new("=").font(font.clone()).color(TEXT_DIM));
                ui.label(RichText::new(format!("{:016X}", val)).font(font.clone()).color(val_color));
            });
            
            if (i + 1) % 4 == 0 {
                ui.end_row();
            }
        }
    });
}
