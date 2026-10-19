/*
   Ghost Sandbox — Live Memory Editor.

   Reads and writes the instrumented target's memory through the shim:
   hex dump + disassembly (client-side), byte patches, NOP/JZ→JMP rewrites,
   register snapshots, in-dump pattern search and dump export.

   Since the CLI exposes the same operations (ghost run --dump/--patch/--nop/
   --jmp) this view and the CLI share one protocol path.
*/

use egui::{RichText, ScrollArea, FontFamily, FontId};

use crate::app::{SandboxApp, YELLOW, CYAN, GREEN, TEXT_DIM, RED_ORANGE};
use crate::disasm::disassemble;
use crate::pipe_server::PipeCommand;

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    // Commands are collected while rendering and sent after the state lock
    // is released, so a shim callback can never deadlock against the UI.
    let mut commands: Vec<PipeCommand> = Vec::new();
    let mut status: Option<String> = None;

    // "main" in a module-relative address means the loaded sample.
    let main_name = std::path::Path::new(&app.sandbox.sample_path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let resolve = |input: &str, app: &SandboxApp| -> Option<u64> {
        let st = app.state.lock().unwrap();
        resolve_target_addr(input, &st, &main_name)
    };

    ui.horizontal(|ui| {
        ui.label("Address:");
        ui.text_edit_singleline(&mut app.memory_addr_input)
            .on_hover_text("Absolute (0x140001000) or module-relative (main+0x40, mylib.dll+0x1234)");
        if ui
            .button("Go")
            .on_hover_text("Dump memory at this address")
            .clicked()
        {
            match resolve(&app.memory_addr_input, app) {
                Some(addr) => {
                    let len = parse_dump_len(&app.memory_dump_len);
                    commands.push(PipeCommand::Dump { address: addr, length: len });
                    status = Some(format!("Dumping {} bytes at 0x{:016X}…", len, addr));
                }
                None => status = Some(
                    "Unknown address — use hex, or module+offset (e.g. main+0x40)".into(),
                ),
            }
        }

        ui.label("Bytes:");
        ui.add(
            egui::TextEdit::singleline(&mut app.memory_dump_len)
                .desired_width(64.0)
                .hint_text("4096"),
        )
        .on_hover_text("Dump size: 16..4096 bytes");

        if ui
            .button("⟳ Registers")
            .on_hover_text("Capture a live register snapshot of the target's main thread")
            .clicked()
        {
            commands.push(PipeCommand::GetRegisters { thread_id: 0 });
            status = Some("Capturing registers…".into());
        }

        // Hand the current address off to Ghost itself or an external tool.
        if let Some(a) = resolve(&app.memory_addr_input, app) {
            let ctx = crate::views::integrations_view::context_for(app, a, "", 0, "");
            crate::views::integrations_view::tool_menu(
                ui,
                app,
                crate::tools::ToolStage::Disassemble,
                &ctx,
                "Disassemble",
            );
            crate::views::integrations_view::tool_menu(
                ui,
                app,
                crate::tools::ToolStage::MemoryEdit,
                &ctx,
                "Edit in…",
            );
            crate::views::integrations_view::tool_menu(
                ui,
                app,
                crate::tools::ToolStage::HexView,
                &ctx,
                "Hex view",
            );
        }
    });

    ui.horizontal(|ui| {
        ui.separator();

        ui.label("NOP len:");
        ui.text_edit_singleline(&mut app.memory_patch_input);

        let addr = resolve(&app.memory_addr_input, app);

        if ui
            .button("NOP Selection")
            .on_hover_text("Replace N bytes at the address with 0x90")
            .clicked()
        {
            match addr {
                Some(a) => {
                    let len = parse_len(&app.memory_patch_input);
                    commands.push(PipeCommand::PatchNop { address: a, length: len });
                    status = Some(format!("NOP {} byte(s) at 0x{:016X}", len, a));
                }
                None => status = Some("Invalid address".into()),
            }
        }
        if ui
            .button("JZ→JMP")
            .on_hover_text("Turn the conditional jump at the address into an unconditional JMP")
            .clicked()
        {
            match addr {
                Some(a) => {
                    commands.push(PipeCommand::PatchJmp { address: a });
                    status = Some(format!("JZ→JMP at 0x{:016X}", a));
                }
                None => status = Some("Invalid address".into()),
            }
        }
        if ui.button("JNZ→JMP").clicked() {
            match addr {
                Some(a) => {
                    commands.push(PipeCommand::PatchJmp { address: a });
                    status = Some(format!("JNZ→JMP at 0x{:016X}", a));
                }
                None => status = Some("Invalid address".into()),
            }
        }

        ui.separator();

        ui.label("Write Bytes:");
        ui.text_edit_singleline(&mut app.hex_bytes_input);
        if ui
            .button("Write")
            .on_hover_text("Write raw bytes at the address (hex, e.g. \"90 90 CC\")")
            .clicked()
        {
            match (addr, parse_hex_bytes(&app.hex_bytes_input)) {
                (Some(a), Some(bytes)) if !bytes.is_empty() => {
                    if bytes.len() > 256 {
                        status = Some("Max 256 bytes per patch".into());
                    } else {
                        let n = bytes.len();
                        commands.push(PipeCommand::Patch { address: a, bytes });
                        status = Some(format!("Writing {} byte(s) at 0x{:016X}", n, a));
                    }
                }
                _ => {
                    status = Some("Need a valid address + hex bytes (e.g. \"90 90 CC\")".into())
                }
            }
        }
    });

    ui.horizontal(|ui| {
        ui.separator();
        ui.label("Find:");
        ui.add(
            egui::TextEdit::singleline(&mut app.memory_search)
                .desired_width(220.0)
                .hint_text("text, or hex (\"90 90\", \"hex:DEADBEEF\")"),
        )
        .on_hover_text("Search inside the current dump. Prefix hex: / text: to force a mode.");

        let connected = app.state.lock().unwrap().connected;
        ui.separator();
        if connected {
            ui.label(RichText::new("● target connected").color(GREEN).size(11.0));
        } else {
            ui.label(
                RichText::new("○ no target — inject one to read/write memory")
                    .color(RED_ORANGE)
                    .size(11.0),
            );
        }
    });

    ui.add_space(8.0);

    // Actions requested by widgets inside the state lock, applied after it.
    let mut jump_to: Option<u64> = None;
    let mut save_request = false;
    let mut dump_snapshot: Option<(u64, Vec<u8>)> = None;
    let mut search_hits: Vec<(u64, String)> = Vec::new();

    {
        let state = app.state.lock().unwrap();
        let memory_data = &state.memory_data;
        let base_addr = state.memory_address;

        // Pattern search (runs while the lock is held; pure computation).
        if !memory_data.is_empty() {
            if let Some(needle) = parse_search(&app.memory_search) {
                let matches = find_matches(memory_data, &needle);
                for off in matches.into_iter().take(64) {
                    let addr = base_addr + off as u64;
                    let ctx_lo = off.saturating_sub(4);
                    let ctx_hi = (off + 16).min(memory_data.len());
                    let ctx: String = memory_data[ctx_lo..ctx_hi]
                        .iter()
                        .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
                        .collect();
                    search_hits.push((addr, ctx));
                }
            }
        }

        ui.columns(2, |cols| {
            // Left: Hex dump
            cols[0].group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Hex Dump");
                    if ui
                        .small_button("Save…")
                        .on_hover_text("Save the current dump (.txt hex dump, or .bin raw bytes)")
                        .clicked()
                    {
                        save_request = true;
                    }
                    ui.label(
                        RichText::new(format!("{} bytes @ 0x{:016X}", memory_data.len(), base_addr))
                            .color(TEXT_DIM)
                            .size(11.0),
                    );
                });
                ScrollArea::vertical()
                    .id_salt("hex_dump_scroll")
                    .max_height(420.0)
                    .show(ui, |ui| {
                        ui.style_mut().override_font_id =
                            Some(FontId::new(14.0, FontFamily::Monospace));

                        if memory_data.is_empty() {
                            ui.label(
                                RichText::new("No data — enter an address and press Go")
                                    .color(TEXT_DIM),
                            );
                        }

                        for (i, chunk) in memory_data.chunks(16).enumerate() {
                            ui.horizontal(|ui| {
                                let addr = base_addr + (i * 16) as u64;
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new(format!("{:016X}", addr))
                                                .color(TEXT_DIM)
                                                .monospace(),
                                        )
                                        .frame(false),
                                    )
                                    .on_hover_text("Click to jump to this address")
                                    .clicked()
                                {
                                    jump_to = Some(addr);
                                }

                                let mut hex_str = String::new();
                                let mut ascii_str = String::new();
                                for &b in chunk {
                                    hex_str.push_str(&format!("{:02X} ", b));
                                    if b.is_ascii_graphic() || b == b' ' {
                                        ascii_str.push(b as char);
                                    } else {
                                        ascii_str.push('.');
                                    }
                                }

                                if chunk.len() < 16 {
                                    for _ in 0..(16 - chunk.len()) {
                                        hex_str.push_str("   ");
                                    }
                                }

                                ui.label(hex_str);
                                ui.label(RichText::new(ascii_str).color(TEXT_DIM));
                            });
                        }
                    });

                // Search results
                if !search_hits.is_empty() {
                    ui.separator();
                    ui.label(
                        RichText::new(format!("{} match(es) in dump", search_hits.len()))
                            .color(CYAN)
                            .size(11.0),
                    );
                    ScrollArea::vertical()
                        .id_salt("search_hits_scroll")
                        .max_height(120.0)
                        .show(ui, |ui| {
                            ui.style_mut().override_font_id =
                                Some(FontId::new(12.0, FontFamily::Monospace));
                            for (addr, ctx) in &search_hits {
                                if ui
                                    .small_button(format!("{:016X}  {}", addr, ctx))
                                    .clicked()
                                {
                                    jump_to = Some(*addr);
                                }
                            }
                        });
                }
            });

            // Right: Disassembly
            cols[1].group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Disassembly");
                    ui.label(
                        RichText::new(format!("{} patch(es) applied", state.memory_patches))
                            .color(TEXT_DIM)
                            .size(11.0),
                    );
                });
                ScrollArea::vertical()
                    .id_salt("disasm_scroll")
                    .max_height(420.0)
                    .show(ui, |ui| {
                        ui.style_mut().override_font_id =
                            Some(FontId::new(14.0, FontFamily::Monospace));

                        if memory_data.is_empty() {
                            ui.label(
                                RichText::new("No data — enter an address and press Go")
                                    .color(TEXT_DIM),
                            );
                        }

                        let instructions = disassemble(memory_data, base_addr, 200);
                        for inst in instructions {
                            ui.horizontal(|ui| {
                                ui.label(format!("{:016X}", inst.address));
                                ui.label(inst.bytes_hex());

                                let is_cond_jump = inst.display().starts_with("jz")
                                    || inst.display().starts_with("jnz");
                                if is_cond_jump {
                                    ui.label(RichText::new(inst.display()).color(YELLOW));
                                    if ui.button("→ JMP").clicked() {
                                        commands.push(PipeCommand::PatchJmp {
                                            address: inst.address,
                                        });
                                        status =
                                            Some(format!("JZ/JNZ→JMP at 0x{:016X}", inst.address));
                                    }
                                } else {
                                    ui.label(inst.display());
                                }
                            });
                        }
                    });
            });
        });

        ui.add_space(8.0);

        // Bottom: Register panel
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Registers");
                ui.label(
                    RichText::new("press ⟳ Registers to snapshot the main thread")
                        .color(TEXT_DIM)
                        .size(11.0),
                );
            });
            ui.style_mut().override_font_id = Some(FontId::new(14.0, FontFamily::Monospace));

            let regs = &state.registers;
            egui::Grid::new("registers_grid")
                .num_columns(8)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    let add_reg = |ui: &mut egui::Ui, name: &str, val: u64| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(name).color(TEXT_DIM));
                            ui.label(RichText::new(format!("{:016X}", val)).color(CYAN));
                        });
                    };

                    add_reg(ui, "RAX", regs.rax); add_reg(ui, "RCX", regs.rcx);
                    add_reg(ui, "RDX", regs.rdx); add_reg(ui, "RBX", regs.rbx);
                    add_reg(ui, "RSP", regs.rsp); add_reg(ui, "RBP", regs.rbp);
                    add_reg(ui, "RSI", regs.rsi); add_reg(ui, "RDI", regs.rdi);
                    ui.end_row();
                    add_reg(ui, "R8", regs.r8);   add_reg(ui, "R9", regs.r9);
                    add_reg(ui, "R10", regs.r10); add_reg(ui, "R11", regs.r11);
                    add_reg(ui, "R12", regs.r12); add_reg(ui, "R13", regs.r13);
                    add_reg(ui, "R14", regs.r14); add_reg(ui, "R15", regs.r15);
                    ui.end_row();
                    add_reg(ui, "RIP", regs.rip);
                    add_reg(ui, "EFLAGS", regs.rflags);
                });
        });

        if save_request && !memory_data.is_empty() {
            dump_snapshot = Some((base_addr, memory_data.clone()));
        }
    }

    // Jump requests just move the address box (press Go to dump there).
    if let Some(addr) = jump_to {
        app.memory_addr_input = format!("0x{:016X}", addr);
        status = Some(format!("Address set to 0x{:016X} — press Go to dump", addr));
    }

    // Save dump (outside the state lock).
    if let Some((base, data)) = dump_snapshot {
        save_dump(&base, &data, &mut status);
    }

    // Send collected commands now that no state lock is held.
    for cmd in commands {
        if let Err(e) = app.pipe.send_command(cmd) {
            status = Some(format!("Command failed: {}", e));
        }
    }
    if let Some(msg) = status {
        app.state.lock().unwrap().status_message = msg;
    }
}

// ─── Dump export ────────────────────────────────────────────

fn save_dump(base: &u64, data: &[u8], status: &mut Option<String>) {
    let default_name = format!("dump_{:016X}.txt", base);
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(&default_name)
        .save_file()
    else {
        return;
    };
    let is_bin = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("bin"))
        .unwrap_or(false);

    let result = if is_bin {
        std::fs::write(&path, data).map(|_| data.len())
    } else {
        let mut text = format!(
            "# Ghost Sandbox memory dump\n# base 0x{:016X}  length {} bytes\n",
            base,
            data.len()
        );
        for (i, chunk) in data.chunks(16).enumerate() {
            let addr = base + (i * 16) as u64;
            let mut hex = String::new();
            let mut ascii = String::new();
            for &b in chunk {
                hex.push_str(&format!("{:02X} ", b));
                ascii.push(if (0x20..0x7F).contains(&b) { b as char } else { '.' });
            }
            text.push_str(&format!("{:016X}  {:<48} {}\n", addr, hex, ascii));
        }
        std::fs::write(&path, text).map(|_| data.len())
    };

    *status = Some(match result {
        Ok(n) => format!("Dump saved ({} bytes) → {}", n, path.display()),
        Err(e) => format!("Save failed: {}", e),
    });
}

// ─── Parsing helpers ────────────────────────────────────────

/// Resolve the address box: absolute hex, or `module+0x1234` /
/// `main+0x40` against the live module list (main = the loaded sample).
pub fn resolve_target_addr(
    s: &str,
    state: &crate::app::AppState,
    main_name: &str,
) -> Option<u64> {
    if let Some(a) = parse_addr(s) {
        return Some(a);
    }
    let (module, off_s) = s.trim().rsplit_once('+')?;
    let offset = parse_addr(off_s)?;

    let matches_name = |m: &crate::app::ModuleInfo, name: &str| -> bool {
        m.base_address != 0
            && !name.is_empty()
            && (m.name.eq_ignore_ascii_case(name)
                || m.path.eq_ignore_ascii_case(name)
                || std::path::Path::new(&m.path)
                    .file_name()
                    .map(|f| f.to_string_lossy().eq_ignore_ascii_case(name))
                    .unwrap_or(false))
    };

    let found = if module.eq_ignore_ascii_case("main") {
        state
            .modules
            .iter()
            .find(|m| matches_name(m, main_name))
            .or_else(|| state.modules.iter().find(|m| m.base_address != 0))
    } else {
        state.modules.iter().find(|m| matches_name(m, module))
    };
    found.map(|m| m.base_address.wrapping_add(offset))
}

fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

fn parse_len(s: &str) -> u32 {
    s.trim().parse::<u32>().unwrap_or(1).clamp(1, 256)
}

fn parse_dump_len(s: &str) -> u32 {
    s.trim().parse::<u32>().unwrap_or(4096).clamp(16, 4096)
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// What to look for inside the dump.
pub enum SearchNeedle {
    Hex(Vec<u8>),
    Text(String),
}

/// Interpret the search box: `hex:`/`text:` prefixes force a mode; a
/// space/comma separated hex string or a long hex run is treated as bytes;
/// anything else is an ASCII (case-insensitive) substring search.
pub fn parse_search(s: &str) -> Option<SearchNeedle> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.strip_prefix("hex:") {
        return parse_hex_bytes(rest)
            .filter(|v| !v.is_empty())
            .map(SearchNeedle::Hex);
    }
    if let Some(rest) = t.strip_prefix("text:").or_else(|| t.strip_prefix("ascii:")) {
        return Some(SearchNeedle::Text(rest.to_string()));
    }
    let cleaned: String = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '-')
        .collect();
    let hexish = cleaned.len() >= 2
        && cleaned.len() % 2 == 0
        && cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if hexish && (t.contains(' ') || t.contains(',') || cleaned.len() >= 8) {
        if let Some(bytes) = parse_hex_bytes(&cleaned) {
            return Some(SearchNeedle::Hex(bytes));
        }
    }
    Some(SearchNeedle::Text(t.to_string()))
}

/// All offsets where `needle` occurs in `hay`.
pub fn find_matches(hay: &[u8], needle: &SearchNeedle) -> Vec<usize> {
    match needle {
        SearchNeedle::Hex(bytes) => {
            if bytes.is_empty() || bytes.len() > hay.len() {
                return Vec::new();
            }
            (0..=hay.len() - bytes.len())
                .filter(|&i| &hay[i..i + bytes.len()] == bytes.as_slice())
                .collect()
        }
        SearchNeedle::Text(text) => {
            let lower: Vec<u8> = text
                .bytes()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            if lower.is_empty() || lower.len() > hay.len() {
                return Vec::new();
            }
            (0..=hay.len() - lower.len())
                .filter(|&i| {
                    hay[i..i + lower.len()]
                        .iter()
                        .map(|b| b.to_ascii_lowercase())
                        .eq(lower.iter().copied())
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_parsing_and_matching() {
        // Hex with separators, hex: prefix, text and forced text.
        assert!(matches!(parse_search("90 90"), Some(SearchNeedle::Hex(v)) if v == vec![0x90, 0x90]));
        assert!(matches!(parse_search("hex:DEADBEEF"), Some(SearchNeedle::Hex(v)) if v == vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert!(matches!(parse_search("MZ"), Some(SearchNeedle::Text(t)) if t == "MZ"));
        assert!(matches!(parse_search("5650"), Some(SearchNeedle::Text(t)) if t == "5650"));
        assert!(parse_search("   ").is_none());

        let hay = b"....MZ\x90\x90test....mz....";
        assert_eq!(find_matches(hay, &parse_search("90 90").unwrap()), vec![6]);
        assert_eq!(find_matches(hay, &parse_search("mz").unwrap()), vec![4, 16]);
        assert!(find_matches(hay, &parse_search("hex:AA BB").unwrap()).is_empty());
    }
}
