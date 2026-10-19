/*
   Ghost Sandbox - About / legal dialog (GUI).

   Keeps the disclaimer and the licence reachable after the one-time
   acknowledgement has been recorded: shows the terms and the recorded
   acknowledgement state for this user, and can re-open the gate on request.

   (c) 2026 Ghost Project
*/

use eframe::egui;

use crate::app::{BORDER, CYAN, GREEN, RED_ORANGE, TEXT_BRIGHT, TEXT_DIM, YELLOW};
use crate::disclaimer as terms;

pub struct AboutDialog {
    /// The dialog is on screen.
    pub open: bool,
    /// The user asked to see the acknowledgement gate again.
    pub reopen_gate: bool,
}

impl AboutDialog {
    pub fn new() -> Self {
        Self {
            open: false,
            reopen_gate: false,
        }
    }

    /// One line describing the per-user acknowledgement state.
    fn ack_status() -> (String, egui::Color32) {
        if terms::env_skip() {
            // Check this first: is_acknowledged() also returns true for the
            // automation override, and the status must not claim a recorded
            // acceptance that does not exist.
            (
                "Malware-analysis disclaimer: bypassed by GHOST_SKIP_DISCLAIMER=1 \
                 (test/automation override)."
                    .to_string(),
                YELLOW,
            )
        } else if terms::is_acknowledged() {
            let text = std::fs::read_to_string(terms::ack_file()).unwrap_or_default();
            let when = text
                .lines()
                .find_map(|l| l.strip_prefix("acknowledged="))
                .unwrap_or("")
                .trim()
                .to_string();
            let line = if when.is_empty() {
                "Malware-analysis disclaimer: acknowledged for this user (shared by the GUI \
                 and the CLI)."
                    .to_string()
            } else {
                format!(
                    "Malware-analysis disclaimer: acknowledged {} for this user (shared by \
                     the GUI and the CLI).",
                    when
                )
            };
            (line, GREEN)
        } else {
            (
                "Malware-analysis disclaimer: not acknowledged yet - the Malware Analysis \
                 view asks once."
                    .to_string(),
                YELLOW,
            )
        }
    }

    /// Draws the dialog while it is open.
    pub fn show(&mut self, ctx: &egui::Context) {
        if !self.open {
            return;
        }
        let (status, status_color) = Self::ack_status();
        let mut close = false;
        let mut reopen = false;

        egui::Modal::new(egui::Id::new("ghost_about")).show(ctx, |ui| {
            ui.set_width(620.0);

            ui.label(
                egui::RichText::new("About Ghost Sandbox")
                    .color(TEXT_BRIGHT)
                    .size(18.0)
                    .strong(),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(format!(
                    "Version {} - dynamic binary instrumentation, live memory editing, \
                     import/export policy and hardware identity spoofing.",
                    crate::report::VERSION
                ))
                .color(TEXT_DIM)
                .size(12.5),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(
                    "Experimental software, provided as-is, without warranty of any kind. \
                     Licence: GNU Affero General Public License v3.0 (AGPL-3.0); its Sections \
                     15 and 16 and the disclaimer below apply. Nothing here purports to \
                     exclude or limit liability or obligations where such exclusion or \
                     limitation is not permitted by applicable law.",
                )
                .color(TEXT_DIM)
                .size(12.5),
            );
            ui.hyperlink_to(
                egui::RichText::new("Full AGPL-3.0 terms")
                    .color(CYAN)
                    .size(12.5),
                "https://www.gnu.org/licenses/agpl-3.0.html",
            );
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new("Disclaimer and limitation of liability")
                    .color(TEXT_BRIGHT)
                    .size(13.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(terms::HEADING_EXPERIMENTAL)
                    .color(TEXT_BRIGHT)
                    .size(12.5)
                    .strong(),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(terms::BODY_EXPERIMENTAL)
                    .color(TEXT_DIM)
                    .size(12.0),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(terms::HEADING_RISKS)
                    .color(YELLOW)
                    .size(12.5)
                    .strong(),
            );
            ui.add_space(2.0);
            for bullet in terms::RISK_BULLETS {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("•").color(YELLOW).size(12.0));
                    ui.label(egui::RichText::new(bullet).color(TEXT_DIM).size(12.0));
                });
                ui.add_space(2.0);
            }
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(terms::HEADING_ASSUMPTION)
                    .color(RED_ORANGE)
                    .size(12.5)
                    .strong(),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(terms::BODY_ASSUMPTION)
                    .color(TEXT_BRIGHT)
                    .size(12.0),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(terms::BODY_ASSUMPTION_LIMIT)
                    .color(TEXT_DIM)
                    .size(11.5),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(terms::ACK_NOTE)
                    .color(TEXT_DIM)
                    .size(12.0)
                    .italics(),
            );
            ui.add_space(10.0);

            ui.separator();
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(status)
                    .color(status_color)
                    .size(12.0),
            );
            ui.add_space(12.0);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let close_btn = egui::Button::new(
                    egui::RichText::new("Close").color(TEXT_BRIGHT).size(13.0),
                )
                .min_size(egui::vec2(110.0, 30.0));
                if ui.add(close_btn).clicked() {
                    close = true;
                }
                ui.add_space(8.0);
                let reopen_btn = egui::Button::new(
                    egui::RichText::new("Open the acknowledgement dialog")
                        .color(TEXT_DIM)
                        .size(12.0),
                )
                .fill(egui::Color32::TRANSPARENT)
                .stroke(egui::Stroke::new(1.0_f32, BORDER))
                .min_size(egui::vec2(230.0, 30.0));
                if ui.add(reopen_btn).clicked() {
                    reopen = true;
                }
            });
        });

        if close {
            self.open = false;
        }
        if reopen {
            self.open = false;
            self.reopen_gate = true;
        }
    }
}
