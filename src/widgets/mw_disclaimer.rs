/*
   Ghost Sandbox - First-run Malware Analysis disclaimer dialog (GUI).
   Mirrors the CLI gate (`--accept-disclaimer`): both share the record in
   crate::disclaimer, so agreeing in either place skips the other; the
   acknowledgement is kept on disk per user (version + timestamp) and is
   re-requested if a future release materially changes the terms.

   (c) 2026 Ghost Project
*/

use eframe::egui;

use crate::app::{BORDER, CYAN, GREEN, PANEL_BG, RED_ORANGE, TEXT_BRIGHT, TEXT_DIM, YELLOW};
use crate::disclaimer as terms;

pub struct MwDisclaimer {
    /// The dialog is on screen.
    pub open: bool,
    /// The sentence the user typed so far.
    pub typed: String,
    /// The acknowledgement checkbox.
    pub checked: bool,
    /// Recorded earlier (file) or accepted during this session.
    pub acknowledged: bool,
    /// Last recording failure - the dialog stays open and nothing counts
    /// as accepted until the record is written.
    pub error: Option<String>,
}

impl MwDisclaimer {
    pub fn new() -> Self {
        Self {
            open: false,
            typed: String::new(),
            checked: false,
            acknowledged: terms::is_acknowledged(),
            error: None,
        }
    }

    /// Both requirements: the exact sentence and the checkbox.
    fn ready(&self) -> bool {
        self.typed.trim() == terms::ACK_SENTENCE && self.checked
    }

    /// Draws the gate while it is open. Returns true when the user completed
    /// it this frame (the caller then navigates to the Malware view).
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        if !self.open {
            return false;
        }

        let ready = self.ready();
        let mut completed = false;
        let mut cancelled = false;

        egui::Modal::new(egui::Id::new("ghost_mw_disclaimer")).show(ctx, |ui| {
            ui.set_width(600.0);

            ui.label(
                egui::RichText::new(terms::TITLE)
                    .color(TEXT_BRIGHT)
                    .size(18.0)
                    .strong(),
            );
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new(terms::HEADING_EXPERIMENTAL)
                    .color(TEXT_BRIGHT)
                    .size(13.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(terms::BODY_EXPERIMENTAL)
                    .color(TEXT_DIM)
                    .size(12.5),
            );
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new(terms::HEADING_RISKS)
                    .color(YELLOW)
                    .size(13.0)
                    .strong(),
            );
            ui.add_space(4.0);
            for bullet in terms::RISK_BULLETS {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("•").color(YELLOW).size(12.5));
                    ui.label(egui::RichText::new(bullet).color(TEXT_DIM).size(12.5));
                });
                ui.add_space(2.0);
            }
            ui.add_space(8.0);

            ui.label(
                egui::RichText::new(terms::HEADING_ASSUMPTION)
                    .color(RED_ORANGE)
                    .size(13.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(terms::BODY_ASSUMPTION)
                    .color(TEXT_BRIGHT)
                    .size(12.5),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(terms::BODY_ASSUMPTION_LIMIT)
                    .color(TEXT_DIM)
                    .size(11.5),
            );
            ui.add_space(10.0);

            ui.label(
                egui::RichText::new(terms::ACK_NOTE)
                    .color(TEXT_DIM)
                    .size(12.0)
                    .italics(),
            );
            ui.add_space(12.0);

            ui.separator();
            ui.add_space(8.0);

            ui.label(
                egui::RichText::new(terms::TYPE_INSTRUCTION)
                    .color(TEXT_BRIGHT)
                    .size(12.5),
            );
            ui.add_space(4.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(
                    egui::RichText::new(terms::ACK_SENTENCE)
                        .monospace()
                        .color(CYAN)
                        .size(12.5),
                );
            });
            ui.add_space(6.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.typed)
                    .desired_width(f32::INFINITY)
                    .hint_text("Type the sentence here"),
            );
            if !self.typed.trim().is_empty() && self.typed.trim() != terms::ACK_SENTENCE {
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("The sentence does not match yet.")
                        .color(RED_ORANGE)
                        .size(11.5),
                );
            }
            ui.add_space(10.0);

            ui.checkbox(
                &mut self.checked,
                egui::RichText::new(terms::CHECKBOX_LABEL)
                    .color(TEXT_BRIGHT)
                    .size(12.5),
            );
            if let Some(err) = &self.error {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(err)
                        .color(RED_ORANGE)
                        .size(11.5),
                );
            }
            ui.add_space(14.0);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = egui::RichText::new(terms::CONTINUE_LABEL)
                    .strong()
                    .color(if ready {
                        egui::Color32::BLACK
                    } else {
                        TEXT_DIM
                    });
                let mut button = egui::Button::new(label).min_size(egui::vec2(200.0, 32.0));
                button = if ready {
                    button.fill(GREEN)
                } else {
                    button
                        .fill(PANEL_BG)
                        .stroke(egui::Stroke::new(1.0_f32, BORDER))
                };
                if ui.add_enabled(ready, button).clicked() {
                    completed = true;
                }
                ui.add_space(8.0);
                if ui.button("Cancel").clicked() {
                    cancelled = true;
                }
            });
        });

        if completed {
            // Record first: if the acknowledgement cannot be stored it must
            // not count as acceptance - the dialog stays open with the error.
            match terms::record_acknowledgement() {
                Ok(()) => {
                    self.error = None;
                    self.acknowledged = true;
                    self.open = false;
                    return true;
                }
                Err(e) => {
                    self.error = Some(format!(
                        "Could not record the acknowledgement, so it does not count as \
                         acceptance: {}",
                        e
                    ));
                }
            }
        }
        if cancelled {
            self.open = false;
        }
        false
    }
}
