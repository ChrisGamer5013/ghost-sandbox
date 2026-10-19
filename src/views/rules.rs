use egui::ComboBox;
use egui_extras::{TableBuilder, Column};

use crate::app::{SandboxApp, Rule, RuleAction};
use crate::pipe_server::PipeCommand;

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    let mut state = app.state.lock().unwrap();

    ui.label("Rules");
    ui.add_space(8.0);

    let mut delete_idx = None;
    let mut toggle: Option<(usize, bool)> = None;

    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(50.0))  // ID
        .column(Column::initial(150.0)) // Hook Name
        .column(Column::initial(150.0)) // Action
        .column(Column::initial(150.0)) // Value
        .column(Column::initial(280.0)) // Status
        .column(Column::remainder())    // Delete btn
        .header(24.0, |mut header| {
            header.col(|ui| { ui.strong("ID"); });
            header.col(|ui| { ui.strong("Hook Name"); });
            header.col(|ui| { ui.strong("Action"); });
            header.col(|ui| { ui.strong("Value"); });
            header.col(|ui| { ui.strong("Status"); });
            header.col(|ui| { ui.strong(""); });
        })
        .body(|mut body| {
            for (i, rule) in state.rules.iter_mut().enumerate() {
                body.row(24.0, |mut row| {
                    row.col(|ui| { ui.label(rule.id.to_string()); });
                    row.col(|ui| { ui.label(&rule.hook_name); });
                    row.col(|ui| { ui.label(rule.action.wire_name()); });
                    if rule.value.is_empty() {
                        row.col(|ui| {
                            ui.label(egui::RichText::new("—").color(crate::app::TEXT_DIM));
                        });
                    } else {
                        row.col(|ui| { ui.label(&rule.value); });
                    }
                    let was_active = rule.active;
                    row.col(|ui| { ui.checkbox(&mut rule.active, "Active"); });
                    if rule.active != was_active {
                        toggle = Some((i, rule.active));
                    }
                    row.col(|ui| {
                        if ui.button("Delete").clicked() {
                            delete_idx = Some(i);
                        }
                    });
                });
            }
        });

    if let Some(i) = delete_idx {
        let rule = state.rules.remove(i);
        if rule.action != RuleAction::Trace {
            send_if_connected(&app.pipe, &mut state, PipeCommand::RuleDel { hook_name: rule.hook_name });
        }
    }

    if let Some((i, now_active)) = toggle {
        if let Some(rule) = state.rules.get(i) {
            if rule.action != RuleAction::Trace {
                let cmd = if now_active {
                    PipeCommand::RuleAdd {
                        hook_name: rule.hook_name.clone(),
                        action: rule.action.wire_name().to_string(),
                        value: rule.value.clone(),
                    }
                } else {
                    PipeCommand::RuleDel { hook_name: rule.hook_name.clone() }
                };
                send_if_connected(&app.pipe, &mut state, cmd);
            }
        }
    }

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label("Add Rule");
    ui.horizontal(|ui| {
        ui.label("Hook Name:");
        ui.text_edit_singleline(&mut app.new_rule_hook);

        ui.label("Action:");
        ComboBox::from_id_salt("new_rule_action_combo")
            .selected_text(app.new_rule_action.wire_name())
            .show_ui(ui, |ui| {
                for action in [
                    RuleAction::Trace,
                    RuleAction::OverrideReturn,
                    RuleAction::ModifyParam,
                    RuleAction::ForcePath,
                    RuleAction::NopInstruction,
                ] {
                    ui.selectable_value(&mut app.new_rule_action, action.clone(), action.wire_name());
                }
            });

        ui.label("Value:");
        ui.text_edit_singleline(&mut app.new_rule_value);

        if ui.button("Add").clicked() {
            if app.new_rule_hook.trim().is_empty() {
                state.status_message = "Hook name is required".into();
            } else {
                let rule = Rule {
                    id: state.next_rule_id,
                    hook_name: app.new_rule_hook.trim().to_string(),
                    action: app.new_rule_action.clone(),
                    value: app.new_rule_value.trim().to_string(),
                    active: true,
                };
                state.next_rule_id += 1;

                if rule.action != RuleAction::Trace {
                    send_if_connected(
                        &app.pipe,
                        &mut state,
                        PipeCommand::RuleAdd {
                            hook_name: rule.hook_name.clone(),
                            action: rule.action.wire_name().to_string(),
                            value: rule.value.clone(),
                        },
                    );
                }
                state.status_message =
                    format!("Rule added: {} ({})", rule.hook_name, rule.action.wire_name());
                state.rules.push(rule);

                app.new_rule_hook.clear();
                app.new_rule_value.clear();
            }
        }
    });

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if ui.button("Load Preset").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Rules TOML", &["toml"])
                .pick_file()
            {
                match crate::rule_engine::RuleSet::load(&path.to_string_lossy()) {
                    Ok(set) => {
                        let mut imported: Vec<Rule> = set
                            .rules
                            .iter()
                            .map(|d| Rule {
                                id: 0,
                                hook_name: d.hook_name.clone(),
                                action: crate::app::RuleAction::from_wire(&d.action),
                                value: d.value.clone(),
                                active: d.active,
                            })
                            .collect();
                        // Re-number ids after import
                        let mut next = state.next_rule_id;
                        for r in imported.iter_mut() {
                            r.id = next;
                            next += 1;
                        }
                        state.next_rule_id = next;
                        let count = imported.len();
                        state.rules.extend(imported);
                        state.status_message =
                            format!("Loaded {} rule(s) from {}", count, path.display());
                    }
                    Err(e) => state.status_message = e,
                }
            }
        }
        if ui.button("Save Rules").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Rules TOML", &["toml"])
                .set_file_name("rules.toml")
                .save_file()
            {
                let set = crate::rule_engine::RuleSet {
                    name: "Ghost Sandbox Rules".into(),
                    rules: state
                        .rules
                        .iter()
                        .map(|r| crate::rule_engine::RuleDefinition {
                            hook_name: r.hook_name.clone(),
                            action: r.action.wire_name().to_string(),
                            value: r.value.clone(),
                            active: r.active,
                        })
                        .collect(),
                };
                match set.save(&path.to_string_lossy()) {
                    Ok(()) => {
                        state.status_message = format!("Saved rules to {}", path.display())
                    }
                    Err(e) => state.status_message = e,
                }
            }
        }
    });
}

/// Send a rule command to the shim (no-op with a status note when disconnected).
fn send_if_connected(
    pipe: &crate::pipe_server::PipeServer,
    state: &mut crate::app::AppState,
    cmd: PipeCommand,
) {
    if !state.connected {
        state.status_message = "Not connected — rule saved locally only".into();
        return;
    }
    if let Err(e) = pipe.send_command(cmd) {
        state.status_message = format!("Command failed: {}", e);
    }
}
