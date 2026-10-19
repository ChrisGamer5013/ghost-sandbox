/*
   Ghost Sandbox — Event Pump
   Drains PipeMessage events from the pipe server into the shared AppState.
   Runs on a dedicated thread; the UI picks the data up on its next repaint.
*/

use std::sync::{Arc, Mutex, Once};

use chrono::Local;
use crossbeam_channel::Receiver;

use crate::app::{AppState, DrmEvent, ModuleInfo, TraceEvent};
use crate::pipe_server::PipeMessage;

/// One-shot diagnostics: confirm the three data streams reach the UI once per run.
static FIRST_TRACE: Once = Once::new();
static FIRST_SPOOF: Once = Once::new();
static FIRST_DLL_LOAD: Once = Once::new();
static FIRST_DRM: Once = Once::new();
static FIRST_POLICY: Once = Once::new();
static FIRST_MALWARE: Once = Once::new();

/// Spawn the pump thread. Exits when the pipe server's channel closes
/// (i.e. when the application is shutting down).
pub fn spawn(state: Arc<Mutex<AppState>>, rx: Receiver<PipeMessage>) {
    let _ = std::thread::Builder::new()
        .name("ghost-pump".into())
        .spawn(move || {
            while let Ok(msg) = rx.recv() {
                apply(&state, msg);
            }
            tracing::warn!("Pipe message channel closed — pump exiting");
        });
}

/// Apply one pipe message to the shared state. Public so the CLI can drive
/// the exact same state machine without the GUI (identical semantics).
pub fn apply(state: &Arc<Mutex<AppState>>, msg: PipeMessage) {
    let now = Local::now().format("%H:%M:%S%.3f").to_string();
    let mut s = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    match msg {
        PipeMessage::Connected { pid, name } => {
            s.connected = true;
            s.target_pid = pid;
            if !name.is_empty() {
                s.target_name = name;
            }
            s.active_hooks = s.hooked_functions.len() as u32;
            s.status_message = format!("Shim connected — {} (PID {})", s.target_name, pid);
        }
        PipeMessage::Disconnected => {
            s.connected = false;
            s.status_message = "Shim disconnected".into();
        }
        PipeMessage::Trace {
            thread_id,
            function,
            module,
            params,
            return_value,
            duration_us,
            spoofed,
        } => {
            FIRST_TRACE.call_once(|| {
                tracing::info!("Trace events flowing — first: {}!{}()", module, function);
            });
            if spoofed {
                FIRST_SPOOF.call_once(|| {
                    tracing::info!("Spoof events flowing — first: {}!{}()", module, function);
                });
            }
            push_trace(
                &mut s,
                TraceEvent {
                    timestamp: now,
                    thread_id,
                    function,
                    module,
                    params,
                    return_value,
                    duration_us,
                    spoofed,
                },
            );
        }
        PipeMessage::DllLoad { name, base_address, size } => {
            FIRST_DLL_LOAD.call_once(|| {
                tracing::info!("Module events flowing — first: {} @ 0x{:X}", name, base_address);
            });
            let short = short_name(&name);
            if let Some(m) = s
                .modules
                .iter_mut()
                .find(|m| m.name.eq_ignore_ascii_case(&short))
            {
                m.base_address = base_address;
                if size > 0 {
                    m.size = size;
                }
                if m.path.is_empty() && name.len() > m.name.len() {
                    m.path = name.clone();
                }
            } else {
                s.modules.push(ModuleInfo {
                    name: short,
                    base_address,
                    size,
                    entry_point: 0,
                    num_exports: 0,
                    num_imports: 0,
                    signed: false,
                    path: name,
                });
            }
        }
        PipeMessage::DllUnload { name } => {
            let short = short_name(&name);
            s.modules.retain(|m| !m.name.eq_ignore_ascii_case(&short));
        }
        PipeMessage::Exception { code, address } => {
            push_trace(
                &mut s,
                TraceEvent {
                    timestamp: now,
                    thread_id: 0,
                    function: "Exception".into(),
                    module: "target".into(),
                    params: format!("code=0x{:08X}, address=0x{:016X}", code, address),
                    return_value: String::new(),
                    duration_us: 0,
                    spoofed: false,
                },
            );
        }
        PipeMessage::PatchAck { address, success } => {
            if success {
                s.memory_patches += 1;
                s.status_message = format!("Patch applied at 0x{:016X}", address);
            } else {
                s.status_message = format!("Patch FAILED at 0x{:016X}", address);
            }
        }
        PipeMessage::CpuidTrap { leaf, subleaf, eax, ebx, ecx, edx } => {
            push_trace(
                &mut s,
                TraceEvent {
                    timestamp: now,
                    thread_id: 0,
                    function: "CPUID".into(),
                    module: "cpuid".into(),
                    params: format!("leaf=0x{:08X}, subleaf=0x{:08X}", leaf, subleaf),
                    return_value: format!(
                        "EAX=0x{:08X} EBX=0x{:08X} ECX=0x{:08X} EDX=0x{:08X}",
                        eax, ebx, ecx, edx
                    ),
                    duration_us: 0,
                    spoofed: true,
                },
            );
        }
        PipeMessage::VTableMod { address, index, old_value, new_value } => {
            push_trace(
                &mut s,
                TraceEvent {
                    timestamp: now,
                    thread_id: 0,
                    function: "VTableWrite".into(),
                    module: "vtable".into(),
                    params: format!("vtable=0x{:016X}, index={}", address, index),
                    return_value: format!("0x{:016X} → 0x{:016X}", old_value, new_value),
                    duration_us: 0,
                    spoofed: true,
                },
            );
        }
        PipeMessage::MemoryDump { address, data } => {
            tracing::info!("Memory dump: 0x{:016X} ({} bytes)", address, data.len());
            s.status_message = format!("Memory dump: 0x{:016X} ({} bytes)", address, data.len());
            s.memory_address = address;
            s.memory_data = data;
        }
        PipeMessage::Registers {
            rax, rbx, rcx, rdx,
            rsi, rdi, rsp, rbp,
            r8, r9, r10, r11,
            r12, r13, r14, r15,
            rip, rflags,
        } => {
            let r = &mut s.registers;
            r.rax = rax; r.rbx = rbx; r.rcx = rcx; r.rdx = rdx;
            r.rsi = rsi; r.rdi = rdi; r.rsp = rsp; r.rbp = rbp;
            r.r8 = r8; r.r9 = r9; r.r10 = r10; r.r11 = r11;
            r.r12 = r12; r.r13 = r13; r.r14 = r14; r.r15 = r15;
            r.rip = rip; r.rflags = rflags;
            tracing::info!("Register snapshot received (rip=0x{:016X})", rip);
            s.status_message = "Register snapshot received".into();
        }
        PipeMessage::ModuleList { modules } => {
            s.modules = modules
                .into_iter()
                .map(|m| ModuleInfo {
                    name: short_name(&m.name),
                    base_address: m.base_address,
                    size: m.size,
                    entry_point: m.entry_point,
                    num_exports: m.num_exports,
                    num_imports: m.num_imports,
                    signed: false,
                    path: m.name,
                })
                .collect();
            s.module_list_seen = true;
            s.status_message = format!("Module list updated ({} modules)", s.modules.len());
        }
        PipeMessage::Drm {
            category,
            severity,
            verdict,
            api,
            api_module,
            caller_module,
            caller_rva,
            ret_value,
            expected,
            returned,
            detail,
        } => {
            FIRST_DRM.call_once(|| {
                tracing::info!(
                    "DRM events flowing — first: {} ({} | expected: \"{}\"→ returned: \"{}\")",
                    api,
                    crate::app::drm_category_name(category),
                    expected,
                    returned
                );
            });

            s.drm_total += 1;
            if verdict == 1 {
                s.drm_detections += 1;
            }

            if verdict == 1 || severity >= 3 {
                let msg = format!(
                    "DRM: {} returned {} — {} +0x{:X}",
                    api, returned, caller_module, caller_rva
                );
                s.drm_last_alert = Some(msg.clone());
                s.status_message = msg;
            }

            s.drm_events.push_back(DrmEvent {
                timestamp: now,
                category,
                severity,
                verdict,
                api,
                api_module,
                caller_module,
                caller_rva,
                ret_value,
                expected,
                returned,
                detail,
            });
            while s.drm_events.len() > s.max_drm_events {
                s.drm_events.pop_front();
            }
        }
        PipeMessage::PolicyHit {
            kind,
            action,
            blocked,
            ret_value,
            module,
            function,
            caller_module,
            caller_rva,
            detail,
        } => {
            if kind == 0 {
                // Engine status (policy applied / cleared).
                s.policy_last_status = format!("{}: {}", function, detail);
                s.status_message = format!("Sandbox policy {}: {}", function, detail);
            } else {
                FIRST_POLICY.call_once(|| {
                    tracing::info!(
                        "Sandbox policy hits flowing — first: {}{} {}!{} (caller {} +0x{:X})",
                        crate::app::policy_action_name(action),
                        if blocked { "(blocked)"} else { ""},
                        module,
                        function,
                        caller_module,
                        caller_rva
                    );
                });
                if blocked {
                    s.policy_blocked += 1;
                    s.status_message = format!(
                        "{}!{} blocked → 0x{:X} — caller {} +0x{:X}",
                        module, function, ret_value, caller_module, caller_rva
                    );
                } else {
                    s.policy_observed += 1;
                }
            }

            s.policy_hits.push_back(crate::app::PolicyHitEvent {
                timestamp: now,
                kind,
                action,
                blocked,
                ret_value,
                module,
                function,
                caller_module,
                caller_rva,
                detail,
            });
            while s.policy_hits.len() > s.max_policy_hits {
                s.policy_hits.pop_front();
            }
        }
        PipeMessage::MalwareOp {
            op_id,
            category,
            action,
            flags,
            verdict,
            pending,
            caller_module,
            caller_rva,
            api,
            target,
            detail,
        } => {
            FIRST_MALWARE.call_once(|| {
                tracing::info!(
                    "Malware events flowing — first: {} {} ({}) caller {} +0x{:X}",
                    crate::app::mw_category_name(category),
                    crate::app::mw_action_name(action),
                    crate::app::mw_verdict_name(verdict),
                    caller_module,
                    caller_rva
                );
            });
            s.malware_mode_active = true;

            // Status-bar hint built before the record takes ownership of the
            // target string.
            let target_hint = if target.is_empty() {
                "(no target)".to_string()
            } else {
                let short: String = target.chars().take(120).collect();
                short
            };

            // Pending and final records share an opId: update in place so the
            // table keeps one row per operation. Counters are rebalanced after
            // the borrow on the deque ends.
            let mut rebalance: Option<(bool, u32)> = None;
            let found = s
                .malware_ops
                .iter_mut()
                .find(|o| o.op_id == op_id);
            match found {
                Some(op) => {
                    rebalance = Some((op.pending, op.verdict));
                    op.category = category;
                    op.action = action;
                    op.flags = flags;
                    op.verdict = verdict;
                    op.pending = pending;
                    op.caller_module = caller_module;
                    op.caller_rva = caller_rva;
                    op.api = api;
                    op.target = target;
                    op.detail = detail;
                }
                None => {
                    s.malware_ops.push_back(crate::app::MalwareOpEvent {
                        timestamp: now,
                        op_id,
                        category,
                        action,
                        flags,
                        verdict,
                        pending,
                        caller_module,
                        caller_rva,
                        api,
                        target,
                        detail,
                    });
                    while s.malware_ops.len() > s.max_malware_ops {
                        s.malware_ops.pop_front();
                    }
                }
            }
            if let Some((was_pending, old_verdict)) = rebalance {
                if was_pending {
                    s.malware_pending = s.malware_pending.saturating_sub(1);
                } else {
                    match old_verdict {
                        1 => s.malware_allowed = s.malware_allowed.saturating_sub(1),
                        2 => s.malware_shadowed = s.malware_shadowed.saturating_sub(1),
                        3 => s.malware_faked = s.malware_faked.saturating_sub(1),
                        4 | 5 => s.malware_blocked = s.malware_blocked.saturating_sub(1),
                        _ => {}
                    }
                }
            }

            if pending {
                s.malware_pending += 1;
                if target_hint.is_empty() {
                    s.status_message = format!(
                        "malware op #{}: {} {} awaiting approval",
                        op_id,
                        crate::app::mw_category_name(category),
                        crate::app::mw_action_name(action)
                    );
                } else {
                    s.status_message = format!(
                        "malware op #{}: {} {} — {}",
                        op_id,
                        crate::app::mw_category_name(category),
                        crate::app::mw_action_name(action),
                        target_hint
                    );
                }
            } else {
                match verdict {
                    1 => {
                        s.malware_allowed += 1;
                        s.status_message = format!(
                            "malware op #{} allowed: {} {}",
                            op_id,
                            crate::app::mw_category_name(category),
                            crate::app::mw_action_name(action)
                        );
                    }
                    2 => {
                        s.malware_shadowed += 1;
                        s.status_message = format!(
                            "malware op #{} shadowed: {} {}",
                            op_id,
                            crate::app::mw_category_name(category),
                            crate::app::mw_action_name(action)
                        );
                    }
                    3 => {
                        s.malware_faked += 1;
                        s.status_message = format!(
                            "malware op #{} faked success: {} {}",
                            op_id,
                            crate::app::mw_category_name(category),
                            crate::app::mw_action_name(action)
                        );
                    }
                    4 | 5 => {
                        s.malware_blocked += 1;
                        s.status_message = format!(
                            "malware op #{} blocked: {} {}",
                            op_id,
                            crate::app::mw_category_name(category),
                            crate::app::mw_action_name(action)
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

fn push_trace(s: &mut AppState, ev: TraceEvent) {
    s.total_api_calls += 1;
    if ev.spoofed {
        s.total_spoofed += 1;
    }
    s.hooked_functions.insert(ev.function.clone());
    s.active_hooks = s.hooked_functions.len() as u32;

    s.trace_events.push_back(ev);
    while s.trace_events.len() > s.max_trace_events {
        s.trace_events.pop_front();
    }
}

/// Extract the file name from a possibly-absolute module path.
fn short_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_string()
}
