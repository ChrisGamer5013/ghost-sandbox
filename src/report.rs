/*
   Ghost Sandbox — Unified Session Report
   One schema for everything Ghost Sandbox produces — static sample analysis,
   live policy hits, DRM detections, trace events — rendered as JSON, JSONL,
   CSV or Markdown. The GUI export and the CLI use this exact code path so
   agents get identical output from either front end.
*/

use serde::Serialize;

use crate::app::{DrmEvent, MalwareOpEvent, ModuleInfo, PolicyHitEvent, TraceEvent};
use crate::pe_inspect::PeInfo;
use crate::policy::{PolicyAction, PolicySet};

pub const TOOL_NAME: &str = "ghost-sandbox";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Licence identifier carried by every report.
pub const LICENSE_ID: &str = "AGPL-3.0";
/// Disclaimer notice carried by every report, so the terms travel with shared
/// artifacts (JSON/JSONL fields, Markdown/Text footers).
pub const REPORT_NOTICE: &str = "Experimental software provided as-is; see the README \
'Disclaimer and Limitation of Liability'. Containment is best-effort, not a security boundary. \
Liability is excluded to the maximum extent permitted by applicable law.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Csv,
    Markdown,
    Text,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<OutputFormat> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Some(OutputFormat::Json),
            "jsonl" | "ndjson" => Some(OutputFormat::Jsonl),
            "csv" => Some(OutputFormat::Csv),
            "md" | "markdown" => Some(OutputFormat::Markdown),
            "text" | "txt" => Some(OutputFormat::Text),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Jsonl => "jsonl",
            OutputFormat::Csv => "csv",
            OutputFormat::Markdown => "markdown",
            OutputFormat::Text => "text",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetInfo {
    pub pid: u32,
    pub name: String,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySummary {
    pub total_rules: usize,
    pub active_rules: usize,
    pub rules: Vec<RuleSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleSummary {
    pub kind: String,
    pub module: String,
    pub function: String,
    pub action: String,
    pub value: u64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Counts {
    pub trace_events: usize,
    pub api_calls_total: u64,
    pub spoofed_total: u64,
    pub drm_events: usize,
    pub drm_detections: u64,
    pub policy_hits: usize,
    pub policy_blocked: u64,
    pub policy_observed: u64,
    pub modules: usize,
    pub memory_patches: u32,
    pub malware_ops: usize,
    pub malware_allowed: u64,
    pub malware_shadowed: u64,
    pub malware_faked: u64,
    pub malware_blocked: u64,
}

/// One file captured in the malware-mode shadow store (a "dropped" file the
/// sample believes it wrote to the real system).
#[derive(Debug, Clone, Serialize, Default)]
pub struct ShadowFileRec {
    /// Path inside the shadow store.
    pub path: String,
    /// Original host path the sample tried to write.
    pub origin: String,
    pub size: u64,
    pub modified: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sha256: String,
}

/// One live memory dump requested from the shim (`ghost run --dump`), or a
/// snapshot taken in the Memory Editor and exported.
#[derive(Debug, Clone, Serialize, Default)]
pub struct MemoryDumpRec {
    pub address: u64,
    pub length: usize,
    /// Hex bytes, no separators (uppercase).
    pub hex: String,
    /// Same bytes rendered as printable ASCII ('.' for non-printables).
    pub ascii: String,
}

impl MemoryDumpRec {
    pub fn new(address: u64, data: &[u8]) -> Self {
        MemoryDumpRec {
            address,
            length: data.len(),
            hex: data.iter().map(|b| format!("{:02X}", b)).collect(),
            ascii: data
                .iter()
                .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionReport {
    pub tool: String,
    pub version: String,
    pub generated: String,
    /// Licence identifier + disclaimer notice: they travel with the artifact.
    pub license: String,
    pub notice: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample: Option<PeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySummary>,
    pub counts: Counts,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<ModuleInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_hits: Vec<PolicyHitEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub drm_events: Vec<DrmEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub memory_dumps: Vec<MemoryDumpRec>,
    /// Malware-analysis behaviour events (malware mode only).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub malware_ops: Vec<MalwareOpEvent>,
    /// Shadow store root + captured files (malware mode only).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub shadow_dir: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shadow_files: Vec<ShadowFileRec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceEvent>,
}

impl SessionReport {
    pub fn empty(kind: &str) -> Self {
        SessionReport {
            tool: TOOL_NAME.into(),
            version: VERSION.into(),
            generated: chrono::Local::now().to_rfc3339(),
            license: LICENSE_ID.into(),
            notice: REPORT_NOTICE.into(),
            kind: kind.into(),
            status: String::new(),
            target: None,
            sample: None,
            policy: None,
            counts: Counts::default(),
            modules: Vec::new(),
            policy_hits: Vec::new(),
            drm_events: Vec::new(),
            memory_dumps: Vec::new(),
            malware_ops: Vec::new(),
            shadow_dir: String::new(),
            shadow_files: Vec::new(),
            trace: Vec::new(),
        }
    }

    pub fn with_policy(mut self, set: &PolicySet) -> Self {
        let (total, active) = set.counts();
        let rules = set
            .rules
            .iter()
            .filter(|r| r.enabled && r.action != PolicyAction::Allow)
            .map(|r| RuleSummary {
                kind: r.kind.label().to_lowercase(),
                module: r.module.clone(),
                function: r.function.clone(),
                action: r.action.label().to_lowercase(),
                value: r.value,
                note: r.note.clone(),
            })
            .collect();
        self.policy = Some(PolicySummary {
            total_rules: total,
            active_rules: active,
            rules,
        });
        self
    }

    pub fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Jsonl => {
                // One JSON object per line: header + one line per event.
                let mut out = String::new();
                let header = serde_json::json!({
                    "type": "report",
                    "tool": self.tool,
                    "version": self.version,
                    "generated": self.generated,
                    "license": self.license,
                    "notice": self.notice,
                    "kind": self.kind,
                    "status": self.status,
                    "counts": self.counts,
                    "sample": self.sample.as_ref().map(|s| serde_json::json!({
                        "file": s.file_name, "sha256": s.sha256, "size": s.size,
                        "imports": s.total_imports, "exports": s.exports.len(),
                    })),
                });
                out.push_str(&header.to_string());
                out.push('\n');
                for h in &self.policy_hits {
                    out.push_str(
                        &serde_json::json!({"type": "policy_hit", "event": h}).to_string(),
                    );
                    out.push('\n');
                }
                for d in &self.drm_events {
                    out.push_str(
                        &serde_json::json!({"type": "drm", "event": d}).to_string(),
                    );
                    out.push('\n');
                }
                for m in &self.malware_ops {
                    out.push_str(
                        &serde_json::json!({"type": "malware_op", "event": m}).to_string(),
                    );
                    out.push('\n');
                }
                for f in &self.shadow_files {
                    out.push_str(
                        &serde_json::json!({"type": "shadow_file", "file": f}).to_string(),
                    );
                    out.push('\n');
                }
                for t in &self.trace {
                    out.push_str(
                        &serde_json::json!({"type": "trace", "event": t}).to_string(),
                    );
                    out.push('\n');
                }
                out
            }
            OutputFormat::Csv => self.render_csv(),
            OutputFormat::Markdown => self.render_markdown(),
            OutputFormat::Text => self.render_text(),
        }
    }

    fn render_csv(&self) -> String {
        let mut out =
            String::from("type,time,module,function,action,blocked_or_verdict,caller,rva,detail\n");
        let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        for h in &self.policy_hits {
            out.push_str(&format!(
                "policy_hit,{},{},{},{},{},{},0x{:X},{}\n",
                esc(&h.timestamp),
                esc(&h.module),
                esc(&h.function),
                esc(crate::app::policy_action_name(h.action)),
                h.blocked as u8,
                esc(&h.caller_module),
                h.caller_rva,
                esc(&h.detail),
            ));
        }
        for d in &self.drm_events {
            out.push_str(&format!(
                "drm,{},{},{},{},{},{},0x{:X},{}\n",
                esc(&d.timestamp),
                esc(&d.api_module),
                esc(&d.api),
                esc(crate::app::drm_category_name(d.category)),
                esc(crate::app::drm_verdict_name(d.verdict)),
                esc(&d.caller_module),
                d.caller_rva,
                esc(&d.detail),
            ));
        }
        for t in &self.trace {
            out.push_str(&format!(
                "trace,{},{},{},,,,0,{}\n",
                esc(&t.timestamp),
                esc(&t.module),
                esc(&t.function),
                esc(&t.return_value),
            ));
        }
        for m in &self.malware_ops {
            out.push_str(&format!(
                "malware,{},{},{},{},{},{},0x{:X},{}\n",
                esc(&m.timestamp),
                esc(&m.api),
                esc(&format!("{} {}", crate::app::mw_category_name(m.category), crate::app::mw_action_name(m.action))),
                esc(if m.pending { "pending" } else { crate::app::mw_verdict_name(m.verdict) }),
                esc(&m.target),
                esc(&m.caller_module),
                m.caller_rva,
                esc(&m.detail),
            ));
        }
        for f in &self.shadow_files {
            out.push_str(&format!(
                "shadow_file,{},{},file,{},,,0,{}\n",
                esc(&f.modified),
                esc(&f.path),
                esc(&f.sha256),
                esc(&format!("{} bytes; origin {}", f.size, f.origin)),
            ));
        }
        out
    }

    fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("# Ghost Sandbox report — {}\n\n", self.kind));
        s.push_str(&format!("- Tool: {} v{}\n", self.tool, self.version));
        s.push_str(&format!("- Generated: {}\n", self.generated));
        if let Some(t) = &self.target {
            s.push_str(&format!(
                "- Target: {} (PID {}) — {}\n",
                t.name,
                t.pid,
                if t.connected { "connected" } else { "not connected" }
            ));
        }
        if let Some(sample) = &self.sample {
            s.push_str(&format!(
                "- Sample: `{}` — {} bytes, sha256 `{}`\n",
                sample.file_name, sample.size, sample.sha256
            ));
            s.push_str(&format!(
                "- PE: {} {}-bit {}, subsystem {}, {} imports, {} exports\n",
                sample.machine_name,
                if sample.is_64bit { 64 } else { 32 },
                if sample.is_dll { "DLL" } else { "EXE" },
                sample.subsystem_name,
                sample.total_imports,
                sample.exports.len()
            ));
            if !sample.packer_hints.is_empty() {
                s.push_str(&format!("- Hints: {}\n", sample.packer_hints.join("; ")));
            }
        }
        if let Some(p) = &self.policy {
            s.push_str(&format!(
                "- Policy: {} active rules\n",
                p.active_rules
            ));
            for r in &p.rules {
                s.push_str(&format!(
                    "  - {} {}!{} → {}{}\n",
                    r.kind, r.module, r.function, r.action,
                    if r.action == "block" { format!(" 0x{:X}", r.value) } else { String::new() }
                ));
            }
        }
        s.push_str(&format!(
            "\n## Counts\n\n- Trace events: {}\n- API calls: {}\n- DRM events: {} ({} detections)\n- Policy hits: {} ({} blocked)\n- Modules: {}\n",
            self.counts.trace_events,
            self.counts.api_calls_total,
            self.counts.drm_events,
            self.counts.drm_detections,
            self.counts.policy_hits,
            self.counts.policy_blocked,
            self.counts.modules,
        ));

        // Static sample symbols — the lists `ghost run` turns into policy rows.
        if let Some(sample) = &self.sample {
            if !sample.imports.is_empty() {
                s.push_str("\n## Imports\n\n");
                for m in &sample.imports {
                    let fns = m.functions.join(", ").replace('|', "\\|");
                    s.push_str(&format!(
                        "- `{}{}` ({}): {}\n",
                        m.name,
                        if m.delayed { " · delay-load" } else { "" },
                        m.functions.len(),
                        fns
                    ));
                }
            }
            if !sample.exports.is_empty() {
                s.push_str("\n## Exports\n\n");
                for e in &sample.exports {
                    s.push_str(&format!(
                        "- `{}` (ordinal {}, RVA 0x{:X}){}{}\n",
                        e.name,
                        e.ordinal,
                        e.rva,
                        if e.forwarded { " → " } else { "" },
                        if e.forwarded {
                            e.forwarder.clone()
                        } else {
                            String::new()
                        }
                    ));
                }
            }
        }

        if !self.policy_hits.is_empty() {
            s.push_str("\n## Import / Export Policy Hits\n\n| Time | Kind | Action | Module!Function | Caller | Detail |\n|---|---|---|---|---|---|\n");
            for h in &self.policy_hits {
                s.push_str(&format!(
                    "| {} | {} | {}{} | `{}!{}` | {} +0x{:X} | {} |\n",
                    h.timestamp,
                    crate::app::policy_kind_name(h.kind),
                    crate::app::policy_action_name(h.action),
                    if h.blocked { " (blocked)" } else { "" },
                    h.module,
                    h.function,
                    h.caller_module,
                    h.caller_rva,
                    h.detail.replace('|', "\\|")
                ));
            }
        }
        if !self.drm_events.is_empty() {
            s.push_str("\n## DRM / Anti-Tamper Events\n\n| Time | Category | Verdict | API | Caller | Expected → Returned |\n|---|---|---|---|---|---|\n");
            for d in &self.drm_events {
                s.push_str(&format!(
                    "| {} | {} | {} | `{}` | {} +0x{:X} | {} → {} |\n",
                    d.timestamp,
                    crate::app::drm_category_name(d.category),
                    crate::app::drm_verdict_name(d.verdict),
                    d.api,
                    d.caller_module,
                    d.caller_rva,
                    d.expected.replace('|', "\\|"),
                    d.returned.replace('|', "\\|")
                ));
            }
        }
        if !self.malware_ops.is_empty() {
            s.push_str("\n## Malware Analysis — Behaviour\n\n");
            if !self.shadow_dir.is_empty() {
                s.push_str(&format!("- Shadow store: `{}`\n", self.shadow_dir));
            }
            s.push_str(&format!(
                "- Operations: {} ({} allowed, {} shadowed, {} fake-success, {} blocked)\n",
                self.counts.malware_ops,
                self.counts.malware_allowed,
                self.counts.malware_shadowed,
                self.counts.malware_faked,
                self.counts.malware_blocked,
            ));
            s.push_str("\n| Time | Category | Action | API | Target | Verdict | Caller | Detail |\n|---|---|---|---|---|---|---|---|\n");
            for m in &self.malware_ops {
                s.push_str(&format!(
                    "| {} | {} | {} | `{}` | {} | {} | {} +0x{:X} | {} |\n",
                    m.timestamp,
                    crate::app::mw_category_name(m.category),
                    crate::app::mw_action_name(m.action),
                    m.api,
                    m.target.replace('|', "\\|"),
                    if m.pending {
                        "PENDING".to_string()
                    } else {
                        crate::app::mw_verdict_name(m.verdict).to_string()
                    },
                    m.caller_module,
                    m.caller_rva,
                    m.detail.replace('|', "\\|"),
                ));
            }
        }
        if !self.shadow_files.is_empty() {
            s.push_str("\n## Shadow Store — Captured Files\n\n| Size | Modified | Path | SHA-256 |\n|---|---|---|---|\n");
            for f in &self.shadow_files {
                s.push_str(&format!(
                    "| {} | {} | `{}` | {} |\n",
                    f.size,
                    f.modified,
                    f.path,
                    if f.sha256.is_empty() { "—" } else { &f.sha256 },
                ));
            }
        }
        if !self.memory_dumps.is_empty() {
            s.push_str("\n## Memory Dumps\n");
            for d in &self.memory_dumps {
                let lines = d.length.div_ceil(16);
                for line in 0..lines {
                    let start = line * 16;
                    let end = (start + 16).min(d.length);
                    let hex_pairs: Vec<String> = (start..end)
                        .map(|i| d.hex[i * 2..i * 2 + 2].to_string())
                        .collect();
                    s.push_str(&format!(
                        "0x{:016X}  {:<48}  {}\n",
                        d.address + start as u64,
                        hex_pairs.join(" "),
                        &d.ascii[start..end]
                    ));
                }
                s.push_str("```\n");
            }
        }
        // Keep the licence + disclaimer on the artifact itself.
        s.push_str(&format!("\n---\n\n*{} — licence {}.*\n", self.notice, self.license));
        s
    }

    fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Ghost Sandbox — {} report\n", self.kind));
        s.push_str(&format!("Generated: {}\n", self.generated));
        if let Some(t) = &self.target {
            s.push_str(&format!("Target: {} (PID {})\n", t.name, t.pid));
        }
        if let Some(sample) = &self.sample {
            s.push_str(&format!("Sample: {}\n", sample.summary_line()));
        }
        s.push_str(&format!(
            "Counts: {} trace, {} DRM ({} detected), {} policy hits ({} blocked)\n",
            self.counts.trace_events,
            self.counts.drm_events,
            self.counts.drm_detections,
            self.counts.policy_hits,
            self.counts.policy_blocked,
        ));
        if !self.policy_hits.is_empty() {
            s.push_str("\nPolicy hits:\n");
            for h in &self.policy_hits {
                s.push_str(&format!(
                    "  [{}] {:>7} {}!{} <- {} +0x{:X} — {}\n",
                    h.timestamp,
                    crate::app::policy_action_name(h.action),
                    h.module,
                    h.function,
                    h.caller_module,
                    h.caller_rva,
                    h.detail
                ));
            }
        }
        if !self.drm_events.is_empty() {
            s.push_str("\nDRM events:\n");
            for d in &self.drm_events {
                s.push_str(&format!(
                    "  [{}] {} — {} ({}) <- {} +0x{:X}: {} → {}\n",
                    d.timestamp,
                    crate::app::drm_verdict_name(d.verdict),
                    d.api,
                    crate::app::drm_category_name(d.category),
                    d.caller_module,
                    d.caller_rva,
                    d.expected,
                    d.returned
                ));
            }
        }
        if !self.malware_ops.is_empty() {
            s.push_str("\nMalware behaviour:\n");
            for m in &self.malware_ops {
                s.push_str(&format!(
                    "  [{}] {:>12} {:>8} {:<10} {} — {} <- {} +0x{:X}\n",
                    m.timestamp,
                    crate::app::mw_category_name(m.category),
                    crate::app::mw_action_name(m.action),
                    if m.pending {
                        "PENDING".to_string()
                    } else {
                        crate::app::mw_verdict_name(m.verdict).to_string()
                    },
                    m.api,
                    m.target,
                    m.caller_module,
                    m.caller_rva
                ));
            }
        }
        if !self.shadow_files.is_empty() {
            s.push_str(&format!(
                "\nShadow store ({} files):\n",
                self.shadow_files.len()
            ));
            for f in &self.shadow_files {
                s.push_str(&format!(
                    "  {:>10} bytes  {}  {}\n",
                    f.size,
                    f.path,
                    if f.sha256.is_empty() { "" } else { &f.sha256 }
                ));
            }
        }
        if !self.memory_dumps.is_empty() {
            s.push_str("\nMemory dumps:\n");
            for d in &self.memory_dumps {
                s.push_str(&format!(
                    "  0x{:016X} ({} bytes)\n",
                    d.address, d.length
                ));
                for line in 0..d.length.div_ceil(16) {
                    let start = line * 16;
                    let end = (start + 16).min(d.length);
                    let hex_pairs: Vec<String> = (start..end)
                        .map(|i| d.hex[i * 2..i * 2 + 2].to_string())
                        .collect();
                    s.push_str(&format!(
                        "   0x{:016X}  {:<48}  {}\n",
                        d.address + start as u64,
                        hex_pairs.join(" "),
                        &d.ascii[start..end]
                    ));
                }
            }
        }
        // Keep the licence + disclaimer on the artifact itself.
        s.push_str(&format!(
            "\n-- notice: {} (licence {})\n",
            self.notice, self.license
        ));
        s
    }

    pub fn save(&self, path: &str, format: OutputFormat) -> Result<(), String> {
        std::fs::write(path, self.render(format)).map_err(|e| format!("write {}: {}", path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_renders_all_formats() {
        let r = SessionReport::empty("test");
        for f in [OutputFormat::Json, OutputFormat::Jsonl, OutputFormat::Csv, OutputFormat::Markdown, OutputFormat::Text] {
            let s = r.render(f);
            assert!(!s.is_empty(), "format {:?} produced nothing", f);
        }
        let json = r.render(OutputFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tool"], "ghost-sandbox");
        assert_eq!(v["license"], "AGPL-3.0");
        assert!(v["notice"].as_str().unwrap().contains("best-effort"));
        assert!(r
            .render(OutputFormat::Markdown)
            .contains("Experimental software provided as-is"));
    }
}
