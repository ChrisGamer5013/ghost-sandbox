/*
   Ghost Sandbox — Import / Export Policy Model
   The controller-side representation of the shim's sandbox policy
   (shim/policy_watch.h): what the instrumented process is allowed to call
   (imports) and what its loaded modules expose (exports).

   Rules are loaded/saved as TOML and shipped to the shim either through
   shared memory (startup, before the target runs) or CMD_POLICY frames
   (live update). Wire layouts mirror trace_format.h exactly.
*/

use serde::{Deserialize, Serialize};

/// Wire constants (mirror PolicyKind / PolicyAction in trace_format.h).
pub const KIND_IMPORT: u32 = 1;
pub const KIND_EXPORT: u32 = 2;
pub const ACTION_OBSERVE: u32 = 1;
pub const ACTION_BLOCK: u32 = 2;

/// Size of one PolicyWireEntry (packed): 4+4+8+64+96.
pub const WIRE_ENTRY_SIZE: usize = 176;
/// Maximum rules the shim accepts.
pub const MAX_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyKind {
    Import,
    Export,
}

impl PolicyKind {
    pub fn wire(&self) -> u32 {
        match self {
            PolicyKind::Import => KIND_IMPORT,
            PolicyKind::Export => KIND_EXPORT,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            PolicyKind::Import => "Import",
            PolicyKind::Export => "Export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// No rule is shipped — the call behaves normally.
    Allow,
    /// Report every call, pass it through to the real function.
    Observe,
    /// Swallow the call and hand `block_value` back to the caller.
    Block,
}

impl PolicyAction {
    pub fn wire(&self) -> u32 {
        match self {
            PolicyAction::Allow => 0,
            PolicyAction::Observe => ACTION_OBSERVE,
            PolicyAction::Block => ACTION_BLOCK,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            PolicyAction::Allow => "Allow",
            PolicyAction::Observe => "Observe",
            PolicyAction::Block => "Block",
        }
    }
}

/// One policy rule (controller side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    #[serde(skip)]
    pub id: usize,
    /// Import = the target *calls* this; Export = the target *provides* it.
    pub kind: PolicyKind,
    /// Module pattern: exact name (case-insensitive), "*" or a trailing-*
    /// prefix pattern like "api-ms-*".
    pub module: String,
    /// Function pattern matched the same way.
    pub function: String,
    pub action: PolicyAction,
    /// Return value the caller receives when `action = "block"`.
    #[serde(default)]
    pub value: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Free-form note surfaced in reports.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

fn default_true() -> bool {
    true
}

impl PolicyRule {
    pub fn new(id: usize, kind: PolicyKind, module: impl Into<String>, function: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            module: module.into(),
            function: function.into(),
            action: PolicyAction::Allow,
            value: 0,
            enabled: true,
            note: String::new(),
        }
    }

    /// A one-line human description ("block kernel32.dll!IsDebuggerPresent -> 0x1").
    pub fn describe(&self) -> String {
        let verb = match self.action {
            PolicyAction::Allow => "allow",
            PolicyAction::Observe => "observe",
            PolicyAction::Block => "block",
        };
        if self.action == PolicyAction::Block {
            format!("{} {}!{} -> 0x{:X}", verb, self.module, self.function, self.value)
        } else {
            format!("{} {}!{}", verb, self.module, self.function)
        }
    }
}

/// A rule set ready for shipping over the wire.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySet {
    #[serde(rename = "rule", default)]
    pub rules: Vec<PolicyRule>,
    #[serde(skip)]
    next_id: usize,
}

impl PolicySet {
    pub fn new() -> Self {
        Self { rules: Vec::new(), next_id: 1 }
    }

    /// Add a rule, returning its id.
    pub fn add(&mut self, kind: PolicyKind, module: &str, function: &str) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.rules.push(PolicyRule::new(id, kind, module, function));
        id
    }

    /// Find (or create) the rule for one import/export row.
    pub fn rule_mut(&mut self, kind: PolicyKind, module: &str, function: &str) -> &mut PolicyRule {
        let id = {
            let found = self
                .rules
                .iter()
                .position(|r| r.kind == kind && r.module == module && r.function == function);
            match found {
                Some(i) => i,
                None => {
                    let id = self.add(kind, module, function);
                    return self.rules.iter_mut().find(|r| r.id == id).unwrap();
                }
            }
        };
        self.rules.iter_mut().find(|r| r.id == id).unwrap()
    }

    pub fn get(&self, kind: PolicyKind, module: &str, function: &str) -> Option<&PolicyRule> {
        self.rules
            .iter()
            .find(|r| r.kind == kind && r.module == module && r.function == function)
    }

    pub fn clear(&mut self) {
        self.rules.clear();
        self.next_id = 1;
    }

    /// Rules that will actually be shipped (enabled and not "allow").
    pub fn active(&self) -> Vec<&PolicyRule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && r.action != PolicyAction::Allow)
            .collect()
    }

    pub fn counts(&self) -> (usize, usize) {
        let all = self.rules.len();
        let active = self.active().len();
        (all, active)
    }

    /// Serialize the active rules into packed wire entries.
    pub fn wire_entries(&self) -> Result<Vec<WireEntry>, String> {
        let active = self.active();
        if active.len() > MAX_ENTRIES {
            return Err(format!(
                "policy has {} active rules; the shim accepts at most {}",
                active.len(),
                MAX_ENTRIES
            ));
        }
        Ok(active
            .iter()
            .map(|r| WireEntry {
                kind: r.kind.wire(),
                action: r.action.wire(),
                block_value: r.value,
                module: r.module.clone(),
                function: r.function.clone(),
            })
            .collect())
    }

    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
        let mut set: PolicySet =
            toml::from_str(&text).map_err(|e| format!("parse {}: {}", path, e))?;
        // Re-seed ids / validate.
        set.next_id = 1;
        for r in set.rules.iter_mut() {
            r.id = set.next_id;
            set.next_id += 1;
            if r.kind == PolicyKind::Export && r.action == PolicyAction::Block && r.value == 0 {
                // Allowed, but a zero return for exports is rarely intended —
                // keep it; the report shows the rule either way.
            }
        }
        Ok(set)
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let text = toml::to_string_pretty(self).map_err(|e| format!("serialize: {}", e))?;
        let header = "# Ghost Sandbox policy — import/export control for the sandbox service\n\
                      # kind = \"import\" | \"export\", action = \"allow\" | \"observe\" | \"block\"\n\
                      # module/function support \"*\" and trailing-* patterns (e.g. \"api-ms-*\")\n\n";
        std::fs::write(path, format!("{}{}", header, text))
            .map_err(|e| format!("write {}: {}", path, e))
    }
}

/// One packed policy entry (mirrors PolicyWireEntry in trace_format.h).
#[derive(Debug, Clone)]
pub struct WireEntry {
    pub kind: u32,
    pub action: u32,
    pub block_value: u64,
    pub module: String,
    pub function: String,
}

impl WireEntry {
    /// Encode as 176 packed bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.action.to_le_bytes());
        out.extend_from_slice(&self.block_value.to_le_bytes());
        push_fixed(out, &self.module, 64);
        push_fixed(out, &self.function, 96);
    }
}

fn push_fixed(out: &mut Vec<u8>, s: &str, len: usize) {
    let mut tmp = s.as_bytes().to_vec();
    tmp.truncate(len.saturating_sub(1));
    tmp.resize(len, 0);
    out.extend_from_slice(&tmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_entry_is_176_bytes() {
        let e = WireEntry {
            kind: KIND_IMPORT,
            action: ACTION_BLOCK,
            block_value: 0x7777,
            module: "kernel32.dll".into(),
            function: "IsDebuggerPresent".into(),
        };
        let mut b = Vec::new();
        e.encode(&mut b);
        assert_eq!(b.len(), WIRE_ENTRY_SIZE);
        assert_eq!(&b[0..4], &1u32.to_le_bytes());
        assert_eq!(&b[4..8], &2u32.to_le_bytes());
        assert_eq!(&b[8..16], &0x7777u64.to_le_bytes());
        assert_eq!(&b[16..28], b"kernel32.dll");
        assert_eq!(&b[28..32], &[0u8; 4]);
    }

    #[test]
    fn toml_roundtrip() {
        let mut s = PolicySet::new();
        {
            let r = s.rule_mut(PolicyKind::Import, "kernel32.dll", "IsDebuggerPresent");
            r.action = PolicyAction::Block;
            r.value = 1;
        }
        {
            let r = s.rule_mut(PolicyKind::Import, "kernel32.dll", "GetTickCount64");
            r.action = PolicyAction::Observe;
        }
        let text = toml::to_string_pretty(&s).unwrap();
        let back: PolicySet = toml::from_str(&text).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.active().len(), 2);
        let e = back.wire_entries().unwrap();
        assert_eq!(e[0].function, "IsDebuggerPresent");
        assert_eq!(e[0].block_value, 1);
    }

    #[test]
    fn allow_rules_are_not_shipped() {
        let mut s = PolicySet::new();
        s.add(PolicyKind::Import, "a.dll", "f");
        assert!(s.wire_entries().unwrap().is_empty());
    }
}
