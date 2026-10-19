/*
   Ghost Sandbox — Rule Engine
   Load, save, and manage instrumentation rules.
*/

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    #[serde(default)]
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub hook_name: String,
    pub action: String,   // "override_return", "modify_param", "force_path", "nop"
    pub value: String,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool { true }

impl RuleSet {
    pub fn load(path: &str) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rules: {}", e))?;
        toml::from_str(&contents)
            .map_err(|e| format!("Failed to parse rules: {}", e))
    }
    
    pub fn save(&self, path: &str) -> Result<(), String> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize rules: {}", e))?;
        std::fs::write(path, contents)
            .map_err(|e| format!("Failed to write rules: {}", e))
    }
}
