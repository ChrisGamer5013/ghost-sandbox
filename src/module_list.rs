/*
   Ghost Sandbox — Module List
   Track loaded modules in the target process.
*/

use crate::app::ModuleInfo;

/// Parse module information from the shim's MODULE_LIST response
pub fn parse_module_list(data: &str) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    
    for line in data.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 6 {
            modules.push(ModuleInfo {
                name: parts[0].trim().to_string(),
                base_address: u64::from_str_radix(parts[1].trim().trim_start_matches("0x"), 16).unwrap_or(0),
                size: parts[2].trim().parse().unwrap_or(0),
                entry_point: u64::from_str_radix(parts[3].trim().trim_start_matches("0x"), 16).unwrap_or(0),
                num_exports: parts[4].trim().parse().unwrap_or(0),
                num_imports: parts[5].trim().parse().unwrap_or(0),
                signed: parts.get(6).map(|s| s.trim() == "1").unwrap_or(false),
                path: String::new(),
            });
        }
    }
    
    modules
}
