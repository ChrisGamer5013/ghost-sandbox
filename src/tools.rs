/*
   Ghost Sandbox — External Tool Integration
   Every analysis stage (disassemble, decompile, debug, memory edit, hex
   view, strings, PE inspect, trace view) can be served either by Ghost
   Sandbox itself or handed off to an external tool (IDA, Ghidra, x64dbg,
   WinDbg, Cheat Engine, HxD, strings, DIE, ...).

   Tool definitions live in tools.toml; each has a command line template
   with context placeholders so the external program opens exactly where
   the user is:

     {file}   absolute path of the sample / module
     {pid}    target process id
     {addr}   absolute address (0x...)
     {module} module name
     {rva}    offset from the module base (0x...)
     {base}   module base address (0x...)
     {func}   function / export name
     {bytes}  current hex bytes selection
     {name}   short label of the thing being opened
*/

use serde::{Deserialize, Serialize};

// ─── Stages ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ToolStage {
    Disassemble,
    Decompile,
    Debug,
    MemoryEdit,
    HexView,
    Strings,
    InspectPe,
    TraceView,
    Custom,
}

impl ToolStage {
    pub fn all() -> [ToolStage; 9] {
        [
            ToolStage::Disassemble,
            ToolStage::Decompile,
            ToolStage::Debug,
            ToolStage::MemoryEdit,
            ToolStage::HexView,
            ToolStage::Strings,
            ToolStage::InspectPe,
            ToolStage::TraceView,
            ToolStage::Custom,
        ]
    }

    pub fn wire(&self) -> &'static str {
        match self {
            ToolStage::Disassemble => "disassemble",
            ToolStage::Decompile => "decompile",
            ToolStage::Debug => "debug",
            ToolStage::MemoryEdit => "memory_edit",
            ToolStage::HexView => "hex_view",
            ToolStage::Strings => "strings",
            ToolStage::InspectPe => "inspect_pe",
            ToolStage::TraceView => "trace_view",
            ToolStage::Custom => "custom",
        }
    }

    pub fn from_wire(s: &str) -> ToolStage {
        match s {
            "disassemble" => ToolStage::Disassemble,
            "decompile" => ToolStage::Decompile,
            "debug" => ToolStage::Debug,
            "memory_edit" => ToolStage::MemoryEdit,
            "hex_view" => ToolStage::HexView,
            "strings" => ToolStage::Strings,
            "inspect_pe" => ToolStage::InspectPe,
            "trace_view" => ToolStage::TraceView,
            _ => ToolStage::Custom,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ToolStage::Disassemble => "Disassemble",
            ToolStage::Decompile => "Decompile",
            ToolStage::Debug => "Debug / Attach",
            ToolStage::MemoryEdit => "Memory Edit",
            ToolStage::HexView => "Hex View",
            ToolStage::Strings => "Strings",
            ToolStage::InspectPe => "Inspect PE",
            ToolStage::TraceView => "Trace / Log",
            ToolStage::Custom => "Custom",
        }
    }
}

// ─── Tool definitions ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub stage: ToolStage,
    /// Executable path (absolute, or a name resolved via PATH).
    pub path: String,
    /// Argument template — one string, split like a command line.
    #[serde(default)]
    pub args: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolsConfig {
    #[serde(rename = "tool", default)]
    pub tools: Vec<ToolDef>,
}

impl ToolsConfig {
    /// The built-in preset catalogue (used when no tools.toml exists).
    pub fn builtin() -> Self {
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
        let pf86 = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| "C:\\Program Files (x86)".into());
        let t = |name: &str, stage: ToolStage, path: String, args: &str, note: &str| ToolDef {
            name: name.into(),
            stage,
            path,
            args: args.into(),
            enabled: true,
            note: note.into(),
        };
        Self {
            tools: vec![
                t("IDA Pro 64", ToolStage::Disassemble,
                  format!("{}\\IDA Pro 9.0\\ida64.exe", pf), "{file}",
                  "Opening the sample in IDA — fully supported Ghost handoff"),
                t("IDA Free 64", ToolStage::Disassemble,
                  format!("{}\\IDA Freeware 8.4\\ida64.exe", pf), "{file}",
                  "IDA Free (if installed)"),
                t("Ghidra", ToolStage::Decompile,
                  format!("{}\\ghidra\\ghidraRun.bat", pf), "{file}",
                  "Ghidra launcher with the sample"),
                t("x64dbg", ToolStage::Debug,
                  format!("{}\\x64dbg\\release\\x64\\x64dbg.exe", pf86), "-p {pid}",
                  "Attach x64dbg to the instrumented target"),
                t("WinDbg (scripted)", ToolStage::Debug,
                  format!("{}\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe", pf86),
                  "-p {pid} -c \"u {addr}\"",
                  "Attach and disassemble at the address"),
                t("Cheat Engine", ToolStage::MemoryEdit,
                  format!("{}\\Cheat Engine 7.5\\CheatEngine.exe", pf), "{pid}",
                  "Live memory editing against the target"),
                t("HxD", ToolStage::HexView,
                  format!("{}\\HxD\\HxD64.exe", pf), "{file}",
                  "File hex view"),
                t("strings (Sysinternals)", ToolStage::Strings,
                  format!("{}\\SysinternalsSuite\\strings64.exe", pf), "{file}",
                  "ASCII/Unicode strings extraction"),
                t("Detect It Easy", ToolStage::InspectPe,
                  format!("{}\\DIE\\diec.exe", pf), "{file}",
                  "PE signature / packer identification"),
                t("Reveal in Explorer", ToolStage::Custom,
                  "explorer.exe".into(), "/select,\"{file}\"",
                  "Select the sample in a File Explorer window"),
            ],
        }
    }

    pub fn load_or_builtin(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).unwrap_or_else(|_| Self::builtin()),
            Err(_) => Self::builtin(),
        }
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let text = toml::to_string_pretty(self).map_err(|e| format!("serialize: {}", e))?;
        let header = "# Ghost Sandbox — external tool handoff configuration\n\
                      # stage = disassemble | decompile | debug | memory_edit | hex_view |\n\
                      #         strings | inspect_pe | trace_view | custom\n\
                      # placeholders: {file} {pid} {addr} {module} {rva} {base} {func} {bytes} {name}\n\n";
        std::fs::write(path, format!("{}{}", header, text))
            .map_err(|e| format!("write {}: {}", path, e))
    }

    pub fn for_stage(&self, stage: ToolStage) -> Vec<&ToolDef> {
        self.tools
            .iter()
            .filter(|t| t.enabled && t.stage == stage)
            .collect()
    }
}

// ─── Context + template expansion ───────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ToolContext {
    pub file: String,
    pub pid: u32,
    pub addr: u64,
    pub module: String,
    pub rva: u64,
    pub base: u64,
    pub func: String,
    pub bytes: String,
    pub name: String,
}

impl ToolContext {
    pub fn substitute(&self, template: &str) -> String {
        template
            .replace("{file}", &self.file)
            .replace("{pid}", &self.pid.to_string())
            .replace("{addr}", &format!("0x{:X}", self.addr))
            .replace("{module}", &self.module)
            .replace("{rva}", &format!("0x{:X}", self.rva))
            .replace("{base}", &format!("0x{:X}", self.base))
            .replace("{func}", &self.func)
            .replace("{bytes}", &self.bytes)
            .replace("{name}", &self.name)
    }
}

/// Split a command-line-ish string into argv tokens (quotes respected).
pub fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if matches!(chars.peek(), Some('"')) => {
                cur.push('"');
                chars.next();
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub struct ResolvedCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl ResolvedCommand {
    /// Display form with quoting (for logs / reports / dry runs).
    pub fn command_line(&self) -> String {
        let mut s = if self.program.contains(' ') {
            format!("\"{}\"", self.program)
        } else {
            self.program.clone()
        };
        for a in &self.args {
            s.push(' ');
            if a.contains(' ') {
                s.push_str(&format!("\"{}\"", a));
            } else {
                s.push_str(a);
            }
        }
        s
    }
}

pub fn resolve(tool: &ToolDef, ctx: &ToolContext) -> ResolvedCommand {
    let program = ctx.substitute(&tool.path);
    let args = split_args(&ctx.substitute(&tool.args));
    ResolvedCommand { program, args }
}

/// Launch an external tool detached. Returns the resolved command line.
pub fn launch(tool: &ToolDef, ctx: &ToolContext) -> Result<String, String> {
    let cmd = resolve(tool, ctx);
    let line = cmd.command_line();

    let path = std::path::Path::new(&cmd.program);
    let exists = if path.is_absolute() {
        path.exists()
    } else {
        // resolve via PATH like the shell would
        which(&cmd.program).is_some()
    };
    if !exists {
        return Err(format!(
            "tool not found: {} (configure it in the Integrations view or tools.toml)",
            cmd.program
        ));
    }

    std::process::Command::new(&cmd.program)
        .args(&cmd.args)
        .spawn()
        .map_err(|e| format!("launch {}: {}", cmd.program, e))?;

    Ok(line)
}

/// Minimal `where.exe` replacement for PATH lookups.
pub fn which(exe: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let names: Vec<String> = if std::path::Path::new(exe).extension().is_some() {
        vec![exe.to_string()]
    } else {
        vec![exe.to_string(), format!("{}.exe", exe)]
    };
    for dir in std::env::split_paths(&path_var) {
        for n in &names {
            let cand = dir.join(n);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_and_split() {
        let ctx = ToolContext {
            file: "C:\\samples\\a b.exe".into(),
            pid: 4242,
            addr: 0x7FF6_1234_5678,
            module: "kernel32.dll".into(),
            rva: 0x1234,
            ..Default::default()
        };
        let s = ctx.substitute("--pid {pid} --addr {addr} \"{file}\" {module}+{rva}");
        assert_eq!(
            s,
            "--pid 4242 --addr 0x7FF612345678 \"C:\\samples\\a b.exe\" kernel32.dll+0x1234"
        );
        let argv = split_args(&s);
        assert_eq!(argv[0], "--pid");
        assert_eq!(argv[1], "4242");
        assert_eq!(argv[4], "C:\\samples\\a b.exe");
    }

    #[test]
    fn builtin_config_has_core_stages() {
        let cfg = ToolsConfig::builtin();
        assert!(!cfg.for_stage(ToolStage::Disassemble).is_empty());
        assert!(!cfg.for_stage(ToolStage::Debug).is_empty());
        assert!(!cfg.for_stage(ToolStage::InspectPe).is_empty());
    }
}
