/*
   Ghost Sandbox — CLI
   The whole suite, headless, for humans and AI agents:

     ghost inspect <file>               static PE report (json / md / csv / text)
     ghost run <file>                   instrumented run with import/export policy
     ghost run <file> --malware         malware analysis under containment
     ghost policy template <file>       policy skeleton generated from the sample
     ghost tools list                   external tool catalogue (IDA/Ghidra/…)
     ghost tools open                   hand off to an external tool with context
     ghost version
     ghost help [command]               usage for one command, or all of them

   The subcommands support --help / -h.  Commands that produce reports support
   --format json|jsonl|csv|md|text and --out FILE so agents can consume
   machine-readable output. `ghost run --stream` emits one JSON object per line
   while the target runs.
*/

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::pipe_server::PipeMessage;
use crate::report::OutputFormat;

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_INJECT: i32 = 3;
const EXIT_NO_CONNECT: i32 = 4;
const EXIT_DISCLAIMER: i32 = 5;

pub fn run_cli(args: Vec<String>) -> i32 {
    if args.is_empty() {
        println!("{}", usage());
        return EXIT_USAGE;
    }
    match args[0].as_str() {
        "inspect" => cmd_inspect(&args[1..]),
        "run" => cmd_run(&args[1..]),
        "policy" => cmd_policy(&args[1..]),
        "tools" => cmd_tools(&args[1..]),
        "version" | "--version" | "-V" => cmd_version(&args[1..]),
        "help" | "--help" | "-h" => match args.get(1).map(|s| s.as_str()) {
            None => {
                println!("{}", usage());
                EXIT_OK
            }
            Some(cmd) => match usage_for(cmd) {
                Some(text) => {
                    println!("{}", text);
                    EXIT_OK
                }
                None => {
                    eprintln!("unknown command '{}'\n", cmd);
                    println!("{}", usage());
                    EXIT_USAGE
                }
            },
        },
        other => {
            eprintln!("unknown command '{}'\n", other);
            println!("{}", usage());
            EXIT_USAGE
        }
    }
}

fn usage() -> String {
    format!(
        r#"Ghost Sandbox CLI v{}

USAGE
  ghost <command> [options] [-- TARGET ARGS...]

COMMANDS
  inspect <file>            static PE analysis (json | jsonl | csv | md | text)
  run <file>                instrumented run; add --malware for analysis under containment
  policy template <file>    policy skeleton generated from the sample
  tools list|open           external tool catalogue and handoff (IDA, Ghidra, …)
  version [--format json]   tool name, version, formats, command list
  help [command]            this overview, or one command's options

The subcommands accept --help (also -h); `ghost help <command>` narrows this
text to one command.  Reports go to stdout; notices and errors go to stderr.

  ghost inspect <file> [--format json|jsonl|csv|md|text] [--out FILE]
      Static PE analysis: headers, sections + entropy, imports, exports,
      delay imports, SHA-256, packer/protection heuristics.

  ghost run <file> [options] [-- TARGET ARGS...]
      Run an EXE — or load a DLL into the host — under Ghost Sandbox with an
      import/export policy enforced before the entry point executes.

      --args "..."              target command line (EXEs)
      --export NAME             export to invoke after loading a DLL
      --policy FILE             policy TOML to load (see: ghost policy template)
      --block MOD!FUNC[=VALUE]  block a call, answer with VALUE (hex or decimal)
      --observe MOD!FUNC        report every call, pass it through
      --allow MOD!FUNC          explicitly allow (overrides a policy rule)
      --profile FILE            hardware profile TOML to publish
      --drm on|off              anti-tamper/DRM watch mode (default: shim default)
      --duration SECS           watch the target for this long (default 25)
      --dump ADDR[:LEN]         dump LEN bytes (default 256, max 4096) once connected
      --patch ADDR=HEXBYTES     write raw bytes ("--patch main+0x40=90 90 CC")
      --nop ADDR[:LEN]          NOP out LEN bytes (default 1)
      --jmp ADDR                turn a JZ/JNZ at ADDR into an unconditional JMP

      Memory addresses accept three forms (ASLR-safe when symbolic):
        0x140001000            absolute
        main+0x1234            offset into the main module (the EXE)
        mylib.dll+0x40         offset into any loaded module (short or full path)

      --format FMT              report format (default json)
      --out FILE                write the report to FILE instead of stdout
      --stream                  emit JSONL events live while running
      --quiet                   suppress progress lines on stderr

  ghost run <file> --malware [options] [-- TARGET ARGS...]
      Malware analysis mode: the target runs under containment; commands,
      settings changes and execution attempts are observed where the guard
      covers them (best-effort, not a security boundary).  File edits need a
      verdict; without a matching --approve-* flag they are denied and the
      sample receives a believable success code (writes land in the shadow
      store, registry keys are faked and readable back, network calls fail
      like an offline host).  The report carries the full behaviour log.

      --containment guest|untrusted|none
                                restricted token with privileges disabled
                                (default guest), + Low integrity (untrusted),
                                or none (UNCONFINED: full user token; warns)
      --accept-disclaimer       agree to the one-time malware-analysis
                                disclaimer (the GUI dialog records the same
                                agreement; the record is versioned and shared,
                                and a failed save does not count)
      --approve-files           allow file writes without a verdict
      --approve-registry        allow registry writes without a verdict
      --approve-exec            allow child process starts without a verdict
      --allow-network           allow outbound connections without a verdict
      --no-approval             never pause for a verdict (deny by default)
      --no-shadow               do not keep shadow copies of denied writes
      --no-fake-network         report hard network failures instead of fake
                                successes (DNS failures are always reported)
      --no-observe-reads        do not log reads of credential stores
      --shadow-dir PATH         shadow store root (default %TEMP%\GhostSandbox\shadow)
      --mw-timeout MS           approval timeout per operation (default 10000)
      --duration SECS           watch the target for this long (default 25)
      --kill-on-exit            terminate the target when the watch window ends

  ghost policy template <file> [--out FILE]
      Emit a policy TOML skeleton listing every import and export (action
      "allow"); flip entries to "observe"/"block" and pass with --policy.

  ghost tools list [--format json|text]
  ghost tools open --stage STAGE [--tool NAME] [--file F] [--pid N]
                   [--addr A] [--module M] [--rva R] [--func X] [--dry-run]
      External tool handoff (IDA, Ghidra, x64dbg, WinDbg, Cheat Engine, …).
      --dry-run prints the resolved command line without launching.

  ghost version [--format json]

MODULE PATTERNS
  module/function accept "*" (any) and trailing-* prefixes (e.g. "api-ms-*").

EXIT CODES
  0 ok · 2 usage · 3 injection failed · 4 shim never connected
  5 malware-analysis disclaimer not acknowledged or not recordable
    (pass --accept-disclaimer)
"#,
        crate::report::VERSION
    )
}

/// `ghost help <command>` / `ghost <command> --help`: one command's block from
/// the full usage text, plus the shared trailers (exit codes always; module
/// patterns when the command takes MOD!FUNC arguments).
fn usage_for(cmd: &str) -> Option<String> {
    let full = usage();
    let (start, next) = match cmd {
        "inspect" => ("  ghost inspect <file>", "  ghost run <file> [options]"),
        "run" => ("  ghost run <file> [options]", "  ghost policy template"),
        "malware" => ("  ghost run <file> --malware", "  ghost policy template"),
        "policy" | "template" => ("  ghost policy template", "  ghost tools list"),
        "tools" | "list" | "open" => ("  ghost tools list", "  ghost version"),
        "version" => ("  ghost version", "\n\nMODULE PATTERNS"),
        _ => return None,
    };
    let from = full.find(start)?;
    let rest = &full[from..];
    let mut s = match rest.find(next) {
        Some(i) => rest[..i].trim_end().to_string(),
        None => rest.trim_end().to_string(),
    };
    s.push_str("\n\n");
    let tail = if cmd == "run" || cmd == "malware" {
        "\nMODULE PATTERNS"
    } else {
        "\nEXIT CODES"
    };
    if let Some(i) = full.find(tail) {
        s.push_str(full[i + 1..].trim_end());
    }
    s.push('\n');
    Some(s)
}

/// True when `--help` / `-h` appears before any bare `--` (target passthrough).
fn wants_help(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
}

// ─── argument parsing ───────────────────────────────────────

#[derive(Default)]
struct ParsedArgs {
    /// Single-value options ("--duration 5"). Repeated keys keep the last.
    opts: HashMap<String, String>,
    /// Repeatable options ("--block a" "--block b").
    lists: HashMap<String, Vec<String>>,
    positional: Vec<String>,
    /// Everything after a bare "--" (forwarded to the target).
    passthrough: Vec<String>,
}

const FLAG_OPTS: [&str; 15] = [
    "stream",
    "quiet",
    "dry-run",
    "help",
    "malware",
    "no-approval",
    "approve-files",
    "approve-registry",
    "approve-exec",
    "allow-network",
    "no-shadow",
    "no-fake-network",
    "no-observe-reads",
    "kill-on-exit",
    "accept-disclaimer",
];
const LIST_OPTS: [&str; 7] = ["block", "observe", "allow", "dump", "patch", "nop", "jmp"];

impl ParsedArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut out = ParsedArgs::default();
        let mut in_pass = false;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            if in_pass {
                out.passthrough.push(a.clone());
                continue;
            }
            if a == "--" {
                in_pass = true;
                continue;
            }
            let (key, inline_val) = match a.split_once('=') {
                Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
                _ => (a.clone(), None),
            };
            if key.starts_with("--") {
                let name = key.trim_start_matches('-').to_string();
                if FLAG_OPTS.contains(&name.as_str()) {
                    if inline_val.is_none() {
                        out.opts.insert(name, "true".into());
                        continue;
                    }
                }
                let value = match inline_val {
                    Some(v) => v,
                    None => {
                        if i >= args.len() {
                            return Err(format!("--{} needs a value", name));
                        }
                        let v = args[i].clone();
                        i += 1;
                        v
                    }
                };
                if LIST_OPTS.contains(&name.as_str()) {
                    out.lists.entry(name).or_default().push(value);
                } else {
                    out.opts.insert(name, value);
                }
            } else {
                out.positional.push(a.clone());
            }
        }
        Ok(out)
    }

    fn flag(&self, name: &str) -> bool {
        self.opts.get(name).map(|v| v == "true").unwrap_or(false)
    }

    fn format(&self) -> OutputFormat {
        match self.opts.get("format") {
            Some(f) => OutputFormat::parse(f).unwrap_or_else(|| {
                eprintln!("unknown --format '{}', using json", f);
                OutputFormat::Json
            }),
            None => OutputFormat::Json,
        }
    }

    fn out_path(&self) -> Option<&str> {
        self.opts.get("out").map(|s| s.as_str())
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    // Plain numbers are decimal; fall back to hex for values like "1F".
    t.parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(t, 16).ok())
}

/// Parse raw bytes from a string, ignoring any non-hex separators:
/// "90 90 CC", "0x9090cc" and "90,90,cc" all work.
fn parse_hex_args(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// An address given on the command line: absolute (`0x140001000`) or
/// module-relative (`drm_probe.exe+0x1000`, `main+0x40`). Module names are
/// matched against the live module list once the shim connects, so the CLI
/// works with ASLR-relocated images.
#[derive(Debug, Clone)]
enum AddrSpec {
    Abs(u64),
    Sym { module: String, offset: u64 },
}

impl AddrSpec {
    fn display(&self) -> String {
        match self {
            AddrSpec::Abs(a) => format!("0x{:016X}", a),
            AddrSpec::Sym { module, offset } => format!("{}+0x{:X}", module, offset),
        }
    }
}

fn parse_addr_spec(s: &str) -> Option<AddrSpec> {
    let t = s.trim();
    if let Some((module, off)) = t.rsplit_once('+') {
        if !module.trim().is_empty() {
            return Some(AddrSpec::Sym {
                module: module.trim().to_string(),
                offset: parse_u64(off)?,
            });
        }
    }
    parse_u64(t).map(AddrSpec::Abs)
}

/// Resolve a spec against the live module list (populated by EVT_MODULE_LIST,
/// which the shim pushes right after connect). `main` resolves by the target
/// file name when available (list order is not guaranteed while DLL-load
/// events stream in), falling back to the first module with a base.
fn resolve_spec(
    spec: &AddrSpec,
    state: &std::sync::Arc<std::sync::Mutex<crate::app::AppState>>,
    main_name: &str,
) -> Option<u64> {
    match spec {
        AddrSpec::Abs(a) => Some(*a),
        AddrSpec::Sym { module, offset } => {
            let s = state.lock().ok()?;
            let found = if module.eq_ignore_ascii_case("main") {
                let by_name = s.modules.iter().find(|m| {
                    m.base_address != 0
                        && !main_name.is_empty()
                        && (m.name.eq_ignore_ascii_case(main_name)
                            || std::path::Path::new(&m.path)
                                .file_name()
                                .map(|f| f.to_string_lossy().eq_ignore_ascii_case(main_name))
                                .unwrap_or(false))
                });
                by_name.or_else(|| s.modules.iter().find(|m| m.base_address != 0))
            } else {
                s.modules.iter().find(|m| {
                    m.base_address != 0
                        && (m.name.eq_ignore_ascii_case(module)
                            || m.path.eq_ignore_ascii_case(module)
                            || std::path::Path::new(&m.path)
                                .file_name()
                                .map(|f| f.to_string_lossy().eq_ignore_ascii_case(module))
                                .unwrap_or(false))
                })
            };
            found.map(|m| m.base_address.wrapping_add(*offset))
        }
    }
}

/// One `--patch/--nop/--jmp` request; addresses are resolved after connect.
enum MemOp {
    Patch { addr: AddrSpec, bytes: Vec<u8> },
    Nop { addr: AddrSpec, length: u32 },
    Jmp { addr: AddrSpec },
}

impl MemOp {
    fn addr(&self) -> &AddrSpec {
        match self {
            MemOp::Patch { addr, .. } | MemOp::Nop { addr, .. } | MemOp::Jmp { addr } => addr,
        }
    }

    fn resolve(
        &self,
        state: &std::sync::Arc<std::sync::Mutex<crate::app::AppState>>,
        main_name: &str,
    ) -> Option<crate::pipe_server::PipeCommand> {
        let address = resolve_spec(self.addr(), state, main_name)?;
        Some(match self {
            MemOp::Patch { bytes, .. } => crate::pipe_server::PipeCommand::Patch {
                address,
                bytes: bytes.clone(),
            },
            MemOp::Nop { length, .. } => crate::pipe_server::PipeCommand::PatchNop {
                address,
                length: *length,
            },
            MemOp::Jmp { .. } => crate::pipe_server::PipeCommand::PatchJmp { address },
        })
    }
}

// ─── inspect ────────────────────────────────────────────────

fn cmd_inspect(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{}", usage_for("inspect").unwrap_or_else(usage));
        return EXIT_OK;
    }
    let parsed = match ParsedArgs::parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_USAGE;
        }
    };
    let Some(file) = parsed.positional.first() else {
        eprintln!("usage: ghost inspect <file> [--format …] [--out FILE]");
        return EXIT_USAGE;
    };

    let info = match crate::pe_inspect::inspect_file(std::path::Path::new(file)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("inspect failed: {}", e);
            return EXIT_USAGE;
        }
    };
    let mut report = crate::report::SessionReport::empty("inspect");
    report.status = info.summary_line();
    report.sample = Some(info);

    write_or_print(&report, parsed.format(), parsed.out_path())
}

fn write_or_print(
    report: &crate::report::SessionReport,
    format: OutputFormat,
    out: Option<&str>,
) -> i32 {
    match out {
        Some(path) => match report.save(path, format) {
            Ok(()) => {
                eprintln!("report written to {} ({})", path, format.name());
                EXIT_OK
            }
            Err(e) => {
                eprintln!("{}", e);
                EXIT_USAGE
            }
        },
        None => {
            println!("{}", report.render(format));
            EXIT_OK
        }
    }
}

// ─── policy template ────────────────────────────────────────

fn cmd_policy(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{}", usage_for("policy").unwrap_or_else(usage));
        return EXIT_OK;
    }
    match args.first().map(|s| s.as_str()) {
        Some("template") => cmd_policy_template(&args[1..]),
        _ => {
            eprintln!("usage: ghost policy template <file> [--out FILE]");
            EXIT_USAGE
        }
    }
}

fn cmd_policy_template(args: &[String]) -> i32 {
    let parsed = match ParsedArgs::parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_USAGE;
        }
    };
    let Some(file) = parsed.positional.first() else {
        eprintln!("usage: ghost policy template <file> [--out FILE]");
        return EXIT_USAGE;
    };

    let info = match crate::pe_inspect::inspect_file(std::path::Path::new(file)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("inspect failed: {}", e);
            return EXIT_USAGE;
        }
    };

    let mut set = crate::policy::PolicySet::new();
    for (module, function) in info.import_pairs() {
        set.add(crate::policy::PolicyKind::Import, &module, &function);
    }
    for e in &info.exports {
        set.add(crate::policy::PolicyKind::Export, &info.file_name, &e.name);
    }

    let text = match toml::to_string_pretty(&set) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("serialize: {}", e);
            return EXIT_USAGE;
        }
    };
    let header = format!(
        "# Ghost Sandbox policy template for {}\n\
         # {} imports, {} exports — set action = \"observe\" or \"block\" on the\n\
         # entries you care about (\"allow\" rules are not shipped to the shim).\n\
         #   ghost run {} --policy <this file>\n\
         # Block rows take a \"value\" (return value handed to the caller):\n\
         #   [[rule]] kind = \"import\"  module = \"kernel32.dll\"\n\
         #            function = \"IsDebuggerPresent\"  action = \"block\"  value = 1\n\n",
        info.file_name,
        info.total_imports,
        info.exports.len(),
        info.file_name
    );
    let full = format!("{}{}", header, text);

    match parsed.out_path() {
        Some(path) => match std::fs::write(path, &full) {
            Ok(()) => {
                eprintln!(
                    "policy template written to {} ({} rules)",
                    path,
                    set.rules.len()
                );
                EXIT_OK
            }
            Err(e) => {
                eprintln!("write {}: {}", path, e);
                EXIT_USAGE
            }
        },
        None => {
            println!("{}", full);
            EXIT_OK
        }
    }
}

// ─── run ────────────────────────────────────────────────────

/// Best-effort lookup of the bundled default hardware profile
/// (profiles/default.toml), relative to the current directory or the
/// executable (works for the target/debug and target/release layouts).
fn default_profile_path() -> Option<std::path::PathBuf> {
    let mut candidates = vec![std::path::PathBuf::from("profiles/default.toml")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("profiles").join("default.toml"));
            if let Some(up2) = dir.parent().and_then(|p| p.parent()) {
                candidates.push(up2.join("profiles").join("default.toml"));
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn cmd_run(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{}", usage_for("run").unwrap_or_else(usage));
        return EXIT_OK;
    }
    let parsed = match ParsedArgs::parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_USAGE;
        }
    };
    let quiet = parsed.flag("quiet");
    let stream = parsed.flag("stream");
    let Some(file) = parsed.positional.first().cloned() else {
        eprintln!("usage: ghost run <file> [--policy FILE] [--block MOD!FUNC=VAL] …");
        return EXIT_USAGE;
    };

    let format = parsed.format();
    let out = parsed.out_path().map(|s| s.to_string());

    // 0) Malware analysis mode: containment, mediation flags, shadow store.
    //    Everything travels to the shim through the child's environment, which
    //    survives even a low-integrity token (policy shared memory does not).
    let mw_active = parsed.flag("malware");

    // One-time disclaimer gate (same record as the GUI dialog): the flag
    // records agreement; --malware refuses to start until the current terms
    // are acknowledged. The record is per-user and tied to the terms version,
    // and a record that cannot be written does not silently count as
    // acceptance - the run refuses with the disclaimer exit code.
    if parsed.flag("accept-disclaimer") && !crate::disclaimer::is_acknowledged() {
        match crate::disclaimer::record_acknowledgement() {
            Ok(()) => eprintln!(
                "disclaimer accepted - recorded for this user (version + timestamp)"
            ),
            Err(e) => {
                eprintln!(
                    "error: could not record the disclaimer acknowledgement ({}); it does not count as acceptance",
                    e
                );
                return EXIT_DISCLAIMER;
            }
        }
    }
    if mw_active && !crate::disclaimer::is_acknowledged() {
        eprintln!("{}", crate::disclaimer::cli_notice());
        return EXIT_DISCLAIMER;
    }
    let mw_containment = crate::injector::Containment::from_label(
        parsed
            .opts
            .get("containment")
            .map(|s| s.as_str())
            .unwrap_or("guest"),
    );
    if mw_active && mw_containment == crate::injector::Containment::None {
        eprintln!(
            "warning: --containment none disables the token layer - the sample runs with your \
             full user token; use only to debug the guard in a disposable VM"
        );
    }
    let shadow_dir = parsed
        .opts
        .get("shadow-dir")
        .cloned()
        .unwrap_or_else(crate::views::malware_view::default_shadow_dir);
    let mut mw_flags_val: u32 = 0;
    if mw_active {
        use crate::app::mw_flags as F;
        mw_flags_val |= F::ACTIVE;
        if !parsed.flag("no-approval") {
            mw_flags_val |= F::APPROVAL;
        }
        if parsed.flag("approve-files") {
            mw_flags_val |= F::ALLOW_FILE;
        }
        if parsed.flag("approve-registry") {
            mw_flags_val |= F::ALLOW_REGISTRY;
        }
        if parsed.flag("approve-exec") {
            mw_flags_val |= F::ALLOW_EXEC;
        }
        if parsed.flag("allow-network") {
            mw_flags_val |= F::ALLOW_NETWORK;
        }
        if !parsed.flag("no-shadow") {
            mw_flags_val |= F::SHADOW_FILES;
        }
        if !parsed.flag("no-fake-network") {
            mw_flags_val |= F::FAKE_NETWORK;
        }
        if !parsed.flag("no-observe-reads") {
            mw_flags_val |= F::OBSERVE_READS;
        }
        if mw_containment == crate::injector::Containment::Untrusted {
            mw_flags_val |= F::UNTRUSTED_TOKEN;
        }
        if let Err(e) = std::fs::create_dir_all(std::path::Path::new(&shadow_dir).join("files")) {
            eprintln!("shadow store {}: {}", shadow_dir, e);
            return EXIT_USAGE;
        }
        if !quiet {
            eprintln!(
                "malware mode: flags 0x{:04X}, containment {}, shadow store {}",
                mw_flags_val,
                mw_containment.label(),
                shadow_dir
            );
            eprintln!(
                "  approvals: files {} registry {} exec {} network {} | shadow {} fake-net {} reads {}",
                if mw_flags_val & crate::app::mw_flags::ALLOW_FILE != 0 { "allow" } else { "ask" },
                if mw_flags_val & crate::app::mw_flags::ALLOW_REGISTRY != 0 { "allow" } else { "ask" },
                if mw_flags_val & crate::app::mw_flags::ALLOW_EXEC != 0 { "allow" } else { "ask" },
                if mw_flags_val & crate::app::mw_flags::ALLOW_NETWORK != 0 { "allow" } else { "ask" },
                mw_flags_val & crate::app::mw_flags::SHADOW_FILES != 0,
                mw_flags_val & crate::app::mw_flags::FAKE_NETWORK != 0,
                mw_flags_val & crate::app::mw_flags::OBSERVE_READS != 0,
            );
        }
    }
    let mw_env: Vec<(String, String)> = if mw_active {
        vec![
            ("GHOST_MALWARE".to_string(), "1".to_string()),
            ("GHOST_MW_FLAGS".to_string(), mw_flags_val.to_string()),
            ("GHOST_MW_SHADOW".to_string(), shadow_dir.clone()),
            (
                "GHOST_MW_TIMEOUT".to_string(),
                parsed
                    .opts
                    .get("mw-timeout")
                    .cloned()
                    .unwrap_or_else(|| "10000".to_string()),
            ),
            (
                "GHOST_MW_LEVEL".to_string(),
                mw_containment.label().to_string(),
            ),
        ]
    } else {
        Vec::new()
    };

    // 1) Static analysis (also decides EXE vs DLL hosting).
    let info = match crate::pe_inspect::inspect_file(std::path::Path::new(&file)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("cannot analyze '{}': {}", file, e);
            return EXIT_USAGE;
        }
    };
    if !quiet {
        eprintln!("sample: {}", info.summary_line());
    }

    // 2) Policy: base file + CLI overrides.
    let mut policy = match parsed.opts.get("policy") {
        Some(p) => match crate::policy::PolicySet::load_from_file(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("policy: {}", e);
                return EXIT_USAGE;
            }
        },
        None => crate::policy::PolicySet::new(),
    };

    let mut apply_rule = |spec: &str, action: crate::policy::PolicyAction| {
        let (target, val) = match spec.rsplit_once('=') {
            Some((t, v)) => (t, Some(parse_u64(v).unwrap_or(0))),
            None => (spec, None),
        };
        let Some((module, function)) = target.rsplit_once('!') else {
            eprintln!("rule '{}' must look like module.dll!Function", spec);
            return;
        };
        let r = policy.rule_mut(crate::policy::PolicyKind::Import, module, function);
        r.action = action;
        if let Some(v) = val {
            r.value = v;
        }
    };
    for spec in parsed.lists.get("block").into_iter().flatten() {
        apply_rule(spec, crate::policy::PolicyAction::Block);
    }
    for spec in parsed.lists.get("observe").into_iter().flatten() {
        apply_rule(spec, crate::policy::PolicyAction::Observe);
    }
    for spec in parsed.lists.get("allow").into_iter().flatten() {
        apply_rule(spec, crate::policy::PolicyAction::Allow);
    }

    // 2b) Live memory operations (applied as soon as the shim connects).
    let main_name = std::path::Path::new(&file)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut mem_ops: Vec<MemOp> = Vec::new();
    let mut dump_specs: Vec<(AddrSpec, u32)> = Vec::new();
    for spec in parsed.lists.get("patch").into_iter().flatten() {
        let ok = spec
            .split_once('=')
            .and_then(|(a, h)| Some((parse_addr_spec(a)?, parse_hex_args(h)?)))
            .filter(|(_, bytes)| !bytes.is_empty() && bytes.len() <= 256);
        match ok {
            Some((addr, bytes)) => mem_ops.push(MemOp::Patch { addr, bytes }),
            None => {
                eprintln!("--patch expects ADDR=HEXBYTES (max 256), e.g. main+0x40=90 90 CC");
                return EXIT_USAGE;
            }
        }
    }
    for spec in parsed.lists.get("nop").into_iter().flatten() {
        let (a, l) = match spec.split_once(':') {
            Some((a, l)) => (a, l),
            None => (spec.as_str(), "1"),
        };
        match parse_addr_spec(a) {
            Some(addr) => mem_ops.push(MemOp::Nop {
                addr,
                length: parse_u64(l).unwrap_or(1).clamp(1, 256) as u32,
            }),
            None => {
                eprintln!("--nop expects ADDR[:LEN]");
                return EXIT_USAGE;
            }
        }
    }
    for spec in parsed.lists.get("jmp").into_iter().flatten() {
        match parse_addr_spec(spec) {
            Some(addr) => mem_ops.push(MemOp::Jmp { addr }),
            None => {
                eprintln!("--jmp expects ADDR");
                return EXIT_USAGE;
            }
        }
    }
    for spec in parsed.lists.get("dump").into_iter().flatten() {
        let (a, l) = match spec.split_once(':') {
            Some((a, l)) => (a, l),
            None => (spec.as_str(), "256"),
        };
        match parse_addr_spec(a) {
            Some(addr) => {
                dump_specs.push((addr, parse_u64(l).unwrap_or(256).clamp(1, 4096) as u32))
            }
            None => {
                eprintln!("--dump expects ADDR[:LEN]");
                return EXIT_USAGE;
            }
        }
    }

    let entries = match policy.wire_entries() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("policy: {}", e);
            return EXIT_USAGE;
        }
    };
    if !quiet {
        eprintln!("policy: {} active rules", entries.len());
        for e in &entries {
            eprintln!(
                "  {} {}!{} {}",
                if e.kind == crate::policy::KIND_IMPORT {
                    "import"
                } else {
                    "export"
                },
                e.module,
                e.function,
                match e.action {
                    crate::policy::ACTION_BLOCK => format!("block -> 0x{:X}", e.block_value),
                    _ => "observe".to_string(),
                }
            );
        }
    }

    // 3) Publish policy + hardware profile to shared memory. Without
    //    --profile the bundled default profile is published so `ghost run`
    //    always presents a consistent fake identity to the target.
    if let Err(e) = crate::shared_policy::publish(&entries, 0) {
        eprintln!("policy shared memory: {}", e);
        return EXIT_INJECT;
    }
    let mut _profile_shmem: isize = 0;
    let explicit_profile = parsed.opts.get("profile");
    let profile = match explicit_profile {
        Some(pf) => match crate::profile::HardwareProfile::load_from_file(pf) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("profile: {}", e);
                return EXIT_USAGE;
            }
        },
        None => default_profile_path()
            .and_then(|p| crate::profile::HardwareProfile::load_from_file(&p.to_string_lossy()).ok())
            .unwrap_or_else(crate::profile::HardwareProfile::default),
    };
    match crate::shared_profile::publish(&profile, 0) {
        Ok(h) => {
            _profile_shmem = h;
            if !quiet {
                match explicit_profile {
                    Some(pf) => eprintln!("hardware profile published: {}", pf),
                    None => eprintln!("hardware profile published: <bundled default>"),
                }
            }
        }
        Err(e) => {
            eprintln!("profile shared memory: {}", e);
            return EXIT_INJECT;
        }
    }

    // 4) Pick the host process.
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let shim_path = std::env::var("GHOST_SHIM").unwrap_or_else(|_| {
        exe_dir
            .join("sandbox_shim.dll")
            .to_string_lossy()
            .to_string()
    });
    if !std::path::Path::new(&shim_path).is_file() {
        eprintln!("shim not found at {} (set GHOST_SHIM)", shim_path);
        return EXIT_INJECT;
    }

    let duration_secs: u64 = parsed
        .opts
        .get("duration")
        .and_then(|d| d.parse().ok())
        .unwrap_or(25);
    let export = parsed.opts.get("export").cloned().unwrap_or_default();

    let (target, target_args, host_label): (String, Vec<String>, String) = if info.is_dll {
        let host = find_host(&exe_dir).unwrap_or_else(|| {
            let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            format!("{}\\System32\\rundll32.exe", sys)
        });
        let is_rundll = host.to_lowercase().contains("rundll32");
        if is_rundll && export.is_empty() {
            eprintln!(
                "ghost_host.exe was not found; rundll32 requires --export <name> \
                 (or set GHOST_HOST / build target/shimtest/ghost_host.exe)"
            );
            return EXIT_USAGE;
        }
        let mut a = vec![info.path.clone()];
        if is_rundll {
            a.push(export.clone());
            let label = "rundll32.exe (fallback)".to_string();
            (host, a, label)
        } else {
            if !export.is_empty() {
                a.push(export.clone());
            }
            a.push("--seconds".into());
            a.push(duration_secs.min(600).to_string());
            let label = host.clone();
            (host, a, label)
        }
    } else {
        let mut a: Vec<String> = Vec::new();
        if let Some(s) = parsed.opts.get("args") {
            a.extend(crate::tools::split_args(s));
        }
        a.extend(parsed.passthrough.iter().cloned());
        (info.path.clone(), a, "direct".into())
    };

    // 5) Own pipe server — it must be listening before the target starts so
    //    the shim's first connect attempt succeeds (one server per process).
    let pipe = crate::pipe_server::PipeServer::new();
    let _ = pipe.send_command(crate::pipe_server::PipeCommand::Policy {
        entries: entries.clone(),
    });
    if let Some(drm) = parsed.opts.get("drm") {
        let enabled = !matches!(drm.as_str(), "off" | "false" | "0");
        let _ = pipe.send_command(crate::pipe_server::PipeCommand::DrmMode { enabled });
    }

    // 6) Inject + resume. The target's console output is redirected into a
    //    log file so `--stream` stays pure JSONL on stdout.
    let target_log = match &out {
        Some(o) => format!("{}.target.log", o),
        None => std::env::temp_dir()
            .join("ghost_target.log")
            .display()
            .to_string(),
    };
    let injected = if mw_active {
        // Confined launch: restricted token (+ low IL) and an explicit
        // environment block carrying the guard configuration.
        let opts = crate::injector::LaunchOptions {
            log_path: Some(&target_log),
            env: mw_env.clone(),
            containment: mw_containment,
        };
        crate::injector::inject_ex(&target, &shim_path, &target_args, &opts)
    } else {
        crate::injector::inject_redirect(&target, &shim_path, &target_args, Some(&target_log))
    };
    let injected = match injected {
        Ok(p) => p,
        Err(e) => {
            eprintln!("injection failed: {}", e);
            return EXIT_INJECT;
        }
    };
    let pid = injected.pid;
    if let Err(e) = injected.resume() {
        eprintln!("resume failed: {}", e);
        return EXIT_INJECT;
    }
    if !quiet {
        eprintln!(
            "{} started via {} (PID {}) — policy applied before entry point",
            info.file_name, host_label, pid
        );
        eprintln!("  target output: {}", target_log);
    }

    // 7) Collect events.
    let state = std::sync::Arc::new(std::sync::Mutex::new(crate::app::AppState::new()));
    if stream {
        println!(
            "{}",
            serde_json::json!({
                "type": "run_start",
                "time": chrono::Local::now().to_rfc3339(),
                "sample": info.file_name,
                "sha256": info.sha256,
                "pid": pid,
                "host": host_label,
                "policy_rules": entries.len(),
                "target_log": target_log,
                "malware": mw_active,
                "malware_flags": mw_flags_val,
                "containment": mw_containment.label(),
                "shadow_dir": if mw_active { shadow_dir.clone() } else { String::new() },
            })
        );
    }

    let mut ever_connected = false;
    let mut connected_at: Option<Instant> = None;
    let mut sent_ops = mem_ops.is_empty();
    let mut sent_dumps = dump_specs.is_empty();
    let mut memory_dumps: Vec<crate::report::MemoryDumpRec> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    while Instant::now() < deadline {
        // Once the shim is up, apply patches, then request dumps — each after
        // a short settle delay so the target has executed its entry point.
        // Symbolic addresses wait for the module list (up to 3 s).
        if let Some(t0) = connected_at {
            let elapsed = t0.elapsed();
            if !sent_ops && elapsed >= Duration::from_millis(200) {
                // Symbolic addresses (main+…, dll+…) need the full module list.
                let list_seen = state.lock().map(|s| s.module_list_seen).unwrap_or(false);
                let ready =
                    list_seen && mem_ops.iter().all(|op| op.resolve(&state, &main_name).is_some());
                if ready || elapsed >= Duration::from_millis(3000) {
                    for op in &mem_ops {
                        match op.resolve(&state, &main_name) {
                            Some(cmd) => {
                                if let Err(e) = pipe.send_command(cmd) {
                                    eprintln!("memory op failed: {}", e);
                                }
                            }
                            None => {
                                eprintln!("memory op skipped: unknown module in {}", op.addr().display())
                            }
                        }
                    }
                    if !quiet && !mem_ops.is_empty() {
                        eprintln!("memory: {} patch(es) sent", mem_ops.len());
                    }
                    sent_ops = true;
                }
            }
            if sent_ops && !sent_dumps && elapsed >= Duration::from_millis(600) {
                let list_seen = state.lock().map(|s| s.module_list_seen).unwrap_or(false);
                let ready = list_seen
                    && dump_specs
                        .iter()
                        .all(|(spec, _)| resolve_spec(spec, &state, &main_name).is_some());
                if ready || elapsed >= Duration::from_millis(3000) {
                    for (spec, length) in &dump_specs {
                        match resolve_spec(spec, &state, &main_name) {
                            Some(address) => {
                                let _ = pipe.send_command(crate::pipe_server::PipeCommand::Dump {
                                    address,
                                    length: *length,
                                });
                            }
                            None => eprintln!(
                                "dump skipped: unknown module in {}",
                                spec.display()
                            ),
                        }
                    }
                    if !quiet && !dump_specs.is_empty() {
                        eprintln!("memory: {} dump(s) requested", dump_specs.len());
                    }
                    sent_dumps = true;
                }
            }
        }

        match pipe.rx.recv_timeout(Duration::from_millis(150)) {
            Ok(msg) => {
                if matches!(msg, PipeMessage::Connected { .. }) {
                    ever_connected = true;
                    connected_at = Some(Instant::now());
                }
                if let PipeMessage::MemoryDump { address, data } = &msg {
                    memory_dumps.push(crate::report::MemoryDumpRec::new(*address, data));
                }
                // Malware mode: answer approval requests immediately from the
                // flag set (deny unless the category was explicitly approved).
                if mw_active {
                    if let PipeMessage::MalwareOp {
                        op_id,
                        category,
                        action,
                        pending: true,
                        target,
                        api,
                        ..
                    } = &msg
                    {
                        use crate::app::mw_flags as F;
                        let allow = match category {
                            1 => mw_flags_val & F::ALLOW_FILE != 0,
                            2 => mw_flags_val & F::ALLOW_REGISTRY != 0,
                            3 => mw_flags_val & F::ALLOW_EXEC != 0,
                            4 | 5 => mw_flags_val & F::ALLOW_NETWORK != 0,
                            _ => false,
                        };
                        if let Err(e) = pipe
                            .send_command(crate::pipe_server::PipeCommand::MalwareVerdict {
                                op_id: *op_id,
                                allow,
                            })
                        {
                            eprintln!("malware verdict failed: {}", e);
                        } else if !quiet {
                            eprintln!(
                                "malware: #{} {} {} → {} ({})",
                                op_id,
                                crate::app::mw_category_name(*category),
                                crate::app::mw_action_name(*action),
                                if allow { "ALLOWED" } else { "DENIED — fake success" },
                                if target.is_empty() { api.as_str() } else { target.as_str() },
                            );
                        }
                    }
                }
                if stream {
                    if let Some(v) = msg_to_json(&msg) {
                        println!("{}", v);
                    }
                }
                crate::pump::apply(&state, msg);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    // 8) Report.
    if parsed.flag("kill-on-exit") {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
        use winapi::um::winnt::PROCESS_TERMINATE;
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 0xB0B);
                CloseHandle(h);
                if !quiet {
                    eprintln!("target PID {} terminated (--kill-on-exit)", pid);
                }
            }
        }
    }
    let mut report = build_report(
        &state,
        Some(info),
        &policy,
        format!("PID {} via {} — target output: {}", pid, host_label, target_log),
    );
    report.memory_dumps = memory_dumps;
    if mw_active {
        report.kind = "malware-run".into();
        report.shadow_dir = shadow_dir.clone();
        report.shadow_files = crate::views::malware_view::shadow_file_records(&shadow_dir);
        report.status = format!(
            "{} | malware flags 0x{:04X}, containment {}",
            report.status,
            mw_flags_val,
            mw_containment.label()
        );
    }
    let connected = ever_connected || state.lock().map(|s| s.connected).unwrap_or(false);
    if stream {
        let summary = serde_json::json!({
            "type": "run_end",
            "time": chrono::Local::now().to_rfc3339(),
            "connected": connected,
            "counts": report.counts,
        });
        println!("{}", summary);
        if let Some(out) = &out {
            let _ = report.save(out, OutputFormat::Json);
        }
        return if connected { EXIT_OK } else { EXIT_NO_CONNECT };
    }

    let code = write_or_print(&report, format, out.as_deref());
    if code == EXIT_OK && !connected {
        eprintln!("warning: the shim never connected (GUI instance holding the pipe? wrong shim?)");
        return EXIT_NO_CONNECT;
    }
    code
}

fn find_host(exe_dir: &std::path::Path) -> Option<String> {
    if let Ok(p) = std::env::var("GHOST_HOST") {
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    let candidates = [
        exe_dir.join("ghost_host.exe"),
        std::path::PathBuf::from("target\\shimtest\\ghost_host.exe"),
        std::path::PathBuf::from("target\\debug\\ghost_host.exe"),
        std::path::PathBuf::from("ghost_host.exe"),
    ];
    candidates
        .iter()
        .find(|p| p.is_file())
        .map(|p| p.display().to_string())
}

/// Build the unified report from the collected state (same schema as the GUI
/// export — agents get identical output from either front end).
fn build_report(
    state: &std::sync::Arc<std::sync::Mutex<crate::app::AppState>>,
    sample: Option<crate::pe_inspect::PeInfo>,
    policy: &crate::policy::PolicySet,
    status: String,
) -> crate::report::SessionReport {
    let s = state.lock().unwrap();
    let mut report = crate::report::SessionReport::empty("sandbox-run");
    report.status = status;
    if s.connected || s.target_pid != 0 {
        report.target = Some(crate::report::TargetInfo {
            pid: s.target_pid,
            name: s.target_name.clone(),
            connected: s.connected,
        });
    }
    report.sample = sample;
    report = report.with_policy(policy);
    report.counts = crate::report::Counts {
        trace_events: s.trace_events.len(),
        api_calls_total: s.total_api_calls,
        spoofed_total: s.total_spoofed,
        drm_events: s.drm_events.len(),
        drm_detections: s.drm_detections,
        policy_hits: s.policy_hits.len(),
        policy_blocked: s.policy_blocked,
        policy_observed: s.policy_observed,
        modules: s.modules.len(),
        memory_patches: s.memory_patches,
        malware_ops: s.malware_ops.len(),
        malware_allowed: s.malware_allowed,
        malware_shadowed: s.malware_shadowed,
        malware_faked: s.malware_faked,
        malware_blocked: s.malware_blocked,
    };
    report.modules = s.modules.clone();
    report.policy_hits = s.policy_hits.iter().cloned().collect();
    report.drm_events = s.drm_events.iter().cloned().collect();
    report.malware_ops = s.malware_ops.iter().cloned().collect();
    report.shadow_dir = s.shadow_dir.clone();
    report.trace = s.trace_events.iter().rev().take(2000).cloned().collect();
    report
}

/// One live event as a compact JSON object (for --stream / JSONL consumers).
fn msg_to_json(msg: &PipeMessage) -> Option<serde_json::Value> {
    use serde_json::json;
    let ts = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
    Some(match msg {
        PipeMessage::Connected { pid, name } => {
            json!({"type":"connected","time":ts,"pid":pid,"name":name})
        }
        PipeMessage::Disconnected => json!({"type":"disconnected","time":ts}),
        PipeMessage::Trace {
            thread_id,
            function,
            module,
            params,
            return_value,
            duration_us,
            spoofed,
        } => json!({
            "type":"trace","time":ts,"thread":thread_id,"module":module,"function":function,
            "params":params,"return":return_value,"duration_us":duration_us,"spoofed":spoofed
        }),
        PipeMessage::DllLoad { name, base_address, size } => json!({
            "type":"dll_load","time":ts,"name":name,
            "base":format!("0x{:X}", base_address),"size":size
        }),
        PipeMessage::DllUnload { name } => json!({"type":"dll_unload","time":ts,"name":name}),
        PipeMessage::Exception { code, address } => json!({
            "type":"exception","time":ts,
            "code":format!("0x{:08X}", code),"address":format!("0x{:X}", address)
        }),
        PipeMessage::PatchAck { address, success } => json!({
            "type":"patch_ack","time":ts,
            "address":format!("0x{:X}", address),"success":success
        }),
        PipeMessage::CpuidTrap { leaf, subleaf, eax, ebx, ecx, edx } => json!({
            "type":"cpuid","time":ts,"leaf":leaf,"subleaf":subleaf,
            "eax":eax,"ebx":ebx,"ecx":ecx,"edx":edx
        }),
        PipeMessage::VTableMod { address, index, old_value, new_value } => json!({
            "type":"vtable_mod","time":ts,"address":format!("0x{:X}", address),"index":index,
            "old":format!("0x{:X}", old_value),"new":format!("0x{:X}", new_value)
        }),
        PipeMessage::MemoryDump { address, data } => json!({
            "type":"memory_dump","time":ts,
            "address":format!("0x{:X}", address),"len":data.len(),
            "hex":data.iter().map(|b| format!("{:02X}", b)).collect::<String>(),
            "ascii":data.iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect::<String>()
        }),
        PipeMessage::Registers { rax, rip, .. } => json!({
            "type":"registers","time":ts,
            "rax":format!("0x{:X}", rax),"rip":format!("0x{:X}", rip)
        }),
        PipeMessage::ModuleList { modules } => json!({
            "type":"module_list","time":ts,"count":modules.len()
        }),
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
        } => json!({
            "type":"drm","time":ts,"category":crate::app::drm_category_name(*category),
            "severity":severity,"verdict":crate::app::drm_verdict_name(*verdict),
            "api":api,"api_module":api_module,"caller":caller_module,
            "rva":format!("0x{:X}", caller_rva),"ret":format!("0x{:X}", ret_value),
            "expected":expected,"returned":returned,"detail":detail
        }),
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
        } => json!({
            "type":"policy_hit","time":ts,
            "kind":crate::app::policy_kind_name(*kind),
            "action":crate::app::policy_action_name(*action),
            "blocked":blocked,"return":format!("0x{:X}", ret_value),
            "module":module,"function":function,"caller":caller_module,
            "rva":format!("0x{:X}", caller_rva),"detail":detail
        }),
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
        } => json!({
            "type":"malware_op","time":ts,"op_id":op_id,
            "category":crate::app::mw_category_name(*category),
            "action":crate::app::mw_action_name(*action),
            "verdict":if *pending { "pending" } else { crate::app::mw_verdict_name(*verdict) },
            "pending":pending,"flags":format!("0x{:04X}", flags),
            "api":api,"target":target,
            "caller":caller_module,"rva":format!("0x{:X}", caller_rva),
            "detail":detail
        }),
    })
}

// ─── tools ──────────────────────────────────────────────────

fn cmd_tools(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{}", usage_for("tools").unwrap_or_else(usage));
        return EXIT_OK;
    }
    match args.first().map(|s| s.as_str()) {
        Some("list") => cmd_tools_list(&args[1..]),
        Some("open") => cmd_tools_open(&args[1..]),
        _ => {
            eprintln!("usage: ghost tools list|open …");
            EXIT_USAGE
        }
    }
}

fn tools_config_path() -> String {
    std::env::var("GHOST_TOOLS_FILE").unwrap_or_else(|_| "tools.toml".to_string())
}

fn cmd_tools_list(args: &[String]) -> i32 {
    let parsed = match ParsedArgs::parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_USAGE;
        }
    };
    let cfg = crate::tools::ToolsConfig::load_or_builtin(&tools_config_path());
    match parsed.opts.get("format").map(|s| s.as_str()) {
        Some("text") | Some("md") => {
            println!("{:<24} {:<14} {:<8} {}", "NAME", "STAGE", "ON", "EXECUTABLE");
            for t in &cfg.tools {
                println!(
                    "{:<24} {:<14} {:<8} {}",
                    t.name,
                    t.stage.wire(),
                    if t.enabled { "yes" } else { "no" },
                    t.path
                );
            }
        }
        Some("json") | None => {
            println!(
                "{}",
                serde_json::to_string_pretty(&cfg).unwrap_or_default()
            );
        }
        Some(f) => {
            eprintln!("unknown format '{}'", f);
            return EXIT_USAGE;
        }
    }
    EXIT_OK
}

fn cmd_tools_open(args: &[String]) -> i32 {
    let parsed = match ParsedArgs::parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            return EXIT_USAGE;
        }
    };
    let stage = match parsed.opts.get("stage") {
        Some(s) => crate::tools::ToolStage::from_wire(s),
        None => {
            eprintln!(
                "--stage is required (disassemble|decompile|debug|memory_edit|hex_view|\
                 strings|inspect_pe|trace_view|custom)"
            );
            return EXIT_USAGE;
        }
    };
    let cfg = crate::tools::ToolsConfig::load_or_builtin(&tools_config_path());

    let tool = match parsed.opts.get("tool") {
        Some(name) => cfg.tools.iter().find(|t| &t.name == name).cloned(),
        None => cfg.for_stage(stage).first().map(|t| (*t).clone()),
    };
    let Some(tool) = tool else {
        eprintln!(
            "no tool configured for stage '{}' (ghost tools list; edit {})",
            stage.wire(),
            tools_config_path()
        );
        return EXIT_USAGE;
    };

    let ctx = crate::tools::ToolContext {
        file: parsed.opts.get("file").cloned().unwrap_or_default(),
        pid: parsed.opts.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0),
        addr: parsed.opts.get("addr").and_then(|v| parse_u64(v)).unwrap_or(0),
        module: parsed.opts.get("module").cloned().unwrap_or_default(),
        rva: parsed.opts.get("rva").and_then(|v| parse_u64(v)).unwrap_or(0),
        base: parsed.opts.get("base").and_then(|v| parse_u64(v)).unwrap_or(0),
        func: parsed.opts.get("func").cloned().unwrap_or_default(),
        bytes: parsed.opts.get("bytes").cloned().unwrap_or_default(),
        name: parsed.opts.get("name").cloned().unwrap_or_default(),
    };

    let resolved = crate::tools::resolve(&tool, &ctx);
    if parsed.flag("dry-run") {
        println!("{}", resolved.command_line());
        return EXIT_OK;
    }
    match crate::tools::launch(&tool, &ctx) {
        Ok(cmd) => {
            println!("launched: {}", cmd);
            EXIT_OK
        }
        Err(e) => {
            eprintln!("{}", e);
            EXIT_USAGE
        }
    }
}

// ─── version ────────────────────────────────────────────────

fn cmd_version(args: &[String]) -> i32 {
    if wants_help(args) {
        println!("{}", usage_for("version").unwrap_or_else(usage));
        return EXIT_OK;
    }
    let json = args.iter().any(|a| a == "--format")
        || args.iter().any(|a| a == "json");
    if json {
        println!(
            "{}",
            serde_json::json!({
                "tool": crate::report::TOOL_NAME,
                "version": crate::report::VERSION,
                "formats": ["json", "jsonl", "csv", "md", "text"],
                "commands": ["inspect", "run", "policy template", "tools list", "tools open", "version", "help"],
            })
        );
    } else {
        println!(
            "{} {} — dynamic binary instrumentation, live memory editing,\n\
             hardware identity spoofing, import/export sandbox and DRM analysis.",
            crate::report::TOOL_NAME,
            crate::report::VERSION
        );
    }
    EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options_lists_and_passthrough() {
        let args: Vec<String> = vec![
            "sample.exe".into(),
            "--duration".into(),
            "5".into(),
            "--block".into(),
            "kernel32.dll!IsDebuggerPresent=0x1".into(),
            "--block=kernel32.dll!GetTickCount64".into(),
            "--observe".into(),
            "user32.dll!MessageBoxW".into(),
            "--stream".into(),
            "--".into(),
            "-foo".into(),
            "bar".into(),
        ];
        let p = ParsedArgs::parse(&args).unwrap();
        assert_eq!(p.positional, vec!["sample.exe"]);
        assert_eq!(p.opts.get("duration").unwrap(), "5");
        assert!(p.flag("stream"));
        let blocks = p.lists.get("block").unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], "kernel32.dll!IsDebuggerPresent=0x1");
        assert_eq!(blocks[1], "kernel32.dll!GetTickCount64");
        assert_eq!(p.lists.get("observe").unwrap()[0], "user32.dll!MessageBoxW");
        assert_eq!(p.passthrough, vec!["-foo", "bar"]);
    }

    #[test]
    fn parses_u64_hex_and_decimal() {
        assert_eq!(parse_u64("0x1F"), Some(31));
        assert_eq!(parse_u64("31"), Some(31));
        assert_eq!(parse_u64("zzz"), None);
    }

    #[test]
    fn message_json_tags_policy_hits() {
        let msg = PipeMessage::PolicyHit {
            kind: 1,
            action: 2,
            blocked: true,
            ret_value: 1,
            module: "kernel32.dll".into(),
            function: "IsDebuggerPresent".into(),
            caller_module: "game.exe".into(),
            caller_rva: 0x1234,
            detail: "blocked".into(),
        };
        let v = msg_to_json(&msg).unwrap();
        assert_eq!(v["type"], "policy_hit");
        assert_eq!(v["action"], "block");
        assert_eq!(v["function"], "IsDebuggerPresent");
    }
}
