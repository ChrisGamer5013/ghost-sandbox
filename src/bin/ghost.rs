/*
   Ghost Sandbox — CLI entry point (`ghost.exe`)

   The full suite, headless: static inspection, instrumented runs with
   import/export control, external tool handoff, and machine-readable
   reports (JSON / JSONL / CSV / Markdown) for AI agents.
*/

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = ghost_sandbox::cli::run_cli(args);
    std::process::exit(code);
}
