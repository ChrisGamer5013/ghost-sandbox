/*
   Ghost Sandbox - One-time Malware Analysis disclaimer acknowledgement.
   Shared by both faces of the suite so the restriction cannot drift:

     - GUI: modal dialog shown before the Malware Analysis view opens
     - CLI: `--accept-disclaimer` gate for `ghost run --malware`

   The acknowledgement is recorded once per user (see ack_file()) and the
   terms are only asked again if ACK_VERSION is bumped. Setting the
   GHOST_SKIP_DISCLAIMER=1 environment variable treats the terms as accepted
   (used by the automated end-to-end suites).

   (c) 2026 Ghost Project
*/

use std::path::PathBuf;

/// Recorded acknowledgement version - bump when the terms change to re-ask.
pub const ACK_VERSION: u32 = 3;

pub const TITLE: &str = "Before you continue";
pub const HEADING_EXPERIMENTAL: &str = "Experimental software";
pub const BODY_EXPERIMENTAL: &str = "Ghost Sandbox is an experimental reverse-engineering \
and dynamic-analysis tool. Its instrumentation and containment mechanisms may be incomplete, \
bypassed, or behave unexpectedly.";
pub const HEADING_RISKS: &str = "Important risks";
pub const RISK_BULLETS: [&str; 4] = [
    "An analyzed program may crash, damage data, or affect your system.",
    "API interception and spoofed return values do not guarantee containment.",
    "Ghost Sandbox is not guaranteed to isolate malicious software from your host.",
    "You should analyze untrusted executables only in an appropriately isolated, disposable environment.",
];
pub const HEADING_ASSUMPTION: &str = "Assumption of risk and exclusion of liability";
pub const BODY_ASSUMPTION: &str = "You use Ghost Sandbox entirely at your own risk and remain \
solely responsible for your systems, data, targets, samples and legal compliance. To the maximum \
extent permitted by applicable law, Ghost Project and the author exclude all warranties and assume \
no liability of any kind — contract, tort (including negligence), strict liability or otherwise — \
for any loss, damage, cost or expense arising from the software or its use.";
pub const BODY_ASSUMPTION_LIMIT: &str = "This exclusion does not apply where liability cannot \
lawfully be excluded or limited (for example, liability for intent, gross negligence, or injury to \
life, body or health).";
pub const ACK_NOTE: &str = "This acknowledgement records that this notice was presented and \
accepted for this user. It does not replace the software's licence terms and does not remove \
rights or obligations that applicable law does not allow to be changed by agreement. Accepting \
applies to the GUI and the CLI alike; the recorded version is kept with the acknowledgement, and \
a future release that materially changes this notice will present the updated terms again.";
pub const TYPE_INSTRUCTION: &str = "To continue, type the following sentence exactly:";
pub const ACK_SENTENCE: &str = "I have read this disclaimer and understand the risks.";
pub const CHECKBOX_LABEL: &str = "I understand this is experimental software and that this \
acknowledgement does not guarantee my system will be protected.";
pub const CONTINUE_LABEL: &str = "Continue to analysis";
/// CLI flag that records agreement and lets `ghost run --malware` proceed.
pub const CLI_FLAG: &str = "--accept-disclaimer";

/// Per-user acknowledgement record (shared by GUI and CLI).
pub fn ack_file() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("ghost_sandbox")
        .join("malware_disclaimer_ack.txt")
}

/// Automation override: treat the terms as accepted without a dialog/flag.
pub fn env_skip() -> bool {
    matches!(std::env::var("GHOST_SKIP_DISCLAIMER").as_deref(), Ok("1"))
}

/// True when the current user already agreed to the current terms.
pub fn is_acknowledged() -> bool {
    if env_skip() {
        return true;
    }
    match std::fs::read_to_string(ack_file()) {
        // Exact line match: a truncated or corrupted record never counts.
        Ok(text) => text
            .lines()
            .any(|line| line.trim() == format!("ack_version={}", ACK_VERSION)),
        Err(_) => false,
    }
}

/// Record the acknowledgement for this user ("never asked again").
pub fn record_acknowledgement() -> Result<(), String> {
    let path = ack_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let body = format!(
        "ack_version={}\nacknowledged={}\nnote=Ghost Sandbox malware-analysis disclaimer acknowledgement\n",
        ACK_VERSION, stamp
    );
    std::fs::write(&path, body).map_err(|e| format!("{}: {}", path.display(), e))
}

/// Plain-text notice printed by the CLI when the flag is missing.
pub fn cli_notice() -> String {
    let mut s = String::new();
    s.push_str(TITLE);
    s.push_str("\n\n");
    s.push_str(HEADING_EXPERIMENTAL);
    s.push_str("\n\n");
    s.push_str(&wrap(BODY_EXPERIMENTAL, 78));
    s.push_str("\n\n");
    s.push_str(HEADING_RISKS);
    s.push('\n');
    for b in RISK_BULLETS {
        s.push_str(&format!("* {}\n", wrap(b, 76).replace('\n', "\n  ")));
    }
    s.push('\n');
    s.push_str(HEADING_ASSUMPTION);
    s.push_str("\n\n");
    s.push_str(&wrap(BODY_ASSUMPTION, 78));
    s.push_str("\n\n");
    s.push_str(&wrap(BODY_ASSUMPTION_LIMIT, 78));
    s.push_str("\n\n");
    s.push_str(&wrap(ACK_NOTE, 78));
    s.push_str("\n\n");
    s.push_str(&format!(
        "Malware analysis mode requires a one-time acknowledgement of these terms.\n\
         Re-run the same command with {} to agree and continue. The acknowledgement is\n\
         recorded per user (version + timestamp, shared with the GUI); if it cannot be\n\
         recorded, the run does not start.\n",
        CLI_FLAG
    ));
    s
}

/// Greedy word wrap, so the CLI notice stays readable without new crates.
fn wrap(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = 0usize;
    for (i, word) in text.split_whitespace().enumerate() {
        if i > 0 {
            if line + 1 + word.len() > width {
                out.push('\n');
                line = 0;
            } else {
                out.push(' ');
                line += 1;
            }
        }
        out.push_str(word);
        line += word.len();
    }
    out
}
