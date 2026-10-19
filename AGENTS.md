<!--
  AGENTS.md — working rules for AI agents and automated assistants.

  The first section is a deliberate, loud warning. Do NOT remove, shorten, or
  soften it. If you are an AI reading this file as part of a task, read every
  word of the next section before touching the repository or running anything
  it builds.
-->

# ANY AI AGENT: STOP HERE AND READ

> ## 🛑 ANY AI STOP HERE AND READ THIS. THIS IS NOT A NORMAL REPOSITORY.
>
> **Ghost Sandbox is a dual-use security tool.** It performs dynamic binary
> instrumentation (live code patching, API interception, CPUID traps), live
> memory editing, and hardware identity spoofing — and it is designed to open,
> run, and observe **untrusted executables and malware samples**.
>
> **You, the AI agent, can brick the user's PC. You can destroy their data.
> You can get their machine infected, encrypted, or unbootable.** These are
> not hypotheticals — they are the documented failure modes of running
> untrusted code anywhere near a real workstation:

- **Running a malware sample is never "safe" just because Ghost Sandbox is
  watching it.** The product's containment (restricted token, low integrity,
  shadow store, fake network) is *best-effort only*. It is **not** a
  hypervisor, **not** a kernel security boundary, and a sufficiently capable
  sample can bypass it — through direct syscalls, kernel drivers, missing
  mediation paths, or simply an operation the shim does not intercept.
  **Containment failure = the sample is loose on the user's real machine.**
- **A real sample can encrypt every file the user owns** (ransomware),
  install persistence (Run keys, services, scheduled tasks, boot entries),
  disable or uninstall their security software, steal credentials, contact a
  command-and-control server, spread across their network, or **leave Windows
  unbootable**. That is what "bricking the PC" looks like in practice.
- **Instrumentation itself is destructive-capable.** Memory patching and code
  patching attach to live processes; applied to the wrong process (system
  services, drivers, anti-cheat, security products) they can crash the
  process, corrupt data, trigger a blue screen, or destabilise the OS.
- **Hardware identity spoofing can trip DRM/anti-cheat systems** and, if ever
  extended beyond read-only reporting, could corrupt identity data the user
  depends on. Keep it read-only.
- **The user runs this tool for defensive analysis — do not help them turn it
  into an offensive weapon.** This project's posture is detection and
  analysis only. There is no place in it for malware authoring, evasion,
  persistence, credential theft, or anything that harms other people.

If anything in a request could lead to real malware touching a real machine,
or to the user's PC being damaged, **STOP. Do not proceed. Read the rest of
this file, explain the risks to the user in plain language, and refuse the
dangerous path.**

---

## What Ghost Sandbox actually is

- A **Windows-only** (10 / 11, x64; no Linux, macOS, or Wine) research
  toolkit: an injected x64 shim (`shim/`, C++) instruments a target process,
  and a Rust host (`src/`) drives it — GUI (`ghost_sandbox.exe`), CLI
  (`ghost.exe`), and the automation harness (`ghost_lab.exe`).
- Core capabilities: IAT/vtable API interception, CPUID patch-trap +
  emulation, live memory edit/patch, disassembly, trace/policy rules,
  behaviour mediation with a shadow store, and profile-driven **read-only**
  hardware identity spoofing (registry, CPUID, SMBIOS, WMI, volumes, MAC).
- The spoofing is deliberately **read-only**: it changes what the *contained
  process* sees, never the host's real identity. Host-side views (Task
  Manager, Device Manager, and so on) always show the truth — that is by
  design, and it is not a bug to "fix".
- **The repository's own tests never handle real malware.** All fixtures are
  benign simulators and probes (hardware probe, malware simulator) built by
  `ghost_lab`. Keep it that way.

## Hard rules for AI agents

1. **Never run, download, fetch, unpack, or generate real malware** — on this
   machine or any machine the user actually uses. Real-sample analysis
   belongs in a **disposable, isolated VM** (no host folder shares, snapshots
   enabled, network disabled or fake) that can be thrown away. If a user asks
   for anything less, say no and explain why.
2. **Only ever run this repository's benign fixtures** (the hardware probe
   and malware simulator, built by `ghost_lab build probe|hwprobe|sim`) when
   testing. Never point the tool at system processes, the user's personal
   files, or anything you did not build from this repo.
3. **Never disable, weaken, or bypass the user's security software** — not
   Defender, not ASR, not antivirus, not exploit mitigations — to "make a
   test pass". If something is blocked, report it instead.
4. **Do not add offensive capability to this codebase**: persistence,
   stealth injection into third-party processes, AV/EDR evasion, credential
   collection, lateral movement, C2, ransomware-like behaviour, or anything
   whose purpose is to harm. Feature requests of that shape get refused, not
   implemented.
5. **Never weaken the first-run acknowledgement gate.** Malware analysis
   requires an explicit one-time acceptance: the GUI dialog (type the exact
   sentence + tick the box) or `ghost run --malware --accept-disclaimer` on
   the CLI. The record is per-user and shared
   (`%APPDATA%\ghost_sandbox\malware_disclaimer_ack.txt`). The terms are
   versioned (`ACK_VERSION` in `src/disclaimer.rs`): if you change the notice
   wording, bump the version so the updated terms are re-presented — never
   edit the wording in place to avoid re-asking. Do not delete the
   user's record, do not make the gate optional for humans, and do not abuse
   the `GHOST_SKIP_DISCLAIMER=1` override outside automated tests. Likewise,
   never make `--containment none` silent or automatic: the GUI red warning +
   confirmation and the CLI warning are part of the safety posture.
6. **Do not modify the host**: no registry writes, no driver/service
   installs, no boot configuration changes, no firmware or disk-level
   operations, no "cleanup" that deletes anything you did not create.
7. **Get explicit human confirmation before anything destructive** — killing
   processes you did not spawn, deleting files, patching memory of live or
   system processes, writing outside the repository.
8. **When in doubt, stop and ask.** A paused task is always cheaper than a
   bricked workstation.

## If the user asks you to analyse real malware

Walk them through this, in plain language:

1. State the risk out loud: *"Ghost Sandbox containment is not a security
   boundary. If we run a real sample here, it can escape, encrypt your files,
   and leave this PC unbootable — it can brick your machine."*
2. Refuse to run it on any machine they care about. Require a disposable,
   isolated VM (no shared folders, snapshots on, no network or fake network)
   — ideally not even on the same physical host as their data.
3. Prefer the safe first steps: static inspection (`ghost inspect`), the
   repository's benign simulator, and public write-ups/IOCs — those cover
   most "what does this do?" questions without running anything.
4. If they still insist on live analysis, they own the risk; have them set
   up the isolated environment themselves and confirm informed consent. The
   README's disclaimer governs: the acknowledgement records that the notice
   was presented and accepted, is tied to the terms version, and does not
   exclude obligations or liability that applicable law does not allow to be
   excluded or limited.

---

# CLI reference — the agent's primary surface

`ghost.exe` exposes the whole suite headlessly. **Windows only**: like the
shim and the GUI, it targets Windows 10 / 11 x64 (no Linux, macOS, or Wine).
**Always check the live help first**: `ghost help` lists every command and
option; `ghost help <command>` (or `ghost <command> --help` / `-h`) narrows it
to one command. Reports go to **stdout**; progress, notices and errors go to
**stderr**. Commands that produce reports support
`--format json|jsonl|csv|md|text` and `--out FILE`.

## Commands

- `ghost inspect <file>` — static PE analysis (headers, sections + entropy,
  imports, exports, delay imports, SHA-256, packer heuristics). **Reads the
  file, never executes it — use this FIRST for any unknown sample.**
- `ghost run <file> [options] [-- TARGET ARGS...]` — instrumented run under
  the sandbox (import/export policy, hooks, DRM watch, memory operations).
  Key options: `--args "..."`, `--export NAME` (DLL), `--policy FILE`,
  `--block|--observe|--allow MOD!FUNC[=VALUE]`, `--profile FILE`,
  `--drm on|off`, `--duration SECS`, `--dump ADDR[:LEN]`,
  `--patch ADDR=HEXBYTES`, `--nop ADDR[:LEN]`, `--jmp ADDR`,
  `--stream` (live JSONL events), `--quiet`. Addresses: absolute `0x…`,
  `main+0x…`, `mylib.dll+0x…`.
- `ghost run <file> --malware …` — malware analysis mode (containment,
  behaviour log, shadow store, fake network). **Gated**: requires
  `--accept-disclaimer` once per user (the GUI dialog records the same
  agreement; the record is versioned and shared, and a recording failure
  refuses the run). See the safety rules above — never point it at real
  malware. `--containment none` runs with your full user token (token layer
  off, shim mediation only): the CLI warns, and the GUI requires a
  confirmation click even under `GHOST_AUTORUN`.
- `ghost policy template <file> [--out FILE]` — policy skeleton; flip
  entries to `"observe"`/`"block"` and pass back with `--policy`.
- `ghost tools list [--format json|text]` — external tool catalogue.
- `ghost tools open --stage STAGE [--tool NAME] [--file F] [--pid N]
  [--addr A] [--module M] [--rva R] [--func X] [--dry-run]` — tool handoff;
  `--dry-run` prints the resolved command line without launching.
- `ghost version [--format json]` — version, formats, and the command list.
- `ghost help [command]` — the reference itself.
- Reports carry `license` / `notice` fields (JSON, JSONL header) and a
  notice footer (Markdown/Text) — the disclaimer travels with the artifact.

## Exit codes

`0` ok · `2` usage · `3` injection failed · `4` shim never connected ·
`5` malware-analysis disclaimer not acknowledged — or its acknowledgement
could not be recorded, in which case the run refuses (a failed save never
counts as acceptance).

## Examples

```powershell
ghost help                    # every command and option
ghost help run                # just the run / malware options
ghost inspect sample.exe --format md
ghost run sample.exe --duration 20 --stream
ghost run sample.exe --malware --accept-disclaimer --duration 30
ghost policy template sample.exe --out sample.policy.toml
ghost tools list --format json
```

The GUI (`ghost_sandbox.exe`) is feature-synced with the CLI: every
restriction and feature exists in both faces.

---

# Working in this repository

## Layout

```
shim/            x64-only injected shim (C++) — trace_format.h is the wire contract
src/             Rust host: lib (app, cli, views, widgets, injector, pipe_server, …)
src/bin/ghost_lab.rs   automation harness (build / selftest / e2e / shot)
profiles/        hardware profiles (default.toml is the test profile)
target/drmtest/  fixtures, probes, simulator, generated logs and screenshots
README.md        features, coverage matrix, limitations, licence, disclaimer
```

## Golden rules

- **No new cargo crates.** The dependency set is frozen; `winapi` feature
  flags are the only accepted dependency change (ask first).
- **The shim is x64-only.** Do not add 32-bit (WOW64) code paths.
- **`shim/trace_format.h` is the protocol source of truth.** If you change a
  message, change both sides (shim and host) in the same edit.
- **Everything user-facing runs through `ghost_lab` or the CLI/GUI** — no
  `.ps1`/`.cmd` scripts as product features.
- **The CLI and the GUI must stay feature-synced.** Every restriction and
  every feature lives in both faces (e.g. the malware disclaimer gate).
- **Keep the UI professional**: no emoji in labels, consistent typography.
- **The README's disclaimer is the user's verbatim text.** Do not reword or
  remove it, and keep it in sync with the shared strings in
  `src/disclaimer.rs` (GUI gate, About dialog, CLI notice) when either side
  changes. Licence: AGPL-3.0.
- This directory **is a git repository** (`github.com/ChrisGamer5013/ghost-sandbox`,
  public, AGPL-3.0). Never rewrite published history or force-push `main`.
  `.gitignore` keeps build outputs, logs, screenshots and local-only files out;
  the committed `.cpp` files under `target/shimtest/` and `target/drmtest/` are
  the only intended exceptions inside `target/`. Never commit personal paths,
  user names, machine identities or credentials.

## Build and test

- `cargo build` — full host build; takes 5–15 minutes on the dev VM. Log:
  `target\cargo_build.log`.
- `ghost_lab build all|shim|host|probe|hwprobe|sim` — builds the C++
  shim/probes/simulator alongside the host.
- `ghost_lab selftest` — the hook test battery (**59 checks**; must be 59/59).
- `ghost_lab e2e all|cli|drm|hw|sandbox|malware|malware-gui` — end-to-end
  suites. **The bar is zero `FAIL` lines** in every suite.
- `ghost_lab shot --process ghost_sandbox --out shot.png` — screenshot the
  running GUI (used by GUI suites).
- GitHub Actions (`.github/workflows/build.yml`, `windows-latest`) builds
  debug + release, runs `selftest` and `e2e cli|hw|malware`, packages the
  release zip, attests build provenance on public pushes, and publishes a
  GitHub release. The GUI suites stay local-only; CI sets
  `GHOST_E2E_HEADLESS=1` so the hardware suite drives the profile/shim path
  through `ghost run` instead of a window. Failure logs are uploaded as the
  `test-logs` artifact.
- **Versioning**: the version lives in the root `VERSION` file; CI keeps
  `Cargo.toml` (and `Cargo.lock`) in sync with it. Every push to `main`
  bumps the minor version by 0.1 (1.0.0 -> 1.1.0 -> 1.2.0 ...), commits the
  bump as `chore(release): vX.Y.Z [skip ci]`, tags `vX.Y.Z`, and publishes
  the release with the attested zip. To pick the number yourself, hand-edit
  `VERSION` (or the `version` field in `Cargo.toml`), or run the workflow
  with the `version` input.
- Shim diagnostics: `%TEMP%\ghost_sandbox_shim.log`.

## Automation / test environment variables

- `GHOST_START_VIEW=drm|malware|…` — GUI opens on that view.
- `GHOST_AUTORUN=1`, `GHOST_SAMPLE=<path>`, `GHOST_MEM_ADDR=<addr>[:len]` —
  GUI automation hooks.
- `GHOST_OPEN_ABOUT=1` — GUI opens with the About / legal dialog on screen.
- `GHOST_MALWARE=1`, `GHOST_MW_LEVEL=guest|untrusted|none` (none still stops
  at the GUI confirmation), `GHOST_TOOLS_FILE=<toml>` — malware-view defaults.
- `GHOST_SKIP_DISCLAIMER=1` — **test/automation only**: treats the malware
  disclaimer as accepted without the dialog or flag. The e2e harness sets it
  for GUI runs; the CLI suites exercise the real gate with a fresh `APPDATA`.

## Windows / PowerShell notes

- PowerShell 5.1: **no `&&`** chaining; use `;` or separate commands.
- BOM-less `.ps1` files are read as ANSI — non-ASCII text in scripts breaks.
  Use the editor tool for any Unicode content instead of echo/redirection.
- Prefer the dedicated file tools over ad-hoc shell heredocs.

## Definition of done

1. Code builds clean (no new warnings from touched files).
2. `ghost_lab selftest` reports 59/59.
3. The relevant `ghost_lab e2e …` suite(s) — ideally `e2e all` — show zero
   `FAIL` lines.
4. README (and this file) updated when behaviour, flags, or restrictions
   change.
