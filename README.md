# Ghost Sandbox

**Dynamic binary instrumentation, live memory editing, import/export policy enforcement, and
hardware-identity spoofing — Windows x64 only.**

**Platform: Windows only.** The shim, hook engine, memory editor, and every tool in the suite
target Windows 10 / 11 on x64 exclusively; there is no Linux, macOS, or Wine support.

Ghost Sandbox injects a native shim (`sandbox_shim.dll`) into a Windows process and gives you a
complete, real-time view of — and control over — what that process does: every hooked API call,
every defensive check, every file/registry/network operation, and every hardware fingerprint it
reads. The whole suite is driven by one GUI (`ghost_sandbox.exe`), one CLI (`ghost.exe`), and one
build/test harness (`ghost_lab.exe`).

> **Use at your own risk.** Ghost Sandbox is experimental software provided "AS IS" and is **not a
> security boundary** — it cannot guarantee complete isolation, may miss malicious behaviour, and
> instrumentation can be incomplete or cause crashes and data loss. Use it only on systems you own
> or are explicitly authorised to test, in isolated, disposable environments. Read the
> **[Disclaimer and Limitation of Liability](#disclaimer-and-limitation-of-liability)** below.
>
> If you found this project through a video, blog, or tutorial that called it "safe" or
> "malware-proof": that is not what this project claims. Ghost Sandbox is not a security boundary
> — use a disposable VM.

---

## Contents

- [Disclaimer and Limitation of Liability](#disclaimer-and-limitation-of-liability)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Quick start](#quick-start)
- [Hardware identity spoofing](#hardware-identity-spoofing)
- [Sandbox policy — import / export control](#sandbox-policy--import--export-control)
- [Anti-tamper / DRM watch](#anti-tamper--drm-watch)
- [Malware analysis mode](#malware-analysis-mode)
- [Memory editor and modules](#memory-editor-and-modules)
- [External tool handoff](#external-tool-handoff)
- [Command-line interface](#command-line-interface)
- [Testing](#testing)
- [Repository layout](#repository-layout)
- [Diagnostics and troubleshooting](#diagnostics-and-troubleshooting)
- [Scope and ethics](#scope-and-ethics)

---

## Disclaimer and Limitation of Liability

**Use at your own risk.** Ghost Sandbox is experimental software provided "AS IS" and without warranties of any kind, to the maximum extent permitted by applicable law. See the accompanying GNU Affero General Public License v3.0 (AGPL-3.0) for the applicable warranty disclaimer and limitation of liability.

### Intended Use

Ghost Sandbox is intended for authorized software testing, reverse engineering, debugging, defensive security research, and malware analysis in environments you are permitted to examine.

You are responsible for ensuring that your use complies with applicable laws, third-party rights, organizational policies, and software licence terms.

### No Guarantee of Isolation or Detection

Ghost Sandbox is not guaranteed to provide complete isolation, prevent all harmful operations, detect every malicious behavior, or prevent a process from affecting the host system. Instrumentation, API interception, emulation, and policy enforcement may be incomplete, bypassed, or behave unexpectedly.

**Do not treat Ghost Sandbox as a security boundary or assume that a sample is safe merely because no suspicious behavior was detected.** Use appropriately isolated, disposable test environments and maintain backups of important data.

### Potential Risks

The software may contain defects or produce incomplete, incorrect, or misleading analysis results. Running or instrumenting software may cause crashes, data loss, system instability, or other unintended effects.

You assume responsibility for evaluating the suitability of the software for your intended use, subject to the rights and protections that cannot lawfully be excluded under applicable law.

### Assumption of Risk and Exclusion of Liability

You use Ghost Sandbox entirely at your own risk and remain solely responsible for your systems,
data, targets, samples and legal compliance. **To the maximum extent permitted by applicable law**,
Ghost Project and the author exclude all warranties and assume no liability of any kind — contract,
tort (including negligence), strict liability or otherwise — for any loss, damage, cost or expense
arising from the software or its use. This exclusion does not apply where liability cannot lawfully
be excluded or limited (for example, liability for intent, gross negligence, or injury to life,
body or health).

### No Security Certification

Ghost Sandbox is not represented as a certified security product, a complete malware containment solution, or a substitute for professional security review.

### Governing Licence

Ghost Sandbox is distributed under the GNU Affero General Public License v3.0 (AGPL-3.0). The licence's terms, including Sections 15 and 16, apply. Nothing in this notice purports to exclude or limit liability where such exclusion or limitation is prohibited by applicable law.

### Acknowledgement

Before malware analysis mode can be used, the terms above must be acknowledged once — in the GUI
dialog (type the acknowledgement sentence, tick the checkbox, then *Continue to analysis*) or with
`ghost run --malware --accept-disclaimer` on the CLI. The acknowledgement is recorded once per user
(version + timestamp in `%APPDATA%\ghost_sandbox\malware_disclaimer_ack.txt`), shared between the
GUI and the CLI, and remembered **together with the version of this notice**: accepting it in
either place means it is not asked again while this version of the terms is current, and a future
release that materially changes the notice presents the updated terms again. The acknowledgement
is evidence that this notice was presented and accepted — it is not a contract, does not replace
the licence terms, and does not exclude or limit any obligation or liability that applicable law
does not allow to be excluded or limited (see *Governing Licence* above). All use of the software
— including every malware-analysis run, instrumentation session, and spoofed environment —
remains at your own risk. The full terms stay reachable at any time from the GUI's *About &
legal* dialog.

---

## What it does

| Capability | Where |
|---|---|
| **API tracing** — every hooked call with module, function, parameters, return value, duration, and caller attribution | *Trace Viewer* view · `ghost run --stream` |
| **Import / export policy** — allow, observe, or block any imported or exported function; blocked calls return a value you choose | *Sandbox* view · `ghost run --policy` |
| **Anti-tamper / DRM watch** — integrity, debugger, timing, module-scan, device, crypto, and environment probes with *expected vs. returned* verdicts | *Anti-Tamper* view |
| **Malware analysis mode** — containment token, shadow file store, fake registry, believable offline-network answers, per-operation approval queue, behaviour log and report | *Malware Analysis* view · `ghost run --malware` |
| **Hardware identity spoofing** — CPU, BIOS, motherboard, memory, storage, network, power, and WMI identity rewritten in-target from a TOML profile | *Hardware Profile* view · `ghost run --profile` |
| **Live memory editing** — hex dump/search, client-side disassembly, byte patches, NOP / JZ→JMP rewrites, register snapshots | *Memory Editor* view · `ghost run --dump/--patch/--nop/--jmp` |
| **Module inventory** — bases, sizes, paths, import/export counts | *Modules* view |
| **External tool handoff** — one click from any row to IDA, Ghidra, x64dbg, WinDbg, Cheat Engine, HxD, … with `{pid} {addr} {module} {rva} {file}` filled in | *Integrations* view · `ghost tools` |
| **Agent-friendly output** — one report per run as JSON / JSONL / CSV / Markdown / text | `ghost inspect/run` |

---

## Architecture

```
┌───────────────────────────────────────────┐        Named pipe          ┌─────────────────────────────────────────┐
│  ghost_sandbox.exe (GUI, Rust + egui)     │ ◄────────────────────────► │  sandbox_shim.dll (C++, x64)            │
│  ghost.exe        (CLI, same engine)      │   \\.\pipe\GhostSandbox     │  injected into the target process       │
│                                           │                            │                                         │
│  • Dashboard        • Sandbox             │        Shared memory       │  • Inline + IAT hook engine             │
│  • Trace Viewer     • Malware Analysis    │ ◄────────────────────────► │  • Import/export policy engine          │
│  • Anti-Tamper      • Integrations        │  GhostSandboxProfile (HW)  │  • DRM / anti-tamper watch              │
│  • Hardware Profile • Memory Editor       │  GhostSandboxPolicy        │  • Malware guard (behaviour mediation)  │
│  • Modules          • Rules               │                            │  • CPUID patch-trap + VEH emulation     │
│                                           │                            │  • Hardware identity engine             │
└───────────────┬───────────────────────────┘                            │  • WMI COM interceptor                  │
                │ same engine, headless                                  │  • DXGI adapter spoofer                 │
                ▼                                                        │  • Ring-buffer pipe client              │
        {pid} {addr} {module} {rva} {file} {func}                        └─────────────────────────────────────────┘
                │
                ▼
        IDA · Ghidra · x64dbg · WinDbg · Cheat Engine · HxD · …
```

The controller (GUI or CLI) launches the target `CREATE_SUSPENDED`, injects the shim, publishes
the hardware profile and policy into named shared memory, and then resumes the process. The shim
reads both sections in `DllMain`, installs its hooks, and connects back over a named pipe. All
traffic uses the binary protocol defined in [`shim/trace_format.h`](shim/trace_format.h).

---

## Requirements

| | |
|---|---|
| OS | **Windows only** — Windows 10 / 11, x64 (no Linux, macOS, or Wine support) |
| Rust | stable toolchain (edition 2021) |
| C++ | Visual Studio 2022 Build Tools with the MSVC x64 toolset |
| Privileges | injecting into processes may require an elevated shell for protected targets |

No PowerShell or batch scripts are used anywhere: every native build, deploy, self-test, and
end-to-end suite runs through `ghost_lab`.

---

## Building

```powershell
cargo build                                 # GUI + ghost.exe + ghost_lab.exe
target\debug\ghost_lab.exe build all        # shim + hook self-test + host + probes, then deploy
```

`build all` compiles the native pieces with MSVC and deploys `sandbox_shim.dll` next to the
binaries (project root, `target\debug\`, `target\release\`). Individual targets:

```powershell
ghost_lab build shim          # sandbox_shim.dll
ghost_lab build host          # ghost_host.exe (DLL sample host)
ghost_lab build selftest      # hook_selftest.exe
ghost_lab build probe         # DRM probe fixture
ghost_lab build hwprobe       # hardware identity probe fixture
ghost_lab build sim           # malware behaviour simulator
ghost_lab deploy              # copy the shim next to the binaries
```

The same build runs in GitHub Actions on every push and pull request
([`.github/workflows/build.yml`](.github/workflows/build.yml), Windows x64):
debug + release host build, native shim/fixtures, `selftest`, the
CLI/hardware/malware e2e suites, then a release zip. On public pushes the zip
receives a build-provenance attestation
(`gh attestation verify ghost-sandbox-windows-x64.zip --repo ChrisGamer5013/ghost-sandbox`),
and `v*` tags publish it as a GitHub release.

---

## Quick start

**GUI**

```powershell
target\debug\ghost_sandbox.exe
```

Pick a view in the left sidebar. For a sample: **Sandbox** → *Open sample* → choose an EXE or
DLL; static analysis (hashes, sections, imports/exports, packer hints) appears immediately, then
*Run under Ghost Sandbox* instruments it with the current policy. The *Sandbox* view's Live Hits
tab shows allowed / observed / blocked calls as they happen.

**CLI**

```powershell
ghost inspect sample.exe --format md            # static PE report
ghost run sample.exe --duration 20              # instrumented run, JSON report on stdout
ghost run sample.exe --stream                   # one JSON event per line while it runs
ghost run sample.exe --malware --duration 30    # malware analysis mode
```

Useful environment variables (GUI automation and tests): `GHOST_START_VIEW=<view>`,
`GHOST_SAMPLE=<path>`, `GHOST_AUTORUN=1`, `GHOST_MEM_ADDR=<addr>[:len]`,
`GHOST_MALWARE=1`, `GHOST_MW_LEVEL=guest|untrusted|none`, `GHOST_TOOLS_FILE=<toml>`,
`GHOST_SKIP_DISCLAIMER=1` (treats the malware-analysis disclaimer as accepted — for
automated suites only; use the GUI dialog or `--accept-disclaimer` as a human).

---

## Hardware identity spoofing

A target process reads its hardware identity from many independent sources. Ghost Sandbox
publishes a single profile — [`profiles/default.toml`](profiles/default.toml) by default, or
`--profile FILE` — into shared memory, and the shim rewrites **all** of the in-target sources so
they agree with each other.

### Coverage

| Source | APIs / paths rewritten |
|---|---|
| **CPU (registry)** | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` — `ProcessorNameString`, `VendorIdentifier`, `Identifier`, `~MHz` |
| **CPUID** | leaves `0`, `1`, `4`, `7`, `0xB`, `0x16`, `0x40000000`–`0x80000008` emulated from the profile (vendor, brand, family/model/stepping, topology, cache sizes, base/max MHz, feature bits) |
| **System info** | `GetSystemInfo`, `GetNativeSystemInfo` (processor count, level, revision, type), `GetLogicalProcessorInformation`, `GetLogicalProcessorInformationEx` (cores, caches, package, NUMA, group) |
| **Memory** | `GlobalMemoryStatusEx`, `GetPhysicallyInstalledSystemMemory`, `NtQuerySystemInformation` (physical pages, processor performance), SMBIOS types 16/17 (per-DIMM size, speed, type, manufacturer, part number) |
| **BIOS / board / chassis** | `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, SMBIOS `GetSystemFirmwareTable('RSMB')` served as a synthesized table (types 0, 1, 2, 3, 4, 7, 16, 17, 32, 127) with a valid `RawSMBIOSData` header |
| **Machine identity** | `MachineGuid`, `ProductId`, `RegisteredOwner`, computer name (`ComputerName`, `ActiveComputerName`, `Hostname`, `NV Hostname`), SMBIOS type-1 UUID |
| **Clocks / power** | `NtPowerInformation(ProcessorPowerInformation)` (per-CPU current/max MHz), registry `~MHz`, CPUID leaf `0x16` |
| **Storage** | volume serial via `GetVolumeInformationW`, `Win32_DiskDrive` (model, serial) in WMI |
| **Network adapters** | `GetAdaptersInfo`, `GetAdaptersAddresses` — MAC, description, and friendly name per adapter (extra adapters get derived MACs from the profile base) |
| **GPU adapters** | DXGI `IDXGIAdapter::GetDesc` (name, vendor/device IDs, VRAM) for every adapter |
| **WMI (in-process)** | `Win32_Processor`, `Win32_PhysicalMemory`, `Win32_BaseBoard`, `Win32_ComputerSystem`, `Win32_DiskDrive`, `Win32_BIOS` |

### How CPUID interception works

CPUID is trapped, not emulated blindly: the shim rewrites the two-byte `CPUID` opcode (`0F A2`)
to `UD2` (`0F 0B`) in every executable section of every module mapped into the target (the shim's
own module excepted), catches the resulting `#UD` in a vectored exception handler, emulates the
requested leaf from the profile, and resumes execution after the instruction. Only the second
opcode byte is written, so the patch is a single-byte, atomic store. Hypervisor leaves
(`0x40000000`+) return zeros and the leaf-1 hypervisor bit stays clear, so a target running inside
a VM sees a plausible bare-metal CPU. Without a published profile, CPUID is passed through
untouched.

### Limitations

- **In-target only.** The shim rewrites what *the instrumented process* reads. Host-side tools
  (Task Manager, WMIC, Device Manager, another process's WMI) are not affected by design.
- **JIT-generated code is not trapped.** Dynamically emitted CPUID instructions are outside the
  patched sections; a JIT-based checker can see the real CPU.
- **Code-integrity self-checks** can notice the CPUID patch, because patched code bytes differ
  from the file on disk. The *Anti-Tamper* view surfaces those hits; run without a profile if you
  need byte-identical code.
- **Performance counters** (`HKEY_PERFORMANCE_DATA`, PDH queries) are not rewritten yet; CPU
  frequency is covered through `NtPowerInformation` and the registry.
- **WMI spoofing is in-process.** Queries issued by the instrumented process are rewritten
  through a COM interceptor; classes outside the table above pass through unchanged.

---

## Sandbox policy — import / export control

The *Sandbox* view (or `ghost run`) makes every imported function the sample resolves a policy
row:

| Action | Effect |
|---|---|
| **Allow** | untouched (default for everything unlisted) |
| **Observe** | the call runs normally and is logged with caller attribution |
| **Block** | the real function is never reached; the caller receives the configured return value (hex or decimal, `0` by default) and the hit is reported |

Coverage:

- **Imports** — IAT slots are patched in every loaded module (the shim's own module is never
  touched); `GetProcAddress` results are intercepted, so delay-load and manually resolved imports
  are covered too; modules loaded later receive the policy through the `LoadLibrary` hooks.
- **Exports** — the sample's own exports are inline-hooked: *Observe* tails through a trampoline to
  the real code, *Block* returns the fake value.
- The policy is applied **before the first instruction of the entry point** runs: it travels in
  shared memory (`GhostSandboxPolicy`) which the shim reads during `DllMain`; live updates
  restore and re-apply without restarting the target.
- Every hit streams as a policy-hit event: kind (import/export), action, blocked flag, return
  value, `module!function`, **caller module + RVA**, and a detail line. Hot entries are throttled
  (first 20 hits, then every 50, 50 000 global cap) so a spammy function cannot flood the pipe.

Policy files are plain TOML — generate a skeleton from the sample itself:

```powershell
ghost policy template sample.exe --out sample.policy.toml
ghost run sample.exe --policy sample.policy.toml `
    --block kernel32.dll!IsDebuggerPresent=1 `
    --observe kernel32.dll!GetTickCount64
```

Rules accept `*` and trailing-`*` wildcards for both module and function (`api-ms-*` matches every
API-set shim) and matching is case-insensitive.

---

## Anti-tamper / DRM watch

The *Anti-Tamper* view catches what a target does to verify, protect, or fingerprint itself. Each
hit reports:

- **Called by** — module and RVA of the caller, resolved from the hook's return address;
- **Expected** — what a benign, uninstrumented environment would return;
- **Returned** — what the caller actually received;
- **Verdict** — `Benign`, `Detected`, or `Unknown`, derived by comparing the two.

| Category | Examples |
|---|---|
| Integrity | `WinVerifyTrust`, `CertVerifyCertificateChainPolicy`, `MapFileAndCheckSumA/W`, `CheckSumMappedFile` |
| Debugger | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (DebugPort / DebugObjectHandle / DebugFlags) |
| Timing | `QueryPerformanceCounter`, `GetTickCount64` |
| Module scan | `CreateToolhelp32Snapshot`, `EnumProcessModules`, `GetModuleFileNameW` |
| Device | `GetSystemFirmwareTable` (SMBIOS), SetupDi device queries |
| Crypto | `CryptVerifySignatureW` |
| Environment | `NtQuerySystemInformation`, `RegQueryValueExW`, `GetAdaptersAddresses`, `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetComputerNameW`, CPUID hypervisor probes (`0x40000000` / leaf-1 bit 31) |
| Memory | `VirtualProtect` (executable page flips / unpacking) |

The view offers category / caller / text filters, a detections-only toggle, per-category counters,
a status-bar alert on every detection, and one-click JSON report export. DRM mode is
detection-only: it never changes spoofing behaviour.

---

## Malware analysis mode

`ghost run <sample> --malware` (GUI: the *Malware Analysis* view, `GHOST_START_VIEW=malware`) runs
a sample under the behaviour guard: file / registry / process / network operations that go through
a covered API are captured with caller module + RVA, target, decoded detail, and a verdict (see
*Known boundaries* below):

**One-time acknowledgement.** The first time malware analysis is opened — the GUI view or
`ghost run --malware` — Ghost Sandbox requires the terms above to be accepted once: the GUI shows
a dialog (type the acknowledgement sentence exactly, tick the confirmation checkbox, then
*Continue to analysis*) and the CLI prints the same terms to stderr and refuses to start until the
command is re-issued with `--accept-disclaimer`. The acknowledgement is recorded per user (version
+ timestamp in `%APPDATA%\ghost_sandbox\malware_disclaimer_ack.txt`) and **shared between the GUI
and the CLI** — accepting it in either place means it is not asked again while this version of the
terms is current, and a recording failure refuses the run rather than counting as acceptance. The
terms stay reachable any time from the GUI's *About & legal* dialog.

| Verdict | Meaning |
|---|---|
| `Observed` | read-only observation; no effect on the sample |
| `Shadowed` | write redirected into the shadow store; the sample sees success |
| `Fake success` | call answered as if it worked; nothing happened on the host |
| `Blocked` | call answered with a plausible failure (`EAI_NONAME` for DNS) |
| `Allowed` | passed through after approval |
| `Timeout` | no verdict arrived in time (treated as deny) |

Defaults are deny-with-a-believable-answer:

- **Files** — writes / moves / deletes / creates land in the shadow store
  (`--shadow-dir`, default `%TEMP%\GhostSandbox\shadow`, mirrored tree). Reads fall back to the
  shadow copy, so a sample can drop a file and read it straight back; the real file is not
  modified for mediated operations (see *Known boundaries*).
- **Registry** — writes / creates return `ERROR_SUCCESS` and are remembered in the shim, so the
  sample can read its own value back; the real registry is not modified for mediated operations.
- **Process** — `CreateProcess` / `WinExec` / `ShellExecute` report success (a suspended decoy
  `cmd.exe /c exit` provides a real-looking PID/handle, then is reaped).
- **Network** — `connect()` succeeds without sending traffic, downloads return `S_OK` without
  producing a file, and **DNS is answered like an offline host** (no fake IPs).
- **Tokens** — `guest` (default) launches under a restricted/LUA copy of *your own* token with
  all privileges disabled; `untrusted` additionally requires Low integrity (S-1-16-4096). These are
  labels, not the Windows *Guest* account or the *Untrusted* integrity level. If the token cannot
  be created, set, and verified, the launch is refused — there is no fallback to your full token.
  `none` skips the token layer entirely: the GUI shows a red warning and requires a confirmation
  click, the CLI prints a warning, and only the shim's best-effort mediation remains.

Approvals: the GUI queues pending operations for a verdict; the CLI denies unless you pass
`--approve-files`, `--approve-registry`, `--approve-exec`, or `--allow-network`
(`--no-approval` never pauses). Each of these is an explicit opt-in that loosens the guard's
deny-by-default answers — prefer the defaults unless you are deliberately testing in an
authorised, disposable environment. The run report carries the full behaviour log (`malware_ops`) and
an inventory of the shadow store (`shadow_files`: path, size, SHA-256) so a dropped payload can be
collected and analysed afterwards. Tuning flags: `--no-shadow`, `--no-fake-network`,
`--no-observe-reads`, `--mw-timeout MS`, `--duration SECS`, `--kill-on-exit`.

### Known boundaries (v1)

- `RegEnumKeyEx` / `RegEnumValue` are not intercepted yet — a sample that *enumerates* a faked key
  will not see the value it wrote (direct read-back works).
- `GetFileAttributesW` is not served from the shadow store yet, so an existence probe after a
  shadowed write reports "missing".
- `RegNotifyChangeKeyValue` and similar wait-on-change APIs are not intercepted.
- **Containment limitation:** when Ghost Sandbox successfully intercepts and denies a covered
  operation, that operation is not forwarded through the intercepted API to the host. This does
  not guarantee that all operations are intercepted, or that the sample cannot affect the host
  through unmonitored paths. See the disclaimer above.
- **Same desktop:** the sample is not moved to a separate desktop or session. A restricted process
  can still send window messages (`SendMessage` / `PostMessage`) to GUI processes on the same
  desktop, which Microsoft's restricted-token guidance recommends avoiding. Treat the desktop as
  untrusted while a sample runs.

---

## Memory editor and modules

The *Memory Editor* view (and the CLI memory flags) read and write the instrumented target while
it runs, over the same pipe protocol as everything else.

**Addresses** are absolute (`0x7FF6FD041000`) or module-relative: `main+0x40` (main module),
`mylib.dll+0x1234` (short or full path). Symbolic forms are resolved against the live module list,
so scripts keep working under ASLR.

**Features**

- Hex dump at any address (16…4096 bytes) with ASCII pane and clickable row addresses.
- Find inside the dump — ASCII (case-insensitive) or hex bytes (`90 90`, `hex:DEADBEEF`).
- Save dump as formatted text or raw `.bin`.
- Register snapshot of the main thread (RAX…R15, RIP, RSP, RBP, RFLAGS).
- Client-side disassembly with one-click `JZ/JNZ → JMP` conversion.
- Patch tools: NOP out N bytes, write arbitrary hex bytes, running patch counter, per-row
  handoff to x64dbg / Cheat Engine / HxD or the built-in editor.

```powershell
ghost run target.exe --dump main+0x1000:256      # capture bytes into the report
ghost run target.exe --patch main+0x40=90 90     # overwrite bytes
ghost run target.exe --nop crackme.dll+0x1F40:6  # NOP a check
ghost run target.exe --jmp main+0x1A20           # JZ/JNZ → unconditional JMP
```

Dumps appear in reports as `memory_dumps: [{address, length, hex, ascii}]` and, with `--stream`,
as live `{"type":"memory_dump", …}` events.

---

## External tool handoff

Every analysis stage can be served by Ghost itself **or** by an external tool, with the current
context passed on the command line:

| Stage | Placeholders | Built-in presets |
|---|---|---|
| Disassemble | `{file} {pid} {addr} {module} {rva} {base} {func} {name}` | IDA, Ghidra, x64dbg, WinDbg |
| Decompile | same | Ghidra, IDA (Hex-Rays) |
| Debug | `{pid} {addr} {module} {func}` | x64dbg, WinDbg |
| MemoryEdit | `{pid} {addr} {bytes}` | Cheat Engine, x64dbg |
| HexView | `{file} {addr}` | HxD, Ghost Memory Editor |
| Strings / InspectPe | `{file} {name}` | strings64, Detect It Easy, Explorer |
| TraceView | `{file} {func}` | Ghost Trace Viewer |

- The catalogue lives in `tools.toml` (override with `GHOST_TOOLS_FILE`); the *Integrations* view
  edits it with a live resolved-command preview.
- In the GUI, look for the *Open with ▾* menus in the Sandbox header, the Live Hits / DRM / Trace
  tables (select a row first), the Memory Editor, and the Module list.
- Every menu also carries an *Open in Memory Editor* entry, so "external tool" and "stay inside
  Ghost" are equally one click away.
- CLI: `ghost tools list`, `ghost tools open --stage … --dry-run`.

Handoff data comes from live state: the module list supplies each module's base address and full
path, so `{addr}` = base + RVA and `{file}` is a real path even for modules inside a running
target.

---

## Command-line interface

`ghost.exe` exposes the whole suite headlessly; like everything else here it
is **Windows-only**. Commands that produce reports support
`--format json|jsonl|csv|md|text` and `--out FILE`, and `ghost <command>
--help` / `-h` prints that command's reference. `ghost help` prints the full
reference (all commands and options); `ghost help <command>` narrows it to one
command — that is the live list an agent should read before driving the tool.

```powershell
ghost inspect sample.exe --format md
ghost run sample.exe --duration 20 --stream
ghost run sample.dll --export DllMain --block kernel32.dll!IsDebuggerPresent
ghost run sample.exe --malware --duration 30 --stream --shadow-dir target\shadow
ghost run sample.exe --malware --accept-disclaimer --duration 30
ghost policy template sample.exe --out sample.policy.toml
ghost tools list --format json
ghost tools open --stage disassemble --file sample.exe --dry-run
ghost version --format json
ghost help run
```

- `run` prints progress on **stderr** and exactly one report on **stdout** — pipe-friendly.
- `--stream` emits one JSON object per line (`run_start`, `trace`, `policy_hit`, `drm`,
  `malware_op`, `dll_load`, `memory_dump`, …, `run_end`).
- Exit codes: `0` success · `2` usage · `3` injection failed · `4` shim never connected ·
  `5` malware-analysis disclaimer not acknowledged (or not recordable).
- Every report carries a short licence + disclaimer footer (`license` and `notice` fields in JSON
  and the JSONL header; a footer in Markdown/Text) so the disclaimer travels with shared artifacts.
- Only one controller can watch a given process at a time (GUI or CLI). Close the GUI before
  using `ghost run` against the same pipe.

> **Advanced (authorised labs only).** `--approve-files`, `--approve-registry`, `--approve-exec`
> and `--allow-network` loosen the guard's deny-by-default answers for testing you are explicitly
> authorised to perform in a disposable environment. Prefer the deny-by-default path; a disclaimer
> is not a substitute for safe defaults.

---

## Testing

```powershell
ghost_lab selftest          # in-process hook engine / DRM / policy checks
ghost_lab e2e all           # every end-to-end suite
ghost_lab e2e cli           # CLI inspection + instrumented run
ghost_lab e2e drm           # anti-tamper watch against a live fixture
ghost_lab e2e hw            # hardware identity vs. profiles/default.toml
ghost_lab e2e sandbox       # import/export policy against a live sample
ghost_lab e2e malware       # behaviour guard, shadow store, fake network
ghost_lab e2e malware-gui   # the same through the GUI
```

- `selftest` runs `hook_selftest.exe`, which exercises the hook engine, the DRM watch, and the
  policy engine end-to-end in-process: **59 checks, 0 failures**.
- `e2e hw` publishes `profiles/default.toml`, injects the hardware probe, and asserts the spoofed
  values in **every** source from the coverage table above, then diffs them against an
  un-injected ground-truth run to prove host values were replaced — including hiding a Hyper-V
  guest's hypervisor flag.
- Fixtures live in `target\drmtest\`: `drm_probe.cpp` (anti-tamper calls), `hw_probe.cpp`
  (machine-readable `[hw] key=value` hardware report), `malware_sim.cpp` (benign behaviour
  simulator that logs what it believes happened), plus policy TOMLs and captured reports.
- `ghost_lab frames --file dump.bin` decodes a raw pipe capture into protocol frames for
  debugging.

---

## Repository layout

```
ghost_sandbox/
├── Cargo.toml                  # Rust manifest
├── Cargo.lock                  # Locked dependency set
├── build.rs                    # Copies shim + host next to the binaries
├── .github/workflows/build.yml # CI: build, tests, attested release artifacts
├── .gitignore                  # Build outputs / local-only files
├── LICENSE                     # AGPL-3.0
├── tools.toml                  # External-tool catalogue (created on first edit)
├── profiles/                   # Hardware identity profiles (default.toml)
├── rules/                      # Instrumentation rule presets
├── src/
│   ├── main.rs                 # GUI entry point + theme
│   ├── bin/ghost.rs            # CLI entry point (ghost.exe)
│   ├── bin/ghost_lab.rs        # Unified build / test / harness binary
│   ├── cli.rs                  # CLI commands (inspect / run / policy / tools)
│   ├── disclaimer.rs           # One-time malware-analysis acknowledgement (GUI + CLI shared)
│   ├── app.rs                  # Application shell and shared state
│   ├── injector.rs             # CREATE_SUSPENDED + DLL injection
│   ├── pipe_server.rs          # Named-pipe server and message pump
│   ├── profile.rs              # Hardware profile TOML parser
│   ├── shared_profile.rs       # Shared-memory profile handoff to the shim
│   ├── policy.rs               # Policy model + TOML (de)serialisation
│   ├── shared_policy.rs        # Shared-memory policy handoff
│   ├── report.rs               # Unified report (JSON / JSONL / CSV / MD / text)
│   ├── pe_inspect.rs           # PE parser + SHA-256
│   ├── disasm.rs               # x86-64 disassembler
│   ├── tools.rs                # External-tool handoff
│   ├── views/                  # egui views
│   └── widgets/                # Custom widgets
├── shim/
│   ├── sandbox_shim.cpp        # Main injected DLL
│   ├── hook_engine.h           # Inline + IAT hooking
│   ├── trace_format.h          # Binary protocol (single source of truth)
│   ├── pipe_client.h           # Ring-buffer pipe client
│   ├── policy_watch.h          # Import/export policy engine
│   ├── hw_identity.h           # Hardware identity engine (registry, SMBIOS, topology)
│   ├── hw_spoofer.h            # System-info / memory hooks
│   ├── cpuid_trap.h            # CPUID patch-trap + VEH emulation
│   ├── dxgi_spoofer.h          # DXGI adapter spoofer
│   ├── wmi_spoofer.h           # WMI COM interceptor
│   ├── drm_watch.h             # Anti-tamper watch hooks
│   └── malware_guard.h         # Malware-analysis behaviour guard
└── target/drmtest/             # E2E fixture sources (.cpp, committed) + captures (ignored)
```

All native builds, deploys, self-tests, and end-to-end suites are driven by `ghost_lab.exe`
(`src/bin/ghost_lab.rs`) — there are no `.ps1` / `.cmd` scripts in the repository.

---

## Diagnostics and troubleshooting

- The shim writes a log to `%TEMP%\ghost_sandbox_shim.log` (locked while the target runs).
- `ghost_lab pipe-sink --out dump.bin` captures the raw pipe traffic; `ghost_lab frames --file
  dump.bin` decodes it. `ghost_lab fake-shim` / `fake-controller` provide protocol peers.
- `ghost_lab shot --process ghost_sandbox --out shot.png` captures the GUI window.

**White / unpainted window (some Intel GPUs and VMs).** If the window shows white content only,
the driver's Vulkan/OpenGL swapchain presentation is failing; DX11 apps, including DWM, are
unaffected. Fixes, in order:

1. Reboot — usually restores native presentation after a driver/VM hiccup.
2. Force software Vulkan via Chrome's SwiftShader ICD (CPU-rendered, slower):
   `set VK_ICD_FILENAMES=C:\Program Files\Google\Chrome\Application\<ver>\vk_swiftshader_icd.json`
   and `set WGPU_BACKEND=vulkan`.
3. `set WGPU_BACKEND=gl` to try the OpenGL backend instead.

`ghost_lab` applies option 2 automatically when the SwiftShader ICD is present.

---

## Scope and ethics

Ghost Sandbox is a **detection and analysis** instrument:

- The shim only observes, reports, and rewrites what the instrumented process itself reads.
  Hardware spoofing is read-only — the host is never modified.
- Malware analysis mode runs samples under containment: a covered operation that the guard
  intercepts and denies is not forwarded through the intercepted API to the host — but
  instrumentation is best-effort, not a security boundary, and unmonitored paths are not covered
  (see the disclaimer).
- There is no persistence, no propagation, and no evasion delivery mechanism in this codebase.

Use it on systems and software you own or are explicitly authorised to analyse. You are
responsible for complying with the laws and licences that apply to your targets.

### Third-party claims

Only this README, AGENTS.md, and the in-app help are official documentation. Videos, streams,
blog posts, tutorials, and social-media threads are not reviewed, endorsed, or supported by this
project. Claims made there — especially that Ghost Sandbox "makes malware safe," "contains" a
sample, or replaces a VM — are the author's claims, not this project's. Where a third-party
description conflicts with this README, this README governs.

**Export control.** Some functionality may be subject to export-control, import, or other laws in
certain jurisdictions. You are responsible for complying with applicable law.

**Third-party names.** IDA, Ghidra, x64dbg, WinDbg, Cheat Engine and other product names are
trademarks of their respective owners; they are referenced only to describe interoperability. No
affiliation or endorsement is implied.

## License

Ghost Sandbox is distributed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
The licence's warranty disclaimer and limitation of liability (Sections 15 and 16) apply; see
<https://www.gnu.org/licenses/agpl-3.0.html> for the full terms.
