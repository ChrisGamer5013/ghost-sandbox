/*
   Ghost Sandbox — ghost_lab: the single build / test / harness binary.

   Everything that used to be a separate script lives here:

     build [all|shim|selftest|host|probe|sim]  MSVC builds (vcvars64 + cl)
     deploy                                    copy the shim next to the exes
     selftest                                  run hook_selftest.exe
     shot    --process NAME --out FILE         window screenshot (PrintWindow
                                               with blank detection + screen
                                               fallback, PNG written in-tree)
     inject  --target "cmdline" --shim DLL     suspended-start DLL injection
     pipe-sink [--pipe NAME] --out FILE        raw pipe byte dump (protocol
                                               debugging without the GUI)
     fake-shim [--pipe NAME]                   stream synthetic protocol frames
                                               at the controller (client role)
     fake-controller [--pipe NAME]             play the controller: pipe server
                                               + profile mapping, send
                                               pause/resume/reload commands
     e2e [all|drm|cli|hw|sandbox|malware|malware-gui]
                                               end-to-end suites (the ones the
                                               .ps1 scripts used to run)

   Nothing here is Windows-shell specific: no PowerShell, no .cmd files, one
   binary that owns every harness. State (logs, screenshots, reports) still
   lands in target\drmtest and target\shimtest so the artefacts stay where
   they have always been.
*/

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use winapi::shared::minwindef::{DWORD, TRUE};
use winapi::shared::windef::{HWND, RECT};
use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE};
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe};
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::{
    CreateFileMappingA, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use winapi::um::wingdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
use winapi::um::winnt::{
    GENERIC_READ, GENERIC_WRITE, PAGE_READWRITE, PROCESS_TERMINATE,
};
use winapi::um::winuser::{
    EnumWindows, GetWindow, GetWindowRect, GetWindowThreadProcessId, IsWindowVisible, PrintWindow,
    ReleaseDC, SetForegroundWindow, SetProcessDPIAware, SetWindowPos, ShowWindow, GW_OWNER,
    HWND_TOP, PW_RENDERFULLCONTENT, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, SW_RESTORE,
};

// ─── Protocol constants (mirror of shim/trace_format.h + src/pipe_server.rs) ──
const EVT_TRACE: u8 = 1;
const EVT_SPOOF: u8 = 2;
const EVT_DLL_LOAD: u8 = 3;
const EVT_CONNECTED: u8 = 9;
const EVT_MEMORY_DUMP: u8 = 10;

const CMD_TRACE_PAUSE: u8 = 8;
const CMD_TRACE_RESUME: u8 = 9;
const CMD_PROFILE_RELOAD: u8 = 14;

const HEADER_SIZE: usize = 17;
const PIPE_NAME: &str = "GhostSandbox";

// ─── tiny CLI ───────────────────────────────────────────────

#[derive(Default)]
struct Opts {
    values: BTreeMap<String, String>,
    /// Every `--key value` pair in order (allows repeated options such as
    /// `--env A=1 --env B=2`).
    multi: Vec<(String, String)>,
    flags: HashSet<String>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String]) -> Opts {
        let mut o = Opts::default();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            if let Some(rest) = a.strip_prefix("--") {
                let (key, inline) = match rest.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => (rest.to_string(), None),
                };
                if let Some(v) = inline {
                    o.values.insert(key.clone(), v.clone());
                    o.multi.push((key, v));
                } else if i < args.len() && !args[i].starts_with("--") {
                    o.values.insert(key.clone(), args[i].clone());
                    o.multi.push((key, args[i].clone()));
                    i += 1;
                } else {
                    o.flags.insert(key);
                }
            } else {
                o.positional.push(a.clone());
            }
        }
        o
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(|s| s.as_str())
    }

    fn get_or(&self, k: &str, d: impl Into<String>) -> String {
        self.values.get(k).cloned().unwrap_or_else(|| d.into())
    }

    /// Boolean flag lookup (`--k` or `--k=1|true`); kept for suite convenience.
    #[allow(dead_code)]
    fn flag(&self, k: &str) -> bool {
        self.flags.contains(k) || self.values.get(k).map(|v| v == "1" || v == "true").unwrap_or(false)
    }

    fn num(&self, k: &str, d: u64) -> u64 {
        self.values
            .get(k)
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    }

    /// All values given for a repeatable option, in order.
    fn all(&self, k: &str) -> Vec<String> {
        self.multi
            .iter()
            .filter(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// First positional (or a --name value): useful for `build sim`.
    fn first(&self, default: &str) -> String {
        self.positional
            .first()
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }
}

// ─── pass/fail accounting ───────────────────────────────────

// The e2e dispatcher aggregates pass/fail itself; name/finish are kept for
// interactive suite runs.
#[allow(dead_code)]
struct Check {
    name: String,
    pass: u32,
    fail: u32,
    failures: Vec<String>,
}

impl Check {
    fn new(name: &str) -> Check {
        println!("\n===== {} =====", name);
        Check {
            name: name.to_string(),
            pass: 0,
            fail: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, cond: bool, what: impl AsRef<str>) {
        let what = what.as_ref();
        if cond {
            self.pass += 1;
            println!("  PASS  {}", what);
        } else {
            self.fail += 1;
            self.failures.push(what.to_string());
            println!("  FAIL  {}", what);
        }
    }

    fn info(&self, line: impl AsRef<str>) {
        println!("  {}", line.as_ref());
    }

    /// Kept for interactive suite runs (the e2e dispatcher aggregates itself).
    #[allow(dead_code)]
    fn finish(&self) -> ExitCode {
        println!(
            "\n===== {} summary: {} pass, {} fail =====",
            self.name, self.pass, self.fail
        );
        for f in &self.failures {
            println!("  failed: {}", f);
        }
        if self.fail == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

// ─── helpers ────────────────────────────────────────────────

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn drmtest() -> PathBuf {
    root().join("target").join("drmtest")
}

fn shimtest() -> PathBuf {
    root().join("target").join("shimtest")
}

fn read_text(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

fn count_matches(hay: &str, needle: &str) -> usize {
    hay.match_indices(needle).count()
}

fn log_has(path: &Path, needle: &str) -> bool {
    read_text(path).contains(needle)
}

/// Locate `vcvars64.bat`: `GHOST_VCVARS` overrides, then vswhere picks the
/// newest Visual Studio with the x64 C++ toolset (BuildTools, Community or
/// Enterprise — GitHub runners have Enterprise), then the dev-VM default.
fn vcvars() -> String {
    if let Ok(v) = std::env::var("GHOST_VCVARS") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }
    let vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
    if Path::new(vswhere).is_file() {
        if let Ok(out) = Command::new(vswhere)
            .args([
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ])
            .output()
        {
            let install = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() && !install.is_empty() {
                let bat = format!("{}\\VC\\Auxiliary\\Build\\vcvars64.bat", install);
                if Path::new(&bat).is_file() {
                    return bat;
                }
            }
        }
    }
    r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
        .to_string()
}

/// Run one `cl` command line inside a vcvars64 environment.
fn run_cl(cl: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let full = format!("call \"{}\" >nul && {}", vcvars(), cl);
    let mut cmd = Command::new("cmd");
    // raw_arg: cmd.exe needs the line verbatim (no Rust quoting).
    cmd.arg("/c").raw_arg(&full);
    let out = cmd
        .current_dir(root())
        .output()
        .map_err(|e| format!("cannot run cl: {}", e))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

fn find_pid(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let want = name.to_ascii_lowercase();
        let mut found = None;
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let end = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
                let exe = String::from_utf16_lossy(&pe.szExeFile[..end]).to_ascii_lowercase();
                if exe == want || exe == format!("{}.exe", want) {
                    found = Some(pe.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

fn kill_proc(name: &str) -> bool {
    let Some(pid) = find_pid(name) else { return false };
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 0xB0B) != 0;
        CloseHandle(h);
        ok
    }
}

fn kill_harness_procs() {
    for n in ["ghost_sandbox", "drm_probe", "malware_sim", "ghost_host", "ghost"] {
        while kill_proc(n) {}
    }
}

fn wait_for_pipe(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(rd) = fs::read_dir(r"\\.\pipe\") {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().contains(PIPE_NAME) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    false
}

/// Point the WebGPU/wgpu stack at Chrome's software Vulkan (SwiftShader) so
/// the GUI paints in VMs whose GPU drivers produce blank windows.
fn swiftshader_env(cmd: &mut Command) -> Option<String> {
    fn find_icd(dir: &Path, depth: usize) -> Option<PathBuf> {
        if depth == 0 {
            return None;
        }
        let rd = fs::read_dir(dir).ok()?;
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                if p.file_name().map(|n| n == "vk_swiftshader_icd.json").unwrap_or(false) {
                    return Some(p);
                }
            } else if p.is_dir() {
                if let Some(f) = find_icd(&p, depth - 1) {
                    return Some(f);
                }
            }
        }
        None
    }

    for base in [
        r"C:\Program Files\Google\Chrome\Application",
        r"C:\Program Files (x86)\Google\Chrome\Application",
    ] {
        if let Some(icd) = find_icd(Path::new(base), 4) {
            let icd_s = icd.display().to_string();
            cmd.env("VK_ICD_FILENAMES", &icd_s);
            cmd.env("WGPU_BACKEND", "vulkan");
            return Some(icd_s);
        }
    }
    None
}

/// Launch the GUI with logs redirected; returns the child.
fn launch_gui(envs: &[(&str, &str)], out_log: &Path, err_log: &Path) -> Result<Child, String> {
    let exe = root().join("target").join("debug").join("ghost_sandbox.exe");
    if !exe.is_file() {
        return Err(format!("GUI not built: {} (run cargo build)", exe.display()));
    }
    let mut cmd = Command::new(&exe);
    cmd.current_dir(root());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    // Automated suites pre-acknowledge the malware-analysis disclaimer (the
    // GUI dialog and the CLI --accept-disclaimer both write the same record).
    cmd.env("GHOST_SKIP_DISCLAIMER", "1");
    let _ = swiftshader_env(&mut cmd);
    cmd.stdout(Stdio::from(
        File::create(out_log).map_err(|e| format!("{}: {}", out_log.display(), e))?,
    ));
    cmd.stderr(Stdio::from(
        File::create(err_log).map_err(|e| format!("{}: {}", err_log.display(), e))?,
    ));
    cmd.spawn().map_err(|e| format!("spawn {}: {}", exe.display(), e))
}

fn find_file_named(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut steps = 0;
    while let Some(d) = stack.pop() {
        steps += 1;
        if steps > 4000 {
            break;
        }
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(p);
            } else if p.file_name().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false) {
                return Some(p);
            }
        }
    }
    None
}

fn reg_value_exists(key: &str, value: &str) -> bool {
    Command::new("reg")
        .args(["query", key, "/v", value])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn reg_delete_value(key: &str, value: &str) {
    let _ = Command::new("reg")
        .args(["delete", key, "/v", value, "/f"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("reg")
        .args(["delete", key, "/f"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Run a command, capture exit code + stdout+stderr.
fn run_capture(cmd: &mut Command) -> (Option<i32>, String) {
    match cmd.output() {
        Ok(out) => {
            let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.code(), t)
        }
        Err(e) => (None, format!("spawn failed: {}", e)),
    }
}

// ─── PNG writer (stored deflate; no external crates) ────────

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_in = Vec::with_capacity(4 + data.len());
    crc_in.extend_from_slice(kind);
    crc_in.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_in).to_be_bytes());
}

/// Encode BGRA pixels (as returned by GetDIBits) as a PNG using stored
/// deflate blocks — valid, self-contained, no compression dependencies.
fn write_png(path: &Path, bgra: &[u8], w: u32, h: u32) -> Result<(), String> {
    let mut raw = Vec::with_capacity((w as usize * 3 + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0); // filter: none
        for x in 0..w as usize {
            let i = (y * w as usize + x) * 4;
            raw.push(bgra[i + 2]);
            raw.push(bgra[i + 1]);
            raw.push(bgra[i]);
        }
    }

    let mut z = vec![0x78u8, 0x01];
    let mut off = 0usize;
    while off < raw.len() {
        let n = (raw.len() - off).min(65535);
        let last = if off + n == raw.len() { 1u8 } else { 0u8 };
        z.push(last);
        z.extend_from_slice(&(n as u16).to_le_bytes());
        z.extend_from_slice(&(!(n as u16)).to_le_bytes());
        z.extend_from_slice(&raw[off..off + n]);
        off += n;
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit truecolour
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &z);
    png_chunk(&mut out, b"IEND", &[]);

    fs::write(path, &out).map_err(|e| format!("{}: {}", path.display(), e))
}

// ─── screenshot ─────────────────────────────────────────────

struct WinSearch {
    pid: u32,
    best: HWND,
    best_area: i64,
}

extern "system" fn enum_windows_cb(hwnd: HWND, lparam: isize) -> i32 {
    unsafe {
        let search = &mut *(lparam as *mut WinSearch);
        let mut pid: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == search.pid
            && IsWindowVisible(hwnd) != 0
            && GetWindow(hwnd, GW_OWNER).is_null()
        {
            let mut r: RECT = std::mem::zeroed();
            if GetWindowRect(hwnd, &mut r) != 0 {
                let area = (r.right - r.left) as i64 * (r.bottom - r.top) as i64;
                if area > search.best_area {
                    search.best_area = area;
                    search.best = hwnd;
                }
            }
        }
        TRUE
    }
}

fn find_main_window(pid: u32) -> Option<HWND> {
    unsafe {
        let mut search = WinSearch {
            pid,
            best: std::ptr::null_mut(),
            best_area: 0,
        };
        EnumWindows(Some(enum_windows_cb), &mut search as *mut _ as isize);
        if search.best.is_null() {
            None
        } else {
            Some(search.best)
        }
    }
}

fn blank_check(bgra: &[u8], w: u32, h: u32) -> bool {
    let mut colors = HashSet::new();
    let stride = (w * 4) as usize;
    let mut y = 20usize;
    while y < (h as usize).saturating_sub(20) {
        let mut x = 20usize;
        while x < (w as usize).saturating_sub(20) {
            let i = y * stride + x * 4;
            if i + 3 < bgra.len() {
                colors.insert((bgra[i + 2], bgra[i + 1], bgra[i]));
            }
            x += 97;
        }
        y += 97;
    }
    colors.len() <= 1
}

/// Capture a window into a BGRA buffer. Tries PrintWindow first, falls back
/// to a screen grab of the window rect (raising it first).
unsafe fn capture_window(hwnd: HWND, w: u32, h: u32) -> Result<(Vec<u8>, bool), String> {
    let hdc_screen = winapi::um::winuser::GetDC(std::ptr::null_mut());
    if hdc_screen.is_null() {
        return Err("GetDC failed".into());
    }
    let hdc_mem = CreateCompatibleDC(hdc_screen);
    let bmp = CreateCompatibleBitmap(hdc_screen, w as i32, h as i32);
    if hdc_mem.is_null() || bmp.is_null() {
        return Err("GDI resource creation failed".into());
    }
    let old = SelectObject(hdc_mem, bmp as *mut _);

    let ok = PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT);

    let mut bih: BITMAPINFOHEADER = std::mem::zeroed();
    bih.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bih.biWidth = w as i32;
    bih.biHeight = -(h as i32); // top-down
    bih.biPlanes = 1;
    bih.biBitCount = 32;
    bih.biCompression = BI_RGB;
    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader = bih;

    let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
    let rows = GetDIBits(
        hdc_mem,
        bmp,
        0,
        h,
        buf.as_mut_ptr() as *mut _,
        &mut bmi,
        DIB_RGB_COLORS,
    );
    let mut used_screen = false;

    if ok == 0 || rows == 0 || blank_check(&buf, w, h) {
        // Fallback: raise the window and blit from the screen.
        ShowWindow(hwnd, SW_RESTORE);
        SetWindowPos(
            hwnd,
            HWND_TOP,
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW,
        );
        SetForegroundWindow(hwnd);
        std::thread::sleep(Duration::from_millis(1200));
        BitBlt(hdc_mem, 0, 0, w as i32, h as i32, hdc_screen, 0, 0, SRCCOPY);
        // The screen DC origin is the desktop: re-capture via window rect.
        let mut r: RECT = std::mem::zeroed();
        GetWindowRect(hwnd, &mut r);
        BitBlt(
            hdc_mem,
            0,
            0,
            w as i32,
            h as i32,
            hdc_screen,
            r.left,
            r.top,
            SRCCOPY,
        );
        let rows2 = GetDIBits(
            hdc_mem,
            bmp,
            0,
            h,
            buf.as_mut_ptr() as *mut _,
            &mut bmi,
            DIB_RGB_COLORS,
        );
        used_screen = rows2 != 0;
        if rows2 == 0 {
            return Err("GetDIBits (screen fallback) failed".into());
        }
    }

    SelectObject(hdc_mem, old);
    DeleteObject(bmp as *mut _);
    DeleteDC(hdc_mem);
    ReleaseDC(std::ptr::null_mut(), hdc_screen);

    Ok((buf, used_screen))
}

// ─── commands ───────────────────────────────────────────────

fn cmd_build(opts: &Opts) -> ExitCode {
    let what = opts.first("all");
    let mut targets: Vec<&str> = Vec::new();
    match what.as_str() {
        "all" => targets = vec!["shim", "selftest", "host", "probe", "sim", "hwprobe"],
        other => targets.push(other),
    }
    // positional list form: `build shim host sim`
    for p in opts.positional.iter().skip(1) {
        targets.push(p);
    }

    for t in targets {
        let (label, cl, artifact): (&str, String, PathBuf) = match t {
            "shim" => (
                "shim",
                "cl /nologo /LD /O2 /EHsc /DNDEBUG /MT /utf-8 shim\\sandbox_shim.cpp /Ishim \
                 /Fo:target\\shimtest\\sandbox_shim.obj \
                 /link /OUT:target\\shimtest\\sandbox_shim_new.dll \
                 kernel32.lib user32.lib advapi32.lib setupapi.lib iphlpapi.lib crypt32.lib \
                 wintrust.lib ole32.lib oleaut32.lib wbemuuid.lib dxgi.lib psapi.lib"
                    .to_string(),
                shimtest().join("sandbox_shim_new.dll"),
            ),
            "selftest" => (
                "selftest",
                "cl /nologo /O2 /EHsc /MT /utf-8 target\\shimtest\\hook_selftest.cpp /Ishim \
                 /Fo:target\\shimtest\\hook_selftest.obj \
                 /Fe:target\\shimtest\\hook_selftest.exe /link kernel32.lib user32.lib"
                    .to_string(),
                shimtest().join("hook_selftest.exe"),
            ),
            "host" => (
                "host",
                "cl /nologo /O2 /EHsc /DNDEBUG /MT /utf-8 target\\shimtest\\ghost_host.cpp \
                 /Fo:target\\shimtest\\ghost_host.obj /link /OUT:target\\shimtest\\ghost_host.exe"
                    .to_string(),
                shimtest().join("ghost_host.exe"),
            ),
            "probe" => (
                "probe",
                "cl /nologo /O2 /EHsc /MT /utf-8 target\\drmtest\\drm_probe.cpp \
                 /Fo:target\\drmtest\\drm_probe.obj /Fe:target\\drmtest\\drm_probe.exe \
                 /link advapi32.lib wintrust.lib psapi.lib iphlpapi.lib"
                    .to_string(),
                drmtest().join("drm_probe.exe"),
            ),
            "sim" => (
                "sim",
                "cl /nologo /O2 /EHsc /MT /utf-8 target\\drmtest\\malware_sim.cpp \
                 /Fo:target\\drmtest\\malware_sim.obj /Fe:target\\drmtest\\malware_sim.exe \
                 /link urlmon.lib ws2_32.lib advapi32.lib"
                    .to_string(),
                drmtest().join("malware_sim.exe"),
            ),
            "hwprobe" => (
                "hwprobe",
                "cl /nologo /O2 /EHsc /MT /utf-8 target\\drmtest\\hw_probe.cpp \
                 /Fo:target\\drmtest\\hw_probe.obj /Fe:target\\drmtest\\hw_probe.exe \
                 /link advapi32.lib iphlpapi.lib ole32.lib oleaut32.lib wbemuuid.lib"
                    .to_string(),
                drmtest().join("hw_probe.exe"),
            ),
            other => {
                eprintln!("unknown build target '{}'", other);
                return ExitCode::from(2);
            }
        };

        println!("[build {}] cl …", label);
        match run_cl(&cl) {
            Ok(text) => {
                for line in text.lines() {
                    if line.contains("error") || line.contains("warning C") {
                        println!("  {}", line);
                    }
                }
                println!("  BUILD OK  {}", artifact.display());
            }
            Err(text) => {
                eprintln!("[build {}] FAILED\n{}", label, text);
                return ExitCode::from(1);
            }
        }
    }

    // The shim build implies deployment (root + debug + release copies).
    if what == "all" || what == "shim" {
        cmd_deploy(&Opts::default());
    }
    ExitCode::SUCCESS
}

fn cmd_deploy(_opts: &Opts) -> ExitCode {
    let src = shimtest().join("sandbox_shim_new.dll");
    if !src.is_file() {
        eprintln!("missing {} — run `ghost_lab build shim`", src.display());
        return ExitCode::from(1);
    }
    let targets = [
        root().join("sandbox_shim.dll"),
        root().join("target").join("debug").join("sandbox_shim.dll"),
        root().join("target").join("release").join("sandbox_shim.dll"),
    ];
    for t in targets {
        if let Some(dir) = t.parent() {
            if !dir.is_dir() {
                println!("  skip {} (no such directory)", t.display());
                continue;
            }
        }
        match fs::copy(&src, &t) {
            Ok(n) => println!("  deployed {} ({} bytes)", t.display(), n),
            Err(e) => {
                eprintln!("  deploy failed {}: {}", t.display(), e);
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

fn cmd_selftest(_opts: &Opts) -> ExitCode {
    let exe = shimtest().join("hook_selftest.exe");
    if !exe.is_file() {
        eprintln!("missing {} — run `ghost_lab build selftest`", exe.display());
        return ExitCode::from(1);
    }
    let (code, text) = run_capture(&mut Command::new(&exe));
    print!("{}", text);
    let _ = fs::write(shimtest().join("selftest_out.txt"), &text);

    let mut pass = 0u32;
    let mut fail = 0u32;
    for line in text.lines() {
        if let Some(rest) = line.split("RESULT:").nth(1) {
            let parts: Vec<&str> = rest.split(',').collect();
            if let Some(p) = parts.first() {
                pass = p.trim().split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
            }
            if let Some(f) = parts.get(1) {
                fail = f.trim().split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
            }
        }
    }
    println!(
        "\nselftest: {} pass, {} fail ({} hooks) — exit {:?}",
        pass,
        fail,
        pass + fail,
        code
    );
    if fail == 0 && pass > 0 && code == Some(0) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn cmd_shot(opts: &Opts) -> ExitCode {
    let name = opts.get_or("process", "ghost_sandbox");
    let out = PathBuf::from(opts.get_or("out", drmtest().join("shot.png").display().to_string()));
    let timeout = Duration::from_millis(opts.num("timeout", 15_000));

    unsafe {
        SetProcessDPIAware();
    }

    let deadline = Instant::now() + timeout;
    let mut pid = None;
    while Instant::now() < deadline {
        if let Some(p) = find_pid(&name) {
            pid = Some(p);
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let Some(pid) = pid else {
        eprintln!("no process named {}", name);
        return ExitCode::from(1);
    };

    // Wait for a usable window, restoring if minimised.
    let mut hwnd = None;
    let mut size = (0u32, 0u32);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(h) = find_main_window(pid) {
            unsafe {
                ShowWindow(h, SW_RESTORE);
                let mut r: RECT = std::mem::zeroed();
                GetWindowRect(h, &mut r);
                let w = (r.right - r.left).max(0) as u32;
                let hh = (r.bottom - r.top).max(0) as u32;
                if w > 300 && hh > 300 {
                    hwnd = Some(h);
                    size = (w, hh);
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    let Some(hwnd) = hwnd else {
        eprintln!("no usable main window for {} (PID {})", name, pid);
        return ExitCode::from(1);
    };

    let (w, h) = size;
    let result = unsafe { capture_window(hwnd, w, h) };
    match result {
        Ok((buf, used_screen)) => {
            let blank = blank_check(&buf, w, h);
            if let Err(e) = write_png(&out, &buf, w, h) {
                eprintln!("{}", e);
                return ExitCode::from(1);
            }
            let len = fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
            println!(
                "saved {} ({}x{}, {} bytes, screen_fallback={}, blank={})",
                out.display(),
                w,
                h,
                len,
                used_screen,
                blank
            );
            if blank {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("capture failed: {}", e);
            ExitCode::from(1)
        }
    }
}

fn split_cmdline(s: &str) -> (String, Vec<String>) {
    let args = ghost_sandbox::tools::split_args(s);
    let mut it = args.into_iter();
    let exe = it.next().unwrap_or_default();
    (exe, it.collect())
}

fn cmd_inject(opts: &Opts) -> ExitCode {
    let target = opts.get_or(
        "target",
        "C:\\Windows\\System32\\cmd.exe /c timeout /t 30 >nul",
    );
    let shim = opts.get_or(
        "shim",
        root().join("target").join("debug").join("sandbox_shim.dll").display().to_string(),
    );
    let pid_file = opts
        .get("pid-file")
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| root().join("target").join("test_target.pid"));
    let (exe, args) = split_cmdline(&target);

    // --env KEY=VALUE (repeatable) → the child environment (malware channel).
    let env: Vec<(String, String)> = opts
        .all("env")
        .iter()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let containment = ghost_sandbox::injector::Containment::from_label(
        opts.get_or("containment", "none").as_str(),
    );
    let log_path = opts.get("log").map(|s| s.to_string());

    let opts_launch = ghost_sandbox::injector::LaunchOptions {
        log_path: log_path.as_deref(),
        env,
        containment,
    };

    let injected = match ghost_sandbox::injector::inject_ex(&exe, &shim, &args, &opts_launch) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("injection failed: {}", e);
            return ExitCode::from(3);
        }
    };
    let pid = injected.pid;
    if let Err(e) = injected.resume() {
        eprintln!("resume failed: {}", e);
        return ExitCode::from(3);
    }
    let _ = fs::write(&pid_file, format!("{}\n", pid));
    println!(
        "injected + resumed PID {} (shim {}, containment {})",
        pid,
        shim,
        containment.label()
    );

    if let Some(ms) = opts.get("wait").and_then(|v| v.parse::<u64>().ok()) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    ExitCode::SUCCESS
}

/// Parse a raw sink dump into protocol frames (type/size/offset) — the
/// desync detector of last resort when a controller grep shows nothing.
fn cmd_frames(opts: &Opts) -> ExitCode {
    let Some(file) = opts.get("file") else {
        eprintln!("usage: ghost_lab frames --file DUMP.bin");
        return ExitCode::from(2);
    };
    let data = match fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {}", file, e);
            return ExitCode::from(1);
        }
    };
    let names: BTreeMap<u8, &str> = [
        (1u8, "trace"),
        (2, "spoof"),
        (3, "dll_load"),
        (4, "dll_unload"),
        (5, "exception"),
        (6, "patch_ack"),
        (7, "cpuid_trap"),
        (8, "vtable_mod"),
        (9, "connected"),
        (10, "memory_dump"),
        (11, "registers"),
        (12, "module_list"),
        (13, "drm"),
        (14, "policy_hit"),
        (15, "malware_op"),
        (16, "target_exec"),
    ]
    .into_iter()
    .collect();

    let mut off = 0usize;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = 0usize;
    while off + 5 <= data.len() {
        let ty = data[off];
        let size = u32::from_le_bytes([data[off + 1], data[off + 2], data[off + 3], data[off + 4]])
            as usize;
        let name = names
            .get(&ty)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("unknown({})", ty));
        if size < 17 || off + size > data.len() {
            println!(
                "  DESYNC at offset {}: type={} size={} (bytes left {})",
                off,
                ty,
                size,
                data.len() - off
            );
            bad += 1;
            break;
        }
        *counts.entry(name.clone()).or_insert(0) += 1;
        if name == "malware_op" {
            // op_id/category/action/flags/verdict/pending at 17..41
            let g = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
            println!(
                "  malware_op opId={} cat={} act={} flags=0x{:X} verdict={} pending={} size={}",
                g(off + 17),
                g(off + 21),
                g(off + 25),
                g(off + 29),
                g(off + 33),
                g(off + 37),
                size
            );
        }
        off += size;
    }
    println!("total {} bytes, {} trailing", off, data.len() - off);
    for (k, v) in counts {
        println!("  {:14} {}", k, v);
    }
    if bad == 0 && off == data.len() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

// ─── raw pipe tools ─────────────────────────────────────────

fn pipe_name_w(name: &str) -> Vec<u16> {
    format!("\\\\.\\pipe\\{}", name)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

unsafe fn pipe_write(h: winapi::um::winnt::HANDLE, data: &[u8]) -> bool {
    let mut written: DWORD = 0;
    WriteFile(
        h,
        data.as_ptr() as *const _,
        data.len() as u32,
        &mut written,
        std::ptr::null_mut(),
    ) != 0
        && written as usize == data.len()
}

fn cmd_pipe_sink(opts: &Opts) -> ExitCode {
    let name = opts.get_or("pipe", PIPE_NAME);
    let out = PathBuf::from(opts.get_or(
        "out",
        drmtest().join("sink.bin").display().to_string(),
    ));
    let seconds = opts.num("seconds", 60);

    unsafe {
        let pw = pipe_name_w(&name);
        let h = CreateNamedPipeW(
            pw.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            eprintln!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
            return ExitCode::from(1);
        }
        println!("sink: waiting for connection on \\\\.\\pipe\\{}", name);
        ConnectNamedPipe(h, std::ptr::null_mut());
        println!("sink: connected");

        let mut file = match File::create(&out) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{}: {}", out.display(), e);
                return ExitCode::from(1);
            }
        };
        let mut buf = vec![0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut total = 0usize;
        while Instant::now() < deadline {
            let mut got: DWORD = 0;
            let ok = ReadFile(
                h,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            );
            if ok == 0 || got == 0 {
                println!("sink: read ended (err {})", std::io::Error::last_os_error());
                break;
            }
            if file.write_all(&buf[..got as usize]).is_err() {
                break;
            }
            let _ = file.flush();
            total += got as usize;
        }
        let _ = file.sync_all();
        CloseHandle(h);
        println!("sink: done, {} bytes in {}", total, out.display());
    }
    ExitCode::SUCCESS
}

fn put_str(buf: &mut [u8], off: usize, s: &str, max_len: usize) {
    let b = s.as_bytes();
    let n = b.len().min(max_len - 1);
    buf[off..off + n].copy_from_slice(&b[..n]);
}

/// Build an EVT_TRACE/EVT_SPOOF frame body (the 1106-byte layout).
fn trace_frame(ty: u8, function: &str, module: &str, params: &str, ret: &str, spoofed: bool) -> Vec<u8> {
    let size = HEADER_SIZE + 128 + 256 + 512 + 128 + 8 + 1 + 7 * 8;
    let mut b = vec![0u8; size];
    b[0] = ty;
    b[1..5].copy_from_slice(&(size as u32).to_le_bytes());
    b[13..17].copy_from_slice(&4096u32.to_le_bytes()); // thread id
    put_str(&mut b, 17, function, 128);
    put_str(&mut b, 145, module, 256);
    put_str(&mut b, 401, params, 512);
    put_str(&mut b, 913, ret, 128);
    b[1041..1049].copy_from_slice(&137u64.to_le_bytes()); // duration
    b[1049] = spoofed as u8;
    b
}

fn cmd_fake_shim(opts: &Opts) -> ExitCode {
    let name = opts.get_or("pipe", PIPE_NAME);
    let pw = pipe_name_w(&name);

    unsafe {
        let mut h: winapi::um::winnt::HANDLE = INVALID_HANDLE_VALUE;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            h = CreateFileW(
                pw.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if h != INVALID_HANDLE_VALUE {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        if h == INVALID_HANDLE_VALUE {
            eprintln!("cannot connect to \\\\.\\pipe\\{}: {}", name, std::io::Error::last_os_error());
            return ExitCode::from(1);
        }
        println!("fake shim: connected to \\\\.\\pipe\\{}", name);

        // EVT_CONNECTED (header only)
        let mut connected = vec![0u8; HEADER_SIZE];
        connected[0] = EVT_CONNECTED;
        connected[1..5].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        pipe_write(h, &connected);

        // EVT_TRACE, split across two writes to exercise frame reassembly
        let trace = trace_frame(
            EVT_TRACE,
            "LoadLibraryW",
            "kernel32.dll",
            "lpLibFileName=\"C:\\test\\payload.dll\"",
            "0x00007FFA12345678",
            false,
        );
        pipe_write(h, &trace[..100]);
        std::thread::sleep(Duration::from_millis(150));
        pipe_write(h, &trace[100..]);

        // EVT_SPOOF
        let spoof = trace_frame(
            EVT_SPOOF,
            "IWbemServices::ExecQuery",
            "wmi",
            "SELECT * FROM Win32_VideoController",
            "S_OK (spoofed)",
            true,
        );
        pipe_write(h, &spoof);

        // EVT_DLL_LOAD (293 bytes)
        let mut dll = vec![0u8; 293];
        dll[0] = EVT_DLL_LOAD;
        dll[1..5].copy_from_slice(&293u32.to_le_bytes());
        put_str(&mut dll, 17, "C:\\test\\payload.dll", 260);
        dll[277..285].copy_from_slice(&0x0000_7FFA_1000_0000u64.to_le_bytes());
        dll[285..293].copy_from_slice(&0x9000u64.to_le_bytes());
        pipe_write(h, &dll);

        // EVT_MEMORY_DUMP (4125 bytes, 16 payload bytes)
        let mut dump = vec![0u8; 4125];
        dump[0] = EVT_MEMORY_DUMP;
        dump[1..5].copy_from_slice(&4125u32.to_le_bytes());
        dump[17..25].copy_from_slice(&0x0000_7FFA_1000_1000u64.to_le_bytes());
        dump[25..29].copy_from_slice(&16u32.to_le_bytes());
        let payload = [0x4Du8, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00];
        dump[29..45].copy_from_slice(&payload);
        pipe_write(h, &dump);

        std::thread::sleep(Duration::from_millis(800));
        CloseHandle(h);
        println!("fake shim: finished");
    }
    ExitCode::SUCCESS
}

fn cmd_fake_controller(opts: &Opts) -> ExitCode {
    let name = opts.get_or("pipe", PIPE_NAME);
    let seconds = opts.num("seconds", 16);
    let profile_mmf = opts.get_or("profile-mmf", "GhostSandboxProfile");
    let pw = pipe_name_w(&name);

    unsafe {
        // Shared hardware-profile mapping the shim reads on startup/reload.
        let mmf_name: Vec<u8> = profile_mmf
            .bytes()
            .chain(std::iter::once(0))
            .collect();
        let map = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            1481,
            mmf_name.as_ptr() as *const i8,
        );
        if map.is_null() {
            eprintln!(
                "CreateFileMappingA({}) failed: {}",
                profile_mmf,
                std::io::Error::last_os_error()
            );
            return ExitCode::from(1);
        }
        let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 1481);
        if view.is_null() {
            eprintln!("MapViewOfFile failed: {}", std::io::Error::last_os_error());
            return ExitCode::from(1);
        }
        *(view as *mut u32) = 0x444E_5347; // "GSND" magic
        println!("[ctrl] shared profile mapping created (magic=0x444E5347)");

        let h = CreateNamedPipeW(
            pw.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            eprintln!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
            return ExitCode::from(1);
        }
        println!("[ctrl] pipe created, waiting for shim…");
        ConnectNamedPipe(h, std::ptr::null_mut());
        println!("[ctrl] shim connected!");

        let start = Instant::now();
        let mut total = 0usize;
        let (mut sent_pause, mut sent_resume, mut sent_reload) = (false, false, false);
        let mut buf = vec![0u8; 8192];
        while start.elapsed().as_secs() < seconds {
            // Drain whatever the shim queued (non-blocking peek).
            loop {
                let mut avail: DWORD = 0;
                let ok = PeekNamedPipe(
                    h,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                );
                if ok == 0 {
                    println!("[ctrl] peek failed — shim gone");
                    break;
                }
                if avail == 0 {
                    break;
                }
                let mut got: DWORD = 0;
                let want = avail.min(buf.len() as u32);
                if ReadFile(h, buf.as_mut_ptr() as *mut _, want, &mut got, std::ptr::null_mut()) != 0 {
                    total += got as usize;
                } else {
                    break;
                }
            }

            let t = start.elapsed().as_secs_f64();
            let send = |ty: u8, label: &str, flag: &mut bool| {
                let frame = [ty, 5, 0, 0, 0];
                if pipe_write(h, &frame) {
                    println!("[ctrl] sent {} at t={:.1}s", label, t);
                }
                *flag = true;
            };
            if !sent_pause && t > 2.0 {
                send(CMD_TRACE_PAUSE, "TRACE_PAUSE", &mut sent_pause);
            }
            if !sent_resume && t > 5.0 {
                send(CMD_TRACE_RESUME, "TRACE_RESUME", &mut sent_resume);
            }
            if !sent_reload && t > 8.0 {
                send(CMD_PROFILE_RELOAD, "PROFILE_RELOAD", &mut sent_reload);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        println!("[ctrl] total event bytes received: {}", total);
        CloseHandle(h);
        UnmapViewOfFile(view as *const _);
        CloseHandle(map);
        println!("[ctrl] done");
    }
    ExitCode::SUCCESS
}

// ─── E2E suites ─────────────────────────────────────────────

fn cmd_e2e(opts: &Opts) -> ExitCode {
    let which = opts.first("all");
    let mut results = Vec::new();
    match which.as_str() {
        "all" => {
            results.push(e2e_cli());
            results.push(e2e_drm());
            results.push(e2e_hw());
            results.push(e2e_sandbox());
            results.push(e2e_malware());
            results.push(e2e_malware_gui());
        }
        "cli" => results.push(e2e_cli()),
        "drm" => results.push(e2e_drm()),
        "hw" => results.push(e2e_hw()),
        "sandbox" => results.push(e2e_sandbox()),
        "malware" => results.push(e2e_malware()),
        "malware-gui" => results.push(e2e_malware_gui()),
        other => {
            eprintln!("unknown e2e suite '{}'", other);
            return ExitCode::from(2);
        }
    }
    let mut fail = 0u32;
    for r in &results {
        fail += r.fail;
    }
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// CLI suite: inspect / policy template / tools / instrumented run / memory ops.
fn e2e_cli() -> Check {
    let mut c = Check::new("e2e cli");
    let out = drmtest();
    let ghost = root().join("target").join("debug").join("ghost.exe");
    let probe = out.join("drm_probe.exe");

    c.check(ghost.is_file(), format!("ghost.exe present ({})", ghost.display()));
    c.check(probe.is_file(), "drm_probe.exe built");
    if !ghost.is_file() || !probe.is_file() {
        return c;
    }

    kill_harness_procs();
    for f in ["cli_run.json", "cli_stream.jsonl", "cli_inspect.md", "cli_policy_tmpl.toml", "cli_run_err.log"] {
        let _ = fs::remove_file(out.join(f));
    }
    std::thread::sleep(Duration::from_millis(500));

    // 1) version
    let (_, ver) = run_capture(Command::new(&ghost).args(["version", "--format", "json"]));
    c.check(ver.contains("\"version\""), "ghost version --format json");

    // 2) inspect
    let md_path = out.join("cli_inspect.md");
    let (code, _) = run_capture(
        Command::new(&ghost)
            .args(["inspect", probe.to_str().unwrap(), "--format", "md", "--out", md_path.to_str().unwrap()]),
    );
    c.check(code == Some(0), "inspect exit code 0");
    let md = read_text(&md_path);
    c.check(md.to_lowercase().contains("sha256") || md.to_lowercase().contains("sha-256"), "inspect report has hashes");
    c.check(md.contains("IsDebuggerPresent"), "inspect report lists imports");
    c.check(md.contains("Experimental software provided as-is"), "inspect report carries the notice");

    // 3) policy template
    let tmpl_path = out.join("cli_policy_tmpl.toml");
    let (code, _) = run_capture(
        Command::new(&ghost).args([
            "policy",
            "template",
            probe.to_str().unwrap(),
            "--out",
            tmpl_path.to_str().unwrap(),
        ]),
    );
    c.check(code == Some(0), "policy template exit code 0");
    let tmpl = read_text(&tmpl_path);
    c.check(tmpl.contains("[[rule]]"), "template has [[rule]] entries");
    c.check(tmpl.contains("function = \"IsDebuggerPresent\""), "template lists IsDebuggerPresent");

    // 4) tools
    let (code, tools_json) = run_capture(Command::new(&ghost).args(["tools", "list", "--format", "json"]));
    c.check(code == Some(0), "tools list exit code 0");
    let tool_count = tools_json.matches("\"name\"").count();
    c.check(tool_count >= 5, format!("tool catalogue has entries ({})", tool_count));
    let (code, dry) = run_capture(Command::new(&ghost).args([
        "tools",
        "open",
        "--stage",
        "disassemble",
        "--file",
        probe.to_str().unwrap(),
        "--dry-run",
    ]));
    c.check(code == Some(0) && !dry.trim().is_empty(), "tools open --dry-run resolved");
    c.info(format!("resolved: {}", dry.lines().next().unwrap_or("")));

    // ── help surfaces ──
    // The live reference an AI agent can always run: `ghost help` lists every
    // command; `ghost help <command>` and `<command> --help` / `-h` narrow it.
    let (code, all) = run_capture(Command::new(&ghost).arg("help"));
    c.check(code == Some(0), "ghost help exit 0");
    for cmd in ["inspect", "run", "policy", "tools", "version", "help"] {
        c.check(all.contains(cmd), format!("ghost help lists '{}'", cmd));
    }
    c.check(all.contains("--accept-disclaimer"), "ghost help documents the malware gate");
    let (code, run_help) = run_capture(Command::new(&ghost).args(["help", "run"]));
    c.check(code == Some(0), "ghost help run exit 0");
    c.check(
        run_help.contains("--malware") && run_help.contains("--containment") && run_help.contains("MODULE PATTERNS"),
        "ghost help run covers run + malware modes",
    );
    let (code, inspect_help) = run_capture(Command::new(&ghost).args(["inspect", "--help"]));
    c.check(code == Some(0) && inspect_help.contains("ghost inspect"), "ghost inspect --help works");
    let (code, tools_help) = run_capture(Command::new(&ghost).args(["tools", "list", "-h"]));
    c.check(code == Some(0) && tools_help.contains("ghost tools open"), "ghost tools list -h works");
    let (code, policy_help) = run_capture(Command::new(&ghost).args(["policy", "--help"]));
    c.check(code == Some(0) && policy_help.contains("ghost policy template"), "ghost policy --help works");

    // 5) instrumented run with an import policy + JSONL streaming
    let report = out.join("cli_run.json");
    let stream = out.join("cli_stream.jsonl");
    let errlog = out.join("cli_run_err.log");
    let stream_file = File::create(&stream).unwrap();
    let err_file = File::create(&errlog).unwrap();
    let status = Command::new(&ghost)
        .current_dir(&out)
        .args([
            "run",
            probe.to_str().unwrap(),
            "--duration",
            "25",
            "--format",
            "json",
            "--out",
            report.to_str().unwrap(),
            "--stream",
            "--quiet",
            "--block",
            "kernel32.dll!IsDebuggerPresent=1",
            "--observe",
            "kernel32.dll!GetTickCount64",
        ])
        .stdout(Stdio::from(stream_file))
        .stderr(Stdio::from(err_file))
        .status();
    let run_code = match &status {
        Ok(s) => s.code(),
        Err(_) => None,
    };
    c.check(run_code == Some(0), format!("run exit code 0 (shim connected) ({:?})", run_code));

    let rep: serde_json::Value = serde_json::from_str(&read_text(&report)).unwrap_or_default();
    let counts = &rep["counts"];
    let hits = counts["policy_hits"].as_u64().unwrap_or(0);
    let blocked = counts["policy_blocked"].as_u64().unwrap_or(0);
    let observed = counts["policy_observed"].as_u64().unwrap_or(0);
    c.info(format!("counts: hits={} blocked={} observed={} drm={}", hits, blocked, observed, counts["drm_events"]));
    c.check(hits >= 1, "report has policy hits");
    c.check(blocked >= 1, "at least one block hit");
    c.check(observed >= 1, "at least one observe hit");
    if let Some(arr) = rep["policy_hits"].as_array() {
        let first_blocked = arr.iter().find(|h| h["blocked"].as_bool().unwrap_or(false));
        c.check(first_blocked.is_some(), "blocked hit names the rule");
        if let Some(b) = first_blocked {
            c.info(format!(
                "first blocked: {}!{} caller {}+0x{:X}",
                b["module"].as_str().unwrap_or(""),
                b["function"].as_str().unwrap_or(""),
                b["caller_module"].as_str().unwrap_or(""),
                b["caller_rva"].as_u64().unwrap_or(0)
            ));
        }
    }

    let st = read_text(&stream);
    c.check(st.contains("\"type\":\"run_start\""), "stream has run_start frame");
    c.check(st.contains("\"type\":\"policy_hit\""), "stream has live policy_hit lines");
    c.check(st.contains("\"type\":\"run_end\""), "stream has run_end frame");
    let foreign = st
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('{'))
        .count();
    c.check(foreign == 0, format!("stream is pure JSONL ({} foreign line(s))", foreign));

    // 6) target-side view of the blocked call
    let tlog = out.join("cli_run.json.target.log");
    let target_log = read_text(&tlog);
    c.check(
        target_log.contains("IsDebuggerPresent() = 1"),
        "blocked call returned the fake value to the target",
    );

    // 7) shim log
    let shim_log = std::env::temp_dir().join("ghost_sandbox_shim.log");
    let sl = read_text(&shim_log);
    c.check(sl.contains("[policy]"), "shim applied the policy");

    // 8) memory ops on a live target (dump / patch / nop)
    let hostexe = shimtest().join("ghost_host.exe");
    let mem_report = out.join("cli_mem.json");
    let mem_stream = out.join("cli_mem.jsonl");
    let mem_err = out.join("cli_mem_err.log");
    let _ = fs::remove_file(&mem_report);
    let _ = fs::remove_file(&mem_stream);
    if hostexe.is_file() {
        let status = Command::new(&ghost)
            .current_dir(&out)
            .args([
                "run",
                hostexe.to_str().unwrap(),
                "--args",
                "C:\\Windows\\System32\\version.dll --seconds 5",
                "--duration",
                "7",
                "--quiet",
                "--format",
                "json",
                "--out",
                mem_report.to_str().unwrap(),
                "--stream",
                "--dump",
                "main+0:80",
                "--dump",
                "nosuch.dll+0:16",
                "--patch",
                "main+0x40=DE AD BE EF",
                "--nop",
                "main+0x48:2",
            ])
            .stdout(Stdio::from(File::create(&mem_stream).unwrap()))
            .stderr(Stdio::from(File::create(&mem_err).unwrap()))
            .status();
        let mem_code = match &status {
            Ok(s) => s.code(),
            Err(_) => None,
        };
        c.check(mem_code == Some(0), "memory run exit code 0");
        let merr = read_text(&mem_err);
        c.check(
            merr.contains("dump skipped: unknown module"),
            "unresolvable module address reported",
        );
        let mrep: serde_json::Value =
            serde_json::from_str(&read_text(&mem_report)).unwrap_or_default();
        let dumps = mrep["memory_dumps"].as_array().cloned().unwrap_or_default();
        c.check(dumps.len() == 1, format!("one memory dump captured ({})", dumps.len()));
        if let Some(d0) = dumps.first() {
            let hex = d0["hex"].as_str().unwrap_or("");
            c.check(hex.len() == 160, format!("dump is 80 bytes of hex ({}/160 chars)", hex.len()));
            c.check(hex.starts_with("4D5A"), "dump starts with MZ (main module)");
            c.check(hex.get(128..136) == Some("DEADBEEF"), "patch landed at main+0x40");
            c.check(hex.get(144..148) == Some("9090"), "nop landed at main+0x48");
            c.check(d0["ascii"].as_str().unwrap_or("").starts_with("MZ"), "ascii rendering present");
        }
        let ms = read_text(&mem_stream);
        c.check(
            ms.contains("\"type\":\"memory_dump\"") && ms.contains("\"hex\":\"4D5A"),
            "stream carries dump hex",
        );
    } else {
        c.check(false, "ghost_host.exe built (needed for the memory run)");
    }

    // Bad address forms fail fast as usage errors (exit 2) before injection.
    let (code, _) = run_capture(Command::new(&ghost).args([
        "run",
        probe.to_str().unwrap(),
        "--jmp",
        "zzz",
        "--quiet",
    ]));
    c.check(code == Some(2), "--jmp with a bad address is a usage error");
    let (code, _) = run_capture(Command::new(&ghost).args([
        "run",
        probe.to_str().unwrap(),
        "--patch",
        "main+0x40=9",
        "--quiet",
    ]));
    c.check(code == Some(2), "--patch with odd hex is a usage error");

    c
}

/// DRM suite: GUI (anti-tamper view) + injected probe, screenshot, logs.
fn e2e_drm() -> Check {
    let mut c = Check::new("e2e drm");
    let out = drmtest();
    let probe = out.join("drm_probe.exe");
    let probe_out = out.join("drm_probe_out.txt");
    let gui_out = out.join("gui_stdout.log");
    let gui_err = out.join("gui_stderr.log");
    let png = out.join("gui_drm_view.png");

    kill_harness_procs();
    for f in [&probe_out, &gui_out, &gui_err, &png] {
        let _ = fs::remove_file(f);
    }
    std::thread::sleep(Duration::from_millis(400));

    let child = match launch_gui(&[("GHOST_START_VIEW", "drm")], &gui_out, &gui_err) {
        Ok(ch) => ch,
        Err(e) => {
            c.check(false, e);
            return c;
        }
    };
    c.check(wait_for_pipe(Duration::from_secs(60)), "GUI control pipe is up");

    // Inject the probe with the freshly built shim.
    let shim = root().join("target").join("debug").join("sandbox_shim.dll");
    let injected = ghost_sandbox::injector::inject(
        probe.to_str().unwrap(),
        shim.to_str().unwrap(),
        &[],
    );
    match injected {
        Ok(p) => {
            let pid = p.pid;
            let _ = p.resume();
            c.check(true, format!("probe injected (PID {})", pid));
            std::thread::sleep(Duration::from_secs(18));

            let shot = shot_to(&png);
            c.check(shot.is_ok(), format!("screenshot captured: {:?}", shot.err()));
            std::thread::sleep(Duration::from_secs(2));

            let po = read_text(&probe_out);
            c.check(po.contains("DRM probe battery"), "probe battery ran");
            c.check(
                po.contains("[mark] memprot") && po.contains("VirtualProtect(RWX)"),
                "probe completed the anti-debug / integrity battery",
            );

            let so = read_text(&gui_out);
            c.check(
                so.contains("DRM events flowing") && so.contains("GetSystemInfo"),
                "GUI received DRM events from the probe",
            );
            c.check(
                so.contains("profile applied"),
                "hardware profile spoof reached the target through the GUI",
            );
            let se = read_text(&gui_err);
            c.check(se.trim().is_empty(), "GUI stderr clean");

            let shim_log = std::env::temp_dir().join("ghost_sandbox_shim.log");
            let sl = read_text(&shim_log);
            let drm_lines = count_matches(&sl, "[DRM]");
            c.check(drm_lines >= 10, format!("shim logged DRM activity ({} lines)", drm_lines));
            c.check(
                sl.contains("caller=drm_probe.exe+"),
                "shim attributed DRM calls to the probe",
            );
        }
        Err(e) => {
            c.check(false, format!("probe injection failed: {}", e));
        }
    }

    kill_proc("drm_probe");
    drop(child);
    let _ = kill_proc("ghost_sandbox");
    c
}

/// Extract the value of an "[hw] key=value" line from probe output.
fn line_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("[hw] {}=", key);
    text.lines()
        .find(|l| l.starts_with(&needle))
        .map(|l| l[needle.len()..].trim_end())
}

/// Hardware identity suite: run the hardware probe un-injected (ground
/// truth), then inject it under the shim with the GUI-published profile and
/// verify every hardware-reporting source matches profiles/default.toml.
fn e2e_hw() -> Check {
    let mut c = Check::new("e2e hw");
    let out = drmtest();
    let probe = out.join("hw_probe.exe");
    let probe_out = out.join("hw_probe_out.txt");
    let ground = out.join("hw_probe_ground.txt");
    let gui_out = out.join("gui_hw_stdout.log");
    let gui_err = out.join("gui_hw_stderr.log");

    c.check(probe.is_file(), "hw_probe.exe built");
    if !probe.is_file() {
        return c;
    }

    let profile_path = root().join("profiles").join("default.toml");
    let profile = match ghost_sandbox::profile::HardwareProfile::load_from_file(
        &profile_path.to_string_lossy(),
    ) {
        Ok(p) => p,
        Err(e) => {
            c.check(false, format!("load {}: {}", profile_path.display(), e));
            return c;
        }
    };

    kill_harness_procs();
    for f in [&probe_out, &ground, &gui_out, &gui_err] {
        let _ = fs::remove_file(f);
    }
    std::thread::sleep(Duration::from_millis(400));

    // 1) Ground truth: identical probe, no shim.
    let gt_ok = Command::new(&probe)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    c.check(gt_ok, "ground-truth probe (no shim) exited cleanly");
    if probe_out.is_file() {
        let _ = fs::copy(&probe_out, &ground);
        let _ = fs::remove_file(&probe_out);
    }
    let gt = read_text(&ground);
    c.check(gt.contains("probe.done"), "ground-truth probe completed");

    // 2) GUI up (publishes the profile), then inject the probe.
    let child = match launch_gui(&[("GHOST_START_VIEW", "drm")], &gui_out, &gui_err) {
        Ok(ch) => ch,
        Err(e) => {
            c.check(false, e);
            return c;
        }
    };
    c.check(wait_for_pipe(Duration::from_secs(60)), "GUI control pipe is up");

    let shim = root().join("target").join("debug").join("sandbox_shim.dll");
    match ghost_sandbox::injector::inject(probe.to_str().unwrap(), shim.to_str().unwrap(), &[]) {
        Ok(p) => {
            let pid = p.pid;
            let _ = p.resume();
            c.check(true, format!("hw probe injected (PID {})", pid));

            let mut po = String::new();
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(500));
                po = read_text(&probe_out);
                if po.contains("probe.done") {
                    break;
                }
            }
            c.check(po.contains("probe.done"), "injected probe completed");
            if po.contains("probe.done") {
                check_hw_profile(&mut c, &po, &gt, &profile);
            }
        }
        Err(e) => c.check(false, format!("probe injection failed: {}", e)),
    }

    kill_proc("hw_probe");
    drop(child);
    let _ = kill_proc("ghost_sandbox");
    c
}

/// Compare the injected probe's report against the published profile, and
/// against the un-injected ground truth to prove host values were replaced.
fn check_hw_profile(
    c: &mut Check,
    po: &str,
    gt: &str,
    p: &ghost_sandbox::profile::HardwareProfile,
) {
    let mac = p
        .network
        .adapters
        .first()
        .map(|a| a.mac.clone())
        .unwrap_or_default();
    let drive = p.storage.drives.first();
    let drive_model = drive.map(|d| d.model.clone()).unwrap_or_default();
    let drive_serial = drive.map(|d| d.serial.clone()).unwrap_or_default();
    let dimms = p.memory.dimm_count.max(1);
    let total_kb = p.memory.total_gb as u64 * 1024 * 1024;
    let vol_serial = p.identity.volume_serial.replace('-', "").to_uppercase();

    let mut expect: Vec<String> = vec![
        format!("reg.cpu.name={}", p.cpu.brand_string),
        format!("reg.cpu.vendor={}", p.cpu.manufacturer),
        format!(
            "reg.cpu.identifier=Intel64 Family {} Model {} Stepping {}",
            p.cpu.family, p.cpu.model, p.cpu.stepping
        ),
        format!("reg.cpu.mhz={}", p.cpu.base_clock_mhz),
        format!("reg.bios.system_manufacturer={}", p.motherboard.manufacturer),
        format!("reg.bios.system_product={}", p.motherboard.product),
        format!("reg.bios.baseboard_product={}", p.motherboard.product),
        format!("reg.bios.vendor={}", p.motherboard.bios_vendor),
        format!("reg.bios.version={}", p.motherboard.bios_version),
        format!("reg.bios.date={}", p.motherboard.bios_date),
        format!("reg.sysinfo.manufacturer={}", p.motherboard.manufacturer),
        format!("reg.sysinfo.product={}", p.motherboard.product),
        format!("reg.machine_guid={}", p.identity.machine_guid),
        format!("reg.hostname={}", p.identity.computer_name),
        format!("reg.product_id={}", p.identity.windows_product_id),
        format!("reg.registered_owner={}", p.identity.user_name),
        format!("cpuid.vendor={}", p.cpu.manufacturer),
        format!("cpuid.brand={}", p.cpu.brand_string),
        "cpuid.hypervisor_bit=0".to_string(),
        format!(
            "cpuid.leaf16.base_mhz={} max_mhz={}",
            p.cpu.base_clock_mhz, p.cpu.max_clock_mhz
        ),
        format!("sysinfo.native.cores={}", p.cpu.cores_logical),
        format!("sysinfo.cores={}", p.cpu.cores_logical),
        format!("glpi.cores={}", p.cpu.cores_physical),
        format!("glpi.l1kb={}", p.cpu.l1_cache_kb),
        format!("glpi.l2kb={}", p.cpu.l2_cache_kb),
        format!("glpi.l3kb={}", p.cpu.l3_cache_kb),
        format!("glpie.cores={}", p.cpu.cores_physical),
        "glpie.packages=1".to_string(),
        "glpie.groups=1".to_string(),
        format!("glpie.group_procs={}", p.cpu.cores_logical),
        format!("glpie.l3kb={}", p.cpu.l3_cache_kb),
        format!("mem.phys_kb={}", total_kb),
        format!("mem.total_gb={}", p.memory.total_gb),
        format!("ntqsi.pages={} num_procs={}", total_kb / 4, p.cpu.cores_logical),
        format!(
            "power.cpu0.max_mhz={} current_mhz={}",
            p.cpu.max_clock_mhz, p.cpu.base_clock_mhz
        ),
        format!("smbios.bios.vendor={}", p.motherboard.bios_vendor),
        format!("smbios.bios.version={}", p.motherboard.bios_version),
        format!("smbios.bios.date={}", p.motherboard.bios_date),
        format!("smbios.sys.manufacturer={}", p.motherboard.manufacturer),
        format!("smbios.sys.product={}", p.motherboard.product),
        format!("smbios.sys.serial={}", p.motherboard.serial),
        format!("smbios.board.product={}", p.motherboard.product),
        format!("smbios.cpu.socket={}", p.cpu.socket),
        format!("smbios.cpu.brand={}", p.cpu.brand_string),
        format!(
            "smbios.cpu.cores={} threads={} max_mhz={}",
            p.cpu.cores_physical, p.cpu.cores_logical, p.cpu.max_clock_mhz
        ),
        format!("smbios.mem.array_max_kb={}", total_kb),
        format!("smbios.mem.devices={}", dimms),
        format!(
            "smbios.mem0.speed={} type=0x22 part={}",
            p.memory.speed_mhz, p.memory.part_number
        ),
    ];
    if !mac.is_empty() && gt.contains("nic0.mac=") {
        expect.push(format!("nic0.mac={}", mac));
        expect.push(format!("nicinfo0.mac={}", mac));
    }
    if !vol_serial.is_empty() && gt.contains("volume.c_serial=") {
        expect.push(format!("volume.c_serial={}", vol_serial));
    }
    // WMI identity is only checked when the host exposes WMI at all.
    if gt.contains("wmi.cpu.name=") {
        expect.push(format!(
            "wmi.cpu.name={} socket={} vendor={} cores={} lcores={} maxmhz={}",
            p.cpu.brand_string,
            p.cpu.socket,
            p.cpu.manufacturer,
            p.cpu.cores_physical,
            p.cpu.cores_logical,
            p.cpu.max_clock_mhz
        ));
        expect.push(format!(
            "wmi.ram0.speed={} capacity_gb={} type=34 part={} man={}",
            p.memory.speed_mhz,
            p.memory.total_gb / dimms,
            p.memory.part_number,
            p.memory.manufacturer
        ));
        expect.push(format!(
            "wmi.board.product={} man={}",
            p.motherboard.product, p.motherboard.manufacturer
        ));
        expect.push(format!(
            "wmi.system.model={} man={} name={} total_gb={}",
            p.motherboard.product,
            p.motherboard.manufacturer,
            p.identity.computer_name,
            p.memory.total_gb
        ));
        expect.push(format!(
            "wmi.disk0.model={} serial={}",
            drive_model, drive_serial
        ));
        expect.push(format!(
            "wmi.bios.man={} version={}",
            p.motherboard.bios_vendor, p.motherboard.bios_version
        ));
    }

    let mut missing: Vec<&str> = Vec::new();
    for e in &expect {
        if !po.contains(&format!("[hw] {}", e)) {
            missing.push(e.as_str());
        }
    }
    c.check(
        missing.is_empty(),
        format!(
            "all {} profile values present in target APIs ({} missing)",
            expect.len(),
            missing.len()
        ),
    );
    for m in missing.iter().take(12) {
        c.info(format!("missing: {}", m));
    }

    // Differential: the host's hypervisor identity must not survive.
    let gt_hv = line_value(gt, "cpuid.hypervisor_vendor").unwrap_or("");
    if !gt_hv.is_empty() {
        c.check(
            line_value(po, "cpuid.hypervisor_vendor") == Some(""),
            format!("hypervisor vendor removed (host reported '{}')", gt_hv),
        );
    }
    if line_value(gt, "cpuid.hypervisor_bit") == Some("1") {
        c.check(
            line_value(po, "cpuid.hypervisor_bit") == Some("0"),
            "hypervisor CPUID bit hidden",
        );
    }

    // Differential: count identity keys whose value changed from the host.
    let mut changed = 0usize;
    for key in [
        "reg.cpu.name",
        "reg.bios.system_manufacturer",
        "reg.bios.system_product",
        "reg.bios.baseboard_product",
        "reg.bios.vendor",
        "reg.bios.version",
        "reg.bios.date",
        "reg.machine_guid",
        "reg.hostname",
        "reg.product_id",
        "cpuid.brand",
        "smbios.sys.manufacturer",
        "smbios.sys.product",
        "smbios.sys.serial",
        "smbios.board.product",
        "smbios.mem0.part",
        "nic0.mac",
        "volume.c_serial",
        "wmi.board.product",
        "wmi.system.model",
        "wmi.disk0.model",
        "wmi.disk0.serial",
    ] {
        if let (Some(g), Some(n)) = (line_value(gt, key), line_value(po, key)) {
            if !g.is_empty() && !g.starts_with('<') && !g.contains(' ') && g != n {
                changed += 1;
            }
        }
    }
    c.check(
        changed >= 5,
        format!("host values replaced across {} identity keys", changed),
    );
}

fn shot_to(path: &Path) -> Result<(), String> {
    let opts = Opts {
        values: [
            ("process".to_string(), "ghost_sandbox".to_string()),
            ("out".to_string(), path.display().to_string()),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    match cmd_shot(&opts) {
        code if code == ExitCode::SUCCESS => Ok(()),
        _ => Err(format!("shot failed for {}", path.display())),
    }
}

/// Sandbox suite: GUI sandbox view with autorun + memory view dump/registers.
fn e2e_sandbox() -> Check {
    let mut c = Check::new("e2e sandbox");
    let out = drmtest();
    let probe = out.join("drm_probe.exe");
    let policy = out.join("sandbox_demo.policy.toml");

    kill_harness_procs();
    let gui_out = out.join("sbx_gui_stdout.log");
    let gui_err = out.join("sbx_gui_stderr.log");
    let png = out.join("gui_sandbox_view.png");
    for f in [&gui_out, &gui_err, &png] {
        let _ = fs::remove_file(f);
    }
    let _ = fs::remove_file(out.join("drm_probe_out.txt"));
    std::thread::sleep(Duration::from_millis(500));

    let envs: Vec<(&str, &str)> = vec![
        ("GHOST_START_VIEW", "sandbox"),
        ("GHOST_SAMPLE", probe.to_str().unwrap()),
        ("GHOST_POLICY", policy.to_str().unwrap()),
        ("GHOST_AUTORUN", "1"),
    ];
    match launch_gui(&envs, &gui_out, &gui_err) {
        Ok(child) => {
            c.check(wait_for_pipe(Duration::from_secs(60)), "GUI control pipe is up");
            std::thread::sleep(Duration::from_secs(22));
            let shot = shot_to(&png);
            c.check(shot.is_ok(), "sandbox view screenshot written");
            std::thread::sleep(Duration::from_secs(2));

            let logs = format!("{}{}", read_text(&gui_out), read_text(&gui_err));
            let activity = logs
                .lines()
                .filter(|l| l.contains("policy") || l.contains("Sandbox") || l.contains("sandbox"))
                .count();
            c.check(activity >= 1, "GUI logged sandbox/policy activity");

            let shim_log = std::env::temp_dir().join("ghost_sandbox_shim.log");
            let sl = read_text(&shim_log);
            c.check(sl.contains("[policy]"), "shim applied the GUI policy");

            let po = read_text(&out.join("drm_probe_out.txt"));
            c.check(po.contains("DRM probe battery"), "probe ran under the sandbox view");

            let _ = kill_proc("ghost_sandbox");
            let _ = kill_proc("drm_probe");
            std::thread::sleep(Duration::from_secs(2));

            // ── memory view: dump + register snapshot ──
            let mem_out = out.join("mem_gui_stdout.log");
            let mem_err = out.join("mem_gui_stderr.log");
            let mem_png = out.join("gui_memory_view.png");
            for f in [&mem_out, &mem_err, &mem_png] {
                let _ = fs::remove_file(f);
            }
            let envs: Vec<(&str, &str)> = vec![
                ("GHOST_START_VIEW", "memory"),
                ("GHOST_SAMPLE", probe.to_str().unwrap()),
                ("GHOST_AUTORUN", "1"),
                ("GHOST_MEM_ADDR", "main+0:512"),
                ("GHOST_POLICY", ""),
            ];
            match launch_gui(&envs, &mem_out, &mem_err) {
                Ok(_child2) => {
                    std::thread::sleep(Duration::from_secs(20));
                    let shot = shot_to(&mem_png);
                    c.check(shot.is_ok(), "memory view screenshot written");
                    let ml = format!("{}{}", read_text(&mem_out), read_text(&mem_err));
                    c.check(ml.contains("Shim connected"), "memory run: target injected");
                    c.check(ml.contains("Memory dump: 0x"), "memory run: dump received by the editor");
                    c.check(ml.contains("Register snapshot received"), "memory run: registers captured");
                }
                Err(e) => c.check(false, format!("memory GUI launch failed: {}", e)),
            }
            let _ = kill_proc("ghost_sandbox");
            let _ = kill_proc("drm_probe");
            drop(child);
        }
        Err(e) => c.check(false, format!("GUI launch failed: {}", e)),
    }
    c
}

/// Malware suite (the core one): CLI malware run of the benign simulator.
/// Asserts the behaviour log, the sample's own view, and — most importantly —
/// that the host is untouched.
fn e2e_malware() -> Check {
    let mut c = Check::new("e2e malware");
    let out = drmtest();
    let sim = out.join("malware_sim.exe");
    let ghost = root().join("target").join("debug").join("ghost.exe");
    c.check(sim.is_file(), "malware_sim.exe built (ghost_lab build sim)");
    c.check(ghost.is_file(), "ghost.exe built (cargo build)");
    if !sim.is_file() || !ghost.is_file() {
        return c;
    }

    kill_harness_procs();

    // Host artefacts the simulator targets — everything must be absent after.
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let docs = PathBuf::from(&home).join("Documents");
    let drop = docs.join("ghost_sim_drop.txt");
    let moved = docs.join("ghost_sim_moved.txt");
    let tmp = std::env::temp_dir().join("ghost_sim_tmp.txt");
    let exec_marker = out.join("ghost_sim_exec.txt");
    let downloaded = out.join("ghost_sim_downloaded.exe");
    let sim_log = out.join("malware_sim_out.txt");
    let shadow = out.join("shadow_mw");
    let report = out.join("mw_run.json");
    let stream = out.join("mw_stream.jsonl");
    let errlog = out.join("mw_run_err.log");

    for f in [&drop, &moved, &tmp, &exec_marker, &downloaded, &sim_log, &report, &stream, &errlog] {
        let _ = fs::remove_file(f);
    }
    let _ = fs::remove_dir_all(&shadow);
    reg_delete_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "GhostSimDemo",
    );
    reg_delete_value(r"HKCU\Software\GhostSim", "Telemetry");
    std::thread::sleep(Duration::from_millis(300));

    // ── disclaimer gate ──
    // With a fresh per-user record, `--malware` must refuse to start until
    // `--accept-disclaimer` is passed; the flag then records the agreement
    // (the same record the GUI dialog writes) and the run proceeds.
    let fresh_appdata = out.join("mw_fresh_appdata");
    let ack_path = fresh_appdata
        .join("ghost_sandbox")
        .join("malware_disclaimer_ack.txt");
    let _ = fs::remove_dir_all(&fresh_appdata);
    let _ = fs::create_dir_all(&fresh_appdata);
    let gate_err = out.join("mw_gate_err.log");
    let _ = fs::remove_file(&gate_err);
    let gate_code = Command::new(&ghost)
        .current_dir(&out)
        .args(["run", sim.to_str().unwrap(), "--malware", "--duration", "1", "--quiet"])
        .env("APPDATA", &fresh_appdata)
        .env_remove("GHOST_SKIP_DISCLAIMER")
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(&gate_err).unwrap()))
        .status()
        .ok()
        .and_then(|s| s.code());
    c.check(
        gate_code == Some(5),
        format!("malware gate refuses without --accept-disclaimer (exit {:?})", gate_code),
    );
    let gate_text = read_text(&gate_err);
    c.check(
        gate_text.contains("Before you continue") && gate_text.contains("--accept-disclaimer"),
        "gate notice shows the terms and the flag to pass",
    );
    c.check(
        !ack_path.is_file(),
        "refusal does not record acceptance",
    );

    // A corrupted or outdated record must ask again (exact-line version
    // match), never silently count as acceptance.
    let _ = fs::create_dir_all(ack_path.parent().unwrap());
    let _ = fs::write(&ack_path, "this is not a valid acknowledgement\n");
    let corrupt_code = Command::new(&ghost)
        .current_dir(&out)
        .args(["run", sim.to_str().unwrap(), "--malware", "--duration", "1", "--quiet"])
        .env("APPDATA", &fresh_appdata)
        .env_remove("GHOST_SKIP_DISCLAIMER")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code());
    c.check(
        corrupt_code == Some(5),
        format!("corrupted record asks again (exit {:?})", corrupt_code),
    );
    let _ = fs::write(&ack_path, "ack_version=1\nacknowledged=2000-01-01 00:00:00\n");
    let oldver_code = Command::new(&ghost)
        .current_dir(&out)
        .args(["run", sim.to_str().unwrap(), "--malware", "--duration", "1", "--quiet"])
        .env("APPDATA", &fresh_appdata)
        .env_remove("GHOST_SKIP_DISCLAIMER")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code());
    c.check(
        oldver_code == Some(5),
        format!("old-version record asks again (exit {:?})", oldver_code),
    );
    let _ = fs::remove_file(&ack_path);

    // A record that cannot be written must refuse the run instead of
    // silently counting as acceptance: block the record directory with a file.
    let bad_appdata = out.join("mw_bad_appdata");
    let _ = fs::remove_dir_all(&bad_appdata);
    let _ = fs::create_dir_all(&bad_appdata);
    let _ = fs::write(bad_appdata.join("ghost_sandbox"), "not a directory");
    let bad_err = out.join("mw_badrecord_err.log");
    let _ = fs::remove_file(&bad_err);
    let bad_code = Command::new(&ghost)
        .current_dir(&out)
        .args([
            "run",
            sim.to_str().unwrap(),
            "--malware",
            "--accept-disclaimer",
            "--duration",
            "1",
            "--quiet",
        ])
        .env("APPDATA", &bad_appdata)
        .env_remove("GHOST_SKIP_DISCLAIMER")
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(&bad_err).unwrap()))
        .status()
        .ok()
        .and_then(|s| s.code());
    c.check(
        bad_code == Some(5),
        format!("unwritable record refuses the run (exit {:?})", bad_code),
    );
    c.check(
        read_text(&bad_err).contains("does not count as acceptance"),
        "unwritable record says it does not count as acceptance",
    );

    let gate_shadow = out.join("shadow_gate");
    let _ = fs::remove_dir_all(&gate_shadow);
    let gate_ok_err = out.join("mw_gate_ok_err.log");
    let _ = fs::remove_file(&gate_ok_err);
    let accept_code = Command::new(&ghost)
        .current_dir(&out)
        .args([
            "run",
            sim.to_str().unwrap(),
            "--malware",
            "--accept-disclaimer",
            "--duration",
            "1",
            "--mw-timeout",
            "500",
            "--no-approval",
            "--kill-on-exit",
            "--quiet",
            "--shadow-dir",
            gate_shadow.to_str().unwrap(),
        ])
        .env("APPDATA", &fresh_appdata)
        .env_remove("GHOST_SKIP_DISCLAIMER")
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(&gate_ok_err).unwrap()))
        .status()
        .ok()
        .and_then(|s| s.code());
    c.check(
        accept_code == Some(0),
        format!("--accept-disclaimer records the terms and runs (exit {:?})", accept_code),
    );
    c.check(
        ack_path.is_file(),
        "acceptance recorded for the user",
    );
    let ack_text = read_text(&ack_path);
    c.check(
        ack_text.contains("ack_version=") && ack_text.contains("acknowledged="),
        "record persists version + timestamp",
    );

    // The main run reuses the per-user record written by the gate test, which
    // proves "asked once" and keeps the developer's own ack file untouched.
    let status = Command::new(&ghost)
        .current_dir(&out)
        .env("APPDATA", &fresh_appdata)
        .args([
            "run",
            sim.to_str().unwrap(),
            "--malware",
            "--accept-disclaimer",
            "--duration",
            "24",
            "--mw-timeout",
            "1200",
            "--format",
            "json",
            "--out",
            report.to_str().unwrap(),
            "--stream",
            "--quiet",
            "--shadow-dir",
            shadow.to_str().unwrap(),
        ])
        .stdout(Stdio::from(File::create(&stream).unwrap()))
        .stderr(Stdio::from(File::create(&errlog).unwrap()))
        .status();
    let code = match &status {
        Ok(s) => s.code(),
        Err(_) => None,
    };
    c.check(code == Some(0), format!("ghost run --malware exit 0 ({:?})", code));
    if code != Some(0) {
        c.info(format!("stderr: {}", read_text(&errlog).lines().take(12).collect::<Vec<_>>().join(" | ")));
    }

    // ── behaviour log ──
    let rep: serde_json::Value = serde_json::from_str(&read_text(&report)).unwrap_or_default();
    let ops = rep["malware_ops"].as_array().cloned().unwrap_or_default();
    c.info(format!("kind={} ops={}", rep["kind"].as_str().unwrap_or(""), ops.len()));
    c.check(rep["kind"].as_str() == Some("malware-run"), "report kind is malware-run");
    c.check(rep["license"].as_str() == Some("AGPL-3.0"), "report carries the licence id");
    c.check(
        rep["notice"]
            .as_str()
            .map(|s| s.contains("best-effort"))
            .unwrap_or(false),
        "report carries the disclaimer notice",
    );
    c.check(ops.len() >= 8, format!("behaviour log has operations ({})", ops.len()));

    let cats: BTreeSet<String> = ops
        .iter()
        .filter_map(|o| o["category"].as_str().map(|s| s.to_string()))
        .collect();
    for want in ["File", "Registry", "Process", "Network", "DNS"] {
        c.check(cats.contains(want), format!("category {} observed", want));
    }
    let verdicts: Vec<String> = ops
        .iter()
        .map(|o| o["verdict"].as_str().unwrap_or("").to_string())
        .collect();
    c.check(verdicts.iter().any(|v| v == "Shadowed"), "some writes were shadowed");
    c.check(
        verdicts.iter().any(|v| v == "Fake success"),
        "some operations answered with fake success",
    );
    c.check(verdicts.iter().any(|v| v == "Blocked"), "some operations were blocked");
    c.check(
        verdicts.iter().all(|v| v != "Allowed"),
        "nothing was allowed (default deny, no --approve-* flags)",
    );
    c.check(ops.iter().all(|o| o["pending"].as_bool() == Some(false)), "no operation left pending");
    let counts = &rep["counts"];
    c.info(format!(
        "counters: shadowed={} faked={} blocked={} allowed={}",
        counts["malware_shadowed"], counts["malware_faked"], counts["malware_blocked"], counts["malware_allowed"]
    ));

    // ── shadow store ──
    c.check(
        rep["shadow_dir"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "report names the shadow store",
    );
    let captured = find_file_named(&shadow, "ghost_sim_drop.txt");
    c.check(captured.is_some(), "shadow store captured ghost_sim_drop.txt");
    if let Some(p) = &captured {
        let content = read_text(p);
        c.check(
            content.contains("GHOST_SIM_DROP_CONTENT_V1"),
            "shadow copy carries the sample's payload",
        );
        c.info(format!("shadow file: {} ({} bytes)", p.display(), content.len()));
    }

    // ── host unchanged (the whole point) ──
    c.check(!drop.exists(), "host Documents\\ghost_sim_drop.txt never created");
    c.check(!moved.exists(), "host Documents\\ghost_sim_moved.txt never created");
    c.check(!tmp.exists(), "temp staging file removed by the guard's view of the sample");
    c.check(!exec_marker.exists(), "no real child process ran (exec marker absent)");
    c.check(!downloaded.exists(), "download produced no file on the host");
    c.check(
        !reg_value_exists(r"HKCU\Software\GhostSim", "Telemetry"),
        "no registry key/value on the host",
    );
    c.check(
        !reg_value_exists(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "GhostSimDemo",
        ),
        "no Run-key persistence value on the host",
    );

    // ── what the sample believed ──
    // The simulator writes its ground-truth log next to its own exe, so the
    // guard shadows that as well: read it back from the shadow store.
    let slog_path = find_file_named(&shadow, "malware_sim_out.txt").unwrap_or_else(|| sim_log.clone());
    let slog = read_text(&slog_path);
    c.check(!slog.is_empty(), "simulator ground-truth log written");
    c.check(
        slog.contains("SIM: end"),
        "simulator ran to completion under the guard",
    );
    c.check(
        !sim_log.exists(),
        "sample's own log never landed on the host",
    );
    c.check(
        slog.contains("file write ghost_sim_drop.txt -> ok"),
        "sample believed the file write succeeded",
    );
    c.check(
        slog.contains("file read-back ghost_sim_drop.txt -> ") && slog.contains("GHOST_SIM_DROP_CONTENT_V1"),
        "sample read its own dropped payload back (shadow read-back)",
    );
    c.check(
        slog.contains("registry read-back Telemetry -> ok: SIM_TELEMETRY_V1"),
        "registry read-back served from the shim's fake store",
    );
    c.check(
        slog.contains("network connect 127.0.0.1:59999 -> 0"),
        "sample saw connect() succeed (fake success)",
    );
    let dns_ok = slog
        .lines()
        .find(|l| l.contains("network DNS example-c2.test -> "))
        .and_then(|l| l.split("-> ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<i32>().ok())
        .map(|n| n != 0)
        .unwrap_or(false);
    c.check(dns_ok, "DNS lookup failed like an offline host");
    c.check(
        slog.contains("process start cmd.exe -> ok"),
        "child process start reported success (decoy)",
    );
    c.check(
        slog.contains("network download payload.exe -> hr=0x00000000 file_exists=0"),
        "download returned S_OK without producing a file",
    );
    c.check(
        slog.contains("registry persistence Run\\GhostSimDemo -> ok"),
        "persistence write reported success to the sample",
    );

    // ── stream ──
    let st = read_text(&stream);
    c.check(st.contains("\"type\":\"malware_op\""), "JSONL stream carries malware_op events");
    c.check(st.contains("\"malware\":true"), "run_start announces malware mode");
    let foreign = st
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('{'))
        .count();
    c.check(foreign == 0, format!("stream is pure JSONL ({} foreign line(s))", foreign));

    // ── shim log ──
    let shim_log = std::env::temp_dir().join("ghost_sandbox_shim.log");
    c.check(
        log_has(&shim_log, "ANALYSIS MODE ACTIVE"),
        "shim announced analysis mode",
    );

    c
}

/// GUI malware view: autorun the simulator with a short approval timeout so
/// the queue is visible in the screenshot before ops time out to deny.
fn e2e_malware_gui() -> Check {
    let mut c = Check::new("e2e malware-gui");
    let out = drmtest();
    let sim = out.join("malware_sim.exe");
    let shadow = out.join("shadow_mw_gui");
    let gui_out = out.join("mw_gui_stdout.log");
    let gui_err = out.join("mw_gui_stderr.log");
    let png = out.join("gui_malware_view.png");
    c.check(sim.is_file(), "malware_sim.exe built");
    if !sim.is_file() {
        return c;
    }

    kill_harness_procs();
    for f in [&gui_out, &gui_err, &png, &out.join("malware_sim_out.txt")] {
        let _ = fs::remove_file(f);
    }
    let _ = fs::remove_dir_all(&shadow);
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let _ = fs::remove_file(PathBuf::from(&home).join("Documents").join("ghost_sim_drop.txt"));
    reg_delete_value(r"HKCU\Software\GhostSim", "Telemetry");
    std::thread::sleep(Duration::from_millis(400));

    let shadow_s = shadow.display().to_string();
    let envs: Vec<(&str, &str)> = vec![
        ("GHOST_START_VIEW", "malware"),
        ("GHOST_SAMPLE", sim.to_str().unwrap()),
        ("GHOST_AUTORUN", "1"),
        ("GHOST_MW_SHADOW", &shadow_s),
        // Deny by timeout quickly so the screenshot lands mid-run.
        ("GHOST_MW_TIMEOUT", "1500"),
        ("GHOST_MW_FLAGS", "0"),
    ];
    match launch_gui(&envs, &gui_out, &gui_err) {
        Ok(child) => {
            c.check(wait_for_pipe(Duration::from_secs(60)), "GUI control pipe is up");
            std::thread::sleep(Duration::from_secs(9));
            let shot = shot_to(&png);
            c.check(shot.is_ok(), "malware view screenshot written");
            std::thread::sleep(Duration::from_secs(8));

            let logs = format!("{}{}", read_text(&gui_out), read_text(&gui_err));
            c.check(logs.contains("Malware events flowing"), "GUI logged malware events");
            c.check(
                logs.contains("caller malware_sim.exe"),
                "GUI reported mediated operations with caller attribution",
            );
            c.check(read_text(&gui_err).trim().is_empty(), "GUI stderr clean (no panic)");

            // Approvals time out to deny, so the host stays clean here too.
            c.check(
                !PathBuf::from(&home).join("Documents").join("ghost_sim_drop.txt").exists(),
                "host untouched by the GUI-mediated run",
            );

            let _ = kill_proc("malware_sim");
            let _ = kill_proc("ghost_sandbox");
            drop(child);
        }
        Err(e) => c.check(false, format!("GUI launch failed: {}", e)),
    }

    // ── containment `none`: autorun must stop at the confirmation dialog ──
    let none_out = out.join("mw_gui_none_stdout.log");
    let none_err = out.join("mw_gui_none_stderr.log");
    let none_png = out.join("gui_malware_unconfined_confirm.png");
    for f in [&none_out, &none_err, &none_png] {
        let _ = fs::remove_file(f);
    }
    std::thread::sleep(Duration::from_millis(800));
    let envs: Vec<(&str, &str)> = vec![
        ("GHOST_START_VIEW", "malware"),
        ("GHOST_SAMPLE", sim.to_str().unwrap()),
        ("GHOST_AUTORUN", "1"),
        ("GHOST_MW_LEVEL", "none"),
    ];
    match launch_gui(&envs, &none_out, &none_err) {
        Ok(child) => {
            c.check(
                wait_for_pipe(Duration::from_secs(60)),
                "unconfined GUI control pipe is up",
            );
            std::thread::sleep(Duration::from_secs(6));
            let shot = shot_to(&none_png);
            c.check(shot.is_ok(), "unconfined confirmation screenshot written");
            let logs = format!("{}{}", read_text(&none_out), read_text(&none_err));
            c.check(
                logs.contains("unconfined launch requires explicit confirmation"),
                "containment none stops at the confirmation dialog",
            );
            c.check(
                !logs.contains("running UNCONFINED"),
                "autorun did not bypass the unconfined confirmation",
            );
            c.check(
                read_text(&none_err).trim().is_empty(),
                "unconfined GUI stderr clean (no panic)",
            );
            let _ = kill_proc("ghost_sandbox");
            drop(child);
        }
        Err(e) => c.check(false, format!("unconfined GUI launch failed: {}", e)),
    }
    c
}

// ─── entry point ────────────────────────────────────────────

fn print_help() {
    println!(
        r#"ghost_lab — Ghost Sandbox build & test harness (one binary, no scripts)

USAGE
  ghost_lab build [all|shim|selftest|host|probe|sim]
      MSVC builds via vcvars64. `shim` also deploys the DLL next to the exes.

  ghost_lab deploy
      Copy target\shimtest\sandbox_shim_new.dll over sandbox_shim.dll (root,
      target\debug, target\release).

  ghost_lab selftest
      Run hook_selftest.exe and print the pass/fail summary.

  ghost_lab shot --process NAME [--out FILE] [--timeout MS]
      Screenshot a window (PrintWindow + blank detection + screen fallback).

  ghost_lab inject --target "cmdline" --shim DLL [--pid-file FILE] [--wait MS]
      Suspended-start injection (LoadLibraryA remote thread), then resume.
      --env KEY=VALUE (repeatable) and --containment guest|untrusted|none
      configure the malware channel / confined token.

  ghost_lab frames --file DUMP.bin
      Parse a raw sink dump into protocol frames and flag desyncs.

  ghost_lab pipe-sink [--pipe NAME] [--out FILE] [--seconds N]
      Raw byte dump of everything a shim sends (protocol debugging).

  ghost_lab fake-shim [--pipe NAME]
      Connect as a synthetic shim and stream protocol frames at the GUI.

  ghost_lab fake-controller [--pipe NAME] [--seconds N] [--profile-mmf NAME]
      Play the controller: pipe server + profile mapping, send
      TRACE_PAUSE / TRACE_RESUME / PROFILE_RELOAD on a schedule.

  ghost_lab e2e [all|cli|drm|sandbox|malware|malware-gui]
      End-to-end suites. Artefacts land in target\drmtest and target\shimtest.

  ghost_lab help
"#
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return ExitCode::from(2);
    }
    let cmd = args[0].clone();
    let opts = Opts::parse(&args[1..]);

    match cmd.as_str() {
        "build" => cmd_build(&opts),
        "deploy" => cmd_deploy(&opts),
        "selftest" => cmd_selftest(&opts),
        "shot" => cmd_shot(&opts),
        "inject" => cmd_inject(&opts),
        "frames" => cmd_frames(&opts),
        "pipe-sink" => cmd_pipe_sink(&opts),
        "fake-shim" => cmd_fake_shim(&opts),
        "fake-controller" => cmd_fake_controller(&opts),
        "e2e" => cmd_e2e(&opts),
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command '{}'\n", other);
            print_help();
            ExitCode::from(2)
        }
    }
}
