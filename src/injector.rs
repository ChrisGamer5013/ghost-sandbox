/*
   Ghost Sandbox — Process Injector
   Creates target process in suspended state and injects sandbox_shim.dll.

   Malware analysis mode adds two launch-time capabilities:

     * Containment — the target can be started with a *restricted token*
       (admin SIDs and dangerous privileges stripped, "guest") and optionally
       at low integrity ("untrusted"). The token is derived from the
       controller's own primary token, so CreateProcessAsUserW works without
       SeAssignPrimaryToken/SeIncreaseQuota.
     * Extra environment — the malware guard in the shim is configured through
       GHOST_MW_* variables; those must survive even under the restricted
       token, so an explicit (unicode) environment block is built and passed
       to the child.

   Environment values and the shim configuration travel in the child's
   environment, which is the only channel that works for every containment
   level (a low-integrity target cannot map the policy shared memory).
*/

use std::ffi::CString;
use std::path::Path;
use std::ptr;

use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, TRUE};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::fileapi::CreateFileA;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{
    CreateProcessA, CreateProcessAsUserW, CreateProcessW, CreateRemoteThread, GetCurrentProcess,
    OpenProcessToken, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE, STARTF_USESTDHANDLES,
};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winnt::{
    DISABLE_MAX_PRIVILEGE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_READ, GENERIC_WRITE, HANDLE, LUA_TOKEN, LUID, LUID_AND_ATTRIBUTES, MEM_COMMIT,
    MEM_RESERVE, PAGE_READWRITE, PSID, SE_GROUP_INTEGRITY, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel, TokenPrivileges,
};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

/// CreateFile dispositions (winbase.h values; winapi keeps them in fileapi).
const CREATE_ALWAYS: DWORD = 2;
const OPEN_EXISTING: DWORD = 3;

/// How confined the target runs (malware analysis mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// No token changes (classic sandboxed run).
    None,
    /// Restricted/LUA copy of the current user's token with all privileges
    /// disabled ("guest"). Not the Windows *Guest* account and not a
    /// separate user SID. File writes land in the shadow store.
    Guest,
    /// Same restricted token plus Low integrity (S-1-16-4096 — not the
    /// *Untrusted* integrity level). File writes cannot reach the shadow
    /// tree from Low IL, so denied writes are answered through fake handles.
    Untrusted,
}

impl Default for Containment {
    fn default() -> Self {
        Containment::None
    }
}

impl Containment {
    pub fn label(self) -> &'static str {
        match self {
            Containment::None => "none",
            Containment::Guest => "guest",
            Containment::Untrusted => "untrusted",
        }
    }

    pub fn from_label(s: &str) -> Containment {
        match s.trim().to_ascii_lowercase().as_str() {
            "guest" => Containment::Guest,
            "untrusted" | "low" | "lowil" => Containment::Untrusted,
            _ => Containment::None,
        }
    }
}

/// Launch options for [`inject_ex`].
pub struct LaunchOptions<'a> {
    /// Redirect the child's stdout/stderr into this file (stdin → NUL).
    pub log_path: Option<&'a str>,
    /// Extra environment variables for the child (replacing existing ones).
    pub env: Vec<(String, String)>,
    /// Token containment level.
    pub containment: Containment,
}

impl Default for LaunchOptions<'_> {
    fn default() -> Self {
        Self {
            log_path: None,
            env: Vec::new(),
            containment: Containment::None,
        }
    }
}

/// Result of a successful injection
pub struct InjectedProcess {
    pub pid: u32,
    pub process_handle: winapi::um::winnt::HANDLE,
    pub thread_handle: winapi::um::winnt::HANDLE,
}

impl InjectedProcess {
    /// Resume the main thread of the target process
    pub fn resume(&self) -> Result<(), String> {
        unsafe {
            let result = ResumeThread(self.thread_handle);
            if result == u32::MAX {
                return Err(format!("ResumeThread failed: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Wait for the target process to exit
    pub fn wait(&self) -> Result<u32, String> {
        unsafe {
            WaitForSingleObject(self.process_handle, INFINITE);
            let mut exit_code: DWORD = 0;
            winapi::um::processthreadsapi::GetExitCodeProcess(self.process_handle, &mut exit_code);
            Ok(exit_code)
        }
    }
}

impl Drop for InjectedProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.thread_handle);
            CloseHandle(self.process_handle);
        }
    }
}

/// Open a file/device with an inheritable handle (for child std handles).
unsafe fn open_inheritable(path: &str, write: bool, create: bool) -> HANDLE {
    let c = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return INVALID_HANDLE_VALUE,
    };
    let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
    sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.bInheritHandle = TRUE;
    CreateFileA(
        c.as_ptr(),
        if write { GENERIC_WRITE } else { GENERIC_READ },
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &mut sa,
        if create { CREATE_ALWAYS } else { OPEN_EXISTING },
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    )
}

/// Create a process in suspended state and inject a DLL into it.
///
/// # Arguments
/// * `exe_path` - Path to the target executable
/// * `dll_path` - Path to sandbox_shim.dll
/// * `args` - Additional command-line arguments for the target
pub fn inject(exe_path: &str, dll_path: &str, args: &[String]) -> Result<InjectedProcess, String> {
    inject_ex(exe_path, dll_path, args, &LaunchOptions::default())
}

/// Like [`inject`], but optionally redirects the child's stdout/stderr into
/// `log_path` (and its stdin to NUL). Used by the CLI so that `--stream`
/// JSONL on stdout never mixes with the target's own console output; the
/// target's console text lands in `log_path` instead. The GUI keeps the
/// child attached to the shared console (`inject`).
pub fn inject_redirect(
    exe_path: &str,
    dll_path: &str,
    args: &[String],
    log_path: Option<&str>,
) -> Result<InjectedProcess, String> {
    inject_ex(
        exe_path,
        dll_path,
        args,
        &LaunchOptions {
            log_path,
            ..Default::default()
        },
    )
}

/// Full-control launch used by malware analysis mode (containment + env).
pub fn inject_ex(
    exe_path: &str,
    dll_path: &str,
    args: &[String],
    opts: &LaunchOptions,
) -> Result<InjectedProcess, String> {
    // Validate paths
    if !Path::new(exe_path).exists() {
        return Err(format!("Target executable not found: {}", exe_path));
    }
    if !Path::new(dll_path).exists() {
        return Err(format!("Shim DLL not found: {}", dll_path));
    }

    // Build command line
    let mut cmd = format!("\"{}\"", exe_path);
    for arg in args {
        if arg.contains(' ') {
            cmd.push_str(&format!(" \"{}\"", arg));
        } else {
            cmd.push_str(&format!(" {}", arg));
        }
    }

    let dll_cstr = CString::new(dll_path).map_err(|_| "Invalid DLL path".to_string())?;

    let confined = opts.containment != Containment::None || !opts.env.is_empty();

    unsafe {
        let pi = if !confined {
            // ── Classic path: ANSI command line, inherited environment ──
            let cmd_cstr = CString::new(cmd.clone()).map_err(|_| "Invalid command line".to_string())?;
            let mut si: STARTUPINFOA = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

            let (log_handle, nul_handle, inherit) = setup_std_handles_ansi(&mut si, opts.log_path);

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let success = CreateProcessA(
                ptr::null(),
                cmd_cstr.as_ptr() as *mut i8,
                ptr::null_mut(),
                ptr::null_mut(),
                inherit,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null(),
                &mut si,
                &mut pi,
            );

            close_std_handles(log_handle, nul_handle);

            if success == FALSE {
                return Err(format!(
                    "CreateProcess failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            pi
        } else {
            // ── Contained path: unicode cmd line + explicit env block ──
            let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
            let env_block = build_env_block(&opts.env);

            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let (log_handle, nul_handle, inherit) = setup_std_handles_wide(&mut si, opts.log_path);

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let creation_flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

            let success = if opts.containment != Containment::None {
                // Fail closed: a requested containment level is either applied
                // and verified, or the launch is refused. Never fall back to
                // the caller's full token.
                let token = match make_restricted_token(opts.containment == Containment::Untrusted) {
                    Ok(token) => token,
                    Err(e) => {
                        close_std_handles(log_handle, nul_handle);
                        return Err(format!(
                            "containment '{}' unavailable ({}); refusing to launch without it",
                            opts.containment.label(),
                            e
                        ));
                    }
                };
                let r = CreateProcessAsUserW(
                    token,
                    ptr::null(),
                    cmd_w.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    inherit,
                    creation_flags,
                    env_block.as_ptr() as LPVOID,
                    ptr::null(),
                    &mut si,
                    &mut pi,
                );
                CloseHandle(token);
                r
            } else {
                CreateProcessW(
                    ptr::null(),
                    cmd_w.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    inherit,
                    creation_flags,
                    env_block.as_ptr() as LPVOID,
                    ptr::null(),
                    &mut si,
                    &mut pi,
                )
            };

            close_std_handles(log_handle, nul_handle);

            if success == FALSE {
                return Err(format!(
                    "CreateProcess (contained, {}) failed: {}",
                    opts.containment.label(),
                    std::io::Error::last_os_error()
                ));
            }
            pi
        };

        tracing::info!(
            "Created suspended process PID={} (containment={})",
            pi.dwProcessId,
            opts.containment.label()
        );

        // Step 2: inject the shim, then hand the process back to the caller.
        match inject_dll(&pi, &dll_cstr) {
            Ok(()) => Ok(InjectedProcess {
                pid: pi.dwProcessId,
                process_handle: pi.hProcess,
                thread_handle: pi.hThread,
            }),
            Err(e) => {
                winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                Err(e)
            }
        }
    }
}

/// Wire up redirected std handles for a started process (ANSI variant).
unsafe fn setup_std_handles_ansi(si: &mut STARTUPINFOA, log_path: Option<&str>) -> (HANDLE, HANDLE, i32) {
    let mut log_handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut nul_handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut inherit = FALSE;
    if let Some(lp) = log_path {
        log_handle = open_inheritable(lp, true, true);
        nul_handle = open_inheritable("NUL", false, false);
        if log_handle != INVALID_HANDLE_VALUE {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdOutput = log_handle;
            si.hStdError = log_handle;
            si.hStdInput = if nul_handle != INVALID_HANDLE_VALUE {
                nul_handle
            } else {
                log_handle
            };
            inherit = TRUE;
        }
    }
    (log_handle, nul_handle, inherit)
}

/// Wide-API twin of [`setup_std_handles_ansi`].
unsafe fn setup_std_handles_wide(si: &mut STARTUPINFOW, log_path: Option<&str>) -> (HANDLE, HANDLE, i32) {
    let mut log_handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut nul_handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut inherit = FALSE;
    if let Some(lp) = log_path {
        log_handle = open_inheritable(lp, true, true);
        nul_handle = open_inheritable("NUL", false, false);
        if log_handle != INVALID_HANDLE_VALUE {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdOutput = log_handle;
            si.hStdError = log_handle;
            si.hStdInput = if nul_handle != INVALID_HANDLE_VALUE {
                nul_handle
            } else {
                log_handle
            };
            inherit = TRUE;
        }
    }
    (log_handle, nul_handle, inherit)
}

unsafe fn close_std_handles(log_handle: HANDLE, nul_handle: HANDLE) {
    if log_handle != INVALID_HANDLE_VALUE {
        CloseHandle(log_handle);
    }
    if nul_handle != INVALID_HANDLE_VALUE {
        CloseHandle(nul_handle);
    }
}

/// Allocate + write the DLL path, then run LoadLibraryA in a remote thread.
unsafe fn inject_dll(pi: &PROCESS_INFORMATION, dll_cstr: &CString) -> Result<(), String> {
    let dll_path_len = dll_cstr.as_bytes_with_nul().len();
    let remote_mem = VirtualAllocEx(
        pi.hProcess,
        ptr::null_mut(),
        dll_path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if remote_mem.is_null() {
        return Err(format!(
            "VirtualAllocEx failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        pi.hProcess,
        remote_mem,
        dll_cstr.as_ptr() as LPVOID,
        dll_path_len,
        &mut bytes_written,
    );
    tracing::info!("Wrote {} bytes of DLL path to target", bytes_written);

    let kernel32 = CString::new("kernel32.dll").unwrap();
    let load_lib_name = CString::new("LoadLibraryA").unwrap();
    let kernel32_handle = GetModuleHandleA(kernel32.as_ptr());
    let load_lib_addr = GetProcAddress(kernel32_handle, load_lib_name.as_ptr());
    if load_lib_addr.is_null() {
        return Err("Failed to get LoadLibraryA address".to_string());
    }

    let remote_thread = CreateRemoteThread(
        pi.hProcess,
        ptr::null_mut(),
        0,
        Some(std::mem::transmute(load_lib_addr)),
        remote_mem,
        0,
        ptr::null_mut(),
    );
    if remote_thread.is_null() {
        return Err(format!(
            "CreateRemoteThread failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Wait for the DLL to load (with timeout).
    WaitForSingleObject(remote_thread, 10000);
    CloseHandle(remote_thread);
    tracing::info!("sandbox_shim.dll injected successfully");
    Ok(())
}

// ─── Containment ────────────────────────────────────────────

/// Build a restricted version of our own primary token. When `low_integrity`
/// is set the token's integrity level is lowered to Low (S-1-16-4096).
unsafe fn make_restricted_token(low_integrity: bool) -> Result<HANDLE, String> {
    let mut self_token: HANDLE = ptr::null_mut();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
        &mut self_token,
    ) == 0
    {
        return Err(format!(
            "OpenProcessToken failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut restricted: HANDLE = ptr::null_mut();
    let ok = winapi::um::securitybaseapi::CreateRestrictedToken(
        self_token,
        DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
        0,
        ptr::null_mut(),
        0,
        ptr::null_mut(),
        0,
        ptr::null_mut(),
        &mut restricted,
    );
    let last_error = std::io::Error::last_os_error();
    CloseHandle(self_token);

    if ok == 0 {
        return Err(format!("CreateRestrictedToken failed: {}", last_error));
    }

    if low_integrity {
        let sid_str: Vec<u16> = "S-1-16-4096".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: PSID = ptr::null_mut();
        if winapi::shared::sddl::ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) == 0 {
            let e = std::io::Error::last_os_error();
            CloseHandle(restricted);
            return Err(format!("ConvertStringSidToSidW(Low IL) failed: {}", e));
        }
        let mut tml: TOKEN_MANDATORY_LABEL = std::mem::zeroed();
        tml.Label.Sid = sid;
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        let len = std::mem::size_of::<TOKEN_MANDATORY_LABEL>()
            + winapi::um::securitybaseapi::GetLengthSid(sid) as usize;
        let set = winapi::um::securitybaseapi::SetTokenInformation(
            restricted,
            TokenIntegrityLevel,
            &mut tml as *mut _ as LPVOID,
            len as u32,
        );
        let e = std::io::Error::last_os_error();
        winapi::um::winbase::LocalFree(sid as winapi::shared::minwindef::HLOCAL);
        if set == 0 {
            CloseHandle(restricted);
            return Err(format!(
                "SetTokenInformation(TokenIntegrityLevel) failed: {} - refusing to run labelled \
                 'untrusted' at the current integrity level",
                e
            ));
        }
    }

    // Verify the token we actually got before handing it to CreateProcessAsUser.
    if let Err(e) = verify_restricted_token(restricted, low_integrity) {
        CloseHandle(restricted);
        return Err(e);
    }

    Ok(restricted)
}

/// Count enabled privileges other than `SeChangeNotifyPrivilege`.
///
/// `DISABLE_MAX_PRIVILEGE` documents exactly that exception, so any other
/// enabled privilege means the containment token is not what we requested.
unsafe fn token_extra_enabled_privileges(token: HANDLE) -> Result<usize, String> {
    let mut len: DWORD = 0;
    GetTokenInformation(token, TokenPrivileges, ptr::null_mut(), 0, &mut len);
    if len == 0 {
        return Err(format!(
            "GetTokenInformation(TokenPrivileges, size) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // u64 words keep the variable-length privilege array aligned.
    let mut buf = vec![0u64; (len as usize + 7) / 8];
    if GetTokenInformation(
        token,
        TokenPrivileges,
        buf.as_mut_ptr() as LPVOID,
        len,
        &mut len,
    ) == 0
    {
        return Err(format!(
            "GetTokenInformation(TokenPrivileges) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let change_notify: Vec<u16> = "SeChangeNotifyPrivilege\0".encode_utf16().collect();
    let mut allowed: LUID = std::mem::zeroed();
    if winapi::um::winbase::LookupPrivilegeValueW(
        ptr::null(),
        change_notify.as_ptr(),
        &mut allowed,
    ) == 0
    {
        return Err(format!(
            "LookupPrivilegeValueW(SeChangeNotifyPrivilege) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let count = *(buf.as_ptr() as *const DWORD) as usize;
    let privileges = std::slice::from_raw_parts(
        (buf.as_ptr() as *const u8).add(std::mem::size_of::<DWORD>())
            as *const LUID_AND_ATTRIBUTES,
        count,
    );
    Ok(privileges
        .iter()
        .filter(|p| {
            p.Attributes & SE_PRIVILEGE_ENABLED != 0
                && (p.Luid.LowPart != allowed.LowPart || p.Luid.HighPart != allowed.HighPart)
        })
        .count())
}

/// Read the token's integrity-level SID as a string (e.g. `S-1-16-4096`).
unsafe fn token_integrity_sid(token: HANDLE) -> Result<String, String> {
    let mut len: DWORD = 0;
    GetTokenInformation(token, TokenIntegrityLevel, ptr::null_mut(), 0, &mut len);
    if len == 0 {
        return Err(format!(
            "GetTokenInformation(TokenIntegrityLevel, size) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // u64 words keep the TOKEN_MANDATORY_LABEL cast aligned.
    let mut buf = vec![0u64; (len as usize + 7) / 8];
    if GetTokenInformation(
        token,
        TokenIntegrityLevel,
        buf.as_mut_ptr() as LPVOID,
        len,
        &mut len,
    ) == 0
    {
        return Err(format!(
            "GetTokenInformation(TokenIntegrityLevel) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
    let mut sid_str: *mut u16 = ptr::null_mut();
    if winapi::shared::sddl::ConvertSidToStringSidW(tml.Label.Sid, &mut sid_str) == 0 {
        return Err(format!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut n = 0usize;
    while *sid_str.add(n) != 0 {
        n += 1;
    }
    let out = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, n));
    winapi::um::winbase::LocalFree(sid_str as winapi::shared::minwindef::HLOCAL);
    Ok(out)
}

/// Confirm the containment token has the properties its label claims.
unsafe fn verify_restricted_token(token: HANDLE, low_integrity: bool) -> Result<(), String> {
    let extra = token_extra_enabled_privileges(token)?;
    if extra != 0 {
        return Err(format!(
            "privilege verification failed: {} enabled privilege(s) beyond SeChangeNotifyPrivilege",
            extra
        ));
    }
    if low_integrity {
        let sid = token_integrity_sid(token)?;
        if sid != "S-1-16-4096" {
            return Err(format!(
                "low-integrity verification failed: token integrity is {}, expected S-1-16-4096",
                sid
            ));
        }
    }
    Ok(())
}

// ─── Environment block ──────────────────────────────────────

/// Length of a NUL-terminated wide string at `p`.
unsafe fn wstr_len(mut p: *const u16) -> usize {
    let mut n = 0usize;
    while *p != 0 {
        n += 1;
        p = p.add(1);
    }
    n
}

/// Build a sorted, double-NUL-terminated unicode environment block from the
/// current environment plus `extra` (which replaces existing entries).
pub unsafe fn build_env_block(extra: &[(String, String)]) -> Vec<u16> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let env_ptr = winapi::um::processenv::GetEnvironmentStringsW();
    if !env_ptr.is_null() {
        let mut p = env_ptr;
        loop {
            let len = wstr_len(p);
            if len == 0 {
                break;
            }
            let slice = std::slice::from_raw_parts(p, len);
            let s = String::from_utf16_lossy(slice);
            if let Some(eq) = s.find('=') {
                // Skip the hidden "=C:=C:\..." drive entries.
                if eq > 0 {
                    pairs.push((s[..eq].to_string(), s[eq + 1..].to_string()));
                }
            }
            p = p.add(len + 1);
        }
        winapi::um::processenv::FreeEnvironmentStringsW(env_ptr);
    }

    for (k, v) in extra {
        if let Some(slot) = pairs.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            slot.1 = v.clone();
        } else {
            pairs.push((k.clone(), v.clone()));
        }
    }

    // CreateProcess requires the block to be sorted (case-insensitive).
    pairs.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()));

    let mut block: Vec<u16> = Vec::new();
    for (k, v) in pairs {
        block.extend(format!("{}={}", k, v).encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}
