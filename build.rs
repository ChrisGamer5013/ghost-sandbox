/*
   Ghost Sandbox — Build Script

   The C++ shim (shim/sandbox_shim.cpp) is compiled manually with MSVC
   (see README.md). This script picks up the compiled sandbox_shim.dll from
   the project root (or shim/) and copies it next to the built executable so
   the injector can always find it at runtime, even after `cargo clean`.
*/

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=shim/");

    let candidates = [
        PathBuf::from("sandbox_shim.dll"),
        PathBuf::from("shim").join("sandbox_shim.dll"),
    ];

    // Deprecated target triple dirs? Not needed — plain copy into the profile dir.
    let Ok(out_dir) = std::env::var("OUT_DIR") else { return };
    let out_dir = PathBuf::from(out_dir);

    // OUT_DIR = target/<profile>/build/<crate>-<hash>/out
    // exe dir = target/<profile>
    let Some(profile_dir) = out_dir.ancestors().nth(3) else { return };

    let Some(src) = candidates.iter().find(|p| p.is_file()) else {
        println!(
            "cargo:warning=sandbox_shim.dll not found in project root or shim/ — \
             compile it with cl.exe and place it there, or injection will fail"
        );
        return;
    };

    println!("cargo:rerun-if-changed={}", src.display());
    copy_if_stale(src, &profile_dir.join("sandbox_shim.dll"));

    // ghost_host.exe (DLL host for the sandbox) travels with the shim: it is
    // built by target/shimtest/build_host.cmd and lives in target/shimtest/.
    let host_candidates = [
        PathBuf::from("ghost_host.exe"),
        PathBuf::from("target").join("shimtest").join("ghost_host.exe"),
    ];
    if let Some(host) = host_candidates.iter().find(|p| p.is_file()) {
        println!("cargo:rerun-if-changed={}", host.display());
        copy_if_stale(host, &profile_dir.join("ghost_host.exe"));
    }
}

/// Copy `src` to `dst` when missing or older (by mtime / size).
fn copy_if_stale(src: &Path, dst: &Path) {
    let stale = match (src.metadata(), dst.metadata()) {
        (Ok(s), Ok(d)) => s.len() != d.len() || s.modified().ok() > d.modified().ok(),
        _ => true,
    };
    if !stale {
        return;
    }
    if let Err(e) = std::fs::copy(src, dst) {
        // The destination may be locked if a ghost_sandbox.exe is running —
        // that is fine, it already has its copy.
        println!("cargo:warning=could not copy {}: {}", src.display(), e);
    }
}
