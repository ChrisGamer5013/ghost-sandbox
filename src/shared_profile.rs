/*
   Ghost Sandbox — Shared Memory Profile Publisher

   Serializes a HardwareProfile into the packed SharedProfile layout expected
   by the injected shim (shim/hw_spoofer.h, #pragma pack(1)) and publishes it
   to the "GhostSandboxProfile" file mapping that the shim reads at DllMain.
*/

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{
    CreateFileMappingW, FlushViewOfFile, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
};
use winapi::um::winnt::{HANDLE, PAGE_READWRITE};

use crate::profile::HardwareProfile;

/// Mapping name (GHOST_SANDBOX_SHMEM_NAME in trace_format.h).
const SHM_NAME: &str = "GhostSandboxProfile";
/// 'GSND' — magic checked by the shim.
const MAGIC: u32 = 0x444E_5347;
const SHM_VERSION: u32 = 1;
/// sizeof(SharedProfile) — packed, must match hw_spoofer.h exactly.
/// 1481 (v1) + 24 (cpu.socket) + 116 (memory detail) + 488 (storage) = 2109.
pub const SHM_SIZE: usize = 2109;

/// Serialize a profile into the packed shim layout.
fn pack(p: &HardwareProfile) -> Result<Vec<u8>, String> {
    let mut b: Vec<u8> = Vec::with_capacity(SHM_SIZE);

    // Header
    push_u32(&mut b, MAGIC);
    push_u32(&mut b, SHM_VERSION);

    // SharedIdentityProfile
    push_wide(&mut b, &p.identity.computer_name, 64);
    push_wide(&mut b, &p.identity.user_name, 64);
    push_fixed(&mut b, &p.identity.machine_guid, 64);
    push_fixed(&mut b, &p.identity.volume_serial, 16);
    push_fixed(&mut b, &p.identity.windows_product_id, 32);

    // SharedCpuProfile
    push_fixed(&mut b, &p.cpu.manufacturer, 64);
    push_fixed(&mut b, &p.cpu.brand_string, 128);
    for v in [
        p.cpu.family,
        p.cpu.model,
        p.cpu.stepping,
        p.cpu.cores_physical,
        p.cpu.cores_logical,
        p.cpu.base_clock_mhz,
        p.cpu.max_clock_mhz,
        p.cpu.l1_cache_kb,
        p.cpu.l2_cache_kb,
        p.cpu.l3_cache_kb,
    ] {
        push_u32(&mut b, v);
    }
    // SharedCpuFeatures — same order as struct SharedCpuFeatures
    for f in [        p.cpu.features.sse,
        p.cpu.features.sse2,
        p.cpu.features.sse3,
        p.cpu.features.ssse3,
        p.cpu.features.sse4_1,
        p.cpu.features.sse4_2,
        p.cpu.features.avx,
        p.cpu.features.avx2,
        p.cpu.features.avx512f,
        p.cpu.features.avx512bw,
        p.cpu.features.avx512vl,
        p.cpu.features.fma,
        p.cpu.features.aes_ni,
        p.cpu.features.popcnt,
        p.cpu.features.rdrand,
        p.cpu.features.rdseed,
        p.cpu.features.bmi1,
        p.cpu.features.bmi2,
        p.cpu.features.adx,
        p.cpu.features.sha,
        p.cpu.features.clmul,
        p.cpu.features.f16c,
        p.cpu.features.movbe,
        p.cpu.features.lzcnt,
        p.cpu.features.abm,
        p.cpu.features.tsx,
        p.cpu.features.sgx,
        p.cpu.features.vaes,
        p.cpu.features.vpclmulqdq,
        p.cpu.features.avx_vnni,
    ] {
        b.push(f as u8);
    }
    push_fixed(&mut b, &p.cpu.socket, 24);

    // SharedGpuProfile
    push_fixed(&mut b, &p.gpu.name, 128);
    push_fixed(&mut b, &p.gpu.vendor, 64);
    for v in [
        p.gpu.vendor_id,
        p.gpu.device_id,
        p.gpu.subsystem_id,
        p.gpu.revision,
    ] {
        push_u32(&mut b, v);
    }
    push_fixed(&mut b, &p.gpu.driver_version, 32);
    for v in [
        p.gpu.vram_mb,
        p.gpu.shared_memory_mb,
        p.gpu.pcie_gen,
        p.gpu.pcie_width,
    ] {
        push_u32(&mut b, v);
    }

    // SharedMotherboardProfile
    push_fixed(&mut b, &p.motherboard.manufacturer, 64);
    push_fixed(&mut b, &p.motherboard.product, 128);
    push_fixed(&mut b, &p.motherboard.serial, 64);
    push_fixed(&mut b, &p.motherboard.version, 32);
    push_fixed(&mut b, &p.motherboard.bios_vendor, 64);
    push_fixed(&mut b, &p.motherboard.bios_version, 32);
    push_fixed(&mut b, &p.motherboard.bios_date, 32);
    b.push(p.motherboard.secure_boot as u8);

    // SharedMemoryProfile
    push_u32(&mut b, p.memory.total_gb);
    push_u32(&mut b, p.memory.speed_mhz);
    push_fixed(&mut b, &p.memory.mem_type, 16);
    push_u32(&mut b, p.memory.dimm_count.max(1));
    push_fixed(&mut b, &p.memory.manufacturer, 32);
    push_fixed(&mut b, &p.memory.part_number, 64);

    // SharedNetworkAdapter (primary adapter)
    let (nname, nmac, nvid, ndid, nspeed, nip) = match p.network.adapters.first() {
        Some(a) => (
            a.name.clone(),
            a.mac.clone(),
            a.vendor_id,
            a.device_id,
            a.speed_mbps,
            a.ipv4.clone(),
        ),
        None => (String::new(), String::new(), 0, 0, 0, String::new()),
    };
    push_fixed(&mut b, &nname, 128);
    b.extend_from_slice(&parse_mac(&nmac));
    push_u32(&mut b, nvid);
    push_u32(&mut b, ndid);
    push_u32(&mut b, nspeed);
    push_fixed(&mut b, &nip, 16);

    // SharedStorageProfile — up to 2 drives
    for i in 0..2 {
        let d = p.storage.drives.get(i);
        push_fixed(
            &mut b,
            d.map(|d| d.model.as_str()).unwrap_or(""),
            128,
        );
        push_fixed(
            &mut b,
            d.map(|d| d.serial.as_str()).unwrap_or(""),
            64,
        );
        push_fixed(
            &mut b,
            d.map(|d| d.firmware.as_str()).unwrap_or(""),
            32,
        );
        push_u32(&mut b, d.map(|d| d.capacity_gb).unwrap_or(0));
        push_fixed(
            &mut b,
            d.map(|d| d.drive_type.as_str()).unwrap_or(""),
            16,
        );
    }

    if b.len() != SHM_SIZE {
        return Err(format!(
            "shared profile layout mismatch: packed {} bytes, expected {}",
            b.len(),
            SHM_SIZE
        ));
    }
    Ok(b)
}

/// Publish (or update) the profile in shared memory. `prev_handle` is the
/// handle returned by a previous call (0 if none). Returns the mapping handle,
/// which must be kept alive for the mapping to stay available.
pub fn publish(profile: &HardwareProfile, prev_handle: isize) -> Result<isize, String> {
    let bytes = pack(profile)?;

    let wide_name: Vec<u16> = SHM_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut h: HANDLE = prev_handle as HANDLE;
        if h.is_null() {
            h = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null_mut(),
                PAGE_READWRITE,
                0,
                SHM_SIZE as DWORD,
                wide_name.as_ptr(),
            );
            if h.is_null() {
                return Err(format!(
                    "CreateFileMapping failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        let view: LPVOID = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
        if view.is_null() {
            let err = std::io::Error::last_os_error();
            if prev_handle == 0 {
                CloseHandle(h);
            }
            return Err(format!("MapViewOfFile failed: {}", err));
        }

        std::ptr::copy_nonoverlapping(bytes.as_ptr(), view as *mut u8, SHM_SIZE);
        FlushViewOfFile(view, SHM_SIZE);
        UnmapViewOfFile(view);

        Ok(h as isize)
    }
}

// ─── Packing helpers ────────────────────────────────────────

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// Push a NUL-padded fixed-size char array (truncating if necessary).
fn push_fixed(b: &mut Vec<u8>, s: &str, len: usize) {
    let mut tmp = s.as_bytes().to_vec();
    tmp.truncate(len.saturating_sub(1));
    tmp.resize(len, 0);
    b.extend_from_slice(&tmp);
}

/// Push a NUL-padded fixed-size UTF-16LE array (truncating if necessary).
fn push_wide(b: &mut Vec<u8>, s: &str, wchars: usize) {
    let mut tmp: Vec<u16> = s.encode_utf16().take(wchars.saturating_sub(1)).collect();
    tmp.resize(wchars, 0);
    for u in tmp {
        b.extend_from_slice(&u.to_le_bytes());
    }
}

/// Parse "AA:BB:CC:DD:EE:FF" (or dash-separated) into 6 bytes.
fn parse_mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() == 6 {
        for (i, p) in parts.iter().enumerate() {
            out[i] = u8::from_str_radix(p.trim(), 16).unwrap_or(0);
        }
    }
    out
}
