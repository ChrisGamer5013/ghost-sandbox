/*
   Ghost Sandbox — Shared Memory Policy Publisher

   Writes the sandbox policy into the "GhostSandboxPolicy" file mapping
   (SharedPolicy in shim/trace_format.h, #pragma pack(1)) so the shim can
   apply it in DllMain — before the target's entry point ever runs.
   Call before injecting; the mapping handle must be kept alive while the
   target runs.
*/

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{
    CreateFileMappingW, FlushViewOfFile, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
};
use winapi::um::winnt::{HANDLE, PAGE_READWRITE};

use crate::policy::{WireEntry, MAX_ENTRIES, WIRE_ENTRY_SIZE};

const SHM_NAME: &str = "GhostSandboxPolicy";
/// 'GSPL' — magic checked by the shim.
const MAGIC: u32 = 0x4C50_5347;
const SHM_VERSION: u32 = 1;
/// sizeof(SharedPolicy): 4 u32 header + 64 packed entries.
pub const SHM_SIZE: usize = 16 + MAX_ENTRIES * WIRE_ENTRY_SIZE;

/// Serialize a policy into the packed shim layout.
pub fn pack(entries: &[WireEntry]) -> Result<Vec<u8>, String> {
    if entries.len() > MAX_ENTRIES {
        return Err(format!(
            "policy has {} entries (max {})",
            entries.len(),
            MAX_ENTRIES
        ));
    }

    let mut b: Vec<u8> = Vec::with_capacity(SHM_SIZE);
    b.extend_from_slice(&MAGIC.to_le_bytes());
    b.extend_from_slice(&SHM_VERSION.to_le_bytes());
    b.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for e in entries {
        e.encode(&mut b);
    }
    b.resize(SHM_SIZE, 0);

    debug_assert_eq!(b.len(), SHM_SIZE);
    Ok(b)
}

/// Publish (or replace) the policy. `prev_handle` is the handle from the
/// previous call (0 if none). Returns the mapping handle which must be kept
/// alive (it keeps the mapping name resolvable for the shim).
pub fn publish(entries: &[WireEntry], prev_handle: isize) -> Result<isize, String> {
    let bytes = pack(entries)?;
    let wide_name: Vec<u16> = SHM_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut h: HANDLE = prev_handle as HANDLE;
        if h.is_null() {
            if prev_handle != 0 {
                // Caller passed a bogus handle; start clean.
            }
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
                    "CreateFileMapping({}) failed: {}",
                    SHM_NAME,
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

/// Clear the published policy (empty rule set).
pub fn clear(prev_handle: isize) -> Result<isize, String> {
    publish(&[], prev_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{KIND_IMPORT, ACTION_BLOCK};

    #[test]
    fn packed_layout_matches_shim() {
        let e = WireEntry {
            kind: KIND_IMPORT,
            action: ACTION_BLOCK,
            block_value: 1,
            module: "k.dll".into(),
            function: "f".into(),
        };
        let b = pack(&[e]).unwrap();
        assert_eq!(b.len(), SHM_SIZE);
        assert_eq!(&b[0..4], &MAGIC.to_le_bytes());
        assert_eq!(&b[4..8], &1u32.to_le_bytes());
        assert_eq!(&b[8..12], &1u32.to_le_bytes()); // count
        assert_eq!(&b[16..20], &KIND_IMPORT.to_le_bytes());
    }
}
