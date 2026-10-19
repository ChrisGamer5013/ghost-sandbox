/*
   Ghost Sandbox — Struct Decoder
   Automatic pretty-printing of Windows structures.
*/

/// Decode a CERT_CONTEXT structure from raw bytes
pub fn decode_cert_context(data: &[u8]) -> String {
    if data.len() < 32 {
        return format!("CERT_CONTEXT (too small: {} bytes)", data.len());
    }
    format!("CERT_CONTEXT {{ dwCertEncodingType: 0x{:X}, cbCertEncoded: {}, pCertInfo: 0x{:X} }}",
        u32::from_le_bytes(data[0..4].try_into().unwrap_or([0;4])),
        u32::from_le_bytes(data[4..8].try_into().unwrap_or([0;4])),
        u64::from_le_bytes(data[16..24].try_into().unwrap_or([0;8])),
    )
}

/// Decode a SYSTEM_INFO structure
pub fn decode_system_info(data: &[u8]) -> String {
    if data.len() < 48 {
        return format!("SYSTEM_INFO (too small: {} bytes)", data.len());
    }
    let arch = u16::from_le_bytes(data[0..2].try_into().unwrap_or([0;2]));
    let num_procs = u32::from_le_bytes(data[32..36].try_into().unwrap_or([0;4]));
    let arch_name = match arch {
        9 => "x86_64",
        5 => "ARM",
        12 => "ARM64",
        0 => "x86",
        _ => "Unknown",
    };
    format!("SYSTEM_INFO {{ arch: {} ({}), num_processors: {} }}", arch, arch_name, num_procs)
}

/// Decode a MEMORYSTATUSEX structure
pub fn decode_memory_status(data: &[u8]) -> String {
    if data.len() < 64 {
        return format!("MEMORYSTATUSEX (too small: {} bytes)", data.len());
    }
    let total_phys = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0;8]));
    let avail_phys = u64::from_le_bytes(data[16..24].try_into().unwrap_or([0;8]));
    format!("MEMORYSTATUSEX {{ total_phys: {} MB, avail_phys: {} MB }}",
        total_phys / (1024 * 1024),
        avail_phys / (1024 * 1024),
    )
}

/// Format a hex dump of raw bytes
pub fn hex_dump(data: &[u8], base_address: u64) -> String {
    let mut result = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_address + (i * 16) as u64;
        result.push_str(&format!("{:016X}  ", addr));
        
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02X} ", byte));
            if j == 7 { result.push(' '); }
        }
        
        // Pad if less than 16 bytes
        for _ in chunk.len()..16 {
            result.push_str("   ");
        }
        
        result.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7E {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }
        result.push_str("|\n");
    }
    result
}
