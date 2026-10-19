/*
   Ghost Sandbox — Static PE Inspector
   Parses a dropped EXE/DLL (headers, sections, entropy, imports, exports,
   delay imports, signature presence) with zero external dependencies.
   Powers the sandbox view's import/export tables and the CLI `inspect`
   and `policy template` commands.
*/

use serde::Serialize;

// ─── Data model ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PeSection {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f32,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeImportDll {
    pub name: String,
    pub functions: Vec<String>,
    pub delayed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeExport {
    pub name: String,
    pub ordinal: u32,
    pub rva: u64,
    pub forwarded: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub forwarder: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub path: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub machine: u16,
    pub machine_name: String,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub subsystem: u16,
    pub subsystem_name: String,
    pub timestamp: u32,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub image_size: u32,
    pub checksum: u32,
    pub has_certificate: bool,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImportDll>,
    pub exports: Vec<PeExport>,
    pub packer_hints: Vec<String>,
    pub max_entropy: f32,
    pub total_imports: usize,
}

impl PeInfo {
    /// Every (module, function) pair, useful for policy templates.
    pub fn import_pairs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for dll in &self.imports {
            for f in &dll.functions {
                if f.starts_with('#') {
                    continue; // ordinal import — cannot name-match
                }
                out.push((dll.name.clone(), f.clone()));
            }
        }
        out
    }

    /// One-paragraph human summary (used in reports).
    pub fn summary_line(&self) -> String {
        format!(
            "{} — {} {}-bit {} / {}, {} imports, {} exports, sha256 {}",
            self.file_name,
            self.machine_name,
            if self.is_64bit { 64 } else { 32 },
            if self.is_dll { "DLL" } else { "EXE" },
            self.subsystem_name,
            self.total_imports,
            self.exports.len(),
            &self.sha256[..16],
        )
    }
}

// ─── Parsing ────────────────────────────────────────────────

pub fn inspect_file(path: &std::path::Path) -> Result<PeInfo, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    inspect_bytes(&data, &path.display().to_string())
}

pub fn inspect_bytes(data: &[u8], path: &str) -> Result<PeInfo, String> {
    let file_name = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_string();

    if data.len() < 0x40 || rd_u16(data, 0) != Some(0x5A4D) {
        return Err("not a PE file (missing MZ header)".into());
    }
    let e_lfanew = rd_u32(data, 0x3C).ok_or("truncated DOS header")? as usize;
    if rd_u32(data, e_lfanew) != Some(0x0000_4550) {
        return Err("not a PE file (missing PE signature)".into());
    }

    let coff = e_lfanew + 4;
    let machine = rd_u16(data, coff).ok_or("truncated COFF header")?;
    let nsections = rd_u16(data, coff + 2).ok_or("truncated COFF header")? as usize;
    let timestamp = rd_u32(data, coff + 4).unwrap_or(0);
    let size_opt = rd_u16(data, coff + 16).ok_or("truncated COFF header")? as usize;
    let characteristics = rd_u16(data, coff + 18).unwrap_or(0);

    let opt = coff + 20;
    let magic = rd_u16(data, opt).ok_or("truncated optional header")?;
    let (is_64bit, dd_off, alignment_check) = match magic {
        0x10B => (false, opt + 96usize, true),
        0x20B => (true, opt + 112usize, true),
        _ => return Err(format!("unknown optional header magic 0x{:X}", magic)),
    };
    let _ = alignment_check;

    let entry_point_rva = rd_u32(data, opt + 16).unwrap_or(0);
    let image_base: u64 = if is_64bit {
        rd_u64(data, opt + 24).unwrap_or(0)
    } else {
        rd_u32(data, opt + 28).unwrap_or(0) as u64
    };
    let image_size = rd_u32(data, opt + 56).unwrap_or(0);
    let size_of_headers = rd_u32(data, opt + 60).unwrap_or(0x400);
    let checksum = rd_u32(data, opt + 64).unwrap_or(0);
    let subsystem = rd_u16(data, opt + 68).unwrap_or(0);

    // Data directories
    let dir_export = rd_dir(data, dd_off, 0);
    let dir_import = rd_dir(data, dd_off, 1);
    let dir_security = rd_dir(data, dd_off, 4);
    let dir_delay = rd_dir(data, dd_off, 13);

    // Sections
    let mut sections = Vec::with_capacity(nsections);
    let sec_off = opt + size_opt;
    for i in 0..nsections.min(96) {
        let base = sec_off + i * 40;
        if base + 40 > data.len() {
            break;
        }
        let raw_name = &data[base..base + 8];
        let name_len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_len]).to_string();
        let vsize = rd_u32(data, base + 8).unwrap_or(0);
        let rva = rd_u32(data, base + 12).unwrap_or(0);
        let raw_size = rd_u32(data, base + 16).unwrap_or(0);
        let raw_off = rd_u32(data, base + 20).unwrap_or(0);
        let chars = rd_u32(data, base + 36).unwrap_or(0);

        let entropy = section_entropy(data, raw_off as usize, raw_size as usize);
        sections.push(PeSection {
            name,
            rva,
            virtual_size: vsize,
            raw_offset: raw_off,
            raw_size,
            characteristics: chars,
            entropy,
            executable: chars & 0x2000_0000 != 0,
            writable: chars & 0x8000_0000 != 0,
        });
    }

    // RVA -> file offset mapper
    let rva_to_off = |rva: u32| -> Option<usize> {
        if (rva as usize) < size_of_headers as usize && (rva as usize) < data.len() {
            return Some(rva as usize);
        }
        for s in &sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.rva && (rva - s.rva) < span {
                let delta = rva - s.rva;
                if delta < s.raw_size {
                    return Some(s.raw_offset as usize + delta as usize);
                }
                return None; // inside uninitialized virtual space
            }
        }
        None
    };
    let read_cstr = |off: usize, max: usize| -> String {
        if off >= data.len() {
            return String::new();
        }
        let end = data[off..].iter().position(|&b| b == 0).unwrap_or(max);
        String::from_utf8_lossy(&data[off..(off + end).min(data.len())]).to_string()
    };

    // Imports
    let mut imports = Vec::new();
    if let Some((iva, sz)) = dir_import {
        if sz > 0 {
            if let Some(ioff) = rva_to_off(iva) {
                let mut p = ioff;
                for _ in 0..4096 {
                    let name_rva = rd_u32(data, p + 12).unwrap_or(0);
                    let oft = rd_u32(data, p + 0).unwrap_or(0);
                    let ft = rd_u32(data, p + 16).unwrap_or(0);
                    if name_rva == 0 && oft == 0 && ft == 0 {
                        break;
                    }
                    let dll_name = rva_to_off(name_rva)
                        .map(|o| read_cstr(o, 260))
                        .unwrap_or_default();
                    let mut funcs = Vec::new();
                    let thunk_rva = if oft != 0 { oft } else { ft };
                    if let Some(toff) = rva_to_off(thunk_rva) {
                        let step = if is_64bit { 8 } else { 4 };
                        for t in 0..20000 {
                            let off = toff + t * step;
                            let val = if is_64bit {
                                rd_u64(data, off)
                            } else {
                                rd_u32(data, off).map(|v| v as u64)
                            };
                            let Some(val) = val else { break };
                            if val == 0 {
                                break;
                            }
                            if is_64bit && val & 0x8000_0000_0000_0000 != 0 {
                                funcs.push(format!("#{}", val & 0xFFFF));
                            } else if !is_64bit && val & 0x8000_0000 != 0 {
                                funcs.push(format!("#{}", val & 0xFFFF));
                            } else {
                                let name_off = rva_to_off(val as u32);
                                match name_off {
                                    Some(no) => funcs.push(read_cstr(no + 2, 256)),
                                    None => funcs.push(format!("<bad rva 0x{:X}>", val)),
                                }
                            }
                        }
                    }
                    imports.push(PeImportDll {
                        name: dll_name,
                        functions: funcs,
                        delayed: false,
                    });
                    p += 20;
                }
            }
        }
    }

    // Delay imports (names and RVAs; thunks carry absolute or RVA values —
    // we only list what can be resolved safely).
    if let Some((dva, sz)) = dir_delay {
        if sz > 0 {
            if let Some(doff) = rva_to_off(dva) {
                let mut p = doff;
                for _ in 0..1024 {
                    let name_rva = rd_u32(data, p + 4).unwrap_or(0);
                    let oft = rd_u32(data, p + 16).unwrap_or(0);
                    if name_rva == 0 && oft == 0 {
                        break;
                    }
                    let dll_name = rva_to_off(name_rva)
                        .map(|o| read_cstr(o, 260))
                        .unwrap_or_default();
                    let mut funcs = Vec::new();
                    if let Some(toff) = rva_to_off(oft) {
                        let step = if is_64bit { 8 } else { 4 };
                        for t in 0..20000 {
                            let off = toff + t * step;
                            let val = if is_64bit {
                                rd_u64(data, off)
                            } else {
                                rd_u32(data, off).map(|v| v as u64)
                            };
                            let Some(val) = val else { break };
                            if val == 0 {
                                break;
                            }
                            let ordinal_bit = if is_64bit { 1u64 << 63 } else { 1u64 << 31 };
                            if val & ordinal_bit != 0 {
                                funcs.push(format!("#{}", val & 0xFFFF));
                            } else if (val as u32) < image_size {
                                if let Some(no) = rva_to_off(val as u32) {
                                    funcs.push(read_cstr(no + 2, 256));
                                }
                            }
                        }
                    }
                    if !dll_name.is_empty() {
                        imports.push(PeImportDll {
                            name: dll_name,
                            functions: funcs,
                            delayed: true,
                        });
                    }
                    p += 32;
                }
            }
        }
    }

    // Exports
    let mut exports = Vec::new();
    if let Some((eva, sz)) = dir_export {
        if sz > 0 {
            if let Some(eoff) = rva_to_off(eva) {
                let base = rd_u32(data, eoff + 16).unwrap_or(0);
                let nfuncs = rd_u32(data, eoff + 20).unwrap_or(0).min(65536);
                let nnames = rd_u32(data, eoff + 24).unwrap_or(0).min(65536);
                let a_funcs = rd_u32(data, eoff + 28).unwrap_or(0);
                let a_names = rd_u32(data, eoff + 32).unwrap_or(0);
                let a_ords = rd_u32(data, eoff + 36).unwrap_or(0);

                let funcs_off = rva_to_off(a_funcs);
                let names_off = rva_to_off(a_names);
                let ords_off = rva_to_off(a_ords);
                let export_span = (eva, eva.wrapping_add(sz));

                for i in 0..nnames as usize {
                    let Some(noff) = names_off.map(|o| rd_u32(data, o + i * 4)).flatten() else { break };
                    let Some(name) = rva_to_off(noff).map(|o| read_cstr(o, 256)) else { continue };
                    let ord = ords_off
                        .and_then(|o| rd_u16(data, o + i * 2))
                        .unwrap_or(0) as u32;
                    let func_rva = funcs_off
                        .and_then(|o| rd_u32(data, o + (ord as usize) * 4))
                        .unwrap_or(0);
                    let forwarded = func_rva >= export_span.0 && func_rva < export_span.1;
                    let forwarder = if forwarded {
                        rva_to_off(func_rva).map(|o| read_cstr(o, 256)).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    exports.push(PeExport {
                        name,
                        ordinal: base + ord,
                        rva: func_rva as u64,
                        forwarded,
                        forwarder,
                    });
                }
                let _ = nfuncs;
            }
        }
    }

    // Packer / protection heuristics
    let mut hints: Vec<String> = Vec::new();
    let suspicious_sections = [
        "upx0", "upx1", "upx2", ".aspack", ".adata", ".nsp0", ".nsp1", ".mpress1",
        ".mpress2", ".themida", ".vmp0", ".vmp1", ".petite", "pelock", ".enigma1",
        ".enigma2", ".boom", ".ccg", ".fsg", ".mew", ".neolite", ".pklstb", ".packed",
        ".perplex",
    ];
    for s in &sections {
        let lower = s.name.to_ascii_lowercase();
        if suspicious_sections.iter().any(|x| lower == *x || lower.starts_with(x.trim_start_matches('.'))) {
            hints.push(format!("packer section name '{}'", s.name));
        }
        if s.entropy > 7.2 && s.raw_size > 4096 {
            hints.push(format!("high entropy in '{}' ({:.2})", s.name, s.entropy));
        }
        if s.writable && s.executable {
            hints.push(format!("writable+executable section '{}'", s.name));
        }
    }
    let total_imports: usize = imports.iter().map(|i| i.functions.len()).sum();
    if total_imports < 10 && data.len() > 64 * 1024 {
        hints.push(format!("only {} imports (packed or delay-loaded?)", total_imports));
    }
    if entry_point_rva as usize >= size_of_headers as usize
        && !sections.iter().any(|s| {
            entry_point_rva >= s.rva && entry_point_rva < s.rva + s.virtual_size.max(s.raw_size)
        })
    {
        hints.push("entry point outside all sections".into());
    }
    if checksum == 0 {
        hints.push("checksum field is zero".into());
    }
    hints.dedup();

    let is_dll = characteristics & 0x2000 != 0;
    let max_entropy = sections.iter().map(|s| s.entropy).fold(0.0f32, f32::max);

    Ok(PeInfo {
        path: path.to_string(),
        file_name,
        size: data.len() as u64,
        sha256: hex(&sha256(data)),
        machine,
        machine_name: machine_name(machine).into(),
        is_64bit,
        is_dll,
        subsystem,
        subsystem_name: subsystem_name(subsystem).into(),
        timestamp,
        entry_point_rva,
        image_base,
        image_size,
        checksum,
        has_certificate: dir_security.map(|(_, sz)| sz > 0).unwrap_or(false),
        sections,
        imports,
        exports,
        packer_hints: hints,
        max_entropy,
        total_imports,
    })
}

// ─── Helpers ────────────────────────────────────────────────

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}
/// Data directory entry #idx: (VirtualAddress, Size).
fn rd_dir(b: &[u8], dd_off: usize, idx: usize) -> Option<(u32, u32)> {
    let va = rd_u32(b, dd_off + idx * 8)?;
    let sz = rd_u32(b, dd_off + idx * 8 + 4)?;
    if va == 0 && sz == 0 {
        None
    } else {
        Some((va, sz))
    }
}

fn section_entropy(data: &[u8], off: usize, len: usize) -> f32 {
    if off >= data.len() || len == 0 {
        return 0.0;
    }
    let end = (off + len).min(data.len());
    let slice = &data[off..end];
    if slice.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in slice {
        counts[b as usize] += 1;
    }
    let n = slice.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h as f32
}

fn machine_name(m: u16) -> &'static str {
    match m {
        0x014C => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x01C4 => "ARMv7",
        0x0200 => "IA64",
        _ => "unknown",
    }
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "GUI",
        3 => "console",
        9 => "WinCE",
        10 => "EFI",
        16 => "boot",
        _ => "unknown",
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// ─── SHA-256 (hand-rolled, no external crates) ──────────────

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parses_own_test_binary() {
        let exe = std::env::current_exe().expect("current exe");
        let pe = inspect_file(&exe).expect("inspect own test exe");
        assert!(pe.is_64bit, "test binary should be 64-bit");
        assert!(!pe.sections.is_empty(), "has sections");
        assert!(pe.total_imports > 0, "has imports; got {}", pe.total_imports);
        assert!(pe.size > 0);
        assert_eq!(pe.sha256.len(), 64);
    }
}
