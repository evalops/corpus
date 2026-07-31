//! Similarity feature extraction (spec 16.2) via goblin. Formats that do
//! not parse store nothing beyond byte-level features — never an error.
//! Extractor versions are embedded in every stored feature row.

use sha2::{Digest, Sha256};

pub const EXTRACTOR_VERSION: &str = "extractor:v1";

#[derive(Debug, Clone)]
pub struct NormalizedFeature {
    /// e.g. "authentihash", "imphash", "elf_build_id", "import_hash",
    /// "section_layout".
    pub name: String,
    pub hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExtractedFeatures {
    /// pe | elf | macho | unknown
    pub format: String,
    pub arch: Option<String>,
    pub size_bytes: u64,
    pub entropy: f64,
    pub ssdeep: String,
    /// Strong normalized identity hashes (16.2 "normalized identity").
    pub normalized: Vec<NormalizedFeature>,
    /// Structural digests (16.2 "structural similarity").
    pub section_layout: Option<String>,
    pub import_set: Option<String>,
    pub export_set: Option<String>,
    pub compiler_hint: Option<String>,
    /// True when bytes looked like a known format but failed to parse —
    /// surfaced as a limitation, not an error (28.5).
    pub parse_limitation: Option<String>,
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn sha256_hex_parts(parts: impl Iterator<Item = String>) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"\0");
    }
    hex::encode(h.finalize())
}

/// Extract all M3a features from artifact bytes.
pub fn extract(bytes: &[u8]) -> ExtractedFeatures {
    let mut f = ExtractedFeatures {
        format: "unknown".into(),
        size_bytes: bytes.len() as u64,
        entropy: shannon_entropy(bytes),
        ssdeep: crate::similarity::fuzzy::fuzzy_hash(bytes),
        ..Default::default()
    };
    match crate::classify::classify(bytes) {
        crate::classify::ArtifactClass::Pe => {
            f.format = "pe".into();
            match goblin::pe::PE::parse(bytes) {
                Ok(pe) => extract_pe(bytes, &pe, &mut f),
                Err(e) => f.parse_limitation = Some(format!("pe parse: {e}")),
            }
        }
        crate::classify::ArtifactClass::Elf => {
            f.format = "elf".into();
            match goblin::elf::Elf::parse(bytes) {
                Ok(elf) => extract_elf(bytes, &elf, &mut f),
                Err(e) => f.parse_limitation = Some(format!("elf parse: {e}")),
            }
        }
        crate::classify::ArtifactClass::MachO | crate::classify::ArtifactClass::MachOFat => {
            f.format = "macho".into();
            match goblin::mach::Mach::parse(bytes) {
                Ok(goblin::mach::Mach::Binary(macho)) => extract_macho(&macho, &mut f),
                Ok(goblin::mach::Mach::Fat(_)) => {
                    f.parse_limitation = Some("fat macho: extraction covers thin binaries only".into())
                }
                Err(e) => f.parse_limitation = Some(format!("macho parse: {e}")),
            }
        }
        _ => {}
    }
    f
}

// ---------------- PE ----------------

/// Authentihash-style normalized hash: SHA-256 over the whole file
/// excluding the CheckSum field, the certificate-table data-directory
/// entry, and the certificate table bytes themselves.
pub fn pe_authentihash(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return None;
    }
    let pe_off = u32::from_le_bytes(bytes[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 0x18 > bytes.len() || bytes[pe_off..pe_off + 4] != *b"PE\0\0" {
        return None;
    }
    let opt = pe_off + 24;
    if opt + 0x70 > bytes.len() {
        return None;
    }
    let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().ok()?);
    let dir_base = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let mut ranges: Vec<(usize, usize)> = vec![
        (opt + 64, opt + 68),       // CheckSum
        (dir_base + 32, dir_base + 40), // certificate table directory entry
    ];
    if dir_base + 40 <= bytes.len() {
        let cert_off = u32::from_le_bytes(bytes[dir_base + 32..dir_base + 36].try_into().ok()?) as usize;
        let cert_len = u32::from_le_bytes(bytes[dir_base + 36..dir_base + 40].try_into().ok()?) as usize;
        if cert_len > 0 && cert_off < bytes.len() {
            ranges.push((cert_off, (cert_off + cert_len).min(bytes.len())));
        }
    }
    ranges.sort();
    let mut h = Sha256::new();
    let mut pos = 0usize;
    for (start, end) in ranges {
        if start > bytes.len() {
            break;
        }
        if start > pos {
            h.update(&bytes[pos..start.min(bytes.len())]);
        }
        pos = pos.max(end.min(bytes.len()));
    }
    if pos < bytes.len() {
        h.update(&bytes[pos..]);
    }
    Some(hex::encode(h.finalize()))
}

fn extract_pe(bytes: &[u8], pe: &goblin::pe::PE, f: &mut ExtractedFeatures) {
    f.arch = Some(format!("0x{:x}", pe.header.coff_header.machine));

    if let Some(ah) = pe_authentihash(bytes) {
        f.normalized.push(NormalizedFeature { name: "authentihash".into(), hash: ah });
    }

    if !pe.imports.is_empty() {
        let ordered: Vec<String> = pe
            .imports
            .iter()
            .map(|i| format!("{}.{}", i.dll.to_lowercase(), i.name.to_lowercase()))
            .collect();
        f.normalized.push(NormalizedFeature {
            name: "imphash".into(),
            hash: sha256_hex_parts(ordered.iter().cloned()),
        });
        let mut set = ordered.clone();
        set.sort();
        set.dedup();
        f.import_set = Some(sha256_hex_parts(set.into_iter()));
    }
    if !pe.exports.is_empty() {
        let mut names: Vec<String> = pe
            .exports
            .iter()
            .filter_map(|e| e.name.map(|n| n.to_lowercase()))
            .collect();
        names.sort();
        names.dedup();
        f.export_set = Some(sha256_hex_parts(names.into_iter()));
    }

    let layout: Vec<String> = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
            let body = &bytes[s.pointer_to_raw_data as usize
                ..(s.pointer_to_raw_data as usize + s.size_of_raw_data as usize).min(bytes.len())];
            format!(
                "{name}:{}:{}:{:x}:{}",
                s.virtual_size,
                s.size_of_raw_data,
                s.characteristics,
                hex::encode(Sha256::digest(body))
            )
        })
        .collect();
    if !layout.is_empty() {
        f.section_layout = Some(sha256_hex_parts(layout.into_iter()));
    }
}

// ---------------- ELF ----------------

fn extract_elf(_bytes: &[u8], elf: &goblin::elf::Elf, f: &mut ExtractedFeatures) {
    f.arch = Some(format!("0x{:x}", elf.header.e_machine));

    // Build ID from .note.gnu.build-id.
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) else { continue };
        if name != ".note.gnu.build-id" {
            continue;
        }
        let start = sh.sh_offset as usize;
        let end = (start + sh.sh_size as usize).min(_bytes.len());
        if let Some(id) = parse_gnu_build_id(&_bytes[start..end]) {
            f.normalized.push(NormalizedFeature { name: "elf_build_id".into(), hash: id });
        }
        let _ = i;
    }

    // Ordered import hash: needed libs (link order) + undefined dyn syms.
    let undef: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|s| s.st_shndx == 0 && s.st_name != 0)
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(|n| n.to_lowercase()))
        .collect();
    if !elf.libraries.is_empty() || !undef.is_empty() {
        let mut parts: Vec<String> = elf.libraries.iter().map(|l| l.to_lowercase()).collect();
        parts.push(";".into());
        parts.extend(undef.iter().cloned());
        f.normalized.push(NormalizedFeature {
            name: "elf_import_hash".into(),
            hash: sha256_hex_parts(parts.into_iter()),
        });
        let mut set = undef.clone();
        set.sort();
        set.dedup();
        f.import_set = Some(sha256_hex_parts(set.into_iter()));
    }

    let layout: Vec<String> = elf
        .section_headers
        .iter()
        .filter_map(|sh| {
            elf.shdr_strtab.get_at(sh.sh_name).map(|name| {
                format!("{name}:{}:{:x}:{}", sh.sh_size, sh.sh_flags, sh.sh_type)
            })
        })
        .collect();
    if !layout.is_empty() {
        f.section_layout = Some(sha256_hex_parts(layout.into_iter()));
    }

    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(".comment") {
            let start = sh.sh_offset as usize;
            let end = (start + sh.sh_size as usize).min(_bytes.len());
            let text = String::from_utf8_lossy(&_bytes[start..end])
                .trim_matches('\0')
                .trim()
                .to_string();
            if !text.is_empty() {
                f.compiler_hint = Some(text);
            }
        }
    }
}

fn parse_gnu_build_id(note: &[u8]) -> Option<String> {
    if note.len() < 12 {
        return None;
    }
    let namesz = u32::from_le_bytes(note[0..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(note[4..8].try_into().ok()?) as usize;
    let note_type = u32::from_le_bytes(note[8..12].try_into().ok()?);
    if note_type != 3 {
        return None;
    }
    let desc_off = 12 + namesz.div_ceil(4) * 4;
    if desc_off + descsz > note.len() {
        return None;
    }
    Some(hex::encode(&note[desc_off..desc_off + descsz]))
}

// ---------------- Mach-O ----------------

fn extract_macho(macho: &goblin::mach::MachO, f: &mut ExtractedFeatures) {
    f.arch = Some(format!("0x{:x}", macho.header.cputype()));

    if let Ok(imports) = macho.imports() {
        if !imports.is_empty() {
            let ordered: Vec<String> = imports
                .iter()
                .map(|i| format!("{}.{}", i.dylib.to_lowercase(), i.name.to_lowercase()))
                .collect();
            f.normalized.push(NormalizedFeature {
                name: "macho_import_hash".into(),
                hash: sha256_hex_parts(ordered.iter().cloned()),
            });
            let mut set = ordered.clone();
            set.sort();
            set.dedup();
            f.import_set = Some(sha256_hex_parts(set.into_iter()));
        }
    }
    if let Ok(exports) = macho.exports() {
        if !exports.is_empty() {
            let mut names: Vec<String> = exports.iter().map(|e| e.name.to_lowercase()).collect();
            names.sort();
            names.dedup();
            f.export_set = Some(sha256_hex_parts(names.into_iter()));
        }
    }

    let layout: Vec<String> = macho
        .segments
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(&s.segname).trim_end_matches('\0').to_string();
            format!("{name}:{}:{}", s.filesize, s.nsects)
        })
        .collect();
    if !layout.is_empty() {
        f.section_layout = Some(sha256_hex_parts(layout.into_iter()));
    }
    // Mach-O code-directory hashes are a documented gap: goblin does not
    // parse LC_CODE_SIGNATURE; nothing is stored (spec allows "where
    // parseable").
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_known_values() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn unparseable_bytes_are_not_errors() {
        let f = extract(b"plain text, no magic");
        assert_eq!(f.format, "unknown");
        assert!(f.normalized.is_empty());
        assert!(f.parse_limitation.is_none());
        assert!(!f.ssdeep.is_empty());
    }
}
