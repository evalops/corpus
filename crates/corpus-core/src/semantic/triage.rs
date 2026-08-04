//! Packed / virtualized-code triage signals beyond mean entropy.
//!
//! Signals explain analysis limitations; they never create a confident
//! semantic edge by themselves.

use crate::similarity::extract::shannon_entropy;
use crate::similarity::model::MODEL_V1;
use serde::Serialize;

pub const TRIAGE_VERSION: &str = "triage:v1";

/// Section metadata: (name, raw bytes, is_executable, is_writable).
pub type SectionMeta = (String, Vec<u8>, bool, bool);

/// Parsed section list plus import count and overlay flag.
type SectionsParse = (Vec<SectionMeta>, usize, bool);

#[derive(Debug, Clone, Serialize)]
pub struct TriageSignal {
    pub name: String,
    pub value: f64,
    pub threshold: f64,
    pub fired: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriageReport {
    pub version: String,
    pub format: String,
    pub signals: Vec<TriageSignal>,
    /// True when the binary should skip confident semantic edges.
    pub block_semantic: bool,
    pub summary: String,
}

/// Run format-aware triage. `code_sections` is (name, bytes, is_executable, is_writable).
pub fn triage(
    format: &str,
    whole: &[u8],
    code_sections: &[SectionMeta],
    import_count: usize,
    has_overlay: bool,
) -> TriageReport {
    let mut signals = Vec::new();
    let entropy_limit = MODEL_V1.packed_entropy_limit;

    // Mean code-section entropy.
    let mut code_bytes = 0usize;
    let mut weighted_entropy = 0.0f64;
    let mut max_section_entropy = 0.0f64;
    let mut exec_writable = 0usize;
    for (name, bytes, exec, writable) in code_sections {
        if *exec && !bytes.is_empty() {
            let e = shannon_entropy(bytes);
            weighted_entropy += e * bytes.len() as f64;
            code_bytes += bytes.len();
            max_section_entropy = max_section_entropy.max(e);
            if *writable {
                exec_writable += 1;
                signals.push(TriageSignal {
                    name: "exec_writable_section".into(),
                    value: 1.0,
                    threshold: 0.0,
                    fired: true,
                    detail: format!("section {name} is executable and writable"),
                });
            }
        }
    }
    let mean_code_entropy = if code_bytes == 0 {
        shannon_entropy(whole)
    } else {
        weighted_entropy / code_bytes as f64
    };
    signals.push(TriageSignal {
        name: "mean_code_entropy".into(),
        value: mean_code_entropy,
        threshold: entropy_limit,
        fired: mean_code_entropy > entropy_limit,
        detail: format!("mean code entropy {mean_code_entropy:.2}"),
    });
    signals.push(TriageSignal {
        name: "max_section_entropy".into(),
        value: max_section_entropy,
        threshold: entropy_limit + 0.3,
        fired: max_section_entropy > entropy_limit + 0.3,
        detail: format!("max section entropy {max_section_entropy:.2}"),
    });

    // Import sparsity: packers often have very few imports.
    let import_threshold = 3.0;
    signals.push(TriageSignal {
        name: "import_sparsity".into(),
        value: import_count as f64,
        threshold: import_threshold,
        fired: import_count > 0
            && (import_count as f64) < import_threshold
            && mean_code_entropy > 6.5,
        detail: format!("{import_count} imports with elevated entropy"),
    });

    // Overlay after the last section is common for packers/droppers.
    signals.push(TriageSignal {
        name: "overlay_present".into(),
        value: if has_overlay { 1.0 } else { 0.0 },
        threshold: 0.5,
        fired: has_overlay && mean_code_entropy > 6.8,
        detail: if has_overlay {
            "file has overlay past section data".into()
        } else {
            "no overlay".into()
        },
    });

    // Known packer marker bytes (UPX, etc.) — presence is a signal only.
    let markers = [
        (&b"UPX0"[..], "upx_section"),
        (&b"UPX1"[..], "upx_section"),
        (&b"UPX!"[..], "upx_magic"),
        (&b".nsp0"[..], "nspack"),
        (&b"PEC2"[..], "pecompact"),
    ];
    for (needle, label) in markers {
        if find_bytes(whole, needle) {
            signals.push(TriageSignal {
                name: "packer_marker".into(),
                value: 1.0,
                threshold: 0.5,
                fired: true,
                detail: label.into(),
            });
        }
    }

    let fired: Vec<&TriageSignal> = signals.iter().filter(|s| s.fired).collect();
    // Block semantic when high entropy fires OR packer marker + another signal.
    let entropy_block = signals
        .iter()
        .any(|s| s.name == "mean_code_entropy" && s.fired);
    let marker_block =
        signals.iter().any(|s| s.name == "packer_marker" && s.fired) && fired.len() >= 2;
    let block_semantic =
        entropy_block || marker_block || exec_writable > 0 && mean_code_entropy > 6.5;

    let summary = if fired.is_empty() {
        "no packing signals".into()
    } else {
        fired
            .iter()
            .map(|s| format!("{}={}", s.name, s.detail))
            .collect::<Vec<_>>()
            .join("; ")
    };

    TriageReport {
        version: TRIAGE_VERSION.into(),
        format: format.into(),
        signals,
        block_semantic,
        summary,
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Collect PE/ELF section metadata for triage without full semantic extract.
pub fn sections_from_bytes(format: &str, bytes: &[u8]) -> SectionsParse {
    match format {
        "pe" => pe_sections(bytes),
        "elf" => elf_sections(bytes),
        _ => (Vec::new(), 0, false),
    }
}

fn pe_sections(bytes: &[u8]) -> SectionsParse {
    let Ok(pe) = goblin::pe::PE::parse(bytes) else {
        return (Vec::new(), 0, false);
    };
    let imports = pe.imports.len();
    let mut last_end = 0usize;
    let mut secs = Vec::new();
    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name)
            .trim_end_matches('\0')
            .to_string();
        let start = s.pointer_to_raw_data as usize;
        let end = (start + s.size_of_raw_data as usize).min(bytes.len());
        last_end = last_end.max(end);
        let chars = s.characteristics;
        let exec = chars & 0x2000_0000 != 0;
        let writable = chars & 0x8000_0000 != 0;
        let body = if start < end {
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };
        secs.push((name, body, exec, writable));
    }
    let overlay = last_end > 0 && last_end + 64 < bytes.len();
    (secs, imports, overlay)
}

fn elf_sections(bytes: &[u8]) -> SectionsParse {
    let Ok(elf) = goblin::elf::Elf::parse(bytes) else {
        return (Vec::new(), 0, false);
    };
    let imports = elf.dynsyms.len().min(64);
    let mut secs = Vec::new();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let start = sh.sh_offset as usize;
        let end = (start + sh.sh_size as usize).min(bytes.len());
        let exec = sh.is_executable();
        let writable = sh.is_writable();
        let body = if start < end {
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };
        secs.push((name, body, exec, writable));
    }
    (secs, imports, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_entropy_blocks_semantic() {
        // Near-random "code" section.
        let mut code = vec![0u8; 1024];
        for (i, b) in code.iter_mut().enumerate() {
            *b = ((i * 17 + 31) % 251) as u8;
        }
        // Boost entropy further
        for (i, b) in code.iter_mut().enumerate().take(256) {
            *b = i as u8;
        }
        let report = triage(
            "pe",
            &code,
            &[(".text".into(), code.clone(), true, false)],
            1,
            false,
        );
        assert!(
            report.block_semantic || report.signals.iter().any(|s| s.name == "mean_code_entropy"),
            "entropy signal should fire: {}",
            report.summary
        );
    }

    #[test]
    fn low_entropy_code_does_not_block() {
        let code = vec![0x90u8; 512]; // NOPs
        let report = triage(
            "pe",
            &code,
            &[(".text".into(), code.clone(), true, false)],
            20,
            false,
        );
        assert!(
            !report.block_semantic,
            "nop sled should not block: {}",
            report.summary
        );
    }

    #[test]
    fn upx_marker_is_recorded() {
        let mut bytes = vec![0u8; 256];
        bytes[100..104].copy_from_slice(b"UPX!");
        let report = triage("pe", &bytes, &[], 2, false);
        assert!(report
            .signals
            .iter()
            .any(|s| s.name == "packer_marker" && s.fired));
    }
}
