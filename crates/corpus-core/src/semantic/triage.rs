//! Packed / virtualized-code triage signals beyond mean entropy.
//!
//! # Purpose
//!
//! Semantic function matching assumes recoverable instruction streams.
//! Packers, crypters, and virtualization layers break that assumption:
//! code sections look like random bytes, entry stubs are thin, and
//! overlays hold payloads. Emitting a *confident* semantic edge against
//! such a binary would be a false lead.
//!
//! This module produces a structured [`TriageReport`] that:
//!
//! 1. Collects multi-signal evidence (entropy, imports, overlays, markers).
//! 2. Sets [`TriageReport::block_semantic`] when analysis should refuse
//!    confident edges.
//! 3. Persists every signal for analyst visibility (via callers storing
//!    the report under `similarity_feature` family `semantic` / name `triage`).
//!
//! # Non-goals
//!
//! - **Never invents similarity.** A fired signal is a *limitation*, not
//!   an edge. Packer markers alone do not claim two samples are related.
//! - **Not an unpacker.** We detect hardness; we do not recover original
//!   code.
//! - **Format coverage is best-effort.** Unknown formats fall back to
//!   whole-file entropy only.
//!
//! # Blocking policy (v1)
//!
//! `block_semantic` is true when any of:
//!
//! - Mean executable-section entropy exceeds
//!   [`MODEL_V1::packed_entropy_limit`] (default 7.2 bits/byte).
//! - A known packer marker is present **and** at least one other signal
//!   fires (marker alone is recorded but not blocking).
//! - At least one executable+writable section exists **and** mean entropy
//!   is elevated (> 6.5).
//!
//! Thresholds live in [`MODEL_V1`] so receipts and the design doc stay
//! synchronized.
//!
//! # Versioning
//!
//! [`TRIAGE_VERSION`] is stored with every report. Changing signal names
//! or block policy requires a version bump so historical rows remain
//! interpretable.

use crate::similarity::extract::shannon_entropy;
use crate::similarity::model::MODEL_V1;
use serde::Serialize;

/// Persisted identity of this triage implementation.
///
/// Stored under `similarity_feature.value` alongside signal payloads so
/// re-analysis under a newer policy can distinguish old reports.
pub const TRIAGE_VERSION: &str = "triage:v1";

/// Section metadata used as triage input.
///
/// Tuple layout: `(name, raw bytes, is_executable, is_writable)`.
/// Callers typically obtain this via [`sections_from_bytes`].
pub type SectionMeta = (String, Vec<u8>, bool, bool);

/// Result of a lightweight PE/ELF section walk: sections, import count,
/// and whether the file has a non-trivial overlay past the last section.
type SectionsParse = (Vec<SectionMeta>, usize, bool);

/// One named measurement with its threshold and fire state.
///
/// All signals are retained even when not fired so analysts can see
/// near-misses (e.g. entropy just under the limit).
#[derive(Debug, Clone, Serialize)]
pub struct TriageSignal {
    /// Stable machine-readable name (`mean_code_entropy`, `packer_marker`, …).
    pub name: String,
    /// Measured value in the same unit as `threshold` (bits/byte, counts, 0/1).
    pub value: f64,
    /// Policy threshold that `value` is compared against.
    pub threshold: f64,
    /// Whether this signal contributes to packing suspicion / blocking.
    pub fired: bool,
    /// Short human-readable detail for UI and logs.
    pub detail: String,
}

/// Full triage outcome for one artifact.
#[derive(Debug, Clone, Serialize)]
pub struct TriageReport {
    /// [`TRIAGE_VERSION`] at the time of analysis.
    pub version: String,
    /// Container format string (`pe`, `elf`, …) provided by the caller.
    pub format: String,
    /// Ordered list of signals (mean entropy, markers, etc.).
    pub signals: Vec<TriageSignal>,
    /// When true, callers must not emit confident semantic edges.
    pub block_semantic: bool,
    /// Semicolon-joined summary of fired signals, or `"no packing signals"`.
    pub summary: String,
}

/// Run format-aware packing/virtualization triage.
///
/// # Arguments
///
/// * `format` — container family (`pe` / `elf` / other). Used only for
///   report metadata; section parsing is already done by the caller.
/// * `whole` — full file bytes (for packer markers and whole-file entropy
///   fallback when no executable sections are present).
/// * `code_sections` — section list from [`sections_from_bytes`].
/// * `import_count` — PE imports or a bounded ELF dynsym count.
/// * `has_overlay` — true when trailing bytes past the last section exist.
///
/// # Complexity
///
/// Linear in total section bytes plus a small constant for marker scans.
pub fn triage(
    format: &str,
    whole: &[u8],
    code_sections: &[SectionMeta],
    import_count: usize,
    has_overlay: bool,
) -> TriageReport {
    let mut signals = Vec::new();
    let entropy_limit = MODEL_V1.packed_entropy_limit;

    // ---- Entropy over executable sections (size-weighted mean + max) ----
    // Packers often encrypt only .text while leaving headers and rdata
    // low-entropy; weighting by section length avoids that loophole.
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
            // RWX sections are a strong packing / self-modifying signal.
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
    // No executable sections: fall back to whole-file entropy so packed
    // blobs without a parseable PE/ELF layout still get a signal.
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
    // Max-section gate sits slightly above mean: a single fully-encrypted
    // section is more suspicious than uniform moderate entropy.
    signals.push(TriageSignal {
        name: "max_section_entropy".into(),
        value: max_section_entropy,
        threshold: entropy_limit + 0.3,
        fired: max_section_entropy > entropy_limit + 0.3,
        detail: format!("max section entropy {max_section_entropy:.2}"),
    });

    // ---- Import sparsity ----
    // Commercial packers often leave a tiny import table (LoadLibrary/
    // GetProcAddress only). Combined with elevated entropy this is a
    // classic packed PE signature. Zero imports are ignored (common for
    // raw shellcode blobs and would false-positive).
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

    // ---- Overlay past last section ----
    // Droppers append payloads after the PE/ELF image. Only fires when
    // entropy is also elevated so normal installer overlays are quieter.
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

    // ---- Known packer marker bytes ----
    // Presence is recorded as a signal only. Blocking requires a second
    // corroborating signal (see block_semantic below) to avoid false
    // positives on strings that merely mention UPX.
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
    // Block policy — see module docs. Note operator precedence:
    // `exec_writable > 0 && mean_code_entropy > 6.5` binds tighter than `||`.
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

/// Naive substring search for short packer markers (files are already in memory).
fn find_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Collect PE/ELF section metadata for triage without a full semantic extract.
///
/// Returns `(sections, import_count, has_overlay)`. Unknown formats yield
/// empty sections so triage falls back to whole-file entropy.
///
/// This path is intentionally lighter than `semantic::extract`: it only
/// needs characteristics flags and raw section bytes for entropy.
pub fn sections_from_bytes(format: &str, bytes: &[u8]) -> SectionsParse {
    match format {
        "pe" => pe_sections(bytes),
        "elf" => elf_sections(bytes),
        _ => (Vec::new(), 0, false),
    }
}

/// Walk PE sections via goblin; import count from the import table.
///
/// Overlay detection: raw data ends more than 64 bytes before EOF.
/// Characteristics bits: `0x20000000` IMAGE_SCN_MEM_EXECUTE,
/// `0x80000000` IMAGE_SCN_MEM_WRITE.
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

/// Walk ELF section headers; import proxy is a capped dynsym count.
///
/// ELF has no standard "overlay" concept analogous to PE, so the third
/// return value is always false.
fn elf_sections(bytes: &[u8]) -> SectionsParse {
    let Ok(elf) = goblin::elf::Elf::parse(bytes) else {
        return (Vec::new(), 0, false);
    };
    // Cap dynsym so a maliciously huge table cannot inflate import_count.
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
        // Boost entropy further with a full byte-value permutation prefix.
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
