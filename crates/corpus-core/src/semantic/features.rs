//! Per-function feature vectors and 256-bit simhash signatures
//! (docs/semantic-similarity-design.md).
//!
//! # What is preserved
//!
//! Tokens capture **mnemonic structure** that tends to survive recompilation
//! of the same source: instruction *families* (`mov`, `arith`, `jcc`, …),
//! not immediates, absolute addresses, or register allocation details.
//!
//! # Scoring inputs
//!
//! - [`FunctionFeatures::token_hashes`] — sorted unique SHA-256-derived
//!   u64s over family tokens; Jaccard similarity is the pair score.
//! - [`FunctionFeatures::signature`] — 256-bit simhash reserved for future
//!   banded indexing (not the primary v1 scorer).
//!
//! Thresholds [`MATCH_TAU`] and [`SIGNIFICANCE_MIN_INSNS`] re-export
//! [`MODEL_V1`] so they cannot drift from the model registry.

use crate::similarity::model::MODEL_V1;
use iced_x86::{Decoder, DecoderOptions};
use sha2::{Digest, Sha256};

pub const SIGNATURE_BITS: usize = 256;
/// Re-export of the authoritative significance floor from MODEL_V1.
pub const SIGNIFICANCE_MIN_INSNS: usize = MODEL_V1.significance_min_insns;
/// Match threshold τ for a function pair — authoritative source is MODEL_V1.
pub const MATCH_TAU: f64 = MODEL_V1.semantic_match_tau;

/// Features extracted from one decoded function body.
#[derive(Debug, Clone)]
pub struct FunctionFeatures {
    /// Simhash kept for future banded indexing.
    pub signature: [u8; SIGNATURE_BITS / 8],
    /// Sorted, deduplicated token hashes (Jaccard scoring).
    pub token_hashes: Vec<u64>,
    pub insn_count: usize,
    pub block_estimate: usize,
    pub call_count: usize,
    /// True for pure jmp/ret stubs — excluded from significance.
    pub is_thunk: bool,
}

/// Whether a function is large enough and non-trivial to enter matching.
pub fn is_significant(f: &FunctionFeatures) -> bool {
    f.insn_count >= MODEL_V1.significance_min_insns && !f.is_thunk
}

fn family(m: iced_x86::Mnemonic) -> String {
    use iced_x86::Mnemonic::*;
    match m {
        Mov | Movzx | Movsx | Movsxd | Cmove | Cmovne | Cmovl | Cmovle | Cmovg | Cmovge | Cmovb
        | Cmovbe | Cmova | Cmovae | Cmovs | Cmovns | Cmovp | Cmovnp | Cmovo | Cmovno | Xchg => {
            "mov".into()
        }
        Add | Sub | Imul | Xor | And | Or | Shl | Shr | Sar | Inc | Dec | Neg | Not | Adc | Sbb
        | Mul | Div | Idiv => "arith".into(),
        Cmp | Test => "cmp".into(),
        Lea => "lea".into(),
        Call => "call".into(),
        Ret => "ret".into(),
        Push | Pushfq => "push".into(),
        Pop | Popfq => "pop".into(),
        Nop | Pause | Int3 => "nop".into(),
        _ if format!("{m:?}").starts_with('J') => "jcc".into(),
        _ if format!("{m:?}").starts_with("Set") => "set".into(),
        other => format!("other:{other:?}"),
    }
}

fn feature_tokens(bytes: &[u8], addr: u64) -> (Vec<String>, usize, usize, usize, bool) {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut mnemonics = Vec::new();
    let mut blocks = 1usize;
    let mut calls = 0usize;
    let mut branch_targets = std::collections::BTreeSet::new();
    for insn in decoder.iter() {
        mnemonics.push(insn.mnemonic());
        match insn.flow_control() {
            iced_x86::FlowControl::Call => {
                calls += 1;
            }
            iced_x86::FlowControl::ConditionalBranch
            | iced_x86::FlowControl::UnconditionalBranch => {
                branch_targets.insert(insn.next_ip());
            }
            _ => {}
        }
        if branch_targets.contains(&insn.ip()) && mnemonics.len() > 1 {
            blocks += 1;
        }
    }
    let is_thunk = mnemonics.len() <= 2
        && mnemonics
            .iter()
            .all(|m| matches!(m, iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Ret));
    let families: Vec<String> = mnemonics.iter().map(|m| family(*m)).collect();
    let mut tokens = Vec::new();
    // Family unigrams + bigrams: the opt-stable structural skeleton.
    for f in &families {
        tokens.push(format!("f1:{f}"));
    }
    for w in families.windows(2) {
        tokens.push(format!("f2:{}:{}", w[0], w[1]));
    }
    // Instruction-mix histogram buckets.
    let counts = [
        mnemonics
            .iter()
            .filter(|m| format!("{m:?}").starts_with("Mov"))
            .count(),
        mnemonics
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    iced_x86::Mnemonic::Add
                        | iced_x86::Mnemonic::Sub
                        | iced_x86::Mnemonic::Imul
                        | iced_x86::Mnemonic::Xor
                        | iced_x86::Mnemonic::And
                        | iced_x86::Mnemonic::Or
                        | iced_x86::Mnemonic::Shl
                        | iced_x86::Mnemonic::Shr
                        | iced_x86::Mnemonic::Sar
                )
            })
            .count(),
        mnemonics
            .iter()
            .filter(|m| matches!(m, iced_x86::Mnemonic::Cmp | iced_x86::Mnemonic::Test))
            .count(),
        mnemonics
            .iter()
            .filter(|m| format!("{m:?}").starts_with('J'))
            .count(),
        mnemonics
            .iter()
            .filter(|m| matches!(m, iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Ret))
            .count(),
        mnemonics
            .iter()
            .filter(|m| format!("{m:?}").starts_with("Push") || format!("{m:?}").starts_with("Pop"))
            .count(),
    ];
    for (i, c) in counts.iter().enumerate() {
        tokens.push(format!("mix{i}:{}", bucket(*c)));
    }
    tokens.push(format!("blocks:{}", bucket(blocks)));
    tokens.push(format!("calls:{}", bucket(calls)));
    tokens.push(format!("insns:{}", bucket(mnemonics.len())));
    (tokens, mnemonics.len(), blocks, calls, is_thunk)
}

fn bucket(n: usize) -> usize {
    match n {
        0 => 0,
        1..=2 => 1,
        3..=5 => 2,
        6..=10 => 3,
        11..=20 => 4,
        21..=40 => 5,
        _ => 6,
    }
}

/// Simhash: each token votes ±1 per bit of its SHA-256; positive bits win.
pub fn signature(tokens: &[String]) -> [u8; SIGNATURE_BITS / 8] {
    let mut votes = [0i32; SIGNATURE_BITS];
    for t in tokens {
        let h = Sha256::digest(t.as_bytes());
        for bit in 0..SIGNATURE_BITS {
            let byte = h[bit / 8];
            let on = (byte >> (bit % 8)) & 1 == 1;
            votes[bit] += if on { 1 } else { -1 };
        }
    }
    let mut sig = [0u8; SIGNATURE_BITS / 8];
    for bit in 0..SIGNATURE_BITS {
        if votes[bit] > 0 {
            sig[bit / 8] |= 1 << (bit % 8);
        }
    }
    sig
}

/// Hamming similarity in [0,1] (kept for banding/tests).
pub fn similarity(a: &[u8; SIGNATURE_BITS / 8], b: &[u8; SIGNATURE_BITS / 8]) -> f64 {
    let dist: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum();
    1.0 - dist as f64 / SIGNATURE_BITS as f64
}

/// Jaccard similarity over sorted deduplicated token hashes.
pub fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (mut i, mut j, mut inter) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - inter;
    if union == 0 {
        1.0
    } else {
        inter as f64 / union as f64
    }
}

/// Disassemble one function span and extract its features.
pub fn features_for(code: &[u8], span_file_offset: u64) -> FunctionFeatures {
    let (tokens, insn_count, block_estimate, call_count, is_thunk) =
        feature_tokens(code, span_file_offset);
    let mut token_hashes: Vec<u64> = tokens
        .iter()
        .map(|t| {
            let h = Sha256::digest(t.as_bytes());
            u64::from_le_bytes(h[..8].try_into().unwrap())
        })
        .collect();
    token_hashes.sort_unstable();
    token_hashes.dedup();
    FunctionFeatures {
        signature: signature(&tokens),
        token_hashes,
        insn_count,
        block_estimate,
        call_count,
        is_thunk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_of(code: &[u8]) -> [u8; 32] {
        features_for(code, 0).signature
    }

    #[test]
    fn identical_code_identical_signature() {
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x89, 0xd1, 0x01, 0xca, 0x89, 0xc8, 0x5d, 0xc3,
        ];
        assert_eq!(sig_of(&code), sig_of(&code));
        assert_eq!(similarity(&sig_of(&code), &sig_of(&code)), 1.0);
    }

    #[test]
    fn immediates_do_not_change_signature() {
        // mov ecx, 5; add ecx, eax / mov ecx, 99; add ecx, eax — same shape.
        let a = [0xb9, 0x05, 0x00, 0x00, 0x00, 0x01, 0xc1, 0x89, 0xc8, 0xc3];
        let b = [0xb9, 0x63, 0x00, 0x00, 0x00, 0x01, 0xc1, 0x89, 0xc8, 0xc3];
        assert_eq!(
            sig_of(&a),
            sig_of(&b),
            "mnemonic tokens abstract immediates"
        );
    }

    #[test]
    fn different_code_scores_lower() {
        let a = [
            0x55, 0x48, 0x89, 0xe5, 0x89, 0xd1, 0x01, 0xca, 0x89, 0xc8, 0x5d, 0xc3,
        ];
        let b = [
            0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0xf7, 0xd0, 0x83, 0xc0, 0x2a, 0x5d, 0xc3,
        ];
        let sim = similarity(&sig_of(&a), &sig_of(&b));
        assert!(
            sim < 1.0 && sim > 0.5,
            "related-ish functions score mid: {sim}"
        );
    }

    #[test]
    fn thunk_is_not_significant() {
        let thunk = [0xe9, 0x01, 0x00, 0x00, 0x00]; // jmp rel32
        let f = features_for(&thunk, 0);
        assert!(f.is_thunk);
        assert!(!is_significant(&f));
    }
}
