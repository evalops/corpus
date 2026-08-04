//! Versioned similarity model: thresholds and weights live here, and the
//! model version is stored on every edge (spec 16.4, 28.5).
//!
//! # Single source of truth
//!
//! All numeric policy for byte similarity, semantic matching, and packed
//! triage is centralized in [`MODEL_V1`]. Downstream modules re-export
//! individual fields for convenience (e.g. `semantic::features::MATCH_TAU`)
//! but **must not** hard-code different numbers.
//!
//! The design doc `docs/semantic-similarity-design.md` is tested against
//! this config (`tests::design_doc_matches_model_config`). If you change
//! a threshold, update the doc in the same commit or CI fails.
//!
//! # Versioning discipline
//!
//! Existing edges under `similarity-model:v1` / `semantic:v1` were
//! produced with these exact values. Changing thresholds **requires**:
//!
//! 1. A new `MODEL_VERSION` string (e.g. `similarity-model:v2`).
//! 2. Re-analysis (or dual-write) under the new version.
//! 3. Optional supersession of old edges via
//!    [`crate::similarity::invalidation`].
//!
//! In-place mutation of historical edges is forbidden.
//!
//! # Strong vs weak edges
//!
//! Spec 28.5: fuzzy hash and weak semantic edges are **searchable leads**
//! only. Only exact, normalized-equivalent, and strong semantic edges
//! merge variant groups ([`merges_groups`]).

/// Persisted model identity on every `similarity_edge.model_version`.
pub const MODEL_VERSION: &str = "similarity-model:v1";

/// Authoritative knobs for one model version.
///
/// Fields are `Copy` so call sites can pass `&MODEL_V1` without cloning.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelConfig {
    /// Minimum ssdeep score (0–100) for a `byte_similar` lead edge.
    pub byte_similar_min_score: i32,
    /// Byte-similar candidates must be within this size ratio of the
    /// reference artifact (max(size_a, size_b) / min(…)).
    pub size_ratio_max: f64,
    /// Maximum entropy distance for a byte_similar edge (evidence gate).
    pub entropy_delta_max: f64,
    /// Jaccard match threshold τ for a significant function pair.
    ///
    /// Pairs with score ≥ τ become candidates for one-to-one greedy
    /// assignment in `semantic::edges::coverage`.
    pub semantic_match_tau: f64,
    /// Minimum bidirectional coverage for a weak semantic edge.
    /// Coverage = matched_pairs / |functions| after suppression.
    pub semantic_weak_coverage: f64,
    /// Minimum bidirectional coverage for a strong semantic edge.
    pub semantic_strong_coverage: f64,
    /// Minimum one-to-one matched function pairs for a strong edge.
    ///
    /// High coverage with only 1–2 pairs is treated as weak to avoid
    /// group merges from a single shared CRT-like leftover.
    pub semantic_strong_min_pairs: usize,
    /// High-entropy code-section gate for packed/virtualized triage
    /// (bits per byte, Shannon).
    pub packed_entropy_limit: f64,
    /// Minimum instruction count for a significant function.
    pub significance_min_insns: usize,
}

/// Authoritative model v1 configuration.
///
/// Hand-set for mnemonic-family Jaccard; **uncalibrated** (issue #16).
/// Do not tweak without a version bump.
pub const MODEL_V1: ModelConfig = ModelConfig {
    byte_similar_min_score: 40,
    size_ratio_max: 4.0,
    entropy_delta_max: 2.0,
    // Hand-set for mnemonic-family Jaccard; uncalibrated (issue #16).
    semantic_match_tau: 0.35,
    semantic_weak_coverage: 0.35,
    semantic_strong_coverage: 0.60,
    semantic_strong_min_pairs: 3,
    packed_entropy_limit: 7.2,
    significance_min_insns: 5,
};

/// Edge type string constants (spec 16.4).
///
/// Weak edges (`BYTE_SIMILAR`, `SHARED_PROVENANCE`, `SEMANTIC_WEAK`) never
/// merge variant groups.
pub mod edge_type {
    pub const EXACT_COPY: &str = "exact_copy";
    pub const NORMALIZED_EQUIVALENT: &str = "normalized_equivalent";
    pub const BYTE_SIMILAR: &str = "byte_similar";
    pub const SHARED_PROVENANCE: &str = "shared_provenance";
    pub const SEMANTIC_STRONG: &str = "semantic_variant_strong";
    pub const SEMANTIC_WEAK: &str = "semantic_variant_weak";
}

/// Whether this edge type should union the two artifacts' variant groups.
///
/// Spec 28.5: fuzzy hash alone never creates automatic family membership.
pub fn merges_groups(edge_type: &str) -> bool {
    matches!(
        edge_type,
        edge_type::EXACT_COPY | edge_type::NORMALIZED_EQUIVALENT | edge_type::SEMANTIC_STRONG
    )
}

/// Classify bidirectional coverage into a semantic edge type, or `None`.
///
/// Strong requires both directions ≥ `semantic_strong_coverage` **and**
/// at least `semantic_strong_min_pairs` matched pairs. Weak requires both
/// directions ≥ `semantic_weak_coverage` (pair floor not applied). Below
/// weak thresholds, no edge is emitted.
pub fn classify_semantic_edge(
    cfg: &ModelConfig,
    a_to_b: f64,
    b_to_a: f64,
    matched_pairs: usize,
) -> Option<&'static str> {
    if a_to_b >= cfg.semantic_strong_coverage
        && b_to_a >= cfg.semantic_strong_coverage
        && matched_pairs >= cfg.semantic_strong_min_pairs
    {
        Some(edge_type::SEMANTIC_STRONG)
    } else if a_to_b >= cfg.semantic_weak_coverage && b_to_a >= cfg.semantic_weak_coverage {
        Some(edge_type::SEMANTIC_WEAK)
    } else {
        None
    }
}

/// Stable 16-byte hex digest of the model configuration for receipts.
///
/// Any field change changes the digest, so analysis receipts prove which
/// threshold set produced an edge without storing the full struct.
pub fn model_config_digest(cfg: &ModelConfig) -> String {
    use sha2::{Digest, Sha256};
    let payload = format!(
        "byte_similar_min_score={};size_ratio_max={};entropy_delta_max={};\
         semantic_match_tau={};semantic_weak_coverage={};semantic_strong_coverage={};\
         semantic_strong_min_pairs={};packed_entropy_limit={};significance_min_insns={}",
        cfg.byte_similar_min_score,
        cfg.size_ratio_max,
        cfg.entropy_delta_max,
        cfg.semantic_match_tau,
        cfg.semantic_weak_coverage,
        cfg.semantic_strong_coverage,
        cfg.semantic_strong_min_pairs,
        cfg.packed_entropy_limit,
        cfg.significance_min_insns,
    );
    let h = Sha256::digest(payload.as_bytes());
    hex::encode(&h[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_never_merges_groups() {
        // 28.5: fuzzy hash alone never creates automatic family membership.
        assert!(!merges_groups(edge_type::BYTE_SIMILAR));
        assert!(merges_groups(edge_type::SEMANTIC_STRONG));
        assert!(!merges_groups(edge_type::SHARED_PROVENANCE));
        assert!(!merges_groups(edge_type::SEMANTIC_WEAK));
        assert!(merges_groups(edge_type::EXACT_COPY));
        assert!(merges_groups(edge_type::NORMALIZED_EQUIVALENT));
    }

    #[test]
    fn classify_uses_strong_pair_floor() {
        let cfg = MODEL_V1;
        assert_eq!(
            classify_semantic_edge(&cfg, 0.7, 0.7, 2),
            Some(edge_type::SEMANTIC_WEAK),
            "strong coverage without enough pairs stays weak"
        );
        assert_eq!(
            classify_semantic_edge(&cfg, 0.7, 0.7, 3),
            Some(edge_type::SEMANTIC_STRONG)
        );
        assert_eq!(classify_semantic_edge(&cfg, 0.2, 0.2, 10), None);
    }

    #[test]
    fn model_config_digest_is_stable() {
        let a = model_config_digest(&MODEL_V1);
        let b = model_config_digest(&MODEL_V1);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn design_doc_matches_model_config() {
        // Keep docs/semantic-similarity-design.md honest: every threshold
        // listed there must match MODEL_V1. A silent drift fails CI.
        let doc = include_str!("../../../../docs/semantic-similarity-design.md");
        let cfg = MODEL_V1;
        let checks = [
            (
                format!("τ = {}", cfg.semantic_match_tau),
                "match threshold τ",
            ),
            (
                format!("both ≥ {}", cfg.semantic_strong_coverage),
                "strong coverage",
            ),
            (
                format!("≥ {} matched", cfg.semantic_strong_min_pairs),
                "strong min pairs",
            ),
            (
                format!("both ≥ {}", cfg.semantic_weak_coverage),
                "weak coverage",
            ),
            (
                format!("≥{} instructions", cfg.significance_min_insns),
                "significance filter",
            ),
            (
                format!("entropy > {}", cfg.packed_entropy_limit),
                "packed entropy gate",
            ),
        ];
        for (needle, label) in checks {
            assert!(
                doc.contains(&needle),
                "design doc missing {label}: expected substring `{needle}`"
            );
        }
    }
}
