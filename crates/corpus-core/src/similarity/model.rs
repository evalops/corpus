//! Versioned similarity model: thresholds and weights live here, and the
//! model version is stored on every edge (spec 16.4, 28.5).
//!
//! Semantic function-match thresholds and strong/weak coverage cutoffs are
//! part of this configuration. The design doc must quote the same values
//! (see `tests::design_doc_matches_model_config`).

pub const MODEL_VERSION: &str = "similarity-model:v1";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelConfig {
    /// Minimum ssdeep score (0-100) for a `byte_similar` lead edge.
    pub byte_similar_min_score: i32,
    /// Byte-similar candidates must be within this size ratio of the
    /// reference artifact.
    pub size_ratio_max: f64,
    /// Maximum entropy distance for a byte_similar edge (evidence gate).
    pub entropy_delta_max: f64,
    /// Jaccard match threshold τ for a significant function pair.
    pub semantic_match_tau: f64,
    /// Minimum bidirectional coverage for a weak semantic edge.
    pub semantic_weak_coverage: f64,
    /// Minimum bidirectional coverage for a strong semantic edge.
    pub semantic_strong_coverage: f64,
    /// Minimum one-to-one matched function pairs for a strong edge.
    pub semantic_strong_min_pairs: usize,
    /// High-entropy code-section gate for packed/virtualized triage.
    pub packed_entropy_limit: f64,
    /// Minimum instruction count for a significant function.
    pub significance_min_insns: usize,
}

/// Authoritative model v1 configuration. Existing edges under
/// `similarity-model:v1` / `semantic:v1` were produced with these values;
/// changing them requires a model-version bump and re-analysis.
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

/// Edge types (spec 16.4). Weak edges never merge variant groups.
pub mod edge_type {
    pub const EXACT_COPY: &str = "exact_copy";
    pub const NORMALIZED_EQUIVALENT: &str = "normalized_equivalent";
    pub const BYTE_SIMILAR: &str = "byte_similar";
    pub const SHARED_PROVENANCE: &str = "shared_provenance";
    pub const SEMANTIC_STRONG: &str = "semantic_variant_strong";
    pub const SEMANTIC_WEAK: &str = "semantic_variant_weak";
}

/// Strong edges form variant groups; weak edges stay searchable leads.
pub fn merges_groups(edge_type: &str) -> bool {
    matches!(
        edge_type,
        edge_type::EXACT_COPY | edge_type::NORMALIZED_EQUIVALENT | edge_type::SEMANTIC_STRONG
    )
}

/// Classify a coverage result into a semantic edge type, or `None`.
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

/// Stable digest of the model configuration for analysis receipts.
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
