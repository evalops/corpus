//! Versioned similarity model: thresholds and weights live here, and the
//! model version is stored on every edge (spec 16.4, 28.5).

pub const MODEL_VERSION: &str = "similarity-model:v1";

#[derive(Debug, Clone, Copy)]
pub struct ModelConfig {
    /// Minimum ssdeep score (0-100) for a `byte_similar` lead edge.
    pub byte_similar_min_score: i32,
    /// Byte-similar candidates must be within this size ratio of the
    /// reference artifact.
    pub size_ratio_max: f64,
    /// Maximum entropy distance for a byte_similar edge (evidence gate).
    pub entropy_delta_max: f64,
}

pub const MODEL_V1: ModelConfig = ModelConfig {
    byte_similar_min_score: 40,
    size_ratio_max: 4.0,
    entropy_delta_max: 2.0,
};

/// Edge types (spec 16.4). Weak edges never merge variant groups.
pub mod edge_type {
    pub const EXACT_COPY: &str = "exact_copy";
    pub const NORMALIZED_EQUIVALENT: &str = "normalized_equivalent";
    pub const BYTE_SIMILAR: &str = "byte_similar";
    pub const SHARED_PROVENANCE: &str = "shared_provenance";
    // Plugin slot, unpopulated in M3a (spec 16.5 / Ghidra BSim).
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
}
