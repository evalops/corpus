//! Similarity feature extraction, typed edges, and variant groups
//! (spec 16, M3a slice).
//!
//! # Layers
//!
//! | Module | Role |
//! |--------|------|
//! | [`extract`] / [`fuzzy`] / [`lsh`] | Byte-level features, ssdeep, LSH bands |
//! | [`model`] | Versioned thresholds + edge type taxonomy |
//! | [`analyzers`] | Capability registry (name@version, formats, digests) |
//! | [`edges`] | Typed edge insert + variant-group union |
//! | [`neighborhood`] | Bounded BFS graph query for analysts |
//! | [`export`] | JSON / DOT / GraphML of neighborhoods & groups |
//! | [`receipts`] | Deterministic analysis audit records (no sample bytes) |
//! | [`invalidation`] | Soft supersession of edges under old model versions |
//! | [`lifecycle`] | Retention cleanup of derived rows + group repair |
//! | [`contract_tests`] | Malformed-binary bounds (test-only) |
//!
//! Function-level (semantic) matching lives in [`crate::semantic`].

pub mod analyzers;
pub mod edges;
pub mod export;
pub mod extract;
pub mod fuzzy;
pub mod invalidation;
pub mod lifecycle;
pub mod lsh;
pub mod model;
pub mod neighborhood;
pub mod receipts;
pub mod testutil;

#[cfg(test)]
mod contract_tests;
