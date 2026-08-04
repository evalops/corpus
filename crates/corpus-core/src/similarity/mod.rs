//! Similarity feature extraction, typed edges, and variant groups
//! (spec 16, M3a slice). Semantic matching lives in `crate::semantic`.

pub mod analyzers;
pub mod edges;
pub mod extract;
pub mod export;
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
