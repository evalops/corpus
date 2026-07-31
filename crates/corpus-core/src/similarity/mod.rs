//! Similarity feature extraction, typed edges, and variant groups
//! (spec 16, M3a slice). BSim/semantic slots exist in the schema but are
//! unpopulated — a documented plugin point, not this slice.

pub mod edges;
pub mod extract;
pub mod fuzzy;
pub mod model;
pub mod testutil;
