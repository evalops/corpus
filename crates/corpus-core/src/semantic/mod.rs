//! Semantic (function-level) similarity without Ghidra (spec 16.2,
//! 16.5). See docs/semantic-similarity-design.md for the design and the
//! honest limits.

pub mod edges;
pub mod extract;
pub mod features;
pub mod fixtures;
pub mod func_index;
pub mod suppress;
pub mod triage;
