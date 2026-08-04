//! Semantic (function-level) similarity without Ghidra (spec 16.2, 16.5).
//!
//! # Modules
//!
//! | Module | Role |
//! |--------|------|
//! | [`extract`] | Recover code sections and function spans from PE/ELF/Mach-O |
//! | [`features`] | Mnemonic-family tokens, Jaccard, significance filter |
//! | [`triage`] | Packed/virtualized signals that **block** confident edges |
//! | [`suppress`] | Drop ubiquitous CRT/runtime functions before scoring |
//! | [`func_index`] | Tenant-scoped function-band candidate index |
//! | [`edges`] | Extract → match → emit strong/weak edges + evidence API |
//! | [`fixtures`] | Test binaries / helpers |
//!
//! Thresholds and edge classification live in
//! [`crate::similarity::model`]. Design and limits:
//! `docs/semantic-similarity-design.md`.

pub mod edges;
pub mod extract;
pub mod features;
pub mod fixtures;
pub mod func_index;
pub mod suppress;
pub mod triage;
