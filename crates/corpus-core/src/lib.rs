//! Shared types and server-side domain logic for the corpus platform.
//!
//! `corpus-server` owns all writes; `corpusctl` reuses only the pure
//! client-side pieces (hashing, classification, DTOs).

pub mod cas;
pub mod classify;
pub mod db;
pub mod dto;
pub mod error;
pub mod hash;
pub mod hunts;
pub mod ingest;
pub mod registry;
pub mod report;
pub mod rules;
pub mod scan;

use uuid::Uuid;

/// M0 is single-tenant; every request that does not carry an explicit
/// `X-Corpus-Tenant` header is scoped to this tenant.
pub const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

pub const ENGINE_VERSION: &str = concat!("yara-x-", env!("CORPUS_YARA_X_VERSION"));
