//! Shared types and server-side domain logic for the corpus platform.
//!
//! # Crate layout
//!
//! | Area | Modules |
//! |------|---------|
//! | Ingest & identity | [`ingest`], [`cas`], [`hash`], [`classify`], [`tenant`] |
//! | Agents | [`agents`], [`mtls`], [`auth`] |
//! | Detection | [`rules`], [`registry`], [`scan`], [`sandbox`], [`hunts`], [`detect`] |
//! | Similarity | [`similarity`], [`semantic`] |
//! | Analyst | [`analyst`], [`report`], [`investigate`], [`opinions`], [`intel`] |
//! | Ops | [`continuous`], [`triggers`], [`metrics`], [`detonate`], [`oci`], [`merlin`] |
//!
//! # Write ownership
//!
//! `corpus-server` owns all durable writes (Postgres + CAS). `corpusctl`
//! reuses pure client pieces (hashing, classification, DTOs). The endpoint
//! agent lives in `corpus-agent` and talks to the server over HTTP/mTLS.
//!
//! # Multi-tenancy
//!
//! Almost every table is keyed by `tenant_id`. Requests without
//! `X-Corpus-Tenant` resolve to [`DEFAULT_TENANT`].
//!
//! # Engine version
//!
//! [`ENGINE_VERSION`] is folded into rule-bundle digests so engine upgrades
//! invalidate prior scan caches (spec 14 / 15.4).

pub mod agents;
pub mod analyst;
pub mod auth;
pub mod cas;
pub mod classify;
pub mod continuous;
pub mod db;
pub mod detect;
pub mod detonate;
pub mod dto;
pub mod error;
pub mod hash;
pub mod hunts;
pub mod ingest;
pub mod intel;
pub mod investigate;
pub mod merlin;
pub mod metrics;
pub mod mtls;
pub mod oci;
pub mod opinions;
pub mod registry;
pub mod report;
pub mod rules;
pub mod sandbox;
pub mod scan;
pub mod semantic;
pub mod similarity;
pub mod tenant;
pub mod triggers;

use uuid::Uuid;

/// Well-known default tenant (slug `default`), seeded by migration.
/// Requests without an `X-Corpus-Tenant` header resolve here.
pub const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

/// YARA-X engine identity folded into bundle digests and scan cache keys.
pub const ENGINE_VERSION: &str = concat!("yara-x-", env!("CORPUS_YARA_X_VERSION"));
