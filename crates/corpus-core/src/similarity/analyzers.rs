//! Versioned analyzer registry for similarity and semantic extractors.
//!
//! # Problem
//!
//! Feature rows, function signatures, and edges all carry a `version`
//! string (e.g. `semantic:v1`, `similarity-model:v1`). Without a central
//! registry, operators cannot answer:
//!
//! - Which analyzers exist and what do they produce?
//! - Is a stored version still active or retired?
//! - What formats / architectures does an analyzer support?
//! - What config digest was baked into a given model version?
//!
//! Capability discovery and controlled migrations should not require
//! reading source history.
//!
//! # Model
//!
//! An [`AnalyzerInfo`] is a static capability declaration keyed by
//! `(name, version)`. The in-process [`AnalyzerRegistry`] is populated
//! once via [`global`] / [`built_in_registry`].
//!
//! Lookups **fail closed**:
//!
//! - Unknown name/version → `Error::BadRequest`
//! - Known but [`AnalyzerStatus::Retired`] → `Error::BadRequest` with
//!   a retire message (callers must pick an active version)
//!
//! Analysis entry points (`semantic::edges::analyze_and_link`) call
//! [`resolve`] before work so a retired analyzer cannot silently run.
//!
//! # Built-in analyzers (v1)
//!
//! | Name | Version const | Families |
//! |------|---------------|----------|
//! | `byte-feature-extractor` | `EXTRACTOR_VERSION` | byte, normalized, structural, provenance |
//! | `semantic-function` | `SEMANTIC_EXTRACTOR_VERSION` | semantic (x86_64) |
//! | `similarity-model` | `MODEL_VERSION` | edge classification / thresholds |
//!
//! All three share a `config_digest` derived from [`MODEL_V1`] via
//! [`model_config_digest`] so receipts can prove threshold identity.
//!
//! # Non-goals
//!
//! - Dynamic plugin loading (registry is compile-time / process-static).
//! - Per-tenant analyzer enablement (global process config only).

use crate::error::{Error, Result};
use crate::semantic::edges::SEMANTIC_EXTRACTOR_VERSION;
use crate::similarity::extract::EXTRACTOR_VERSION;
use crate::similarity::model::{model_config_digest, MODEL_V1, MODEL_VERSION};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Capability declaration for one analyzer implementation.
///
/// Fields use `'static` data where possible so the built-in registry
/// can be constructed without allocation of name/format tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerInfo {
    /// Stable name, e.g. `byte-feature-extractor` or `semantic-function`.
    pub name: &'static str,
    /// Version string persisted on feature/function/edge rows.
    pub version: &'static str,
    /// Formats this analyzer may run on (`pe`, `elf`, `macho`, `*`).
    pub formats: &'static [&'static str],
    /// Architectures this analyzer may run on (`x86_64`, `aarch64`, `*`).
    pub architectures: &'static [&'static str],
    /// Feature families produced (`byte`, `normalized`, `semantic`, …).
    pub feature_families: &'static [&'static str],
    /// Whether re-running over existing artifacts is safe and idempotent.
    pub supports_backfill: bool,
    /// Digest of configuration that affects output identity.
    ///
    /// For model-coupled analyzers this is [`model_config_digest`]; it
    /// lets receipts prove which thresholds produced an edge.
    pub config_digest: String,
    /// Human-readable status for capability discovery.
    pub status: AnalyzerStatus,
}

/// Lifecycle state of a registered analyzer version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerStatus {
    /// Safe to invoke for new analysis and backfill.
    Active,
    /// Still listed for archaeology; [`AnalyzerRegistry::lookup`] rejects it.
    Retired,
}

/// Lookup key: name + version (owned strings for flexible query APIs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnalyzerKey {
    pub name: String,
    pub version: String,
}

impl AnalyzerKey {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// In-process registry of known analyzers.
///
/// Uses a [`BTreeMap`] so [`list`] / [`list_ids`] are deterministically
/// ordered (stable API responses and tests).
#[derive(Debug, Default)]
pub struct AnalyzerRegistry {
    by_key: BTreeMap<AnalyzerKey, AnalyzerInfo>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace an analyzer under its `(name, version)` key.
    pub fn register(&mut self, info: AnalyzerInfo) {
        let key = AnalyzerKey::new(info.name, info.version);
        self.by_key.insert(key, info);
    }

    /// Resolve an active analyzer or return a closed-form error.
    ///
    /// Retired analyzers are distinguishable from unknown ones in the
    /// error message so operators know whether to re-register or migrate.
    pub fn lookup(&self, name: &str, version: &str) -> Result<&AnalyzerInfo> {
        let key = AnalyzerKey::new(name, version);
        match self.by_key.get(&key) {
            Some(info) if info.status == AnalyzerStatus::Active => Ok(info),
            Some(info) if info.status == AnalyzerStatus::Retired => Err(Error::BadRequest(
                format!("analyzer {name}@{version} is retired; pick an active version"),
            )),
            _ => Err(Error::BadRequest(format!(
                "unknown analyzer {name}@{version}; known: {}",
                self.list_ids().join(", ")
            ))),
        }
    }

    /// Resolve by the version string stored on rows (e.g. `semantic:v1`).
    ///
    /// Useful when only the persisted version id is available (no name).
    /// Does **not** enforce Active status — use [`lookup`] when invoking.
    pub fn lookup_by_version_id(&self, version_id: &str) -> Result<&AnalyzerInfo> {
        self.by_key
            .values()
            .find(|i| i.version == version_id)
            .ok_or_else(|| Error::BadRequest(format!("unknown analyzer version {version_id}")))
    }

    /// All registered analyzers (active and retired), key order.
    pub fn list(&self) -> Vec<&AnalyzerInfo> {
        self.by_key.values().collect()
    }

    /// `name@version` strings for error messages and capability lists.
    pub fn list_ids(&self) -> Vec<String> {
        self.by_key
            .values()
            .map(|i| format!("{}@{}", i.name, i.version))
            .collect()
    }

    /// Active analyzers only (what new analysis may select).
    pub fn active(&self) -> Vec<&AnalyzerInfo> {
        self.by_key
            .values()
            .filter(|i| i.status == AnalyzerStatus::Active)
            .collect()
    }
}

/// Built-in registry populated at first use (process-wide singleton).
pub fn global() -> &'static AnalyzerRegistry {
    static REG: OnceLock<AnalyzerRegistry> = OnceLock::new();
    REG.get_or_init(built_in_registry)
}

/// Construct the default registry with current extractors and model.
///
/// Exposed separately from [`global`] so tests can inspect a fresh copy
/// without mutating the process singleton.
pub fn built_in_registry() -> AnalyzerRegistry {
    let mut reg = AnalyzerRegistry::new();
    let cfg_digest = model_config_digest(&MODEL_V1);

    reg.register(AnalyzerInfo {
        name: "byte-feature-extractor",
        version: EXTRACTOR_VERSION,
        formats: &["pe", "elf", "macho", "unknown"],
        architectures: &["*"],
        feature_families: &["byte", "normalized", "structural", "provenance"],
        supports_backfill: true,
        config_digest: cfg_digest.clone(),
        status: AnalyzerStatus::Active,
    });

    reg.register(AnalyzerInfo {
        name: "semantic-function",
        version: SEMANTIC_EXTRACTOR_VERSION,
        formats: &["pe", "elf", "macho"],
        // AArch64 is a planned follow-up (issue #18); claim only x86_64.
        architectures: &["x86_64"],
        feature_families: &["semantic"],
        supports_backfill: true,
        config_digest: cfg_digest.clone(),
        status: AnalyzerStatus::Active,
    });

    reg.register(AnalyzerInfo {
        name: "similarity-model",
        version: MODEL_VERSION,
        formats: &["*"],
        architectures: &["*"],
        feature_families: &["edge"],
        supports_backfill: true,
        config_digest: cfg_digest,
        status: AnalyzerStatus::Active,
    });

    reg
}

/// Convenience: resolve against the process-global registry or fail closed.
pub fn resolve(name: &str, version: &str) -> Result<&'static AnalyzerInfo> {
    global().lookup(name, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_lookup_succeeds() {
        let reg = built_in_registry();
        let info = reg
            .lookup("semantic-function", SEMANTIC_EXTRACTOR_VERSION)
            .unwrap();
        assert_eq!(info.architectures, &["x86_64"]);
        assert!(info.supports_backfill);
        assert!(!info.config_digest.is_empty());
    }

    #[test]
    fn unknown_version_fails_closed() {
        let reg = built_in_registry();
        let err = reg
            .lookup("semantic-function", "semantic:v999")
            .unwrap_err();
        assert!(err.to_string().contains("unknown analyzer"));
    }

    #[test]
    fn retired_fails_closed() {
        let mut reg = AnalyzerRegistry::new();
        reg.register(AnalyzerInfo {
            name: "legacy",
            version: "legacy:v0",
            formats: &["*"],
            architectures: &["*"],
            feature_families: &[],
            supports_backfill: false,
            config_digest: "x".into(),
            status: AnalyzerStatus::Retired,
        });
        let err = reg.lookup("legacy", "legacy:v0").unwrap_err();
        assert!(err.to_string().contains("retired"));
    }

    #[test]
    fn lookup_by_version_id() {
        let reg = built_in_registry();
        let info = reg.lookup_by_version_id(EXTRACTOR_VERSION).unwrap();
        assert_eq!(info.name, "byte-feature-extractor");
    }

    #[test]
    fn global_is_stable() {
        let a = global().list_ids();
        let b = global().list_ids();
        assert_eq!(a, b);
        assert!(a.iter().any(|s| s.contains("semantic-function")));
    }
}
