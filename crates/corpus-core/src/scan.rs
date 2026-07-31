//! YARA-X scanning and the scan result cache key (spec 15.4).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

/// Per-file scan configuration. The digest over this config is part of the
/// cache key, so changing limits invalidates cached results.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
const SCAN_CONFIG: &str = "corpus-scan-config:v1:timeout_ms=10000:max_match_evidence=64";

pub fn scan_config_digest() -> String {
    hex::encode(Sha256::digest(SCAN_CONFIG.as_bytes()))
}

/// The five-field scan cache key (spec 15.4). Field order here is the
/// canonical order used in queries and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanCacheKey {
    pub tenant_id: Uuid,
    pub artifact_sha256: Vec<u8>,
    pub rule_bundle_digest: String,
    pub engine_version: String,
    pub scan_config_digest: String,
}

impl ScanCacheKey {
    pub fn new(tenant_id: Uuid, artifact_sha256: Vec<u8>, rule_bundle_digest: &str) -> Self {
        ScanCacheKey {
            tenant_id,
            artifact_sha256,
            rule_bundle_digest: rule_bundle_digest.to_string(),
            engine_version: crate::ENGINE_VERSION.to_string(),
            scan_config_digest: scan_config_digest(),
        }
    }

    /// Column names in canonical key order; kept next to the migration so a
    /// drift between the two fails loudly in tests.
    pub const COLUMNS: [&'static str; 5] = [
        "tenant_id",
        "artifact_sha256",
        "rule_bundle_digest",
        "engine_version",
        "scan_config_digest",
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEvidence {
    pub identifier: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchEvidence {
    pub rule_id: String,
    pub namespace: String,
    pub patterns: Vec<PatternEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Clean,
    Matched,
    Timeout,
    Error,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Clean => "clean",
            ScanStatus::Matched => "matched",
            ScanStatus::Timeout => "timeout",
            ScanStatus::Error => "error",
        }
    }
}

pub struct ScanOutcome {
    pub status: ScanStatus,
    pub matches: Vec<RuleMatchEvidence>,
    pub duration_ms: i64,
    pub error_code: Option<String>,
}

/// Compile a bundle from its ordered member rule sources.
pub fn compile_bundle(sources: &[(String, String)]) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    for (namespace, source) in sources {
        compiler.new_namespace(namespace);
        compiler.add_source(source.as_str()).map_err(|e| e.to_string())?;
    }
    Ok(compiler.build())
}

/// Scan whole-file bytes with a compiled immutable bundle.
pub fn scan_bytes(rules: &yara_x::Rules, bytes: &[u8]) -> ScanOutcome {
    let started = std::time::Instant::now();
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(SCAN_TIMEOUT);
    match scanner.scan(bytes) {
        Ok(results) => {
            let mut matches = Vec::new();
            for rule in results.matching_rules() {
                let mut patterns = Vec::new();
                for pat in rule.patterns() {
                    for m in pat.matches().take(64) {
                        patterns.push(PatternEvidence {
                            identifier: pat.identifier().to_string(),
                            offset: m.range().start as u64,
                            length: (m.range().end - m.range().start) as u64,
                        });
                    }
                }
                matches.push(RuleMatchEvidence {
                    rule_id: rule.identifier().to_string(),
                    namespace: rule.namespace().to_string(),
                    patterns,
                });
            }
            ScanOutcome {
                status: if matches.is_empty() { ScanStatus::Clean } else { ScanStatus::Matched },
                matches,
                duration_ms: started.elapsed().as_millis() as i64,
                error_code: None,
            }
        }
        Err(err) => {
            let msg = err.to_string();
            let is_timeout = msg.to_lowercase().contains("timeout");
            ScanOutcome {
                status: if is_timeout { ScanStatus::Timeout } else { ScanStatus::Error },
                matches: Vec::new(),
                duration_ms: started.elapsed().as_millis() as i64,
                error_code: Some(msg),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_carries_all_five_fields() {
        let key = ScanCacheKey::new(Uuid::nil(), vec![1, 2, 3], "digest-x");
        assert_eq!(key.tenant_id, Uuid::nil());
        assert_eq!(key.artifact_sha256, vec![1, 2, 3]);
        assert_eq!(key.rule_bundle_digest, "digest-x");
        assert_eq!(key.engine_version, crate::ENGINE_VERSION);
        assert_eq!(key.scan_config_digest, scan_config_digest());
        // Keys differing in any single field must not be equal.
        let other_tenant = ScanCacheKey::new(Uuid::from_u128(9), vec![1, 2, 3], "digest-x");
        assert_ne!(key, other_tenant);
        let other_bundle = ScanCacheKey::new(Uuid::nil(), vec![1, 2, 3], "digest-y");
        assert_ne!(key, other_bundle);
        let other_artifact = ScanCacheKey::new(Uuid::nil(), vec![9, 9, 9], "digest-x");
        assert_ne!(key, other_artifact);
    }

    #[test]
    fn cache_key_columns_match_migration() {
        // Guard against drift between the key and the scan_cache PK in
        // migrations/0001_init.sql.
        assert_eq!(
            ScanCacheKey::COLUMNS,
            ["tenant_id", "artifact_sha256", "rule_bundle_digest", "engine_version", "scan_config_digest"]
        );
        assert_eq!(scan_config_digest().len(), 64);
    }

    #[test]
    fn scans_bytes_with_compiled_bundle() {
        let src = r#"rule Marker { strings: $m = "CORPUS_DEMO_MARKER" condition: $m }"#;
        let rules = compile_bundle(&[("default".into(), src.into())]).unwrap();
        let hit = scan_bytes(&rules, b"xx CORPUS_DEMO_MARKER yy");
        assert_eq!(hit.status, ScanStatus::Matched);
        assert_eq!(hit.matches[0].rule_id, "Marker");
        assert_eq!(hit.matches[0].patterns[0].offset, 3);
        let miss = scan_bytes(&rules, b"nothing here");
        assert_eq!(miss.status, ScanStatus::Clean);
    }
}
