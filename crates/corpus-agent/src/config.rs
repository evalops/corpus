//! Agent configuration file, modeled on the spec 10.9 default policy.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    /// One-time enrollment token. Ignored once the state DB holds an identity.
    #[serde(default)]
    pub enrollment_token: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    pub state_dir: PathBuf,
    pub spool_dir: PathBuf,
    #[serde(default)]
    pub watch: WatchConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Polling interval for the reconciliation/fallback scanner.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    /// Substring or simple `*suffix` / `prefix*` path patterns to exclude.
    #[serde(default)]
    pub exclusions: Vec<String>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        WatchConfig {
            paths: vec![],
            poll_interval_secs: default_poll_interval(),
            debounce_ms: default_debounce_ms(),
            exclusions: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        BaselineConfig { enabled: true }
    }
}

/// Limits from the spec 10.9 default policy (smaller defaults here for dev).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    #[serde(default = "default_max_spool_bytes")]
    pub max_spool_bytes: u64,
    #[serde(default = "default_max_concurrent_reads")]
    pub max_concurrent_reads: usize,
    #[serde(default = "default_stable_read_retries")]
    pub stable_read_retries: u32,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_artifact_bytes: default_max_artifact_bytes(),
            max_spool_bytes: default_max_spool_bytes(),
            max_concurrent_reads: default_max_concurrent_reads(),
            stable_read_retries: default_stable_read_retries(),
            max_attempts: default_max_attempts(),
        }
    }
}

fn default_heartbeat_interval() -> u64 {
    30
}
fn default_poll_interval() -> u64 {
    60
}
fn default_debounce_ms() -> u64 {
    2000
}
fn default_true() -> bool {
    true
}
fn default_max_artifact_bytes() -> u64 {
    268435456 // 256 MiB, spec 10.9
}
fn default_max_spool_bytes() -> u64 {
    4294967296 // 4 GiB, spec 10.9
}
fn default_max_concurrent_reads() -> usize {
    2
}
fn default_stable_read_retries() -> u32 {
    3
}
fn default_max_attempts() -> u32 {
    8
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    /// Digest reported in heartbeats; identifies the local policy revision.
    pub fn policy_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = serde_yaml::to_string(&self.limits).unwrap_or_default()
            + &serde_yaml::to_string(&self.watch).unwrap_or_default();
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// Substring or `*suffix` / `prefix*` pattern matching for exclusions.
pub fn matches_exclusion(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pat| {
        if let Some(suffix) = pat.strip_prefix('*') {
            path.ends_with(suffix)
        } else if let Some(prefix) = pat.strip_suffix('*') {
            path.contains(prefix)
        } else {
            path.contains(pat.as_str())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let yaml = r#"
server_url: http://127.0.0.1:8080
state_dir: ./agent-data/state
spool_dir: ./agent-data/spool
watch:
  paths: [./watch]
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.limits.max_artifact_bytes, 268435456);
        assert_eq!(cfg.limits.stable_read_retries, 3);
        assert_eq!(cfg.watch.paths, vec![PathBuf::from("./watch")]);
        assert!(cfg.baseline.enabled);
    }

    #[test]
    fn exclusions_match() {
        let patterns = vec!["*.tmp".to_string(), "/spool/".to_string()];
        assert!(matches_exclusion(&patterns, "/data/x.tmp"));
        assert!(matches_exclusion(&patterns, "/host/spool/blob1"));
        assert!(!matches_exclusion(&patterns, "/data/real.bin"));
    }
}
