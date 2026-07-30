//! API request/response types shared by server and CLI.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------- tenants ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreateRequest {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantResponse {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// ---------- ingest ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OccurrenceInfo {
    pub host_name: String,
    pub agent_id: Uuid,
    pub boot_id: Uuid,
    pub agent_sequence: i64,
    pub path: String,
    pub observed_at: DateTime<Utc>,
    pub file_size: i64,
    pub file_mtime: Option<DateTime<Utc>>,
    pub capture_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceRequest {
    pub sha256: String,
    pub size_bytes: i64,
    pub occurrence: OccurrenceInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnnounceDisposition {
    AlreadyPresent,
    UploadRequired,
    MetadataOnlyAccepted,
    RejectedPolicy,
    RejectedQuota,
    RetryLater,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceResponse {
    pub disposition: AnnounceDisposition,
    pub upload_id: Option<Uuid>,
    pub artifact_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub upload_id: Uuid,
    pub sha256: String,
    pub size_bytes: i64,
    pub occurrence: OccurrenceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeResponse {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub storage_state: String,
    pub forward_matches: Vec<String>,
}

// ---------- rules & bundles ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCreateRequest {
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponse {
    pub id: Uuid,
    pub namespace: String,
    pub stable_id: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlePublishRequest {
    /// Rule UUIDs to include. Order-independent; the digest is computed
    /// over canonically ordered (namespace, stable_id, source).
    pub rule_ids: Vec<Uuid>,
    /// When true the bundle is activated for forward coverage: every newly
    /// committed artifact is scanned with it post-commit (spec 15.9).
    pub activate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleResponse {
    pub id: Uuid,
    pub digest: String,
    pub scope: String,
    pub engine_version: String,
    pub active: bool,
    pub rule_count: i64,
    pub created_at: DateTime<Utc>,
}

// ---------- hunts ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntCreateRequest {
    pub bundle_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResponse {
    pub id: Uuid,
    pub kind: String,
    pub bundle_digest: String,
    pub state: String,
    pub corpus_watermark: Option<i64>,
    pub planned_artifacts: i64,
    pub scanned: i64,
    pub cache_hits: i64,
    pub matched: i64,
    pub timed_out: i64,
    pub failed: i64,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

// ---------- blast radius ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusArtifact {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub size_bytes: i64,
    pub artifact_class: String,
    pub first_committed_at: DateTime<Utc>,
    pub matched_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusOccurrence {
    pub artifact_sha256: String,
    pub host_name: String,
    pub path: Option<String>,
    pub capture_reason: String,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub execution_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusHost {
    pub host_name: String,
    pub artifact_sha256: Vec<String>,
    pub paths: Vec<String>,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusReport {
    pub generated_at: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub query: serde_json::Value,
    pub hunt: Option<HuntResponse>,
    pub artifacts: Vec<BlastRadiusArtifact>,
    pub hosts: Vec<BlastRadiusHost>,
    pub occurrences: Vec<BlastRadiusOccurrence>,
    /// M0 reports historical observation only; no current-state
    /// verification task exists yet (spec 17.2 is later scope).
    pub verification_state: String,
}
