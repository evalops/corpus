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

// ---------- agents (M1) ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenCreateRequest {
    pub label: Option<String>,
    pub ttl_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenResponse {
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub host_name: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    pub agent_token: String,
    pub tenant_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_version: String,
    pub policy_digest: String,
    pub baseline_state: String,
    pub baseline_percent: f64,
    pub queue_depth: i64,
    pub spool_bytes: i64,
    pub oldest_pending_secs: Option<i64>,
    pub sensor: String,
    pub outcome_counts: serde_json::Value,
    pub last_upload_at: Option<DateTime<Utc>>,
    pub clock_offset_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapEvent {
    pub observed_at: DateTime<Utc>,
    pub capture_reason: String,
    pub terminal_outcome: String,
    pub artifact_sha256: Option<String>,
    pub path: Option<String>,
    pub detail_code: Option<String>,
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusResponse {
    pub id: Uuid,
    pub host_name: String,
    pub version: String,
    pub enrolled_at: DateTime<Utc>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_upload_at: Option<DateTime<Utc>>,
    pub policy_digest: Option<String>,
    pub baseline_state: Option<String>,
    pub baseline_percent: Option<f64>,
    pub queue_depth: Option<i64>,
    pub spool_bytes: Option<i64>,
    pub oldest_pending_secs: Option<i64>,
    pub sensor: Option<String>,
    pub outcome_counts: serde_json::Value,
    pub clock_offset_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CoverageGapRow {
    pub id: Uuid,
    pub host_name: String,
    pub agent_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub capture_reason: String,
    pub terminal_outcome: String,
    pub artifact_sha256_hex: Option<String>,
    pub path: Option<String>,
    pub detail_code: Option<String>,
}

// ---------- blast radius ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarEdgeView {
    pub other_artifact: Uuid,
    pub other_sha256: String,
    pub edge_type: String,
    pub model_version: String,
    pub score: f64,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarResponse {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub edges: Vec<SimilarEdgeView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantMember {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub artifact_class: String,
    pub first_committed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantsResponse {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub group_id: Option<Uuid>,
    pub members: Vec<VariantMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillResponse {
    pub analyzed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantExpansion {
    /// Strong-edge group members beyond the query's matched artifacts.
    pub group_artifacts: Vec<BlastRadiusArtifact>,
    pub group_occurrences: Vec<BlastRadiusOccurrence>,
    /// Weak neighbors (byte_similar, shared_provenance) — leads only,
    /// never automatic family membership (spec 16.4, 28.5).
    pub weak_leads: Vec<SimilarEdgeView>,
}



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
    /// Present only when the report was requested with expand_variants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_expansion: Option<VariantExpansion>,
}
