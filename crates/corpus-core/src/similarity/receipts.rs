//! Deterministic analysis receipts for similarity and semantic runs.
//!
//! # Purpose
//!
//! Every analysis pass should leave an auditable record of:
//!
//! - **Who** ran (analyzer name + version)
//! - **What** was analyzed (artifact id, input sha256 + size)
//! - **With which policy** (model version + config digest)
//! - **Outcome** (status, optional limitation, function/edge counts)
//!
//! Receipts answer “why is this edge missing?” (packed limitation) and
//! “which thresholds produced this edge?” without re-reading sample
//! bytes from CAS.
//!
//! # Privacy invariant
//!
//! Receipts **never** store sample bytes, disassembly, or full token
//! vectors. The body is a JSON serialization of [`AnalysisReceipt`]
//! only — digests and counts.
//!
//! # Identity
//!
//! [`receipt_id`] is a content-derived 16-byte hex digest (SHA-256
//! truncated), not a random UUID. Re-running identical analysis with the
//! same inputs upserts the same row (`ON CONFLICT (id) DO UPDATE`), which
//! makes concurrent re-analysis idempotent.
//!
//! Fields included in the id payload (see [`receipt_id`]):
//! tenant, artifact, analyzer name/version, model version, config
//! digest, input sha256, status, function_count.
//!
//! # Schema
//!
//! See `migrations/0010_receipts_and_cleanup.sql` (`analysis_receipt`).
//!
//! # Pipeline hooks
//!
//! `semantic::edges::analyze_and_link` persists a receipt after extract
//! (status `ok` / `empty` / `limitation`) and updates it after edge
//! emission with the final `edge_count`.

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Structured analysis outcome persisted under a content-derived id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReceipt {
    pub tenant_id: Uuid,
    pub artifact_id: Uuid,
    /// Registry name, e.g. `semantic-function`.
    pub analyzer_name: String,
    /// Persisted version string, e.g. `semantic:v1`.
    pub analyzer_version: String,
    /// Edge model version, e.g. `similarity-model:v1`.
    pub model_version: String,
    /// Digest of thresholds/weights that affect scoring identity.
    pub config_digest: String,
    /// Hex SHA-256 of the bytes that were analyzed.
    pub input_sha256: String,
    pub input_size_bytes: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// Coarse outcome: `ok`, `empty`, `limitation`, or future values.
    pub status: String,
    /// When status is `limitation`, a short machine-readable reason
    /// (e.g. `packed_or_virtualized: …`). Never sample content.
    pub limitation: Option<String>,
    /// Significant functions retained after extract filters.
    pub function_count: usize,
    /// Edges inserted during this pass (may be updated on a second persist).
    pub edge_count: usize,
    /// Extra structured metrics (format, arch, …) — still no sample bytes.
    pub metrics: serde_json::Value,
}

/// Stable receipt identifier derived from content (not random).
///
/// Changing any field in the payload changes the id, so a re-run that
/// discovers more functions creates a distinct receipt row rather than
/// silently overwriting history under a random key.
pub fn receipt_id(r: &AnalysisReceipt) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        r.tenant_id,
        r.artifact_id,
        r.analyzer_name,
        r.analyzer_version,
        r.model_version,
        r.config_digest,
        r.input_sha256,
        r.status,
        r.function_count,
    );
    let h = Sha256::digest(payload.as_bytes());
    hex::encode(&h[..16])
}

/// Upsert a receipt by content-derived id.
///
/// Concurrent identical runs converge on one row. A later pass that
/// updates `edge_count` / `status` refreshes `body` and `created_at`
/// (which stores `finished_at` for chronological listing).
pub async fn persist(pool: &PgPool, receipt: &AnalysisReceipt) -> Result<()> {
    let id = receipt_id(receipt);
    let body = serde_json::to_value(receipt).unwrap_or_else(|_| serde_json::json!({}));
    sqlx::query(
        "INSERT INTO analysis_receipt (id, tenant_id, artifact_id, analyzer_name, analyzer_version,
             model_version, config_digest, status, body, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET
             status = EXCLUDED.status,
             body = EXCLUDED.body,
             created_at = EXCLUDED.created_at",
    )
    .bind(&id)
    .bind(receipt.tenant_id)
    .bind(receipt.artifact_id)
    .bind(&receipt.analyzer_name)
    .bind(&receipt.analyzer_version)
    .bind(&receipt.model_version)
    .bind(&receipt.config_digest)
    .bind(&receipt.status)
    .bind(&body)
    .bind(receipt.finished_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// List receipts for an artifact (newest first), injecting `receipt_id`
/// into each JSON body for API convenience.
pub async fn for_artifact(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
) -> Result<Vec<serde_json::Value>> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, body FROM analysis_receipt
         WHERE tenant_id = $1 AND artifact_id = $2
         ORDER BY created_at DESC",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, mut body)| {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("receipt_id".into(), serde_json::json!(id));
            }
            body
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AnalysisReceipt {
        AnalysisReceipt {
            tenant_id: Uuid::from_u128(1),
            artifact_id: Uuid::from_u128(2),
            analyzer_name: "semantic-function".into(),
            analyzer_version: "semantic:v1".into(),
            model_version: "similarity-model:v1".into(),
            config_digest: "abc".into(),
            input_sha256: "deadbeef".into(),
            input_size_bytes: 64,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            status: "ok".into(),
            limitation: None,
            function_count: 3,
            edge_count: 1,
            metrics: serde_json::json!({}),
        }
    }

    #[test]
    fn receipt_id_is_deterministic() {
        let r = sample();
        assert_eq!(receipt_id(&r), receipt_id(&r));
        assert_eq!(receipt_id(&r).len(), 32);
    }

    #[test]
    fn receipt_id_changes_with_inputs() {
        let mut r = sample();
        let a = receipt_id(&r);
        r.function_count = 9;
        let b = receipt_id(&r);
        assert_ne!(a, b);
    }
}
