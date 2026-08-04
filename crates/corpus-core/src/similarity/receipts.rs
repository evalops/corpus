//! Deterministic analysis receipts for similarity and semantic runs.
//!
//! A receipt records who analyzed what, with which model/config, and the
//! bounded outcome. Receipts never store sample bytes.

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReceipt {
    pub tenant_id: Uuid,
    pub artifact_id: Uuid,
    pub analyzer_name: String,
    pub analyzer_version: String,
    pub model_version: String,
    pub config_digest: String,
    pub input_sha256: String,
    pub input_size_bytes: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: String,
    pub limitation: Option<String>,
    pub function_count: usize,
    pub edge_count: usize,
    pub metrics: serde_json::Value,
}

/// Stable receipt identifier derived from content (not random).
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
