//! Re-analysis invalidation and edge replacement semantics.
//!
//! When an analyzer/model version is superseded, existing features and
//! edges keep their identity under the old version. New analysis writes
//! rows under the new version. Optional supersession marks old edges as
//! non-current without deleting them (auditability).

use crate::error::Result;
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct InvalidationReport {
    pub tenant_id: Uuid,
    pub artifact_id: Option<Uuid>,
    pub old_model_version: String,
    pub new_model_version: String,
    pub edges_superseded: u64,
    pub dry_run: bool,
}

/// Mark edges under `old_model_version` as superseded for a tenant
/// (optionally one artifact). Does not delete rows; inserts a
/// `superseded_by` annotation into evidence for auditability.
pub async fn supersede_edges(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Option<Uuid>,
    old_model_version: &str,
    new_model_version: &str,
    dry_run: bool,
) -> Result<InvalidationReport> {
    let count_sql = if artifact.is_some() {
        "SELECT COUNT(*) FROM similarity_edge
         WHERE tenant_id = $1 AND model_version = $2
           AND (src_artifact = $3 OR dst_artifact = $3)
           AND COALESCE((evidence->>'superseded')::boolean, false) = false"
    } else {
        "SELECT COUNT(*) FROM similarity_edge
         WHERE tenant_id = $1 AND model_version = $2
           AND COALESCE((evidence->>'superseded')::boolean, false) = false
           AND ($3::uuid IS NULL OR true)"
    };

    let n: i64 = if let Some(a) = artifact {
        sqlx::query_scalar(count_sql)
            .bind(tenant)
            .bind(old_model_version)
            .bind(a)
            .fetch_one(pool)
            .await?
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM similarity_edge
             WHERE tenant_id = $1 AND model_version = $2
               AND COALESCE((evidence->>'superseded')::boolean, false) = false",
        )
        .bind(tenant)
        .bind(old_model_version)
        .fetch_one(pool)
        .await?
    };

    if dry_run {
        return Ok(InvalidationReport {
            tenant_id: tenant,
            artifact_id: artifact,
            old_model_version: old_model_version.into(),
            new_model_version: new_model_version.into(),
            edges_superseded: n as u64,
            dry_run: true,
        });
    }

    let annotation = serde_json::json!({
        "superseded": true,
        "superseded_by": new_model_version,
        "superseded_at": Utc::now().to_rfc3339(),
    });

    if let Some(a) = artifact {
        sqlx::query(
            "UPDATE similarity_edge
             SET evidence = evidence || $4::jsonb
             WHERE tenant_id = $1 AND model_version = $2
               AND (src_artifact = $3 OR dst_artifact = $3)
               AND COALESCE((evidence->>'superseded')::boolean, false) = false",
        )
        .bind(tenant)
        .bind(old_model_version)
        .bind(a)
        .bind(&annotation)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE similarity_edge
             SET evidence = evidence || $3::jsonb
             WHERE tenant_id = $1 AND model_version = $2
               AND COALESCE((evidence->>'superseded')::boolean, false) = false",
        )
        .bind(tenant)
        .bind(old_model_version)
        .bind(&annotation)
        .execute(pool)
        .await?;
    }

    Ok(InvalidationReport {
        tenant_id: tenant,
        artifact_id: artifact,
        old_model_version: old_model_version.into(),
        new_model_version: new_model_version.into(),
        edges_superseded: n as u64,
        dry_run: false,
    })
}

/// Whether an edge evidence blob is still current (not superseded).
pub fn edge_is_current(evidence: &serde_json::Value) -> bool {
    !evidence
        .get("superseded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_by_default() {
        assert!(edge_is_current(&serde_json::json!({"tau": 0.35})));
        assert!(!edge_is_current(
            &serde_json::json!({"superseded": true, "superseded_by": "v2"})
        ));
    }
}
