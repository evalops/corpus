//! Re-analysis invalidation and edge replacement semantics.
//!
//! # Model identity vs supersession
//!
//! Edges are keyed by
//! `(tenant, src, dst, edge_type, model_version)`. When thresholds or
//! extractors change, the correct response is a **new model/extractor
//! version**, not an in-place rewrite of historical edges.
//!
//! That preserves:
//!
//! - Auditability (“what did we believe under v1?”)
//! - Safe dual-running during migration
//! - Idempotent re-analysis under the *same* version (`ON CONFLICT DO NOTHING`)
//!
//! # Supersession (optional soft invalidation)
//!
//! [`supersede_edges`] annotates existing edges under an old model version
//! with:
//!
//! ```json
//! { "superseded": true, "superseded_by": "<new>", "superseded_at": "<rfc3339>" }
//! ```
//!
//! Rows are **not** deleted. Analyst UIs and neighborhood queries can
//! filter via [`edge_is_current`]. Dry-run mode returns the count without
//! writing.
//!
//! # Scope
//!
//! Supersession can target an entire tenant or a single artifact (any edge
//! where the artifact is `src` or `dst`). Features and function rows are
//! versioned separately and are not modified here.
//!
//! # Non-goals
//!
//! - Automatic background migration jobs (callers schedule supersession).
//! - Physical purge (use lifecycle cleanup for deleted artifacts).

use crate::error::Result;
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Outcome of a supersession pass (dry-run or applied).
#[derive(Debug, Clone, Serialize)]
pub struct InvalidationReport {
    pub tenant_id: Uuid,
    /// `None` when the whole tenant was in scope.
    pub artifact_id: Option<Uuid>,
    pub old_model_version: String,
    pub new_model_version: String,
    /// Number of edges matching the filter that were (or would be) annotated.
    pub edges_superseded: u64,
    pub dry_run: bool,
}

/// Mark edges under `old_model_version` as superseded for a tenant
/// (optionally one artifact).
///
/// Does not delete rows; merges a `superseded*` annotation into the
/// existing `evidence` jsonb via `evidence || $annotation`. Already-
/// superseded edges are skipped so the operation is idempotent.
pub async fn supersede_edges(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Option<Uuid>,
    old_model_version: &str,
    new_model_version: &str,
    dry_run: bool,
) -> Result<InvalidationReport> {
    // Count first so dry-run and apply report the same filter semantics.
    let n: i64 = if let Some(a) = artifact {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM similarity_edge
             WHERE tenant_id = $1 AND model_version = $2
               AND (src_artifact = $3 OR dst_artifact = $3)
               AND COALESCE((evidence->>'superseded')::boolean, false) = false",
        )
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
///
/// Missing or non-boolean `superseded` is treated as current — the
/// default for all edges written before supersession existed.
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
