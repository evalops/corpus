//! Human opinions on artifacts, separate from analyzer scores (spec 5.5).
//! Append-only; current opinion = latest row. Every set is audited (24.3)
//! and malicious/suspicious opinions fire trigger events.

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

pub const OPINIONS: [&str; 5] = ["trusted", "grayware", "vulnerable", "malicious", "suspicious"];

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OpinionRow {
    pub id: Uuid,
    pub opinion: String,
    pub actor: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub superseded_by: Option<Uuid>,
}

/// Set an opinion: mark the previous current opinion superseded, insert
/// the new row, write the audit event — one transaction. Returns the id.
pub async fn set_opinion(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    opinion: &str,
    actor: &str,
    reason: &str,
) -> Result<Uuid> {
    let opinion = opinion.to_ascii_lowercase();
    if !OPINIONS.contains(&opinion.as_str()) {
        return Err(Error::BadRequest(format!("invalid opinion {opinion:?}; supported: {}", OPINIONS.join(", "))));
    }
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await?;

    let previous: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM artifact_opinion
         WHERE tenant_id = $1 AND artifact_id = $2 AND superseded_by IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((prev,)) = previous {
        sqlx::query("UPDATE artifact_opinion SET superseded_by = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(prev)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query(
        "INSERT INTO artifact_opinion (id, tenant_id, artifact_id, opinion, actor, reason, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(id)
    .bind(tenant)
    .bind(artifact)
    .bind(&opinion)
    .bind(actor)
    .bind(reason)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO audit_event (id, tenant_id, actor, action, target, detail, created_at)
         VALUES ($1,$2,$3,'opinion.set',$4,$5,$6)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(actor)
    .bind(artifact.to_string())
    .bind(serde_json::json!({"opinion": opinion, "reason": reason, "opinion_id": id}))
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Trigger: new malicious/suspicious verdict (outside the tx).
    if matches!(opinion.as_str(), "malicious" | "suspicious") {
        crate::triggers::fire(
            pool,
            tenant,
            crate::triggers::CONDITION_MALICIOUS_VERDICT,
            serde_json::json!({
                "type": "malicious_verdict",
                "artifact_id": artifact,
                "opinion": opinion,
                "actor": actor,
                "reason": reason,
            }),
        )
        .await?;
    }
    Ok(id)
}

pub async fn current_opinion(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Option<OpinionRow>> {
    let row = sqlx::query_as::<_, OpinionRow>(
        "SELECT id, opinion, actor, reason, created_at, superseded_by FROM artifact_opinion
         WHERE tenant_id = $1 AND artifact_id = $2 AND superseded_by IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn opinion_history(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Vec<OpinionRow>> {
    let rows = sqlx::query_as::<_, OpinionRow>(
        "SELECT id, opinion, actor, reason, created_at, superseded_by FROM artifact_opinion
         WHERE tenant_id = $1 AND artifact_id = $2
         ORDER BY created_at",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn artifact_for_sha(pool: &PgPool, tenant: Uuid, sha256_hex: &str) -> Result<Option<(Uuid,)>> {
    let raw = crate::hash::hex_to_raw(sha256_hex)
        .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {sha256_hex:?}")))?;
    Ok(sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
        .bind(tenant)
        .bind(&raw)
        .fetch_optional(pool)
        .await?)
}
