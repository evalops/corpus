//! Artifact retention cleanup for similarity-derived rows.
//!
//! Removes or tombstones function rows, features, LSH bands, edges, and
//! group membership for a deleted/expired artifact, then repairs variant
//! groups deterministically.

use crate::error::{Error, Result};
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CleanupCounts {
    pub features: u64,
    pub functions: u64,
    pub edges: u64,
    pub lsh_bands: u64,
    pub group_memberships: u64,
    pub receipts: u64,
    pub groups_repaired: u64,
    pub groups_removed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub tenant_id: Uuid,
    pub artifact_id: Uuid,
    pub dry_run: bool,
    pub legal_hold: bool,
    pub counts: CleanupCounts,
    pub recorded_at: chrono::DateTime<Utc>,
}

/// Enumerate (and optionally delete) all similarity-derived rows for an
/// artifact. When `dry_run` is true, only counts are returned.
pub async fn cleanup_artifact(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    dry_run: bool,
) -> Result<CleanupReport> {
    // Legal hold: refuse destructive cleanup when the artifact is held.
    let legal_hold: bool = sqlx::query_scalar(
        "SELECT COALESCE(
             (SELECT (provenance->>'legal_hold')::boolean
              FROM artifact WHERE tenant_id = $1 AND id = $2),
             false
         )",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    if legal_hold && !dry_run {
        return Err(Error::Conflict(format!(
            "artifact {artifact} is under legal hold; cleanup refused"
        )));
    }

    let mut counts = CleanupCounts {
        features: count(
            pool,
            "SELECT COUNT(*) FROM similarity_feature WHERE tenant_id = $1 AND artifact_id = $2",
            tenant,
            artifact,
        )
        .await?,
        functions: count(
            pool,
            "SELECT COUNT(*) FROM similarity_function WHERE tenant_id = $1 AND artifact_id = $2",
            tenant,
            artifact,
        )
        .await?,
        edges: count(
            pool,
            "SELECT COUNT(*) FROM similarity_edge
             WHERE tenant_id = $1 AND (src_artifact = $2 OR dst_artifact = $2)",
            tenant,
            artifact,
        )
        .await?,
        lsh_bands: count_lsh(pool, tenant, artifact).await?,
        group_memberships: count(
            pool,
            "SELECT COUNT(*) FROM variant_group_member WHERE tenant_id = $1 AND artifact_id = $2",
            tenant,
            artifact,
        )
        .await?,
        receipts: count_receipts(pool, tenant, artifact).await?,
        groups_repaired: 0,
        groups_removed: 0,
    };

    if dry_run || legal_hold {
        return Ok(CleanupReport {
            tenant_id: tenant,
            artifact_id: artifact,
            dry_run: true,
            legal_hold,
            counts,
            recorded_at: Utc::now(),
        });
    }

    // Capture group id before membership removal for repair.
    let group_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT group_id FROM variant_group_member WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM similarity_feature WHERE tenant_id = $1 AND artifact_id = $2")
        .bind(tenant)
        .bind(artifact)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM similarity_function WHERE tenant_id = $1 AND artifact_id = $2")
        .bind(tenant)
        .bind(artifact)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE FROM similarity_edge
         WHERE tenant_id = $1 AND (src_artifact = $2 OR dst_artifact = $2)",
    )
    .bind(tenant)
    .bind(artifact)
    .execute(pool)
    .await?;
    delete_lsh(pool, tenant, artifact).await?;
    sqlx::query("DELETE FROM variant_group_member WHERE tenant_id = $1 AND artifact_id = $2")
        .bind(tenant)
        .bind(artifact)
        .execute(pool)
        .await?;
    delete_receipts(pool, tenant, artifact).await?;

    if let Some(gid) = group_id {
        let repaired = repair_group(pool, tenant, gid).await?;
        if repaired.removed {
            counts.groups_removed = 1;
        } else if repaired.changed {
            counts.groups_repaired = 1;
        }
    }

    // Audit row.
    sqlx::query(
        "INSERT INTO similarity_cleanup_log (tenant_id, artifact_id, dry_run, counts, created_at)
         VALUES ($1,$2,false,$3,$4)",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(serde_json::to_value(&counts).unwrap_or_default())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(CleanupReport {
        tenant_id: tenant,
        artifact_id: artifact,
        dry_run: false,
        legal_hold: false,
        counts,
        recorded_at: Utc::now(),
    })
}

struct RepairResult {
    changed: bool,
    removed: bool,
}

/// After a member is removed, ensure the group still has ≥2 members or
/// dissolve it. Singleton groups are not meaningful partitions.
async fn repair_group(pool: &PgPool, tenant: Uuid, group_id: Uuid) -> Result<RepairResult> {
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM variant_group_member WHERE tenant_id = $1 AND group_id = $2",
    )
    .bind(tenant)
    .bind(group_id)
    .fetch_one(pool)
    .await?;

    if remaining <= 1 {
        // Dissolve: remaining singleton is no longer a group.
        sqlx::query("DELETE FROM variant_group_member WHERE tenant_id = $1 AND group_id = $2")
            .bind(tenant)
            .bind(group_id)
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM variant_group WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(group_id)
            .execute(pool)
            .await?;
        return Ok(RepairResult {
            changed: true,
            removed: true,
        });
    }
    Ok(RepairResult {
        changed: false,
        removed: false,
    })
}

async fn count(pool: &PgPool, sql: &str, tenant: Uuid, artifact: Uuid) -> Result<u64> {
    let n: i64 = sqlx::query_scalar(sql)
        .bind(tenant)
        .bind(artifact)
        .fetch_one(pool)
        .await?;
    Ok(n as u64)
}

async fn count_lsh(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<u64> {
    // LSH table may not exist on very old DBs; treat missing as zero.
    let res = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM similarity_lsh_band WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_one(pool)
    .await;
    match res {
        Ok(n) => Ok(n as u64),
        Err(_) => Ok(0),
    }
}

async fn delete_lsh(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<()> {
    let _ = sqlx::query(
        "DELETE FROM similarity_lsh_band WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .execute(pool)
    .await;
    Ok(())
}

async fn count_receipts(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<u64> {
    let res = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM analysis_receipt WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_one(pool)
    .await;
    match res {
        Ok(n) => Ok(n as u64),
        Err(_) => Ok(0),
    }
}

async fn delete_receipts(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<()> {
    let _ = sqlx::query(
        "DELETE FROM analysis_receipt WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .execute(pool)
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_counts_default_zero() {
        let c = CleanupCounts::default();
        assert_eq!(c.features, 0);
        assert_eq!(c.edges, 0);
    }
}
