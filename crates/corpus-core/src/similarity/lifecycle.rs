//! Artifact retention cleanup for similarity-derived rows.
//!
//! # When to call
//!
//! After an artifact is deleted or expires under retention policy, derived
//! similarity state must not linger as orphan rows or ghost group
//! memberships. [`cleanup_artifact`] enumerates (and optionally deletes)
//! every similarity-owned row for one artifact inside a tenant.
//!
//! # What is cleaned
//!
//! | Table / family | Action |
//! |----------------|--------|
//! | `similarity_feature` | DELETE by artifact |
//! | `similarity_function` | DELETE by artifact |
//! | `similarity_function_band` | DELETE by artifact (best-effort) |
//! | `similarity_edge` | DELETE where src or dst is the artifact |
//! | `similarity_lsh_band` | DELETE (best-effort if table missing) |
//! | `variant_group_member` | DELETE membership, then repair group |
//! | `analysis_receipt` | DELETE (best-effort if table missing) |
//!
//! The artifact row itself and CAS object are **out of scope** — callers
//! own primary retention.
//!
//! # Dry-run & legal hold
//!
//! - `dry_run = true` (API default): count only, no deletes, still returns
//!   a report. Legal-hold artifacts also return counts-only.
//! - Destructive cleanup refuses with `Error::Conflict` when
//!   `artifact.provenance.legal_hold` is true.
//!
//! # Group repair
//!
//! Variant groups are partitions of size ≥ 2 linked by strong edges.
//! After removing a member:
//!
//! - If **≥ 2** members remain → leave the group intact.
//! - If **≤ 1** remains → dissolve the group (delete remaining membership
//!   and the `variant_group` row). Singleton groups are not meaningful.
//!
//! # Audit
//!
//! Successful destructive cleanups insert a row into
//! `similarity_cleanup_log` with the count JSON (see migration
//! `0010_receipts_and_cleanup.sql`).
//!
//! # Idempotency
//!
//! Re-running cleanup after a successful delete yields zero counts and
//! no group repair. Concurrent cleanups of different artifacts are
//! independent; same-artifact concurrency may race on group repair and
//! is acceptable (both converge on dissolved or multi-member).

use crate::error::{Error, Result};
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Per-table deletion (or dry-run) counts for one cleanup pass.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CleanupCounts {
    pub features: u64,
    pub functions: u64,
    /// Edges incident on the artifact (either endpoint).
    pub edges: u64,
    pub lsh_bands: u64,
    pub group_memberships: u64,
    pub receipts: u64,
    /// Groups whose membership changed but the group survived.
    pub groups_repaired: u64,
    /// Groups dissolved because fewer than 2 members remained.
    pub groups_removed: u64,
}

/// Full cleanup outcome returned to API / CLI callers.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub tenant_id: Uuid,
    pub artifact_id: Uuid,
    /// True when no deletes were performed (requested dry-run or legal hold).
    pub dry_run: bool,
    /// True when the artifact is under legal hold.
    pub legal_hold: bool,
    pub counts: CleanupCounts,
    pub recorded_at: chrono::DateTime<Utc>,
}

/// Enumerate (and optionally delete) all similarity-derived rows for an
/// artifact.
///
/// When `dry_run` is true, only counts are returned. When the artifact is
/// under legal hold, destructive cleanup is refused (unless dry-run).
pub async fn cleanup_artifact(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    dry_run: bool,
) -> Result<CleanupReport> {
    // Legal hold is stored as a boolean under artifact.provenance JSON.
    // COALESCE + subquery treats missing artifacts as not held so dry-run
    // of unknown ids still returns zero counts rather than erroring here.
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
    // Function-band table may not exist on older DBs; ignore errors.
    let _ = sqlx::query(
        "DELETE FROM similarity_function_band WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .execute(pool)
    .await;
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

    // Audit row for compliance / operator forensics.
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

/// LSH table may not exist on very old DBs; treat missing as zero.
async fn count_lsh(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<u64> {
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
    let _ =
        sqlx::query("DELETE FROM similarity_lsh_band WHERE tenant_id = $1 AND artifact_id = $2")
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
    let _ = sqlx::query("DELETE FROM analysis_receipt WHERE tenant_id = $1 AND artifact_id = $2")
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
