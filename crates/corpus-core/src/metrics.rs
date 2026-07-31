//! Platform metrics for ops dashboards and health beyond liveness.

use crate::dto::PlatformMetrics;
use crate::error::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn platform_metrics(pool: &PgPool, tenant_id: Option<Uuid>) -> Result<PlatformMetrics> {
    // When tenant is None, aggregate across all tenants (admin view).
    let (
        artifacts,
        occurrences,
        hunts_total,
        hunts_active,
        jobs,
        detections,
        bundles,
        agents,
        cont,
    ) = if let Some(t) = tenant_id {
        let artifacts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact WHERE tenant_id = $1 AND storage_state = 'committed'",
        )
        .bind(t)
        .fetch_one(pool)
        .await?;
        let occurrences: i64 =
            sqlx::query_scalar("SELECT count(*) FROM occurrence_event WHERE tenant_id = $1")
                .bind(t)
                .fetch_one(pool)
                .await?;
        let hunts_total: i64 = sqlx::query_scalar("SELECT count(*) FROM hunt WHERE tenant_id = $1")
            .bind(t)
            .fetch_one(pool)
            .await?;
        let hunts_active: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM hunt WHERE tenant_id = $1 AND state IN ('QUEUED','RUNNING','VALIDATING','PLANNED')",
            )
            .bind(t)
            .fetch_one(pool)
            .await?;
        let jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM hunt_job j
                 JOIN hunt h ON h.id = j.hunt_id
                 WHERE h.tenant_id = $1 AND j.finished_at IS NULL",
        )
        .bind(t)
        .fetch_one(pool)
        .await?;
        let detections: i64 =
            sqlx::query_scalar("SELECT count(*) FROM detection_event WHERE tenant_id = $1")
                .bind(t)
                .fetch_one(pool)
                .await?;
        let bundles: i64 =
            sqlx::query_scalar("SELECT count(*) FROM rule_bundle WHERE tenant_id = $1 AND active")
                .bind(t)
                .fetch_one(pool)
                .await?;
        let agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agent WHERE tenant_id = $1")
            .bind(t)
            .fetch_one(pool)
            .await?;
        let cont: i64 =
            sqlx::query_scalar("SELECT count(*) FROM continuous_reanalysis WHERE tenant_id = $1")
                .bind(t)
                .fetch_one(pool)
                .await?;
        (
            artifacts,
            occurrences,
            hunts_total,
            hunts_active,
            jobs,
            detections,
            bundles,
            agents,
            cont,
        )
    } else {
        let artifacts: i64 =
            sqlx::query_scalar("SELECT count(*) FROM artifact WHERE storage_state = 'committed'")
                .fetch_one(pool)
                .await?;
        let occurrences: i64 = sqlx::query_scalar("SELECT count(*) FROM occurrence_event")
            .fetch_one(pool)
            .await?;
        let hunts_total: i64 = sqlx::query_scalar("SELECT count(*) FROM hunt")
            .fetch_one(pool)
            .await?;
        let hunts_active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM hunt WHERE state IN ('QUEUED','RUNNING','VALIDATING','PLANNED')",
        )
        .fetch_one(pool)
        .await?;
        let jobs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM hunt_job WHERE finished_at IS NULL")
                .fetch_one(pool)
                .await?;
        let detections: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_event")
            .fetch_one(pool)
            .await?;
        let bundles: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_bundle WHERE active")
            .fetch_one(pool)
            .await?;
        let agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agent")
            .fetch_one(pool)
            .await?;
        let cont: i64 = sqlx::query_scalar("SELECT count(*) FROM continuous_reanalysis")
            .fetch_one(pool)
            .await?;
        (
            artifacts,
            occurrences,
            hunts_total,
            hunts_active,
            jobs,
            detections,
            bundles,
            agents,
            cont,
        )
    };

    Ok(PlatformMetrics {
        artifacts_committed: artifacts,
        occurrences,
        hunts_total,
        hunts_queued_or_running: hunts_active,
        hunt_jobs_pending: jobs,
        detections_total: detections,
        active_bundles: bundles,
        agents_enrolled: agents,
        continuous_reanalyses: cont,
    })
}
