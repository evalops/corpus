//! Continuous re-analysis: when new intelligence arrives (activated bundle,
//! hash intel), re-examine retained history automatically.
//!
//! Controlled by env:
//! - `CORPUS_AUTO_RETRO_ON_ACTIVATE` — default **on**. Set to `0`/`false` to disable.
//! - `CORPUS_AUTO_HASH_INTEL` — default **on**. Exact-hash hunt on sha256 IOCs.

use crate::error::Result;
use crate::hunts;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

fn env_flag_default_on(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => true,
    }
}

pub fn auto_retro_on_activate() -> bool {
    env_flag_default_on("CORPUS_AUTO_RETRO_ON_ACTIVATE")
}

pub fn auto_hash_intel() -> bool {
    env_flag_default_on("CORPUS_AUTO_HASH_INTEL")
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReanalysisRecord {
    pub id: Uuid,
    pub trigger_kind: String,
    pub trigger_ref: Option<String>,
    pub hunt_id: Option<Uuid>,
    pub state: String,
}

async fn insert_record(
    pool: &PgPool,
    tenant_id: Uuid,
    trigger_kind: &str,
    trigger_ref: Option<&str>,
    hunt_id: Option<Uuid>,
    state: &str,
    detail: serde_json::Value,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO continuous_reanalysis
         (id, tenant_id, trigger_kind, trigger_ref, hunt_id, state, detail, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(trigger_kind)
    .bind(trigger_ref)
    .bind(hunt_id)
    .bind(state)
    .bind(&detail)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(id)
}

/// After a bundle is activated for forward coverage, enqueue a full
/// retro-hunt over the retained endpoint corpus (continuous re-analysis loop:
/// new intelligence re-examines history).
pub async fn on_bundle_activated(
    pool: &PgPool,
    tenant_id: Uuid,
    bundle_digest: &str,
) -> Result<Option<crate::dto::HuntResponse>> {
    if !auto_retro_on_activate() {
        return Ok(None);
    }
    // Avoid stacking identical QUEUED/RUNNING retros for the same digest.
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM hunt
         WHERE tenant_id = $1 AND kind = 'retro' AND bundle_digest = $2
           AND state IN ('QUEUED','RUNNING','VALIDATING','PLANNED','DRAFT')
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(bundle_digest)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = existing {
        let h = hunts::get_hunt(pool, tenant_id, id).await?;
        if h.state == "DRAFT" {
            hunts::enqueue_hunt(pool, tenant_id, id).await?;
        }
        insert_record(
            pool,
            tenant_id,
            "bundle_activate",
            Some(bundle_digest),
            Some(id),
            "reused",
            serde_json::json!({"note": "existing open hunt"}),
        )
        .await?;
        return Ok(Some(hunts::get_hunt(pool, tenant_id, id).await?));
    }

    let hunt = hunts::create_hunt(pool, tenant_id, bundle_digest).await?;
    let hunt = hunts::enqueue_hunt(pool, tenant_id, hunt.id).await?;
    insert_record(
        pool,
        tenant_id,
        "bundle_activate",
        Some(bundle_digest),
        Some(hunt.id),
        "enqueued",
        serde_json::json!({}),
    )
    .await?;
    Ok(Some(hunt))
}

/// Exact-hash continuous hunt: for each sha256 IOC, match endpoint corpus
/// and emit detection events.
pub async fn on_hash_indicators(
    pool: &PgPool,
    tenant_id: Uuid,
    source: &str,
    hashes: &[String],
) -> Result<crate::dto::ContinuousHashIntelResult> {
    if !auto_hash_intel() || hashes.is_empty() {
        return Ok(crate::dto::ContinuousHashIntelResult {
            hits: 0,
            detections: 0,
            hunt_ids: vec![],
        });
    }
    let hits = crate::intel::hash_hunt(pool, tenant_id, hashes).await?;
    let mut detections = 0usize;
    for h in &hits {
        crate::detect::record(
            pool,
            tenant_id,
            h.artifact_id,
            crate::detect::DetectionInput {
                source: "hash_intel",
                severity: "high",
                title: &format!("Exact-hash intel match ({source})"),
                detail: serde_json::json!({
                    "ioc_value": h.value,
                    "source": source,
                    "artifact_sha256": h.artifact_sha256,
                }),
                mitre_techniques: &[],
            },
        )
        .await?;
        detections += 1;
        // Fire webhook for malicious-style intel hit via hunt_match-adjacent
        // condition if configured — use malicious_verdict only for opinions.
        crate::triggers::fire(
            pool,
            tenant_id,
            crate::triggers::CONDITION_HUNT_MATCH,
            serde_json::json!({
                "type": "hash_intel_match",
                "source": source,
                "artifact_id": h.artifact_id,
                "sha256": h.artifact_sha256,
                "ioc": h.value,
            }),
        )
        .await
        .ok();
    }
    let rec_id = insert_record(
        pool,
        tenant_id,
        "hash_intel",
        Some(source),
        None,
        if hits.is_empty() { "no_hits" } else { "hits" },
        serde_json::json!({
            "hashes": hashes.len(),
            "hits": hits.len(),
            "detections": detections,
        }),
    )
    .await?;
    let _ = rec_id;
    Ok(crate::dto::ContinuousHashIntelResult {
        hits: hits.len(),
        detections,
        hunt_ids: vec![],
    })
}

#[derive(Debug, sqlx::FromRow)]
struct ReanalysisRow {
    id: Uuid,
    trigger_kind: String,
    trigger_ref: Option<String>,
    hunt_id: Option<Uuid>,
    state: String,
    detail: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
}

pub async fn list_recent(
    pool: &PgPool,
    tenant_id: Uuid,
    limit: i64,
) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query_as::<_, ReanalysisRow>(
        "SELECT id, trigger_kind, trigger_ref, hunt_id, state, detail, created_at
         FROM continuous_reanalysis
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2",
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "trigger_kind": r.trigger_kind,
                "trigger_ref": r.trigger_ref,
                "hunt_id": r.hunt_id,
                "state": r.state,
                "detail": r.detail,
                "created_at": r.created_at,
            })
        })
        .collect())
}
