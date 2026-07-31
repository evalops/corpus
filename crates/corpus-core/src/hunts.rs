//! Single-node retro-hunt engine and forward coverage (spec 15).

use crate::cas::FsCas;
use crate::dto::HuntResponse;
use crate::error::{Error, Result};
use crate::registry;
use crate::scan::{self, ScanCacheKey, ScanStatus};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct HuntRow {
    pub id: Uuid,
    pub kind: String,
    pub bundle_id: Uuid,
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

impl HuntRow {
    pub fn into_response(self) -> HuntResponse {
        HuntResponse {
            id: self.id,
            kind: self.kind,
            bundle_digest: self.bundle_digest,
            state: self.state,
            corpus_watermark: self.corpus_watermark,
            planned_artifacts: self.planned_artifacts,
            scanned: self.scanned,
            cache_hits: self.cache_hits,
            matched: self.matched,
            timed_out: self.timed_out,
            failed: self.failed,
            error: self.error,
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
        }
    }
}

const HUNT_COLS: &str = "id, kind, bundle_id, bundle_digest, state, corpus_watermark,
     planned_artifacts, scanned, cache_hits, matched, timed_out, failed,
     error, created_at, started_at, completed_at";

pub async fn create_hunt(
    pool: &PgPool,
    tenant_id: Uuid,
    bundle_digest: &str,
) -> Result<HuntResponse> {
    let bundle = registry::get_bundle(pool, tenant_id, bundle_digest).await?;
    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, HuntRow>(&format!(
        "INSERT INTO hunt (id, tenant_id, kind, bundle_id, bundle_digest, state, created_at)
         VALUES ($1,$2,'retro',$3,$4,'DRAFT',$5)
         RETURNING {HUNT_COLS}"
    ))
    .bind(id)
    .bind(tenant_id)
    .bind(bundle.id)
    .bind(bundle_digest)
    .bind(Utc::now())
    .fetch_one(pool)
    .await?;
    Ok(row.into_response())
}

pub async fn get_hunt(pool: &PgPool, tenant_id: Uuid, hunt_id: Uuid) -> Result<HuntResponse> {
    let row = sqlx::query_as::<_, HuntRow>(&format!(
        "SELECT {HUNT_COLS} FROM hunt WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(hunt_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::NotFound(format!("hunt {hunt_id}")))?;
    Ok(row.into_response())
}

pub async fn list_hunts(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<HuntResponse>> {
    let rows = sqlx::query_as::<_, HuntRow>(&format!(
        "SELECT {HUNT_COLS} FROM hunt WHERE tenant_id = $1 ORDER BY created_at"
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(HuntRow::into_response).collect())
}

async fn set_state(pool: &PgPool, tenant_id: Uuid, hunt_id: Uuid, state: &str) -> Result<()> {
    sqlx::query("UPDATE hunt SET state = $3 WHERE id = $1 AND tenant_id = $2")
        .bind(hunt_id)
        .bind(tenant_id)
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

/// Insert one hunt match idempotently (invariant #8). Returns true if a new
/// row was committed.
async fn commit_match(
    pool: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
    artifact_id: Uuid,
    rule_id: &str,
    match_summary: serde_json::Value,
) -> Result<bool> {
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO hunt_match (hunt_id, tenant_id, artifact_id, rule_id, engine_version, match_summary, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (hunt_id, artifact_id, rule_id) DO NOTHING
         RETURNING hunt_id",
    )
    .bind(hunt_id)
    .bind(tenant_id)
    .bind(artifact_id)
    .bind(rule_id)
    .bind(crate::ENGINE_VERSION)
    .bind(match_summary)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(inserted.is_some())
}

/// Record a terminal scan result in the cache (spec 15.4).
async fn commit_cache_entry(
    pool: &PgPool,
    key: &ScanCacheKey,
    status: &str,
    matched_rule_ids: &[String],
    duration_ms: i64,
    error_code: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO scan_cache
         (tenant_id, artifact_sha256, rule_bundle_digest, engine_version, scan_config_digest,
          status, matched_rule_ids, duration_ms, error_code, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (tenant_id, artifact_sha256, rule_bundle_digest, engine_version, scan_config_digest)
         DO NOTHING",
    )
    .bind(key.tenant_id)
    .bind(&key.artifact_sha256)
    .bind(&key.rule_bundle_digest)
    .bind(&key.engine_version)
    .bind(&key.scan_config_digest)
    .bind(status)
    .bind(serde_json::json!(matched_rule_ids))
    .bind(duration_ms)
    .bind(error_code)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

struct CacheHit {
    status: String,
    matched_rule_ids: Vec<String>,
}

async fn cache_lookup(pool: &PgPool, key: &ScanCacheKey) -> Result<Option<CacheHit>> {
    let row: Option<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT status, matched_rule_ids FROM scan_cache
         WHERE tenant_id = $1 AND artifact_sha256 = $2 AND rule_bundle_digest = $3
           AND engine_version = $4 AND scan_config_digest = $5",
    )
    .bind(key.tenant_id)
    .bind(&key.artifact_sha256)
    .bind(&key.rule_bundle_digest)
    .bind(&key.engine_version)
    .bind(&key.scan_config_digest)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(status, ids)| CacheHit {
        status,
        matched_rule_ids: serde_json::from_value(ids).unwrap_or_default(),
    }))
}

/// Execute a retro-hunt on this node: snapshot the watermark, scan every
/// committed artifact at/below it not covered by the scan cache, commit
/// matches idempotently, and land in COMPLETED or COMPLETED_PARTIAL
/// (spec 15.1, 15.2). Synchronous for M0.
///
/// Once a watermark has been pinned, re-runs reuse it (cache-replay path)
/// and never expand the planned set to newer commits.
pub async fn run_hunt(
    pool: &PgPool,
    cas: &FsCas,
    tenant_id: Uuid,
    hunt_id: Uuid,
) -> Result<HuntResponse> {
    let hunt = get_hunt(pool, tenant_id, hunt_id).await?;
    if hunt.kind != "retro" {
        return Err(Error::BadRequest(
            "only retro hunts are run explicitly".into(),
        ));
    }
    if matches!(hunt.state.as_str(), "RUNNING" | "QUEUED") {
        return Err(Error::Conflict(format!("hunt {hunt_id} is {}", hunt.state)));
    }

    // VALIDATING: bundle must resolve and compile.
    set_state(pool, tenant_id, hunt_id, "VALIDATING").await?;
    let bundle_row: (Uuid,) =
        sqlx::query_as("SELECT bundle_id FROM hunt WHERE id = $1 AND tenant_id = $2")
            .bind(hunt_id)
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;
    let sources = registry::bundle_sources(pool, tenant_id, bundle_row.0).await?;
    let compiled = match scan::compile_bundle(&sources) {
        Ok(c) => c,
        Err(e) => {
            sqlx::query(
                "UPDATE hunt SET state = 'FAILED', error = $3, completed_at = $4
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(hunt_id)
            .bind(tenant_id)
            .bind(&e)
            .bind(Utc::now())
            .execute(pool)
            .await?;
            return Err(Error::RuleCompile(e));
        }
    };

    // PLANNED: pin the corpus watermark once (max committed artifact sequence).
    // Re-runs keep the original pin so the planned set is immutable.
    let watermark = if let Some(w) = hunt.corpus_watermark {
        w
    } else {
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM artifact
             WHERE tenant_id = $1 AND storage_state = 'committed'",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?
    };
    let planned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM artifact
         WHERE tenant_id = $1 AND storage_state = 'committed' AND scope = 'endpoint' AND seq <= $2",
    )
    .bind(tenant_id)
    .bind(watermark)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "UPDATE hunt SET state = 'PLANNED', corpus_watermark = $3, planned_artifacts = $4,
             scanned = 0, cache_hits = 0, matched = 0, timed_out = 0, failed = 0,
             error = NULL, completed_at = NULL
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(hunt_id)
    .bind(tenant_id)
    .bind(watermark)
    .bind(planned)
    .execute(pool)
    .await?;

    // QUEUED -> RUNNING (single node: immediate).
    let tier = crate::sandbox::tier_from_env();
    set_state(pool, tenant_id, hunt_id, "QUEUED").await?;
    sqlx::query(
        "UPDATE hunt SET state = 'RUNNING', started_at = COALESCE(started_at, $3)
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(hunt_id)
    .bind(tenant_id)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    let artifacts: Vec<(Uuid, Vec<u8>, String)> = sqlx::query_as(
        "SELECT id, sha256, object_key FROM artifact
         WHERE tenant_id = $1 AND storage_state = 'committed' AND scope = 'endpoint' AND seq <= $2
         ORDER BY seq",
    )
    .bind(tenant_id)
    .bind(watermark)
    .fetch_all(pool)
    .await?;

    let mut scanned = 0i64;
    let mut cache_hits = 0i64;
    let mut matched = 0i64;
    let mut timed_out = 0i64;
    let mut failed = 0i64;

    for (artifact_id, sha_raw, object_key) in &artifacts {
        let key = ScanCacheKey::new(tenant_id, sha_raw.clone(), &hunt.bundle_digest);

        if let Some(hit) = cache_lookup(pool, &key).await? {
            // Re-running the same immutable hunt never rereads bytes, but
            // cached TERMINAL states still count: a cached timeout/error
            // must keep the rerun COMPLETED_PARTIAL instead of silently
            // relabeling the hunt COMPLETED (spec 15.2, M9 review fix).
            cache_hits += 1;
            if hit.status == ScanStatus::Timeout.as_str() {
                timed_out += 1;
            } else if hit.status == ScanStatus::Error.as_str() {
                failed += 1;
            } else if hit.status == ScanStatus::Matched.as_str() {
                for rule_id in &hit.matched_rule_ids {
                    commit_match(
                        pool,
                        tenant_id,
                        hunt_id,
                        *artifact_id,
                        rule_id,
                        serde_json::json!({"cached": true}),
                    )
                    .await?;
                    matched += 1;
                    fire_hunt_match(pool, tenant_id, hunt_id, *artifact_id, rule_id).await?;
                }
            }
        } else {
            // M6: scans run in the sandboxed corpus-scanner subprocess by
            // default (tier from CORPUS_SCANNER_TIER; inprocess for dev).
            match cas.read(object_key) {
                Ok(bytes) => {
                    let sample_path = cas.root().join(object_key);
                    let outcome = crate::sandbox::scan_with_tier(
                        tier,
                        &sources,
                        Some(&compiled),
                        &bytes,
                        Some(&sample_path),
                    )
                    .await;
                    let rule_ids: Vec<String> =
                        outcome.matches.iter().map(|m| m.rule_id.clone()).collect();
                    commit_cache_entry(
                        pool,
                        &key,
                        outcome.status.as_str(),
                        &rule_ids,
                        outcome.duration_ms,
                        outcome.error_code.as_deref(),
                    )
                    .await?;
                    match outcome.status {
                        ScanStatus::Matched => {
                            scanned += 1;
                            for m in &outcome.matches {
                                let summary = serde_json::to_value(m).unwrap_or_default();
                                commit_match(
                                    pool,
                                    tenant_id,
                                    hunt_id,
                                    *artifact_id,
                                    &m.rule_id,
                                    summary,
                                )
                                .await?;
                                matched += 1;
                                fire_hunt_match(pool, tenant_id, hunt_id, *artifact_id, &m.rule_id)
                                    .await?;
                            }
                        }
                        ScanStatus::Clean => scanned += 1,
                        ScanStatus::Timeout => timed_out += 1,
                        ScanStatus::Error => failed += 1,
                    }
                }
                Err(e) => {
                    failed += 1;
                    commit_cache_entry(pool, &key, "error", &[], 0, Some(&e.to_string())).await?;
                }
            }
        }

        sqlx::query(
            "UPDATE hunt SET scanned = $3, cache_hits = $4, matched = $5, timed_out = $6, failed = $7
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(hunt_id)
        .bind(tenant_id)
        .bind(scanned)
        .bind(cache_hits)
        .bind(matched)
        .bind(timed_out)
        .bind(failed)
        .execute(pool)
        .await?;
    }

    // COMPLETED_PARTIAL is mandatory when anything timed out or failed (spec 15.2).
    let final_state = if timed_out > 0 || failed > 0 {
        "COMPLETED_PARTIAL"
    } else {
        "COMPLETED"
    };
    sqlx::query("UPDATE hunt SET state = $3, completed_at = $4 WHERE id = $1 AND tenant_id = $2")
        .bind(hunt_id)
        .bind(tenant_id)
        .bind(final_state)
        .bind(Utc::now())
        .execute(pool)
        .await?;

    get_hunt(pool, tenant_id, hunt_id).await
}

/// Forward coverage (spec 15.9): scan newly committed bytes with every
/// active bundle, filling the same scan cache and match tables. Returns the
/// rule ids that matched across all active bundles.
pub async fn forward_scan(
    pool: &PgPool,
    tenant_id: Uuid,
    artifact_id: Uuid,
    sha_raw: &[u8],
    bytes: &[u8],
    object_key: &str,
    cas: &FsCas,
) -> Result<Vec<String>> {
    let bundles: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, digest FROM rule_bundle WHERE tenant_id = $1 AND active")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;

    let tier = crate::sandbox::tier_from_env();
    let sample_path = cas.root().join(object_key);
    let mut all_matches = Vec::new();
    for (bundle_id, digest) in bundles {
        let key = ScanCacheKey::new(tenant_id, sha_raw.to_vec(), &digest);
        if cache_lookup(pool, &key).await?.is_some() {
            continue;
        }
        let sources = registry::bundle_sources(pool, tenant_id, bundle_id).await?;
        let compiled = scan::compile_bundle(&sources).map_err(Error::RuleCompile)?;
        let outcome = crate::sandbox::scan_with_tier(
            tier,
            &sources,
            Some(&compiled),
            bytes,
            Some(&sample_path),
        )
        .await;
        let rule_ids: Vec<String> = outcome.matches.iter().map(|m| m.rule_id.clone()).collect();
        commit_cache_entry(
            pool,
            &key,
            outcome.status.as_str(),
            &rule_ids,
            outcome.duration_ms,
            outcome.error_code.as_deref(),
        )
        .await?;

        if let Some((forward_hunt_id,)) = sqlx::query_as::<_, (Uuid,)>(
            "SELECT id FROM hunt WHERE tenant_id = $1 AND bundle_id = $2 AND kind = 'forward'",
        )
        .bind(tenant_id)
        .bind(bundle_id)
        .fetch_optional(pool)
        .await?
        {
            for m in &outcome.matches {
                let summary = serde_json::to_value(m).unwrap_or_default();
                commit_match(
                    pool,
                    tenant_id,
                    forward_hunt_id,
                    artifact_id,
                    &m.rule_id,
                    summary,
                )
                .await?;
            }
            // Count every terminal scan (clean, match, timeout, error) so the
            // forward hunt reflects post-commit coverage, not only hits.
            let (d_scanned, d_matched, d_timeout, d_failed) = match outcome.status {
                ScanStatus::Clean | ScanStatus::Matched => {
                    (1i64, outcome.matches.len() as i64, 0i64, 0i64)
                }
                ScanStatus::Timeout => (0, 0, 1, 0),
                ScanStatus::Error => (0, 0, 0, 1),
            };
            sqlx::query(
                "UPDATE hunt SET scanned = scanned + $2, matched = matched + $3,
                     timed_out = timed_out + $4, failed = failed + $5
                 WHERE id = $1 AND tenant_id = $6",
            )
            .bind(forward_hunt_id)
            .bind(d_scanned)
            .bind(d_matched)
            .bind(d_timeout)
            .bind(d_failed)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }
        if !rule_ids.is_empty() {
            all_matches.extend(rule_ids);
        }
    }
    Ok(all_matches)
}

/// Trigger event for a committed hunt match (fires are idempotent-tolerant;
/// the outbox is at-least-once by design).
async fn fire_hunt_match(
    pool: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
    artifact_id: Uuid,
    rule_id: &str,
) -> Result<()> {
    crate::triggers::fire(
        pool,
        tenant_id,
        crate::triggers::CONDITION_HUNT_MATCH,
        serde_json::json!({
            "type": "hunt_match",
            "hunt_id": hunt_id,
            "artifact_id": artifact_id,
            "rule_id": rule_id,
        }),
    )
    .await?;
    Ok(())
}
