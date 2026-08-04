//! Analyst surface: prevalence, rarity search, and related queries.
//!
//! # Prevalence
//!
//! How widely is a digest observed across hosts/agents within a tenant?
//! Low prevalence + high severity is a classic investigation pivot.
//!
//! # Rarity
//!
//! Search for uncommon structural features (imports, section layouts)
//! among committed artifacts. Backed by similarity features, not raw
//! bytes.

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Prevalence {
    pub host_count: i64,
    pub path_count: i64,
    pub first_observed: Option<DateTime<Utc>>,
    pub last_observed: Option<DateTime<Utc>>,
}

/// Fleet prevalence for one artifact: distinct hosts and paths, first and
/// last observation across all occurrences.
pub async fn prevalence_for(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Prevalence> {
    let row = sqlx::query_as::<_, Prevalence>(
        "SELECT count(DISTINCT host_name) AS host_count,
                count(DISTINCT path) AS path_count,
                min(observed_at) AS first_observed,
                max(observed_at) AS last_observed
         FROM occurrence_event
         WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

#[derive(Debug, Clone, Serialize)]
pub struct RarityHit {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub artifact_class: String,
    pub first_committed_at: DateTime<Utc>,
    pub prevalence: Prevalence,
    pub opinion: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
struct RarityRow {
    id: Uuid,
    sha256: Vec<u8>,
    artifact_class: String,
    first_committed_at: DateTime<Utc>,
    host_count: i64,
    path_count: i64,
    first_observed: Option<DateTime<Utc>>,
    last_observed: Option<DateTime<Utc>>,
    opinion: Option<String>,
}

/// Rarity hunting: endpoint-scope artifacts seen on at most `max_hosts`
/// hosts, with activity at or after `since`. Ordered rarest-first.
pub async fn rarity_search(
    pool: &PgPool,
    tenant: Uuid,
    max_hosts: i64,
    since: DateTime<Utc>,
    opinion: Option<&str>,
    limit: i64,
) -> Result<Vec<RarityHit>> {
    let rows: Vec<RarityRow> = sqlx::query_as(
        "SELECT a.id, a.sha256, a.artifact_class, a.first_committed_at,
                count(DISTINCT o.host_name) AS host_count,
                count(DISTINCT o.path) AS path_count,
                min(o.observed_at) AS first_observed,
                max(o.observed_at) AS last_observed,
                (SELECT op.opinion FROM artifact_opinion op
                 WHERE op.tenant_id = a.tenant_id AND op.artifact_id = a.id
                 ORDER BY op.created_at DESC LIMIT 1) AS opinion
         FROM artifact a
         JOIN occurrence_event o ON o.tenant_id = a.tenant_id AND o.artifact_id = a.id
         WHERE a.tenant_id = $1 AND a.scope = 'endpoint' AND a.storage_state = 'committed'
         GROUP BY a.id, a.sha256, a.artifact_class, a.first_committed_at
         HAVING count(DISTINCT o.host_name) <= $2 AND max(o.observed_at) >= $3
           AND ($4::text IS NULL OR (SELECT op.opinion FROM artifact_opinion op
                 WHERE op.tenant_id = a.tenant_id AND op.artifact_id = a.id
                 ORDER BY op.created_at DESC LIMIT 1) = $4)
         ORDER BY host_count ASC, last_observed DESC
         LIMIT $5",
    )
    .bind(tenant)
    .bind(max_hosts)
    .bind(since)
    .bind(opinion)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RarityHit {
            artifact_id: r.id,
            sha256: hex::encode(r.sha256),
            artifact_class: r.artifact_class,
            first_committed_at: r.first_committed_at,
            prevalence: Prevalence {
                host_count: r.host_count,
                path_count: r.path_count,
                first_observed: r.first_observed,
                last_observed: r.last_observed,
            },
            opinion: r.opinion,
        })
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct DropperCandidate {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub host_name: String,
    pub path: Option<String>,
    pub host_count: i64,
    pub min_time_delta_secs: i64,
    pub first_observed: Option<DateTime<Utc>>,
}

/// Dropper heuristic (lead generator, NOT a verdict): artifacts with low
/// prevalence (host_count <= max_hosts) whose FIRST observation on a host
/// falls within +/- window_hours of an occurrence of the seed artifact or
/// any of its variant group members, on the same host. A candidate whose
/// first observation on that host is outside the window does NOT match,
/// even if a later occurrence happens to land inside it.
pub async fn dropper_candidates(
    pool: &PgPool,
    tenant: Uuid,
    seed_sha256: &str,
    max_hosts: i64,
    window_hours: i64,
    limit: i64,
) -> Result<Vec<DropperCandidate>> {
    let raw = crate::hash::hex_to_raw(seed_sha256)
        .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {seed_sha256:?}")))?;
    let seed: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant)
            .bind(&raw)
            .fetch_optional(pool)
            .await?;
    let Some((seed_id,)) = seed else {
        return Ok(vec![]);
    };

    // Seed set: the artifact plus its variant group members.
    let mut seed_ids = vec![seed_id];
    let (_g, members) = crate::similarity::edges::group_members(pool, tenant, seed_id).await?;
    seed_ids.extend(members.into_iter().map(|(id, _)| id));

    let window_secs = window_hours * 3600;
    #[derive(sqlx::FromRow)]
    struct DropRow {
        id: Uuid,
        sha256: Vec<u8>,
        host_name: String,
        path: Option<String>,
        host_count: i64,
        min_delta: i64,
        first_observed: Option<DateTime<Utc>>,
    }
    // first_occ is each candidate artifact's FIRST observation per host
    // (MIN(observed_at) per artifact+host); only that first observation is
    // allowed to fall inside the seed window (M9 review fix).
    let rows: Vec<DropRow> = sqlx::query_as(
        "WITH seed_occ AS (
           SELECT host_name, observed_at FROM occurrence_event
           WHERE tenant_id = $1 AND artifact_id = ANY($2)
         ),
         first_occ AS (
           SELECT DISTINCT ON (o.artifact_id, o.host_name)
                  o.artifact_id AS id, o.host_name, o.path, o.observed_at
           FROM occurrence_event o
           JOIN artifact a ON a.tenant_id = o.tenant_id AND a.id = o.artifact_id
           WHERE o.tenant_id = $1 AND NOT (o.artifact_id = ANY($2))
             AND a.scope = 'endpoint'
           ORDER BY o.artifact_id, o.host_name, o.observed_at ASC
         ),
         cand AS (
           SELECT f.id, f.host_name, f.path,
                  min(abs(extract(epoch FROM (f.observed_at - s.observed_at))))::bigint AS min_delta
           FROM first_occ f
           JOIN seed_occ s ON s.host_name = f.host_name
                          AND abs(extract(epoch FROM (f.observed_at - s.observed_at))) <= $3
           GROUP BY f.id, f.host_name, f.path
         )
         SELECT c.id, a.sha256, c.host_name, c.path,
                (SELECT count(DISTINCT o2.host_name) FROM occurrence_event o2
                 WHERE o2.tenant_id = $1 AND o2.artifact_id = c.id) AS host_count,
                c.min_delta AS min_delta,
                (SELECT min(o3.observed_at) FROM occurrence_event o3
                 WHERE o3.tenant_id = $1 AND o3.artifact_id = c.id) AS first_observed
         FROM cand c
         JOIN artifact a ON a.tenant_id = $1 AND a.id = c.id
         ORDER BY min_delta ASC
         LIMIT $4",
    )
    .bind(tenant)
    .bind(&seed_ids)
    .bind(window_secs)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.host_count <= max_hosts)
        .map(|r| DropperCandidate {
            artifact_id: r.id,
            sha256: hex::encode(r.sha256),
            host_name: r.host_name,
            path: r.path,
            host_count: r.host_count,
            min_time_delta_secs: r.min_delta,
            first_observed: r.first_observed,
        })
        .collect())
}

/// Parse a --since value: RFC3339 or a relative duration like 7d/24h/30m.
pub fn parse_since(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| Error::BadRequest(format!("invalid --since {s:?}")))?;
    let now = Utc::now();
    match unit {
        "d" => Ok(now - chrono::Duration::days(n)),
        "h" => Ok(now - chrono::Duration::hours(n)),
        "m" => Ok(now - chrono::Duration::minutes(n)),
        _ => Err(Error::BadRequest(format!(
            "invalid --since {s:?} (use RFC3339 or 7d/24h/30m)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since_values() {
        assert!(parse_since("2026-01-01T00:00:00Z").is_ok());
        assert!(parse_since("7d").is_ok());
        assert!(parse_since("24h").is_ok());
        assert!(parse_since("30m").is_ok());
        assert!(parse_since("xd").is_err());
        assert!(parse_since("soon").is_err());
        let t = parse_since("1d").unwrap();
        let delta = (Utc::now() - t).num_hours();
        assert!((23..=24).contains(&delta));
    }
}
