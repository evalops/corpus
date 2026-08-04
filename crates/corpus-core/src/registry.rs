//! Rule registry and immutable bundle publication (spec 14).
//!
//! # Lifecycle
//!
//! 1. Operators upsert individual rule sources (validated via [`crate::rules`]).
//! 2. A **bundle** freezes a set of rules + compiler config into a digest.
//! 3. One bundle may be **activated** for forward scans; retro-hunts pin
//!    any historical digest.
//!
//! Bundles are content-addressed and never mutated in place. Activation
//! is a pointer flip.

use crate::dto::{BundleResponse, RuleResponse};
use crate::error::{Error, Result};
use crate::rules;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
/// Stored rule source row with stable id and compile metadata.
pub struct RuleRow {
    pub id: Uuid,
    pub namespace: String,
    pub stable_id: String,
    pub source: String,
    pub state: String,
    pub created_at: chrono::DateTime<Utc>,
}

impl RuleRow {
    pub fn into_response(self) -> RuleResponse {
        RuleResponse {
            id: self.id,
            namespace: self.namespace,
            stable_id: self.stable_id,
            state: self.state,
            created_at: self.created_at,
        }
    }
}

/// Add a rule: parse the stable id, validate compilation via YARA-X, and
/// store it VALIDATED (spec 14.4 step 1; the deeper validation pipeline —
/// tests, profiling, review — is post-M0).
pub async fn create_rule(pool: &PgPool, tenant_id: Uuid, source: &str) -> Result<RuleResponse> {
    let stable_id = rules::parse_rule_name(source)?;
    rules::compile_validate(source)?;

    if let Some(existing) = get_rule_by_stable_id(pool, tenant_id, &stable_id).await? {
        if existing.source == source {
            return Ok(existing.into_response());
        }
        return Err(Error::Conflict(format!(
            "rule {stable_id:?} already exists with different source; revoke it first"
        )));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let row = sqlx::query_as::<_, RuleRow>(
        "INSERT INTO rule (id, tenant_id, namespace, stable_id, source, state, created_at, updated_at)
         VALUES ($1,$2,'default',$3,$4,'VALIDATED',$5,$5)
         RETURNING id, namespace, stable_id, source, state, created_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&stable_id)
    .bind(source)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.into_response())
}

/// Fetch a rule by its stable name-derived id.
pub async fn get_rule_by_stable_id(
    pool: &PgPool,
    tenant_id: Uuid,
    stable_id: &str,
) -> Result<Option<RuleRow>> {
    Ok(sqlx::query_as::<_, RuleRow>(
        "SELECT id, namespace, stable_id, source, state, created_at
         FROM rule WHERE tenant_id = $1 AND stable_id = $2",
    )
    .bind(tenant_id)
    .bind(stable_id)
    .fetch_optional(pool)
    .await?)
}

/// List rules for a tenant.
pub async fn list_rules(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<RuleResponse>> {
    let rows = sqlx::query_as::<_, RuleRow>(
        "SELECT id, namespace, stable_id, source, state, created_at
         FROM rule WHERE tenant_id = $1 ORDER BY stable_id",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(RuleRow::into_response).collect())
}

/// Publish an immutable bundle (spec 14.5). The digest covers canonically
/// ordered rule sources plus compiler config; re-publishing the same set
/// returns the existing bundle. `activate` turns on forward coverage
/// (spec 15.9) and creates the bundle's persistent forward hunt.
pub async fn publish_bundle(
    pool: &PgPool,
    tenant_id: Uuid,
    rule_ids: &[Uuid],
    activate: bool,
) -> Result<BundleResponse> {
    if rule_ids.is_empty() {
        return Err(Error::BadRequest(
            "bundle requires at least one rule".into(),
        ));
    }

    let mut members = Vec::new();
    for id in rule_ids {
        let rule = sqlx::query_as::<_, RuleRow>(
            "SELECT id, namespace, stable_id, source, state, created_at
             FROM rule WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| Error::NotFound(format!("rule {id}")))?;
        if rule.state == "REVOKED" {
            return Err(Error::BadRequest(format!(
                "rule {} is REVOKED",
                rule.stable_id
            )));
        }
        members.push(rule);
    }
    members.sort_by(|a, b| a.stable_id.cmp(&b.stable_id));

    // Whole bundle must compile together before publication.
    let sources: Vec<(String, String)> = members
        .iter()
        .map(|r| (r.namespace.clone(), r.source.clone()))
        .collect();
    crate::scan::compile_bundle(&sources).map_err(Error::RuleCompile)?;

    let digest = rules::bundle_digest(
        &members
            .iter()
            .map(|r| (r.stable_id.clone(), r.source.clone()))
            .collect::<Vec<_>>(),
        rules::COMPILER_CONFIG,
    );

    let mut tx = pool.begin().await?;

    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM rule_bundle WHERE tenant_id = $1 AND digest = $2")
            .bind(tenant_id)
            .bind(&digest)
            .fetch_optional(&mut *tx)
            .await?;

    let bundle_id = if let Some((id,)) = existing {
        if activate {
            sqlx::query("UPDATE rule_bundle SET active = true WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        id
    } else {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO rule_bundle (id, tenant_id, digest, scope, engine_version, active, created_at)
             VALUES ($1,$2,$3,'tenant',$4,$5,$6)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&digest)
        .bind(crate::ENGINE_VERSION)
        .bind(activate)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;
        for (pos, rule) in members.iter().enumerate() {
            sqlx::query(
                "INSERT INTO rule_bundle_rule (bundle_id, rule_id, position) VALUES ($1,$2,$3)",
            )
            .bind(id)
            .bind(rule.id)
            .bind(pos as i32)
            .execute(&mut *tx)
            .await?;
        }
        id
    };

    // Publication activates member rules (DRAFT/VALIDATED -> ACTIVE).
    for rule in &members {
        sqlx::query("UPDATE rule SET state = 'ACTIVE', updated_at = $2 WHERE id = $1 AND state IN ('DRAFT','VALIDATED')")
            .bind(rule.id)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await?;
    }

    // Forward coverage: one persistent forward hunt per active bundle.
    if activate {
        let forward_exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM hunt WHERE tenant_id = $1 AND bundle_id = $2 AND kind = 'forward'",
        )
        .bind(tenant_id)
        .bind(bundle_id)
        .fetch_optional(&mut *tx)
        .await?;
        if forward_exists.is_none() {
            sqlx::query(
                "INSERT INTO hunt (id, tenant_id, kind, bundle_id, bundle_digest, state, created_at)
                 VALUES ($1,$2,'forward',$3,$4,'ACTIVE_FORWARD',$5)",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(bundle_id)
            .bind(&digest)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    get_bundle(pool, tenant_id, &digest).await
}

#[derive(Debug, sqlx::FromRow)]
/// Published bundle metadata including content digest.
pub struct BundleRow {
    pub id: Uuid,
    pub digest: String,
    pub scope: String,
    pub engine_version: String,
    pub active: bool,
    pub rule_count: i64,
    pub created_at: chrono::DateTime<Utc>,
}

impl BundleRow {
    pub fn into_response(self) -> BundleResponse {
        BundleResponse {
            id: self.id,
            digest: self.digest,
            scope: self.scope,
            engine_version: self.engine_version,
            active: self.active,
            rule_count: self.rule_count,
            created_at: self.created_at,
        }
    }
}

/// Load bundle metadata by digest for a tenant.
pub async fn get_bundle(pool: &PgPool, tenant_id: Uuid, digest: &str) -> Result<BundleResponse> {
    let row = sqlx::query_as::<_, BundleRow>(
        "SELECT b.id, b.digest, b.scope, b.engine_version, b.active,
                (SELECT count(*) FROM rule_bundle_rule rbr WHERE rbr.bundle_id = b.id) AS rule_count,
                b.created_at
         FROM rule_bundle b WHERE b.tenant_id = $1 AND b.digest = $2",
    )
    .bind(tenant_id)
    .bind(digest)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::NotFound(format!("bundle {digest}")))?;
    Ok(row.into_response())
}

/// List published bundles for a tenant.
pub async fn list_bundles(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<BundleResponse>> {
    let rows = sqlx::query_as::<_, BundleRow>(
        "SELECT b.id, b.digest, b.scope, b.engine_version, b.active,
                (SELECT count(*) FROM rule_bundle_rule rbr WHERE rbr.bundle_id = b.id) AS rule_count,
                b.created_at
         FROM rule_bundle b WHERE b.tenant_id = $1 ORDER BY b.created_at",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(BundleRow::into_response).collect())
}

/// Ordered (namespace, source) pairs for a bundle, used to compile the
/// immutable bundle for scanning.
pub async fn bundle_sources(
    pool: &PgPool,
    tenant_id: Uuid,
    bundle_id: Uuid,
) -> Result<Vec<(String, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT r.namespace, r.source
         FROM rule_bundle_rule rbr JOIN rule r ON r.id = rbr.rule_id
         WHERE rbr.bundle_id = $1 AND r.tenant_id = $2
         ORDER BY rbr.position",
    )
    .bind(bundle_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
