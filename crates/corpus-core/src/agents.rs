//! Agent enrollment, heartbeat, and gap reporting (spec 10.1, 10.11).
//!
//! # Enrollment
//!
//! One-time enrollment tokens mint long-lived agent credentials. Tokens
//! are shown once, hashed at rest, and expire by TTL. Successful enroll
//! creates an `agent` row bound to a tenant and returns the credential
//! material the endpoint stores locally.
//!
//! # Heartbeat
//!
//! Agents periodically report host identity, agent version, boot id, and
//! sequence high-water marks. Missed heartbeats surface in coverage gap
//! views.
//!
//! # Gaps
//!
//! Agents may report sequence gaps (lost observations). The server
//! records them for analyst follow-up; it does not re-task the agent
//! (observe-only).

use crate::dto::{
    AgentStatusResponse, EnrollRequest, EnrollResponse, EnrollmentTokenResponse, GapEvent,
    HeartbeatRequest,
};
use crate::error::{Error, Result};
use crate::hash;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Authenticated agent identity resolved from a bearer token.
pub struct AgentIdentity {
    pub agent_id: Uuid,
    pub tenant_id: Uuid,
    pub host_name: String,
}

/// SHA-256 of a plaintext enrollment/agent token for at-rest storage.
pub fn hash_token(token: &str) -> Vec<u8> {
    hash::sha256_raw(token.as_bytes())
}

/// Mint a one-time enrollment token (operator action via corpusctl).
pub async fn create_enrollment_token(
    pool: &PgPool,
    tenant_id: Uuid,
    label: &str,
    ttl_secs: Option<i64>,
) -> Result<EnrollmentTokenResponse> {
    let token = format!("cptok-{}", Uuid::new_v4());
    let expires_at = ttl_secs.map(|s| Utc::now() + chrono::Duration::seconds(s));
    sqlx::query(
        "INSERT INTO enrollment_token (token_sha256, tenant_id, label, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(hash_token(&token))
    .bind(tenant_id)
    .bind(label)
    .bind(Utc::now())
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(EnrollmentTokenResponse { token, expires_at })
}

/// Exchange a one-time enrollment token for an agent identity + bearer token.
/// The response also carries a signed mTLS client cert for the agent
/// listener — the bearer token is a legacy/dev credential only.
pub async fn enroll(
    pool: &PgPool,
    ca: &crate::mtls::DeploymentCa,
    req: &EnrollRequest,
) -> Result<EnrollResponse> {
    let token_hash = hash_token(&req.enrollment_token);
    let row: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE enrollment_token SET consumed_at = $2
         WHERE token_sha256 = $1 AND consumed_at IS NULL
           AND (expires_at IS NULL OR expires_at > $2)
         RETURNING tenant_id",
    )
    .bind(&token_hash)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    let (tenant_id,) = row.ok_or_else(|| {
        Error::BadRequest("invalid, expired, or consumed enrollment token".into())
    })?;

    // Enrollment is a write path: the token's tenant must be active.
    let tenant = crate::tenant::get_tenant(pool, tenant_id).await?;
    if tenant.status != "active" {
        return Err(Error::Forbidden(format!(
            "tenant {} is {}",
            tenant.slug, tenant.status
        )));
    }

    let agent_id = Uuid::new_v4();
    let agent_token = format!("cpagent-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO agent (id, tenant_id, host_name, token_sha256, version, enrolled_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(agent_id)
    .bind(tenant_id)
    .bind(&req.host_name)
    .bind(hash_token(&agent_token))
    .bind(&req.agent_version)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    sqlx::query("UPDATE enrollment_token SET consumed_by = $2 WHERE token_sha256 = $1")
        .bind(&token_hash)
        .bind(agent_id)
        .execute(pool)
        .await?;
    let (client_cert_pem, client_key_pem) =
        crate::mtls::sign_client_cert(ca, agent_id, crate::mtls::DEFAULT_TTL_DAYS)?;
    Ok(EnrollResponse {
        agent_id,
        agent_token,
        tenant_id,
        ca_cert_pem: ca.cert_pem.clone(),
        client_cert_pem,
        client_key_pem,
    })
}

/// Issue a fresh client cert to an agent authenticated over mTLS
/// (rotation; TTL restarts from now).
pub fn renew_cert(
    ca: &crate::mtls::DeploymentCa,
    agent_id: Uuid,
) -> Result<crate::dto::RenewCertResponse> {
    let (client_cert_pem, client_key_pem) =
        crate::mtls::sign_client_cert(ca, agent_id, crate::mtls::DEFAULT_TTL_DAYS)?;
    Ok(crate::dto::RenewCertResponse {
        client_cert_pem,
        client_key_pem,
        ca_cert_pem: ca.cert_pem.clone(),
    })
}

/// Resolve an agent by cert-derived identity (mTLS path).
pub async fn authenticate_cert(pool: &PgPool, agent_id: Uuid) -> Result<AgentIdentity> {
    let row: Option<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, tenant_id, host_name FROM agent WHERE id = $1")
            .bind(agent_id)
            .fetch_optional(pool)
            .await?;
    let (agent_id, tenant_id, host_name) =
        row.ok_or_else(|| Error::Unauthorized("unknown agent cert identity".into()))?;
    Ok(AgentIdentity {
        agent_id,
        tenant_id,
        host_name,
    })
}

/// Resolve an agent bearer token to its identity. Legacy dev mode only —
/// requires CORPUS_AGENT_LEGACY_BEARER=1 on the server.
pub async fn authenticate(pool: &PgPool, bearer: &str) -> Result<AgentIdentity> {
    if std::env::var("CORPUS_AGENT_LEGACY_BEARER").is_err() {
        return Err(Error::Unauthorized(
            "bearer auth disabled (mTLS agent listener is the default); set CORPUS_AGENT_LEGACY_BEARER=1 for legacy dev mode".into(),
        ));
    }
    let row: Option<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, tenant_id, host_name FROM agent WHERE token_sha256 = $1")
            .bind(hash_token(bearer))
            .fetch_optional(pool)
            .await?;
    let (agent_id, tenant_id, host_name) =
        row.ok_or_else(|| Error::Unauthorized("invalid agent token".into()))?;
    Ok(AgentIdentity {
        agent_id,
        tenant_id,
        host_name,
    })
}

/// Store the latest heartbeat fields on the agent row (spec 10.11).
pub async fn heartbeat(pool: &PgPool, ident: &AgentIdentity, hb: &HeartbeatRequest) -> Result<()> {
    sqlx::query(
        "UPDATE agent SET
           version = $2, last_heartbeat_at = $3, last_upload_at = $4, policy_digest = $5,
           baseline_state = $6, baseline_percent = $7, queue_depth = $8, spool_bytes = $9,
           oldest_pending_secs = $10, sensor = $11, outcome_counts = $12, clock_offset_ms = $13
         WHERE id = $1",
    )
    .bind(ident.agent_id)
    .bind(&hb.agent_version)
    .bind(Utc::now())
    .bind(hb.last_upload_at)
    .bind(&hb.policy_digest)
    .bind(&hb.baseline_state)
    .bind(hb.baseline_percent)
    .bind(hb.queue_depth)
    .bind(hb.spool_bytes)
    .bind(hb.oldest_pending_secs)
    .bind(&hb.sensor)
    .bind(&hb.outcome_counts)
    .bind(hb.clock_offset_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist a batch of coverage-gap capture attempts (spec 2.2 taxonomy).
pub async fn record_gaps(pool: &PgPool, ident: &AgentIdentity, gaps: &[GapEvent]) -> Result<usize> {
    record_gaps_scoped(
        pool,
        ident.tenant_id,
        &ident.host_name,
        ident.agent_id,
        gaps,
    )
    .await
}

/// Dev-path gap reporting (no bearer, e.g. corpusctl OCI importer): host
/// comes from the event, agent identity is nil.
pub async fn record_gaps_dev(pool: &PgPool, tenant_id: Uuid, gaps: &[GapEvent]) -> Result<usize> {
    let host = gaps
        .first()
        .and_then(|g| g.host_name.clone())
        .unwrap_or_else(|| "corpusctl".into());
    record_gaps_scoped(pool, tenant_id, &host, Uuid::nil(), gaps).await
}

async fn record_gaps_scoped(
    pool: &PgPool,
    tenant_id: Uuid,
    host_name: &str,
    agent_id: Uuid,
    gaps: &[GapEvent],
) -> Result<usize> {
    let mut tx = pool.begin().await?;
    for g in gaps {
        let sha = match &g.artifact_sha256 {
            Some(s) => Some(
                hash::hex_to_raw(s)
                    .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {s:?}")))?,
            ),
            None => None,
        };
        sqlx::query(
            "INSERT INTO capture_attempt
             (id, tenant_id, host_name, agent_id, observed_at, capture_reason,
              terminal_outcome, artifact_sha256, path, detail_code, detail)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(host_name)
        .bind(agent_id)
        .bind(g.observed_at)
        .bind(&g.capture_reason)
        .bind(&g.terminal_outcome)
        .bind(sha)
        .bind(&g.path)
        .bind(&g.detail_code)
        .bind(g.detail.clone().unwrap_or_else(|| serde_json::json!({})))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(gaps.len())
}

#[derive(Debug, sqlx::FromRow)]
struct AgentRow {
    id: Uuid,
    host_name: String,
    version: String,
    enrolled_at: DateTime<Utc>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    last_upload_at: Option<DateTime<Utc>>,
    policy_digest: Option<String>,
    baseline_state: Option<String>,
    baseline_percent: Option<f64>,
    queue_depth: Option<i64>,
    spool_bytes: Option<i64>,
    oldest_pending_secs: Option<i64>,
    sensor: Option<String>,
    outcome_counts: serde_json::Value,
    clock_offset_ms: Option<i64>,
}

impl AgentRow {
    fn into_response(self) -> AgentStatusResponse {
        AgentStatusResponse {
            id: self.id,
            host_name: self.host_name,
            version: self.version,
            enrolled_at: self.enrolled_at,
            last_heartbeat_at: self.last_heartbeat_at,
            last_upload_at: self.last_upload_at,
            policy_digest: self.policy_digest,
            baseline_state: self.baseline_state,
            baseline_percent: self.baseline_percent,
            queue_depth: self.queue_depth,
            spool_bytes: self.spool_bytes,
            oldest_pending_secs: self.oldest_pending_secs,
            sensor: self.sensor,
            outcome_counts: self.outcome_counts,
            clock_offset_ms: self.clock_offset_ms,
        }
    }
}

const AGENT_COLS: &str = "id, host_name, version, enrolled_at, last_heartbeat_at, last_upload_at,
     policy_digest, baseline_state, baseline_percent, queue_depth, spool_bytes,
     oldest_pending_secs, sensor, outcome_counts, clock_offset_ms";

/// List agents for a tenant with last-heartbeat metadata.
pub async fn list_agents(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<AgentStatusResponse>> {
    let rows = sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {AGENT_COLS} FROM agent WHERE tenant_id = $1 ORDER BY enrolled_at"
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(AgentRow::into_response).collect())
}

/// Fetch one agent's status by id.
pub async fn agent_status(
    pool: &PgPool,
    tenant_id: Uuid,
    agent_id: Uuid,
) -> Result<AgentStatusResponse> {
    let row = sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {AGENT_COLS} FROM agent WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::NotFound(format!("agent {agent_id}")))?;
    Ok(row.into_response())
}

/// Coverage-gap view over capture attempts (spec 2.2: a missed file is data).
pub async fn coverage_gaps(
    pool: &PgPool,
    tenant_id: Uuid,
    outcome: Option<&str>,
    limit: i64,
) -> Result<Vec<crate::dto::CoverageGapRow>> {
    let rows = sqlx::query_as::<_, crate::dto::CoverageGapRow>(
        "SELECT id, host_name, agent_id, observed_at, capture_reason, terminal_outcome,
                encode(artifact_sha256, 'hex') AS artifact_sha256_hex, path, detail_code
         FROM capture_attempt
         WHERE tenant_id = $1
           AND terminal_outcome NOT IN ('CAPTURED', 'ALREADY_PRESENT')
           AND ($2::text IS NULL OR terminal_outcome = $2)
         ORDER BY observed_at DESC
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(outcome)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
