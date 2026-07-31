//! Announce-before-upload protocol and two-phase artifact commit
//! (spec 11.1, 11.2). The server owns every write.

use crate::cas::FsCas;
use crate::classify;
use crate::dto::{
    AnnounceDisposition, AnnounceRequest, AnnounceResponse, FinalizeRequest, FinalizeResponse,
    OccurrenceInfo,
};
use crate::error::{Error, Result};
use crate::hash;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub const OUTCOME_CAPTURED: &str = "CAPTURED";
pub const OUTCOME_ALREADY_PRESENT: &str = "ALREADY_PRESENT";
pub const OUTCOME_HASH_MISMATCH: &str = "HASH_MISMATCH";

struct OccurrenceInsert<'a> {
    tenant_id: Uuid,
    artifact_id: Option<Uuid>,
    artifact_sha256: Option<&'a [u8]>,
    occ: &'a OccurrenceInfo,
}

async fn insert_occurrence<'e>(
    tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
    i: OccurrenceInsert<'_>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO occurrence_event
         (id, tenant_id, host_name, agent_id, boot_id, agent_sequence, artifact_id,
          artifact_sha256, event_type, capture_reason, observed_at, received_at,
          path, file_size, file_mtime, process_evidence)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (tenant_id, agent_id, boot_id, agent_sequence) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(i.tenant_id)
    .bind(&i.occ.host_name)
    .bind(i.occ.agent_id)
    .bind(i.occ.boot_id)
    .bind(i.occ.agent_sequence)
    .bind(i.artifact_id)
    .bind(i.artifact_sha256)
    .bind("observed")
    .bind(&i.occ.capture_reason)
    .bind(i.occ.observed_at)
    .bind(Utc::now())
    .bind(&i.occ.path)
    .bind(i.occ.file_size)
    .bind(i.occ.file_mtime)
    .bind(Option::<serde_json::Value>::None)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_capture_attempt<'e>(
    tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
    tenant_id: Uuid,
    host_name: &str,
    agent_id: Uuid,
    observed_at: chrono::DateTime<Utc>,
    capture_reason: &str,
    outcome: &str,
    sha256: Option<&[u8]>,
    path: Option<&str>,
    detail_code: Option<&str>,
    detail: serde_json::Value,
) -> Result<()> {
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
    .bind(observed_at)
    .bind(capture_reason)
    .bind(outcome)
    .bind(sha256)
    .bind(path)
    .bind(detail_code)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Host/agent/reason triple for capture-attempt bookkeeping, derived from
/// the occurrence when present, else from intel provenance.
fn attempt_meta<'a>(occ: Option<&'a OccurrenceInfo>, provenance: Option<&'a serde_json::Value>) -> (String, Uuid, chrono::DateTime<Utc>, String, Option<&'a str>) {
    match occ {
        Some(o) => (o.host_name.clone(), o.agent_id, o.observed_at, o.capture_reason.clone(), Some(o.path.as_str())),
        None => {
            let source = provenance
                .and_then(|p| p.get("source").and_then(|s| s.as_str()))
                .unwrap_or("intel-import")
                .to_string();
            let path = provenance.and_then(|p| p.get("path").and_then(|s| s.as_str()));
            (source, Uuid::nil(), Utc::now(), "intel_import".to_string(), path)
        }
    }
}

/// Phase 1: dedup check scoped to the tenant. A dedup hit still records the
/// occurrence and capture attempt (spec 11.1) — endpoint evidence is never
/// skipped.
pub async fn announce(pool: &PgPool, tenant_id: Uuid, req: &AnnounceRequest) -> Result<AnnounceResponse> {
    let sha_raw = hash::hex_to_raw(&req.sha256)
        .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {:?}", req.sha256)))?;

    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant_id)
            .bind(&sha_raw)
            .fetch_optional(pool)
            .await?;

    if let Some((artifact_id,)) = existing {
        let mut tx = pool.begin().await?;
        if let Some(occ) = &req.occurrence {
            insert_occurrence(
                &mut tx,
                OccurrenceInsert {
                    tenant_id,
                    artifact_id: Some(artifact_id),
                    artifact_sha256: Some(&sha_raw),
                    occ,
                },
            )
            .await?;
        }
        let (host, agent, observed, reason, path) = attempt_meta(req.occurrence.as_ref(), None);
        insert_capture_attempt(
            &mut tx,
            tenant_id,
            &host,
            agent,
            observed,
            &reason,
            OUTCOME_ALREADY_PRESENT,
            Some(&sha_raw),
            path,
            None,
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        return Ok(AnnounceResponse {
            disposition: AnnounceDisposition::AlreadyPresent,
            upload_id: None,
            artifact_id: Some(artifact_id),
        });
    }

    let upload_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_session (id, tenant_id, announced_sha256, announced_size, staging_key, state, created_at)
         VALUES ($1,$2,$3,$4,$5,'open',$6)",
    )
    .bind(upload_id)
    .bind(tenant_id)
    .bind(&sha_raw)
    .bind(req.size_bytes)
    .bind(upload_id.to_string())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(AnnounceResponse {
        disposition: AnnounceDisposition::UploadRequired,
        upload_id: Some(upload_id),
        artifact_id: None,
    })
}

/// Phase 2a: receive staged bytes for an open upload session.
pub async fn stage_upload(pool: &PgPool, cas: &FsCas, tenant_id: Uuid, upload_id: Uuid, bytes: &[u8]) -> Result<()> {
    let state: Option<(String,)> =
        sqlx::query_as("SELECT state FROM upload_session WHERE id = $1 AND tenant_id = $2")
            .bind(upload_id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;
    match state.map(|s| s.0) {
        Some(s) if s == "open" => cas.stage(&upload_id.to_string(), bytes),
        Some(s) => Err(Error::Conflict(format!("upload session {upload_id} is {s}"))),
        None => Err(Error::NotFound(format!("upload session {upload_id}"))),
    }
}

/// Phase 2b: rehash staged bytes, reject on mismatch (invariant #1), promote
/// to the CAS, and commit artifact + occurrence + capture attempt in one
/// transaction. Then run forward-coverage scans for active bundles.
pub async fn finalize(pool: &PgPool, cas: &FsCas, tenant_id: Uuid, req: &FinalizeRequest) -> Result<FinalizeResponse> {
    let session: Option<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT state, staging_key, announced_sha256 FROM upload_session WHERE id = $1 AND tenant_id = $2",
    )
    .bind(req.upload_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    let (state, staging_key, _announced) = session
        .ok_or_else(|| Error::NotFound(format!("upload session {}", req.upload_id)))?;
    if state != "open" {
        return Err(Error::Conflict(format!("upload session {} is {state}", req.upload_id)));
    }

    let bytes = cas.read(&format!("staging/{staging_key}"))?;

    if bytes.len() as i64 != req.size_bytes {
        cas.discard_staging(&staging_key);
        mark_session_failed(pool, req.upload_id).await?;
        return Err(Error::BadRequest(format!(
            "size mismatch: announced {}, received {}",
            req.size_bytes,
            bytes.len()
        )));
    }

    // Invariant #1: server-recomputed hash is the identity; client hash is a hint.
    let sha_raw = match hash::verify_upload(&bytes, &req.sha256) {
        Ok(raw) => raw,
        Err(err @ Error::HashMismatch { .. }) => {
            let recomputed = hash::sha256_hex(&bytes);
            // Record the coverage gap against the *announced* (untrusted) hash;
            // the recomputed bytes are never committed.
            let announced_raw = hash::hex_to_raw(&req.sha256).unwrap_or_default();
            let (host, agent, observed, reason, path) = attempt_meta(req.occurrence.as_ref(), req.provenance.as_ref());
            let mut tx = pool.begin().await?;
            insert_capture_attempt(
                &mut tx,
                tenant_id,
                &host,
                agent,
                observed,
                &reason,
                OUTCOME_HASH_MISMATCH,
                Some(&announced_raw),
                path,
                Some("SHA256_MISMATCH"),
                serde_json::json!({"announced": req.sha256, "recomputed": recomputed}),
            )
            .await?;
            sqlx::query("UPDATE upload_session SET state = 'failed' WHERE id = $1")
                .bind(req.upload_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            cas.discard_staging(&staging_key);
            return Err(err);
        }
        Err(other) => return Err(other),
    };

    let sha_hex = hex::encode(&sha_raw);
    let artifact_class = classify::classify(&bytes);
    let scope = req.scope.as_deref().unwrap_or("endpoint");
    if !matches!(scope, "endpoint" | "intel") {
        cas.discard_staging(&staging_key);
        return Err(Error::BadRequest(format!("invalid artifact scope {scope:?}")));
    }
    let provenance = req.provenance.clone().unwrap_or_else(|| serde_json::json!({}));
    let object_key = FsCas::object_key(tenant_id, &sha_hex);
    cas.commit(&staging_key, &object_key)?;

    let mut tx = pool.begin().await?;
    let artifact_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO artifact
         (id, tenant_id, sha256, size_bytes, artifact_class, storage_state, object_key, first_committed_at, scope, provenance)
         VALUES ($1,$2,$3,$4,$5,'committed',$6,$7,$8,$9)
         ON CONFLICT (tenant_id, sha256) DO NOTHING
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(&sha_raw)
    .bind(req.size_bytes)
    .bind(artifact_class.as_str())
    .bind(&object_key)
    .bind(Utc::now())
    .bind(scope)
    .bind(&provenance)
    .fetch_optional(&mut *tx)
    .await?;
    // Lost an insert race: adopt the existing row.
    let artifact_id = match artifact_id {
        Some(id) => id,
        None => sqlx::query_scalar("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant_id)
            .bind(&sha_raw)
            .fetch_one(&mut *tx)
            .await?,
    };

    if let Some(occ) = &req.occurrence {
        insert_occurrence(
            &mut tx,
            OccurrenceInsert {
                tenant_id,
                artifact_id: Some(artifact_id),
                artifact_sha256: Some(&sha_raw),
                occ,
            },
        )
        .await?;
    }
    let (host, agent, observed, reason, path) = attempt_meta(req.occurrence.as_ref(), req.provenance.as_ref());
    insert_capture_attempt(
        &mut tx,
        tenant_id,
        &host,
        agent,
        observed,
        &reason,
        OUTCOME_CAPTURED,
        Some(&sha_raw),
        path,
        None,
        serde_json::json!({"artifact_class": artifact_class.as_str()}),
    )
    .await?;
    sqlx::query("UPDATE upload_session SET state = 'committed' WHERE id = $1")
        .bind(req.upload_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Forward coverage (spec 15.9): active bundles scan newly committed bytes.
    let forward_matches =
        crate::hunts::forward_scan(pool, tenant_id, artifact_id, &sha_raw, &bytes).await?;

    // Similarity analysis (spec 16): extract features, generate edges,
    // maintain variant groups. Never blocks the commit.
    if let Err(e) = crate::similarity::edges::analyze_new_artifact(
        pool,
        tenant_id,
        artifact_id,
        artifact_class.as_str(),
        &bytes,
    )
    .await
    {
        tracing::warn!(error = %e, artifact = %artifact_id, "similarity analysis failed");
    }

    Ok(FinalizeResponse {
        artifact_id,
        sha256: sha_hex,
        storage_state: "committed".to_string(),
        forward_matches,
    })
}

async fn mark_session_failed(pool: &PgPool, upload_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE upload_session SET state = 'failed' WHERE id = $1")
        .bind(upload_id)
        .execute(pool)
        .await?;
    Ok(())
}
