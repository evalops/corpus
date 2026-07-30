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
         ON CONFLICT (agent_id, boot_id, agent_sequence) DO NOTHING",
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
    occ: &OccurrenceInfo,
    outcome: &str,
    sha256: Option<&[u8]>,
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
    .bind(&occ.host_name)
    .bind(occ.agent_id)
    .bind(occ.observed_at)
    .bind(&occ.capture_reason)
    .bind(outcome)
    .bind(sha256)
    .bind(&occ.path)
    .bind(detail_code)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
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
        insert_occurrence(
            &mut tx,
            OccurrenceInsert {
                tenant_id,
                artifact_id: Some(artifact_id),
                artifact_sha256: Some(&sha_raw),
                occ: &req.occurrence,
            },
        )
        .await?;
        insert_capture_attempt(
            &mut tx,
            tenant_id,
            &req.occurrence,
            OUTCOME_ALREADY_PRESENT,
            Some(&sha_raw),
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
            let mut tx = pool.begin().await?;
            insert_capture_attempt(
                &mut tx,
                tenant_id,
                &req.occurrence,
                OUTCOME_HASH_MISMATCH,
                Some(&announced_raw),
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
    let object_key = FsCas::object_key(tenant_id, &sha_hex);
    cas.commit(&staging_key, &object_key)?;

    let mut tx = pool.begin().await?;
    let artifact_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO artifact
         (id, tenant_id, sha256, size_bytes, artifact_class, storage_state, object_key, first_committed_at)
         VALUES ($1,$2,$3,$4,$5,'committed',$6,$7)
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

    insert_occurrence(
        &mut tx,
        OccurrenceInsert {
            tenant_id,
            artifact_id: Some(artifact_id),
            artifact_sha256: Some(&sha_raw),
            occ: &req.occurrence,
        },
    )
    .await?;
    insert_capture_attempt(
        &mut tx,
        tenant_id,
        &req.occurrence,
        OUTCOME_CAPTURED,
        Some(&sha_raw),
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
