//! Merlin telemetry bridge.
//!
//! Ingests Merlin observation/segment payloads and stores them as
//! tenant-scoped rows for correlation with corpus artifacts (e.g. by
//! path, hash, or host). This is an integration surface — not a
//! replacement for the endpoint agent.
//!
//! # Safety
//!
//! Payloads are treated as untrusted input: size-bounded, validated, and
//! never executed. Cross-linking to artifacts is best-effort by digest.

use crate::dto::{MerlinObservationView, MerlinSegmentRequest, MerlinSegmentResponse};
use crate::error::{Error, Result};
use sqlx::PgPool;
use uuid::Uuid;

const MERLIN_SCHEMA_VERSION: i32 = 1;
const MAX_EVENTS_PER_REQUEST: usize = 50_000;
const MAX_EVENT_BYTES: usize = 256 << 10;
const MAX_HOST_BYTES: usize = 128;
const MAX_SEGMENT_BYTES: usize = 255;
const MAX_EVENT_ID_BYTES: usize = 256;

#[derive(Debug, sqlx::FromRow)]
struct MerlinObservationRow {
    id: Uuid,
    host_name: String,
    segment: String,
    event_id: String,
    boot_id: String,
    source_seq: Option<i64>,
    kind: String,
    process_key: Option<String>,
    artifact_sha256: Option<String>,
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
    received_at: chrono::DateTime<chrono::Utc>,
    payload: serde_json::Value,
}

impl MerlinObservationRow {
    fn into_view(self) -> MerlinObservationView {
        MerlinObservationView {
            id: self.id,
            host_name: self.host_name,
            segment: self.segment,
            event_id: self.event_id,
            boot_id: self.boot_id,
            source_seq: self.source_seq,
            kind: self.kind,
            process_key: self.process_key,
            artifact_sha256: self.artifact_sha256,
            observed_at: self.observed_at,
            received_at: self.received_at,
            payload: self.payload,
        }
    }
}

/// Store one segment or one replay-safe batch from a segment.
pub async fn ingest_segment(
    pool: &PgPool,
    tenant_id: Uuid,
    req: &MerlinSegmentRequest,
) -> Result<MerlinSegmentResponse> {
    validate_request(req)?;
    let segment_sha256 = req.segment_sha256.to_ascii_lowercase();
    let mut tx = pool.begin().await?;
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, segment_sha256
         FROM merlin_segment
         WHERE tenant_id = $1 AND host_name = $2 AND segment = $3
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&req.host_name)
    .bind(&req.segment)
    .fetch_optional(&mut *tx)
    .await?;

    let segment_id = match existing {
        Some((id, digest)) => {
            if digest != segment_sha256 {
                return Err(Error::Conflict(format!(
                    "Merlin segment {}/{} was already stored with a different digest",
                    req.host_name, req.segment
                )));
            }
            id
        }
        None => {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO merlin_segment
             (id, tenant_id, host_name, segment, segment_sha256, schema_version,
              received_at, event_count)
             VALUES ($1,$2,$3,$4,$5,$6,NOW(),0)
             RETURNING id",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(&req.host_name)
            .bind(&req.segment)
            .bind(&segment_sha256)
            .bind(req.schema_version)
            .fetch_one(&mut *tx)
            .await?
        }
    };

    let mut accepted_events = 0usize;
    for (index, event) in req.events.iter().enumerate() {
        let identity = event_identity(index, event)?;
        let result = sqlx::query(
            "INSERT INTO merlin_observation
             (id, tenant_id, segment_id, host_name, segment, event_id, boot_id,
              source_seq, kind, process_key, artifact_sha256, observed_at,
              received_at, payload)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),$13)
             ON CONFLICT (tenant_id, host_name, event_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(segment_id)
        .bind(&req.host_name)
        .bind(&req.segment)
        .bind(&identity.event_id)
        .bind(&identity.boot_id)
        .bind(identity.source_seq)
        .bind(&identity.kind)
        .bind(&identity.process_key)
        .bind(&identity.artifact_sha256)
        .bind(identity.observed_at)
        .bind(event)
        .execute(&mut *tx)
        .await?;
        accepted_events += result.rows_affected() as usize;
    }

    sqlx::query(
        "UPDATE merlin_segment
         SET event_count = (SELECT COUNT(*) FROM merlin_observation WHERE segment_id = $1)
         WHERE id = $1",
    )
    .bind(segment_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(MerlinSegmentResponse {
        schema_version: MERLIN_SCHEMA_VERSION,
        receipt_version: 1,
        segment_id,
        segment_sha256,
        status: if accepted_events == 0 {
            "duplicate"
        } else {
            "accepted"
        }
        .into(),
        accepted_events,
        duplicate_events: req.events.len() - accepted_events,
    })
}

pub async fn list_observations(
    pool: &PgPool,
    tenant_id: Uuid,
    host_name: Option<&str>,
    limit: i64,
) -> Result<Vec<MerlinObservationView>> {
    let limit = limit.clamp(1, 1_000);
    let rows = sqlx::query_as::<_, MerlinObservationRow>(
        "SELECT id, host_name, segment, event_id, boot_id, source_seq, kind,
                process_key, artifact_sha256, observed_at, received_at, payload
         FROM merlin_observation
         WHERE tenant_id = $1
           AND ($2::text IS NULL OR host_name = $2)
         ORDER BY observed_at DESC NULLS LAST, received_at DESC
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(host_name)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(MerlinObservationRow::into_view)
        .collect())
}

#[derive(Debug)]
struct EventIdentity {
    event_id: String,
    boot_id: String,
    source_seq: Option<i64>,
    kind: String,
    process_key: Option<String>,
    artifact_sha256: Option<String>,
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn validate_request(req: &MerlinSegmentRequest) -> Result<()> {
    if req.schema_version != MERLIN_SCHEMA_VERSION {
        return Err(Error::BadRequest(format!(
            "unsupported Merlin schema_version {}; expected {}",
            req.schema_version, MERLIN_SCHEMA_VERSION
        )));
    }
    if !valid_host(&req.host_name) {
        return Err(Error::BadRequest("invalid Merlin host_name".into()));
    }
    if !valid_segment(&req.segment) {
        return Err(Error::BadRequest("invalid Merlin segment".into()));
    }
    if !valid_sha256(&req.segment_sha256) {
        return Err(Error::BadRequest("invalid Merlin segment_sha256".into()));
    }
    if req.events.len() > MAX_EVENTS_PER_REQUEST {
        return Err(Error::BadRequest(format!(
            "Merlin event batch exceeds {} events",
            MAX_EVENTS_PER_REQUEST
        )));
    }
    for (index, event) in req.events.iter().enumerate() {
        if !event.is_object() {
            return Err(Error::BadRequest(format!(
                "Merlin event {index} is not a JSON object"
            )));
        }
        if event.to_string().len() > MAX_EVENT_BYTES {
            return Err(Error::BadRequest(format!(
                "Merlin event {index} exceeds {} bytes",
                MAX_EVENT_BYTES
            )));
        }
    }
    Ok(())
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HOST_BYTES
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT_BYTES
        && value.ends_with(".jsonl.gz")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn string_field(event: &serde_json::Value, key: &str, max: usize) -> Option<String> {
    let value = event.get(key)?.as_str()?.trim();
    if value.is_empty() || value.len() > max || value.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    Some(value.to_string())
}

fn event_identity(index: usize, event: &serde_json::Value) -> Result<EventIdentity> {
    let boot_id = string_field(event, "boot_id", 128).unwrap_or_else(|| "unknown".into());
    let source_seq = event.get("source_seq").and_then(serde_json::Value::as_i64);
    let event_id = string_field(event, "event_id", MAX_EVENT_ID_BYTES)
        .or_else(|| {
            (boot_id != "unknown")
                .then(|| source_seq.map(|seq| format!("{boot_id}:{seq}")))
                .flatten()
        })
        .ok_or_else(|| {
            Error::BadRequest(format!(
                "Merlin event {index} is missing event_id or boot_id/source_seq"
            ))
        })?;
    let kind = string_field(event, "kind", 64).unwrap_or_else(|| "unknown".into());
    let process_key = string_field(event, "process_key", 256);
    let artifact_sha256 = ["exe_sha256", "script_sha256", "file_sha256", "sha256"]
        .iter()
        .find_map(|key| {
            let value = string_field(event, key, 64)?;
            valid_sha256(&value).then(|| value.to_ascii_lowercase())
        });
    let observed_at = event
        .get("ts")
        .and_then(serde_json::Value::as_f64)
        .filter(|ts| ts.is_finite())
        .and_then(|ts| {
            let seconds = ts.trunc() as i64;
            let nanos = ((ts - seconds as f64) * 1_000_000_000.0).round();
            (0.0..1_000_000_000.0)
                .contains(&nanos)
                .then(|| chrono::DateTime::from_timestamp(seconds, nanos as u32))
                .flatten()
        });

    Ok(EventIdentity {
        event_id,
        boot_id,
        source_seq,
        kind,
        process_key,
        artifact_sha256,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_identity_preserves_merlin_ordering_and_hashes() {
        let event = serde_json::json!({
            "boot_id": "boot-a",
            "source_seq": 42,
            "kind": "exec",
            "process_key": "boot-a:123:99",
            "script_sha256": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            "ts": 1_700_000_000.25,
        });
        let identity = event_identity(0, &event).unwrap();
        assert_eq!(identity.event_id, "boot-a:42");
        assert_eq!(identity.source_seq, Some(42));
        assert_eq!(identity.kind, "exec");
        assert_eq!(
            identity.artifact_sha256.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert!(identity.observed_at.is_some());
    }

    #[test]
    fn invalid_segment_digest_and_non_object_events_are_rejected() {
        let base = MerlinSegmentRequest {
            schema_version: MERLIN_SCHEMA_VERSION,
            host_name: "host-1".into(),
            segment: "merlin-events.jsonl.gz".into(),
            segment_sha256: "not-a-digest".into(),
            events: vec![serde_json::json!({"kind": "exec"})],
        };
        assert!(validate_request(&base).is_err());

        let mut object = base;
        object.segment_sha256 = "a".repeat(64);
        object.events = vec![serde_json::json!("not an event")];
        assert!(validate_request(&object).is_err());
    }
}

#[test]
fn merlin_receipt_serializes_delivery_contract() {
    let receipt = MerlinSegmentResponse {
        schema_version: MERLIN_SCHEMA_VERSION,
        receipt_version: 1,
        segment_id: Uuid::nil(),
        segment_sha256: "a".repeat(64),
        status: "accepted".into(),
        accepted_events: 2,
        duplicate_events: 1,
    };
    let value = serde_json::to_value(receipt).unwrap();
    assert_eq!(value["receipt_version"], 1);
    assert_eq!(value["segment_sha256"], "a".repeat(64));
    assert_eq!(value["status"], "accepted");
}
