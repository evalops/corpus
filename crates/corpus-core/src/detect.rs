//! Autonomous detection events: first-class records when forward scans,
//! hash intel, or retro-hunts surface matches. Feeds investigation reports
//! and continuous re-analysis without requiring a prior external alert.

use crate::error::Result;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DetectionEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub artifact_id: Uuid,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub detail: serde_json::Value,
    pub mitre_techniques: Vec<String>,
    pub created_at: chrono::DateTime<Utc>,
}

/// Inputs for [`record`].
pub struct DetectionInput<'a> {
    pub source: &'a str,
    pub severity: &'a str,
    pub title: &'a str,
    pub detail: serde_json::Value,
    pub mitre_techniques: &'a [String],
}

/// Record a detection. Idempotent-tolerant: duplicates are allowed (audit
/// trail); callers de-dupe for product UX if needed.
pub async fn record(
    pool: &PgPool,
    tenant_id: Uuid,
    artifact_id: Uuid,
    input: DetectionInput<'_>,
) -> Result<Uuid> {
    let DetectionInput {
        source,
        severity,
        title,
        detail,
        mitre_techniques,
    } = input;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO detection_event
         (id, tenant_id, artifact_id, source, severity, title, detail, mitre_techniques, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(artifact_id)
    .bind(source)
    .bind(severity)
    .bind(title)
    .bind(detail)
    .bind(mitre_techniques)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn for_artifact(
    pool: &PgPool,
    tenant_id: Uuid,
    artifact_id: Uuid,
    limit: i64,
) -> Result<Vec<DetectionEvent>> {
    let rows = sqlx::query_as::<_, DetectionEvent>(
        "SELECT id, tenant_id, artifact_id, source, severity, title, detail,
                mitre_techniques, created_at
         FROM detection_event
         WHERE tenant_id = $1 AND artifact_id = $2
         ORDER BY created_at DESC
         LIMIT $3",
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn recent(pool: &PgPool, tenant_id: Uuid, limit: i64) -> Result<Vec<DetectionEvent>> {
    let rows = sqlx::query_as::<_, DetectionEvent>(
        "SELECT id, tenant_id, artifact_id, source, severity, title, detail,
                mitre_techniques, created_at
         FROM detection_event
         WHERE tenant_id = $1
         ORDER BY created_at DESC
         LIMIT $2",
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Map common YARA / CAPE labels into coarse MITRE technique IDs for
/// investigation reports. This is a bounded heuristic, not full ATT&CK
/// mapping.
pub fn heuristic_mitre(labels: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for l in labels {
        let lower = l.to_ascii_lowercase();
        if lower.contains("inject") || lower.contains("process_hollow") {
            push_unique(&mut out, "T1055");
        }
        if lower.contains("persist") || lower.contains("runkey") || lower.contains("scheduled") {
            push_unique(&mut out, "T1547");
        }
        if lower.contains("ransom") || lower.contains("encrypt") {
            push_unique(&mut out, "T1486");
        }
        if lower.contains("c2") || lower.contains("beacon") || lower.contains("backdoor") {
            push_unique(&mut out, "T1071");
        }
        if lower.contains("steal") || lower.contains("credential") || lower.contains("mimikatz") {
            push_unique(&mut out, "T1003");
        }
        if lower.contains("dropper") || lower.contains("downloader") {
            push_unique(&mut out, "T1105");
        }
        if lower.contains("pack") || lower.contains("obfus") {
            push_unique(&mut out, "T1027");
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, tech: &str) {
    if !out.iter().any(|t| t == tech) {
        out.push(tech.to_string());
    }
}
