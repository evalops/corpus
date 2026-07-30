//! Periodic health heartbeat (spec 10.11).

use crate::capture::AgentRuntime;
use corpus_core::dto::HeartbeatRequest;
use std::sync::Arc;

pub async fn run(rt: Arc<AgentRuntime>) {
    let interval = std::time::Duration::from_secs(rt.cfg.heartbeat_interval_secs.max(2));
    loop {
        if let Err(e) = send_once(&rt).await {
            tracing::warn!(error = %e, "heartbeat failed (server unreachable?)");
        }
        tokio::time::sleep(interval).await;
    }
}

async fn send_once(rt: &AgentRuntime) -> anyhow::Result<()> {
    let db = &rt.db;
    let baseline_state = db
        .get_identity("baseline_state")?
        .unwrap_or_else(|| "unknown".into());
    let baseline_percent = if baseline_state == "complete" { 100.0 } else { 0.0 };
    let counts: serde_json::Map<String, serde_json::Value> = db
        .drain_counters()?
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::from(v)))
        .collect();
    let last_upload_at = db
        .get_identity("last_upload_at")?
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    let sensor = db.get_identity("sensor")?.unwrap_or_else(|| "unknown".into());

    rt.uploader
        .heartbeat(&HeartbeatRequest {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_digest: rt.cfg.policy_digest(),
            baseline_state,
            baseline_percent,
            queue_depth: db.queue_depth()?,
            spool_bytes: spool_bytes(&rt.cfg.spool_dir),
            oldest_pending_secs: db.oldest_pending_secs()?,
            sensor,
            outcome_counts: serde_json::Value::Object(counts),
            last_upload_at,
            clock_offset_ms: None,
        })
        .await
}

fn spool_bytes(dir: &std::path::Path) -> i64 {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len() as i64)
        .sum()
}
