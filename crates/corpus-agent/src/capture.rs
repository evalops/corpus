//! Capture state machine driver (spec 10.4): OBSERVED -> DEBOUNCING ->
//! OPENING -> COPYING_AND_HASHING -> HASHED -> ANNOUNCED -> DEDUP_HIT |
//! UPLOAD_REQUIRED -> UPLOADING -> FINALIZING -> OCCURRENCE_QUEUED ->
//! COMPLETE, or GAP_RECORDED with a spec 2.2 terminal outcome.

use crate::config::Config;
use crate::stable_read::{self, StableReadError};
use crate::state::{states, Candidate, StateDb};
use crate::uploader::Uploader;
use anyhow::Result;
use corpus_core::dto::{AnnounceDisposition, AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

pub const OUTCOME_CHANGED_DURING_READ: &str = "CHANGED_DURING_READ";
pub const OUTCOME_DELETED_BEFORE_READ: &str = "DELETED_BEFORE_READ";
pub const OUTCOME_PERMISSION_DENIED: &str = "PERMISSION_DENIED";
pub const OUTCOME_TOO_LARGE: &str = "TOO_LARGE";
pub const OUTCOME_UPLOAD_FAILED: &str = "UPLOAD_FAILED";

pub struct AgentRuntime {
    pub cfg: Arc<Config>,
    pub db: Arc<StateDb>,
    pub uploader: Uploader,
    pub agent_id: Uuid,
    pub boot_id: Uuid,
    pub host_name: String,
}

fn backoff_secs(attempts: i64) -> i64 {
    (5i64 * 2i64.pow(attempts.min(6) as u32)).min(300)
}

fn spool_used_bytes(spool_dir: &Path) -> u64 {
    walkdir::WalkDir::new(spool_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

fn record_gap(db: &StateDb, reason: &str, outcome: &str, sha: Option<&str>, path: Option<&str>, code: Option<&str>, detail: &str) {
    if let Err(e) = db.record_gap(reason, outcome, sha, path, code, detail) {
        tracing::error!(error = %e, "failed to record gap locally");
    }
}

/// Process one candidate through the state machine. Idempotent across
/// crashes: each step resumes from the persisted state.
pub async fn process_candidate(rt: &AgentRuntime, cand: &Candidate) -> Result<()> {
    let db = &rt.db;
    let path = PathBuf::from(&cand.path);
    let max_attempts = rt.cfg.limits.max_attempts as i64;

    let mut state = cand.state.as_str();
    if state == states::DEBOUNCING || state == states::OBSERVED {
        db.transition(cand.id, states::OPENING)?;
        state = states::OPENING;
    }

    // OPENING + COPYING_AND_HASHING via the stable reader (spec 10.5).
    if state == states::OPENING || state == states::COPYING_AND_HASHING {
        let spool_free = rt.cfg.limits.max_spool_bytes.saturating_sub(spool_used_bytes(&rt.cfg.spool_dir));
        db.transition(cand.id, states::COPYING_AND_HASHING)?;
        let spool_dir = rt.cfg.spool_dir.clone();
        let read_path = path.clone();
        let max_bytes = rt.cfg.limits.max_artifact_bytes;
        let retries = rt.cfg.limits.stable_read_retries;
        let outcome = tokio::task::spawn_blocking(move || {
            stable_read::stable_read(&read_path, &spool_dir, max_bytes, spool_free, retries, None)
        })
        .await?;

        match outcome {
            Ok(r) => {
                db.set_hashed(cand.id, &r.sha256, r.size as i64, &r.spool_path.to_string_lossy())?;
            }
            Err(err) => {
                let outcome_name = match &err {
                    StableReadError::DeletedBeforeRead => OUTCOME_DELETED_BEFORE_READ,
                    StableReadError::PermissionDenied => OUTCOME_PERMISSION_DENIED,
                    StableReadError::TooLarge { .. } => OUTCOME_TOO_LARGE,
                    StableReadError::ChangedDuringRead => OUTCOME_CHANGED_DURING_READ,
                    StableReadError::SpoolFull => {
                        // Spool pressure is backpressure, not failure (10.8):
                        // defer WITHOUT burning attempts so sustained pressure
                        // never terminalizes a temporary condition.
                        db.defer(cand.id, chrono::Utc::now().timestamp() + 30)?;
                        return Ok(());
                    }
                    StableReadError::Io(_) => {
                        if cand.attempts >= max_attempts {
                            OUTCOME_UPLOAD_FAILED
                        } else {
                            db.set_retry(cand.id, chrono::Utc::now().timestamp() + backoff_secs(cand.attempts))?;
                            return Ok(());
                        }
                    }
                };
                let detail = match &err {
                    StableReadError::TooLarge { size } => format!("{{\"size_bytes\":{size}}}"),
                    other => format!("{{\"error\":{other:?}}}"),
                };
                record_gap(db, &cand.capture_reason, outcome_name, None, Some(&cand.path), None, &detail);
                db.finish_gap(cand.id, outcome_name)?;
                return Ok(());
            }
        }
    }

    // Reload: HASHED (or later) carries sha256 + spool path.
    let Some(cand) = db.get(cand.id)? else {
        // Row vanished underneath us; nothing to resume.
        return Ok(());
    };

    // Crash-resume for post-announce states: the server already has the
    // evidence (dedup-hit announce records occurrence + capture attempt);
    // just finish locally. These states must never strand a candidate.
    if matches!(cand.state.as_str(), states::DEDUP_HIT | states::OCCURRENCE_QUEUED) {
        db.transition(cand.id, states::COMPLETE)?;
        if let Some(p) = &cand.spool_path {
            let _ = std::fs::remove_file(p);
        }
        return Ok(());
    }

    let sha256 = match &cand.sha256 {
        Some(s) => s.clone(),
        None => anyhow::bail!("candidate {} in state {} without sha256", cand.id, cand.state),
    };
    let size = cand.size_bytes.unwrap_or(0);
    let spool_path = cand.spool_path.clone().map(PathBuf::from);

    let occ = |seq: i64| OccurrenceInfo {
        host_name: rt.host_name.clone(),
        agent_id: rt.agent_id,
        boot_id: rt.boot_id,
        agent_sequence: seq,
        path: cand.path.clone(),
        observed_at: chrono::Utc::now(),
        file_size: size,
        file_mtime: std::fs::metadata(&path).and_then(|m| m.modified()).ok().map(chrono::DateTime::from),
        capture_reason: cand.capture_reason.clone(),
    };

    // HASHED (or a post-crash resume of any upload-phase state) -> ANNOUNCED.
    // Re-announcing is safe: dedup hits are idempotent server-side and a
    // fresh upload session is allocated when bytes are still required.
    if matches!(
        cand.state.as_str(),
        states::HASHED | states::ANNOUNCED | states::UPLOAD_REQUIRED | states::UPLOADING | states::FINALIZING
    ) {
        let seq = db.next_sequence()?;
        let ann = rt
            .uploader
            .announce(&AnnounceRequest { sha256: sha256.clone(), size_bytes: size, occurrence: Some(occ(seq)) })
            .await;
        let ann = match ann {
            Ok(a) => a,
            Err(e) => return retry_or_fail(db, &cand, max_attempts, format!("announce: {e}")),
        };
        db.transition(cand.id, states::ANNOUNCED)?;
        match ann.disposition {
            AnnounceDisposition::AlreadyPresent => {
                // Server already recorded occurrence + capture attempt (11.1).
                db.transition(cand.id, states::DEDUP_HIT)?;
                db.transition(cand.id, states::OCCURRENCE_QUEUED)?;
                db.transition(cand.id, states::COMPLETE)?;
                db.increment_counter("ALREADY_PRESENT")?;
                if let Some(p) = &spool_path {
                    let _ = std::fs::remove_file(p);
                }
                return Ok(());
            }
            AnnounceDisposition::UploadRequired => {
                db.transition(cand.id, states::UPLOAD_REQUIRED)?;
                let Some(upload_id) = ann.upload_id else {
                    return retry_or_fail(db, &cand, max_attempts, "UPLOAD_REQUIRED without upload_id".into());
                };
                db.set_identity(&format!("upload_id:{}", cand.id), &upload_id.to_string())?;

                // UPLOADING.
                db.transition(cand.id, states::UPLOADING)?;
                let Some(spool) = spool_path.as_ref() else {
                    return retry_or_fail(db, &cand, max_attempts, "missing spool path at UPLOADING".into());
                };
                let bytes = std::fs::read(spool)?;
                if let Err(e) = rt.uploader.upload(upload_id, bytes).await {
                    return retry_or_fail(db, &cand, max_attempts, format!("upload: {e}"));
                }

                // FINALIZING.
                db.transition(cand.id, states::FINALIZING)?;
                let seq = db.next_sequence()?;
                let fin = rt
                    .uploader
                    .finalize(&FinalizeRequest {
                        upload_id,
                        sha256: sha256.clone(),
                        size_bytes: size,
                        occurrence: Some(occ(seq)),
                        scope: None,
                        provenance: None,
                    })
                    .await;
                match fin {
                    Ok(_) => {
                        db.transition(cand.id, states::OCCURRENCE_QUEUED)?;
                        db.transition(cand.id, states::COMPLETE)?;
                        db.increment_counter("CAPTURED")?;
                        db.set_identity("last_upload_at", &chrono::Utc::now().to_rfc3339())?;
                        if let Some(p) = &spool_path {
                            let _ = std::fs::remove_file(p);
                        }
                        return Ok(());
                    }
                    Err(e) => return retry_or_fail(&rt.db, &cand, max_attempts, format!("finalize: {e}")),
                }
            }
            other => {
                let name = format!("{other:?}");
                record_gap(db, &cand.capture_reason, &name, Some(&sha256), Some(&cand.path), None, "{}");
                db.finish_gap(cand.id, &name)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn retry_or_fail(db: &StateDb, cand: &Candidate, max_attempts: i64, why: String) -> Result<()> {
    tracing::warn!(path = %cand.path, error = %why, attempts = cand.attempts, "capture step failed");
    if cand.attempts >= max_attempts {
        let sha = cand.sha256.as_deref();
        record_gap(db, &cand.capture_reason, OUTCOME_UPLOAD_FAILED, sha, Some(&cand.path), None, &format!("{{\"error\":\"{why}\"}}"));
        db.finish_gap(cand.id, OUTCOME_UPLOAD_FAILED)?;
    } else {
        db.set_retry(cand.id, chrono::Utc::now().timestamp() + backoff_secs(cand.attempts))?;
    }
    Ok(())
}

/// Worker loop: lease due candidates by priority with bounded concurrency.
/// A per-candidate renewal task keeps the lease alive while processing so
/// a slow capture (large artifact, slow disk) is never leased twice.
pub async fn worker_loop(rt: Arc<AgentRuntime>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(rt.cfg.limits.max_concurrent_reads));
    loop {
        match rt.db.lease_next_due(120) {
            Ok(Some(cand)) => {
                let permit = sem.clone().acquire_owned().await.expect("semaphore closed");
                let rt = rt.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let id = cand.id;
                    let path = cand.path.clone();
                    // Lease renewal watchdog (review: lease could expire
                    // mid-processing → double stable-read/announce).
                    let renew_rt = rt.clone();
                    let renew = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            if renew_rt.db.renew_lease(id, 120).is_err() {
                                return;
                            }
                        }
                    });
                    let result = process_candidate(&rt, &cand).await;
                    renew.abort();
                    if let Err(e) = result {
                        tracing::error!(candidate = id, path = %path, error = %e, "candidate processing error");
                        let _ = rt.db.set_retry(id, chrono::Utc::now().timestamp() + 30);
                    }
                });
            }
            Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            Err(e) => {
                tracing::error!(error = %e, "state db error in worker loop");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::priority;

    fn test_runtime(dir: &tempfile::TempDir, max_spool_bytes: u64) -> (AgentRuntime, Arc<StateDb>) {
        let yaml = format!(
            "server_url: http://127.0.0.1:1\nstate_dir: {0}/state\nspool_dir: {0}/spool\nlimits:\n  max_spool_bytes: {1}\n",
            dir.path().display(),
            max_spool_bytes
        );
        let mut cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        std::fs::create_dir_all(&cfg.spool_dir).unwrap();
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        let db = Arc::new(StateDb::open(&cfg.state_dir.join("agent.db")).unwrap());
        cfg.watch.paths = vec![dir.path().to_path_buf()];
        let rt = AgentRuntime {
            uploader: Uploader::new("http://127.0.0.1:1", "bogus"),
            cfg: Arc::new(cfg),
            db: db.clone(),
            agent_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
            host_name: "test-host".into(),
        };
        (rt, db)
    }

    /// Drive a candidate to `state`, drop every handle (simulated crash),
    /// reopen the state DB, and resume processing with an unreachable
    /// server. Post-announce states must COMPLETE without any network call.
    async fn resume_after_crash(dir: &tempfile::TempDir, state: &str) {
        let (rt, db) = test_runtime(dir, 1 << 20);
        let id = db.enqueue("/w/resume.bin", priority::BASELINE, "baseline", 0).unwrap().unwrap();
        db.set_hashed(id, "abc123", 10, "/nonexistent-spool").unwrap();
        db.transition(id, state).unwrap();
        let cfg = rt.cfg.clone();
        drop(db);
        drop(rt); // crash: every handle to the state DB is gone
        let db2 = Arc::new(StateDb::open(&cfg.state_dir.join("agent.db")).unwrap());
        let rt2 = AgentRuntime {
            uploader: Uploader::new("http://127.0.0.1:1", "bogus"),
            cfg,
            db: db2.clone(),
            agent_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
            host_name: "test-host".into(),
        };
        let cand = db2.get(id).unwrap().unwrap();
        process_candidate(&rt2, &cand).await.unwrap();
        assert_eq!(db2.get(id).unwrap().unwrap().state, states::COMPLETE);
    }

    #[tokio::test]
    async fn crash_resume_from_dedup_hit_completes_without_network() {
        let dir = tempfile::tempdir().unwrap();
        resume_after_crash(&dir, states::DEDUP_HIT).await;
    }

    #[tokio::test]
    async fn crash_resume_from_occurrence_queued_completes_without_network() {
        let dir = tempfile::tempdir().unwrap();
        resume_after_crash(&dir, states::OCCURRENCE_QUEUED).await;
    }

    #[tokio::test]
    async fn spool_pressure_defers_without_burning_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("some.bin");
        std::fs::write(&target, b"some bytes here").unwrap();
        // Zero spool capacity: stable_read reports SpoolFull immediately.
        let (rt, db) = test_runtime(&dir, 0);
        let id = db
            .enqueue(&target.to_string_lossy(), priority::BASELINE, "baseline", 0)
            .unwrap()
            .unwrap();
        let cand = db.get(id).unwrap().unwrap();
        process_candidate(&rt, &cand).await.unwrap();
        let after = db.get(id).unwrap().unwrap();
        assert_eq!(after.attempts, 0, "spool backpressure must not burn attempts");
        assert_ne!(after.state, states::GAP_RECORDED);
        assert!(db.pending_gaps(10).unwrap().is_empty(), "no gap for a temporary condition");
    }
}
