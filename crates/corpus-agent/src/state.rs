//! Durable local state: SQLite in WAL mode (spec 10.3).
//!
//! Holds agent identity, the capture state machine rows, baseline
//! checkpoints, pending gap batches, seen-file snapshots, and health
//! counters. Transitions are transactional: a crash may repeat a
//! transition but cannot silently drop it (spec 10.4).

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Capture state machine states (spec 10.4), stored as text.
pub mod states {
    pub const OBSERVED: &str = "observed";
    pub const DEBOUNCING: &str = "debouncing";
    pub const OPENING: &str = "opening";
    pub const COPYING_AND_HASHING: &str = "copying_and_hashing";
    pub const HASHED: &str = "hashed";
    pub const ANNOUNCED: &str = "announced";
    pub const DEDUP_HIT: &str = "dedup_hit";
    pub const UPLOAD_REQUIRED: &str = "upload_required";
    pub const UPLOADING: &str = "uploading";
    pub const FINALIZING: &str = "finalizing";
    pub const OCCURRENCE_QUEUED: &str = "occurrence_queued";
    pub const COMPLETE: &str = "complete";
    pub const GAP_RECORDED: &str = "gap_recorded";
}

/// Priorities (spec 10.8), lower number = higher priority. Some variants
/// are only produced by the Linux fanotify sensor or tests.
#[allow(dead_code)]
pub mod priority {
    pub const EXEC_TARGET: i64 = 1;
    pub const WRITTEN_OR_RENAMED: i64 = 2;
    pub const VERIFICATION_TASK: i64 = 4;
    pub const BASELINE: i64 = 5;
    pub const RECONCILIATION: i64 = 6;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: i64,
    pub path: String,
    pub priority: i64,
    pub capture_reason: String,
    pub state: String,
    pub attempts: i64,
    pub next_retry_at: i64,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub spool_path: Option<String>,
    pub terminal_reason: Option<String>,
}

#[derive(Debug)]
pub struct PendingGap {
    pub id: i64,
    pub observed_at: String,
    pub capture_reason: String,
    pub terminal_outcome: String,
    pub artifact_sha256: Option<String>,
    pub path: Option<String>,
    pub detail_code: Option<String>,
    pub detail: String,
}

pub struct StateDb {
    conn: Mutex<Connection>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl StateDb {
    pub fn open(path: &Path) -> Result<StateDb> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identity (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS candidate (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               path TEXT NOT NULL,
               priority INTEGER NOT NULL,
               capture_reason TEXT NOT NULL,
               state TEXT NOT NULL,
               attempts INTEGER NOT NULL DEFAULT 0,
               next_retry_at INTEGER NOT NULL DEFAULT 0,
               size_bytes INTEGER,
               sha256 TEXT,
               spool_path TEXT,
               terminal_reason TEXT,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_candidate_active_path
               ON candidate(path) WHERE state NOT IN ('complete','gap_recorded');
             CREATE INDEX IF NOT EXISTS idx_candidate_due
               ON candidate(state, next_retry_at, priority);
             CREATE TABLE IF NOT EXISTS baseline_dir (
               path TEXT PRIMARY KEY,
               done INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS pending_gap (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               observed_at TEXT NOT NULL,
               capture_reason TEXT NOT NULL,
               terminal_outcome TEXT NOT NULL,
               artifact_sha256 TEXT,
               path TEXT,
               detail_code TEXT,
               detail TEXT NOT NULL DEFAULT '{}'
             );
             CREATE TABLE IF NOT EXISTS outcome_counter (
               outcome TEXT PRIMARY KEY,
               count INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS seen_file (
               path TEXT PRIMARY KEY,
               inode INTEGER NOT NULL,
               mtime_secs INTEGER NOT NULL,
               size INTEGER NOT NULL
             );",
        )?;
        Ok(StateDb { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("state db mutex poisoned")
    }

    // ---------- identity ----------

    pub fn get_identity(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM identity WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_identity(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO identity (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Persist several identity keys in ONE transaction: a crash between
    /// keys (e.g. agent_id written, agent_token not) is impossible.
    pub fn set_identity_many(&self, pairs: &[(&str, &str)]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for (key, value) in pairs {
            tx.execute(
                "INSERT INTO identity (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Monotonic per-agent occurrence sequence (spec 12.4).
    pub fn next_sequence(&self) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO identity (key, value) VALUES ('agent_sequence', '0')
             ON CONFLICT(key) DO NOTHING",
            [],
        )?;
        conn.execute(
            "UPDATE identity SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'agent_sequence'",
            [],
        )?;
        let v: String =
            conn.query_row("SELECT value FROM identity WHERE key = 'agent_sequence'", [], |r| r.get(0))?;
        Ok(v.parse()?)
    }

    // ---------- candidates / state machine ----------

    /// Enqueue a candidate; dedupes against active rows for the same path.
    /// Returns the row id, or None if an identical active candidate exists.
    pub fn enqueue(&self, path: &str, priority: i64, capture_reason: &str, debounce_ms: u64) -> Result<Option<i64>> {
        let t = now();
        let debounce_at = t + (debounce_ms as i64 / 1000);
        let initial = if debounce_ms > 0 { states::DEBOUNCING } else { states::OBSERVED };
        let conn = self.conn();
        conn.execute(
            "INSERT INTO candidate (path, priority, capture_reason, state, next_retry_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(path) WHERE state NOT IN ('complete','gap_recorded') DO NOTHING",
            params![path, priority, capture_reason, initial, debounce_at, t],
        )?;
        if conn.changes() == 0 {
            return Ok(None);
        }
        Ok(Some(conn.last_insert_rowid()))
    }

    /// Transactional state transition (spec 10.4).
    pub fn transition(&self, id: i64, new_state: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET state = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, new_state, now()],
        )?;
        Ok(())
    }

    pub fn set_retry(&self, id: i64, next_retry_at: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET attempts = attempts + 1, next_retry_at = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, next_retry_at, now()],
        )?;
        Ok(())
    }

    /// Defer a candidate WITHOUT burning an attempt. Used for backpressure
    /// conditions (spool pressure) that must not terminalize.
    pub fn defer(&self, id: i64, next_retry_at: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET next_retry_at = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, next_retry_at, now()],
        )?;
        Ok(())
    }

    /// Renew the lease on a candidate being processed so a slow capture is
    /// not leased twice concurrently. Safe on terminal rows (they are
    /// filtered out of due queries regardless).
    pub fn renew_lease(&self, id: i64, lease_secs: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET next_retry_at = ?2 WHERE id = ?1 AND state NOT IN ('complete','gap_recorded')",
            params![id, now() + lease_secs],
        )?;
        Ok(())
    }

    pub fn set_hashed(&self, id: i64, sha256: &str, size: i64, spool_path: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET state = ?2, sha256 = ?3, size_bytes = ?4, spool_path = ?5, updated_at = ?6 WHERE id = ?1",
            params![id, states::HASHED, sha256, size, spool_path, now()],
        )?;
        Ok(())
    }

    pub fn finish_gap(&self, id: i64, terminal_reason: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE candidate SET state = ?2, terminal_reason = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, states::GAP_RECORDED, terminal_reason, now()],
        )?;
        Ok(())
    }

    pub fn get(&self, id: i64) -> Result<Option<Candidate>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, path, priority, capture_reason, state, attempts, next_retry_at,
                        size_bytes, sha256, spool_path, terminal_reason
                 FROM candidate WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Candidate {
                        id: r.get(0)?,
                        path: r.get(1)?,
                        priority: r.get(2)?,
                        capture_reason: r.get(3)?,
                        state: r.get(4)?,
                        attempts: r.get(5)?,
                        next_retry_at: r.get(6)?,
                        size_bytes: r.get(7)?,
                        sha256: r.get(8)?,
                        spool_path: r.get(9)?,
                        terminal_reason: r.get(10)?,
                    })
                },
            )
            .optional()?)
    }

    /// Next due candidate by priority then age (spec 10.8 ordering).
    #[cfg(test)]
    pub fn next_due(&self) -> Result<Option<Candidate>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT id, path, priority, capture_reason, state, attempts, next_retry_at,
                        size_bytes, sha256, spool_path, terminal_reason
                 FROM candidate
                 WHERE state NOT IN ('complete','gap_recorded') AND next_retry_at <= ?1
                 ORDER BY priority ASC, id ASC
                 LIMIT 1",
                params![now()],
                |r| {
                    Ok(Candidate {
                        id: r.get(0)?,
                        path: r.get(1)?,
                        priority: r.get(2)?,
                        capture_reason: r.get(3)?,
                        state: r.get(4)?,
                        attempts: r.get(5)?,
                        next_retry_at: r.get(6)?,
                        size_bytes: r.get(7)?,
                        sha256: r.get(8)?,
                        spool_path: r.get(9)?,
                        terminal_reason: r.get(10)?,
                    })
                },
            )
            .optional()?)
    }

    /// Atomically pick the next due candidate and push its retry time into
    /// the future so no other worker picks it while it is being processed.
    pub fn lease_next_due(&self, lease_secs: i64) -> Result<Option<Candidate>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "UPDATE candidate SET next_retry_at = ?2, updated_at = ?3
                 WHERE id = (
                   SELECT id FROM candidate
                   WHERE state NOT IN ('complete','gap_recorded') AND next_retry_at <= ?3
                   ORDER BY priority ASC, id ASC LIMIT 1
                 )
                 RETURNING id, path, priority, capture_reason, state, attempts, next_retry_at,
                           size_bytes, sha256, spool_path, terminal_reason",
                params![now() + lease_secs, now() + lease_secs, now()],
                |r| {
                    Ok(Candidate {
                        id: r.get(0)?,
                        path: r.get(1)?,
                        priority: r.get(2)?,
                        capture_reason: r.get(3)?,
                        state: r.get(4)?,
                        attempts: r.get(5)?,
                        next_retry_at: r.get(6)?,
                        size_bytes: r.get(7)?,
                        sha256: r.get(8)?,
                        spool_path: r.get(9)?,
                        terminal_reason: r.get(10)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn queue_depth(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT count(*) FROM candidate WHERE state NOT IN ('complete','gap_recorded')",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn oldest_pending_secs(&self) -> Result<Option<i64>> {
        let oldest: Option<i64> = self.conn().query_row(
            "SELECT min(created_at) FROM candidate WHERE state NOT IN ('complete','gap_recorded')",
            [],
            |r| r.get(0),
        )?;
        Ok(oldest.map(|t| (now() - t).max(0)))
    }

    // ---------- baseline checkpoints ----------

    pub fn baseline_dir_done(&self, path: &str) -> Result<bool> {
        let done: Option<i64> = self
            .conn()
            .query_row("SELECT done FROM baseline_dir WHERE path = ?1", params![path], |r| r.get(0))
            .optional()?;
        Ok(done == Some(1))
    }

    pub fn mark_baseline_dir(&self, path: &str, done: bool) -> Result<()> {
        self.conn().execute(
            "INSERT INTO baseline_dir (path, done) VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET done = excluded.done",
            params![path, done as i64],
        )?;
        Ok(())
    }

    // ---------- gaps ----------

    #[allow(clippy::too_many_arguments)]
    pub fn record_gap(
        &self,
        capture_reason: &str,
        terminal_outcome: &str,
        artifact_sha256: Option<&str>,
        path: Option<&str>,
        detail_code: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO pending_gap (observed_at, capture_reason, terminal_outcome, artifact_sha256, path, detail_code, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chrono::Utc::now().to_rfc3339(),
                capture_reason,
                terminal_outcome,
                artifact_sha256,
                path,
                detail_code,
                detail
            ],
        )?;
        conn.execute(
            "INSERT INTO outcome_counter (outcome, count) VALUES (?1, 1)
             ON CONFLICT(outcome) DO UPDATE SET count = count + 1",
            params![terminal_outcome],
        )?;
        Ok(())
    }

    pub fn increment_counter(&self, outcome: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO outcome_counter (outcome, count) VALUES (?1, 1)
             ON CONFLICT(outcome) DO UPDATE SET count = count + 1",
            params![outcome],
        )?;
        Ok(())
    }

    /// Read per-outcome counters without clearing them ("counts since
    /// prior heartbeat", 10.11). Pair with `clear_counters` AFTER the
    /// heartbeat has been delivered.
    pub fn read_counters(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT outcome, count FROM outcome_counter ORDER BY outcome")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn clear_counters(&self) -> Result<()> {
        self.conn().execute("DELETE FROM outcome_counter", [])?;
        Ok(())
    }

    pub fn pending_gaps(&self, limit: i64) -> Result<Vec<PendingGap>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, observed_at, capture_reason, terminal_outcome, artifact_sha256, path, detail_code, detail
             FROM pending_gap ORDER BY id LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(PendingGap {
                    id: r.get(0)?,
                    observed_at: r.get(1)?,
                    capture_reason: r.get(2)?,
                    terminal_outcome: r.get(3)?,
                    artifact_sha256: r.get(4)?,
                    path: r.get(5)?,
                    detail_code: r.get(6)?,
                    detail: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn delete_gaps(&self, ids: &[i64]) -> Result<()> {
        let conn = self.conn();
        for id in ids {
            conn.execute("DELETE FROM pending_gap WHERE id = ?1", params![id])?;
        }
        Ok(())
    }

    // ---------- seen files (poll sensor snapshot) ----------

    /// Returns true if the file is new or changed since the last snapshot.
    pub fn seen_check_and_update(&self, path: &str, inode: i64, mtime_secs: i64, size: i64) -> Result<bool> {
        let conn = self.conn();
        let prev: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT inode, mtime_secs, size FROM seen_file WHERE path = ?1",
                params![path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let changed = prev != Some((inode, mtime_secs, size));
        if changed {
            conn.execute(
                "INSERT INTO seen_file (path, inode, mtime_secs, size) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, mtime_secs = excluded.mtime_secs, size = excluded.size",
                params![path, inode, mtime_secs, size],
            )?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp() -> (tempfile::TempDir, StateDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(&dir.path().join("state.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn state_machine_transitions_are_transactional_and_durable() {
        let (dir, db) = open_tmp();
        let id = db.enqueue("/w/a.bin", priority::WRITTEN_OR_RENAMED, "close_write", 0).unwrap().unwrap();
        assert_eq!(db.get(id).unwrap().unwrap().state, states::OBSERVED);
        db.transition(id, states::OPENING).unwrap();
        db.transition(id, states::COPYING_AND_HASHING).unwrap();
        db.set_hashed(id, "deadbeef", 42, "/spool/xyz").unwrap();
        let c = db.get(id).unwrap().unwrap();
        assert_eq!(c.state, states::HASHED);
        assert_eq!(c.sha256.as_deref(), Some("deadbeef"));
        drop(db);
        // "Crash": reopen the DB — state must survive (10.4).
        let db = StateDb::open(&dir.path().join("state.db")).unwrap();
        let c = db.get(id).unwrap().unwrap();
        assert_eq!(c.state, states::HASHED);
        assert_eq!(c.spool_path.as_deref(), Some("/spool/xyz"));
        db.transition(id, states::COMPLETE).unwrap();
        assert_eq!(db.queue_depth().unwrap(), 0);
    }

    #[test]
    fn enqueue_dedupes_active_paths() {
        let (_dir, db) = open_tmp();
        let first = db.enqueue("/w/dup.bin", 2, "poll", 0).unwrap();
        let second = db.enqueue("/w/dup.bin", 2, "poll", 0).unwrap();
        assert!(first.is_some());
        assert!(second.is_none(), "active duplicate must be deduped");
        db.transition(first.unwrap(), states::COMPLETE).unwrap();
        let third = db.enqueue("/w/dup.bin", 2, "poll", 0).unwrap();
        assert!(third.is_some(), "completed path may be re-enqueued");
    }

    #[test]
    fn priority_ordering_prefers_exec_over_baseline() {
        let (_dir, db) = open_tmp();
        db.enqueue("/w/base.bin", priority::BASELINE, "baseline", 0).unwrap();
        db.enqueue("/w/exec.bin", priority::EXEC_TARGET, "exec_open", 0).unwrap();
        let next = db.next_due().unwrap().unwrap();
        assert_eq!(next.path, "/w/exec.bin");
    }

    #[test]
    fn sequence_is_monotonic_across_reopen() {
        let (dir, db) = open_tmp();
        assert_eq!(db.next_sequence().unwrap(), 1);
        assert_eq!(db.next_sequence().unwrap(), 2);
        drop(db);
        let db = StateDb::open(&dir.path().join("state.db")).unwrap();
        assert_eq!(db.next_sequence().unwrap(), 3);
    }

    #[test]
    fn gaps_and_counters() {
        let (_dir, db) = open_tmp();
        db.record_gap("baseline", "TOO_LARGE", None, Some("/w/big"), None, "{}").unwrap();
        db.record_gap("baseline", "TOO_LARGE", None, Some("/w/big2"), None, "{}").unwrap();
        let gaps = db.pending_gaps(10).unwrap();
        assert_eq!(gaps.len(), 2);
        // read_counters must NOT clear (heartbeat may fail after reading).
        let counters = db.read_counters().unwrap();
        assert_eq!(counters, vec![("TOO_LARGE".to_string(), 2)]);
        let counters_again = db.read_counters().unwrap();
        assert_eq!(counters_again, counters, "read must not clear counters");
        db.clear_counters().unwrap();
        assert!(db.read_counters().unwrap().is_empty());
        db.delete_gaps(&[gaps[0].id]).unwrap();
        assert_eq!(db.pending_gaps(10).unwrap().len(), 1);
    }

    #[test]
    fn defer_does_not_burn_attempts() {
        let (_dir, db) = open_tmp();
        let id = db.enqueue("/w/x.bin", 5, "baseline", 0).unwrap().unwrap();
        db.defer(id, 99999).unwrap();
        db.defer(id, 99999).unwrap();
        let c = db.get(id).unwrap().unwrap();
        assert_eq!(c.attempts, 0, "backpressure deferral must not burn attempts");
        assert_eq!(c.next_retry_at, 99999);
        db.set_retry(id, 100000).unwrap();
        assert_eq!(db.get(id).unwrap().unwrap().attempts, 1);
    }
}
