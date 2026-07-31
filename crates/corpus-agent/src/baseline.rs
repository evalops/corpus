//! Checkpointed, resumable baseline inventory (spec 10.7).
//!
//! Each watch root is walked top-level entry by top-level entry. Completed
//! entries are checkpointed in SQLite; a restart skips them. Baseline
//! candidates are enqueued at the lowest capture priority so live events
//! always win the worker (spec 10.8).

use crate::state::{priority, StateDb};
use anyhow::Result;
use std::path::Path;

pub struct BaselineReport {
    pub dirs_completed: usize,
    pub dirs_total: usize,
    pub candidates_enqueued: usize,
}

/// Run (or resume) the baseline for `roots`. `stop_after_dirs` is a test
/// seam that simulates a crash partway through the walk.
pub fn run_baseline(
    db: &StateDb,
    roots: &[std::path::PathBuf],
    exclusions: &[String],
    debounce_ms: u64,
    stop_after_dirs: Option<usize>,
) -> Result<BaselineReport> {
    let mut dirs_total = 0usize;
    let mut dirs_completed = 0usize;
    let mut enqueued = 0usize;

    for root in roots {
        if !root.is_dir() {
            continue;
        }
        // Top-level entries are the checkpoint granularity.
        let mut entries: Vec<_> = std::fs::read_dir(root)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();

        for entry in entries {
            dirs_total += 1;
            let key = entry.to_string_lossy().to_string();
            if db.baseline_dir_done(&key)? {
                dirs_completed += 1;
                continue;
            }
            if let Some(limit) = stop_after_dirs {
                if dirs_completed >= limit {
                    return Ok(BaselineReport { dirs_completed, dirs_total, candidates_enqueued: enqueued });
                }
            }
            enqueued += enqueue_tree(db, &entry, exclusions, priority::BASELINE, "baseline", debounce_ms)?;
            db.mark_baseline_dir(&key, true)?;
            dirs_completed += 1;
        }
    }
    db.set_identity("baseline_state", if dirs_completed == dirs_total { "complete" } else { "incomplete" })?;
    Ok(BaselineReport { dirs_completed, dirs_total, candidates_enqueued: enqueued })
}

/// Walk one tree and enqueue regular files, returning the count enqueued.
fn enqueue_tree(
    db: &StateDb,
    path: &Path,
    exclusions: &[String],
    prio: i64,
    reason: &str,
    debounce_ms: u64,
) -> Result<usize> {
    let mut n = 0;
    for entry in walkdir::WalkDir::new(path).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let s = p.to_string_lossy();
        if crate::config::matches_exclusion(exclusions, &s) {
            continue;
        }
        if db.enqueue(&s, prio, reason, debounce_ms)?.is_some() {
            n += 1;
        }
    }
    Ok(n)
}

/// Periodic reconciliation: re-enqueue files whose stat changed since the
/// last snapshot (spec 10.10 Linux fallback / 10.7 step 6).
pub fn reconcile_scan(
    db: &StateDb,
    roots: &[std::path::PathBuf],
    exclusions: &[String],
    debounce_ms: u64,
) -> Result<usize> {
    let mut n = 0;
    for root in roots {
        for entry in walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let p = entry.path();
            let s = p.to_string_lossy();
            if crate::config::matches_exclusion(exclusions, &s) {
                continue;
            }
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let key = crate::fileid::scan_key(&md);
            if db.seen_check_and_update(&s, key.index as i64, (key.mtime_ns / 1_000_000_000) as i64, key.size as i64)?
                && db.enqueue(&s, priority::RECONCILIATION, "reconcile_scan", debounce_ms)?.is_some()
            {
                n += 1;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::states;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for d in ["a", "b", "c"] {
            let sub = dir.path().join(d);
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(format!("{d}1.bin")), d.repeat(16)).unwrap();
            std::fs::write(sub.join(format!("{d}2.bin")), d.repeat(32)).unwrap();
        }
        dir
    }

    #[test]
    fn baseline_resume_skips_completed_dirs() {
        let root = tree();
        let db_dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(&db_dir.path().join("s.db")).unwrap();

        // "Crash" after the first top-level dir.
        let r1 = run_baseline(&db, &[root.path().to_path_buf()], &[], 0, Some(1)).unwrap();
        assert_eq!(r1.dirs_completed, 1);
        assert_eq!(r1.dirs_total, 2, "walk stopped early; total counts only entries seen");
        // The completed dir's candidates were fully processed before the crash.
        while let Some(c) = db.lease_next_due(0).unwrap() {
            db.transition(c.id, states::COMPLETE).unwrap();
        }
        assert_eq!(db.queue_depth().unwrap(), 0);

        // Simulate restart: new StateDb on the same file. The checkpoint must
        // prevent re-enqueueing the completed dir — dedup alone would not,
        // because its candidates are already complete.
        drop(db);
        let db = StateDb::open(&db_dir.path().join("s.db")).unwrap();
        let r2 = run_baseline(&db, &[root.path().to_path_buf()], &[], 0, None).unwrap();
        assert_eq!(r2.dirs_completed, 3);
        assert_eq!(r2.candidates_enqueued, 4, "only dirs b and c may be enqueued");
        assert_eq!(db.queue_depth().unwrap(), 4);
        assert_eq!(
            db.get_identity("baseline_state").unwrap().as_deref(),
            Some("complete")
        );
    }

    #[test]
    fn reconcile_detects_new_and_changed_files_only() {
        let root = tree();
        let db_dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(&db_dir.path().join("s.db")).unwrap();
        let n1 = reconcile_scan(&db, &[root.path().to_path_buf()], &[], 0).unwrap();
        assert_eq!(n1, 6, "first scan sees every file");
        let n2 = reconcile_scan(&db, &[root.path().to_path_buf()], &[], 0).unwrap();
        assert_eq!(n2, 0, "unchanged files are not re-reported");
        // Drain the first scan's candidates so the changed file can be
        // re-enqueued (active candidates dedupe by path).
        while let Some(c) = db.lease_next_due(0).unwrap() {
            db.transition(c.id, states::COMPLETE).unwrap();
        }
        std::fs::write(root.path().join("a/a1.bin"), b"changed content").unwrap();
        std::fs::write(root.path().join("new.bin"), b"brand new").unwrap();
        let n3 = reconcile_scan(&db, &[root.path().to_path_buf()], &[], 0).unwrap();
        assert_eq!(n3, 2, "only the changed and the new file");
    }
}
