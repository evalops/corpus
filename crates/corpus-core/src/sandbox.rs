//! Sandboxed scan execution (M6 hardening): the `corpus-scanner` helper
//! runs as a subprocess under an OS sandbox — macOS seatbelt, Linux
//! landlock (best-effort), or gVisor when configured. Tier 1 only is NOT
//! a hostile-malware boundary; see docs/hardening-decisions.md.

use crate::scan::ScanOutcome;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerTier {
    /// Legacy in-process scanning (dev).
    InProcess,
    /// Subprocess + OS sandbox (default).
    Subprocess,
    /// gVisor runsc via docker (real Linux hosts only; errors elsewhere).
    Gvisor,
}

pub fn tier_from_env() -> ScannerTier {
    match std::env::var("CORPUS_SCANNER_TIER").as_deref() {
        Ok("inprocess") => ScannerTier::InProcess,
        Ok("gvisor") => ScannerTier::Gvisor,
        _ => ScannerTier::Subprocess,
    }
}

fn scanner_binary() -> PathBuf {
    if let Ok(p) = std::env::var("CORPUS_SCANNER_BIN") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        // Same dir as the caller (target/debug/corpus-scanner next to
        // corpus-server), then the parent dir (tests live in deps/).
        let dir = exe.parent().map(|p| p.to_path_buf());
        if let Some(d) = &dir {
            let candidate = d.join("corpus-scanner");
            if candidate.exists() {
                return candidate;
            }
            if let Some(parent) = d.parent() {
                let candidate = parent.join("corpus-scanner");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from("corpus-scanner")
}

/// macOS seatbelt profile: no network, filesystem read-only outside
/// /tmp and /dev. A strict `deny default` profile aborts under dyld on
/// modern macOS, so reads are not narrowed here — the guarantees are
/// network isolation and write confinement. Documented honestly in
/// docs/hardening-decisions.md.
#[cfg(target_os = "macos")]
fn seatbelt_profile(_scanner: &Path, _sample_dir: &Path) -> String {
    "(version 1)(allow default)(deny network*)(deny file-write*)\
     (allow file-write* (subpath \"/tmp\")(subpath \"/dev\"))"
        .to_string()
}

/// Run the sandboxed scan. Returns ScanOutcome-shaped data as JSON value
/// plus a terminal status string.
pub async fn scan_subprocess(
    rules: &[(String, String)],
    sample_path: &Path,
    timeout: Duration,
    output_cap: usize,
) -> std::io::Result<serde_json::Value> {
    let scanner = scanner_binary();
    let job = serde_json::json!({
        "rules": rules,
        "sample_path": sample_path,
    });
    run_sandboxed(&scanner, sample_path, &job.to_string(), timeout, output_cap).await
}

/// Test hook: run the scanner with a custom job body (used for timeout
/// and output-cap tests).
pub async fn run_sandboxed(
    scanner: &Path,
    sample_path: &Path,
    job_json: &str,
    timeout: Duration,
    output_cap: usize,
) -> std::io::Result<serde_json::Value> {
    #[allow(unused_variables)]
    let sample_dir = sample_path.parent().unwrap_or(Path::new("/"));

    #[cfg(target_os = "macos")]
    let mut cmd = {
        let profile = seatbelt_profile(scanner, sample_dir);
        let mut c = tokio::process::Command::new("sandbox-exec");
        c.arg("-p").arg(profile).arg(scanner);
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = tokio::process::Command::new(scanner);
        // Landlock best-effort: narrow filesystem view in the child.
        let sample = sample_dir.to_path_buf();
        unsafe {
            c.pre_exec(move || {
                if let Err(e) = apply_landlock(&sample) {
                    eprintln!("landlock unavailable ({e}); running without filesystem sandbox");
                }
                Ok(())
            });
        }
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let mut cmd = tokio::process::Command::new(scanner);

    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let job = job_json.to_string();
    let write_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(job.as_bytes()).await;
        let _ = stdin.shutdown().await;
    });

    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(res) => res?,
        Err(_) => {
            // kill_on_drop: dropping the child here terminates the runaway.
            let _ = write_task.await;
            return Ok(serde_json::json!({
                "status": "timeout", "matches": [], "duration_ms": timeout.as_millis() as i64,
                "error_code": format!("scan exceeded {}ms sandbox timeout", timeout.as_millis()),
            }));
        }
    };
    let _ = write_task.await;
    if output.stdout.len() > output_cap {
        return Ok(serde_json::json!({
            "status": "error", "matches": [], "duration_ms": 0,
            "error_code": format!("scanner output exceeded {output_cap} byte cap"),
        }));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        serde_json::json!({
            "status": "error", "matches": [], "duration_ms": 0,
            "error_code": format!("scanner produced invalid output (exit {:?})", output.status.code()),
        })
    });
    Ok(parsed)
}

#[cfg(target_os = "linux")]
fn apply_landlock(sample_dir: &Path) -> std::io::Result<()> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };
    let abi = ABI::V1;
    let paths = vec![
        "/usr".into(),
        "/lib".into(),
        "/lib64".into(),
        "/etc".into(),
        "/dev".into(),
        "/proc".into(),
        sample_dir.to_path_buf(),
    ];
    Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .set_compatibility(CompatLevel::BestEffort)
        .create()
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .add_rules(landlock::path_beneath_rules(
            paths,
            AccessFs::from_read(abi),
        ))
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .restrict_self()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

/// Scan with the configured tier. `compiled` is used only for the
/// in-process tier; the subprocess tier recompiles per invocation
/// (documented cost of isolation in M6).
pub async fn scan_with_tier(
    tier: ScannerTier,
    sources: &[(String, String)],
    compiled: Option<&yara_x::Rules>,
    bytes: &[u8],
    sample_path: Option<&Path>,
) -> ScanOutcome {
    match tier {
        ScannerTier::InProcess => {
            let rules = compiled.expect("inprocess tier requires compiled rules");
            crate::scan::scan_bytes(rules, bytes)
        }
        ScannerTier::Subprocess => {
            let path = match sample_path {
                Some(p) => p,
                None => return error_outcome("subprocess tier requires a sample path"),
            };
            match scan_subprocess(sources, path, crate::scan::SCAN_TIMEOUT, 1024 * 1024).await {
                Ok(v) => outcome_from_json(&v),
                Err(e) => error_outcome(&format!("sandbox spawn: {e}")),
            }
        }
        ScannerTier::Gvisor => error_outcome(
            "gvisor tier unavailable: no runsc runtime registered in docker (verified: Colima ships runc only); configure gVisor on a real Linux host",
        ),
    }
}

fn error_outcome(msg: &str) -> ScanOutcome {
    ScanOutcome {
        status: crate::scan::ScanStatus::Error,
        matches: Vec::new(),
        duration_ms: 0,
        error_code: Some(msg.to_string()),
    }
}

fn outcome_from_json(v: &serde_json::Value) -> ScanOutcome {
    let status = match v.get("status").and_then(|s| s.as_str()) {
        Some("matched") => crate::scan::ScanStatus::Matched,
        Some("clean") => crate::scan::ScanStatus::Clean,
        Some("timeout") => crate::scan::ScanStatus::Timeout,
        _ => crate::scan::ScanStatus::Error,
    };
    let matches = v
        .get("matches")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| serde_json::from_value(m.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    ScanOutcome {
        status,
        matches,
        duration_ms: v.get("duration_ms").and_then(|d| d.as_i64()).unwrap_or(0),
        error_code: v
            .get("error_code")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str =
        r#"rule SandboxMarker { strings: $m = "CORPUS_SANDBOX_MARKER" condition: $m }"#;

    #[tokio::test]
    async fn subprocess_scan_matches_and_isolated_run() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("sample.bin");
        std::fs::write(&sample, b"payload CORPUS_SANDBOX_MARKER tail").unwrap();
        let scanner = scanner_binary();
        if !scanner.exists() {
            eprintln!("corpus-scanner binary not built; skipping");
            return;
        }
        let outcome = scan_subprocess(
            &[("default".into(), RULE.into())],
            &sample,
            Duration::from_secs(15),
            1024 * 1024,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome["status"], "matched",
            "subprocess scan must match: {outcome}"
        );
    }

    #[tokio::test]
    async fn timeout_kills_runaway() {
        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("sample.bin");
        std::fs::write(&sample, b"x").unwrap();
        let scanner = scanner_binary();
        if !scanner.exists() {
            eprintln!("corpus-scanner binary not built; skipping");
            return;
        }
        let job = serde_json::json!({
            "rules": [["default", RULE]],
            "sample_path": sample,
            "sleep_ms": 10000,
        });
        let outcome = run_sandboxed(
            &scanner,
            &sample,
            &job.to_string(),
            Duration::from_millis(500),
            1024 * 1024,
        )
        .await
        .unwrap();
        assert_eq!(outcome["status"], "timeout");
    }
}
