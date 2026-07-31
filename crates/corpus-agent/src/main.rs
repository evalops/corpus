//! corpus-agent: Linux user-mode collection agent (spec 10, M1).
//!
//! Observe-only: the agent never blocks execution and never runs
//! server-supplied commands. Local state is SQLite WAL; the spool is
//! plaintext with 0600/0700 permissions (encryption is M1-production
//! hardening — see README deviations).

mod baseline;
mod capture;
mod config;
mod heartbeat;
mod sensors;
mod stable_read;
mod state;
mod uploader;

use anyhow::{Context, Result};
use capture::AgentRuntime;
use clap::{Parser, Subcommand};
use config::Config;
use corpus_core::dto::EnrollRequest;
use state::StateDb;
use std::path::PathBuf;
use std::sync::Arc;
use uploader::Uploader;

#[derive(Parser)]
#[command(name = "corpus-agent", about = "Corpus endpoint agent (Linux, M1)")]
struct Cli {
    #[arg(long, default_value = "agent.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll (if needed) and run: baseline, sensors, capture, upload.
    Run,
    /// Print local state summary.
    Status,
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into())
}

/// OS boot identity (spec 12.4). Linux: kernel boot_id UUID. macOS:
/// kern.boottime via sysctl, folded into a v5 UUID. Changes on reboot.
fn os_boot_id() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
    }
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let mut tv: libc::timeval = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::timeval>();
            let name = c"kern.boottime".as_ptr();
            if libc::sysctlbyname(name, &mut tv as *mut _ as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) == 0 {
                return uuid::Uuid::new_v5(
                    &uuid::Uuid::NAMESPACE_OID,
                    format!("corpus-boot:{}:{}", tv.tv_sec, tv.tv_usec).as_bytes(),
                )
                .to_string();
            }
            uuid::Uuid::new_v4().to_string()
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        uuid::Uuid::new_v4().to_string()
    }
}

/// Refresh the persisted boot identity against the OS boot id. On boot
/// change, replace boot_id and reset the occurrence sequence (ordering is
/// per boot, spec 12.4). Returns true when the boot id changed.
fn refresh_boot_identity(db: &StateDb, current: &str) -> Result<bool> {
    let stored = db.get_identity("boot_id")?;
    if stored.as_deref() == Some(current) {
        return Ok(false);
    }
    db.set_identity_many(&[("boot_id", current), ("agent_sequence", "0")])?;
    Ok(stored.is_some())
}

async fn ensure_identity(cfg: &Config, db: &StateDb) -> Result<(uuid::Uuid, String)> {
    if let (Some(id), Some(token)) = (db.get_identity("agent_id")?, db.get_identity("agent_token")?) {
        return Ok((uuid::Uuid::parse_str(&id)?, token));
    }
    let token = cfg
        .enrollment_token
        .clone()
        .context("no identity in state db and no enrollment_token in config")?;
    let host = cfg.host_name.clone().unwrap_or_else(hostname);
    let resp = Uploader::enroll(
        &cfg.server_url,
        &EnrollRequest {
            enrollment_token: token,
            host_name: host,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    // One transaction: a crash can never persist agent_id without the token.
    db.set_identity_many(&[
        ("agent_id", &resp.agent_id.to_string()),
        ("agent_token", &resp.agent_token),
    ])?;
    tracing::info!(agent_id = %resp.agent_id, "enrolled");
    Ok((resp.agent_id, resp.agent_token))
}

async fn run(cfg_path: PathBuf) -> Result<()> {
    let cfg = Arc::new(Config::load(&cfg_path)?);
    std::fs::create_dir_all(&cfg.state_dir)?;
    std::fs::create_dir_all(&cfg.spool_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cfg.spool_dir, std::fs::Permissions::from_mode(0o700));
    }

    let db = Arc::new(StateDb::open(&cfg.state_dir.join("agent.db"))?);
    let (agent_id, agent_token) = ensure_identity(&cfg, &db).await?;
    let host_name = cfg.host_name.clone().unwrap_or_else(hostname);
    let boot_id_str = os_boot_id();
    if refresh_boot_identity(&db, &boot_id_str)? {
        tracing::info!(boot_id = %boot_id_str, "OS boot id changed; sequence reset");
    }
    let boot_id = uuid::Uuid::parse_str(&boot_id_str).unwrap_or_else(|_| uuid::Uuid::new_v4());

    let rt = Arc::new(AgentRuntime {
        uploader: Uploader::new(&cfg.server_url, &agent_token),
        cfg: cfg.clone(),
        db: db.clone(),
        agent_id,
        boot_id,
        host_name,
    });

    // Sensor selection: fanotify where permitted, poll reconciliation always
    // runs as the recovery/fallback path (spec 10.10).
    #[cfg(target_os = "linux")]
    match sensors::fanotify::FanotifySensor::start(&cfg.watch.paths) {
        Ok(sensor) => {
            let db2 = db.clone();
            let debounce = cfg.watch.debounce_ms;
            let exclusions = cfg.watch.exclusions.clone();
            tokio::task::spawn_blocking(move || sensor.run(db2, debounce, exclusions));
            db.set_identity("sensor", "fanotify")?;
        }
        Err(e) => {
            tracing::warn!(error = %e, "fanotify unavailable; poll sensor only (lower assurance)");
            db.set_identity("sensor", "poll_reconcile")?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("non-Linux dev build: poll sensor only (fanotify is Linux-only)");
        db.set_identity("sensor", "poll_reconcile")?;
    }

    // Baseline: low-priority checkpointed walk (spec 10.7), resumes itself.
    if cfg.baseline.enabled {
        db.set_identity("baseline_state", "running")?;
        let db2 = db.clone();
        let cfg2 = cfg.clone();
        tokio::task::spawn_blocking(move || {
            match baseline::run_baseline(&db2, &cfg2.watch.paths, &cfg2.watch.exclusions, cfg2.watch.debounce_ms, None) {
                Ok(r) => tracing::info!(
                    dirs_done = r.dirs_completed,
                    dirs_total = r.dirs_total,
                    candidates = r.candidates_enqueued,
                    "baseline complete"
                ),
                Err(e) => tracing::error!(error = %e, "baseline failed"),
            }
        });
    }

    tokio::spawn(heartbeat::run(rt.clone()));
    tokio::spawn(gap_flusher(rt.clone()));
    tokio::spawn(sensors::poll::run(db.clone(), cfg.clone()));

    tracing::info!("corpus-agent running");
    capture::worker_loop(rt).await;
    Ok(())
}

/// Batch pending gap events to the server (spec 10.1: batched gap reporting).
async fn gap_flusher(rt: Arc<AgentRuntime>) {
    loop {
        let gaps = rt.db.pending_gaps(100);
        match gaps {
            Ok(gaps) if !gaps.is_empty() => {
                let mut events = Vec::new();
                let mut delivered_ids = Vec::new();
                for g in &gaps {
                    let parsed = chrono::DateTime::parse_from_rfc3339(&g.observed_at).ok();
                    match parsed {
                        Some(observed_at) => {
                            events.push(corpus_core::dto::GapEvent {
                                observed_at: observed_at.with_timezone(&chrono::Utc),
                                capture_reason: g.capture_reason.clone(),
                                terminal_outcome: g.terminal_outcome.clone(),
                                artifact_sha256: g.artifact_sha256.clone(),
                                path: g.path.clone(),
                                detail_code: g.detail_code.clone(),
                                detail: serde_json::from_str(&g.detail).ok(),
                                host_name: None,
                            });
                            delivered_ids.push(g.id);
                        }
                        None => {
                            // Loud, and NOT deleted: a row we could not
                            // deliver must not be silently dropped.
                            tracing::error!(gap_id = g.id, outcome = %g.terminal_outcome, "unparseable gap row; left pending");
                        }
                    }
                }
                if events.is_empty() {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
                match rt.uploader.report_gaps(&events).await {
                    Ok(()) => {
                        if let Err(e) = rt.db.delete_gaps(&delivered_ids) {
                            tracing::error!(error = %e, "failed to delete flushed gaps");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "gap flush failed; will retry"),
                }
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "failed to read pending gaps"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn status(cfg_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&cfg_path)?;
    let db = StateDb::open(&cfg.state_dir.join("agent.db"))?;
    println!("agent_id:       {}", db.get_identity("agent_id")?.unwrap_or_else(|| "not enrolled".into()));
    println!("sensor:         {}", db.get_identity("sensor")?.unwrap_or_else(|| "unknown".into()));
    println!("baseline_state: {}", db.get_identity("baseline_state")?.unwrap_or_else(|| "unknown".into()));
    println!("queue_depth:    {}", db.queue_depth()?);
    println!("pending_gaps:   {}", db.pending_gaps(1000)?.len());
    println!("sequence:       {}", db.get_identity("agent_sequence")?.unwrap_or_else(|| "0".into()));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "corpus_agent=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run(cli.config).await,
        Cmd::Status => status(cli.config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_id_refresh_resets_sequence_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(&dir.path().join("s.db")).unwrap();

        // First boot: stored.
        assert!(!refresh_boot_identity(&db, "boot-aaa").unwrap());
        assert_eq!(db.next_sequence().unwrap(), 1);
        assert_eq!(db.next_sequence().unwrap(), 2);

        // Same boot: no change, sequence preserved.
        assert!(!refresh_boot_identity(&db, "boot-aaa").unwrap());
        assert_eq!(db.next_sequence().unwrap(), 3);

        // New boot: returns "changed" and sequence restarts.
        assert!(refresh_boot_identity(&db, "boot-bbb").unwrap());
        assert_eq!(db.get_identity("boot_id").unwrap().as_deref(), Some("boot-bbb"));
        assert_eq!(db.next_sequence().unwrap(), 1);
    }

    #[test]
    fn identity_many_is_atomic_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(&dir.path().join("s.db")).unwrap();
        db.set_identity_many(&[("agent_id", "id-1"), ("agent_token", "tok-1")]).unwrap();
        assert_eq!(db.get_identity("agent_id").unwrap().as_deref(), Some("id-1"));
        assert_eq!(db.get_identity("agent_token").unwrap().as_deref(), Some("tok-1"));
    }
}
