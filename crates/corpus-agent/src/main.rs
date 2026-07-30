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

fn os_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
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
    db.set_identity("agent_id", &resp.agent_id.to_string())?;
    db.set_identity("agent_token", &resp.agent_token)?;
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
    let boot_id = db
        .get_identity("boot_id")?
        .unwrap_or_else(|| {
            let b = os_boot_id();
            let _ = db.set_identity("boot_id", &b);
            b
        });
    let boot_id = uuid::Uuid::parse_str(&boot_id).unwrap_or_else(|_| uuid::Uuid::new_v4());

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
                let events: Vec<corpus_core::dto::GapEvent> = gaps
                    .iter()
                    .filter_map(|g| {
                        Some(corpus_core::dto::GapEvent {
                            observed_at: chrono::DateTime::parse_from_rfc3339(&g.observed_at).ok()?.with_timezone(&chrono::Utc),
                            capture_reason: g.capture_reason.clone(),
                            terminal_outcome: g.terminal_outcome.clone(),
                            artifact_sha256: g.artifact_sha256.clone(),
                            path: g.path.clone(),
                            detail_code: g.detail_code.clone(),
                            detail: serde_json::from_str(&g.detail).ok(),
                        })
                    })
                    .collect();
                match rt.uploader.report_gaps(&events).await {
                    Ok(()) => {
                        if let Err(e) = rt.db.delete_gaps(&gaps.iter().map(|g| g.id).collect::<Vec<_>>()) {
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
