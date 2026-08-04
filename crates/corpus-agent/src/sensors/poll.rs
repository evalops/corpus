//! Portable periodic re-scan sensor.
//!
//! Used when native journals are unavailable or as a safety net. More
//! expensive than event-driven sensors; interval is config-driven.

use crate::baseline::reconcile_scan;
use crate::config::Config;
use crate::state::StateDb;
use std::sync::Arc;

pub async fn run(db: Arc<StateDb>, cfg: Arc<Config>) {
    let interval = std::time::Duration::from_secs(cfg.watch.poll_interval_secs.max(1));
    // The checkpointed baseline owns the initial pass; the first
    // reconciliation scan runs one interval later.
    tokio::time::sleep(interval).await;
    loop {
        let db2 = db.clone();
        let cfg2 = cfg.clone();
        let result = tokio::task::spawn_blocking(move || {
            reconcile_scan(
                &db2,
                &cfg2.watch.paths,
                &cfg2.watch.exclusions,
                cfg2.watch.debounce_ms,
            )
        })
        .await;
        match result {
            Ok(Ok(n)) if n > 0 => {
                tracing::info!(candidates = n, "reconcile scan enqueued candidates")
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "reconcile scan failed"),
            Err(e) => tracing::warn!(error = %e, "reconcile scan join error"),
            _ => {}
        }
        tokio::time::sleep(interval).await;
    }
}
