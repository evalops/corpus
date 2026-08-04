//! Postgres connection pool and schema migrations.
//!
//! Migrations live in the repo-root `migrations/` directory and are
//! embedded at compile time via `sqlx::migrate!`. [`connect`] builds a
//! small pool (max 8) suitable for a single-node server; production
//! deployments can raise this via a future config surface.
//!
//! Call [`migrate`] once at process start before serving traffic.

use crate::error::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::{future::Future, time::Duration};

const DATABASE_STARTUP_ATTEMPTS: u32 = 10;
const DATABASE_STARTUP_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const DATABASE_STARTUP_MAX_BACKOFF: Duration = Duration::from_secs(5);
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Open a Postgres pool (`max_connections = 8`) for the given URL.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    retry_database_startup(
        DATABASE_STARTUP_ATTEMPTS,
        DATABASE_STARTUP_INITIAL_BACKOFF,
        DATABASE_STARTUP_MAX_BACKOFF,
        || {
            PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(DATABASE_CONNECT_TIMEOUT)
                .connect(database_url)
        },
        tokio::time::sleep,
    )
    .await
    .map_err(Into::into)
}

/// Apply embedded SQL migrations from the repo `migrations/` directory.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}

async fn retry_database_startup<T, E, Connect, ConnectFuture, Sleep, SleepFuture>(
    attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    mut connect: Connect,
    mut sleep: Sleep,
) -> std::result::Result<T, E>
where
    E: std::fmt::Display,
    Connect: FnMut() -> ConnectFuture,
    ConnectFuture: Future<Output = std::result::Result<T, E>>,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let max_attempts = attempts.max(1);
    let mut backoff = initial_backoff.min(max_backoff);
    for attempt in 1..=max_attempts {
        match connect().await {
            Ok(value) => {
                tracing::info!(attempt, "corpus database connected");
                return Ok(value);
            }
            Err(error) if attempt == max_attempts => return Err(error),
            Err(error) => {
                tracing::warn!(
                    attempt,
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "corpus database startup retry"
                );
                sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
    unreachable!("max_attempts always executes at least once")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn startup_retry_survives_a_slow_database_proxy() {
        let observed_attempts = AtomicU32::new(0);
        let result = retry_database_startup(
            DATABASE_STARTUP_ATTEMPTS,
            Duration::ZERO,
            Duration::ZERO,
            || async {
                let attempt = observed_attempts.fetch_add(1, Ordering::Relaxed) + 1;
                if attempt <= 6 {
                    Err("database proxy is not ready")
                } else {
                    Ok(())
                }
            },
            |_delay| async {},
        )
        .await;

        assert_eq!(result, Ok(()));
        assert_eq!(observed_attempts.load(Ordering::Relaxed), 7);
    }
}
