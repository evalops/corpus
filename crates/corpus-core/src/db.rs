//! Postgres connection pool and schema migrations.
//!
//! Migrations live in the repo-root `migrations/` directory and are
//! embedded at compile time via `sqlx::migrate!`. [`connect`] builds a
//! small pool (max 8) suitable for a single-node server; production
//! deployments can raise this via a future config surface.
//!
//! Each migration filename must have a unique numeric prefix because SQLx
//! persists that prefix as the primary-keyed migration version.
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

    #[test]
    fn migration_versions_are_unique() {
        use std::{collections::BTreeMap, fs, path::Path};

        let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut versions = BTreeMap::new();

        for entry in fs::read_dir(&migrations_dir).expect("read migrations directory") {
            let path = entry.expect("read migration directory entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
                continue;
            }

            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("migration filename is valid UTF-8")
                .to_owned();
            let (version, _) = name
                .split_once('_')
                .expect("migration filename has a numeric prefix");
            let version: i64 = version.parse().expect("migration prefix is numeric");

            assert!(
                versions.insert(version, name).is_none(),
                "duplicate migration version {version}"
            );
        }
    }

    #[test]
    fn applied_agent_migration_checksum_is_immutable() {
        use sha2::{Digest, Sha256};
        use std::{fs, path::Path};

        let migration =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations/0002_agents.sql");
        let checksum = hex::encode(Sha256::digest(fs::read(migration).expect("read migration")));

        assert_eq!(
            checksum, "45f16bac4c5d1021f7ed9636ebfa203767b828807bbaf53b7f6f53d2aeebb8d1",
            "migration 0002 is already applied in production and must not be edited"
        );
    }
}
