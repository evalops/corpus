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
//! SQLx also records a SHA-384 checksum for each applied migration, so
//! applied files are immutable; add a new migration instead of editing one.
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
    use sha2::{Digest, Sha384};
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicU32, Ordering},
    };

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
    fn applied_migration_checksums_are_immutable() {
        const APPLIED_MIGRATIONS: &[(&str, &str)] = &[
            (
                "0001_init.sql",
                "e2dd15450914e699dfc1523c96a94e4d63dffa1a4b9bc4dfb5f6d253cfdd6a0695c7f9466be74ca36f613570a765d2e9",
            ),
            (
                "0002_agents.sql",
                "b63e38b1816f2279767f059e8b5bbcbe0b1e4aa34a08b07e00884626ea85492baf6e3ea3599e643930fdae2d30d68d7a",
            ),
            (
                "0003_similarity.sql",
                "9afa81e8f30af8158e959a4d5d6bfdc9d67a0337826cd4f0651ed3fca250baf81573a00f9ce6d1d57f89a3a844dccebe",
            ),
            (
                "0004_bootstrap.sql",
                "ccdb12d8a0e28d2e66f5a311760bb10d96c7f66ada4a71c62c9d5642802f5a10d57028e0da672e16ad49d7ae226104de",
            ),
            (
                "0005_analyst.sql",
                "68c9f52ceed1cf6d93b287054b3ecd396da6a522499fb2def326462ade364bf300ed21a9af88aebebe038ccd695a4b1c",
            ),
            (
                "0006_semantic.sql",
                "7020f4223c4d165881f738e4656855cb534360a86841540d8ae6f69dcba1f63160c4dfbac7c6ed489e4254695cc5295c",
            ),
            (
                "0007_detonation.sql",
                "8b5f867b081243df98cce5b6f857d35d246cfdd4cbbe55614048cfabc507b8e922ef125b4a306ac34582ccb3110cf6e9",
            ),
            (
                "0008_lsh_and_hunt_queue.sql",
                "261485c56c6eb617d70c57fab1c99341ecc16bb70b0fab364209d8fbaf890c16e0df1e6b10c425ac26993f2786fb4e2e",
            ),
            (
                "0009_continuous_investigate.sql",
                "5b3861bc0eb81eadb3c9d7932e5e216365f151873f3b4fe6c96e18a62e741ccc1452b995d2cd962bfaf9130fa107f7f0",
            ),
            (
                "0010_receipts_and_cleanup.sql",
                "bfb3ac668520b6893a5d0b49d73112c1fe8c705d59585ef9f518d250c6998686c108476438c9f8264552540e0e444573",
            ),
        ];

        let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        for (name, expected) in APPLIED_MIGRATIONS {
            let bytes = fs::read(migrations_dir.join(name)).expect("read applied migration");
            let actual = hex::encode(Sha384::digest(&bytes));
            assert_eq!(actual, *expected, "applied migration {name} was modified");
        }
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
}
