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

/// Open a Postgres pool (`max_connections = 8`) for the given URL.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// Apply embedded SQL migrations from the repo `migrations/` directory.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path};

    #[test]
    fn migration_versions_are_unique() {
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
