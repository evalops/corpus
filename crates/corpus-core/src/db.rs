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
