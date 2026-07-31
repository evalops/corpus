use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Server-recomputed SHA-256 does not match the client-announced hash.
    /// The commit must be rejected (core invariant #1).
    #[error("sha256 mismatch: announced {announced}, recomputed {recomputed}")]
    HashMismatch { announced: String, recomputed: String },

    #[error("rule compile error: {0}")]
    RuleCompile(String),

    #[error("invalid rule source: {0}")]
    RuleParse(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("forbidden: {0}")]
    Forbidden(String),
}

pub type Result<T> = std::result::Result<T, Error>;
