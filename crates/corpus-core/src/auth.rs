//! Admin API authentication and listen-address policy.
//!
//! # Goals
//!
//! - Bind admin routes to a shared secret or mTLS identity depending on
//!   deployment mode.
//! - Refuse to expose unauthenticated admin APIs on non-loopback
//!   addresses without an explicit opt-in.
//!
//! Agent traffic uses separate enrollment tokens / mTLS (see [`crate::agents`]
//! and [`crate::mtls`]); this module is for human/admin operators and
//! control-plane tools like `corpusctl`.

use crate::error::{Error, Result};
use std::net::SocketAddr;

pub const MCP_DEV_TOKEN: &str = "mcp-dev-token";

#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Static operator token from `CORPUS_ADMIN_TOKEN`, if set.
    pub admin_token: Option<String>,
    /// When true, admin routes require a matching Bearer token.
    pub require_admin: bool,
    /// When true, announce/upload/finalize accept unauthenticated
    /// `corpusctl import` (tenant from header only).
    pub allow_dev_ingest: bool,
    /// MCP bearer token (never the hardcoded default on non-loopback).
    pub mcp_token: String,
    /// Narrow service token for the Merlin telemetry bridge. It is separate
    /// from the admin token so a deployed sensor control plane cannot mutate
    /// Corpus policy or hunts.
    pub merlin_ingest_token: Option<String>,
    pub listen_is_loopback: bool,
}

impl AuthConfig {
    /// Build from environment and the admin listen address string
    /// (`CORPUS_LISTEN`).
    pub fn from_env(listen: &str) -> Result<AuthConfig> {
        let listen_is_loopback = is_loopback_listen(listen);
        let admin_token = std::env::var("CORPUS_ADMIN_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if !listen_is_loopback && admin_token.is_none() {
            return Err(Error::BadRequest(
                "CORPUS_LISTEN is non-loopback but CORPUS_ADMIN_TOKEN is unset; \
                 refuse to start without admin auth (bind 127.0.0.1 or set a token)"
                    .into(),
            ));
        }

        let require_admin = admin_token.is_some()
            || std::env::var("CORPUS_REQUIRE_ADMIN").is_ok()
            || !listen_is_loopback;

        if require_admin && admin_token.is_none() {
            return Err(Error::BadRequest(
                "admin auth required (CORPUS_REQUIRE_ADMIN or non-loopback) but \
                 CORPUS_ADMIN_TOKEN is unset"
                    .into(),
            ));
        }

        let mcp_token = std::env::var("CORPUS_MCP_TOKEN").unwrap_or_else(|_| {
            if listen_is_loopback {
                MCP_DEV_TOKEN.to_string()
            } else {
                String::new()
            }
        });
        if !listen_is_loopback && (mcp_token.is_empty() || mcp_token == MCP_DEV_TOKEN) {
            return Err(Error::BadRequest(
                "non-loopback bind requires CORPUS_MCP_TOKEN set to a \
                 non-default value"
                    .into(),
            ));
        }

        let merlin_ingest_token = std::env::var("CORPUS_MERLIN_INGEST_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let allow_dev_ingest = listen_is_loopback
            && std::env::var("CORPUS_DENY_DEV_INGEST").is_err()
            && !require_admin;

        // If admin token is set even on loopback, still allow dev ingest
        // only when explicitly opted in — operators with a token usually
        // want corpusctl to send that token.
        let allow_dev_ingest = if admin_token.is_some() {
            std::env::var("CORPUS_ALLOW_DEV_INGEST").is_ok()
        } else {
            allow_dev_ingest || std::env::var("CORPUS_ALLOW_DEV_INGEST").is_ok()
        };

        Ok(AuthConfig {
            admin_token,
            require_admin,
            allow_dev_ingest,
            mcp_token,
            merlin_ingest_token,
            listen_is_loopback,
        })
    }

    /// Constant-time-ish check that `provided` matches the configured
    /// admin token. Returns false if no admin token is configured.
    pub fn admin_matches(&self, provided: &str) -> bool {
        match &self.admin_token {
            Some(expected) => subtle_eq(expected.as_bytes(), provided.as_bytes()),
            None => false,
        }
    }

    pub fn mcp_matches(&self, provided: &str) -> bool {
        subtle_eq(self.mcp_token.as_bytes(), provided.as_bytes())
    }

    pub fn merlin_matches(&self, provided: &str) -> bool {
        self.merlin_ingest_token
            .as_deref()
            .is_some_and(|expected| subtle_eq(expected.as_bytes(), provided.as_bytes()))
    }

    /// The bridge may use its narrow service token or an admin token during
    /// local operations. Production deployments should use the former.
    pub fn check_merlin_ingest(&self, authorization_header: Option<&str>) -> Result<()> {
        let Some(token) = bearer_from_authorization(authorization_header) else {
            return Err(Error::Unauthorized(
                "Merlin bridge requires Authorization: Bearer <CORPUS_MERLIN_INGEST_TOKEN>".into(),
            ));
        };
        if self.merlin_matches(token) || self.admin_matches(token) {
            return Ok(());
        }
        Err(Error::Unauthorized("invalid Merlin bridge token".into()))
    }

    /// Require admin auth when `require_admin` is set.
    pub fn check_admin(&self, authorization_header: Option<&str>) -> Result<()> {
        if !self.require_admin {
            return Ok(());
        }
        let Some(token) = bearer_from_authorization(authorization_header) else {
            return Err(Error::Unauthorized(
                "admin routes require Authorization: Bearer <CORPUS_ADMIN_TOKEN>".into(),
            ));
        };
        if !self.admin_matches(token) {
            return Err(Error::Unauthorized("invalid admin token".into()));
        }
        Ok(())
    }
}

/// True for `127.0.0.1`, `::1`, `localhost`, and unspecified host forms
/// that resolve only to loopback when written as `ip:port`.
pub fn is_loopback_listen(listen: &str) -> bool {
    let listen = listen.trim();
    // Bare host without port (unusual).
    if listen == "localhost" || listen == "127.0.0.1" || listen == "::1" {
        return true;
    }
    if let Ok(addr) = listen.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }
    // `host:port` where host is a name we treat as loopback only for
    // localhost — do not reverse-DNS arbitrary hostnames.
    if let Some((host, _port)) = listen.rsplit_once(':') {
        let host = host.trim_matches(|c| c == '[' || c == ']');
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    }
    false
}

pub fn bearer_from_authorization(header: Option<&str>) -> Option<&str> {
    header.and_then(|s| s.strip_prefix("Bearer "))
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detects_ipv4_and_localhost() {
        assert!(is_loopback_listen("127.0.0.1:8080"));
        assert!(is_loopback_listen("localhost:8080"));
        assert!(is_loopback_listen("[::1]:8080"));
        assert!(!is_loopback_listen("0.0.0.0:8080"));
        assert!(!is_loopback_listen("10.0.0.5:8080"));
    }

    #[test]
    fn admin_token_match_is_length_sensitive() {
        let cfg = AuthConfig {
            admin_token: Some("secret-token".into()),
            require_admin: true,
            allow_dev_ingest: false,
            mcp_token: "mcp".into(),
            merlin_ingest_token: Some("merlin".into()),
            listen_is_loopback: false,
        };
        assert!(cfg.admin_matches("secret-token"));
        assert!(!cfg.admin_matches("secret-toke"));
        assert!(!cfg.admin_matches("wrong"));
    }
}
