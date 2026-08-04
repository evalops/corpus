//! HTTP tests for admin auth and listen-address policy.

use corpus_core::auth::{is_loopback_listen, AuthConfig, MCP_DEV_TOKEN};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn non_loopback_without_token_fails() {
    let _g = ENV_LOCK.lock().unwrap();
    // SAFETY: single-threaded under ENV_LOCK for this process.
    unsafe {
        std::env::remove_var("CORPUS_ADMIN_TOKEN");
        std::env::remove_var("CORPUS_REQUIRE_ADMIN");
        std::env::remove_var("CORPUS_MCP_TOKEN");
    }
    let err = AuthConfig::from_env("0.0.0.0:8080").unwrap_err();
    assert!(
        err.to_string().contains("CORPUS_ADMIN_TOKEN"),
        "expected admin token required, got {err}"
    );
}

#[test]
fn loopback_allows_missing_admin_token() {
    let _g = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("CORPUS_ADMIN_TOKEN");
        std::env::remove_var("CORPUS_REQUIRE_ADMIN");
        std::env::remove_var("CORPUS_MCP_TOKEN");
        std::env::remove_var("CORPUS_ALLOW_DEV_INGEST");
        std::env::remove_var("CORPUS_DENY_DEV_INGEST");
    }
    let cfg = AuthConfig::from_env("127.0.0.1:8080").unwrap();
    assert!(!cfg.require_admin);
    assert!(cfg.allow_dev_ingest);
    assert_eq!(cfg.mcp_token, MCP_DEV_TOKEN);
}

#[test]
fn admin_token_gates_routes() {
    let cfg = AuthConfig {
        admin_token: Some("test-admin-secret".into()),
        require_admin: true,
        allow_dev_ingest: false,
        mcp_token: "mcp-prod-secret".into(),
        merlin_ingest_token: Some("merlin-service-secret".into()),
        listen_is_loopback: false,
    };
    assert!(cfg.check_admin(None).is_err());
    assert!(cfg.check_admin(Some("Bearer wrong")).is_err());
    assert!(cfg.check_admin(Some("Bearer test-admin-secret")).is_ok());
    assert!(cfg
        .check_merlin_ingest(Some("Bearer merlin-service-secret"))
        .is_ok());
    assert!(cfg
        .check_merlin_ingest(Some("Bearer test-admin-secret"))
        .is_ok());
    assert!(cfg.check_merlin_ingest(Some("Bearer wrong")).is_err());
}

#[test]
fn loopback_detection() {
    assert!(is_loopback_listen("127.0.0.1:8080"));
    assert!(!is_loopback_listen("0.0.0.0:8080"));
}
