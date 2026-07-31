//! Integration test for the M1 agent endpoints against real PostgreSQL.
//! Gated on CORPUS_TEST_DATABASE_URL like the M0 test; no-op without it.

use corpus_core::dto::{
    AnnounceDisposition, AnnounceRequest, EnrollRequest, GapEvent, HeartbeatRequest, OccurrenceInfo,
};
use corpus_core::{agents, db, hash, ingest};
use uuid::Uuid;

fn occ(host: &str, agent: Uuid, boot: Uuid, seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: host.into(),
        agent_id: agent,
        boot_id: boot,
        agent_sequence: seq,
        path: path.into(),
        observed_at: chrono::Utc::now(),
        file_size: size,
        file_mtime: None,
        capture_reason: "baseline".into(),
    }
}

#[tokio::test]
async fn agent_enroll_heartbeat_gaps_and_dedup_occurrence() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    // Bearer is now legacy dev mode; agent traffic is mTLS by default.
    unsafe { std::env::set_var("CORPUS_AGENT_LEGACY_BEARER", "1") };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    // FK-scoped world: the tenant must exist and be active first.
    let tenant = Uuid::new_v4();
    let slug = format!("itest-{}", &tenant.simple().to_string()[..8]);
    corpus_core::tenant::ensure_tenant(&pool, tenant, &slug, "Agent API integration test")
        .await
        .unwrap();

    // --- enrollment: one-time token exchange
    let ca =
        corpus_core::mtls::load_or_create_ca(tempfile::tempdir().unwrap().path(), &[]).unwrap();
    let tok = agents::create_enrollment_token(&pool, tenant, "itest", Some(3600))
        .await
        .unwrap();
    let resp = agents::enroll(
        &pool,
        &ca,
        &EnrollRequest {
            enrollment_token: tok.token.clone(),
            host_name: "itest-host".into(),
            agent_version: "0.1.0-test".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(resp.tenant_id, tenant);
    assert!(!resp.client_cert_pem.is_empty() && !resp.ca_cert_pem.is_empty());
    // Token is consumed: a second exchange must fail.
    let second = agents::enroll(
        &pool,
        &ca,
        &EnrollRequest {
            enrollment_token: tok.token,
            host_name: "itest-host".into(),
            agent_version: "0.1.0-test".into(),
        },
    )
    .await;
    assert!(second.is_err(), "consumed token must not enroll twice");

    // --- bearer auth resolves identity
    let ident = agents::authenticate(&pool, &resp.agent_token)
        .await
        .unwrap();
    assert_eq!(ident.agent_id, resp.agent_id);
    assert_eq!(ident.host_name, "itest-host");
    assert!(agents::authenticate(&pool, "cpagent-bogus").await.is_err());

    // --- heartbeat lands on the agent row
    agents::heartbeat(
        &pool,
        &ident,
        &HeartbeatRequest {
            agent_version: "0.1.0-test".into(),
            policy_digest: "deadbeef".into(),
            baseline_state: "complete".into(),
            baseline_percent: 100.0,
            queue_depth: 3,
            spool_bytes: 1234,
            oldest_pending_secs: Some(42),
            sensor: "poll_reconcile".into(),
            outcome_counts: serde_json::json!({"CAPTURED": 2, "TOO_LARGE": 1}),
            last_upload_at: Some(chrono::Utc::now()),
            clock_offset_ms: None,
        },
    )
    .await
    .unwrap();
    let status = agents::agent_status(&pool, tenant, resp.agent_id)
        .await
        .unwrap();
    assert_eq!(status.queue_depth, Some(3));
    assert_eq!(status.baseline_state.as_deref(), Some("complete"));
    assert_eq!(status.outcome_counts["TOO_LARGE"], 1);

    // --- batched gap reporting lands in capture_attempt
    agents::record_gaps(
        &pool,
        &ident,
        &[GapEvent {
            observed_at: chrono::Utc::now(),
            capture_reason: "baseline".into(),
            terminal_outcome: "TOO_LARGE".into(),
            artifact_sha256: None,
            path: Some("/watch/big.bin".into()),
            detail_code: None,
            detail: Some(serde_json::json!({"size_bytes": 999})),
            host_name: None,
        }],
    )
    .await
    .unwrap();
    let gaps = agents::coverage_gaps(&pool, tenant, Some("TOO_LARGE"), 10)
        .await
        .unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].path.as_deref(), Some("/watch/big.bin"));
    assert_eq!(gaps[0].host_name, "itest-host");

    // --- dedup via the agent path still records occurrences (spec 11.1)
    let bytes = b"agent-carried CORPUS_DEMO_MARKER_STRING bytes";
    let sha = hash::sha256_hex(bytes);
    let boot = Uuid::new_v4();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = corpus_core::cas::FsCas::new(cas_dir.path()).unwrap();

    let ann1 = ingest::announce(
        &pool,
        tenant,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(
                "itest-host",
                resp.agent_id,
                boot,
                1,
                "/watch/a.bin",
                bytes.len() as i64,
            )),
        },
    )
    .await
    .unwrap();
    assert_eq!(ann1.disposition, AnnounceDisposition::UploadRequired);
    let upload_id = ann1.upload_id.unwrap();
    ingest::stage_upload(&pool, &cas, tenant, upload_id, bytes)
        .await
        .unwrap();
    ingest::finalize(
        &pool,
        &cas,
        tenant,
        &corpus_core::dto::FinalizeRequest {
            upload_id,
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(
                "itest-host",
                resp.agent_id,
                boot,
                2,
                "/watch/a.bin",
                bytes.len() as i64,
            )),
            scope: None,
            provenance: None,
        },
    )
    .await
    .unwrap();

    // Same bytes seen at another path: dedup hit, occurrence still recorded.
    let ann2 = ingest::announce(
        &pool,
        tenant,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(
                "itest-host",
                resp.agent_id,
                boot,
                3,
                "/watch/copy.bin",
                bytes.len() as i64,
            )),
        },
    )
    .await
    .unwrap();
    assert_eq!(ann2.disposition, AnnounceDisposition::AlreadyPresent);

    // Occurrences: one from finalize, one from the dedup-hit announce. The
    // initial UPLOAD_REQUIRED announce records none until finalize commits.
    let occ_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM occurrence_event WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(tenant)
    .bind(resp.agent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        occ_count, 2,
        "finalize + dedup-hit announce each record one occurrence"
    );
    let paths: Vec<(String,)> = sqlx::query_as(
        "SELECT path FROM occurrence_event WHERE tenant_id = $1 AND agent_id = $2 ORDER BY agent_sequence",
    )
    .bind(tenant)
    .bind(resp.agent_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(paths.iter().any(|p| p.0 == "/watch/copy.bin"));

    // --- fleet list shows the enrolled agent
    let list = agents::list_agents(&pool, tenant).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, resp.agent_id);
}
