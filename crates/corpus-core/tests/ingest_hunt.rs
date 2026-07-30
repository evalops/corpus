//! End-to-end integration test against a real PostgreSQL and a tempfile CAS.
//!
//! Gated on CORPUS_TEST_DATABASE_URL (the demo script sets it); without it
//! the test is a no-op so plain `cargo test` stays hermetic.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceDisposition, AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::{db, hash, hunts, ingest, registry, report};
use uuid::Uuid;

const MARKER: &[u8] = b"prefix CORPUS_DEMO_MARKER_STRING suffix";
const RULE: &str = r#"rule CorpusDemoMarker {
  strings:
    $m = "CORPUS_DEMO_MARKER_STRING"
  condition:
    $m
}"#;

fn occ(path: &str, seq: i64, agent: Uuid, boot: Uuid) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "test-host".into(),
        agent_id: agent,
        boot_id: boot,
        agent_sequence: seq,
        path: path.into(),
        observed_at: chrono::Utc::now(),
        file_size: 0, // caller-independent; tests set sizes explicitly where needed
        file_mtime: None,
        capture_reason: "cli_import".into(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn import_bytes(
    pool: &sqlx::PgPool,
    cas: &FsCas,
    tenant: Uuid,
    path: &str,
    bytes: &[u8],
    seq: i64,
    agent: Uuid,
    boot: Uuid,
) -> (String, AnnounceDisposition) {
    let sha = hash::sha256_hex(bytes);
    let mut o = occ(path, seq, agent, boot);
    o.file_size = bytes.len() as i64;
    let ann = ingest::announce(
        pool,
        tenant,
        &AnnounceRequest { sha256: sha.clone(), size_bytes: bytes.len() as i64, occurrence: o.clone() },
    )
    .await
    .unwrap();
    if ann.disposition == AnnounceDisposition::UploadRequired {
        let upload_id = ann.upload_id.unwrap();
        ingest::stage_upload(pool, cas, tenant, upload_id, bytes).await.unwrap();
        ingest::finalize(
            pool,
            cas,
            tenant,
            &FinalizeRequest {
                upload_id,
                sha256: sha.clone(),
                size_bytes: bytes.len() as i64,
                occurrence: o,
            },
        )
        .await
        .unwrap();
    }
    (sha, ann.disposition)
}

#[tokio::test]
async fn ingest_hunt_and_blast_radius_end_to_end() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();
    let tenant = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let boot = Uuid::new_v4();

    // --- import two files: one marker carrier, one plain binary
    let (marker_sha, disp) =
        import_bytes(&pool, &cas, tenant, "/import/marker.txt", MARKER, 1, agent, boot).await;
    assert_eq!(disp, AnnounceDisposition::UploadRequired);
    let (_, disp) =
        import_bytes(&pool, &cas, tenant, "/import/plain.bin", b"\x7fELF\x02plain", 2, agent, boot).await;
    assert_eq!(disp, AnnounceDisposition::UploadRequired);

    // --- re-import: dedup hit must still record occurrence + capture attempt
    let (_, disp) =
        import_bytes(&pool, &cas, tenant, "/import/marker-copy.txt", MARKER, 3, agent, boot).await;
    assert_eq!(disp, AnnounceDisposition::AlreadyPresent);
    let occ_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM occurrence_event WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(occ_count, 3);
    let attempts: Vec<(String,)> = sqlx::query_as(
        "SELECT terminal_outcome FROM capture_attempt WHERE tenant_id = $1 ORDER BY observed_at",
    )
    .bind(tenant)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(attempts.iter().any(|a| a.0 == ingest::OUTCOME_ALREADY_PRESENT));
    assert_eq!(attempts.iter().filter(|a| a.0 == ingest::OUTCOME_CAPTURED).count(), 2);

    // --- hash mismatch must be rejected and leave no artifact row
    let bad = b"different bytes entirely";
    let wrong_sha = hash::sha256_hex(b"claimed bytes");
    let mut o = occ("/import/evil.bin", 4, agent, boot);
    o.file_size = bad.len() as i64;
    let ann = ingest::announce(
        &pool,
        tenant,
        &AnnounceRequest { sha256: wrong_sha.clone(), size_bytes: bad.len() as i64, occurrence: o.clone() },
    )
    .await
    .unwrap();
    let upload_id = ann.upload_id.unwrap();
    ingest::stage_upload(&pool, &cas, tenant, upload_id, bad).await.unwrap();
    let err = ingest::finalize(
        &pool,
        &cas,
        tenant,
        &FinalizeRequest { upload_id, sha256: wrong_sha.clone(), size_bytes: bad.len() as i64, occurrence: o },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, corpus_core::error::Error::HashMismatch { .. }));
    let bad_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM artifact WHERE tenant_id = $1 AND sha256 = decode($2, 'hex')",
    )
    .bind(tenant)
    .bind(&wrong_sha)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bad_rows, 0);
    let mismatch_recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM capture_attempt WHERE tenant_id = $1 AND terminal_outcome = 'HASH_MISMATCH'",
    )
    .bind(tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mismatch_recorded, 1);

    // --- rule + bundle publish (forward coverage active)
    let rule = registry::create_rule(&pool, tenant, RULE).await.unwrap();
    assert_eq!(rule.stable_id, "CorpusDemoMarker");
    let bundle = registry::publish_bundle(&pool, tenant, &[rule.id], true).await.unwrap();
    assert!(bundle.active);
    // republishing the same rule set must yield the same digest
    let bundle2 = registry::publish_bundle(&pool, tenant, &[rule.id], true).await.unwrap();
    assert_eq!(bundle.digest, bundle2.digest);

    // --- retro hunt, twice: second run must be a pure cache replay
    let hunt = hunts::create_hunt(&pool, tenant, &bundle.digest).await.unwrap();
    let hunt = hunts::run_hunt(&pool, &cas, tenant, hunt.id).await.unwrap();
    assert_eq!(hunt.state, "COMPLETED");
    assert_eq!(hunt.planned_artifacts, 2);
    assert_eq!(hunt.scanned, 2);
    assert_eq!(hunt.matched, 1);

    let hunt2 = hunts::run_hunt(&pool, &cas, tenant, hunt.id).await.unwrap();
    assert_eq!(hunt2.state, "COMPLETED");
    assert_eq!(hunt2.cache_hits, 2, "second run must not reread bytes");
    assert_eq!(hunt2.scanned, 0);

    // idempotency: no duplicate match rows
    let match_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM hunt_match WHERE tenant_id = $1 AND hunt_id = $2",
    )
    .bind(tenant)
    .bind(hunt.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(match_count, 1);

    // --- forward coverage: new commit hits the active bundle's forward hunt
    // (novel bytes carrying the marker; identical bytes would be a dedup hit
    // and never reach finalize, by design)
    let (fwd_sha, _) = import_bytes(
        &pool, &cas, tenant, "/import/late-marker.txt",
        b"late arrival CORPUS_DEMO_MARKER_STRING tail", 5, agent, boot,
    ).await;
    let forward_matches: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM hunt_match m JOIN hunt h ON h.id = m.hunt_id
         WHERE m.tenant_id = $1 AND h.kind = 'forward'",
    )
    .bind(tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(forward_matches, 1);

    // --- blast radius by hunt and by exact hash
    let br = report::by_hunt(&pool, tenant, hunt.id).await.unwrap();
    assert_eq!(br.artifacts.len(), 1);
    assert_eq!(br.artifacts[0].sha256, marker_sha);
    assert_eq!(br.artifacts[0].matched_rules, vec!["CorpusDemoMarker"]);
    assert_eq!(br.occurrences.len(), 2, "original + dedup-hit occurrence");
    assert_eq!(br.hosts.len(), 1);
    assert_eq!(br.hosts[0].host_name, "test-host");
    assert!(br.verification_state.contains("historical_observation_only"));

    let br2 = report::by_sha256(&pool, tenant, &fwd_sha).await.unwrap();
    assert_eq!(br2.artifacts.len(), 1);
    assert_eq!(br2.occurrences.len(), 1);

    // --- tenant isolation: other tenants see nothing (invariant #3)
    let other = report::by_sha256(&pool, Uuid::new_v4(), &marker_sha).await.unwrap();
    assert!(other.artifacts.is_empty());
}
