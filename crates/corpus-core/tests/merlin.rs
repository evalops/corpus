//! Integration tests for Merlin observation ingest and listing.
//! Gated on `CORPUS_TEST_DATABASE_URL`.

use corpus_core::dto::MerlinSegmentRequest;
use corpus_core::{db, merlin, tenant};
use uuid::Uuid;

#[tokio::test]
async fn merlin_segment_ingest_is_idempotent_and_rejects_digest_conflicts() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping Merlin integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("merlin-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Merlin bridge integration test")
        .await
        .unwrap();

    let req = MerlinSegmentRequest {
        schema_version: 1,
        host_name: "merlin-test-host".into(),
        segment: "merlin-events.20260804-010203.jsonl.gz".into(),
        segment_sha256: "A".repeat(64),
        events: vec![
            serde_json::json!({
                "schema_version": 1,
                "boot_id": "boot-a",
                "source_seq": 1,
                "event_id": "boot-a:1",
                "kind": "exec",
                "process_key": "boot-a:42:9",
                "ts": 1_722_744_003.25,
            }),
            serde_json::json!({
                "schema_version": 1,
                "boot_id": "boot-a",
                "source_seq": 2,
                "event_id": "boot-a:2",
                "kind": "connect",
                "ts": 1_722_744_004.25,
            }),
        ],
    };

    let first = merlin::ingest_segment(&pool, tenant_id, &req)
        .await
        .unwrap();
    assert_eq!(first.accepted_events, 2);
    assert_eq!(first.duplicate_events, 0);

    assert_eq!(first.receipt_version, 1);
    assert_eq!(first.segment_sha256, "a".repeat(64));
    assert_eq!(first.status, "accepted");
    let replay = merlin::ingest_segment(&pool, tenant_id, &req)
        .await
        .unwrap();
    assert_eq!(replay.segment_id, first.segment_id);
    assert_eq!(replay.accepted_events, 0);
    assert_eq!(replay.duplicate_events, 2);

    assert_eq!(replay.receipt_version, 1);
    assert_eq!(replay.status, "duplicate");
    let observations = merlin::list_observations(&pool, tenant_id, Some("merlin-test-host"), 100)
        .await
        .unwrap();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].host_name, "merlin-test-host");
    assert_eq!(observations[0].payload["kind"], "connect");

    let mut conflict = req.clone();
    conflict.segment_sha256 = "B".repeat(64);
    assert!(merlin::ingest_segment(&pool, tenant_id, &conflict)
        .await
        .is_err());
}
