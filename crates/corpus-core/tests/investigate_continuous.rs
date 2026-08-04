//! Integration tests for investigation reports and continuous re-analysis.
//! Gated on `CORPUS_TEST_DATABASE_URL`.

use corpus_core::cas::FsCas;
use corpus_core::dto::*;
use corpus_core::{db, hunts, ingest, intel, investigate, registry, DEFAULT_TENANT};
use uuid::Uuid;

#[tokio::test]
async fn continuous_activate_enqueues_retro_and_investigate() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping");
        return;
    };
    // Force continuous on for this test process.
    unsafe {
        std::env::set_var("CORPUS_AUTO_RETRO_ON_ACTIVATE", "1");
        std::env::set_var("CORPUS_SCANNER_TIER", "inprocess");
    }

    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let tenant_id = DEFAULT_TENANT;
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();

    // Unique marker so re-runs do not collide with other suites' rules.
    let marker = format!("CONT_MARKER_{}", &Uuid::new_v4().to_string()[..8]);
    let yar = format!(r#"rule ContMarker {{ strings: $m = "{marker}" condition: $m }}"#);
    let rule = registry::create_rule(&pool, tenant_id, &yar).await.unwrap();

    let bytes = format!("payload {marker} tail").into_bytes();
    let sha = corpus_core::hash::sha256_hex(&bytes);
    let ann = ingest::announce(
        &pool,
        tenant_id,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(OccurrenceInfo {
                host_name: "inv-host".into(),
                agent_id: Uuid::new_v4(),
                boot_id: Uuid::new_v4(),
                agent_sequence: 1,
                path: "/tmp/cont.bin".into(),
                observed_at: chrono::Utc::now(),
                file_size: bytes.len() as i64,
                file_mtime: None,
                capture_reason: "test".into(),
            }),
        },
    )
    .await
    .unwrap();
    if let Some(uid) = ann.upload_id {
        ingest::stage_upload(&pool, &cas, tenant_id, uid, &bytes)
            .await
            .unwrap();
        ingest::finalize(
            &pool,
            &cas,
            tenant_id,
            &FinalizeRequest {
                upload_id: uid,
                sha256: sha.clone(),
                size_bytes: bytes.len() as i64,
                occurrence: Some(OccurrenceInfo {
                    host_name: "inv-host".into(),
                    agent_id: Uuid::new_v4(),
                    boot_id: Uuid::new_v4(),
                    agent_sequence: 2,
                    path: "/tmp/cont.bin".into(),
                    observed_at: chrono::Utc::now(),
                    file_size: bytes.len() as i64,
                    file_mtime: None,
                    capture_reason: "test".into(),
                }),
                scope: None,
                provenance: None,
            },
        )
        .await
        .unwrap();
    }

    let bundle = registry::publish_bundle(&pool, tenant_id, &[rule.id], true)
        .await
        .unwrap();
    let retro = corpus_core::continuous::on_bundle_activated(&pool, tenant_id, &bundle.digest)
        .await
        .unwrap()
        .expect("continuous retro should enqueue");
    assert_eq!(retro.state, "QUEUED");

    let done = hunts::execute_hunt(&pool, &cas, tenant_id, retro.id)
        .await
        .unwrap();
    assert!(
        matches!(done.state.as_str(), "COMPLETED" | "COMPLETED_PARTIAL"),
        "state={}",
        done.state
    );
    assert!(done.matched >= 1, "expected match on continuous retro");

    let inv = investigate::by_sha256(&pool, tenant_id, &sha)
        .await
        .unwrap();
    assert!(!inv.recommended_actions.is_empty());
    assert!(!inv.blast_radius.artifacts.is_empty() || !inv.detections.is_empty());

    // Hash intel continuous path.
    let cont = corpus_core::continuous::on_hash_indicators(
        &pool,
        tenant_id,
        "test-feed",
        std::slice::from_ref(&sha),
    )
    .await
    .unwrap();
    assert_eq!(cont.hits, 1);
    assert_eq!(cont.detections, 1);

    let _ = intel::upsert_indicators;
}
