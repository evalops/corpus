//! Integration tests for prevalence and rarity analyst APIs.
//! Gated on `CORPUS_TEST_DATABASE_URL`.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::{analyst, db, hash, ingest, opinions, report, tenant, triggers};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn occ(
    host: &str,
    seq: i64,
    path: &str,
    size: i64,
    observed: chrono::DateTime<chrono::Utc>,
) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: host.into(),
        agent_id: Uuid::new_v4(),
        boot_id: Uuid::new_v4(),
        agent_sequence: seq,
        path: path.into(),
        observed_at: observed,
        file_size: size,
        file_mtime: None,
        capture_reason: "cli_import".into(),
    }
}

async fn commit(
    pool: &sqlx::PgPool,
    cas: &FsCas,
    tenant_id: Uuid,
    occurrence: OccurrenceInfo,
    bytes: &[u8],
) -> (Uuid, String) {
    let sha = hash::sha256_hex(bytes);
    let ann = ingest::announce(
        pool,
        tenant_id,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occurrence.clone()),
        },
    )
    .await
    .unwrap();
    if let Some(upload_id) = ann.upload_id {
        ingest::stage_upload(pool, cas, tenant_id, upload_id, bytes)
            .await
            .unwrap();
        let fin = ingest::finalize(
            pool,
            cas,
            tenant_id,
            &FinalizeRequest {
                upload_id,
                sha256: sha.clone(),
                size_bytes: bytes.len() as i64,
                occurrence: Some(occurrence),
                scope: None,
                provenance: None,
            },
        )
        .await
        .unwrap();
        return (fin.artifact_id, sha);
    }
    (ann.artifact_id.unwrap(), sha)
}

/// Webhook receiver that verifies HMAC signatures on the first `n`
/// requests it sees and records (event, signature_valid) for each.
struct VerifiedWebhook {
    pub base: String,
    pub received: Arc<Mutex<Vec<(serde_json::Value, bool)>>>,
}

fn start_verified_webhook(secret: &str, n: usize) -> VerifiedWebhook {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let received = Arc::new(Mutex::new(Vec::new()));
    let received2 = received.clone();
    let secret = secret.to_string();
    std::thread::spawn(move || {
        for _ in 0..n {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            let _ = reader.read_line(&mut request_line);
            let mut signature = String::new();
            let mut content_length = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("x-corpus-signature: sha256=") {
                    signature = v.trim().to_string();
                }
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            let _ = reader.read_exact(&mut body);
            let expected = triggers::hmac_signature(&secret, &body);
            let valid = signature == expected;
            let event: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            received2.lock().unwrap().push((event, valid));
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    VerifiedWebhook { base, received }
}

#[tokio::test]
async fn analyst_surface_end_to_end() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("analyst-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Analyst test")
        .await
        .unwrap();

    let t0 = chrono::DateTime::parse_from_rfc3339("2024-06-01T10:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let h = chrono::Duration::hours(1);

    // Layout: seed on host1@t0; candidate on host1@t0+1h (rare, in window);
    // common on host1..4@t0+1h (in window but not rare);
    // old on host1@t0-48h (rare but out of window).
    let (seed, sha_seed) = commit(
        &pool,
        &cas,
        tenant_id,
        occ("host1", 1, "/tmp/bad.exe", 10, t0),
        b"bad seed CORPUS_ANALYST_MARKER",
    )
    .await;
    let (cand, sha_cand) = commit(
        &pool,
        &cas,
        tenant_id,
        occ("host1", 2, "/tmp/helper.dll", 11, t0 + h),
        b"helper dll bytes",
    )
    .await;
    let (_, sha_common) = commit(
        &pool,
        &cas,
        tenant_id,
        occ("host1", 3, "/bin/common", 12, t0 + h),
        b"common bytes everywhere",
    )
    .await;
    for (i, host) in ["host2", "host3", "host4"].iter().enumerate() {
        commit(
            &pool,
            &cas,
            tenant_id,
            occ(host, i as i64 + 4, "/bin/common", 12, t0 + h),
            b"common bytes everywhere",
        )
        .await;
    }
    commit(
        &pool,
        &cas,
        tenant_id,
        occ("host1", 7, "/opt/old.so", 9, t0 - chrono::Duration::days(2)),
        b"old library bytes",
    )
    .await;

    // ===== 1. PREVALENCE =====
    let p_common = analyst::prevalence_for(&pool, tenant_id, {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = decode($2,'hex')",
        )
        .bind(tenant_id)
        .bind(&sha_common)
        .fetch_optional(&pool)
        .await
        .unwrap();
        row.unwrap().0
    })
    .await
    .unwrap();
    assert_eq!(p_common.host_count, 4);
    assert_eq!(p_common.path_count, 1);
    let p_seed = analyst::prevalence_for(&pool, tenant_id, seed)
        .await
        .unwrap();
    assert_eq!(p_seed.host_count, 1);
    assert_eq!(p_seed.first_observed, Some(t0));

    // ===== 2. rarity search: only the two host_count<=1 artifacts =====
    let hits = analyst::rarity_search(
        &pool,
        tenant_id,
        1,
        t0 - chrono::Duration::days(3),
        None,
        50,
    )
    .await
    .unwrap();
    let shas: Vec<&str> = hits.iter().map(|h| h.sha256.as_str()).collect();
    assert!(shas.contains(&sha_seed.as_str()) && shas.contains(&sha_cand.as_str()));
    assert!(
        !shas.contains(&sha_common.as_str()),
        "4-host artifact is not rare"
    );

    // ===== 3. opinions + audit =====
    opinions::set_opinion(
        &pool,
        tenant_id,
        seed,
        "suspicious",
        "analyst-1",
        "odd imports",
    )
    .await
    .unwrap();
    opinions::set_opinion(
        &pool,
        tenant_id,
        seed,
        "malicious",
        "analyst-1",
        "confirmed C2",
    )
    .await
    .unwrap();
    let current = opinions::current_opinion(&pool, tenant_id, seed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.opinion, "malicious");
    let history = opinions::opinion_history(&pool, tenant_id, seed)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert!(
        history[0].superseded_by.is_some(),
        "first opinion superseded"
    );
    assert!(history[1].superseded_by.is_none());
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = 'opinion.set'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 2, "every opinion set is audited");

    // malicious_verdict trigger rows queued by both opinion sets
    let outbox_verdict: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM trigger_outbox o JOIN trigger_rule r ON r.id = o.trigger_id
         WHERE o.tenant_id = $1 AND r.condition = 'malicious_verdict'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox_verdict, 0, "no triggers yet");

    // ===== 4. triggers: hunt_match with HMAC-verified delivery =====
    let secret = "test-webhook-secret".to_string();
    let hook = start_verified_webhook(&secret, 2);
    let (row, _) = triggers::create_trigger(
        &pool,
        tenant_id,
        "match-hook",
        triggers::CONDITION_HUNT_MATCH,
        &hook.base,
        Some(secret.clone()),
    )
    .await
    .unwrap();
    assert!(row.enabled);

    // verdict trigger too, to assert opinion-set firing
    triggers::create_trigger(
        &pool,
        tenant_id,
        "verdict-hook",
        triggers::CONDITION_MALICIOUS_VERDICT,
        &hook.base,
        Some(secret.clone()),
    )
    .await
    .unwrap();
    opinions::set_opinion(
        &pool,
        tenant_id,
        cand,
        "suspicious",
        "analyst-2",
        "near bad seed",
    )
    .await
    .unwrap();
    let outbox_verdict2: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM trigger_outbox o JOIN trigger_rule r ON r.id = o.trigger_id
         WHERE o.tenant_id = $1 AND r.condition = 'malicious_verdict'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        outbox_verdict2, 1,
        "suspicious opinion fires verdict trigger"
    );

    // Hunt that matches the seed.
    let rule = corpus_core::registry::create_rule(
        &pool,
        tenant_id,
        r#"rule AnalystMarker { strings: $m = "CORPUS_ANALYST_MARKER" condition: $m }"#,
    )
    .await
    .unwrap();
    let bundle = corpus_core::registry::publish_bundle(&pool, tenant_id, &[rule.id], false)
        .await
        .unwrap();
    let hunt = corpus_core::hunts::create_hunt(&pool, tenant_id, &bundle.digest)
        .await
        .unwrap();
    let hunt = corpus_core::hunts::run_hunt(&pool, &cas, tenant_id, hunt.id)
        .await
        .unwrap();
    assert_eq!(hunt.matched, 1);

    let delivered = triggers::deliver_pending(&pool).await.unwrap();
    assert!(delivered >= 1);
    let events = hook.received.lock().unwrap().clone();
    assert!(!events.is_empty(), "webhook received deliveries");
    assert!(
        events.iter().all(|(_, valid)| *valid),
        "every delivery carries a valid HMAC signature"
    );
    let types: Vec<&str> = events
        .iter()
        .filter_map(|(e, _)| e["type"].as_str())
        .collect();
    assert!(
        types.contains(&"hunt_match"),
        "hunt match event delivered: {types:?}"
    );
    assert!(
        types.contains(&"malicious_verdict"),
        "verdict event delivered: {types:?}"
    );

    // ===== 5. dropper hunt =====
    let droppers = analyst::dropper_candidates(&pool, tenant_id, &sha_seed, 3, 24, 50)
        .await
        .unwrap();
    let dshas: Vec<&str> = droppers.iter().map(|d| d.sha256.as_str()).collect();
    assert!(
        dshas.contains(&sha_cand.as_str()),
        "near-in-time rare file is a candidate"
    );
    assert!(
        !dshas.contains(&sha_common.as_str()),
        "common file excluded (prevalence)"
    );
    let old_sha = hash::sha256_hex(b"old library bytes");
    assert!(
        !dshas.contains(&old_sha.as_str()),
        "out-of-window file excluded"
    );
    let cand_hit = droppers.iter().find(|d| d.sha256 == sha_cand).unwrap();
    assert_eq!(cand_hit.host_name, "host1");
    assert_eq!(cand_hit.host_count, 1);
    assert_eq!(cand_hit.min_time_delta_secs, 3600);

    // ===== 6. proof of absence =====
    let br = report::by_sha256(&pool, tenant_id, &"00".repeat(32), false)
        .await
        .unwrap();
    let att = br.attestation.expect("no-match report carries attestation");
    assert_eq!(att.result, "no_match");
    assert_eq!(att.scope, "endpoint");
    assert_eq!(
        att.artifacts_evaluated, 4,
        "all four endpoint artifacts evaluated"
    );
    assert!(att.corpus_watermark >= 4);
    assert!(br.artifacts.is_empty());

    // Hunt-scoped attestation uses the hunt's own watermark.
    let miss_rule = corpus_core::registry::create_rule(
        &pool,
        tenant_id,
        r#"rule NoSuchMarker { strings: $m = "DEFINITELY-NOT-PRESENT-STRING-XYZ" condition: $m }"#,
    )
    .await
    .unwrap();
    let miss_bundle =
        corpus_core::registry::publish_bundle(&pool, tenant_id, &[miss_rule.id], false)
            .await
            .unwrap();
    let miss_hunt = corpus_core::hunts::create_hunt(&pool, tenant_id, &miss_bundle.digest)
        .await
        .unwrap();
    let miss_hunt = corpus_core::hunts::run_hunt(&pool, &cas, tenant_id, miss_hunt.id)
        .await
        .unwrap();
    assert_eq!(miss_hunt.matched, 0);
    let br2 = report::by_hunt(&pool, tenant_id, miss_hunt.id, false)
        .await
        .unwrap();
    let att2 = br2.attestation.expect("empty hunt carries attestation");
    assert_eq!(att2.artifacts_evaluated, miss_hunt.planned_artifacts);

    // ===== 7. intel scope stays out of rarity/hunts =====
    let _intel_fin = ingest::finalize(&pool, &cas, tenant_id, &{
        let sha = hash::sha256_hex(b"intel scoped bytes");
        let ann = ingest::announce(
            &pool,
            tenant_id,
            &AnnounceRequest {
                sha256: sha.clone(),
                size_bytes: 18,
                occurrence: None,
            },
        )
        .await
        .unwrap();
        let upload_id = ann.upload_id.unwrap();
        ingest::stage_upload(&pool, &cas, tenant_id, upload_id, b"intel scoped bytes")
            .await
            .unwrap();
        FinalizeRequest {
            upload_id,
            sha256: sha,
            size_bytes: 18,
            occurrence: None,
            scope: Some("intel".into()),
            provenance: Some(serde_json::json!({"source": "test"})),
        }
    })
    .await
    .unwrap();
    let hits2 = analyst::rarity_search(
        &pool,
        tenant_id,
        10,
        t0 - chrono::Duration::days(3),
        None,
        50,
    )
    .await
    .unwrap();
    assert!(
        hits2
            .iter()
            .all(|h| h.sha256 != hash::sha256_hex(b"intel scoped bytes")),
        "intel scope excluded from rarity search"
    );
}
