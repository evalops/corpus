//! Integration test for the M3a similarity pipeline against real
//! PostgreSQL. Gated on CORPUS_TEST_DATABASE_URL; no-op without it.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::similarity::edges;
use corpus_core::similarity::model::edge_type;
use corpus_core::similarity::testutil::build_pe;
use corpus_core::{db, hash, ingest, report, tenant};
use uuid::Uuid;

fn occ(agent: Uuid, boot: Uuid, seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "sim-test-host".into(),
        agent_id: agent,
        boot_id: boot,
        agent_sequence: seq,
        path: path.into(),
        observed_at: chrono::Utc::now(),
        file_size: size,
        file_mtime: None,
        capture_reason: "cli_import".into(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn commit(
    pool: &sqlx::PgPool,
    cas: &FsCas,
    tenant_id: Uuid,
    agent: Uuid,
    boot: Uuid,
    seq: i64,
    path: &str,
    bytes: &[u8],
) -> (Uuid, String) {
    let sha = hash::sha256_hex(bytes);
    let ann = ingest::announce(pool, tenant_id, &AnnounceRequest {
        sha256: sha.clone(),
        size_bytes: bytes.len() as i64,
        occurrence: occ(agent, boot, seq, path, bytes.len() as i64),
    })
    .await
    .unwrap();
    let upload_id = ann.upload_id.expect("fresh artifact must require upload");
    ingest::stage_upload(pool, cas, tenant_id, upload_id, bytes).await.unwrap();
    let fin = ingest::finalize(pool, cas, tenant_id, &FinalizeRequest {
        upload_id,
        sha256: sha.clone(),
        size_bytes: bytes.len() as i64,
        occurrence: occ(agent, boot, seq, path, bytes.len() as i64),
    })
    .await
    .unwrap();
    (fin.artifact_id, sha)
}

fn edge_between<'a>(
    edges: &'a [corpus_core::dto::SimilarEdgeView],
    other: &str,
    etype: &str,
) -> Option<&'a corpus_core::dto::SimilarEdgeView> {
    edges.iter().find(|e| e.other_sha256 == other && e.edge_type == etype)
}

#[tokio::test]
async fn similarity_pipeline_end_to_end() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("sim-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Similarity test").await.unwrap();
    let agent = Uuid::new_v4();
    let boot = Uuid::new_v4();

    // A and B: same PE imports, different bodies -> normalized_equivalent.
    let pe_a = build_pe("KERNEL32.dll", "ExitProcess", b"body-variant-one", 0, None);
    let pe_b = build_pe("KERNEL32.dll", "ExitProcess", b"body-variant-two!!", 0, None);
    // C: different imports -> isolated.
    let pe_c = build_pe("USER32.dll", "MessageBoxA", b"body-variant-one", 0, None);
    // D and E: large near-identical blobs -> byte_similar weak lead only.
    let mut blob_d = vec![0u8; 8192];
    for (i, b) in blob_d.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut blob_e = blob_d.clone();
    blob_e[1000] ^= 0xff;
    blob_e[5000] ^= 0xff;

    let (a, sha_a) = commit(&pool, &cas, tenant_id, agent, boot, 1, "/w/a.exe", &pe_a).await;
    let (b, sha_b) = commit(&pool, &cas, tenant_id, agent, boot, 2, "/w/b.exe", &pe_b).await;
    let (c, sha_c) = commit(&pool, &cas, tenant_id, agent, boot, 3, "/w/c.exe", &pe_c).await;
    let (_d, sha_d) = commit(&pool, &cas, tenant_id, agent, boot, 4, "/w/d.bin", &blob_d).await;
    let (_e, sha_e) = commit(&pool, &cas, tenant_id, agent, boot, 5, "/w/e.bin", &blob_e).await;

    // --- edges from A's perspective
    let sim_a = edges::similar_view(&pool, tenant_id, &sha_a).await.unwrap().unwrap();
    let norm = edge_between(&sim_a.edges, &sha_b, edge_type::NORMALIZED_EQUIVALENT).expect("A<->B normalized edge");
    assert_eq!(norm.model_version, corpus_core::similarity::model::MODEL_VERSION);
    assert_eq!(norm.evidence["matched_feature"], "imphash");
    assert!(edge_between(&sim_a.edges, &sha_c, edge_type::NORMALIZED_EQUIVALENT).is_none(), "C has different imports");

    // --- variant groups: A and B together, C alone
    let var_a = edges::variants_view(&pool, tenant_id, &sha_a).await.unwrap().unwrap();
    let members: Vec<&str> = var_a.members.iter().map(|m| m.sha256.as_str()).collect();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&sha_a.as_str()) && members.contains(&sha_b.as_str()));
    let var_c = edges::variants_view(&pool, tenant_id, &sha_c).await.unwrap().unwrap();
    assert!(var_c.members.is_empty(), "C must not be grouped");

    // --- weak fuzzy edge D<->E, and it must NOT merge a group
    let sim_d = edges::similar_view(&pool, tenant_id, &sha_d).await.unwrap().unwrap();
    let weak = edge_between(&sim_d.edges, &sha_e, edge_type::BYTE_SIMILAR).expect("D<->E byte_similar edge");
    assert!(weak.score >= 40.0, "near-identical blobs score high, got {}", weak.score);
    assert!(weak.evidence["note"].as_str().unwrap().contains("never merges"));
    let var_d = edges::variants_view(&pool, tenant_id, &sha_d).await.unwrap().unwrap();
    assert!(var_d.members.is_empty(), "fuzzy alone never merges groups (28.5)");

    // --- group merge determinism: re-analyze (backfill path) must not
    // duplicate edges or split groups.
    let count_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM similarity_edge WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let _ = edges::analyze_artifact(&pool, tenant_id, a, "pe", &pe_a).await.unwrap();
    let _ = edges::analyze_artifact(&pool, tenant_id, b, "pe", &pe_b).await.unwrap();
    let var_a2 = edges::variants_view(&pool, tenant_id, &sha_a).await.unwrap().unwrap();
    assert_eq!(var_a2.members.len(), 2);
    let count_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM similarity_edge WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count_after, count_before, "re-analysis is idempotent");

    // --- blast radius with variant expansion
    let br = report::by_sha256(&pool, tenant_id, &sha_a, true).await.unwrap();
    let expansion = br.variant_expansion.expect("expansion present");
    assert!(
        expansion.group_artifacts.iter().any(|g| g.sha256 == sha_b),
        "expansion includes B as group member"
    );
    assert!(
        expansion.group_occurrences.iter().any(|o| o.artifact_sha256 == sha_b),
        "expansion includes B's occurrences"
    );

    // Weak neighbors labeled as leads, not members.
    let br_d = report::by_sha256(&pool, tenant_id, &sha_d, true).await.unwrap();
    let exp_d = br_d.variant_expansion.unwrap();
    assert!(exp_d.group_artifacts.is_empty(), "weak edges do not expand groups");
    let lead = exp_d.weak_leads.iter().find(|l| l.other_sha256 == sha_e).expect("weak lead E");
    assert_eq!(lead.edge_type, edge_type::BYTE_SIMILAR);

    // Without the flag there is no expansion.
    let br_plain = report::by_sha256(&pool, tenant_id, &sha_a, false).await.unwrap();
    assert!(br_plain.variant_expansion.is_none());

    // --- tenant isolation: nothing leaks to another tenant
    let other = Uuid::new_v4();
    let oslug = format!("sim-{}", &other.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, other, &oslug, "Other").await.unwrap();
    assert!(edges::similar_view(&pool, other, &sha_a).await.unwrap().is_none());
    let occ_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM similarity_edge WHERE tenant_id = $1",
    )
    .bind(other)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(occ_count, 0);

    // `c` sanity: used (different imports check above).
    let _ = c;
}
