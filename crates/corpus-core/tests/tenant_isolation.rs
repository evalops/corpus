//! Tenant-isolation property tests for similarity and semantic indexes.
//! Gated on CORPUS_TEST_DATABASE_URL.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::semantic;
use corpus_core::similarity::edges;
use corpus_core::similarity::lsh;
use corpus_core::similarity::neighborhood::{self, NeighborhoodQuery};
use corpus_core::similarity::testutil::build_pe;
use corpus_core::{db, hash, ingest, tenant};
use uuid::Uuid;

fn occ(agent: Uuid, boot: Uuid, seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "iso-test-host".into(),
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

async fn commit(
    pool: &sqlx::PgPool,
    cas: &FsCas,
    tenant_id: Uuid,
    agent: Uuid,
    boot: Uuid,
    seq: i64,
    path: &str,
    bytes: &[u8],
) -> Uuid {
    let sha = hash::sha256_hex(bytes);
    let ann = ingest::announce(
        pool,
        tenant_id,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(agent, boot, seq, path, bytes.len() as i64)),
        },
    )
    .await
    .unwrap();
    let upload_id = ann.upload_id.expect("upload required");
    ingest::stage_upload(pool, cas, tenant_id, upload_id, bytes)
        .await
        .unwrap();
    let fin = ingest::finalize(
        pool,
        cas,
        tenant_id,
        &FinalizeRequest {
            upload_id,
            sha256: sha,
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(agent, boot, seq, path, bytes.len() as i64)),
            scope: None,
            provenance: None,
        },
    )
    .await
    .unwrap();
    fin.artifact_id
}

async fn make_tenant(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let slug = format!("{label}-{}", &id.simple().to_string()[..8]);
    tenant::ensure_tenant(pool, id, &slug, label).await.unwrap();
    id
}

#[tokio::test]
async fn identical_bytes_do_not_cross_tenants() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();

    let t1 = make_tenant(&pool, "iso-a").await;
    let t2 = make_tenant(&pool, "iso-b").await;
    let agent = Uuid::new_v4();
    let boot = Uuid::new_v4();

    // Identical PE bytes in both tenants.
    let pe = build_pe("KERNEL32.dll", "ExitProcess", b"shared-body-bytes!!", 0, None);
    let a1 = commit(&pool, &cas, t1, agent, boot, 1, "/t1/a.exe", &pe).await;
    let a2 = commit(&pool, &cas, t2, agent, boot, 1, "/t2/a.exe", &pe).await;

    // Analyze both.
    edges::analyze_artifact(&pool, t1, a1, "pe", &pe)
        .await
        .unwrap();
    edges::analyze_artifact(&pool, t2, a2, "pe", &pe)
        .await
        .unwrap();
    let _ = semantic::edges::analyze_and_link(&pool, t1, a1, "pe", &pe).await;
    let _ = semantic::edges::analyze_and_link(&pool, t2, a2, "pe", &pe).await;

    // Features scoped.
    let t1_feats: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_feature WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(t1)
    .bind(a2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t1_feats, 0, "tenant1 must not see tenant2 features");

    let t1_fns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_function WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(t1)
    .bind(a2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t1_fns, 0, "tenant1 must not see tenant2 functions");

    // Edges never cross tenants even with identical digests.
    let cross: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_edge
         WHERE (tenant_id = $1 AND (src_artifact = $2 OR dst_artifact = $2))
            OR (tenant_id = $2 AND (src_artifact = $1 OR dst_artifact = $1))",
    )
    .bind(t1)
    .bind(t2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cross, 0);

    // Cross-tenant edge query via ids: no edge between a1 and a2 under either tenant.
    let cross_pair: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_edge
         WHERE (src_artifact = $1 AND dst_artifact = $2)
            OR (src_artifact = $2 AND dst_artifact = $1)",
    )
    .bind(a1)
    .bind(a2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cross_pair, 0, "no edge may join artifacts of different tenants");

    // Neighborhood stays in-tenant.
    let sha = hash::sha256_hex(&pe);
    let nq = NeighborhoodQuery {
        seed: sha.clone(),
        edge_types: vec![],
        model_version: None,
        min_score: 0.0,
        max_depth: 2,
        max_nodes: 64,
        max_edges: 64,
        offset: 0,
        limit: 50,
        include_weak: true,
    };
    let nb = neighborhood::query(&pool, t1, &nq).await.unwrap();
    assert!(nb.nodes.iter().all(|n| n.artifact_id != a2));
    assert_eq!(nb.tenant_id, t1);

    // LSH bands are tenant-scoped: same ssdeep under two tenants must not
    // surface the other tenant's artifact as a candidate.
    let ssdeep = corpus_core::similarity::fuzzy::fuzzy_hash(&pe);
    let _ = lsh::store_bands(&pool, t1, a1, &ssdeep).await;
    let _ = lsh::store_bands(&pool, t2, a2, &ssdeep).await;
    let t1_bands: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT artifact_id FROM similarity_lsh_band WHERE tenant_id = $1",
    )
    .bind(t1)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();
    assert!(
        t1_bands.iter().all(|(id,)| *id != a2),
        "LSH bands must not leak tenant2 artifacts"
    );

    // Cleanup for this test's tenants (best-effort).
    for (t, a) in [(t1, a1), (t2, a2)] {
        let _ = corpus_core::similarity::lifecycle::cleanup_artifact(&pool, t, a, false).await;
    }
}
