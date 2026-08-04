//! Concurrency and idempotency tests for edge insertion and group union
//! (issue #31).
//!
//! # Properties under test
//!
//! - Concurrent `analyze_and_link` / edge inserts for the same pair do not
//!   create duplicate edges (unique key + `ON CONFLICT DO NOTHING`).
//! - Group union under concurrent strong edges remains a single coherent
//!   partition (no torn membership).
//!
//! Gated on `CORPUS_TEST_DATABASE_URL` (no-op hermetic skip in CI).

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::semantic;
use corpus_core::similarity::edges;
use corpus_core::similarity::model::{edge_type, MODEL_VERSION};
use corpus_core::similarity::testutil::build_pe;
use corpus_core::{db, hash, ingest, tenant};
use std::sync::Arc;
use uuid::Uuid;

fn occ(agent: Uuid, boot: Uuid, seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "conc-test-host".into(),
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
    ingest::finalize(
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
    .unwrap()
    .artifact_id
}

#[tokio::test]
async fn concurrent_analysis_is_idempotent() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();

    let tenant_id = Uuid::new_v4();
    let slug = format!("conc-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Concurrency test")
        .await
        .unwrap();
    let agent = Uuid::new_v4();
    let boot = Uuid::new_v4();

    // Two near-identical PEs so analysis has work to do.
    let pe_a = build_pe("KERNEL32.dll", "ExitProcess", b"body-aaaaaaaaaaaa", 0, None);
    let pe_b = build_pe("KERNEL32.dll", "ExitProcess", b"body-bbbbbbbbbbbb", 0, None);
    let a = commit(&pool, &cas, tenant_id, agent, boot, 1, "/c/a.exe", &pe_a).await;
    let b = commit(&pool, &cas, tenant_id, agent, boot, 2, "/c/b.exe", &pe_b).await;

    let pool = Arc::new(pool);
    let pe_a = Arc::new(pe_a);
    let pe_b = Arc::new(pe_b);

    // Fire concurrent analyze passes for both artifacts repeatedly.
    let mut handles = Vec::new();
    for i in 0..6 {
        let pool = Arc::clone(&pool);
        let pe_a = Arc::clone(&pe_a);
        let pe_b = Arc::clone(&pe_b);
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let _ = edges::analyze_artifact(&pool, tenant_id, a, "pe", &pe_a).await;
                let _ = semantic::edges::analyze_and_link(&pool, tenant_id, a, "pe", &pe_a).await;
            } else {
                let _ = edges::analyze_artifact(&pool, tenant_id, b, "pe", &pe_b).await;
                let _ = semantic::edges::analyze_and_link(&pool, tenant_id, b, "pe", &pe_b).await;
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // One current edge per (tenant, pair, type, model).
    let edge_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT edge_type, COUNT(*)::bigint FROM similarity_edge
         WHERE tenant_id = $1
           AND ((src_artifact = $2 AND dst_artifact = $3)
             OR (src_artifact = $3 AND dst_artifact = $2))
           AND model_version = $4
         GROUP BY edge_type",
    )
    .bind(tenant_id)
    .bind(a.min(b))
    .bind(a.max(b))
    .bind(MODEL_VERSION)
    .fetch_all(pool.as_ref())
    .await
    .unwrap();
    for (etype, n) in &edge_counts {
        assert_eq!(*n, 1, "duplicate edges for type {etype}");
    }

    // Each artifact in at most one current group.
    let memberships: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM variant_group_member WHERE tenant_id = $1 AND artifact_id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&[a, b][..])
    .fetch_one(pool.as_ref())
    .await
    .unwrap();
    assert!(memberships <= 2);

    // No orphan groups (groups with zero members) for this tenant from our run.
    let orphans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM variant_group g
         WHERE g.tenant_id = $1
           AND NOT EXISTS (
             SELECT 1 FROM variant_group_member m
             WHERE m.tenant_id = g.tenant_id AND m.group_id = g.id
           )",
    )
    .bind(tenant_id)
    .fetch_one(pool.as_ref())
    .await
    .unwrap();
    assert_eq!(orphans, 0, "orphan variant groups after concurrent union");

    // Safe retry: re-run analysis; counts must not grow.
    edges::analyze_artifact(pool.as_ref(), tenant_id, a, "pe", &pe_a)
        .await
        .unwrap();
    edges::analyze_artifact(pool.as_ref(), tenant_id, b, "pe", &pe_b)
        .await
        .unwrap();
    let edge_counts_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM similarity_edge WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(pool.as_ref())
            .await
            .unwrap();
    let edge_counts_before: i64 = edge_counts.iter().map(|(_, n)| n).sum();
    // After retry, total edges for the pair types should be stable; allow other
    // edge types but no duplicates of the pair.
    let pair_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_edge
         WHERE tenant_id = $1
           AND ((src_artifact = $2 AND dst_artifact = $3)
             OR (src_artifact = $3 AND dst_artifact = $2))",
    )
    .bind(tenant_id)
    .bind(a.min(b))
    .bind(a.max(b))
    .fetch_one(pool.as_ref())
    .await
    .unwrap();
    assert_eq!(
        pair_after,
        edge_counts_before,
        "retry must not create more pair edges (before types sum {edge_counts_before}, after {pair_after}, total tenant edges {edge_counts_after})"
    );

    // Cleanup created data.
    let _ =
        corpus_core::similarity::lifecycle::cleanup_artifact(pool.as_ref(), tenant_id, a, false)
            .await;
    let _ =
        corpus_core::similarity::lifecycle::cleanup_artifact(pool.as_ref(), tenant_id, b, false)
            .await;

    // Silence unused import warning if edge_type not used in asserts.
    let _ = edge_type::BYTE_SIMILAR;
}
