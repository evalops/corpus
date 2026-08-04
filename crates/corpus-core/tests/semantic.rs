//! Integration tests for semantic extract, match, and edge emission.
//! Gated on `CORPUS_TEST_DATABASE_URL`.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::semantic::fixtures::{
    compile_fixture, BASE_SOURCE, TWEAK_SOURCE, UNRELATED_SOURCE,
};
use corpus_core::similarity::edges;
use corpus_core::similarity::model::edge_type;
use corpus_core::{db, hash, ingest, tenant};
use uuid::Uuid;

fn occ(seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "sem-test-host".into(),
        agent_id: Uuid::new_v4(),
        boot_id: Uuid::new_v4(),
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
    seq: i64,
    path: &str,
    bytes: &[u8],
) -> String {
    let sha = hash::sha256_hex(bytes);
    let ann = ingest::announce(
        pool,
        tenant_id,
        &AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(seq, path, bytes.len() as i64)),
        },
    )
    .await
    .unwrap();
    let upload_id = ann.upload_id.expect("fresh bytes");
    ingest::stage_upload(pool, cas, tenant_id, upload_id, bytes)
        .await
        .unwrap();
    ingest::finalize(
        pool,
        cas,
        tenant_id,
        &FinalizeRequest {
            upload_id,
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(seq, path, bytes.len() as i64)),
            scope: None,
            provenance: None,
        },
    )
    .await
    .unwrap();
    sha
}

fn edge<'a>(
    edges: &'a [corpus_core::dto::SimilarEdgeView],
    other: &str,
    etype: &str,
) -> Option<&'a corpus_core::dto::SimilarEdgeView> {
    edges
        .iter()
        .find(|e| e.other_sha256 == other && e.edge_type == etype)
}

#[tokio::test]
async fn semantic_opt_level_invariance_and_tweak() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("sem-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Semantic test")
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let fixtures = [
        ("base_O0", BASE_SOURCE, "-O0"),
        ("base_O2", BASE_SOURCE, "-O2"),
        ("base_Os", BASE_SOURCE, "-Os"),
        ("tweak_O2", TWEAK_SOURCE, "-O2"),
        ("unrel_O2", UNRELATED_SOURCE, "-O2"),
    ];
    let mut shas = std::collections::HashMap::new();
    for (i, (name, src, opt)) in fixtures.iter().enumerate() {
        if !compile_fixture(dir.path(), name, src, opt) {
            eprintln!("cc unavailable or target unsupported; skipping semantic corpus test");
            return;
        }
        let bytes = std::fs::read(dir.path().join(name)).unwrap();
        let sha = commit(
            &pool,
            &cas,
            tenant_id,
            i as i64 + 1,
            &format!("/w/{name}"),
            &bytes,
        )
        .await;
        shas.insert(*name, sha);
    }

    // SAME source, different opt levels: strong semantic edge + shared group.
    let sim_o0 = edges::similar_view(&pool, tenant_id, &shas["base_O0"])
        .await
        .unwrap()
        .unwrap();
    let strong = edge(&sim_o0.edges, &shas["base_O2"], edge_type::SEMANTIC_STRONG);
    let Some(strong) = strong else {
        panic!(
            "expected strong semantic edge O0<->O2, got: {:?}",
            sim_o0
                .edges
                .iter()
                .map(|e| (e.edge_type.clone(), e.score))
                .collect::<Vec<_>>()
        );
    };
    assert!(
        strong.evidence["matched_pairs"].as_i64().unwrap() >= 3,
        "evidence lists matched function pairs"
    );
    assert!(
        strong.evidence["top_pairs"].as_array().unwrap().len() >= 2,
        "top function pairs in evidence"
    );

    let var = edges::variants_view(&pool, tenant_id, &shas["base_O0"])
        .await
        .unwrap()
        .unwrap();
    let members: Vec<&str> = var.members.iter().map(|m| m.sha256.as_str()).collect();
    assert!(
        members.contains(&shas["base_O2"].as_str()),
        "O0 and O2 share a variant group"
    );
    assert!(
        members.contains(&shas["base_Os"].as_str()),
        "Os joins the same variant group"
    );

    // Tweak: edge present (strong or weak) with real evidence; NOT identical coverage.
    let strong_or_weak = edge(&sim_o0.edges, &shas["tweak_O2"], edge_type::SEMANTIC_STRONG)
        .or_else(|| edge(&sim_o0.edges, &shas["tweak_O2"], edge_type::SEMANTIC_WEAK));
    let Some(twe) = strong_or_weak else {
        panic!(
            "expected a semantic edge to the tweaked build: {:?}",
            sim_o0
                .edges
                .iter()
                .map(|e| (e.edge_type.clone(), e.score))
                .collect::<Vec<_>>()
        );
    };
    let scores: Vec<f64> = twe.evidence["top_pairs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["score"].as_f64())
        .collect();
    assert!(
        scores.iter().any(|s| *s < 1.0),
        "tweaked source matches with non-identical pair scores: {scores:?}"
    );

    // Unrelated: no semantic edge at all.
    assert!(edge(&sim_o0.edges, &shas["unrel_O2"], edge_type::SEMANTIC_STRONG).is_none());
    assert!(edge(&sim_o0.edges, &shas["unrel_O2"], edge_type::SEMANTIC_WEAK).is_none());
    let var_unrel = edges::variants_view(&pool, tenant_id, &shas["unrel_O2"])
        .await
        .unwrap()
        .unwrap();
    assert!(
        var_unrel.members.is_empty(),
        "unrelated binary stays isolated"
    );
}

#[tokio::test]
async fn packed_sample_records_limitation_not_edge() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("sem-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Semantic packed test")
        .await
        .unwrap();

    // An ELF whose .text is fully high-entropy (packed-looking).
    let mut seed = 0u32;
    let body: Vec<u8> = (0..4096)
        .map(|_| {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            (seed >> 24) as u8
        })
        .collect();
    let pe = corpus_core::similarity::testutil::build_elf_text(&body);
    let artifact = Uuid::new_v4();
    let (rows, limitation) =
        corpus_core::semantic::edges::extract_and_store(&pool, tenant_id, artifact, "elf", &pe)
            .await
            .unwrap();
    assert!(rows.is_empty());
    let Some(limitation) = limitation else {
        panic!("packed sample must record a limitation")
    };
    assert!(
        limitation.contains("entropy"),
        "limitation names entropy: {limitation}"
    );
    let lim: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT value FROM similarity_feature WHERE tenant_id = $1 AND artifact_id = $2 AND family = 'semantic' AND name = 'analysis_limitation'",
    )
    .bind(tenant_id)
    .bind(artifact)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        lim.is_some(),
        "limitation persisted as a feature row (16.7)"
    );
}
