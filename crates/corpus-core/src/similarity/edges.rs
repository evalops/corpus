//! Candidate generation, typed edge insertion, and variant-group
//! maintenance (spec 16.3, 16.4, 16.6).
//!
//! Scale note: byte-similar candidate scoring is brute-force over the
//! per-tenant corpus narrowed by format+size bucket (16.3 layers 1-2).
//! That is fine at M3 scale (tens of thousands of artifacts); the banded
//! LSH index is the documented follow-up when tenants outgrow it.

use crate::cas::FsCas;
use crate::error::Result;
use crate::similarity::extract::{self, ExtractedFeatures, EXTRACTOR_VERSION};
use crate::similarity::fuzzy;
use crate::similarity::model::{edge_type, merges_groups, MODEL_V1, MODEL_VERSION};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct EdgeRow {
    pub src_artifact: Uuid,
    pub dst_artifact: Uuid,
    pub edge_type: String,
    pub model_version: String,
    pub score: f64,
    pub evidence: serde_json::Value,
    pub created_at: chrono::DateTime<Utc>,
}

async fn store_features(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    f: &ExtractedFeatures,
) -> Result<()> {
    let mut rows: Vec<(&str, &str, serde_json::Value)> = vec![(
        "byte",
        "ssdeep",
        serde_json::json!({"digest": f.ssdeep, "size_bytes": f.size_bytes, "entropy": f.entropy}),
    )];
    for n in &f.normalized {
        rows.push(("normalized", &n.name, serde_json::json!({"hash": n.hash})));
    }
    if let Some(l) = &f.section_layout {
        rows.push((
            "structural",
            "section_layout",
            serde_json::json!({"hash": l}),
        ));
    }
    if let Some(l) = &f.import_set {
        rows.push(("structural", "import_set", serde_json::json!({"hash": l})));
    }
    if let Some(l) = &f.export_set {
        rows.push(("structural", "export_set", serde_json::json!({"hash": l})));
    }
    if let Some(c) = &f.compiler_hint {
        rows.push((
            "provenance",
            "compiler_hint",
            serde_json::json!({"value": c}),
        ));
    }
    if let Some(l) = &f.parse_limitation {
        rows.push((
            "structural",
            "parse_limitation",
            serde_json::json!({"value": l}),
        ));
    }
    for (family, name, value) in rows {
        sqlx::query(
            "INSERT INTO similarity_feature (tenant_id, artifact_id, family, name, version, value, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (tenant_id, artifact_id, family, name, version) DO NOTHING",
        )
        .bind(tenant)
        .bind(artifact)
        .bind(family)
        .bind(name)
        .bind(EXTRACTOR_VERSION)
        .bind(&value)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn insert_edge(
    pool: &PgPool,
    tenant: Uuid,
    a: Uuid,
    b: Uuid,
    etype: &str,
    score: f64,
    evidence: serde_json::Value,
) -> Result<bool> {
    let (src, dst) = if a < b { (a, b) } else { (b, a) };
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO similarity_edge (tenant_id, src_artifact, dst_artifact, edge_type, model_version, score, evidence, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (tenant_id, src_artifact, dst_artifact, edge_type, model_version) DO NOTHING
         RETURNING src_artifact",
    )
    .bind(tenant)
    .bind(src)
    .bind(dst)
    .bind(etype)
    .bind(MODEL_VERSION)
    .bind(score)
    .bind(&evidence)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    if inserted.is_some() && merges_groups(etype) {
        union_groups(pool, tenant, src, dst).await?;
    }
    Ok(inserted.is_some())
}

async fn group_of(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT group_id FROM variant_group_member WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_optional(pool)
    .await?)
}

async fn add_member(pool: &PgPool, tenant: Uuid, group: Uuid, artifact: Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO variant_group_member (tenant_id, group_id, artifact_id) VALUES ($1,$2,$3)
         ON CONFLICT (tenant_id, artifact_id) DO NOTHING",
    )
    .bind(tenant)
    .bind(group)
    .bind(artifact)
    .execute(pool)
    .await?;
    Ok(())
}

/// Union the groups of two artifacts linked by a strong edge. Deterministic:
/// the merged component keeps the smaller group id regardless of insertion
/// order (spec 16.6 connected components).
pub async fn union_groups(pool: &PgPool, tenant: Uuid, a: Uuid, b: Uuid) -> Result<()> {
    let (ga, gb) = (
        group_of(pool, tenant, a).await?,
        group_of(pool, tenant, b).await?,
    );
    match (ga, gb) {
        (Some(g1), Some(g2)) if g1 != g2 => {
            let (keep, drop_g) = (g1.min(g2), g1.max(g2));
            sqlx::query("UPDATE variant_group_member SET group_id = $3 WHERE tenant_id = $1 AND group_id = $2")
                .bind(tenant)
                .bind(drop_g)
                .bind(keep)
                .execute(pool)
                .await?;
            sqlx::query("DELETE FROM variant_group WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(drop_g)
                .execute(pool)
                .await?;
        }
        (Some(g), None) => {
            add_member(pool, tenant, g, b).await?;
            fire_variant_join(pool, tenant, g, b).await?;
        }
        (None, Some(g)) => {
            add_member(pool, tenant, g, a).await?;
            fire_variant_join(pool, tenant, g, a).await?;
        }
        (None, None) => {
            let g = Uuid::new_v4();
            sqlx::query("INSERT INTO variant_group (id, tenant_id, created_at) VALUES ($1,$2,$3)")
                .bind(g)
                .bind(tenant)
                .bind(Utc::now())
                .execute(pool)
                .await?;
            add_member(pool, tenant, g, a).await?;
            add_member(pool, tenant, g, b).await?;
        }
        _ => {}
    }
    Ok(())
}

/// Trigger event when an artifact joins an EXISTING variant group.
async fn fire_variant_join(pool: &PgPool, tenant: Uuid, group: Uuid, artifact: Uuid) -> Result<()> {
    crate::triggers::fire(
        pool,
        tenant,
        crate::triggers::CONDITION_VARIANT_JOIN,
        serde_json::json!({
            "type": "variant_join",
            "group_id": group,
            "artifact_id": artifact,
        }),
    )
    .await?;
    Ok(())
}

/// Full analysis for one committed artifact: extract + store features,
/// generate candidates, insert typed edges, maintain variant groups.
/// Idempotent; safe to re-run from backfill.
pub async fn analyze_artifact(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    artifact_class: &str,
    bytes: &[u8],
) -> Result<usize> {
    let f = extract::extract(bytes);
    store_features(pool, tenant, artifact, &f).await?;
    let mut edges = 0usize;

    // Layer 1: normalized hash index -> normalized_equivalent (strong).
    for n in &f.normalized {
        let candidates: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT artifact_id FROM similarity_feature
             WHERE tenant_id = $1 AND family = 'normalized' AND name = $2
               AND value->>'hash' = $3 AND artifact_id != $4",
        )
        .bind(tenant)
        .bind(&n.name)
        .bind(&n.hash)
        .bind(artifact)
        .fetch_all(pool)
        .await?;
        for (other,) in candidates {
            // Compatible format check via artifact_class of both sides.
            let other_class: Option<(String,)> = sqlx::query_as(
                "SELECT artifact_class FROM artifact WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant)
            .bind(other)
            .fetch_optional(pool)
            .await?;
            if other_class.map(|c| c.0) != Some(artifact_class.to_string()) {
                continue;
            }
            let evidence = serde_json::json!({
                "matched_feature": n.name, "hash": n.hash, "format": artifact_class,
            });
            if insert_edge(
                pool,
                tenant,
                artifact,
                other,
                edge_type::NORMALIZED_EQUIVALENT,
                1.0,
                evidence,
            )
            .await?
            {
                edges += 1;
            }
        }
    }

    // Layers 2+3: format/size bucket -> fuzzy nearest candidates (weak lead).
    let bucket: Vec<(Uuid, Vec<u8>, String, f64)> = sqlx::query_as(
        "SELECT a.id, a.sha256, sf.value->>'digest' AS digest,
                (sf.value->>'entropy')::float8 AS entropy
         FROM artifact a
         JOIN similarity_feature sf
           ON sf.tenant_id = a.tenant_id AND sf.artifact_id = a.id
          AND sf.family = 'byte' AND sf.name = 'ssdeep' AND sf.version = $4
         WHERE a.tenant_id = $1 AND a.artifact_class = $2 AND a.id != $3
           AND a.size_bytes > 0",
    )
    .bind(tenant)
    .bind(artifact_class)
    .bind(artifact)
    .bind(EXTRACTOR_VERSION)
    .fetch_all(pool)
    .await?;
    for (other, _sha, digest, entropy) in bucket {
        let other_size: i64 =
            sqlx::query_scalar("SELECT size_bytes FROM artifact WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(other)
                .fetch_one(pool)
                .await?;
        let ratio = (f.size_bytes.max(other_size as u64) as f64)
            / (f.size_bytes.min(other_size as u64).max(1) as f64);
        if ratio > MODEL_V1.size_ratio_max {
            continue;
        }
        let entropy_delta = (f.entropy - entropy).abs();
        let score = fuzzy::compare(&f.ssdeep, &digest);
        if score < MODEL_V1.byte_similar_min_score || entropy_delta > MODEL_V1.entropy_delta_max {
            continue;
        }
        let evidence = serde_json::json!({
            "ssdeep_score": score, "size_ratio": ratio, "entropy_delta": entropy_delta,
            "note": "weak lead; never merges variant groups",
        });
        if insert_edge(
            pool,
            tenant,
            artifact,
            other,
            edge_type::BYTE_SIMILAR,
            score as f64,
            evidence,
        )
        .await?
        {
            edges += 1;
        }
    }

    // Semantic (spec 16.2/16.5): function-level matching for x86-64.
    let _ = crate::semantic::edges::analyze_and_link(pool, tenant, artifact, artifact_class, bytes)
        .await?;

    // Provenance: shared compiler hint (context edge only).
    if let Some(hint) = &f.compiler_hint {
        let candidates: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT artifact_id FROM similarity_feature
             WHERE tenant_id = $1 AND family = 'provenance' AND name = 'compiler_hint'
               AND value->>'value' = $2 AND artifact_id != $3",
        )
        .bind(tenant)
        .bind(hint)
        .bind(artifact)
        .fetch_all(pool)
        .await?;
        for (other,) in candidates {
            let evidence = serde_json::json!({"compiler_hint": hint, "note": "context edge, never family proof"});
            if insert_edge(
                pool,
                tenant,
                artifact,
                other,
                edge_type::SHARED_PROVENANCE,
                1.0,
                evidence,
            )
            .await?
            {
                edges += 1;
            }
        }
    }

    Ok(edges)
}

/// Post-commit hook: analyze a newly committed artifact from its bytes.
pub async fn analyze_new_artifact(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    artifact_class: &str,
    bytes: &[u8],
) -> Result<usize> {
    analyze_artifact(pool, tenant, artifact, artifact_class, bytes).await
}

/// Backfill all committed artifacts in the tenant that have no features
/// for the current extractor version. Returns artifacts analyzed.
pub async fn backfill(pool: &PgPool, cas: &FsCas, tenant: Uuid) -> Result<usize> {
    let pending: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT a.id, a.artifact_class, a.object_key FROM artifact a
         WHERE a.tenant_id = $1 AND a.storage_state = 'committed'
           AND NOT EXISTS (
             SELECT 1 FROM similarity_feature sf
             WHERE sf.tenant_id = a.tenant_id AND sf.artifact_id = a.id AND sf.version = $2
           )
         ORDER BY a.seq",
    )
    .bind(tenant)
    .bind(EXTRACTOR_VERSION)
    .fetch_all(pool)
    .await?;
    let mut n = 0;
    for (artifact, class, key) in pending {
        let bytes = cas.read(&key)?;
        analyze_artifact(pool, tenant, artifact, &class, &bytes).await?;
        n += 1;
    }
    Ok(n)
}

/// All edges touching an artifact, with the other side's sha256.
pub async fn edges_for(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Vec<EdgeRow>> {
    let rows = sqlx::query_as::<_, EdgeRow>(
        "SELECT src_artifact, dst_artifact, edge_type, model_version, score, evidence, created_at
         FROM similarity_edge
         WHERE tenant_id = $1 AND (src_artifact = $2 OR dst_artifact = $2)
         ORDER BY edge_type, score DESC",
    )
    .bind(tenant)
    .bind(artifact)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Variant group members (strong-edge component) for an artifact.
pub async fn group_members(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
) -> Result<(Option<Uuid>, Vec<(Uuid, Vec<u8>)>)> {
    let group = group_of(pool, tenant, artifact).await?;
    let Some(g) = group else {
        return Ok((None, vec![]));
    };
    let members: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT m.artifact_id, a.sha256 FROM variant_group_member m
         JOIN artifact a ON a.tenant_id = m.tenant_id AND a.id = m.artifact_id
         WHERE m.tenant_id = $1 AND m.group_id = $2
         ORDER BY a.first_committed_at",
    )
    .bind(tenant)
    .bind(g)
    .fetch_all(pool)
    .await?;
    Ok((Some(g), members))
}

/// `corpusctl similar <sha256>` view: typed edges with component evidence.
pub async fn similar_view(
    pool: &PgPool,
    tenant: Uuid,
    sha256_hex: &str,
) -> Result<Option<crate::dto::SimilarResponse>> {
    let Ok(raw) = crate::hash::hex_to_raw(sha256_hex) else {
        return Ok(None);
    };
    let artifact: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant)
            .bind(&raw)
            .fetch_optional(pool)
            .await?;
    let Some((artifact,)) = artifact else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for e in edges_for(pool, tenant, artifact).await? {
        let other = if e.src_artifact == artifact {
            e.dst_artifact
        } else {
            e.src_artifact
        };
        let sha: Vec<u8> =
            sqlx::query_scalar("SELECT sha256 FROM artifact WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(other)
                .fetch_one(pool)
                .await?;
        out.push(crate::dto::SimilarEdgeView {
            other_artifact: other,
            other_sha256: hex::encode(sha),
            edge_type: e.edge_type,
            model_version: e.model_version,
            score: e.score,
            evidence: e.evidence,
        });
    }
    Ok(Some(crate::dto::SimilarResponse {
        artifact_id: artifact,
        sha256: sha256_hex.to_string(),
        edges: out,
    }))
}

/// `corpusctl variants <sha256>` view: strong-edge group members.
pub async fn variants_view(
    pool: &PgPool,
    tenant: Uuid,
    sha256_hex: &str,
) -> Result<Option<crate::dto::VariantsResponse>> {
    let Ok(raw) = crate::hash::hex_to_raw(sha256_hex) else {
        return Ok(None);
    };
    let artifact: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant)
            .bind(&raw)
            .fetch_optional(pool)
            .await?;
    let Some((artifact,)) = artifact else {
        return Ok(None);
    };
    let (group, members) = group_members(pool, tenant, artifact).await?;
    let mut out = Vec::new();
    for (id, sha) in members {
        let row: Option<(String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT artifact_class, first_committed_at FROM artifact WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(pool)
        .await?;
        if let Some((class, committed)) = row {
            out.push(crate::dto::VariantMember {
                artifact_id: id,
                sha256: hex::encode(sha),
                artifact_class: class,
                first_committed_at: committed,
            });
        }
    }
    Ok(Some(crate::dto::VariantsResponse {
        artifact_id: artifact,
        sha256: sha256_hex.to_string(),
        group_id: group,
        members: out,
    }))
}
