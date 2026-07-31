//! Semantic variant matching (spec 16.4/16.5): per-function signature
//! storage, candidate scoring, bidirectional weighted coverage, and
//! strong/weak edge emission. See docs/semantic-similarity-design.md.

use crate::error::Error;
use crate::error::Result;
use crate::semantic::extract::functions_for;
use crate::semantic::features::{features_for, is_significant, jaccard, MATCH_TAU};
use crate::similarity::model::{edge_type, MODEL_VERSION};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub const SEMANTIC_EXTRACTOR_VERSION: &str = "semantic:v1";
pub const PACKED_ENTROPY_LIMIT: f64 = 7.2;

#[derive(Clone)]
pub struct FunctionRow {
    pub offset: u64,
    pub size: usize,
    pub name: Option<String>,
    pub insn_count: usize,
    pub token_hashes: Vec<u64>,
}

/// Extract, filter, and persist function signatures for one artifact.
/// Returns (significant rows, limitation if any).
pub async fn extract_and_store(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    format: &str,
    bytes: &[u8],
) -> Result<(Vec<FunctionRow>, Option<String>)> {
    let mut significant = Vec::new();
    let mut total_functions = 0usize;

    for (code, spans) in functions_for(format, bytes) {
        if code.entropy > PACKED_ENTROPY_LIMIT {
            let limitation = format!(
                "packed_or_high_entropy_code: entropy {:.2} > {}",
                code.entropy, PACKED_ENTROPY_LIMIT
            );
            store_limitation(pool, tenant, artifact, &limitation).await?;
            return Ok((Vec::new(), Some(limitation)));
        }
        for span in &spans {
            total_functions += 1;
            let end = (span.offset + span.size).min(code.bytes.len());
            let f = features_for(&code.bytes[span.offset..end], span.file_offset);
            if !is_significant(&f) {
                continue;
            }
            significant.push(FunctionRow {
                offset: span.file_offset,
                size: span.size,
                name: span.name.clone(),
                insn_count: f.insn_count,
                token_hashes: f.token_hashes,
            });
        }
    }

    // Persist per-function rows (idempotent re-analysis). sig stores the
    // packed sorted token hashes (8 bytes each) used by Jaccard scoring.
    for f in &significant {
        let packed: Vec<u8> = f
            .token_hashes
            .iter()
            .flat_map(|h| h.to_le_bytes())
            .collect();
        sqlx::query(
            "INSERT INTO similarity_function (tenant_id, artifact_id, func_offset, func_size, name, insn_count, sig, version, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (tenant_id, artifact_id, func_offset, version) DO NOTHING",
        )
        .bind(tenant)
        .bind(artifact)
        .bind(f.offset as i64)
        .bind(f.size as i64)
        .bind(&f.name)
        .bind(f.insn_count as i64)
        .bind(&packed)
        .bind(SEMANTIC_EXTRACTOR_VERSION)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    }

    // Aggregate feature row in the semantic schema slot (spec 16.2).
    sqlx::query(
        "INSERT INTO similarity_feature (tenant_id, artifact_id, family, name, version, value, created_at)
         VALUES ($1,$2,'semantic','aggregate',$3,$4,$5)
         ON CONFLICT (tenant_id, artifact_id, family, name, version) DO NOTHING",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(SEMANTIC_EXTRACTOR_VERSION)
    .bind(serde_json::json!({
        "function_count": total_functions,
        "significant_count": significant.len(),
    }))
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok((significant, None))
}

async fn store_limitation(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    limitation: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO similarity_feature (tenant_id, artifact_id, family, name, version, value, created_at)
         VALUES ($1,$2,'semantic','analysis_limitation',$3,$4,$5)
         ON CONFLICT (tenant_id, artifact_id, family, name, version) DO NOTHING",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(SEMANTIC_EXTRACTOR_VERSION)
    .bind(serde_json::json!({"value": limitation}))
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PairScore {
    pub a_offset: u64,
    pub b_offset: u64,
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct Coverage {
    pub a_to_b: f64,
    pub b_to_a: f64,
    pub matched_pairs: usize,
    pub top_pairs: Vec<PairScore>,
}

/// Bidirectional weighted coverage between two function sets (spec 16.5
/// step 4: a small loader cannot match a large benign program).
pub fn coverage(a: &[FunctionRow], b: &[FunctionRow]) -> Coverage {
    let mut a_matched = 0usize;
    let mut top: Vec<PairScore> = Vec::new();
    for fa in a {
        let best = b
            .iter()
            .map(|fb| (fb, jaccard(&fa.token_hashes, &fb.token_hashes)))
            .max_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal));
        if let Some((fb, score)) = best {
            if score >= MATCH_TAU {
                a_matched += 1;
                top.push(PairScore {
                    a_offset: fa.offset,
                    b_offset: fb.offset,
                    score,
                });
            }
        }
    }
    let mut b_matched = 0usize;
    for fb in b {
        let best = a
            .iter()
            .map(|fa| jaccard(&fa.token_hashes, &fb.token_hashes))
            .max_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(score) = best {
            if score >= MATCH_TAU {
                b_matched += 1;
            }
        }
    }
    top.sort_by(|x, y| {
        y.score
            .partial_cmp(&x.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    top.truncate(5);
    Coverage {
        a_to_b: if a.is_empty() {
            0.0
        } else {
            a_matched as f64 / a.len() as f64
        },
        b_to_a: if b.is_empty() {
            0.0
        } else {
            b_matched as f64 / b.len() as f64
        },
        matched_pairs: a_matched,
        top_pairs: top,
    }
}

/// Full semantic pass for one newly analyzed artifact: extract functions,
/// then score against every other artifact in the tenant that has stored
/// function signatures for the same class. Returns edges inserted.
pub async fn analyze_and_link(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    artifact_class: &str,
    bytes: &[u8],
) -> Result<usize> {
    let format = match artifact_class {
        "pe" | "elf" | "macho" => artifact_class,
        _ => return Ok(0),
    };
    let (functions, limitation) = extract_and_store(pool, tenant, artifact, format, bytes).await?;
    if limitation.is_some() || functions.is_empty() {
        return Ok(0);
    }

    let others: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT artifact_id FROM similarity_function
         WHERE tenant_id = $1 AND artifact_id != $2 AND version = $3",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(SEMANTIC_EXTRACTOR_VERSION)
    .fetch_all(pool)
    .await?;

    let mut edges = 0;
    for (other,) in others {
        // Class compatibility check (16.4: compatible format/arch).
        let other_class: Option<(String,)> =
            sqlx::query_as("SELECT artifact_class FROM artifact WHERE tenant_id = $1 AND id = $2")
                .bind(tenant)
                .bind(other)
                .fetch_optional(pool)
                .await?;
        if other_class.map(|c| c.0) != Some(artifact_class.to_string()) {
            continue;
        }
        #[derive(sqlx::FromRow)]
        struct FnRow {
            func_offset: i64,
            func_size: i64,
            name: Option<String>,
            insn_count: i64,
            sig: Vec<u8>,
        }
        let rows: Vec<FnRow> = sqlx::query_as(
            "SELECT func_offset, func_size, name, insn_count, sig FROM similarity_function
             WHERE tenant_id = $1 AND artifact_id = $2 AND version = $3",
        )
        .bind(tenant)
        .bind(other)
        .bind(SEMANTIC_EXTRACTOR_VERSION)
        .fetch_all(pool)
        .await?;
        let other_funcs: Vec<FunctionRow> = rows
            .into_iter()
            .map(|r| {
                let token_hashes: Vec<u64> = r
                    .sig
                    .chunks_exact(8)
                    .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                    .collect();
                FunctionRow {
                    offset: r.func_offset as u64,
                    size: r.func_size as usize,
                    name: r.name,
                    insn_count: r.insn_count as usize,
                    token_hashes,
                }
            })
            .collect();
        let cov = coverage(&functions, &other_funcs);
        let etype = if cov.a_to_b >= 0.60 && cov.b_to_a >= 0.60 && cov.matched_pairs >= 3 {
            Some(edge_type::SEMANTIC_STRONG)
        } else if cov.a_to_b >= 0.35 && cov.b_to_a >= 0.35 {
            Some(edge_type::SEMANTIC_WEAK)
        } else {
            None
        };
        let Some(etype) = etype else { continue };
        let evidence = serde_json::json!({
            "coverage_a_to_b": cov.a_to_b,
            "coverage_b_to_a": cov.b_to_a,
            "matched_pairs": cov.matched_pairs,
            "top_pairs": cov.top_pairs.iter().map(|p| serde_json::json!({
                "a_offset": p.a_offset, "b_offset": p.b_offset, "score": p.score,
            })).collect::<Vec<_>>(),
            "tau": MATCH_TAU,
        });
        let score = (cov.a_to_b + cov.b_to_a) / 2.0;
        if insert_edge(pool, tenant, artifact, other, etype, score, evidence).await? {
            edges += 1;
        }
    }
    Ok(edges)
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
    if inserted.is_some() && crate::similarity::model::merges_groups(etype) {
        crate::similarity::edges::union_groups(pool, tenant, src, dst).await?;
    }
    Ok(inserted.is_some())
}

pub fn unsupported_format_err(format: &str) -> Error {
    Error::BadRequest(format!("semantic analysis unsupported for {format}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::features::features_for;

    fn row(offset: u64, code: &[u8]) -> FunctionRow {
        let f = features_for(code, offset);
        FunctionRow {
            offset,
            size: code.len(),
            name: None,
            insn_count: f.insn_count,
            token_hashes: f.token_hashes,
        }
    }

    fn row_tokens(offset: u64, hashes: &[u64]) -> FunctionRow {
        FunctionRow {
            offset,
            size: 0,
            name: None,
            insn_count: 10,
            token_hashes: hashes.to_vec(),
        }
    }

    const FA: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x89, 0xd1, 0x01, 0xca, 0x89, 0xc8, 0x5d, 0xc3,
    ];
    const FA2: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x89, 0xd1, 0x29, 0xca, 0x89, 0xc8, 0x5d, 0xc3,
    ];
    const FB: &[u8] = &[
        0x48, 0x83, 0xec, 0x08, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x08, 0xc3,
    ];

    fn funcset(codes: &[&[u8]]) -> Vec<FunctionRow> {
        codes
            .iter()
            .enumerate()
            .map(|(i, c)| row((i * 0x40) as u64, c))
            .collect()
    }

    #[test]
    fn identical_sets_full_coverage() {
        let a = funcset(&[FA, FA2, FB, FA, FA2, FA]);
        let b = funcset(&[FA, FA2, FB, FA, FA2, FA]);
        let cov = coverage(&a, &b);
        assert_eq!(cov.a_to_b, 1.0);
        assert_eq!(cov.b_to_a, 1.0);
        assert_eq!(cov.matched_pairs, 6);
    }

    #[test]
    fn asymmetric_sets_bidirectional_differs() {
        // Small A fully inside large B: A→B is high, B→A is diluted by
        // B's unrelated functions (spec 16.5 step 4). Synthetic token
        // sets test the coverage math directly.
        let a = vec![
            row_tokens(0, &[1, 2, 3, 4, 5, 6, 7, 8]),
            row_tokens(0x40, &[10, 20, 30, 40, 50, 60]),
            row_tokens(0x80, &[100, 200, 300, 400, 500]),
        ];
        let mut b = a.clone();
        b.extend([
            row_tokens(0x100, &[1_000, 2_000, 3_000, 4_000, 5_000]),
            row_tokens(0x140, &[6_000, 7_000, 8_000, 9_000]),
            row_tokens(0x180, &[10_000, 20_000, 30_000]),
        ]);
        let cov = coverage(&a, &b);
        assert_eq!(cov.a_to_b, 1.0, "every A function finds a match in B");
        assert_eq!(cov.b_to_a, 0.5, "only half of B's functions match back");
    }
}
