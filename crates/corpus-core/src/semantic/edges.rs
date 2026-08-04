//! Semantic variant matching (spec 16.4/16.5): per-function signature
//! storage, candidate scoring, one-to-one coverage, and strong/weak edge
//! emission. See docs/semantic-similarity-design.md.

use crate::error::Error;
use crate::error::Result;
use crate::semantic::extract::functions_for;
use crate::semantic::features::{features_for, is_significant, jaccard, MATCH_TAU};
use crate::similarity::analyzers;
use crate::similarity::model::{
    classify_semantic_edge, model_config_digest, MODEL_V1, MODEL_VERSION,
};
use crate::similarity::receipts::{self, AnalysisReceipt};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub const SEMANTIC_EXTRACTOR_VERSION: &str = "semantic:v1";
pub const PACKED_ENTROPY_LIMIT: f64 = MODEL_V1.packed_entropy_limit;

/// Schema version for explainable function-pair evidence responses.
pub const EVIDENCE_SCHEMA_VERSION: &str = "semantic-evidence:v1";

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
    /// Functions on A that had a candidate ≥ τ but lost the assignment.
    pub contested_a: Vec<u64>,
    /// Functions on B that had a candidate ≥ τ but lost the assignment.
    pub contested_b: Vec<u64>,
    /// Functions on A with no candidate ≥ τ.
    pub unmatched_a: Vec<u64>,
    /// Functions on B with no candidate ≥ τ.
    pub unmatched_b: Vec<u64>,
}

/// One-to-one bidirectional coverage (spec 16.5 step 4).
///
/// Candidate pairs with Jaccard ≥ τ are ranked by score (desc), then by
/// `(a_offset, b_offset)` for deterministic tie-breaking. Greedy assignment
/// ensures each function appears in at most one accepted pair.
pub fn coverage(a: &[FunctionRow], b: &[FunctionRow]) -> Coverage {
    coverage_with_tau(a, b, MATCH_TAU)
}

pub fn coverage_with_tau(a: &[FunctionRow], b: &[FunctionRow], tau: f64) -> Coverage {
    let mut candidates: Vec<(usize, usize, f64)> = Vec::new();
    for (i, fa) in a.iter().enumerate() {
        for (j, fb) in b.iter().enumerate() {
            let score = jaccard(&fa.token_hashes, &fb.token_hashes);
            if score >= tau {
                candidates.push((i, j, score));
            }
        }
    }
    // Deterministic order: score desc, then a_offset, then b_offset.
    candidates.sort_by(|x, y| {
        y.2.partial_cmp(&x.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a[x.0].offset.cmp(&a[y.0].offset))
            .then_with(|| b[x.1].offset.cmp(&b[y.1].offset))
    });

    let mut used_a = vec![false; a.len()];
    let mut used_b = vec![false; b.len()];
    let mut had_candidate_a = vec![false; a.len()];
    let mut had_candidate_b = vec![false; b.len()];
    for &(i, j, _) in &candidates {
        had_candidate_a[i] = true;
        had_candidate_b[j] = true;
    }

    let mut assigned: Vec<PairScore> = Vec::new();
    for (i, j, score) in candidates {
        if used_a[i] || used_b[j] {
            continue;
        }
        used_a[i] = true;
        used_b[j] = true;
        assigned.push(PairScore {
            a_offset: a[i].offset,
            b_offset: b[j].offset,
            score,
        });
    }

    let matched = assigned.len();
    let contested_a: Vec<u64> = a
        .iter()
        .enumerate()
        .filter(|(i, _)| had_candidate_a[*i] && !used_a[*i])
        .map(|(_, f)| f.offset)
        .collect();
    let contested_b: Vec<u64> = b
        .iter()
        .enumerate()
        .filter(|(j, _)| had_candidate_b[*j] && !used_b[*j])
        .map(|(_, f)| f.offset)
        .collect();
    let unmatched_a: Vec<u64> = a
        .iter()
        .enumerate()
        .filter(|(i, _)| !had_candidate_a[*i])
        .map(|(_, f)| f.offset)
        .collect();
    let unmatched_b: Vec<u64> = b
        .iter()
        .enumerate()
        .filter(|(j, _)| !had_candidate_b[*j])
        .map(|(_, f)| f.offset)
        .collect();

    let mut top = assigned;
    top.sort_by(|x, y| {
        y.score
            .partial_cmp(&x.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| x.a_offset.cmp(&y.a_offset))
            .then_with(|| x.b_offset.cmp(&y.b_offset))
    });
    top.truncate(5);

    Coverage {
        a_to_b: if a.is_empty() {
            0.0
        } else {
            matched as f64 / a.len() as f64
        },
        b_to_a: if b.is_empty() {
            0.0
        } else {
            matched as f64 / b.len() as f64
        },
        matched_pairs: matched,
        top_pairs: top,
        contested_a,
        contested_b,
        unmatched_a,
        unmatched_b,
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

    // Fail closed if the semantic analyzer was retired.
    let analyzer = analyzers::resolve("semantic-function", SEMANTIC_EXTRACTOR_VERSION)?;

    let started = Utc::now();
    let (functions, limitation) = extract_and_store(pool, tenant, artifact, format, bytes).await?;

    let receipt = AnalysisReceipt {
        tenant_id: tenant,
        artifact_id: artifact,
        analyzer_name: analyzer.name.to_string(),
        analyzer_version: analyzer.version.to_string(),
        model_version: MODEL_VERSION.to_string(),
        config_digest: analyzer.config_digest.clone(),
        input_sha256: crate::hash::sha256_hex(bytes),
        input_size_bytes: bytes.len() as u64,
        started_at: started,
        finished_at: Utc::now(),
        status: if limitation.is_some() {
            "limitation".into()
        } else if functions.is_empty() {
            "empty".into()
        } else {
            "ok".into()
        },
        limitation: limitation.clone(),
        function_count: functions.len(),
        edge_count: 0,
        metrics: serde_json::json!({
            "format": format,
            "architecture": "x86_64",
        }),
    };
    receipts::persist(pool, &receipt).await?;

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
        let other_funcs = load_functions(pool, tenant, other).await?;
        let cov = coverage(&functions, &other_funcs);
        let Some(etype) =
            classify_semantic_edge(&MODEL_V1, cov.a_to_b, cov.b_to_a, cov.matched_pairs)
        else {
            continue;
        };
        let evidence = build_edge_evidence(&cov, &receipt);
        let score = (cov.a_to_b + cov.b_to_a) / 2.0;
        if insert_edge(pool, tenant, artifact, other, etype, score, evidence).await? {
            edges += 1;
        }
    }

    // Update receipt with edge count (best-effort; primary receipt already stored).
    let mut final_receipt = receipt;
    final_receipt.edge_count = edges;
    final_receipt.finished_at = Utc::now();
    receipts::persist(pool, &final_receipt).await?;

    Ok(edges)
}

fn build_edge_evidence(cov: &Coverage, receipt: &AnalysisReceipt) -> serde_json::Value {
    serde_json::json!({
        "coverage_a_to_b": cov.a_to_b,
        "coverage_b_to_a": cov.b_to_a,
        "matched_pairs": cov.matched_pairs,
        "top_pairs": cov.top_pairs.iter().map(|p| serde_json::json!({
            "a_offset": p.a_offset, "b_offset": p.b_offset, "score": p.score,
        })).collect::<Vec<_>>(),
        "contested_a": cov.contested_a,
        "contested_b": cov.contested_b,
        "unmatched_a_count": cov.unmatched_a.len(),
        "unmatched_b_count": cov.unmatched_b.len(),
        "tau": MATCH_TAU,
        "model_version": MODEL_VERSION,
        "model_config_digest": model_config_digest(&MODEL_V1),
        "extractor_version": SEMANTIC_EXTRACTOR_VERSION,
        "receipt_id": receipts::receipt_id(receipt),
        "matching": "one_to_one_greedy",
    })
}

async fn load_functions(pool: &PgPool, tenant: Uuid, artifact: Uuid) -> Result<Vec<FunctionRow>> {
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
         WHERE tenant_id = $1 AND artifact_id = $2 AND version = $3
         ORDER BY func_offset",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(SEMANTIC_EXTRACTOR_VERSION)
    .fetch_all(pool)
    .await?;
    Ok(rows
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
        .collect())
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

/// Bounded explainable evidence for a semantic edge between two artifacts.
/// Never returns sample bytes; tenant-scoped.
pub async fn function_pair_evidence(
    pool: &PgPool,
    tenant: Uuid,
    a: Uuid,
    b: Uuid,
    max_pairs: usize,
    max_tokens_per_fn: usize,
) -> Result<serde_json::Value> {
    const MAX_PAIRS: usize = 64;
    const MAX_TOKENS: usize = 64;
    const MAX_RESPONSE_BYTES: usize = 256 * 1024;

    let max_pairs = max_pairs.clamp(1, MAX_PAIRS);
    let max_tokens = max_tokens_per_fn.clamp(1, MAX_TOKENS);

    let funcs_a = load_functions(pool, tenant, a).await?;
    let funcs_b = load_functions(pool, tenant, b).await?;
    let cov = coverage(&funcs_a, &funcs_b);

    let by_off_a: std::collections::BTreeMap<u64, &FunctionRow> =
        funcs_a.iter().map(|f| (f.offset, f)).collect();
    let by_off_b: std::collections::BTreeMap<u64, &FunctionRow> =
        funcs_b.iter().map(|f| (f.offset, f)).collect();

    // Full assigned set for recomputation (not just top-5).
    let mut all_pairs = {
        let mut candidates: Vec<(u64, u64, f64)> = Vec::new();
        for fa in &funcs_a {
            for fb in &funcs_b {
                let score = jaccard(&fa.token_hashes, &fb.token_hashes);
                if score >= MATCH_TAU {
                    candidates.push((fa.offset, fb.offset, score));
                }
            }
        }
        candidates.sort_by(|x, y| {
            y.2.partial_cmp(&x.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| x.0.cmp(&y.0))
                .then_with(|| x.1.cmp(&y.1))
        });
        let mut used_a = std::collections::BTreeSet::new();
        let mut used_b = std::collections::BTreeSet::new();
        let mut assigned = Vec::new();
        for (ao, bo, score) in candidates {
            if used_a.contains(&ao) || used_b.contains(&bo) {
                continue;
            }
            used_a.insert(ao);
            used_b.insert(bo);
            assigned.push((ao, bo, score));
        }
        assigned
    };
    all_pairs.truncate(max_pairs);

    let pairs: Vec<serde_json::Value> = all_pairs
        .iter()
        .map(|(ao, bo, score)| {
            let fa = by_off_a.get(ao);
            let fb = by_off_b.get(bo);
            let tokens_a = fa
                .map(|f| {
                    f.token_hashes
                        .iter()
                        .take(max_tokens)
                        .copied()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let tokens_b = fb
                .map(|f| {
                    f.token_hashes
                        .iter()
                        .take(max_tokens)
                        .copied()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "a": {
                    "offset": ao,
                    "size": fa.map(|f| f.size),
                    "name": fa.and_then(|f| f.name.clone()),
                    "insn_count": fa.map(|f| f.insn_count),
                    "token_hashes_prefix": tokens_a,
                    "token_count": fa.map(|f| f.token_hashes.len()),
                },
                "b": {
                    "offset": bo,
                    "size": fb.map(|f| f.size),
                    "name": fb.and_then(|f| f.name.clone()),
                    "insn_count": fb.map(|f| f.insn_count),
                    "token_hashes_prefix": tokens_b,
                    "token_count": fb.map(|f| f.token_hashes.len()),
                },
                "score": score,
                "score_components": {
                    "jaccard": score,
                    "tau": MATCH_TAU,
                },
            })
        })
        .collect();

    let body = serde_json::json!({
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tenant_id": tenant,
        "artifact_a": a,
        "artifact_b": b,
        "extractor_version": SEMANTIC_EXTRACTOR_VERSION,
        "model_version": MODEL_VERSION,
        "model_config_digest": model_config_digest(&MODEL_V1),
        "tau": MATCH_TAU,
        "matching": "one_to_one_greedy",
        "coverage_a_to_b": cov.a_to_b,
        "coverage_b_to_a": cov.b_to_a,
        "matched_pairs": cov.matched_pairs,
        "contested_a": cov.contested_a,
        "contested_b": cov.contested_b,
        "unmatched_a": cov.unmatched_a,
        "unmatched_b": cov.unmatched_b,
        "pairs": pairs,
        "limits": {
            "max_pairs": max_pairs,
            "max_tokens_per_fn": max_tokens,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
    });

    let serialized = serde_json::to_vec(&body).unwrap_or_default();
    if serialized.len() > MAX_RESPONSE_BYTES {
        return Err(Error::BadRequest(format!(
            "evidence response exceeds {MAX_RESPONSE_BYTES} bytes; reduce max_pairs"
        )));
    }
    Ok(body)
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

    #[test]
    fn many_to_one_is_prevented() {
        // Three identical A functions all prefer the same B function.
        // One-to-one assignment: only one pair is accepted.
        let shared = &[1u64, 2, 3, 4, 5, 6, 7, 8];
        let a = vec![
            row_tokens(0, shared),
            row_tokens(0x40, shared),
            row_tokens(0x80, shared),
        ];
        let b = vec![row_tokens(0x100, shared)];
        let cov = coverage(&a, &b);
        assert_eq!(cov.matched_pairs, 1);
        assert_eq!(cov.a_to_b, 1.0 / 3.0);
        assert_eq!(cov.b_to_a, 1.0);
        assert_eq!(cov.contested_a.len(), 2);
        // Deterministic: lowest a_offset wins when scores tie.
        assert_eq!(cov.top_pairs[0].a_offset, 0);
        assert_eq!(cov.top_pairs[0].b_offset, 0x100);
    }

    #[test]
    fn assignment_is_deterministic() {
        let a = vec![
            row_tokens(10, &[1, 2, 3, 4, 5]),
            row_tokens(20, &[1, 2, 3, 4, 5]),
        ];
        let b = vec![
            row_tokens(30, &[1, 2, 3, 4, 5]),
            row_tokens(40, &[1, 2, 3, 4, 5]),
        ];
        let c1 = coverage(&a, &b);
        let c2 = coverage(&a, &b);
        assert_eq!(c1.top_pairs.len(), c2.top_pairs.len());
        for (p1, p2) in c1.top_pairs.iter().zip(c2.top_pairs.iter()) {
            assert_eq!(p1.a_offset, p2.a_offset);
            assert_eq!(p1.b_offset, p2.b_offset);
            assert_eq!(p1.score, p2.score);
        }
    }

    #[test]
    fn no_double_use_of_target() {
        // A0 prefers B0 (score 1.0), A1 also prefers B0 (score 1.0) and
        // has a weaker match to B1. After A0 claims B0, A1 must take B1.
        let a = vec![
            row_tokens(0, &[1, 2, 3, 4, 5, 6, 7, 8]),
            row_tokens(1, &[1, 2, 3, 4, 5, 6, 7, 8]),
        ];
        let b = vec![
            row_tokens(10, &[1, 2, 3, 4, 5, 6, 7, 8]),
            row_tokens(11, &[1, 2, 3, 4, 5, 6]),
        ];
        let cov = coverage(&a, &b);
        assert_eq!(cov.matched_pairs, 2);
        let b_offsets: std::collections::BTreeSet<_> =
            cov.top_pairs.iter().map(|p| p.b_offset).collect();
        assert_eq!(b_offsets.len(), 2, "each B used once");
    }
}
