//! Function-level candidate index for semantic similarity.
//!
//! # Problem
//!
//! Pairwise Jaccard over every function in a tenant is
//! `O(artifacts × functions²)` and does not scale. We need a cheap
//! *candidate generator* that recalls likely matches without missing
//! correctness when the index is empty or cold.
//!
//! # Design (v1 bands)
//!
//! For each significant function we derive [`FUNC_BAND_COUNT`] (4)
//! deterministic band keys from its sorted token-hash vector:
//!
//! | Band | Key material |
//! |------|----------------|
//! | 0 | first token hash (hex) |
//! | 1 | last token hash (hex) |
//! | 2 | XOR-fold of all hashes (hex) |
//! | 3 | length bucket (`0..=3`) + mid hash |
//!
//! At query time we collect keys for the probe artifact's functions and
//! look up other artifacts that share any key under the same
//! `(tenant_id, version)`. Results are hard-capped at
//! [`FUNC_CANDIDATE_CAP`] (256).
//!
//! This is **not** classical MinHash LSH with independent permutations;
//! it is a lightweight, deterministic approximation tuned for recall of
//! near-identical token sets (shared first/last tokens, similar length).
//! False candidates are filtered by exact Jaccard + coverage later.
//!
//! # Cold index fallback
//!
//! When the table has no rows for the tenant/version, or a probe returns
//! zero candidates, callers (`semantic::edges::analyze_and_link`) fall
//! back to a full tenant scan of `similarity_function`. Correctness is
//! unchanged; only latency differs. The cold path is recorded in edge
//! evidence as `candidate_source`.
//!
//! # Isolation & versioning
//!
//! - All rows are tenant-scoped; there is no cross-tenant lookup.
//! - `version` is the semantic extractor version (`semantic:v1`). A new
//!   extractor does not collide with old bands.
//! - Storage is replace-on-write per artifact (`DELETE` then `INSERT`) so
//!   re-analysis does not leave stale bands.
//!
//! # Schema
//!
//! See `migrations/0011_function_lsh.sql` (`similarity_function_band`).

use crate::error::Result;
use crate::semantic::edges::{FunctionRow, SEMANTIC_EXTRACTOR_VERSION};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Number of band keys emitted per function.
pub const FUNC_BAND_COUNT: usize = 4;

/// Hard upper bound on candidate artifacts returned by [`candidates`].
///
/// Prevents a popular band key from exploding the pairwise scoring set.
pub const FUNC_CANDIDATE_CAP: i64 = 256;

/// Derive deterministic band keys from a function's token-hash signature.
///
/// Empty token sets produce no bands (nothing useful to index). Output
/// order is stable: local band index `0..FUNC_BAND_COUNT`.
pub fn function_bands(token_hashes: &[u64]) -> Vec<(i32, String)> {
    if token_hashes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(FUNC_BAND_COUNT);
    // Band 0: first token hash — identical function prologues collide.
    out.push((0, format!("{:016x}", token_hashes[0])));
    // Band 1: last token hash — shared epilogues (returns, stack cleanup).
    out.push((1, format!("{:016x}", token_hashes[token_hashes.len() - 1])));
    // Band 2: XOR fold of all hashes — coarse multiset fingerprint.
    let fold = token_hashes.iter().fold(0u64, |a, b| a ^ b);
    out.push((2, format!("{:016x}", fold)));
    // Band 3: length bucket + mid hash — similar-sized functions with a
    // shared interior token. Buckets reduce cardinality for short vs long.
    let mid = token_hashes[token_hashes.len() / 2];
    let len_bucket = match token_hashes.len() {
        0..=4 => 0,
        5..=16 => 1,
        17..=64 => 2,
        _ => 3,
    };
    out.push((3, format!("{len_bucket}:{:016x}", mid)));
    out
}

/// Replace function-index bands for one artifact (idempotent re-analysis).
///
/// Deletes existing rows for `(tenant, artifact, version)` then inserts
/// bands for every function. Global `band_idx` packs per-function local
/// indices as `func_ordinal * FUNC_BAND_COUNT + local_idx` so the primary
/// key stays unique without a separate function id column.
pub async fn store_function_bands(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    functions: &[FunctionRow],
    version: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM similarity_function_band
         WHERE tenant_id = $1 AND artifact_id = $2 AND version = $3",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(version)
    .execute(pool)
    .await?;

    let mut band_idx_global = 0i32;
    for f in functions {
        for (local_idx, key) in function_bands(&f.token_hashes) {
            sqlx::query(
                "INSERT INTO similarity_function_band
                   (tenant_id, artifact_id, version, band_idx, band_key, func_offset)
                 VALUES ($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (tenant_id, artifact_id, version, band_idx, func_offset)
                 DO UPDATE SET band_key = EXCLUDED.band_key",
            )
            .bind(tenant)
            .bind(artifact)
            .bind(version)
            .bind(band_idx_global + local_idx)
            .bind(&key)
            .bind(f.offset as i64)
            .execute(pool)
            .await?;
        }
        band_idx_global += FUNC_BAND_COUNT as i32;
    }
    Ok(())
}

/// True when the tenant has any function-index rows for this version.
///
/// Used by the analyze path to decide index vs cold full-scan.
pub async fn index_populated(pool: &PgPool, tenant: Uuid, version: &str) -> Result<bool> {
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM similarity_function_band
         WHERE tenant_id = $1 AND version = $2 LIMIT 1",
    )
    .bind(tenant)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    Ok(exists.is_some())
}

/// Candidate artifacts that share at least one function band with `artifact`.
///
/// Returns an empty vec when the index is cold or there is no band
/// overlap — callers must fall back to a full scan for correctness.
///
/// Query keys use `band_idx % FUNC_BAND_COUNT` so storage's packed global
/// indices still match the local band semantics used at query time.
pub async fn candidates(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    functions: &[FunctionRow],
    version: &str,
) -> Result<Vec<Uuid>> {
    if functions.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys: HashSet<(i32, String)> = HashSet::new();
    for f in functions {
        for (idx, key) in function_bands(&f.token_hashes) {
            // Normalize to local band index (0..FUNC_BAND_COUNT).
            keys.insert((idx % FUNC_BAND_COUNT as i32, key));
        }
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (band_mod, band_key) in keys {
        // Match any stored band whose local index equals band_mod and
        // whose key matches. LIMIT is applied per key; overall cap is
        // enforced after dedup across keys.
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT artifact_id FROM similarity_function_band
             WHERE tenant_id = $1 AND version = $2 AND band_key = $3
               AND artifact_id != $4
               AND (band_idx % $5) = $6
             LIMIT $7",
        )
        .bind(tenant)
        .bind(version)
        .bind(&band_key)
        .bind(artifact)
        .bind(FUNC_BAND_COUNT as i32)
        .bind(band_mod)
        .bind(FUNC_CANDIDATE_CAP)
        .fetch_all(pool)
        .await?;
        for (id,) in rows {
            if seen.insert(id) {
                out.push(id);
            }
            if out.len() as i64 >= FUNC_CANDIDATE_CAP {
                return Ok(out);
            }
        }
    }
    // Keep the extractor version symbol live for future version gates.
    let _ = SEMANTIC_EXTRACTOR_VERSION;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_are_deterministic() {
        let tokens = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(function_bands(&tokens), function_bands(&tokens));
        assert_eq!(function_bands(&tokens).len(), FUNC_BAND_COUNT);
    }

    #[test]
    fn empty_tokens_no_bands() {
        assert!(function_bands(&[]).is_empty());
    }

    #[test]
    fn similar_token_sets_share_band() {
        let a = vec![10u64, 20, 30, 40, 50];
        let b = vec![10u64, 20, 30, 40, 99]; // same first
        let ka: HashSet<_> = function_bands(&a).into_iter().map(|(_, k)| k).collect();
        let kb: HashSet<_> = function_bands(&b).into_iter().map(|(_, k)| k).collect();
        assert!(ka.intersection(&kb).next().is_some());
    }
}
