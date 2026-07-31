//! Banded LSH over ssdeep digests for fuzzy candidate generation.
//!
//! Each digest is split into fixed-width character n-grams; each n-gram is
//! a band key. Artifacts that share any band key are candidates for the
//! full ssdeep compare. This replaces a full per-class table scan when
//! the LSH index is populated.

use crate::error::Result;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Number of character n-grams used as bands from each ssdeep half.
pub const BAND_WIDTH: usize = 3;
/// Cap on how many LSH candidates we pull before scoring.
pub const CANDIDATE_CAP: i64 = 512;

/// Derive band keys from an ssdeep digest (`blocksize:h1:h2`).
pub fn band_keys(ssdeep: &str) -> Vec<(i32, String)> {
    let mut parts = ssdeep.splitn(3, ':');
    let bs = parts.next().unwrap_or("");
    let h1 = parts.next().unwrap_or("");
    let h2 = parts.next().unwrap_or("");
    let mut out = Vec::new();
    let mut idx = 0i32;
    for half in [h1, h2] {
        if half.len() < BAND_WIDTH {
            if !half.is_empty() {
                out.push((idx, format!("{bs}:{half}")));
                idx += 1;
            }
            continue;
        }
        for window in half.as_bytes().windows(BAND_WIDTH) {
            let w = std::str::from_utf8(window).unwrap_or("");
            out.push((idx, format!("{bs}:{w}")));
            idx += 1;
        }
    }
    out
}

/// Replace LSH bands for one artifact.
pub async fn store_bands(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    ssdeep: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM similarity_lsh_band WHERE tenant_id = $1 AND artifact_id = $2")
        .bind(tenant)
        .bind(artifact)
        .execute(pool)
        .await?;
    for (band_idx, band_key) in band_keys(ssdeep) {
        sqlx::query(
            "INSERT INTO similarity_lsh_band (tenant_id, artifact_id, band_idx, band_key)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (tenant_id, artifact_id, band_idx) DO UPDATE SET band_key = EXCLUDED.band_key",
        )
        .bind(tenant)
        .bind(artifact)
        .bind(band_idx)
        .bind(&band_key)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Candidate artifact ids that share at least one LSH band with `ssdeep`.
/// Falls back to empty when the index has no rows for this tenant (caller
/// may fall back to brute-force).
pub async fn candidates(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    ssdeep: &str,
) -> Result<Vec<Uuid>> {
    let keys = band_keys(ssdeep);
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (band_idx, band_key) in keys {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT artifact_id FROM similarity_lsh_band
             WHERE tenant_id = $1 AND band_idx = $2 AND band_key = $3
               AND artifact_id != $4
             LIMIT $5",
        )
        .bind(tenant)
        .bind(band_idx)
        .bind(&band_key)
        .bind(artifact)
        .bind(CANDIDATE_CAP)
        .fetch_all(pool)
        .await?;
        for (id,) in rows {
            if seen.insert(id) {
                out.push(id);
            }
            if out.len() as i64 >= CANDIDATE_CAP {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// True when this tenant has any LSH rows (index is live).
pub async fn index_populated(pool: &PgPool, tenant: Uuid) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM similarity_lsh_band WHERE tenant_id = $1 LIMIT 1",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await?;
    // COUNT(*) always returns a row; use EXISTS-style check via limit query.
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM similarity_lsh_band WHERE tenant_id = $1 LIMIT 1",
    )
    .bind(tenant)
    .fetch_optional(pool)
    .await?;
    let _ = n;
    Ok(exists.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_keys_are_stable_and_nonempty() {
        let k = band_keys("3:abcde:fghij");
        assert!(!k.is_empty());
        // Same input → same keys.
        assert_eq!(k, band_keys("3:abcde:fghij"));
    }

    #[test]
    fn similar_digests_share_bands() {
        let a = band_keys("3:ABCDEFGH:IJKLMNOP");
        let b = band_keys("3:ABCDEFXY:IJKLMNZZ");
        let set_a: HashSet<_> = a.into_iter().map(|(_, k)| k).collect();
        let set_b: HashSet<_> = b.into_iter().map(|(_, k)| k).collect();
        assert!(
            set_a.intersection(&set_b).next().is_some(),
            "overlapping prefix n-grams should share a band"
        );
    }
}
