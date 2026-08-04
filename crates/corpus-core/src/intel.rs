//! Intel ↔ corpus connectors (M4 vault bootstrap).
//!
//! # Indicator store
//!
//! Hash / string indicators land in a tenant-scoped store with provenance
//! (TAXII, manual upload, …). Exact-hash hunts resolve indicators against
//! committed artifacts and emit detections on hit.
//!
//! # Design bounds
//!
//! Indicators are not samples. Matching is digest equality (or future
//! fuzzy intel) — never "download the malware from the intel feed into
//! CAS" unless a separate ingest path is used.

use crate::error::{Error, Result};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

// ---------------- indicator store ----------------

#[derive(Debug, Clone)]
pub struct Indicator {
    pub ioc_type: String, // sha256 | sha1 | md5 | domain | url
    pub value: String,
    pub raw: serde_json::Value,
}

pub async fn upsert_indicators(
    pool: &PgPool,
    tenant: Uuid,
    source: &str,
    indicators: &[Indicator],
) -> Result<usize> {
    let mut n = 0;
    for i in indicators {
        let changed = sqlx::query(
            "INSERT INTO intel_indicator (id, tenant_id, source, ioc_type, value, raw, first_seen, last_seen)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
             ON CONFLICT (tenant_id, source, ioc_type, value)
             DO UPDATE SET last_seen = EXCLUDED.last_seen, raw = EXCLUDED.raw",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(source)
        .bind(&i.ioc_type)
        .bind(i.value.to_lowercase())
        .bind(&i.raw)
        .bind(Utc::now())
        .execute(pool)
        .await?
        .rows_affected();
        n += changed as usize;
    }
    Ok(n)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HashHuntHit {
    pub value: String,
    pub artifact_id: Uuid,
    pub artifact_sha256: String,
    pub first_committed_at: chrono::DateTime<Utc>,
}

/// Exact-hash hunt over ENDPOINT-scope artifacts (spec 14.6: hash intel
/// is an indexed lookup). Intel-scope artifacts are not returned.
pub async fn hash_hunt(pool: &PgPool, tenant: Uuid, hashes: &[String]) -> Result<Vec<HashHuntHit>> {
    let mut hits = Vec::new();
    for h in hashes {
        let raw = crate::hash::hex_to_raw(h)
            .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {h:?}")))?;
        let rows: Vec<(Uuid, Vec<u8>, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, sha256, first_committed_at FROM artifact
             WHERE tenant_id = $1 AND sha256 = $2 AND scope = 'endpoint' AND storage_state = 'committed'",
        )
        .bind(tenant)
        .bind(&raw)
        .fetch_all(pool)
        .await?;
        for (id, sha, committed) in rows {
            hits.push(HashHuntHit {
                value: h.clone(),
                artifact_id: id,
                artifact_sha256: hex::encode(sha),
                first_committed_at: committed,
            });
        }
    }
    Ok(hits)
}

// ---------------- STIX 2.1 extraction ----------------

/// Extract file-hash IOCs from a STIX 2.1 bundle of indicator objects.
/// Handles patterns like [file:hashes.'SHA-256' = 'abc...'].
pub fn extract_hash_iocs(bundle: &serde_json::Value) -> Vec<Indicator> {
    let mut out = Vec::new();
    let Some(objects) = bundle.get("objects").and_then(|o| o.as_array()) else {
        return out;
    };
    for obj in objects {
        if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
            continue;
        }
        let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
            continue;
        };
        for (ioc_type, value) in scan_hash_tokens(pattern) {
            out.push(Indicator {
                ioc_type,
                value: value.to_lowercase(),
                raw: serde_json::json!({
                    "stix_id": obj.get("id").and_then(|i| i.as_str()),
                    "pattern": pattern,
                }),
            });
        }
    }
    out
}

/// Find hex tokens of hash lengths (64/40/32) in a pattern string.
/// Non-hex characters are token boundaries; short fragments from words
/// like "file" and "hashes" fall out via the length filter.
fn scan_hash_tokens(pattern: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in pattern.chars() {
        if c.is_ascii_hexdigit() {
            cur.push(c);
        } else {
            take_token(&mut cur, &mut out);
        }
    }
    take_token(&mut cur, &mut out);
    out
}

fn take_token(cur: &mut String, out: &mut Vec<(String, String)>) {
    let t = match cur.len() {
        64 => Some("sha256"),
        40 => Some("sha1"),
        32 => Some("md5"),
        _ => None,
    };
    if let Some(t) = t {
        if cur.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push((t.to_string(), cur.clone()));
        }
    }
    cur.clear();
}

// ---------------- TAXII 2.1 client ----------------

pub async fn fetch_taxii_indicators(
    server_url: &str,
    collection: &str,
    api_key: Option<&str>,
) -> Result<serde_json::Value> {
    let http = reqwest::Client::new();
    let url = format!(
        "{}/collections/{}/objects/?type=indicator&limit=500",
        server_url.trim_end_matches('/'),
        collection
    );
    let mut req = http
        .get(&url)
        .header("Accept", "application/taxii+json;version=2.1");
    if let Some(key) = api_key {
        req = req.header("Authorization", format!("Token {key}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| Error::BadRequest(format!("taxii fetch: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BadRequest(format!(
            "taxii {} -> {}",
            url,
            resp.status()
        )));
    }
    resp.json()
        .await
        .map_err(|e| Error::BadRequest(format!("taxii json: {e}")))
}

// ---------------- MalwareBazaar client ----------------

pub const MB_API_URL: &str = "https://mb-api.abuse.ch/api/v1/";
pub const MB_ZIP_PASSWORD: &[u8] = b"infected";

/// List recent sample hashes (query=get_recent).
pub async fn mb_recent_hashes(api_url: &str, limit: u32) -> Result<Vec<String>> {
    let http = reqwest::Client::new();
    let resp: serde_json::Value = http
        .post(api_url)
        .form(&[("query", "get_recent"), ("selector", &limit.to_string())])
        .send()
        .await
        .map_err(|e| Error::BadRequest(format!("malwarebazaar recent: {e}")))?
        .json()
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    if resp.get("query_status").and_then(|s| s.as_str()) != Some("ok") {
        return Err(Error::BadRequest(format!(
            "malwarebazaar get_recent status: {resp}"
        )));
    }
    let hashes = resp
        .get("data")
        .and_then(|d| d.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    e.get("sha256_hash")
                        .and_then(|h| h.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(hashes)
}

/// Download one sample zip (query=get_file).
pub async fn mb_fetch_zip(api_url: &str, sha256: &str) -> Result<Vec<u8>> {
    let http = reqwest::Client::new();
    let resp = http
        .post(api_url)
        .form(&[("query", "get_file"), ("sha256_hash", sha256)])
        .send()
        .await
        .map_err(|e| Error::BadRequest(format!("malwarebazaar get_file: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::BadRequest(format!(
            "malwarebazaar get_file {sha256} -> {}",
            resp.status()
        )));
    }
    Ok(resp
        .bytes()
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?
        .to_vec())
}

/// Unpack a MalwareBazaar zip (password "infected") into (name, bytes).
/// These are live malware samples — they go straight to the CAS.
/// Plain (unencrypted) entries are accepted too so mocks/tests work
/// without a ZipCrypto writer.
pub fn mb_unzip(zip_bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| Error::BadRequest(format!("zip: {e}")))?;
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = None;
        {
            if let Ok(mut file) = archive.by_index_decrypt(i, MB_ZIP_PASSWORD) {
                if file.is_file() {
                    let name = file.name().to_string();
                    let mut buf = Vec::new();
                    if std::io::Read::read_to_end(&mut file, &mut buf).is_ok() {
                        entry = Some((name, buf));
                    }
                }
            }
        }
        if entry.is_none() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| Error::BadRequest(format!("zip entry {i}: {e}")))?;
            if !file.is_file() {
                continue;
            }
            let name = file.name().to_string();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut buf)
                .map_err(|e| Error::BadRequest(e.to_string()))?;
            entry = Some((name, buf));
        }
        out.push(entry.unwrap());
    }
    Ok(out)
}

#[cfg(test)]
mod mb_zip_tests {
    use super::*;

    #[test]
    fn unzips_plain_mock_zip() {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("sample.exe", options).unwrap();
        std::io::Write::write_all(&mut writer, b"MZ fake sample").unwrap();
        let zip_bytes = writer.finish().unwrap().into_inner();
        let files = mb_unzip(&zip_bytes).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "sample.exe");
        assert_eq!(files[0].1, b"MZ fake sample");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stix_hash_extraction() {
        let bundle = serde_json::json!({
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--1",
                 "pattern": "[file:hashes.'SHA-256' = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899']"},
                {"type": "indicator", "id": "indicator--2",
                 "pattern": "[file:hashes.MD5 = '44d88612fea8a8f36de82e1278abb02f']"},
                {"type": "indicator", "id": "indicator--3",
                 "pattern": "[domain-name:value = 'evil.example']"},
                {"type": "marking-definition"}
            ]
        });
        let iocs = extract_hash_iocs(&bundle);
        assert_eq!(iocs.len(), 2);
        assert!(iocs.iter().any(|i| i.ioc_type == "sha256"
            && i.value == "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"));
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == "md5" && i.value == "44d88612fea8a8f36de82e1278abb02f"));
    }

    #[test]
    fn empty_bundle_is_fine() {
        assert!(extract_hash_iocs(&serde_json::json!({"objects": []})).is_empty());
        assert!(extract_hash_iocs(&serde_json::json!({})).is_empty());
    }
}
