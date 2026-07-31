//! Integration test for the M4 vault-bootstrap features against real
//! PostgreSQL plus in-process mock servers (OCI registry, TAXII).
//! Gated on CORPUS_TEST_DATABASE_URL; no-op without it.

use corpus_core::cas::FsCas;
use corpus_core::dto::{AnnounceRequest, FinalizeRequest, OccurrenceInfo};
use corpus_core::{db, hash, ingest, intel, oci, report, tenant};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use uuid::Uuid;

// ---------- tiny mock HTTP server ----------

struct MockServer {
    base: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockServer {
    /// Serve `routes` (path-suffix -> (content-type, body)) for up to
    /// `max_requests` connections, one response each.
    fn start(routes: Vec<(String, (String, Vec<u8>))>, max_requests: usize) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for _ in 0..max_requests {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                // Drain headers, capturing Content-Length.
                let mut content_length: u64 = 0;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                // Read exactly the request body, then respond.
                let mut sink = vec![0u8; content_length as usize];
                let _ = reader.read_exact(&mut sink);
                let found = routes.iter().find(|(p, _)| path.ends_with(p.as_str()) || path.contains(p.as_str()));
                let (status, body, ctype) = match found {
                    Some((_, (ct, b))) => ("200 OK", b.clone(), ct.clone()),
                    None => ("404 Not Found", b"{}".to_vec(), "application/json".into()),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        MockServer { base, handle: Some(handle) }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------- helpers ----------

fn occ(host: &str, seq: i64, path: &str, size: i64, observed: chrono::DateTime<chrono::Utc>, reason: &str) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: host.into(),
        agent_id: Uuid::new_v4(),
        boot_id: Uuid::new_v4(),
        agent_sequence: seq,
        path: path.into(),
        observed_at: observed,
        file_size: size,
        file_mtime: None,
        capture_reason: reason.into(),
    }
}

async fn commit(
    pool: &sqlx::PgPool,
    cas: &FsCas,
    tenant_id: Uuid,
    occurrence: Option<OccurrenceInfo>,
    scope: Option<&str>,
    provenance: Option<serde_json::Value>,
    bytes: &[u8],
) -> (Uuid, String) {
    let sha = hash::sha256_hex(bytes);
    let ann = ingest::announce(pool, tenant_id, &AnnounceRequest {
        sha256: sha.clone(),
        size_bytes: bytes.len() as i64,
        occurrence: occurrence.clone(),
    })
    .await
    .unwrap();
    if let Some(upload_id) = ann.upload_id {
        ingest::stage_upload(pool, cas, tenant_id, upload_id, bytes).await.unwrap();
        let fin = ingest::finalize(pool, cas, tenant_id, &FinalizeRequest {
            upload_id,
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence,
            scope: scope.map(|s| s.to_string()),
            provenance,
        })
        .await
        .unwrap();
        return (fin.artifact_id, sha);
    }
    (ann.artifact_id.unwrap(), sha)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut enc, bytes).unwrap();
    enc.finish().unwrap()
}

fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

#[allow(clippy::too_many_arguments)]
#[tokio::test]
async fn vault_bootstrap_end_to_end() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let cas_dir = tempfile::tempdir().unwrap();
    let cas = FsCas::new(cas_dir.path()).unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("boot-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Bootstrap test").await.unwrap();

    let t0 = chrono::DateTime::parse_from_rfc3339("2024-01-15T08:00:00Z").unwrap().with_timezone(&chrono::Utc);
    let t1 = chrono::DateTime::parse_from_rfc3339("2024-03-20T08:00:00Z").unwrap().with_timezone(&chrono::Utc);

    // ===== FEATURE 1: snapshot backfill =====
    // snap1: /etc/tool = v1, /etc/app = X
    // snap2: /etc/tool = v2, /opt/app = X (same bytes, new path)
    let v1 = b"tool binary v1 CORPUS_DEMO_MARKER_STRING";
    let v2 = b"tool binary v2 changed CORPUS_DEMO_MARKER_STRING";
    let x = b"app payload bytes";
    commit(&pool, &cas, tenant_id, Some(occ("prod-web-1", 1, "/etc/tool", v1.len() as i64, t0, "historical_backfill")), None, None, v1).await;
    commit(&pool, &cas, tenant_id, Some(occ("prod-web-1", 2, "/etc/app", x.len() as i64, t0, "historical_backfill")), None, None, x).await;
    let (_, sha_v2) = commit(&pool, &cas, tenant_id, Some(occ("prod-web-1", 1, "/etc/tool", v2.len() as i64, t1, "historical_backfill")), None, None, v2).await;
    let (art_x, sha_x) = commit(&pool, &cas, tenant_id, Some(occ("prod-web-1", 2, "/opt/app", x.len() as i64, t1, "historical_backfill")), None, None, x).await;

    // Same bytes at a new path: ONE artifact, TWO occurrences spanning t0..t1.
    let br = report::by_sha256(&pool, tenant_id, &sha_x, false).await.unwrap();
    assert_eq!(br.artifacts.len(), 1);
    assert_eq!(br.occurrences.len(), 2, "dedup across snapshots still records occurrences");
    let first = br.hosts[0].first_observed;
    let last = br.hosts[0].last_observed;
    assert_eq!(first, t0, "first observed comes from the oldest snapshot");
    assert_eq!(last, t1, "last observed from the newest snapshot");
    for o in &br.occurrences {
        assert!(o.received_at >= o.observed_at, "received_at stays truthful");
        assert_eq!(o.capture_reason, "historical_backfill");
        assert_eq!(o.host_name, "prod-web-1");
    }
    let _ = art_x;

    // Hunt over backfilled history: rule matches v2 only.
    let rule = registry_rule(&pool, tenant_id).await;
    let bundle = corpus_core::registry::publish_bundle(&pool, tenant_id, &[rule], false).await.unwrap();
    let hunt = corpus_core::hunts::create_hunt(&pool, tenant_id, &bundle.digest).await.unwrap();
    let hunt = corpus_core::hunts::run_hunt(&pool, &cas, tenant_id, hunt.id).await.unwrap();
    assert_eq!(hunt.matched, 1);
    let br_h = report::by_hunt(&pool, tenant_id, hunt.id, false).await.unwrap();
    assert_eq!(br_h.artifacts[0].sha256, sha_v2);
    assert_eq!(br_h.occurrences[0].observed_at, t1, "hunt blast radius shows backdated observation");

    // ===== FEATURE 3b: intel scope + hash hunt =====
    let intel_bytes = b"intel sample bytes (mock, not real malware)";
    let (intel_art, intel_sha) = commit(
        &pool,
        &cas,
        tenant_id,
        None,
        Some("intel"),
        Some(serde_json::json!({"source": "malwarebazaar", "sample_sha256": "mock"})),
        intel_bytes,
    )
    .await;

    // Intel artifact: no occurrences, excluded from retro hunts.
    let br_i = report::by_sha256(&pool, tenant_id, &intel_sha, false).await.unwrap();
    assert_eq!(br_i.artifacts.len(), 1);
    assert!(br_i.occurrences.is_empty(), "intel artifacts carry NO host occurrences");
    let scope: (String,) = sqlx::query_as("SELECT scope FROM artifact WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(intel_art)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scope.0, "intel");

    let hunt2 = corpus_core::hunts::create_hunt(&pool, tenant_id, &bundle.digest).await.unwrap();
    let hunt2 = corpus_core::hunts::run_hunt(&pool, &cas, tenant_id, hunt2.id).await.unwrap();
    assert_eq!(hunt2.planned_artifacts, 3, "only endpoint-scope artifacts are hunted (v1, v2, x)");

    // Indicators + exact-hash hunt against endpoint scope.
    intel::upsert_indicators(
        &pool,
        tenant_id,
        "taxii:mock",
        &[
            intel::Indicator { ioc_type: "sha256".into(), value: sha_x.clone(), raw: serde_json::json!({}) },
            intel::Indicator { ioc_type: "sha256".into(), value: intel_sha.clone(), raw: serde_json::json!({}) },
        ],
    )
    .await
    .unwrap();
    let hits = intel::hash_hunt(&pool, tenant_id, &[sha_x.clone(), intel_sha.clone()]).await.unwrap();
    assert_eq!(hits.len(), 1, "endpoint hash hits, intel hash excluded");
    assert_eq!(hits[0].value, sha_x);

    // ===== FEATURE 2: OCI import against mock registry =====
    let layer = build_tar(&[("bin/demo", b"\x7fELF\x02demo-elf-bytes"), ("etc/note", b"note")]);
    let layer_gz = gzip(&layer);
    let layer_digest = format!("sha256:{}", hash::sha256_hex(&layer_gz));
    let config = serde_json::json!({"created": "2024-06-01T00:00:00Z"});
    let config_digest = format!("sha256:{}", hash::sha256_hex(config.to_string().as_bytes()));
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config.to_string().len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_digest, "size": layer_gz.len()}],
    });
    let mock = MockServer::start(
        vec![
            ("/manifests/1.0".into(), ("application/vnd.oci.image.manifest.v1+json".into(), manifest.to_string().into_bytes())),
            (format!("/blobs/{config_digest}"), ("application/octet-stream".into(), config.to_string().into_bytes())),
            (format!("/blobs/{layer_digest}"), ("application/octet-stream".into(), layer_gz)),
        ],
        4,
    );
    let iref = oci::parse_image_ref(&format!("{}/demo/img:1.0", mock.base.trim_start_matches("http://"))).unwrap();
    let reg = oci::RegistryClient::connect(&iref, None).await.unwrap();
    let resolved = reg.resolve(&iref).await.unwrap();
    assert_eq!(resolved.layers, vec![layer_digest.clone()]);
    let layer_bytes = reg.layer_bytes(&iref, &layer_digest).await.unwrap();
    let entries = oci::walk_layer(&layer_bytes, true, 1 << 20).unwrap();
    assert_eq!(entries.len(), 2);
    for (i, e) in entries.iter().enumerate() {
        let prov = oci::file_provenance("localhost/demo/img:1.0", &resolved.image_digest, &layer_digest, &e.path);
        let o = occ("localhost/demo/img:1.0", i as i64 + 1, &e.path, e.size as i64, resolved.created.unwrap(), "oci_image");
        commit(&pool, &cas, tenant_id, Some(o), None, Some(prov), e.bytes.as_ref().unwrap()).await;
    }
    let prov: (serde_json::Value,) = sqlx::query_as(
        "SELECT provenance FROM artifact WHERE tenant_id = $1 AND scope = 'endpoint' ORDER BY seq DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(prov.0["layer_digest"], serde_json::Value::String(layer_digest.clone()));
    let occ_row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT host_name, observed_at FROM occurrence_event WHERE tenant_id = $1 AND capture_reason = 'oci_image' LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    let (h, observed) = occ_row.expect("oci occurrence recorded");
    assert_eq!(h, "localhost/demo/img:1.0");
    assert_eq!(observed, chrono::DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc));

    // ===== FEATURE 3a: mock TAXII poll =====
    let stix = serde_json::json!({
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--x",
             "pattern": format!("[file:hashes.'SHA-256' = '{sha_x}']")},
        ]
    });
    let taxii = MockServer::start(
        vec![("/objects/".into(), ("application/taxii+json;version=2.1".into(), stix.to_string().into_bytes()))],
        1,
    );
    let bundle = intel::fetch_taxii_indicators(&taxii.base, "col-1", None).await.unwrap();
    let iocs = intel::extract_hash_iocs(&bundle);
    assert_eq!(iocs.len(), 1);
    assert_eq!(iocs[0].value, sha_x);
}

async fn registry_rule(pool: &sqlx::PgPool, tenant_id: Uuid) -> Uuid {
    let src = r#"rule V2Marker { strings: $m = "tool binary v2 changed" condition: $m }"#;
    corpus_core::registry::create_rule(pool, tenant_id, src).await.unwrap().id
}
