//! Integration tests for detonation adapter enqueue/poll storage.
//! Gated on `CORPUS_TEST_DATABASE_URL`.

use corpus_core::detonate::{CapeProvider, DetonationConfig, DetonationProvider};
use corpus_core::{db, detonate, tenant};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use uuid::Uuid;

struct MockServer {
    base: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockServer {
    fn start(routes: Vec<(String, (String, Vec<u8>))>, max_requests: usize) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for _ in 0..max_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut content_length = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut sink = vec![0u8; content_length];
                let _ = reader.read_exact(&mut sink);
                let found = routes.iter().find(|(p, _)| path.contains(p.as_str()));
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
        MockServer {
            base,
            handle: Some(handle),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn cfg(enabled: bool, url: Option<String>) -> DetonationConfig {
    DetonationConfig {
        enabled,
        cape_url: url,
        cape_token: None,
        poll_interval_secs: 1,
        max_polls: 5,
    }
}

#[tokio::test]
async fn detonation_flow_end_to_end() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let tenant_id = Uuid::new_v4();
    let slug = format!("det-{}", &tenant_id.simple().to_string()[..8]);
    tenant::ensure_tenant(&pool, tenant_id, &slug, "Detonation test")
        .await
        .unwrap();
    let artifact = Uuid::new_v4();
    let bytes = b"mock sample bytes for detonation";

    // Egress disabled by default: submit must be refused BEFORE any bytes leave.
    let no_mock = CapeProvider::new("http://127.0.0.1:1", None);
    let err = detonate::detonate(
        &pool,
        tenant_id,
        artifact,
        "deadbeef",
        bytes,
        &no_mock,
        &cfg(false, None),
        "itest",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, corpus_core::error::Error::Forbidden(_)),
        "disabled egress must forbid: {err}"
    );

    // Full flow against the mock CAPE.
    let report = serde_json::json!({
        "signatures": [
            {"name": "persistence_autorun", "description": "writes an autorun registry key", "severity": 3},
            {"name": "injection_thread", "description": "creates a remote thread", "severity": 2},
        ],
        "ttps": [{"ttp": "T1547"}, {"ttp": "T1055"}],
    });
    let mock = MockServer::start(
        vec![
            (
                "/api/tasks/create/file/".into(),
                (
                    "application/json".into(),
                    br#"{"data":{"task_ids":[42]}}"#.to_vec(),
                ),
            ),
            (
                "/api/tasks/view/42".into(),
                (
                    "application/json".into(),
                    br#"{"task":{"status":"reported"}}"#.to_vec(),
                ),
            ),
            (
                "/api/tasks/report/42".into(),
                ("application/json".into(), report.to_string().into_bytes()),
            ),
        ],
        3,
    );
    let provider = CapeProvider::new(&mock.base, None);
    assert!(
        provider.capabilities().sample_bytes,
        "manifest declares sampleBytes:true"
    );

    let result = detonate::detonate(
        &pool,
        tenant_id,
        artifact,
        "deadbeef",
        bytes,
        &provider,
        &cfg(true, Some(mock.base.clone())),
        "itest",
    )
    .await
    .unwrap();
    assert_eq!(result.finding_count, 4, "2 signatures + 2 TTPs");

    // analysis_run row, analyzer pinned.
    let run: (String, String, String) = sqlx::query_as(
        "SELECT analyzer_name, analyzer_version, status FROM analysis_run WHERE id = $1",
    )
    .bind(result.analysis_run_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(run.0, "cape");
    assert_eq!(run.2, "completed");

    // Findings carry DYNAMIC_BEHAVIOR typing (spec 17.4).
    let types: Vec<(String, i64)> = sqlx::query_as(
        "SELECT evidence_type, count(*) FROM finding WHERE tenant_id = $1 AND artifact_id = $2 GROUP BY evidence_type",
    )
    .bind(tenant_id)
    .bind(artifact)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(types, vec![("DYNAMIC_BEHAVIOR".to_string(), 4)]);
    let attack: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM finding WHERE tenant_id = $1 AND artifact_id = $2 AND category = 'attack'",
    )
    .bind(tenant_id)
    .bind(artifact)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attack, 2);

    // The detonation request is audited with the egress declaration.
    let audit: (serde_json::Value,) = sqlx::query_as(
        "SELECT detail FROM audit_event WHERE tenant_id = $1 AND action = 'detonate.submit' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit.0["provider"], "cape");
    assert_eq!(audit.0["sample_bytes"], true);

    // Blast radius surfaces the findings for the artifact (report path).
    let found = sqlx::query_as::<_, corpus_core::dto::FindingView>(
        "SELECT evidence_type, category, summary FROM finding WHERE tenant_id = $1 AND artifact_id = $2",
    )
    .bind(tenant_id)
    .bind(artifact)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(found.iter().all(|f| f.evidence_type == "DYNAMIC_BEHAVIOR"));
}
