//! Authenticated agent ingest: bearer-authenticated announce/upload/
//! finalize with server-enforced occurrence identity, 401 on bad tokens,
//! and the unauthenticated dev path for `corpusctl import`.
//!
//! Spawns the real corpus-server binary against a scratch CAS and the
//! test database. Gated on CORPUS_TEST_DATABASE_URL; no-op without it.

use corpus_core::dto::*;
use corpus_core::{db, DEFAULT_TENANT};
use uuid::Uuid;

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn occ(agent_id: Uuid, seq: i64, path: &str, size: i64) -> OccurrenceInfo {
    OccurrenceInfo {
        host_name: "forged-host".into(),
        agent_id,
        boot_id: Uuid::new_v4(),
        agent_sequence: seq,
        path: path.into(),
        observed_at: chrono::Utc::now(),
        file_size: size,
        file_mtime: None,
        capture_reason: "baseline".into(),
    }
}

#[tokio::test]
async fn agent_ingest_requires_and_enforces_bearer_identity() {
    let Ok(url) = std::env::var("CORPUS_TEST_DATABASE_URL") else {
        eprintln!("CORPUS_TEST_DATABASE_URL unset; skipping integration test");
        return;
    };
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();

    let cas = tempfile::tempdir().unwrap();
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_corpus-server"))
        .env("DATABASE_URL", &url)
        .env("CORPUS_CAS_ROOT", cas.path())
        .env("CORPUS_LISTEN", format!("127.0.0.1:{port}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);

    let http = reqwest::Client::new();
    let mut up = false;
    for _ in 0..60 {
        if http.get(format!("{base}/api/v1/health")).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(up, "server did not become healthy");

    // Enroll an agent via the operator token flow.
    let tok: EnrollmentTokenResponse = http
        .post(format!("{base}/api/v1/enrollment-tokens"))
        .json(&EnrollmentTokenCreateRequest { label: Some("auth-test".into()), ttl_secs: Some(600) })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: EnrollResponse = http
        .post(format!("{base}/api/v1/agents/enroll"))
        .json(&EnrollRequest {
            enrollment_token: tok.token,
            host_name: "auth-test-host".into(),
            agent_version: "test".into(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // (a) Bad bearer token → 401.
    // Payload must be unique per run: the test DB is shared and dedup is real.
    let bytes = format!("auth test payload {}", Uuid::new_v4());
    let bytes = bytes.as_bytes();
    let sha = corpus_core::hash::sha256_hex(bytes);
    let forged_id = Uuid::new_v4();
    let resp = http
        .post(format!("{base}/api/v1/artifacts/announce"))
        .bearer_auth("cpagent-bogus")
        .json(&AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(forged_id, 1, "/w/a", bytes.len() as i64)),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "bad bearer must be rejected");

    // (b) Valid bearer with FORGED occurrence identity: server must
    // overwrite agent_id/host_name from the authenticated identity.
    let ann: AnnounceResponse = http
        .post(format!("{base}/api/v1/artifacts/announce"))
        .bearer_auth(&enrolled.agent_token)
        .json(&AnnounceRequest {
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(forged_id, 1, "/w/a", bytes.len() as i64)),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let upload_id = ann.upload_id.unwrap();
    let up = http
        .put(format!("{base}/api/v1/artifacts/uploads/{upload_id}"))
        .bearer_auth(&enrolled.agent_token)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert!(up.status().is_success());
    let fin: FinalizeResponse = http
        .post(format!("{base}/api/v1/artifacts/finalize"))
        .bearer_auth(&enrolled.agent_token)
        .json(&FinalizeRequest {
            upload_id,
            sha256: sha.clone(),
            size_bytes: bytes.len() as i64,
            occurrence: Some(occ(forged_id, 2, "/w/a", bytes.len() as i64)),
            scope: None,
            provenance: None,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fin.storage_state, "committed");

    let (occ_agent, occ_host): (Uuid, String) = sqlx::query_as(
        "SELECT agent_id, host_name FROM occurrence_event WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT 1",
    )
    .bind(DEFAULT_TENANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(occ_agent, enrolled.agent_id, "forged agent_id must be overwritten");
    assert_eq!(occ_host, "auth-test-host", "forged host_name must be overwritten");
    assert_ne!(occ_agent, forged_id);

    // (c) No bearer at all: unauthenticated dev path still works
    // (corpusctl import / scripts/demo.sh).
    let dev_bytes = format!("dev path payload {}", Uuid::new_v4());
    let dev_bytes = dev_bytes.as_bytes();
    let dev_sha = corpus_core::hash::sha256_hex(dev_bytes);
    let resp = http
        .post(format!("{base}/api/v1/artifacts/announce"))
        .json(&AnnounceRequest {
            sha256: dev_sha,
            size_bytes: dev_bytes.len() as i64,
            occurrence: Some(occ(Uuid::new_v4(), 1, "/w/dev", dev_bytes.len() as i64)),
        })
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "dev path must remain open for corpusctl");
}
