//! Detonation adapter (M10): external sandbox submission behind a
//! provider trait. We orchestrate; the sandbox detonates. Egress is
//! off by default and explicitly declared (spec 20.6).
//!
//! See docs/detonation-design.md.

use crate::error::{Error, Result};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub const ANALYZER_NAME: &str = "cape";
pub const ANALYZER_VERSION: &str = "cape-adapter:v1";

/// What the provider transmits. Surfaced in config and docs (spec 20.6:
/// enrichers must declare whether they send hashes, metadata, or bytes).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderCapabilities {
    pub name: String,
    pub sample_bytes: bool,
    pub hash_only: bool,
    pub self_hosted: bool,
}

pub trait DetonationProvider {
    fn capabilities(&self) -> ProviderCapabilities;
    fn submit(
        &self,
        file_name: &str,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<String>> + Send;
    fn poll(&self, job_id: &str) -> impl std::future::Future<Output = Result<PollOutcome>> + Send;
}

pub enum PollOutcome {
    Pending,
    Done(serde_json::Value),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct DetonationConfig {
    /// Master switch. Off by default — sample egress must be explicit.
    pub enabled: bool,
    pub cape_url: Option<String>,
    pub cape_token: Option<String>,
    pub poll_interval_secs: u64,
    pub max_polls: u32,
}

impl DetonationConfig {
    pub fn from_env() -> DetonationConfig {
        DetonationConfig {
            enabled: std::env::var("CORPUS_DETONATION_ENABLED").is_ok(),
            cape_url: std::env::var("CORPUS_CAPE_URL").ok(),
            cape_token: std::env::var("CORPUS_CAPE_TOKEN").ok(),
            poll_interval_secs: std::env::var("CORPUS_DETONATION_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            max_polls: std::env::var("CORPUS_DETONATION_MAX_POLLS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        }
    }

    /// Fail closed when egress is enabled but CAPE is misconfigured.
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let url_ok = self
            .cape_url
            .as_ref()
            .map(|u| !u.is_empty())
            .unwrap_or(false);
        if !url_ok {
            return Err(Error::BadRequest(
                "CORPUS_DETONATION_ENABLED=1 requires CORPUS_CAPE_URL".into(),
            ));
        }
        // Require an auth token for CAPE unless explicitly opted out
        // (local CAPE with no auth — rare and dangerous on a network).
        let token_ok = self
            .cape_token
            .as_ref()
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        if !token_ok && std::env::var("CORPUS_CAPE_ALLOW_NO_AUTH").is_err() {
            return Err(Error::BadRequest(
                "CORPUS_DETONATION_ENABLED=1 requires CORPUS_CAPE_TOKEN \
                 (or CORPUS_CAPE_ALLOW_NO_AUTH=1 for a local unauthenticated CAPE)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// CAPEv2 provider (self-hosted default).
pub struct CapeProvider {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl CapeProvider {
    pub fn new(base: &str, token: Option<String>) -> CapeProvider {
        CapeProvider {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
            token,
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.header("Authorization", format!("Token {t}")),
            None => req,
        }
    }
}

impl DetonationProvider for CapeProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            name: ANALYZER_NAME.into(),
            sample_bytes: true,
            hash_only: false,
            self_hosted: true,
        }
    }

    async fn submit(&self, file_name: &str, bytes: &[u8]) -> Result<String> {
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(file_name.to_string()),
        );
        let resp = self
            .http
            .post(format!("{}/api/tasks/create/file/", self.base));
        let resp = match &self.token {
            Some(t) => resp.header("Authorization", format!("Token {t}")),
            None => resp,
        }
        .multipart(form)
        .send()
        .await
        .map_err(|e| Error::BadRequest(format!("cape submit: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::BadRequest(format!(
                "cape submit -> {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::BadRequest(e.to_string()))?;
        let task = body
            .get("data")
            .and_then(|d| {
                d.get("task_ids")
                    .and_then(|ids| ids.as_array())
                    .and_then(|a| a.first())
            })
            .or_else(|| body.get("task_id"))
            .and_then(|t| t.as_i64())
            .ok_or_else(|| Error::BadRequest(format!("cape submit: no task id in {body}")))?;
        Ok(task.to_string())
    }

    async fn poll(&self, job_id: &str) -> Result<PollOutcome> {
        let resp = self
            .auth(
                self.http
                    .get(format!("{}/api/tasks/view/{job_id}", self.base)),
            )
            .send()
            .await
            .map_err(|e| Error::BadRequest(format!("cape view: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::BadRequest(format!("cape view -> {}", resp.status())));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::BadRequest(e.to_string()))?;
        let status = body
            .pointer("/task/status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        match status {
            "reported" | "completed" => {
                let report = self
                    .auth(
                        self.http
                            .get(format!("{}/api/tasks/report/{job_id}", self.base)),
                    )
                    .send()
                    .await
                    .map_err(|e| Error::BadRequest(format!("cape report: {e}")))?;
                if !report.status().is_success() {
                    return Err(Error::BadRequest(format!(
                        "cape report -> {}",
                        report.status()
                    )));
                }
                let json: serde_json::Value = report
                    .json()
                    .await
                    .map_err(|e| Error::BadRequest(e.to_string()))?;
                Ok(PollOutcome::Done(json))
            }
            "failed_analysis" | "failed_processing" | "failed_reporting" => Ok(
                PollOutcome::Failed(format!("cape task {job_id} status {status}")),
            ),
            _ => Ok(PollOutcome::Pending),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetonationResult {
    pub analysis_run_id: Uuid,
    pub finding_count: usize,
    pub findings: Vec<serde_json::Value>,
}

/// Full flow: egress check, submit, poll, persist analysis_run +
/// DYNAMIC_BEHAVIOR findings, audit (24.3).
#[allow(clippy::too_many_arguments)]
pub async fn detonate(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    artifact_sha: &str,
    bytes: &[u8],
    provider: &impl DetonationProvider,
    cfg: &DetonationConfig,
    actor: &str,
) -> Result<DetonationResult> {
    if !cfg.enabled {
        return Err(Error::Forbidden(
            "detonation egress is disabled; set CORPUS_DETONATION_ENABLED=1 to send sample bytes to an external sandbox".into(),
        ));
    }
    let caps = provider.capabilities();
    if !caps.sample_bytes {
        return Err(Error::BadRequest(
            "provider does not accept sample bytes".into(),
        ));
    }

    // Audit FIRST: the request to send bytes out is itself the event (24.3).
    sqlx::query(
        "INSERT INTO audit_event (id, tenant_id, actor, action, target, detail, created_at)
         VALUES ($1,$2,$3,'detonate.submit',$4,$5,$6)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(actor)
    .bind(artifact_sha)
    .bind(serde_json::json!({"provider": caps.name, "sample_bytes": caps.sample_bytes, "self_hosted": caps.self_hosted}))
    .bind(Utc::now())
    .execute(pool)
    .await?;

    let job_id = provider.submit(artifact_sha, bytes).await?;
    let mut report = None;
    for _ in 0..cfg.max_polls {
        match provider.poll(&job_id).await? {
            PollOutcome::Done(r) => {
                report = Some(r);
                break;
            }
            PollOutcome::Failed(e) => return Err(Error::BadRequest(e)),
            PollOutcome::Pending => {
                tokio::time::sleep(std::time::Duration::from_secs(cfg.poll_interval_secs)).await;
            }
        }
    }
    let report = report.ok_or_else(|| Error::BadRequest("detonation timed out".into()))?;

    let findings = map_report_to_findings(&report);
    let analysis_run_id = Uuid::new_v4();
    let dummy = vec![0u8; 32];
    sqlx::query(
        "INSERT INTO analysis_run (id, tenant_id, artifact_id, analyzer_name, analyzer_version,
             analyzer_image_digest, config_digest, support_data_digest, status, started_at, completed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'completed',$9,$9)",
    )
    .bind(analysis_run_id)
    .bind(tenant)
    .bind(artifact)
    .bind(ANALYZER_NAME)
    .bind(ANALYZER_VERSION)
    .bind(&dummy)
    .bind(&dummy)
    .bind(&dummy)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    for f in &findings {
        sqlx::query(
            "INSERT INTO finding (id, tenant_id, artifact_id, analysis_run_id, evidence_type, category, summary, detail, created_at)
             VALUES ($1,$2,$3,$4,'DYNAMIC_BEHAVIOR',$5,$6,$7,$8)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(artifact)
        .bind(analysis_run_id)
        .bind(f["category"].as_str().unwrap_or("signature"))
        .bind(f["summary"].as_str().unwrap_or(""))
        .bind(f)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    }

    Ok(DetonationResult {
        analysis_run_id,
        finding_count: findings.len(),
        findings,
    })
}

/// Map a CAPE JSON report to bounded findings with DYNAMIC_BEHAVIOR
/// typing (spec 17.4: behavior observed in the sandbox).
pub fn map_report_to_findings(report: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if let Some(sigs) = report.get("signatures").and_then(|s| s.as_array()) {
        for sig in sigs.iter().take(25) {
            let name = sig
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("signature");
            let desc = sig
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let severity = sig.get("severity").and_then(|s| s.as_i64()).unwrap_or(1);
            out.push(serde_json::json!({
                "category": "signature",
                "summary": format!("{name}: {desc}"),
                "severity": severity,
                "sandbox": "cape",
            }));
        }
    }
    if let Some(ttps) = report.get("ttps").and_then(|t| t.as_array()) {
        for t in ttps.iter().take(25) {
            if let Some(id) = t.get("ttp").and_then(|v| v.as_str()) {
                out.push(serde_json::json!({
                    "category": "attack",
                    "summary": format!("ATT&CK {id} (observed in sandbox)"),
                    "sandbox": "cape",
                }));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_mapping_is_dynamic_behavior_bounded() {
        let report = serde_json::json!({
            "signatures": [
                {"name": "exec_crash", "description": "crashes on start", "severity": 2},
                {"name": "persistence_autorun", "description": "writes autorun key", "severity": 3},
            ],
            "ttps": [{"ttp": "T1059"}, {"ttp": "T1547"}],
        });
        let findings = map_report_to_findings(&report);
        assert_eq!(findings.len(), 4);
        assert!(
            findings
                .iter()
                .any(|f| f["category"] == "attack"
                    && f["summary"].as_str().unwrap().contains("T1059"))
        );
        assert!(findings.iter().any(|f| f["severity"] == 3));
    }

    #[test]
    fn empty_report_maps_to_nothing() {
        assert!(map_report_to_findings(&serde_json::json!({})).is_empty());
    }
}
