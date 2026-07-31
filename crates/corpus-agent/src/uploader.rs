//! HTTP client for the server ingest/agent APIs. The server owns all
//! writes; the agent reuses the M0 announce/upload/finalize flow.

use anyhow::{anyhow, Context, Result};
use corpus_core::dto::*;
use uuid::Uuid;

pub struct Uploader {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Uploader {
    pub fn new(base: &str, token: &str) -> Self {
        Uploader {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }

    async fn decode<T: serde::de::DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("server returned {status}: {body}"));
        }
        serde_json::from_str(&body).with_context(|| format!("decoding response: {body}"))
    }

    pub async fn announce(&self, req: &AnnounceRequest) -> Result<AnnounceResponse> {
        let resp = self.req(reqwest::Method::POST, "/api/v1/artifacts/announce").json(req).send().await?;
        self.decode(resp).await
    }

    pub async fn upload(&self, upload_id: Uuid, bytes: Vec<u8>) -> Result<()> {
        let resp = self
            .req(reqwest::Method::PUT, &format!("/api/v1/artifacts/uploads/{upload_id}"))
            .body(bytes)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("upload failed: {status}: {body}"));
        }
        Ok(())
    }

    pub async fn finalize(&self, req: &FinalizeRequest) -> Result<FinalizeResponse> {
        let resp = self.req(reqwest::Method::POST, "/api/v1/artifacts/finalize").json(req).send().await?;
        self.decode(resp).await
    }

    pub async fn heartbeat(&self, hb: &HeartbeatRequest) -> Result<()> {
        let resp = self.req(reqwest::Method::POST, "/api/v1/agents/heartbeat").json(hb).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("heartbeat failed: {status}: {body}"));
        }
        Ok(())
    }

    pub async fn report_gaps(&self, gaps: &[GapEvent]) -> Result<()> {
        let resp = self.req(reqwest::Method::POST, "/api/v1/agents/gaps").json(&gaps).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("gap report failed: {status}: {body}"));
        }
        Ok(())
    }

    /// Enrollment is unauthenticated except for the one-time token.
    pub async fn enroll(base: &str, req: &EnrollRequest) -> Result<EnrollResponse> {
        let http = reqwest::Client::new();
        let resp = http
            .post(format!("{}/api/v1/agents/enroll", base.trim_end_matches('/')))
            .json(req)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("enroll failed: {status}: {body}"));
        }
        Ok(serde_json::from_str(&body)?)
    }
}
