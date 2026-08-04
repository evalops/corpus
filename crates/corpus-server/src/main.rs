//! corpus-server: axum REST API owning all writes.
//!
//! Dev profile: filesystem CAS + PostgreSQL via Docker Compose. Tenants are
//! first-class rows; `X-Corpus-Tenant` accepts a UUID or slug and defaults
//! to the seeded `default` tenant when omitted.
//!
//! Admin auth: see `corpus_core::auth`. Non-loopback binds require
//! `CORPUS_ADMIN_TOKEN`. Hunts enqueue async by default; pass `?sync=1`
//! to run in-request.

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use corpus_core::auth::AuthConfig;
use corpus_core::cas::FsCas;
use corpus_core::dto::*;
use corpus_core::error::Error;
use corpus_core::{db, hunts, ingest, registry, report, tenant};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    cas: std::sync::Arc<FsCas>,
    ca: std::sync::Arc<corpus_core::mtls::DeploymentCa>,
    auth: AuthConfig,
}

struct AppError(Error);

impl From<Error> for AppError {
    fn from(e: Error) -> Self {
        AppError(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Error::BadRequest(_) | Error::RuleParse(_) => StatusCode::BAD_REQUEST,
            Error::Forbidden(_) => StatusCode::FORBIDDEN,
            Error::RuleCompile(_) | Error::HashMismatch { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Error::Db(_) | Error::Io(_) | Error::Migrate(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({"error": self.0.to_string()})),
        )
            .into_response()
    }
}

/// Resolve an active tenant from `X-Corpus-Tenant` (UUID or slug). Missing
/// header → seeded default tenant.
async fn resolve_tenant(pool: &PgPool, headers: &HeaderMap) -> Result<Uuid, AppError> {
    let raw = headers
        .get("x-corpus-tenant")
        .map(|v| {
            v.to_str()
                .map(|s| s.to_string())
                .map_err(|_| Error::BadRequest("invalid tenant header encoding".into()))
        })
        .transpose()?;
    Ok(tenant::resolve_active_tenant(pool, raw.as_deref()).await?)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "engine": corpus_core::ENGINE_VERSION}))
}

async fn openapi_spec() -> Json<serde_json::Value> {
    Json(serde_json::from_str(include_str!("../../../docs/openapi.json")).unwrap_or_else(|_| {
        serde_json::json!({"openapi": "3.0.3", "info": {"title": "Corpus API", "version": "0.1.0"}})
    }))
}

async fn create_tenant(
    State(st): State<AppState>,
    Json(req): Json<TenantCreateRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(tenant::create_tenant(&st.pool, &req).await?),
    ))
}

async fn list_tenants(State(st): State<AppState>) -> Result<Json<Vec<TenantResponse>>, AppError> {
    Ok(Json(tenant::list_tenants(&st.pool).await?))
}

async fn get_tenant(
    State(st): State<AppState>,
    Path(id_or_slug): Path<String>,
) -> Result<Json<TenantResponse>, AppError> {
    if let Ok(id) = Uuid::parse_str(&id_or_slug) {
        return Ok(Json(tenant::get_tenant(&st.pool, id).await?));
    }
    Ok(Json(
        tenant::get_tenant_by_slug(&st.pool, &id_or_slug.to_ascii_lowercase()).await?,
    ))
}

/// Ingest authentication: admin bearer → tenant-scoped CLI path; agent
/// bearer → agent identity; no bearer → unauthenticated dev path only
/// when `allow_dev_ingest` is true.
enum IngestAuth {
    Agent(corpus_core::agents::AgentIdentity),
    Dev(Uuid),
}

async fn ingest_auth(st: &AppState, headers: &HeaderMap) -> Result<IngestAuth, AppError> {
    if let Some(v) = headers.get("authorization") {
        let tok = v
            .to_str()
            .ok()
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Error::Unauthorized("malformed authorization header".into()))?;
        if st.auth.admin_matches(tok) {
            return Ok(IngestAuth::Dev(resolve_tenant(&st.pool, headers).await?));
        }
        let ident = corpus_core::agents::authenticate(&st.pool, tok).await?;
        return Ok(IngestAuth::Agent(ident));
    }
    if !st.auth.allow_dev_ingest {
        return Err(Error::Unauthorized(
            "ingest requires agent or admin bearer (dev path disabled)".into(),
        )
        .into());
    }
    Ok(IngestAuth::Dev(resolve_tenant(&st.pool, headers).await?))
}

/// Middleware: when admin auth is required, all routes except health,
/// enroll, ingest, and agent self-service need a matching admin token.
async fn admin_gate(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !st.auth.require_admin {
        return Ok(next.run(req).await);
    }
    let path = req.uri().path();
    let skip = path == "/api/v1/health"
        || path == "/api/v1/agents/enroll"
        || path == "/api/v1/artifacts/announce"
        || path == "/api/v1/artifacts/finalize"
        || path.starts_with("/api/v1/artifacts/uploads/")
        || path == "/api/v1/agents/heartbeat"
        || path == "/api/v1/agents/gaps";
    if skip {
        return Ok(next.run(req).await);
    }
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    st.auth.check_admin(auth)?;
    Ok(next.run(req).await)
}

fn apply_agent_identity(
    ident: &corpus_core::agents::AgentIdentity,
    occ: &mut Option<OccurrenceInfo>,
) {
    if let Some(occ) = occ {
        occ.agent_id = ident.agent_id;
        occ.host_name = ident.host_name.clone();
    }
}

async fn announce(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(mut req): Json<AnnounceRequest>,
) -> Result<Json<AnnounceResponse>, AppError> {
    let t = match ingest_auth(&st, &headers).await? {
        IngestAuth::Agent(ident) => {
            apply_agent_identity(&ident, &mut req.occurrence);
            ident.tenant_id
        }
        IngestAuth::Dev(t) => t,
    };
    Ok(Json(ingest::announce(&st.pool, t, &req).await?))
}

async fn upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(upload_id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let t = match ingest_auth(&st, &headers).await? {
        IngestAuth::Agent(ident) => ident.tenant_id,
        IngestAuth::Dev(t) => t,
    };
    ingest::stage_upload(&st.pool, &st.cas, t, upload_id, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finalize(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(mut req): Json<FinalizeRequest>,
) -> Result<Json<FinalizeResponse>, AppError> {
    let t = match ingest_auth(&st, &headers).await? {
        IngestAuth::Agent(ident) => {
            apply_agent_identity(&ident, &mut req.occurrence);
            ident.tenant_id
        }
        IngestAuth::Dev(t) => t,
    };
    Ok(Json(ingest::finalize(&st.pool, &st.cas, t, &req).await?))
}

async fn create_rule(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RuleCreateRequest>,
) -> Result<Json<RuleResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(registry::create_rule(&st.pool, t, &req.source).await?))
}

async fn list_rules(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RuleResponse>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(registry::list_rules(&st.pool, t).await?))
}

async fn publish_bundle(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BundlePublishRequest>,
) -> Result<Json<BundlePublishResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let bundle = registry::publish_bundle(&st.pool, t, &req.rule_ids, req.activate).await?;
    let mut continuous_retro_hunt_id = None;
    if req.activate {
        if let Some(hunt) =
            corpus_core::continuous::on_bundle_activated(&st.pool, t, &bundle.digest).await?
        {
            continuous_retro_hunt_id = Some(hunt.id);
            // Execution is claimed by the durable hunt worker loop.
        }
    }
    Ok(Json(BundlePublishResponse {
        bundle,
        continuous_retro_hunt_id,
    }))
}

async fn list_bundles(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BundleResponse>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(registry::list_bundles(&st.pool, t).await?))
}

async fn create_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HuntCreateRequest>,
) -> Result<Json<HuntResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        hunts::create_hunt(&st.pool, t, &req.bundle_digest).await?,
    ))
}

async fn list_hunts(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<HuntResponse>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(hunts::list_hunts(&st.pool, t).await?))
}

async fn get_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(hunt_id): Path<Uuid>,
) -> Result<Json<HuntResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(hunts::get_hunt(&st.pool, t, hunt_id).await?))
}

#[derive(Debug, Deserialize)]
struct RunHuntQuery {
    /// When true (or `1`), run the hunt in-request to completion.
    /// Default: enqueue and return QUEUED; a background worker executes.
    sync: Option<String>,
}

async fn run_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(hunt_id): Path<Uuid>,
    Query(q): Query<RunHuntQuery>,
) -> Result<Json<HuntResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let sync = q
        .sync
        .as_deref()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("CORPUS_HUNT_SYNC").is_ok();
    if sync {
        return Ok(Json(hunts::run_hunt(&st.pool, &st.cas, t, hunt_id).await?));
    }
    // Enqueue only; the durable hunt worker claims and executes.
    Ok(Json(hunts::enqueue_hunt(&st.pool, t, hunt_id).await?))
}

#[derive(Debug, Deserialize)]
struct BlastRadiusQuery {
    hunt_id: Option<Uuid>,
    sha256: Option<String>,
    expand_variants: Option<bool>,
}

async fn blast_radius(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlastRadiusQuery>,
) -> Result<Json<BlastRadiusReport>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let expand = q.expand_variants.unwrap_or(false);
    match (q.hunt_id, q.sha256) {
        (Some(id), None) => Ok(Json(report::by_hunt(&st.pool, t, id, expand).await?)),
        (None, Some(sha)) => Ok(Json(report::by_sha256(&st.pool, t, &sha, expand).await?)),
        _ => Err(Error::BadRequest("provide exactly one of hunt_id or sha256".into()).into()),
    }
}

async fn similar(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<SimilarResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    corpus_core::similarity::edges::similar_view(&st.pool, t, &sha256)
        .await?
        .map(Json)
        .ok_or_else(|| Error::NotFound(format!("artifact {sha256}")).into())
}

async fn variants(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<VariantsResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    corpus_core::similarity::edges::variants_view(&st.pool, t, &sha256)
        .await?
        .map(Json)
        .ok_or_else(|| Error::NotFound(format!("artifact {sha256}")).into())
}

async fn similarity_backfill(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BackfillResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let analyzed = corpus_core::similarity::edges::backfill(&st.pool, &st.cas, t).await?;
    Ok(Json(BackfillResponse { analyzed }))
}

async fn similarity_neighborhood(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NeighborhoodQueryParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let seed = q
        .seed
        .or(q.sha256)
        .ok_or_else(|| Error::BadRequest("seed or sha256 required".into()))?;
    let edge_types = q
        .edge_types
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let nq = corpus_core::similarity::neighborhood::NeighborhoodQuery {
        seed,
        edge_types,
        model_version: q.model_version,
        min_score: q.min_score.unwrap_or(0.0),
        max_depth: q.max_depth.unwrap_or(1),
        max_nodes: q.max_nodes.unwrap_or(64),
        max_edges: q.max_edges.unwrap_or(128),
        offset: q.offset.unwrap_or(0),
        limit: q.limit.unwrap_or(50),
        include_weak: q.include_weak.unwrap_or(true),
    };
    let resp = corpus_core::similarity::neighborhood::query(&st.pool, t, &nq).await?;
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct NeighborhoodQueryParams {
    seed: Option<String>,
    sha256: Option<String>,
    edge_types: Option<String>,
    model_version: Option<String>,
    min_score: Option<f64>,
    max_depth: Option<u32>,
    max_nodes: Option<usize>,
    max_edges: Option<usize>,
    offset: Option<usize>,
    limit: Option<usize>,
    include_weak: Option<bool>,
}

async fn similarity_export(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExportQueryParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let format = corpus_core::similarity::export::ExportFormat::parse(
        q.format.as_deref().unwrap_or("json"),
    )?;
    if let Some(group_id) = q.group_id {
        let exp =
            corpus_core::similarity::export::export_group(&st.pool, t, group_id, format).await?;
        return Ok(Json(serde_json::to_value(exp).unwrap_or_default()));
    }
    let seed = q
        .seed
        .or(q.sha256)
        .ok_or_else(|| Error::BadRequest("seed, sha256, or group_id required".into()))?;
    let nq = corpus_core::similarity::neighborhood::NeighborhoodQuery {
        seed,
        edge_types: q
            .edge_types
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        model_version: q.model_version,
        min_score: q.min_score.unwrap_or(0.0),
        max_depth: q.max_depth.unwrap_or(1),
        max_nodes: q.max_nodes.unwrap_or(64),
        max_edges: q.max_edges.unwrap_or(128),
        offset: 0,
        limit: q.max_edges.unwrap_or(128),
        include_weak: q.include_weak.unwrap_or(true),
    };
    let exp =
        corpus_core::similarity::export::export_neighborhood(&st.pool, t, &nq, format).await?;
    Ok(Json(serde_json::to_value(exp).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct ExportQueryParams {
    seed: Option<String>,
    sha256: Option<String>,
    group_id: Option<Uuid>,
    format: Option<String>,
    edge_types: Option<String>,
    model_version: Option<String>,
    min_score: Option<f64>,
    max_depth: Option<u32>,
    max_nodes: Option<usize>,
    max_edges: Option<usize>,
    include_weak: Option<bool>,
}

async fn semantic_evidence(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((a, b)): Path<(Uuid, Uuid)>,
    Query(q): Query<EvidenceQueryParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let body = corpus_core::semantic::edges::function_pair_evidence(
        &st.pool,
        t,
        a,
        b,
        q.max_pairs.unwrap_or(32),
        q.max_tokens.unwrap_or(32),
    )
    .await?;
    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
struct EvidenceQueryParams {
    max_pairs: Option<usize>,
    max_tokens: Option<usize>,
}

async fn similarity_cleanup(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(artifact_id): Path<Uuid>,
    Query(q): Query<CleanupQueryParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let report = corpus_core::similarity::lifecycle::cleanup_artifact(
        &st.pool,
        t,
        artifact_id,
        q.dry_run.unwrap_or(true),
    )
    .await?;
    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct CleanupQueryParams {
    dry_run: Option<bool>,
}

async fn list_analyzers() -> Result<Json<serde_json::Value>, AppError> {
    let items: Vec<serde_json::Value> = corpus_core::similarity::analyzers::global()
        .list()
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "version": a.version,
                "formats": a.formats,
                "architectures": a.architectures,
                "feature_families": a.feature_families,
                "supports_backfill": a.supports_backfill,
                "config_digest": a.config_digest,
                "status": match a.status {
                    corpus_core::similarity::analyzers::AnalyzerStatus::Active => "active",
                    corpus_core::similarity::analyzers::AnalyzerStatus::Retired => "retired",
                },
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"analyzers": items})))
}

async fn artifact_receipts(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let rows = corpus_core::similarity::receipts::for_artifact(&st.pool, t, artifact_id).await?;
    Ok(Json(serde_json::json!({"receipts": rows})))
}

// ---------- agent endpoints (M1) ----------

fn bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let v = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Error::BadRequest("missing bearer token".into()))?;
    Ok(v.to_string())
}

async fn create_enrollment_token(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollmentTokenCreateRequest>,
) -> Result<Json<EnrollmentTokenResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        corpus_core::agents::create_enrollment_token(
            &st.pool,
            t,
            req.label.as_deref().unwrap_or(""),
            req.ttl_secs,
        )
        .await?,
    ))
}

async fn enroll(
    State(st): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    Ok(Json(
        corpus_core::agents::enroll(&st.pool, &st.ca, &req).await?,
    ))
}

// ---------- mTLS agent listener (M6) ----------

/// Peer certificate DER injected per connection on the agent listener.
#[derive(Clone)]
struct PeerCertDer(Option<Vec<u8>>);

async fn peer_identity(
    st: &AppState,
    peer: &PeerCertDer,
) -> Result<corpus_core::agents::AgentIdentity, AppError> {
    let der = peer
        .0
        .as_ref()
        .ok_or_else(|| Error::Unauthorized("client certificate required".into()))?;
    let agent_id = corpus_core::mtls::agent_id_from_cert_der(der)?;
    Ok(corpus_core::agents::authenticate_cert(&st.pool, agent_id).await?)
}

async fn agent_heartbeat_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
    Json(hb): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    corpus_core::agents::heartbeat(&st.pool, &ident, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn report_gaps_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
    Json(gaps): Json<Vec<GapEvent>>,
) -> Result<StatusCode, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    corpus_core::agents::record_gaps(&st.pool, &ident, &gaps).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_cert_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
) -> Result<Json<RenewCertResponse>, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    Ok(Json(corpus_core::agents::renew_cert(
        &st.ca,
        ident.agent_id,
    )?))
}

async fn announce_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
    Json(mut req): Json<AnnounceRequest>,
) -> Result<Json<AnnounceResponse>, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    apply_agent_identity(&ident, &mut req.occurrence);
    Ok(Json(
        ingest::announce(&st.pool, ident.tenant_id, &req).await?,
    ))
}

async fn upload_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
    Path(upload_id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    ingest::stage_upload(&st.pool, &st.cas, ident.tenant_id, upload_id, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finalize_mtls(
    State(st): State<AppState>,
    Extension(peer): Extension<PeerCertDer>,
    Json(mut req): Json<FinalizeRequest>,
) -> Result<Json<FinalizeResponse>, AppError> {
    let ident = peer_identity(&st, &peer).await?;
    apply_agent_identity(&ident, &mut req.occurrence);
    Ok(Json(
        ingest::finalize(&st.pool, &st.cas, ident.tenant_id, &req).await?,
    ))
}

/// Accept loop for the mTLS agent listener: rustls with required client
/// certs; the peer cert DER is injected as a per-connection extension.
async fn run_agent_listener(
    listen: &str,
    ca: std::sync::Arc<corpus_core::mtls::DeploymentCa>,
    pool: PgPool,
    cas: std::sync::Arc<FsCas>,
    auth: AuthConfig,
) -> anyhow::Result<()> {
    use axum::Extension as AxExtension;
    let config = corpus_core::mtls::server_config(&ca)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "mTLS agent listener (client certs required)");
    let router = Router::new()
        .route("/api/v1/agents/heartbeat", post(agent_heartbeat_mtls))
        .route("/api/v1/agents/gaps", post(report_gaps_mtls))
        .route("/api/v1/agents/renew", post(renew_cert_mtls))
        .route("/api/v1/artifacts/announce", post(announce_mtls))
        .route("/api/v1/artifacts/uploads/{upload_id}", put(upload_mtls))
        .route("/api/v1/artifacts/finalize", post(finalize_mtls))
        .with_state(AppState {
            pool,
            cas,
            ca,
            auth,
        });
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(error = %e, "agent TLS handshake rejected");
                    return;
                }
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first().map(|d| d.as_ref().to_vec()));
            let app = router.layer(AxExtension(PeerCertDer(peer)));
            let io = hyper_util::rt::TokioIo::new(tls);
            let service = hyper_util::service::TowerToHyperService::new(app.into_service());
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
        });
    }
}

async fn agent_heartbeat(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(hb): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let ident = corpus_core::agents::authenticate(&st.pool, &bearer_token(&headers)?).await?;
    corpus_core::agents::heartbeat(&st.pool, &ident, &hb).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn report_gaps(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(gaps): Json<Vec<GapEvent>>,
) -> Result<StatusCode, AppError> {
    // Bearer -> agent identity. No bearer -> dev path (corpusctl importers),
    // host taken from the event payload.
    if headers.contains_key("authorization") {
        let ident = corpus_core::agents::authenticate(&st.pool, &bearer_token(&headers)?).await?;
        corpus_core::agents::record_gaps(&st.pool, &ident, &gaps).await?;
    } else {
        let t = resolve_tenant(&st.pool, &headers).await?;
        corpus_core::agents::record_gaps_dev(&st.pool, t, &gaps).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_agents(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentStatusResponse>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(corpus_core::agents::list_agents(&st.pool, t).await?))
}

async fn agent_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<AgentStatusResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        corpus_core::agents::agent_status(&st.pool, t, agent_id).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct CoverageGapsQuery {
    outcome: Option<String>,
    limit: Option<i64>,
}

async fn coverage_gaps(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CoverageGapsQuery>,
) -> Result<Json<Vec<CoverageGapRow>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        corpus_core::agents::coverage_gaps(
            &st.pool,
            t,
            q.outcome.as_deref(),
            q.limit.unwrap_or(100),
        )
        .await?,
    ))
}

async fn upsert_indicators(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IndicatorsUpsertRequest>,
) -> Result<Json<IndicatorsUpsertResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let indicators: Vec<corpus_core::intel::Indicator> = req
        .indicators
        .into_iter()
        .map(|i| corpus_core::intel::Indicator {
            ioc_type: i.ioc_type,
            value: i.value,
            raw: i.raw.unwrap_or_else(|| serde_json::json!({})),
        })
        .collect();
    let upserted =
        corpus_core::intel::upsert_indicators(&st.pool, t, &req.source, &indicators).await?;
    let sha_hashes: Vec<String> = indicators
        .iter()
        .filter(|i| i.ioc_type.eq_ignore_ascii_case("sha256"))
        .map(|i| i.value.clone())
        .collect();
    let continuous =
        corpus_core::continuous::on_hash_indicators(&st.pool, t, &req.source, &sha_hashes).await?;
    Ok(Json(IndicatorsUpsertResponse {
        upserted,
        continuous,
    }))
}

#[derive(Debug, Deserialize)]
struct InvestigateQuery {
    sha256: Option<String>,
    hunt_id: Option<Uuid>,
}

async fn investigate(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InvestigateQuery>,
) -> Result<Json<InvestigationReport>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    match (q.sha256, q.hunt_id) {
        (Some(sha), None) => Ok(Json(
            corpus_core::investigate::by_sha256(&st.pool, t, &sha).await?,
        )),
        (None, Some(hid)) => Ok(Json(
            corpus_core::investigate::by_hunt(&st.pool, t, hid).await?,
        )),
        _ => Err(Error::BadRequest("provide exactly one of sha256 or hunt_id".into()).into()),
    }
}

async fn list_detections(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DetectionEventView>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let rows = corpus_core::detect::recent(&st.pool, t, 100).await?;
    Ok(Json(
        rows.into_iter()
            .map(|d| DetectionEventView {
                id: d.id,
                source: d.source,
                severity: d.severity,
                title: d.title,
                detail: d.detail,
                mitre_techniques: d.mitre_techniques,
                created_at: d.created_at,
            })
            .collect(),
    ))
}

async fn list_continuous(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        corpus_core::continuous::list_recent(&st.pool, t, 50).await?,
    ))
}

async fn platform_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PlatformMetrics>, AppError> {
    // Tenant-scoped when header present; global when default tenant resolution
    // still applies (header optional). Always scope to resolved tenant.
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(
        corpus_core::metrics::platform_metrics(&st.pool, Some(t)).await?,
    ))
}

async fn hash_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HashHuntRequest>,
) -> Result<Json<HashHuntResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let hits = corpus_core::intel::hash_hunt(&st.pool, t, &req.hashes).await?;
    Ok(Json(HashHuntResponse {
        hits: hits
            .into_iter()
            .map(|h| HashHuntHitView {
                value: h.value,
                artifact_id: h.artifact_id,
                artifact_sha256: h.artifact_sha256,
                first_committed_at: h.first_committed_at,
            })
            .collect(),
    }))
}

// ---------- detonation (M10) ----------

async fn detonate_artifact(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let raw = corpus_core::hash::hex_to_raw(&sha256)
        .map_err(|_| Error::BadRequest("invalid sha256 hex".into()))?;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, object_key FROM artifact WHERE tenant_id = $1 AND sha256 = $2 AND storage_state = 'committed'")
            .bind(t)
            .bind(&raw)
            .fetch_optional(&st.pool)
            .await
            .map_err(Error::from)?;
    let (artifact_id, object_key) =
        row.ok_or_else(|| Error::NotFound(format!("artifact {sha256}")))?;
    let bytes = st.cas.read(&object_key)?;
    let cfg = corpus_core::detonate::DetonationConfig::from_env();
    cfg.validate()?;
    if !cfg.enabled {
        return Err(Error::BadRequest(
            "detonation disabled; set CORPUS_DETONATION_ENABLED=1".into(),
        )
        .into());
    }
    let provider = match &cfg.cape_url {
        Some(url) => corpus_core::detonate::CapeProvider::new(url, cfg.cape_token.clone()),
        None => {
            return Err(Error::BadRequest(
                "no detonation provider configured (set CORPUS_CAPE_URL and CORPUS_DETONATION_ENABLED=1)".into(),
            )
            .into())
        }
    };
    let result = corpus_core::detonate::detonate(
        &st.pool,
        t,
        artifact_id,
        &sha256,
        &bytes,
        &provider,
        &cfg,
        "corpusctl",
    )
    .await?;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

// ---------- analyst surface (M5) ----------

async fn artifact_id_for(pool: &PgPool, tenant: Uuid, sha: &str) -> Result<Uuid, AppError> {
    corpus_core::opinions::artifact_for_sha(pool, tenant, sha)
        .await?
        .map(|(id,)| id)
        .ok_or_else(|| Error::NotFound(format!("artifact {sha}")).into())
}

async fn prevalence(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<PrevalenceView>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let id = artifact_id_for(&st.pool, t, &sha256).await?;
    let p = corpus_core::analyst::prevalence_for(&st.pool, t, id).await?;
    Ok(Json(PrevalenceView {
        host_count: p.host_count,
        path_count: p.path_count,
        first_observed: p.first_observed,
        last_observed: p.last_observed,
    }))
}

async fn set_opinion(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
    Json(req): Json<OpinionSetRequest>,
) -> Result<Json<OpinionView>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let id = artifact_id_for(&st.pool, t, &sha256).await?;
    let actor = req.actor.unwrap_or_else(|| "corpusctl".into());
    let oid =
        corpus_core::opinions::set_opinion(&st.pool, t, id, &req.opinion, &actor, &req.reason)
            .await?;
    // Optional auto-submit policy (default OFF): suspicious/malicious
    // verdicts can trigger detonation when explicitly enabled.
    if matches!(req.opinion.as_str(), "malicious" | "suspicious")
        && std::env::var("CORPUS_DETONATION_AUTO").is_ok()
    {
        let cfg = corpus_core::detonate::DetonationConfig::from_env();
        if cfg.enabled {
            if let Some(url) = cfg.cape_url.clone() {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT object_key FROM artifact WHERE tenant_id = $1 AND id = $2 AND storage_state = 'committed'",
                )
                .bind(t)
                .bind(id)
                .fetch_optional(&st.pool)
                .await
                .map_err(Error::from)?;
                if let Some((object_key,)) = row {
                    if let Ok(bytes) = st.cas.read(&object_key) {
                        let provider =
                            corpus_core::detonate::CapeProvider::new(&url, cfg.cape_token.clone());
                        let pool = st.pool.clone();
                        let sha = sha256.clone();
                        tokio::spawn(async move {
                            if let Err(e) = corpus_core::detonate::detonate(
                                &pool,
                                t,
                                id,
                                &sha,
                                &bytes,
                                &provider,
                                &cfg,
                                "auto-policy",
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "auto-submit detonation failed");
                            }
                        });
                    }
                }
            }
        }
    }
    let current = corpus_core::opinions::current_opinion(&st.pool, t, id)
        .await?
        .ok_or_else(|| Error::NotFound("opinion".into()))?;
    debug_assert_eq!(current.id, oid);
    Ok(Json(OpinionView {
        id: current.id,
        opinion: current.opinion,
        actor: current.actor,
        reason: current.reason,
        created_at: current.created_at,
        superseded_by: current.superseded_by,
    }))
}

async fn get_opinion(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<Option<OpinionView>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let id = artifact_id_for(&st.pool, t, &sha256).await?;
    let view = corpus_core::opinions::current_opinion(&st.pool, t, id)
        .await?
        .map(|o| OpinionView {
            id: o.id,
            opinion: o.opinion,
            actor: o.actor,
            reason: o.reason,
            created_at: o.created_at,
            superseded_by: o.superseded_by,
        });
    Ok(Json(view))
}

async fn opinion_history(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> Result<Json<Vec<OpinionView>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let id = artifact_id_for(&st.pool, t, &sha256).await?;
    let rows = corpus_core::opinions::opinion_history(&st.pool, t, id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|o| OpinionView {
                id: o.id,
                opinion: o.opinion,
                actor: o.actor,
                reason: o.reason,
                created_at: o.created_at,
                superseded_by: o.superseded_by,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    max_hosts: Option<i64>,
    since: Option<String>,
    opinion: Option<String>,
    limit: Option<i64>,
}

async fn rarity_search(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let since = q
        .since
        .as_deref()
        .map(corpus_core::analyst::parse_since)
        .transpose()?
        .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::days(30));
    let hits = corpus_core::analyst::rarity_search(
        &st.pool,
        t,
        q.max_hosts.unwrap_or(5),
        since,
        q.opinion.as_deref(),
        q.limit.unwrap_or(100),
    )
    .await?;
    Ok(Json(serde_json::to_value(hits).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct DropperRequest {
    sha256: String,
    max_hosts: Option<i64>,
    window_hours: Option<i64>,
}

async fn dropper_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DropperRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let hits = corpus_core::analyst::dropper_candidates(
        &st.pool,
        t,
        &req.sha256,
        req.max_hosts.unwrap_or(3),
        req.window_hours.unwrap_or(24),
        100,
    )
    .await?;
    Ok(Json(serde_json::json!({
        "note": "lead generator, not a verdict",
        "candidates": serde_json::to_value(hits).unwrap_or_default(),
    })))
}

async fn create_trigger(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TriggerCreateRequest>,
) -> Result<Json<TriggerCreateResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let (row, secret) = corpus_core::triggers::create_trigger(
        &st.pool,
        t,
        &req.name,
        &req.condition,
        &req.webhook_url,
        req.secret,
    )
    .await?;
    Ok(Json(TriggerCreateResponse {
        trigger: TriggerView {
            id: row.id,
            name: row.name,
            condition: row.condition,
            webhook_url: row.webhook_url,
            enabled: row.enabled,
            created_at: row.created_at,
        },
        hmac_secret: secret,
    }))
}

async fn list_triggers(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TriggerView>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let rows = corpus_core::triggers::list_triggers(&st.pool, t).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| TriggerView {
                id: r.id,
                name: r.name,
                condition: r.condition,
                webhook_url: r.webhook_url,
                enabled: r.enabled,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

async fn test_trigger(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(trigger_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT condition FROM trigger_rule WHERE tenant_id = $1 AND id = $2")
            .bind(t)
            .bind(trigger_id)
            .fetch_optional(&st.pool)
            .await
            .map_err(Error::from)?;
    let (condition,) = row.ok_or_else(|| Error::NotFound(format!("trigger {trigger_id}")))?;
    corpus_core::triggers::fire(
        &st.pool,
        t,
        &condition,
        serde_json::json!({"type": "test", "trigger_id": trigger_id, "condition": condition}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- MCP read-only server (M5) ----------

async fn mcp_endpoint(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !st.auth.mcp_matches(provided) {
        return Err(Error::Unauthorized("invalid MCP token".into()).into());
    }
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(mcp::handle(&st, t, req).await))
}

mod mcp {
    use super::*;
    use serde_json::json;

    fn result(id: &serde_json::Value, result: serde_json::Value) -> serde_json::Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }
    fn error(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
    }

    pub async fn handle(st: &AppState, tenant: Uuid, req: serde_json::Value) -> serde_json::Value {
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        match method {
            "initialize" => result(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "corpus-mcp", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"tools": {}},
                }),
            ),
            "tools/list" => result(
                &id,
                json!({"tools": [
                    {"name": "search_artifacts", "description": "Rarity search over endpoint artifacts",
                     "inputSchema": {"type": "object", "properties": {"max_hosts": {"type": "integer"}, "since": {"type": "string"}}}},
                    {"name": "get_prevalence", "description": "Fleet prevalence for an artifact by sha256",
                     "inputSchema": {"type": "object", "properties": {"sha256": {"type": "string"}}, "required": ["sha256"]}},
                    {"name": "get_opinion", "description": "Current human opinion for an artifact",
                     "inputSchema": {"type": "object", "properties": {"sha256": {"type": "string"}}, "required": ["sha256"]}},
                    {"name": "blast_radius", "description": "Blast-radius report by sha256 (historical observation)",
                     "inputSchema": {"type": "object", "properties": {"sha256": {"type": "string"}}, "required": ["sha256"]}},
                    {"name": "list_variants", "description": "Variant group members for an artifact",
                     "inputSchema": {"type": "object", "properties": {"sha256": {"type": "string"}}, "required": ["sha256"]}},
                ]}),
            ),
            "tools/call" => {
                let name = req
                    .pointer("/params/name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let args = req
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                call(st, tenant, &id, name, args).await
            }
            _ => error(&id, -32601, "method not found"),
        }
    }

    async fn call(
        st: &AppState,
        tenant: Uuid,
        id: &serde_json::Value,
        name: &str,
        args: serde_json::Value,
    ) -> serde_json::Value {
        let text: String = match name {
            "search_artifacts" => {
                let since = args
                    .get("since")
                    .and_then(|s| s.as_str())
                    .map(corpus_core::analyst::parse_since);
                let since = match since {
                    Some(Ok(t)) => t,
                    Some(Err(e)) => return error(id, -32602, &e.to_string()),
                    None => chrono::Utc::now() - chrono::Duration::days(30),
                };
                match corpus_core::analyst::rarity_search(
                    &st.pool,
                    tenant,
                    args.get("max_hosts").and_then(|v| v.as_i64()).unwrap_or(5),
                    since,
                    None,
                    50,
                )
                .await
                {
                    Ok(h) => serde_json::to_string_pretty(&h).unwrap_or_default(),
                    Err(e) => return error(id, -32000, &e.to_string()),
                }
            }
            "get_prevalence" | "get_opinion" | "blast_radius" | "list_variants" => {
                let Some(sha) = args.get("sha256").and_then(|s| s.as_str()) else {
                    return error(id, -32602, "sha256 required");
                };
                let r: std::result::Result<serde_json::Value, corpus_core::error::Error> = match name {
                    "get_prevalence" => async {
                        let art = corpus_core::opinions::artifact_for_sha(&st.pool, tenant, sha).await?;
                        match art {
                            Some((a,)) => {
                                let p = corpus_core::analyst::prevalence_for(&st.pool, tenant, a).await?;
                                Ok(json!({"host_count": p.host_count, "path_count": p.path_count,
                                          "first_observed": p.first_observed, "last_observed": p.last_observed}))
                            }
                            None => Ok(json!({"error": "unknown artifact"})),
                        }
                    }
                    .await,
                    "get_opinion" => async {
                        let art = corpus_core::opinions::artifact_for_sha(&st.pool, tenant, sha).await?;
                        match art {
                            Some((a,)) => {
                                let o = corpus_core::opinions::current_opinion(&st.pool, tenant, a).await?;
                                Ok(serde_json::to_value(o).unwrap_or_default())
                            }
                            None => Ok(json!({"error": "unknown artifact"})),
                        }
                    }
                    .await,
                    "blast_radius" => {
                        corpus_core::report::by_sha256(&st.pool, tenant, sha, false).await.map(|r| serde_json::to_value(r).unwrap_or_default())
                    }
                    _ => corpus_core::similarity::edges::variants_view(&st.pool, tenant, sha)
                        .await
                        .map(|v| serde_json::to_value(v).unwrap_or_default()),
                };
                match r {
                    Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_default(),
                    Err(e) => return error(id, -32000, &e.to_string()),
                }
            }
            _ => return error(id, -32602, &format!("unknown tool {name:?}")),
        };
        result(id, json!({"content": [{"type": "text", "text": text}]}))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "corpus_server=info,corpus_core=info".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://corpus:corpus@127.0.0.1:5434/corpus".into());
    let cas_root = std::env::var("CORPUS_CAS_ROOT").unwrap_or_else(|_| "./data/cas".into());
    let listen = std::env::var("CORPUS_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());

    let auth = AuthConfig::from_env(&listen).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if auth.require_admin {
        tracing::info!("admin auth required on non-public routes (CORPUS_ADMIN_TOKEN)");
    } else {
        tracing::warn!(
            "admin auth off (loopback bind without CORPUS_ADMIN_TOKEN); \
             do not expose this listener"
        );
    }
    if auth.listen_is_loopback && auth.mcp_token == corpus_core::auth::MCP_DEV_TOKEN {
        tracing::warn!("MCP using default dev token; set CORPUS_MCP_TOKEN for anything non-local");
    }
    // Fail closed early if detonation is misconfigured while enabled.
    corpus_core::detonate::DetonationConfig::from_env()
        .validate()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;
    tracing::info!("migrations applied");
    // Confirm the default tenant is present (seeded by migration).
    let default = tenant::get_tenant(&pool, corpus_core::DEFAULT_TENANT).await?;
    tracing::info!(slug = %default.slug, id = %default.id, "default tenant ready");
    let cas = FsCas::new(&cas_root)?;
    tracing::info!(%cas_root, "filesystem CAS ready (dev profile)");

    // mTLS deployment CA (M6): agents authenticate to the agent listener
    // with client certs signed by this CA.
    let ca_dir = std::env::var("CORPUS_CA_DIR").unwrap_or_else(|_| "./data/ca".into());
    let extra_sans: Vec<String> = std::env::var("CORPUS_CA_SANS")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let ca = std::sync::Arc::new(corpus_core::mtls::load_or_create_ca(
        std::path::Path::new(&ca_dir),
        &extra_sans,
    )?);
    let agent_listen =
        std::env::var("CORPUS_AGENT_LISTEN").unwrap_or_else(|_| "127.0.0.1:8443".into());

    let state = AppState {
        pool: pool.clone(),
        cas: std::sync::Arc::new(cas),
        ca: ca.clone(),
        auth: auth.clone(),
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/tenants", post(create_tenant).get(list_tenants))
        .route("/api/v1/tenants/{id_or_slug}", get(get_tenant))
        .route("/api/v1/artifacts/announce", post(announce))
        .route("/api/v1/artifacts/uploads/{upload_id}", put(upload))
        .route("/api/v1/artifacts/finalize", post(finalize))
        .route("/api/v1/rules", post(create_rule).get(list_rules))
        .route("/api/v1/bundles", post(publish_bundle).get(list_bundles))
        .route("/api/v1/hunts", post(create_hunt).get(list_hunts))
        .route("/api/v1/hunts/{hunt_id}", get(get_hunt))
        .route("/api/v1/hunts/{hunt_id}/run", post(run_hunt))
        .route("/api/v1/reports/blast-radius", get(blast_radius))
        .route("/api/v1/artifacts/{sha256}/similar", get(similar))
        .route("/api/v1/artifacts/{sha256}/variants", get(variants))
        .route("/api/v1/similarity/backfill", post(similarity_backfill))
        .route("/api/v1/similarity/neighborhood", get(similarity_neighborhood))
        .route("/api/v1/similarity/export", get(similarity_export))
        .route("/api/v1/similarity/analyzers", get(list_analyzers))
        .route(
            "/api/v1/similarity/evidence/{a}/{b}",
            get(semantic_evidence),
        )
        .route(
            "/api/v1/artifacts/{artifact_id}/receipts",
            get(artifact_receipts),
        )
        .route(
            "/api/v1/artifacts/{artifact_id}/similarity-cleanup",
            post(similarity_cleanup),
        )
        .route("/api/v1/enrollment-tokens", post(create_enrollment_token))
        .route("/api/v1/agents/enroll", post(enroll))
        .route("/api/v1/agents/heartbeat", post(agent_heartbeat))
        .route("/api/v1/agents/gaps", post(report_gaps))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{agent_id}", get(agent_status))
        .route("/api/v1/coverage/gaps", get(coverage_gaps))
        .route("/api/v1/intel/indicators", post(upsert_indicators))
        .route("/api/v1/intel/hash-hunt", post(hash_hunt))
        .route("/api/v1/artifacts/{sha256}/prevalence", get(prevalence))
        .route(
            "/api/v1/artifacts/{sha256}/opinion",
            post(set_opinion).get(get_opinion),
        )
        .route(
            "/api/v1/artifacts/{sha256}/opinion/history",
            get(opinion_history),
        )
        .route("/api/v1/search", get(rarity_search))
        .route("/api/v1/hunts/droppers", post(dropper_hunt))
        .route("/api/v1/triggers", post(create_trigger).get(list_triggers))
        .route("/api/v1/triggers/{trigger_id}/test", post(test_trigger))
        .route(
            "/api/v1/artifacts/{sha256}/detonate",
            post(detonate_artifact),
        )
        .route("/api/v1/openapi.json", get(openapi_spec))
        .route("/api/v1/investigate", get(investigate))
        .route("/api/v1/detections", get(list_detections))
        .route("/api/v1/continuous", get(list_continuous))
        .route("/api/v1/metrics", get(platform_metrics))
        .route("/mcp", post(mcp_endpoint))
        .layer(middleware::from_fn_with_state(state.clone(), admin_gate))
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024))
        .with_state(state);

    // mTLS agent listener (M6): /agents/* + authenticated ingest behind
    // required client certificates.
    {
        let agent_pool = pool.clone();
        let agent_cas = std::sync::Arc::new(FsCas::new(&cas_root)?);
        let agent_ca = ca.clone();
        let agent_listen = agent_listen.clone();
        let agent_auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_agent_listener(&agent_listen, agent_ca, agent_pool, agent_cas, agent_auth).await
            {
                tracing::error!(error = %e, "mTLS agent listener failed");
            }
        });
    }

    // Trigger outbox delivery loop (M5): poll due rows, POST with HMAC.
    {
        let delivery_pool = pool.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = corpus_core::triggers::deliver_pending(&delivery_pool).await {
                    tracing::warn!(error = %e, "trigger delivery sweep failed");
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }

    // Durable hunt worker: claim queued jobs (covers continuous re-analysis
    // enqueues that lost their spawn, and multi-node claim).
    {
        let worker_pool = pool.clone();
        let worker_cas = std::sync::Arc::new(FsCas::new(&cas_root)?);
        let worker_id = format!("local-{}", uuid::Uuid::new_v4());
        tokio::spawn(async move {
            loop {
                match hunts::claim_next_job(&worker_pool, &worker_id).await {
                    Ok(Some((tenant_id, hunt_id))) => {
                        if let Err(e) =
                            hunts::execute_hunt(&worker_pool, &worker_cas, tenant_id, hunt_id).await
                        {
                            tracing::error!(%hunt_id, error = %e, "hunt worker failed");
                        }
                    }
                    Ok(None) => {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "hunt worker claim failed");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "corpus-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
