//! corpus-server: axum REST API owning all writes (spec 8.2).
//!
//! Dev profile: filesystem CAS + PostgreSQL via Docker Compose. Tenants are
//! first-class rows; `X-Corpus-Tenant` accepts a UUID or slug and defaults
//! to the seeded `default` tenant when omitted.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
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
        (status, Json(serde_json::json!({"error": self.0.to_string()}))).into_response()
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

async fn create_tenant(
    State(st): State<AppState>,
    Json(req): Json<TenantCreateRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), AppError> {
    Ok((StatusCode::CREATED, Json(tenant::create_tenant(&st.pool, &req).await?)))
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

/// Ingest authentication: a bearer token means "agent" — the occurrence's
/// agent identity is overwritten from the authenticated identity (agents
/// cannot forge another agent's evidence), and the tenant comes from the
/// agent row. No bearer means the unauthenticated dev path used by
/// `corpusctl import` in local demos.
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
        let ident = corpus_core::agents::authenticate(&st.pool, tok).await?;
        return Ok(IngestAuth::Agent(ident));
    }
    Ok(IngestAuth::Dev(resolve_tenant(&st.pool, headers).await?))
}

fn apply_agent_identity(ident: &corpus_core::agents::AgentIdentity, occ: &mut Option<OccurrenceInfo>) {
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

async fn list_rules(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<RuleResponse>>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(registry::list_rules(&st.pool, t).await?))
}

async fn publish_bundle(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BundlePublishRequest>,
) -> Result<Json<BundleResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(registry::publish_bundle(&st.pool, t, &req.rule_ids, req.activate).await?))
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
    Ok(Json(hunts::create_hunt(&st.pool, t, &req.bundle_digest).await?))
}

async fn list_hunts(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<HuntResponse>>, AppError> {
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

async fn run_hunt(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(hunt_id): Path<Uuid>,
) -> Result<Json<HuntResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(hunts::run_hunt(&st.pool, &st.cas, t, hunt_id).await?))
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
    Ok(Json(corpus_core::agents::enroll(&st.pool, &req).await?))
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
    Ok(Json(corpus_core::agents::agent_status(&st.pool, t, agent_id).await?))
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
        corpus_core::agents::coverage_gaps(&st.pool, t, q.outcome.as_deref(), q.limit.unwrap_or(100))
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
    let upserted = corpus_core::intel::upsert_indicators(&st.pool, t, &req.source, &indicators).await?;
    Ok(Json(IndicatorsUpsertResponse { upserted }))
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

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;
    tracing::info!("migrations applied");
    // Confirm the default tenant is present (seeded by migration).
    let default = tenant::get_tenant(&pool, corpus_core::DEFAULT_TENANT).await?;
    tracing::info!(slug = %default.slug, id = %default.id, "default tenant ready");
    let cas = FsCas::new(&cas_root)?;
    tracing::info!(%cas_root, "filesystem CAS ready (dev profile; not a hostile-sample trust boundary)");

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
        .route("/api/v1/enrollment-tokens", post(create_enrollment_token))
        .route("/api/v1/agents/enroll", post(enroll))
        .route("/api/v1/agents/heartbeat", post(agent_heartbeat))
        .route("/api/v1/agents/gaps", post(report_gaps))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{agent_id}", get(agent_status))
        .route("/api/v1/coverage/gaps", get(coverage_gaps))
        .route("/api/v1/intel/indicators", post(upsert_indicators))
        .route("/api/v1/intel/hash-hunt", post(hash_hunt))
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024))
        .with_state(AppState { pool, cas: std::sync::Arc::new(cas) });

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "corpus-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
