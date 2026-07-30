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

async fn announce(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AnnounceRequest>,
) -> Result<Json<AnnounceResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    Ok(Json(ingest::announce(&st.pool, t, &req).await?))
}

async fn upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(upload_id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    ingest::stage_upload(&st.pool, &st.cas, t, upload_id, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finalize(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FinalizeRequest>,
) -> Result<Json<FinalizeResponse>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
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
}

async fn blast_radius(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlastRadiusQuery>,
) -> Result<Json<BlastRadiusReport>, AppError> {
    let t = resolve_tenant(&st.pool, &headers).await?;
    match (q.hunt_id, q.sha256) {
        (Some(id), None) => Ok(Json(report::by_hunt(&st.pool, t, id).await?)),
        (None, Some(sha)) => Ok(Json(report::by_sha256(&st.pool, t, &sha).await?)),
        _ => Err(Error::BadRequest("provide exactly one of hunt_id or sha256".into()).into()),
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
        .unwrap_or_else(|_| "postgres://corpus:corpus@127.0.0.1:5433/corpus".into());
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
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024))
        .with_state(AppState { pool, cas: std::sync::Arc::new(cas) });

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "corpus-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
