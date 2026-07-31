//! First-class multi-tenant registry.
//!
//! Every write path resolves an active tenant before touching tenant-scoped
//! tables. The well-known default tenant (`DEFAULT_TENANT` / slug `default`)
//! is seeded by migration and used when the client omits `X-Corpus-Tenant`.

use crate::dto::{TenantCreateRequest, TenantResponse};
use crate::error::{Error, Result};
use crate::DEFAULT_TENANT;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Slug rules mirrored by the SQL CHECK constraint.
pub fn validate_slug(slug: &str) -> Result<()> {
    let ok = slug.len() <= 63
        && !slug.is_empty()
        && slug
            .chars()
            .enumerate()
            .all(|(i, c)| match c {
                'a'..='z' | '0'..='9' => true,
                '-' => i > 0 && i + 1 < slug.len(),
                _ => false,
            });
    if ok {
        Ok(())
    } else {
        Err(Error::BadRequest(format!(
            "invalid tenant slug {slug:?}: use lowercase alphanumeric, optional internal hyphens, max 63 chars"
        )))
    }
}

#[derive(Debug, sqlx::FromRow)]
struct TenantRow {
    id: Uuid,
    slug: String,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
}

impl TenantRow {
    fn into_response(self) -> TenantResponse {
        TenantResponse {
            id: self.id,
            slug: self.slug,
            name: self.name,
            status: self.status,
            created_at: self.created_at,
        }
    }
}

/// Create a tenant. Slug must be unique.
pub async fn create_tenant(pool: &PgPool, req: &TenantCreateRequest) -> Result<TenantResponse> {
    let slug = req.slug.trim().to_ascii_lowercase();
    validate_slug(&slug)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(Error::BadRequest("tenant name must not be empty".into()));
    }
    if name.len() > 200 {
        return Err(Error::BadRequest("tenant name too long (max 200)".into()));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let row = sqlx::query_as::<_, TenantRow>(
        "INSERT INTO tenant (id, slug, name, status, created_at)
         VALUES ($1,$2,$3,'active',$4)
         RETURNING id, slug, name, status, created_at",
    )
    .bind(id)
    .bind(&slug)
    .bind(name)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.constraint() == Some("tenant_slug_key") => {
            Error::Conflict(format!("tenant slug {slug:?} already exists"))
        }
        _ => Error::from(e),
    })?;
    Ok(row.into_response())
}

pub async fn list_tenants(pool: &PgPool) -> Result<Vec<TenantResponse>> {
    let rows = sqlx::query_as::<_, TenantRow>(
        "SELECT id, slug, name, status, created_at FROM tenant ORDER BY created_at, slug",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(TenantRow::into_response).collect())
}

pub async fn get_tenant(pool: &PgPool, id: Uuid) -> Result<TenantResponse> {
    let row = sqlx::query_as::<_, TenantRow>(
        "SELECT id, slug, name, status, created_at FROM tenant WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::NotFound(format!("tenant {id}")))?;
    Ok(row.into_response())
}

pub async fn get_tenant_by_slug(pool: &PgPool, slug: &str) -> Result<TenantResponse> {
    let row = sqlx::query_as::<_, TenantRow>(
        "SELECT id, slug, name, status, created_at FROM tenant WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::NotFound(format!("tenant slug {slug:?}")))?;
    Ok(row.into_response())
}

/// Resolve a header value (UUID or slug) or the default tenant, and require
/// that the tenant exists and is `active`.
pub async fn resolve_active_tenant(pool: &PgPool, header: Option<&str>) -> Result<Uuid> {
    let tenant = match header {
        None | Some("") => get_tenant(pool, DEFAULT_TENANT).await?,
        Some(raw) => {
            let s = raw.trim();
            if let Ok(id) = Uuid::parse_str(s) {
                get_tenant(pool, id).await?
            } else {
                get_tenant_by_slug(pool, &s.to_ascii_lowercase()).await?
            }
        }
    };
    if tenant.status != "active" {
        return Err(Error::Forbidden(format!(
            "tenant {} is {}",
            tenant.slug, tenant.status
        )));
    }
    Ok(tenant.id)
}

/// Ensure a tenant row exists (used by tests that mint random tenant ids).
pub async fn ensure_tenant(pool: &PgPool, id: Uuid, slug: &str, name: &str) -> Result<TenantResponse> {
    if let Ok(existing) = get_tenant(pool, id).await {
        return Ok(existing);
    }
    let slug = slug.trim().to_ascii_lowercase();
    validate_slug(&slug)?;
    let now = Utc::now();
    let row = sqlx::query_as::<_, TenantRow>(
        "INSERT INTO tenant (id, slug, name, status, created_at)
         VALUES ($1,$2,$3,'active',$4)
         ON CONFLICT (id) DO UPDATE SET slug = EXCLUDED.slug
         RETURNING id, slug, name, status, created_at",
    )
    .bind(id)
    .bind(&slug)
    .bind(name)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation() {
        assert!(validate_slug("default").is_ok());
        assert!(validate_slug("acme-corp").is_ok());
        assert!(validate_slug("a").is_ok());
        assert!(validate_slug("a1").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("-acme").is_err());
        assert!(validate_slug("acme-").is_err());
        assert!(validate_slug("Acme").is_err());
        assert!(validate_slug("has_underscore").is_err());
        assert!(validate_slug(&"a".repeat(64)).is_err());
    }

    #[test]
    fn default_tenant_id_matches_seed() {
        assert_eq!(
            DEFAULT_TENANT.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
    }
}
