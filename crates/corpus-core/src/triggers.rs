//! Outbound triggers for high-signal events.
//!
//! Exactly three condition classes fire triggers:
//!
//! 1. **hunt_match** — a retro or forward scan matched
//! 2. **malicious_verdict** — an opinion or analyzer verdict flipped bad
//! 3. **detection_event** — an autonomous detection was recorded
//!
//! Actions are HMAC-signed webhooks (or future ticket sinks). Secrets stay
//! server-side; payloads never include sample bytes — digests and metadata
//! only.

use crate::error::{Error, Result};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

pub const CONDITION_HUNT_MATCH: &str = "hunt_match";
pub const CONDITION_MALICIOUS_VERDICT: &str = "malicious_verdict";
pub const CONDITION_VARIANT_JOIN: &str = "variant_join";

pub const CONDITIONS: [&str; 3] = [
    CONDITION_HUNT_MATCH,
    CONDITION_MALICIOUS_VERDICT,
    CONDITION_VARIANT_JOIN,
];

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TriggerRow {
    pub id: Uuid,
    pub name: String,
    pub condition: String,
    pub webhook_url: String,
    pub enabled: bool,
    pub created_at: chrono::DateTime<Utc>,
}

pub async fn create_trigger(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    condition: &str,
    webhook_url: &str,
    secret: Option<String>,
) -> Result<(TriggerRow, String)> {
    if !CONDITIONS.contains(&condition) {
        return Err(Error::BadRequest(format!(
            "invalid condition {condition:?}; supported: {}",
            CONDITIONS.join(", ")
        )));
    }
    if !(webhook_url.starts_with("http://") || webhook_url.starts_with("https://")) {
        return Err(Error::BadRequest("webhook_url must be http(s)".into()));
    }
    let id = Uuid::new_v4();
    let secret = secret.unwrap_or_else(|| hex::encode(Uuid::new_v4().into_bytes()));
    let row = sqlx::query_as::<_, TriggerRow>(
        "INSERT INTO trigger_rule (id, tenant_id, name, condition, webhook_url, hmac_secret, enabled, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,true,$7)
         RETURNING id, name, condition, webhook_url, enabled, created_at",
    )
    .bind(id)
    .bind(tenant)
    .bind(name)
    .bind(condition)
    .bind(webhook_url)
    .bind(&secret)
    .bind(Utc::now())
    .fetch_one(pool)
    .await?;
    Ok((row, secret))
}

pub async fn list_triggers(pool: &PgPool, tenant: Uuid) -> Result<Vec<TriggerRow>> {
    let rows = sqlx::query_as::<_, TriggerRow>(
        "SELECT id, name, condition, webhook_url, enabled, created_at FROM trigger_rule
         WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Queue an event for every enabled trigger of this tenant+condition.
pub async fn fire(
    pool: &PgPool,
    tenant: Uuid,
    condition: &str,
    event: serde_json::Value,
) -> Result<usize> {
    let triggers: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM trigger_rule WHERE tenant_id = $1 AND condition = $2 AND enabled",
    )
    .bind(tenant)
    .bind(condition)
    .fetch_all(pool)
    .await?;
    for (trigger_id,) in &triggers {
        sqlx::query(
            "INSERT INTO trigger_outbox (id, tenant_id, trigger_id, event, next_attempt_at, created_at)
             VALUES ($1,$2,$3,$4,$5,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(trigger_id)
        .bind(&event)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    }
    Ok(triggers.len())
}

/// HMAC-SHA256 hex over the body (RFC 2104, no extra dependency).
pub fn hmac_signature(secret: &str, body: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(body);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

/// One delivery sweep: post due outbox rows with the HMAC header, retry
/// with exponential backoff (max 8 attempts).
pub async fn deliver_pending(pool: &PgPool) -> Result<usize> {
    let due: Vec<(Uuid, Uuid, String, String, serde_json::Value, i32)> = sqlx::query_as(
        "SELECT o.id, o.trigger_id, t.webhook_url, t.hmac_secret, o.event, o.attempts
         FROM trigger_outbox o JOIN trigger_rule t ON t.id = o.trigger_id
         WHERE o.delivered_at IS NULL AND o.next_attempt_at <= now()
         ORDER BY o.next_attempt_at
         LIMIT 20",
    )
    .fetch_all(pool)
    .await?;
    let http = reqwest::Client::new();
    let mut delivered = 0;
    for (id, _trigger, url, secret, event, attempts) in due {
        let body = event.to_string();
        let sig = hmac_signature(&secret, body.as_bytes());
        let result = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Corpus-Signature", format!("sha256={sig}"))
            .body(body)
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                sqlx::query("UPDATE trigger_outbox SET delivered_at = now() WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await?;
                delivered += 1;
            }
            other => {
                let err = match other {
                    Ok(resp) => format!("http {}", resp.status()),
                    Err(e) => e.to_string(),
                };
                if attempts + 1 >= 8 {
                    sqlx::query(
                        "UPDATE trigger_outbox SET attempts = attempts + 1, last_error = $2, delivered_at = now() WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&err)
                    .execute(pool)
                    .await?;
                } else {
                    let backoff = (5i64 * 2i64.pow(attempts as u32)).min(300);
                    sqlx::query(
                        "UPDATE trigger_outbox SET attempts = attempts + 1, last_error = $2,
                            next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&err)
                    .bind(backoff)
                    .execute(pool)
                    .await?;
                }
            }
        }
    }
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        assert_eq!(
            hmac_signature("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_is_deterministic_and_key_sensitive() {
        let a = hmac_signature("secret", b"payload");
        let b = hmac_signature("secret", b"payload");
        let c = hmac_signature("other", b"payload");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
