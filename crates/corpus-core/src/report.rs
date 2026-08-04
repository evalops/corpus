//! Blast-radius reporting (spec 17.1).
//!
//! Given a seed artifact (or hunt match set), compute the set of hosts,
//! paths, and related artifacts in scope — the operational "how bad is
//! this?" view. Reports are assembled from occurrences, edges, and group
//! membership without shipping sample bytes to the client.

use crate::dto::{BlastRadiusArtifact, BlastRadiusHost, BlastRadiusOccurrence, BlastRadiusReport};
use crate::error::{Error, Result};
use crate::hunts;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

pub const HISTORICAL_OBSERVATION_ONLY: &str =
    "historical_observation_only: no current-state verification in M0";

#[derive(Debug, sqlx::FromRow)]
struct ArtifactRow {
    id: Uuid,
    sha256: Vec<u8>,
    size_bytes: i64,
    artifact_class: String,
    first_committed_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct OccurrenceRow {
    host_name: String,
    path: Option<String>,
    capture_reason: String,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    process_evidence: Option<serde_json::Value>,
    artifact_sha256: Vec<u8>,
}

async fn attestation_for(
    pool: &PgPool,
    tenant_id: Uuid,
    hunt: &Option<crate::dto::HuntResponse>,
) -> Result<crate::dto::Attestation> {
    // With a hunt, attest against ITS pinned watermark and planned set;
    // otherwise against the current endpoint corpus.
    let (watermark, evaluated) = if let Some(h) = hunt {
        (h.corpus_watermark.unwrap_or(0), h.planned_artifacts)
    } else {
        let w: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM artifact WHERE tenant_id = $1 AND storage_state = 'committed' AND scope = 'endpoint'",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact WHERE tenant_id = $1 AND storage_state = 'committed' AND scope = 'endpoint'",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
        (w, n)
    };
    Ok(crate::dto::Attestation {
        result: "no_match".into(),
        corpus_watermark: watermark,
        artifacts_evaluated: evaluated,
        evaluated_at: Utc::now(),
        scope: "endpoint".into(),
    })
}

async fn build_report(
    pool: &PgPool,
    tenant_id: Uuid,
    query: serde_json::Value,
    hunt: Option<crate::dto::HuntResponse>,
    artifact_ids: &[Uuid],
    matched_rules: &BTreeMap<Uuid, Vec<String>>,
    expand_variants: bool,
) -> Result<BlastRadiusReport> {
    if artifact_ids.is_empty() {
        // Proof of absence (M5): "no match across the complete retained
        // history as of this watermark" is an evidentiary output.
        let attestation = attestation_for(pool, tenant_id, &hunt).await?;
        return Ok(BlastRadiusReport {
            generated_at: Utc::now(),
            tenant_id,
            query,
            hunt,
            artifacts: vec![],
            hosts: vec![],
            occurrences: vec![],
            verification_state: HISTORICAL_OBSERVATION_ONLY.to_string(),
            variant_expansion: None,
            attestation: Some(attestation),
        });
    }

    let artifacts = sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, sha256, size_bytes, artifact_class, first_committed_at
         FROM artifact WHERE tenant_id = $1 AND id = ANY($2) ORDER BY first_committed_at",
    )
    .bind(tenant_id)
    .bind(artifact_ids)
    .fetch_all(pool)
    .await?;

    let occurrences = sqlx::query_as::<_, OccurrenceRow>(
        "SELECT host_name, path, capture_reason, observed_at, received_at, process_evidence, artifact_sha256
         FROM occurrence_event
         WHERE tenant_id = $1 AND artifact_id = ANY($2)
         ORDER BY observed_at",
    )
    .bind(tenant_id)
    .bind(artifact_ids)
    .fetch_all(pool)
    .await?;

    let mut hosts: BTreeMap<String, BlastRadiusHost> = BTreeMap::new();
    for occ in &occurrences {
        let sha_hex = hex::encode(&occ.artifact_sha256);
        let entry = hosts
            .entry(occ.host_name.clone())
            .or_insert_with(|| BlastRadiusHost {
                host_name: occ.host_name.clone(),
                artifact_sha256: vec![],
                paths: vec![],
                first_observed: occ.observed_at,
                last_observed: occ.observed_at,
            });
        if !entry.artifact_sha256.contains(&sha_hex) {
            entry.artifact_sha256.push(sha_hex);
        }
        if let Some(p) = &occ.path {
            if !entry.paths.contains(p) {
                entry.paths.push(p.clone());
            }
        }
        entry.first_observed = entry.first_observed.min(occ.observed_at);
        entry.last_observed = entry.last_observed.max(occ.observed_at);
    }

    let mut artifact_views = Vec::new();
    for a in artifacts {
        let prev = crate::analyst::prevalence_for(pool, tenant_id, a.id).await?;
        let opinion = crate::opinions::current_opinion(pool, tenant_id, a.id)
            .await?
            .map(|o| o.opinion);
        let findings = sqlx::query_as::<_, crate::dto::FindingView>(
            "SELECT evidence_type, category, summary FROM finding WHERE tenant_id = $1 AND artifact_id = $2 ORDER BY created_at LIMIT 50",
        )
        .bind(tenant_id)
        .bind(a.id)
        .fetch_all(pool)
        .await?;
        artifact_views.push(BlastRadiusArtifact {
            artifact_id: a.id,
            sha256: hex::encode(&a.sha256),
            size_bytes: a.size_bytes,
            artifact_class: a.artifact_class,
            first_committed_at: a.first_committed_at,
            matched_rules: matched_rules.get(&a.id).cloned().unwrap_or_default(),
            prevalence: Some(crate::dto::PrevalenceView {
                host_count: prev.host_count,
                path_count: prev.path_count,
                first_observed: prev.first_observed,
                last_observed: prev.last_observed,
            }),
            opinion,
            findings,
        });
    }

    Ok(BlastRadiusReport {
        generated_at: Utc::now(),
        tenant_id,
        query,
        hunt,
        artifacts: artifact_views,
        hosts: hosts.into_values().collect(),
        occurrences: occurrences
            .into_iter()
            .map(|o| BlastRadiusOccurrence {
                artifact_sha256: hex::encode(&o.artifact_sha256),
                host_name: o.host_name,
                path: o.path,
                capture_reason: o.capture_reason,
                observed_at: o.observed_at,
                received_at: o.received_at,
                execution_evidence: o.process_evidence,
            })
            .collect(),
        verification_state: HISTORICAL_OBSERVATION_ONLY.to_string(),
        variant_expansion: if expand_variants {
            Some(expand_variants_for(pool, tenant_id, artifact_ids).await?)
        } else {
            None
        },
        attestation: None,
    })
}

/// Spec 17.1 steps 2-3: resolve matched artifacts through their variant
/// groups (strong edges) and list weak neighbors as clearly labeled leads.
async fn expand_variants_for(
    pool: &PgPool,
    tenant_id: Uuid,
    artifact_ids: &[Uuid],
) -> Result<crate::dto::VariantExpansion> {
    use crate::dto::{
        BlastRadiusArtifact, BlastRadiusOccurrence, SimilarEdgeView, VariantExpansion,
    };
    use crate::similarity::edges;
    use crate::similarity::model::edge_type;

    let mut group_ids: Vec<Uuid> = Vec::new();
    for id in artifact_ids {
        let (_g, members) = edges::group_members(pool, tenant_id, *id).await?;
        for (member, _sha) in members {
            if !artifact_ids.contains(&member) && !group_ids.contains(&member) {
                group_ids.push(member);
            }
        }
    }

    let group_artifacts = sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, sha256, size_bytes, artifact_class, first_committed_at
         FROM artifact WHERE tenant_id = $1 AND id = ANY($2) ORDER BY first_committed_at",
    )
    .bind(tenant_id)
    .bind(&group_ids)
    .fetch_all(pool)
    .await?;
    let group_occurrences = if group_ids.is_empty() {
        vec![]
    } else {
        sqlx::query_as::<_, OccurrenceRow>(
            "SELECT host_name, path, capture_reason, observed_at, received_at, process_evidence, artifact_sha256
             FROM occurrence_event WHERE tenant_id = $1 AND artifact_id = ANY($2) ORDER BY observed_at",
        )
        .bind(tenant_id)
        .bind(&group_ids)
        .fetch_all(pool)
        .await?
    };

    let mut weak_leads = Vec::new();
    for id in artifact_ids {
        for e in edges::edges_for(pool, tenant_id, *id).await? {
            if !matches!(
                e.edge_type.as_str(),
                edge_type::BYTE_SIMILAR | edge_type::SHARED_PROVENANCE | edge_type::SEMANTIC_WEAK
            ) {
                continue;
            }
            let other = if e.src_artifact == *id {
                e.dst_artifact
            } else {
                e.src_artifact
            };
            if artifact_ids.contains(&other) {
                continue;
            }
            let sha: Vec<u8> =
                sqlx::query_scalar("SELECT sha256 FROM artifact WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(other)
                    .fetch_one(pool)
                    .await?;
            weak_leads.push(SimilarEdgeView {
                other_artifact: other,
                other_sha256: hex::encode(sha),
                edge_type: e.edge_type,
                model_version: e.model_version,
                score: e.score,
                evidence: e.evidence,
            });
        }
    }

    Ok(VariantExpansion {
        group_artifacts: group_artifacts
            .into_iter()
            .map(|a| BlastRadiusArtifact {
                artifact_id: a.id,
                sha256: hex::encode(&a.sha256),
                size_bytes: a.size_bytes,
                artifact_class: a.artifact_class,
                first_committed_at: a.first_committed_at,
                matched_rules: vec![],
                prevalence: None,
                opinion: None,
                findings: vec![],
            })
            .collect(),
        group_occurrences: group_occurrences
            .into_iter()
            .map(|o| BlastRadiusOccurrence {
                artifact_sha256: hex::encode(&o.artifact_sha256),
                host_name: o.host_name,
                path: o.path,
                capture_reason: o.capture_reason,
                observed_at: o.observed_at,
                received_at: o.received_at,
                execution_evidence: o.process_evidence,
            })
            .collect(),
        weak_leads,
    })
}

/// Blast radius of every artifact matched by a hunt (spec 17.1 step 1-5).
pub async fn by_hunt(
    pool: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
    expand_variants: bool,
) -> Result<BlastRadiusReport> {
    let hunt = hunts::get_hunt(pool, tenant_id, hunt_id).await?;
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT artifact_id, rule_id FROM hunt_match WHERE tenant_id = $1 AND hunt_id = $2",
    )
    .bind(tenant_id)
    .bind(hunt_id)
    .fetch_all(pool)
    .await?;

    let mut matched_rules: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    for (artifact_id, rule_id) in rows {
        matched_rules.entry(artifact_id).or_default().push(rule_id);
    }
    let artifact_ids: Vec<Uuid> = matched_rules.keys().copied().collect();

    build_report(
        pool,
        tenant_id,
        serde_json::json!({"type": "hunt", "hunt_id": hunt_id}),
        Some(hunt),
        &artifact_ids,
        &matched_rules,
        expand_variants,
    )
    .await
}

/// Blast radius of one exact artifact hash (indexed lookup path).
pub async fn by_sha256(
    pool: &PgPool,
    tenant_id: Uuid,
    sha256_hex: &str,
    expand_variants: bool,
) -> Result<BlastRadiusReport> {
    let raw = crate::hash::hex_to_raw(sha256_hex)
        .map_err(|_| Error::BadRequest(format!("invalid sha256 hex: {sha256_hex:?}")))?;
    let artifact: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM artifact WHERE tenant_id = $1 AND sha256 = $2")
            .bind(tenant_id)
            .bind(&raw)
            .fetch_optional(pool)
            .await?;
    let artifact_ids = artifact.map(|(id,)| vec![id]).unwrap_or_default();
    build_report(
        pool,
        tenant_id,
        serde_json::json!({"type": "sha256", "sha256": sha256_hex}),
        None,
        &artifact_ids,
        &BTreeMap::new(),
        expand_variants,
    )
    .await
}
