//! Investigation / campaign report: one artifact (or hunt) → full picture
//! for an analyst: detections, blast radius, variants, opinions, findings,
//! and recommended actions. SOC-facing assemble over retained corpus
//! evidence (API/CLI JSON, not a hosted investigation UI).

use crate::dto::{InvestigationReport, RecommendedAction, SeveritySummary};
use crate::error::{Error, Result};
use crate::report;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

/// Build a campaign-style investigation for one sha256 (endpoint or any
/// committed artifact). Always expands variants for blast radius.
pub async fn by_sha256(
    pool: &PgPool,
    tenant_id: Uuid,
    sha256: &str,
) -> Result<InvestigationReport> {
    let raw = crate::hash::hex_to_raw(sha256)
        .map_err(|_| Error::BadRequest("invalid sha256 hex".into()))?;
    let row: Option<(Uuid, String, i64, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, artifact_class, size_bytes, scope, first_committed_at
         FROM artifact
         WHERE tenant_id = $1 AND sha256 = $2 AND storage_state = 'committed'",
    )
    .bind(tenant_id)
    .bind(&raw)
    .fetch_optional(pool)
    .await?;
    let (artifact_id, class, size, scope, first_committed) =
        row.ok_or_else(|| Error::NotFound(format!("artifact {sha256}")))?;

    let blast = report::by_sha256(pool, tenant_id, sha256, true).await?;
    let detections = crate::detect::for_artifact(pool, tenant_id, artifact_id, 50).await?;
    let opinion = crate::opinions::current_opinion(pool, tenant_id, artifact_id)
        .await?
        .map(|o| o.opinion.clone());
    let prevalence = crate::analyst::prevalence_for(pool, tenant_id, artifact_id).await?;
    let variants = crate::similarity::edges::variants_view(pool, tenant_id, sha256)
        .await?
        .unwrap_or(crate::dto::VariantsResponse {
            artifact_id,
            sha256: sha256.to_string(),
            group_id: None,
            members: vec![],
        });

    let mut mitre: Vec<String> = detections
        .iter()
        .flat_map(|d| d.mitre_techniques.clone())
        .collect();
    for a in &blast.artifacts {
        for f in &a.findings {
            mitre.extend(crate::detect::heuristic_mitre(&[
                f.category.clone(),
                f.summary.clone(),
            ]));
        }
        mitre.extend(crate::detect::heuristic_mitre(&a.matched_rules));
    }
    mitre.sort();
    mitre.dedup();

    let severity = summarize_severity(&detections, opinion.as_deref(), &blast);
    let actions = recommend(
        sha256,
        &blast,
        opinion.as_deref(),
        &detections,
        prevalence.host_count,
    );

    let title = if !detections.is_empty() {
        detections[0].title.clone()
    } else if blast.artifacts.iter().any(|a| !a.matched_rules.is_empty()) {
        "Rule match in retained corpus".into()
    } else {
        format!("Investigation: {sha256}")
    };

    let executive_summary = format!(
        "Artifact {} ({class}, {size} bytes, scope={scope}) first committed {}. \
         Seen on {} host(s) / {} path(s). Severity={}. \
         Detections={} rule-matched-artifacts={} variant-members={}.",
        &sha256[..sha256.len().min(16)],
        first_committed.to_rfc3339(),
        prevalence.host_count,
        prevalence.path_count,
        severity.level,
        detections.len(),
        blast
            .artifacts
            .iter()
            .filter(|a| !a.matched_rules.is_empty())
            .count(),
        variants.members.len(),
    );

    Ok(InvestigationReport {
        generated_at: Utc::now(),
        tenant_id,
        title,
        executive_summary,
        severity,
        seed_sha256: sha256.to_string(),
        seed_artifact_id: artifact_id,
        seed_class: class,
        seed_scope: scope,
        first_committed_at: first_committed,
        opinion,
        prevalence: crate::dto::PrevalenceView {
            host_count: prevalence.host_count,
            path_count: prevalence.path_count,
            first_observed: prevalence.first_observed,
            last_observed: prevalence.last_observed,
        },
        detections: detections
            .into_iter()
            .map(|d| crate::dto::DetectionEventView {
                id: d.id,
                source: d.source,
                severity: d.severity,
                title: d.title,
                detail: d.detail,
                mitre_techniques: d.mitre_techniques,
                created_at: d.created_at,
            })
            .collect(),
        mitre_techniques: mitre,
        blast_radius: blast,
        variants,
        recommended_actions: actions,
        verification_state: report::HISTORICAL_OBSERVATION_ONLY.to_string(),
    })
}

/// Investigation seeded by a completed hunt: report + detections for all
/// matched artifacts, actions per host set.
pub async fn by_hunt(pool: &PgPool, tenant_id: Uuid, hunt_id: Uuid) -> Result<InvestigationReport> {
    let blast = report::by_hunt(pool, tenant_id, hunt_id, true).await?;
    let hunt = blast.hunt.clone();
    if blast.artifacts.is_empty() {
        return Ok(InvestigationReport {
            generated_at: Utc::now(),
            tenant_id,
            title: format!("Hunt {hunt_id}: no matches"),
            executive_summary: format!(
                "Hunt {hunt_id} matched no artifacts across the pinned watermark. \
                 Proof-of-absence attestation is included on the blast-radius payload."
            ),
            severity: SeveritySummary {
                level: "info".into(),
                reasons: vec!["no matches".into()],
            },
            seed_sha256: String::new(),
            seed_artifact_id: Uuid::nil(),
            seed_class: String::new(),
            seed_scope: "endpoint".into(),
            first_committed_at: Utc::now(),
            opinion: None,
            prevalence: crate::dto::PrevalenceView {
                host_count: 0,
                path_count: 0,
                first_observed: None,
                last_observed: None,
            },
            detections: vec![],
            mitre_techniques: vec![],
            blast_radius: blast,
            variants: crate::dto::VariantsResponse {
                artifact_id: Uuid::nil(),
                sha256: String::new(),
                group_id: None,
                members: vec![],
            },
            recommended_actions: vec![RecommendedAction {
                action: "none".into(),
                priority: "low".into(),
                detail: "No matched artifacts; retain attestation for the investigation record."
                    .into(),
                host_names: vec![],
                sha256s: vec![],
            }],
            verification_state: report::HISTORICAL_OBSERVATION_ONLY.to_string(),
        });
    }

    // Seed = first matched artifact for a concrete investigation spine.
    let seed = blast.artifacts[0].sha256.clone();
    let mut report = by_sha256(pool, tenant_id, &seed).await?;
    report.title = format!(
        "Hunt {} campaign ({} artifacts)",
        hunt.as_ref().map(|h| h.id.to_string()).unwrap_or_default(),
        report.blast_radius.artifacts.len()
    );
    // Replace blast with hunt-scoped expansion (includes all hunt matches).
    report.blast_radius = blast;
    report.executive_summary = format!(
        "Hunt-driven investigation: {} host(s) touched, {} artifact(s), severity={}.",
        report.blast_radius.hosts.len(),
        report.blast_radius.artifacts.len(),
        report.severity.level
    );
    report.recommended_actions = recommend(
        &seed,
        &report.blast_radius,
        report.opinion.as_deref(),
        &[],
        report.prevalence.host_count,
    );
    Ok(report)
}

fn summarize_severity(
    detections: &[crate::detect::DetectionEvent],
    opinion: Option<&str>,
    blast: &crate::dto::BlastRadiusReport,
) -> SeveritySummary {
    let mut reasons = Vec::new();
    let mut level = "info";
    if detections.iter().any(|d| d.severity == "critical") {
        level = "critical";
        reasons.push("critical detection event".into());
    } else if detections.iter().any(|d| d.severity == "high") || opinion == Some("malicious") {
        level = "high";
        reasons.push("high severity detection or malicious opinion".into());
    } else if detections.iter().any(|d| d.severity == "medium")
        || opinion == Some("suspicious")
        || blast.artifacts.iter().any(|a| !a.matched_rules.is_empty())
    {
        level = "medium";
        reasons.push("rule match or suspicious opinion".into());
    } else if opinion == Some("grayware") || opinion == Some("vulnerable") {
        level = "low";
        reasons.push(format!("opinion={opinion:?}"));
    }
    if blast.hosts.len() > 5 && level != "info" {
        reasons.push(format!("broad host footprint ({})", blast.hosts.len()));
        if level == "medium" {
            level = "high";
        }
    }
    if reasons.is_empty() {
        reasons.push("no elevated signals".into());
    }
    SeveritySummary {
        level: level.into(),
        reasons,
    }
}

fn recommend(
    seed_sha: &str,
    blast: &crate::dto::BlastRadiusReport,
    opinion: Option<&str>,
    detections: &[crate::detect::DetectionEvent],
    host_count: i64,
) -> Vec<RecommendedAction> {
    let mut actions = Vec::new();
    let hosts: Vec<String> = blast.hosts.iter().map(|h| h.host_name.clone()).collect();
    let shas: Vec<String> = blast.artifacts.iter().map(|a| a.sha256.clone()).collect();

    let elevated = opinion == Some("malicious")
        || opinion == Some("suspicious")
        || detections
            .iter()
            .any(|d| matches!(d.severity.as_str(), "high" | "critical"))
        || blast.artifacts.iter().any(|a| !a.matched_rules.is_empty());

    if elevated {
        actions.push(RecommendedAction {
            action: "block_hash".into(),
            priority: "high".into(),
            detail: format!(
                "Block SHA-256 {seed_sha} (and variant group members) in EDR/allowlist controls"
            ),
            host_names: hosts.clone(),
            sha256s: shas.clone(),
        });
        if host_count > 0 {
            actions.push(RecommendedAction {
                action: "contain_hosts".into(),
                priority: "high".into(),
                detail: format!(
                    "Review and contain {} host(s) with historical observations; \
                     verify current-state presence out of band",
                    hosts.len()
                ),
                host_names: hosts.clone(),
                sha256s: shas.clone(),
            });
        }
        actions.push(RecommendedAction {
            action: "detonate".into(),
            priority: "medium".into(),
            detail: "Optional: corpusctl detonate <sha256> if CORPUS_DETONATION_ENABLED and CAPE configured"
                .into(),
            host_names: vec![],
            sha256s: vec![seed_sha.to_string()],
        });
        actions.push(RecommendedAction {
            action: "set_opinion".into(),
            priority: "medium".into(),
            detail: "Confirm human opinion (malicious|suspicious|…) for audit trail".into(),
            host_names: vec![],
            sha256s: vec![seed_sha.to_string()],
        });
    } else {
        actions.push(RecommendedAction {
            action: "monitor".into(),
            priority: "low".into(),
            detail: "No elevated detection; retain in corpus for future continuous re-analysis"
                .into(),
            host_names: hosts,
            sha256s: shas,
        });
    }
    actions
}
