//! Bounded similarity neighborhood queries for analyst tooling.
//!
//! # Purpose
//!
//! Given a seed artifact (UUID or sha256), return a **small, tenant-scoped
//! subgraph** of typed similarity edges and neighbor digests. This powers
//! the investigation UI and `corpusctl similarity neighborhood`.
//!
//! # Safety invariants
//!
//! - **Tenant isolation:** every SQL predicate includes `tenant_id`. Seeds
//!   that resolve in another tenant return NotFound.
//! - **No sample bytes:** nodes expose `sha256` + class only; edges expose
//!   a stripped `evidence_ref` (scores, pair counts, receipt id) — never
//!   disassembly or raw tokens.
//! - **Hard bounds:** client-requested depth/nodes/edges are clamped to
//!   [`MAX_DEPTH`] / [`MAX_NODES`] / [`MAX_EDGES`]. Oversized JSON responses
//!   fail with BadRequest rather than streaming unbounded graphs.
//!
//! # Traversal
//!
//! BFS from the seed up to `max_depth`. At each node, load undirected
//! neighbors from `similarity_edge` filtered by model version, min score,
//! optional edge-type allowlist, and weak-edge inclusion.
//!
//! Note: `include_weak` controls whether weak edge types appear in the
//! result set at all. Variant **group** expansion is a separate concept
//! (`merges_groups`); neighborhood traversal follows stored edges only.
//!
//! # Determinism
//!
//! Nodes sort by `(depth, sha256, artifact_id)`. Edges sort by
//! `(score desc, edge_type, src_sha, dst_sha)`. Pagination (`offset`/`limit`)
//! applies after sorting so pages are stable.

use crate::error::{Error, Result};
use crate::similarity::model::MODEL_VERSION;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use uuid::Uuid;

/// Hard limits enforced regardless of client request (server-side caps).
pub const MAX_DEPTH: u32 = 4;
pub const MAX_NODES: usize = 256;
pub const MAX_EDGES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Client query parameters for a neighborhood traversal.
#[derive(Debug, Clone, Deserialize)]
pub struct NeighborhoodQuery {
    /// Seed artifact digest (hex sha256) or artifact UUID string.
    pub seed: String,
    /// Edge types to follow (empty = all types).
    #[serde(default)]
    pub edge_types: Vec<String>,
    /// Restrict to a model version (default: current [`MODEL_VERSION`]).
    pub model_version: Option<String>,
    /// Minimum edge score (inclusive).
    #[serde(default)]
    pub min_score: f64,
    /// Traversal depth (0 = seed only). Clamped to [`MAX_DEPTH`].
    #[serde(default = "default_depth")]
    pub max_depth: u32,
    /// Maximum nodes in the response. Clamped to [`MAX_NODES`].
    #[serde(default = "default_nodes")]
    pub max_nodes: usize,
    /// Maximum edges collected during traversal. Clamped to [`MAX_EDGES`].
    #[serde(default = "default_edges")]
    pub max_edges: usize,
    /// Offset for pagination of the sorted edge list.
    #[serde(default)]
    pub offset: usize,
    /// Page size for edges (after traversal and sort).
    #[serde(default = "default_page")]
    pub limit: usize,
    /// When false, drop weak lead edge types from the graph entirely.
    #[serde(default = "default_true")]
    pub include_weak: bool,
}

fn default_depth() -> u32 {
    1
}
fn default_nodes() -> usize {
    64
}
fn default_edges() -> usize {
    128
}
fn default_page() -> usize {
    50
}
fn default_true() -> bool {
    true
}

/// One artifact in the returned subgraph.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborhoodNode {
    pub artifact_id: Uuid,
    /// Hex-encoded sha256 (never raw bytes).
    pub sha256: String,
    /// Container class (`pe`, `elf`, `macho`, …).
    pub artifact_class: String,
    /// BFS distance from the seed (0 = seed).
    pub depth: u32,
}

/// One typed edge with digests on both endpoints and stripped evidence.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborhoodEdge {
    pub src_artifact: Uuid,
    pub dst_artifact: Uuid,
    pub src_sha256: String,
    pub dst_sha256: String,
    pub edge_type: String,
    pub model_version: String,
    pub score: f64,
    /// Bounded reference only: type, score, matched_pairs, receipt_id, tau.
    pub evidence_ref: serde_json::Value,
}

/// Full neighborhood response with applied limit metadata.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborhoodResponse {
    pub tenant_id: Uuid,
    pub seed_artifact: Uuid,
    pub seed_sha256: String,
    pub model_version: String,
    pub nodes: Vec<NeighborhoodNode>,
    /// Possibly paginated edge page (see query offset/limit).
    pub edges: Vec<NeighborhoodEdge>,
    /// True when node or edge caps stopped expansion early.
    pub truncated: bool,
    pub limits: NeighborhoodLimits,
}

/// Echo of hard caps and the values applied after clamping.
#[derive(Debug, Clone, Serialize)]
pub struct NeighborhoodLimits {
    pub max_depth: u32,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_response_bytes: usize,
    pub applied_depth: u32,
    pub applied_nodes: usize,
    pub applied_edges: usize,
}

/// Execute a bounded neighborhood query for `tenant`.
///
/// Resolves the seed, BFS-expands, sorts deterministically, pages edges,
/// then rejects responses larger than [`MAX_RESPONSE_BYTES`].
pub async fn query(
    pool: &PgPool,
    tenant: Uuid,
    q: &NeighborhoodQuery,
) -> Result<NeighborhoodResponse> {
    let depth = q.max_depth.min(MAX_DEPTH);
    let max_nodes = q.max_nodes.clamp(1, MAX_NODES);
    let max_edges = q.max_edges.clamp(1, MAX_EDGES);
    let model = q
        .model_version
        .clone()
        .unwrap_or_else(|| MODEL_VERSION.to_string());

    let seed = resolve_seed(pool, tenant, &q.seed).await?;
    let (seed_id, seed_sha, seed_class) = seed;

    let mut nodes: BTreeMap<Uuid, NeighborhoodNode> = BTreeMap::new();
    nodes.insert(
        seed_id,
        NeighborhoodNode {
            artifact_id: seed_id,
            sha256: seed_sha.clone(),
            artifact_class: seed_class,
            depth: 0,
        },
    );

    let mut all_edges: Vec<NeighborhoodEdge> = Vec::new();
    let mut seen_edge_keys: BTreeSet<(Uuid, Uuid, String)> = BTreeSet::new();
    let mut truncated = false;

    let mut frontier: VecDeque<(Uuid, u32)> = VecDeque::new();
    frontier.push_back((seed_id, 0));
    let mut visited: BTreeSet<Uuid> = BTreeSet::new();
    visited.insert(seed_id);

    while let Some((current, d)) = frontier.pop_front() {
        if d >= depth {
            continue;
        }
        let neighbors = load_neighbors(
            pool,
            tenant,
            current,
            &model,
            q.min_score,
            &q.edge_types,
            q.include_weak,
        )
        .await?;

        for (edge, other_id, other_sha, other_class) in neighbors {
            let key = (edge.src_artifact, edge.dst_artifact, edge.edge_type.clone());
            if seen_edge_keys.insert(key) {
                if all_edges.len() < max_edges {
                    all_edges.push(edge);
                } else {
                    truncated = true;
                }
            }

            if !visited.contains(&other_id) {
                if nodes.len() < max_nodes {
                    visited.insert(other_id);
                    nodes.insert(
                        other_id,
                        NeighborhoodNode {
                            artifact_id: other_id,
                            sha256: other_sha,
                            artifact_class: other_class,
                            depth: d + 1,
                        },
                    );
                    frontier.push_back((other_id, d + 1));
                } else {
                    truncated = true;
                }
            }
        }
        if truncated && nodes.len() >= max_nodes && all_edges.len() >= max_edges {
            break;
        }
    }

    // Deterministic ordering.
    let mut node_list: Vec<_> = nodes.into_values().collect();
    node_list.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.sha256.cmp(&b.sha256))
            .then_with(|| a.artifact_id.cmp(&b.artifact_id))
    });
    all_edges.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.edge_type.cmp(&b.edge_type))
            .then_with(|| a.src_sha256.cmp(&b.src_sha256))
            .then_with(|| a.dst_sha256.cmp(&b.dst_sha256))
    });

    let page_end = (q.offset + q.limit).min(all_edges.len());
    let page = if q.offset < all_edges.len() {
        all_edges[q.offset..page_end].to_vec()
    } else {
        Vec::new()
    };

    let resp = NeighborhoodResponse {
        tenant_id: tenant,
        seed_artifact: seed_id,
        seed_sha256: seed_sha,
        model_version: model,
        nodes: node_list,
        edges: page,
        truncated,
        limits: NeighborhoodLimits {
            max_depth: MAX_DEPTH,
            max_nodes: MAX_NODES,
            max_edges: MAX_EDGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            applied_depth: depth,
            applied_nodes: max_nodes,
            applied_edges: max_edges,
        },
    };

    let bytes = serde_json::to_vec(&resp).unwrap_or_default();
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::BadRequest(format!(
            "neighborhood response exceeds {MAX_RESPONSE_BYTES} bytes; reduce depth/nodes"
        )));
    }
    Ok(resp)
}

/// Resolve seed as UUID first, else as hex sha256. Always tenant-scoped.
async fn resolve_seed(pool: &PgPool, tenant: Uuid, seed: &str) -> Result<(Uuid, String, String)> {
    if let Ok(id) = Uuid::parse_str(seed) {
        let row: Option<(Uuid, Vec<u8>, String)> = sqlx::query_as(
            "SELECT id, sha256, artifact_class FROM artifact
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(pool)
        .await?;
        return row
            .map(|(i, s, c)| (i, hex::encode(s), c))
            .ok_or_else(|| Error::NotFound(format!("artifact {seed}")));
    }
    let raw = crate::hash::hex_to_raw(seed)
        .map_err(|_| Error::BadRequest("seed must be sha256 hex or artifact uuid".into()))?;
    let row: Option<(Uuid, Vec<u8>, String)> = sqlx::query_as(
        "SELECT id, sha256, artifact_class FROM artifact
         WHERE tenant_id = $1 AND sha256 = $2",
    )
    .bind(tenant)
    .bind(&raw)
    .fetch_optional(pool)
    .await?;
    row.map(|(i, s, c)| (i, hex::encode(s), c))
        .ok_or_else(|| Error::NotFound(format!("artifact {seed}")))
}

/// Load undirected neighbors of `artifact` under one model version.
///
/// Returns tuples of `(edge, other_id, other_sha_hex, other_class)` with
/// evidence already reduced to a reference object.
async fn load_neighbors(
    pool: &PgPool,
    tenant: Uuid,
    artifact: Uuid,
    model: &str,
    min_score: f64,
    edge_types: &[String],
    include_weak: bool,
) -> Result<Vec<(NeighborhoodEdge, Uuid, String, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        src_artifact: Uuid,
        dst_artifact: Uuid,
        edge_type: String,
        model_version: String,
        score: f64,
        evidence: serde_json::Value,
        other_id: Uuid,
        other_sha: Vec<u8>,
        other_class: String,
        src_sha: Vec<u8>,
        dst_sha: Vec<u8>,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT e.src_artifact, e.dst_artifact, e.edge_type, e.model_version, e.score, e.evidence,
                CASE WHEN e.src_artifact = $2 THEN e.dst_artifact ELSE e.src_artifact END AS other_id,
                oa.sha256 AS other_sha, oa.artifact_class AS other_class,
                sa.sha256 AS src_sha, da.sha256 AS dst_sha
         FROM similarity_edge e
         JOIN artifact sa ON sa.tenant_id = e.tenant_id AND sa.id = e.src_artifact
         JOIN artifact da ON da.tenant_id = e.tenant_id AND da.id = e.dst_artifact
         JOIN artifact oa ON oa.tenant_id = e.tenant_id
              AND oa.id = CASE WHEN e.src_artifact = $2 THEN e.dst_artifact ELSE e.src_artifact END
         WHERE e.tenant_id = $1
           AND (e.src_artifact = $2 OR e.dst_artifact = $2)
           AND e.model_version = $3
           AND e.score >= $4
         ORDER BY e.score DESC, e.edge_type, e.src_artifact, e.dst_artifact",
    )
    .bind(tenant)
    .bind(artifact)
    .bind(model)
    .bind(min_score)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::new();
    for r in rows {
        if !edge_types.is_empty() && !edge_types.iter().any(|t| t == &r.edge_type) {
            continue;
        }
        if !include_weak
            && matches!(
                r.edge_type.as_str(),
                "byte_similar" | "shared_provenance" | "semantic_variant_weak"
            )
        {
            continue;
        }
        // Evidence reference only — strip bulky nested content if present.
        let evidence_ref = serde_json::json!({
            "edge_type": r.edge_type,
            "model_version": r.model_version,
            "score": r.score,
            "matched_pairs": r.evidence.get("matched_pairs"),
            "receipt_id": r.evidence.get("receipt_id"),
            "tau": r.evidence.get("tau"),
        });
        out.push((
            NeighborhoodEdge {
                src_artifact: r.src_artifact,
                dst_artifact: r.dst_artifact,
                src_sha256: hex::encode(r.src_sha),
                dst_sha256: hex::encode(r.dst_sha),
                edge_type: r.edge_type,
                model_version: r.model_version,
                score: r.score,
                evidence_ref,
            },
            r.other_id,
            hex::encode(r.other_sha),
            r.other_class,
        ));
    }
    Ok(out)
}
