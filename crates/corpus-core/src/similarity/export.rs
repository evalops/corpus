//! Deterministic export of similarity graphs for offline analyst tooling.
//!
//! # Formats
//!
//! | Format | Role |
//! |--------|------|
//! | **JSON** | Canonical interchange (`schema_version: similarity-export:v1`) |
//! | **DOT** | Graphviz-friendly derived view |
//! | **GraphML** | XML graph interchange derived view |
//!
//! JSON is the source of truth for equality tests and re-import. DOT and
//! GraphML are lossy presentations (labels/scores only).
//!
//! # Sources
//!
//! - [`export_neighborhood`] — BFS neighborhood via
//!   [`crate::similarity::neighborhood`].
//! - [`export_group`] — all members of a variant group plus edges whose
//!   both endpoints are members.
//!
//! # Safety
//!
//! Same invariants as neighborhood queries: tenant-scoped, no sample
//! bytes, hard size bound [`MAX_EXPORT_BYTES`]. Node/edge order in JSON
//! is sorted by digests so identical graphs produce identical bytes
//! (modulo `generated_at` on the wrapper).

use crate::error::{Error, Result};
use crate::similarity::model::MODEL_VERSION;
use crate::similarity::neighborhood::{self, NeighborhoodQuery, NeighborhoodResponse};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Maximum serialized body size for any export format (1 MiB).
pub const MAX_EXPORT_BYTES: usize = 1024 * 1024;

/// Supported wire formats for graph export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Canonical pretty-printed JSON document.
    Json,
    /// Graphviz `strict graph` DOT.
    Dot,
    /// GraphML XML.
    GraphMl,
}

impl ExportFormat {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "dot" => Ok(Self::Dot),
            "graphml" | "xml" => Ok(Self::GraphMl),
            other => Err(Error::BadRequest(format!(
                "unknown export format {other:?}; use json|dot|graphml"
            ))),
        }
    }
}

/// Wrapper returned to API/CLI: metadata + rendered body string.
#[derive(Debug, Clone, Serialize)]
pub struct GraphExport {
    /// `json` | `dot` | `graphml`.
    pub format: String,
    pub model_version: String,
    pub tenant_id: Uuid,
    /// Wall-clock generation time (not part of body determinism).
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Rendered document bytes as UTF-8 text.
    pub body: String,
    pub node_count: usize,
    pub edge_count: usize,
    /// Propagated from the underlying neighborhood/group query.
    pub truncated: bool,
}

/// Export a neighborhood (or single-artifact star) in the chosen format.
pub async fn export_neighborhood(
    pool: &PgPool,
    tenant: Uuid,
    q: &NeighborhoodQuery,
    format: ExportFormat,
) -> Result<GraphExport> {
    let graph = neighborhood::query(pool, tenant, q).await?;
    render(tenant, &graph, format)
}

/// Export a variant group as its member graph with intra-group edges only.
///
/// Members are ordered by sha256. Edges are those with both endpoints in
/// the member set (not the full incident star to the rest of the tenant).
pub async fn export_group(
    pool: &PgPool,
    tenant: Uuid,
    group_id: Uuid,
    format: ExportFormat,
) -> Result<GraphExport> {
    let members: Vec<(Uuid, Vec<u8>, String)> = sqlx::query_as(
        "SELECT m.artifact_id, a.sha256, a.artifact_class
         FROM variant_group_member m
         JOIN artifact a ON a.tenant_id = m.tenant_id AND a.id = m.artifact_id
         WHERE m.tenant_id = $1 AND m.group_id = $2
         ORDER BY a.sha256",
    )
    .bind(tenant)
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    if members.is_empty() {
        return Err(Error::NotFound(format!("variant group {group_id}")));
    }

    let ids: Vec<Uuid> = members.iter().map(|m| m.0).collect();
    #[derive(sqlx::FromRow)]
    struct ERow {
        src_artifact: Uuid,
        dst_artifact: Uuid,
        edge_type: String,
        model_version: String,
        score: f64,
        evidence: serde_json::Value,
    }
    let erows: Vec<ERow> = sqlx::query_as(
        "SELECT src_artifact, dst_artifact, edge_type, model_version, score, evidence
         FROM similarity_edge
         WHERE tenant_id = $1
           AND src_artifact = ANY($2)
           AND dst_artifact = ANY($2)
         ORDER BY edge_type, score DESC, src_artifact, dst_artifact",
    )
    .bind(tenant)
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    let sha_map: std::collections::BTreeMap<Uuid, String> = members
        .iter()
        .map(|(id, sha, _)| (*id, hex::encode(sha)))
        .collect();

    let seed = members[0].0;
    let graph = NeighborhoodResponse {
        tenant_id: tenant,
        seed_artifact: seed,
        seed_sha256: sha_map.get(&seed).cloned().unwrap_or_default(),
        model_version: MODEL_VERSION.to_string(),
        nodes: members
            .iter()
            .map(|(id, sha, class)| neighborhood::NeighborhoodNode {
                artifact_id: *id,
                sha256: hex::encode(sha),
                artifact_class: class.clone(),
                depth: 0,
            })
            .collect(),
        edges: erows
            .into_iter()
            .map(|r| neighborhood::NeighborhoodEdge {
                src_artifact: r.src_artifact,
                dst_artifact: r.dst_artifact,
                src_sha256: sha_map.get(&r.src_artifact).cloned().unwrap_or_default(),
                dst_sha256: sha_map.get(&r.dst_artifact).cloned().unwrap_or_default(),
                edge_type: r.edge_type,
                model_version: r.model_version,
                score: r.score,
                evidence_ref: serde_json::json!({
                    "matched_pairs": r.evidence.get("matched_pairs"),
                    "receipt_id": r.evidence.get("receipt_id"),
                    "tau": r.evidence.get("tau"),
                }),
            })
            .collect(),
        truncated: false,
        limits: neighborhood::NeighborhoodLimits {
            max_depth: 0,
            max_nodes: neighborhood::MAX_NODES,
            max_edges: neighborhood::MAX_EDGES,
            max_response_bytes: neighborhood::MAX_RESPONSE_BYTES,
            applied_depth: 0,
            applied_nodes: members.len(),
            applied_edges: 0,
        },
    };
    render(tenant, &graph, format)
}

/// Render a neighborhood response into the chosen format and enforce size.
fn render(tenant: Uuid, graph: &NeighborhoodResponse, format: ExportFormat) -> Result<GraphExport> {
    let body = match format {
        ExportFormat::Json => render_json(graph)?,
        ExportFormat::Dot => render_dot(graph),
        ExportFormat::GraphMl => render_graphml(graph),
    };
    if body.len() > MAX_EXPORT_BYTES {
        return Err(Error::BadRequest(format!(
            "export exceeds {MAX_EXPORT_BYTES} bytes; reduce neighborhood size"
        )));
    }
    Ok(GraphExport {
        format: match format {
            ExportFormat::Json => "json",
            ExportFormat::Dot => "dot",
            ExportFormat::GraphMl => "graphml",
        }
        .into(),
        model_version: graph.model_version.clone(),
        tenant_id: tenant,
        generated_at: chrono::Utc::now(),
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        truncated: graph.truncated,
        body,
    })
}

/// Canonical JSON: sorted nodes/edges, fixed schema_version, no sample bytes.
fn render_json(graph: &NeighborhoodResponse) -> Result<String> {
    #[derive(Serialize)]
    struct Canonical {
        schema_version: &'static str,
        tenant_id: Uuid,
        seed_artifact: Uuid,
        seed_sha256: String,
        model_version: String,
        truncated: bool,
        nodes: Vec<CanonicalNode>,
        edges: Vec<CanonicalEdge>,
    }
    #[derive(Serialize)]
    struct CanonicalNode {
        artifact_id: Uuid,
        sha256: String,
        artifact_class: String,
        depth: u32,
    }
    #[derive(Serialize)]
    struct CanonicalEdge {
        src_artifact: Uuid,
        dst_artifact: Uuid,
        src_sha256: String,
        dst_sha256: String,
        edge_type: String,
        model_version: String,
        score: f64,
        evidence: serde_json::Value,
    }
    let mut nodes: Vec<_> = graph
        .nodes
        .iter()
        .map(|n| CanonicalNode {
            artifact_id: n.artifact_id,
            sha256: n.sha256.clone(),
            artifact_class: n.artifact_class.clone(),
            depth: n.depth,
        })
        .collect();
    nodes.sort_by(|a, b| {
        a.sha256
            .cmp(&b.sha256)
            .then(a.artifact_id.cmp(&b.artifact_id))
    });
    let mut edges: Vec<_> = graph
        .edges
        .iter()
        .map(|e| CanonicalEdge {
            src_artifact: e.src_artifact,
            dst_artifact: e.dst_artifact,
            src_sha256: e.src_sha256.clone(),
            dst_sha256: e.dst_sha256.clone(),
            edge_type: e.edge_type.clone(),
            model_version: e.model_version.clone(),
            score: e.score,
            evidence: e.evidence_ref.clone(),
        })
        .collect();
    edges.sort_by(|a, b| {
        a.src_sha256
            .cmp(&b.src_sha256)
            .then(a.dst_sha256.cmp(&b.dst_sha256))
            .then(a.edge_type.cmp(&b.edge_type))
    });
    let c = Canonical {
        schema_version: "similarity-export:v1",
        tenant_id: graph.tenant_id,
        seed_artifact: graph.seed_artifact,
        seed_sha256: graph.seed_sha256.clone(),
        model_version: graph.model_version.clone(),
        truncated: graph.truncated,
        nodes,
        edges,
    };
    serde_json::to_string_pretty(&c).map_err(|e| Error::BadRequest(format!("json serialize: {e}")))
}

/// Graphviz undirected graph; node labels use first 12 hex chars of sha256.
fn render_dot(graph: &NeighborhoodResponse) -> String {
    let mut out = String::from("strict graph similarity {\n");
    out.push_str("  graph [overlap=false];\n");
    for n in &graph.nodes {
        let short = &n.sha256[..12.min(n.sha256.len())];
        let label = format!("{short}\\n{}", n.artifact_class);
        out.push_str(&format!(
            "  \"{}\" [label=\"{}\", shape=box];\n",
            n.artifact_id,
            escape_dot(&label)
        ));
    }
    for e in &graph.edges {
        out.push_str(&format!(
            "  \"{}\" -- \"{}\" [label=\"{}:{:.2}\"];\n",
            e.src_artifact, e.dst_artifact, e.edge_type, e.score
        ));
    }
    out.push_str("}\n");
    out
}

/// GraphML with keys for sha256, artifact_class, edge_type, score, model.
fn render_graphml(graph: &NeighborhoodResponse) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="sha" for="node" attr.name="sha256" attr.type="string"/>
  <key id="class" for="node" attr.name="artifact_class" attr.type="string"/>
  <key id="etype" for="edge" attr.name="edge_type" attr.type="string"/>
  <key id="score" for="edge" attr.name="score" attr.type="double"/>
  <key id="model" for="edge" attr.name="model_version" attr.type="string"/>
  <graph id="similarity" edgedefault="undirected">
"#,
    );
    for n in &graph.nodes {
        out.push_str(&format!(
            "    <node id=\"{}\">\n      <data key=\"sha\">{}</data>\n      <data key=\"class\">{}</data>\n    </node>\n",
            n.artifact_id,
            xml_escape(&n.sha256),
            xml_escape(&n.artifact_class)
        ));
    }
    for (i, e) in graph.edges.iter().enumerate() {
        out.push_str(&format!(
            "    <edge id=\"e{i}\" source=\"{}\" target=\"{}\">\n      <data key=\"etype\">{}</data>\n      <data key=\"score\">{}</data>\n      <data key=\"model\">{}</data>\n    </edge>\n",
            e.src_artifact,
            e.dst_artifact,
            xml_escape(&e.edge_type),
            e.score,
            xml_escape(&e.model_version)
        ));
    }
    out.push_str("  </graph>\n</graphml>\n");
    out
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::similarity::neighborhood::{NeighborhoodEdge, NeighborhoodLimits, NeighborhoodNode};

    fn sample_graph() -> NeighborhoodResponse {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        NeighborhoodResponse {
            tenant_id: Uuid::from_u128(9),
            seed_artifact: a,
            seed_sha256: "aa".repeat(32),
            model_version: MODEL_VERSION.to_string(),
            nodes: vec![
                NeighborhoodNode {
                    artifact_id: a,
                    sha256: "aa".repeat(32),
                    artifact_class: "elf".into(),
                    depth: 0,
                },
                NeighborhoodNode {
                    artifact_id: b,
                    sha256: "bb".repeat(32),
                    artifact_class: "elf".into(),
                    depth: 1,
                },
            ],
            edges: vec![NeighborhoodEdge {
                src_artifact: a,
                dst_artifact: b,
                src_sha256: "aa".repeat(32),
                dst_sha256: "bb".repeat(32),
                edge_type: "semantic_variant_strong".into(),
                model_version: MODEL_VERSION.to_string(),
                score: 0.9,
                evidence_ref: serde_json::json!({"matched_pairs": 3}),
            }],
            truncated: false,
            limits: NeighborhoodLimits {
                max_depth: 4,
                max_nodes: 256,
                max_edges: 1024,
                max_response_bytes: 512 * 1024,
                applied_depth: 1,
                applied_nodes: 64,
                applied_edges: 128,
            },
        }
    }

    #[test]
    fn json_export_is_deterministic() {
        let g = sample_graph();
        let a = render_json(&g).unwrap();
        let b = render_json(&g).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("similarity-export:v1"));
        assert!(!a.contains("sample_bytes"));
    }

    #[test]
    fn dot_and_graphml_render() {
        let g = sample_graph();
        let dot = render_dot(&g);
        assert!(dot.starts_with("strict graph"));
        let gml = render_graphml(&g);
        assert!(gml.contains("<graphml"));
        assert!(gml.contains("semantic_variant_strong"));
    }
}
