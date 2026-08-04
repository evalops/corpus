//! corpusctl: thin administrative/CLI client. All writes go through the
//! server's REST API; the CLI only classifies, hashes, and uploads bytes.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use corpus_core::classify;
use corpus_core::dto::*;
use corpus_core::hash;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "corpusctl", about = "Corpus platform CLI")]
struct Cli {
    /// Server base URL.
    #[arg(
        long,
        env = "CORPUS_SERVER_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    server: String,

    /// Tenant UUID or slug. Defaults server-side to the seeded `default` tenant
    /// when omitted. Prefer an explicit value for multi-tenant work.
    #[arg(long, env = "CORPUS_TENANT")]
    tenant: Option<String>,

    /// Admin API token (`CORPUS_ADMIN_TOKEN` on the server). Required when
    /// the server enforces admin auth.
    #[arg(long, env = "CORPUS_ADMIN_TOKEN")]
    admin_token: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Tenant registry operations.
    Tenants {
        #[command(subcommand)]
        cmd: TenantsCmd,
    },
    /// Import a directory: classify, hash, announce, upload on
    /// UPLOAD_REQUIRED, finalize. Dedup hits still record occurrences.
    Import {
        dir: String,
        /// Capture reason recorded on occurrences/capture attempts.
        #[arg(long, default_value = "cli_import")]
        capture_reason: String,
    },
    /// Snapshot backfill: import a mounted snapshot with an explicit
    /// (backdated) observed_at. received_at stays truthful.
    /// Run oldest-to-newest across snapshots; dedup makes repeats free.
    Backfill {
        /// Snapshot root to import.
        #[arg(long)]
        root: Option<String>,
        /// When this snapshot was taken (RFC3339). Required with --root.
        #[arg(long)]
        observed_at: Option<chrono::DateTime<chrono::Utc>>,
        /// Host label for occurrences (the snapshotted machine).
        #[arg(long, default_value = "snapshot-host")]
        host: String,
        /// File with one "<dir> <rfc3339>" per line; processed oldest first.
        #[arg(long)]
        snapshot_times_file: Option<String>,
    },
    /// Rule registry operations.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Immutable bundle operations.
    Bundles {
        #[command(subcommand)]
        cmd: BundlesCmd,
    },
    /// Retro-hunt operations.
    Hunts {
        #[command(subcommand)]
        cmd: HuntsCmd,
    },
    /// Reports.
    Report {
        #[command(subcommand)]
        cmd: ReportCmd,
    },
    /// Campaign-style investigation (blast radius + detections + actions).
    Investigate {
        /// Artifact sha256.
        #[arg(long)]
        sha256: Option<String>,
        /// Completed or in-progress hunt id.
        #[arg(long)]
        hunt: Option<Uuid>,
    },
    /// Recent autonomous detection events.
    Detections,
    /// Continuous re-analysis audit log.
    Continuous,
    /// Platform metrics for the resolved tenant.
    Metrics,
    /// Mint one-time agent enrollment tokens.
    EnrollToken {
        #[command(subcommand)]
        cmd: EnrollTokenCmd,
    },
    /// Deployment CA operations (mTLS agent auth).
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// Fleet health (spec 10.11).
    Agents {
        #[command(subcommand)]
        cmd: AgentsCmd,
    },
    /// Coverage reporting.
    Coverage {
        #[command(subcommand)]
        cmd: CoverageCmd,
    },
    /// OCI image ingestion: walk an image's layers via the registry HTTP
    /// API (no docker needed) or a `docker save` tar, and commit
    /// code-bearing files with image provenance.
    ImportOci {
        /// e.g. alpine:3.20 or ghcr.io/org/img:1.0. Omit with --from-tar.
        image_ref: Option<String>,
        /// Offline path: `docker save` output tar.
        #[arg(long)]
        from_tar: Option<String>,
        #[arg(long, default_value = "268435456")]
        max_artifact_bytes: u64,
    },
    /// Intel-corpus connectors (indicators, intel-scope samples).
    Intel {
        #[command(subcommand)]
        cmd: IntelCmd,
    },
    /// Show typed similarity edges for an artifact (spec 16.4).
    Similar { sha256: String },
    /// Show variant-group members for an artifact (spec 16.6).
    Variants { sha256: String },
    /// Similarity maintenance.
    Similarity {
        #[command(subcommand)]
        cmd: SimilarityCmd,
    },
    /// Fleet prevalence for one artifact (hosts, paths, first/last seen).
    Prevalence { sha256: String },
    /// Submit an artifact to the external sandbox (CAPE). Sample egress —
    /// requires server-side detonation config and writes an audit event.
    Detonate { sha256: String },
    /// Rarity hunting over endpoint artifacts.
    Search {
        /// Max distinct hosts an artifact may be seen on.
        #[arg(long, default_value = "5")]
        max_hosts: i64,
        /// Only artifacts observed at/after this time (RFC3339 or 7d/24h/30m).
        #[arg(long)]
        since: Option<String>,
        /// Filter by current opinion (trusted|grayware|vulnerable|malicious|suspicious).
        #[arg(long)]
        opinion: Option<String>,
        #[arg(long, default_value = "100")]
        limit: i64,
    },
    /// Human opinions on artifacts (spec 5.5).
    Opinion {
        #[command(subcommand)]
        cmd: OpinionCmd,
    },
    /// Webhook triggers (hunt_match | malicious_verdict | variant_join).
    Triggers {
        #[command(subcommand)]
        cmd: TriggersCmd,
    },
    /// Targeted analyst hunts.
    Hunt {
        #[command(subcommand)]
        cmd: HuntCmd,
    },
}

#[derive(Subcommand)]
enum OpinionCmd {
    /// Set an opinion (supersedes the current one, audited).
    Set {
        sha256: String,
        /// trusted | grayware | vulnerable | malicious | suspicious
        level: String,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long)]
        actor: Option<String>,
    },
    /// Current opinion for an artifact.
    Get { sha256: String },
    /// Full opinion history (append-only).
    History { sha256: String },
}

#[derive(Subcommand)]
enum TriggersCmd {
    /// Create a webhook trigger. Secret is shown once if not provided.
    Create {
        #[arg(long)]
        name: String,
        /// hunt_match | malicious_verdict | variant_join
        #[arg(long)]
        condition: String,
        #[arg(long)]
        webhook_url: String,
        #[arg(long)]
        secret: Option<String>,
    },
    List,
    /// Queue a signed test event for one trigger.
    Test {
        trigger_id: Uuid,
    },
}

#[derive(Subcommand)]
enum HuntCmd {
    /// Dropper heuristic: low-prevalence artifacts first-observed near
    /// (in time, on the same host) a seed artifact or its variant group.
    /// Lead generator, not a verdict.
    Droppers {
        #[arg(long)]
        sha256: String,
        #[arg(long, default_value = "3")]
        max_hosts: i64,
        #[arg(long, default_value = "24")]
        window_hours: i64,
    },
}

#[derive(Subcommand)]
enum IntelCmd {
    /// Pull recent samples from MalwareBazaar as intel-scope artifacts.
    /// These are LIVE MALWARE: they land in the CAS, never execute them.
    Malwarebazaar {
        #[arg(long, default_value = "10")]
        limit: u32,
        /// API URL override (mock servers in tests/demo).
        #[arg(long)]
        url: Option<String>,
    },
    /// Poll a TAXII 2.1 collection for hash indicators.
    Taxii {
        #[arg(long)]
        url: String,
        #[arg(long)]
        collection: String,
        /// Also run an exact-hash hunt over endpoint-scope artifacts.
        #[arg(long)]
        auto_hunt: bool,
    },
}

#[derive(Subcommand)]
enum SimilarityCmd {
    /// Compute features + edges for artifacts that predate M3a.
    Backfill,
    /// Bounded neighborhood query around an artifact digest or id.
    Neighborhood {
        seed: String,
        #[arg(long)]
        edge_types: Option<String>,
        #[arg(long)]
        model_version: Option<String>,
        #[arg(long, default_value = "0")]
        min_score: f64,
        #[arg(long, default_value = "1")]
        max_depth: u32,
        #[arg(long, default_value = "64")]
        max_nodes: usize,
        #[arg(long, default_value = "128")]
        max_edges: usize,
        #[arg(long, default_value = "false")]
        no_weak: bool,
    },
    /// Export neighborhood or variant group as json|dot|graphml.
    Export {
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        group_id: Option<Uuid>,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = "1")]
        max_depth: u32,
        #[arg(long, default_value = "64")]
        max_nodes: usize,
    },
    /// Explainable function-pair evidence for a semantic edge.
    Evidence {
        artifact_a: Uuid,
        artifact_b: Uuid,
        #[arg(long, default_value = "32")]
        max_pairs: usize,
    },
    /// List registered similarity/semantic analyzers.
    Analyzers,
    /// Dry-run or execute derived-row cleanup for one artifact.
    Cleanup {
        artifact_id: Uuid,
        #[arg(long, default_value = "true")]
        dry_run: bool,
        /// Set to actually delete (requires --dry-run=false).
        #[arg(long, default_value = "false")]
        execute: bool,
    },
}

#[derive(Subcommand)]
enum CaCmd {
    /// Print the deployment CA fingerprint and paths (created on first
    /// server run under CORPUS_CA_DIR, default ./data/ca).
    Init,
}

#[derive(Subcommand)]
enum EnrollTokenCmd {
    /// Create a one-time enrollment token (printed exactly once).
    Create {
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long)]
        ttl_secs: Option<i64>,
    },
}

#[derive(Subcommand)]
enum AgentsCmd {
    List,
    Status { agent_id: Uuid },
}

#[derive(Subcommand)]
enum CoverageCmd {
    /// List capture attempts that ended in a gap outcome (spec 2.2).
    Gaps {
        #[arg(long)]
        outcome: Option<String>,
        #[arg(long, default_value = "100")]
        limit: i64,
    },
}

#[derive(Subcommand)]
enum TenantsCmd {
    /// Create a tenant (slug must be unique, lowercase alphanumeric + hyphens).
    Create {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        name: String,
    },
    /// List all tenants.
    List,
    /// Show one tenant by UUID or slug.
    Get { id_or_slug: String },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Validate-compile and register a single-rule .yar file.
    Add {
        file: String,
    },
    List,
}

#[derive(Subcommand)]
enum BundlesCmd {
    /// Publish an immutable bundle from rule stable ids or UUIDs.
    Publish {
        /// Rule stable ids (names) or UUIDs, in any order.
        #[arg(long = "rule", required = true)]
        rules: Vec<String>,
        /// Activate forward coverage: newly committed artifacts are scanned
        /// with this bundle post-commit (spec 15.9).
        #[arg(long)]
        activate: bool,
    },
    List,
}

#[derive(Subcommand)]
enum HuntsCmd {
    /// Create a DRAFT retro-hunt for a bundle digest.
    Create {
        #[arg(long)]
        bundle: String,
    },
    /// Enqueue a hunt on the server and poll until terminal state.
    /// Pass `--no-wait` to return after enqueue (async).
    Run {
        hunt_id: Uuid,
        /// Return immediately after enqueue; do not poll for completion.
        #[arg(long)]
        no_wait: bool,
        /// Max seconds to wait for completion (default 600).
        #[arg(long, default_value = "600")]
        wait_secs: u64,
    },
    Status {
        hunt_id: Uuid,
    },
    List,
}

#[derive(Subcommand)]
enum ReportCmd {
    /// Blast-radius report: by hunt or by exact artifact hash.
    BlastRadius {
        #[arg(long)]
        hunt: Option<Uuid>,
        #[arg(long)]
        sha256: Option<String>,
        /// Resolve matched artifacts through variant groups and list weak
        /// neighbors as leads (spec 17.1 steps 2-3).
        #[arg(long)]
        expand_variants: bool,
    },
}

struct Client {
    http: reqwest::Client,
    base: String,
    tenant: Option<String>,
    admin_token: Option<String>,
}

impl Client {
    fn new(base: String, tenant: Option<String>, admin_token: Option<String>) -> Self {
        Client {
            http: reqwest::Client::new(),
            base,
            tenant,
            admin_token,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut b = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.tenant {
            b = b.header("x-corpus-tenant", t);
        }
        if let Some(tok) = &self.admin_token {
            b = b.header("authorization", format!("Bearer {tok}"));
        }
        b
    }

    async fn send_raw(&self, rb: reqwest::RequestBuilder) -> Result<(reqwest::StatusCode, String)> {
        let resp = rb.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    async fn send<T: serde::de::DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T> {
        let (status, body) = self.send_raw(rb).await?;
        if !status.is_success() {
            bail!("server returned {status}: {body}");
        }
        serde_json::from_str(&body).with_context(|| format!("decoding response: {body}"))
    }
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into())
}

/// Announce/upload/finalize one file's bytes. Returns (sha256, outcome).
async fn commit_bytes(
    client: &Client,
    bytes: &[u8],
    occ: Option<OccurrenceInfo>,
    scope: Option<&str>,
    provenance: Option<serde_json::Value>,
) -> Result<(String, String)> {
    let sha = hash::sha256_hex(bytes);
    let ann: AnnounceResponse = client
        .send(
            client
                .req(reqwest::Method::POST, "/api/v1/artifacts/announce")
                .json(&AnnounceRequest {
                    sha256: sha.clone(),
                    size_bytes: bytes.len() as i64,
                    occurrence: occ.clone(),
                }),
        )
        .await?;
    match ann.disposition {
        AnnounceDisposition::AlreadyPresent => Ok((sha, "already_present".into())),
        AnnounceDisposition::UploadRequired => {
            let upload_id = ann.upload_id.context("no upload_id in response")?;
            let up = client
                .req(
                    reqwest::Method::PUT,
                    &format!("/api/v1/artifacts/uploads/{upload_id}"),
                )
                .body(bytes.to_vec())
                .send()
                .await?;
            if !up.status().is_success() {
                let s = up.status();
                let body = up.text().await.unwrap_or_default();
                bail!("upload failed: {s}: {body}");
            }
            let _fin: FinalizeResponse = client
                .send(
                    client
                        .req(reqwest::Method::POST, "/api/v1/artifacts/finalize")
                        .json(&FinalizeRequest {
                            upload_id,
                            sha256: sha.clone(),
                            size_bytes: bytes.len() as i64,
                            occurrence: occ,
                            scope: scope.map(|s| s.to_string()),
                            provenance,
                        }),
                )
                .await?;
            Ok((sha, "captured".into()))
        }
        other => Ok((sha, format!("{other:?}"))),
    }
}

async fn report_gap(
    client: &Client,
    host: &str,
    reason: &str,
    outcome: &str,
    path: &str,
    detail: serde_json::Value,
) -> Result<()> {
    client
        .req(reqwest::Method::POST, "/api/v1/agents/gaps")
        .json(&vec![GapEvent {
            observed_at: chrono::Utc::now(),
            capture_reason: reason.to_string(),
            terminal_outcome: outcome.to_string(),
            artifact_sha256: None,
            path: Some(path.to_string()),
            detail_code: None,
            detail: Some(detail),
            host_name: Some(host.to_string()),
        }])
        .send()
        .await?;
    Ok(())
}

async fn cmd_import_oci(
    client: &Client,
    image_ref: Option<String>,
    from_tar: Option<String>,
    max_artifact_bytes: u64,
) -> Result<()> {
    let host = hostname();
    let agent_id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, format!("corpusctl:{host}").as_bytes());
    let boot_id = Uuid::new_v4();
    let mut seq: i64 = 0;

    // (label, image_digest, created, [(layer_digest, entries)])
    type OciJob = (
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Vec<(String, Vec<corpus_core::oci::LayerEntry>)>,
    );
    let mut jobs: Vec<OciJob> = Vec::new();

    match (image_ref, from_tar) {
        (None, Some(tar_path)) => {
            let bytes = std::fs::read(&tar_path).with_context(|| format!("reading {tar_path}"))?;
            let (tags, layers) = corpus_core::oci::walk_docker_save(&bytes)?;
            let label = tags.first().cloned().unwrap_or_else(|| tar_path.clone());
            let mut entries = Vec::new();
            for layer in &layers {
                let digest = format!("sha256:{}", hash::sha256_hex(layer));
                let files = corpus_core::oci::walk_layer(layer, false, max_artifact_bytes)?;
                entries.push((digest, files));
            }
            jobs.push((label, "docker-save".into(), None, entries));
        }
        (Some(image_ref), None) => {
            let iref = corpus_core::oci::parse_image_ref(&image_ref)?;
            let creds = match (
                std::env::var("CORPUS_OCI_USERNAME"),
                std::env::var("CORPUS_OCI_PASSWORD"),
            ) {
                (Ok(u), Ok(p)) => Some((u, p)),
                _ => None,
            };
            let reg = corpus_core::oci::RegistryClient::connect(&iref, creds).await?;
            let resolved = reg.resolve(&iref).await?;
            println!(
                "resolved {} -> {} ({} layers)",
                image_ref,
                resolved.image_digest,
                resolved.layers.len()
            );
            let mut entries = Vec::new();
            for digest in &resolved.layers {
                let layer = reg.layer_bytes(&iref, digest).await?;
                let files = corpus_core::oci::walk_layer(&layer, true, max_artifact_bytes)?;
                entries.push((digest.clone(), files));
            }
            jobs.push((image_ref, resolved.image_digest, resolved.created, entries));
        }
        _ => bail!("provide exactly one of <image-ref> or --from-tar <path>"),
    }

    let mut captured = 0usize;
    let mut dedup = 0usize;
    let mut too_large = 0usize;
    let mut skipped = 0usize;
    for (label, image_digest, created, layers) in &jobs {
        for (layer_digest, files) in layers {
            for f in files {
                seq += 1;
                let path = f.path.clone();
                let Some(bytes) = &f.bytes else {
                    too_large += 1;
                    report_gap(
                        client,
                        label,
                        "oci_image",
                        "TOO_LARGE",
                        &path,
                        serde_json::json!({"size_bytes": f.size, "layer_digest": layer_digest}),
                    )
                    .await?;
                    println!(
                        "TOO_LARGE {} ({} bytes) layer {}",
                        path, f.size, layer_digest
                    );
                    continue;
                };
                // Code-bearing artifacts only (spec 2.3): executables,
                // libraries, scripts. Docs/config are not corpus content.
                let class = corpus_core::classify::classify(bytes);
                if class == corpus_core::classify::ArtifactClass::Unknown {
                    skipped += 1;
                    continue;
                }
                let occ = OccurrenceInfo {
                    host_name: label.clone(),
                    agent_id,
                    boot_id,
                    agent_sequence: seq,
                    path: path.clone(),
                    observed_at: created.unwrap_or_else(chrono::Utc::now),
                    file_size: bytes.len() as i64,
                    file_mtime: None,
                    capture_reason: "oci_image".into(),
                };
                let prov =
                    corpus_core::oci::file_provenance(label, image_digest, layer_digest, &path);
                let (sha, outcome) =
                    commit_bytes(client, bytes, Some(occ), None, Some(prov)).await?;
                if outcome == "captured" {
                    captured += 1;
                } else {
                    dedup += 1;
                }
                println!("{outcome} {sha} {path}");
            }
        }
    }
    println!("oci import complete: {captured} captured, {dedup} already present, {too_large} too large, {skipped} non-code skipped");
    Ok(())
}

/// Options for one import/backfill pass over a directory.
struct ImportOptions {
    capture_reason: String,
    host: Option<String>,
    /// Explicit observed_at (snapshot backfill); None = now.
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn cmd_import(client: &Client, dir: &str, capture_reason: &str) -> Result<()> {
    import_dir(
        client,
        dir,
        &ImportOptions {
            capture_reason: capture_reason.to_string(),
            host: None,
            observed_at: None,
        },
    )
    .await
}

async fn import_dir(client: &Client, dir: &str, opts: &ImportOptions) -> Result<()> {
    let host = opts.host.clone().unwrap_or_else(hostname);
    // M0: agent identity is the importing host. Stable per host, fresh boot
    // id per import run; sequence numbers order the run's events (spec 12.4).
    let agent_id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, format!("corpusctl:{host}").as_bytes());
    let boot_id = Uuid::new_v4();
    let mut captured = 0usize;
    let mut already_present = 0usize;
    let mut failed = 0usize;

    let mut paths: Vec<_> = walkdir::WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    paths.sort();

    for (idx, path) in paths.into_iter().enumerate() {
        let seq = idx as i64 + 1;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("READ_FAILED {} ({e})", path.display());
                failed += 1;
                continue;
            }
        };
        let class = classify::classify(&bytes);
        let sha = hash::sha256_hex(&bytes);
        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .map(chrono::DateTime::<chrono::Utc>::from);
        let occ = OccurrenceInfo {
            host_name: host.clone(),
            agent_id,
            boot_id,
            agent_sequence: seq,
            path: path.display().to_string(),
            observed_at: opts.observed_at.unwrap_or_else(chrono::Utc::now),
            file_size: bytes.len() as i64,
            file_mtime: mtime,
            capture_reason: opts.capture_reason.clone(),
        };

        let announce: AnnounceResponse = client
            .send(
                client
                    .req(reqwest::Method::POST, "/api/v1/artifacts/announce")
                    .json(&AnnounceRequest {
                        sha256: sha.clone(),
                        size_bytes: bytes.len() as i64,
                        occurrence: Some(occ.clone()),
                    }),
            )
            .await?;

        match announce.disposition {
            AnnounceDisposition::AlreadyPresent => {
                println!("ALREADY_PRESENT {sha} {} ({class})", path.display());
                already_present += 1;
            }
            AnnounceDisposition::UploadRequired => {
                let upload_id = announce.upload_id.context("no upload_id in response")?;
                let up = client
                    .req(
                        reqwest::Method::PUT,
                        &format!("/api/v1/artifacts/uploads/{upload_id}"),
                    )
                    .body(bytes.clone())
                    .send()
                    .await?;
                if !up.status().is_success() {
                    let s = up.status();
                    let body = up.text().await.unwrap_or_default();
                    eprintln!("UPLOAD_FAILED {sha} {} ({s}: {body})", path.display());
                    failed += 1;
                    continue;
                }
                let fin: FinalizeResponse = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/artifacts/finalize")
                            .json(&FinalizeRequest {
                                upload_id,
                                sha256: sha.clone(),
                                size_bytes: bytes.len() as i64,
                                occurrence: Some(occ),
                                scope: None,
                                provenance: None,
                            }),
                    )
                    .await?;
                let fwd = if fin.forward_matches.is_empty() {
                    String::new()
                } else {
                    format!(" forward_matches=[{}]", fin.forward_matches.join(","))
                };
                println!("CAPTURED {sha} {} ({class}){fwd}", path.display());
                captured += 1;
            }
            other => {
                println!("{other:?} {sha} {}", path.display());
            }
        }
    }
    println!(
        "import complete: {captured} captured, {already_present} already present, {failed} failed"
    );
    Ok(())
}

async fn resolve_rule_ids(client: &Client, specs: &[String]) -> Result<Vec<Uuid>> {
    let rules: Vec<RuleResponse> = client
        .send(client.req(reqwest::Method::GET, "/api/v1/rules"))
        .await?;
    specs
        .iter()
        .map(|spec| {
            if let Ok(id) = Uuid::parse_str(spec) {
                if rules.iter().any(|r| r.id == id) {
                    return Ok(id);
                }
            }
            rules
                .iter()
                .find(|r| r.stable_id == *spec)
                .map(|r| r.id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown rule {spec:?} (known: {})",
                        rules
                            .iter()
                            .map(|r| r.stable_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new(
        cli.server.trim_end_matches('/').to_string(),
        cli.tenant,
        cli.admin_token,
    );

    match cli.cmd {
        Cmd::Tenants { cmd } => match cmd {
            TenantsCmd::Create { slug, name } => {
                // Tenant create is global; no X-Corpus-Tenant required.
                let bare = Client::new(client.base.clone(), None, client.admin_token.clone());
                let t: TenantResponse = bare
                    .send(
                        bare.req(reqwest::Method::POST, "/api/v1/tenants")
                            .json(&TenantCreateRequest { slug, name }),
                    )
                    .await?;
                println!(
                    "tenant_id: {} slug: {} name: {} status: {}",
                    t.id, t.slug, t.name, t.status
                );
            }
            TenantsCmd::List => {
                let bare = Client::new(client.base.clone(), None, client.admin_token.clone());
                let tenants: Vec<TenantResponse> = bare
                    .send(bare.req(reqwest::Method::GET, "/api/v1/tenants"))
                    .await?;
                for t in tenants {
                    println!("{} {} {} {}", t.id, t.slug, t.status, t.name);
                }
            }
            TenantsCmd::Get { id_or_slug } => {
                let bare = Client::new(client.base.clone(), None, client.admin_token.clone());
                let t: TenantResponse = bare
                    .send(bare.req(
                        reqwest::Method::GET,
                        &format!("/api/v1/tenants/{id_or_slug}"),
                    ))
                    .await?;
                println!("{} {} {} {}", t.id, t.slug, t.status, t.name);
            }
        },

        Cmd::Import {
            dir,
            capture_reason,
        } => cmd_import(&client, &dir, &capture_reason).await?,

        Cmd::ImportOci {
            image_ref,
            from_tar,
            max_artifact_bytes,
        } => {
            cmd_import_oci(&client, image_ref, from_tar, max_artifact_bytes).await?;
        }

        Cmd::Intel { cmd } => match cmd {
            IntelCmd::Malwarebazaar { limit, url } => {
                let api = url.unwrap_or_else(|| corpus_core::intel::MB_API_URL.to_string());
                eprintln!("WARNING: MalwareBazaar samples are LIVE MALWARE. They are committed to the CAS with scope=intel and must never be executed.");
                let hashes = corpus_core::intel::mb_recent_hashes(&api, limit).await?;
                println!("{} samples listed", hashes.len());
                let mut imported = 0usize;
                for sha in &hashes {
                    let zip = corpus_core::intel::mb_fetch_zip(&api, sha).await?;
                    for (name, bytes) in corpus_core::intel::mb_unzip(&zip)? {
                        let prov = serde_json::json!({
                            "source": "malwarebazaar", "sample_sha256": sha, "name": name,
                        });
                        let (got_sha, outcome) =
                            commit_bytes(&client, &bytes, None, Some("intel"), Some(prov)).await?;
                        println!("{outcome} {got_sha} {name} (malwarebazaar, intel-scope)");
                        imported += 1;
                    }
                }
                println!("malwarebazaar import complete: {imported} files, scope=intel, no host occurrences");
            }
            IntelCmd::Taxii {
                url,
                collection,
                auto_hunt,
            } => {
                let api_key = std::env::var("CORPUS_TAXII_API_KEY").ok();
                let bundle = corpus_core::intel::fetch_taxii_indicators(
                    &url,
                    &collection,
                    api_key.as_deref(),
                )
                .await?;
                let iocs = corpus_core::intel::extract_hash_iocs(&bundle);
                println!("{} hash indicators extracted", iocs.len());
                let source = format!("taxii:{url}/{collection}");
                let resp: IndicatorsUpsertResponse = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/intel/indicators")
                            .json(&IndicatorsUpsertRequest {
                                source: source.clone(),
                                indicators: iocs
                                    .iter()
                                    .map(|i| IndicatorInput {
                                        ioc_type: i.ioc_type.clone(),
                                        value: i.value.clone(),
                                        raw: Some(i.raw.clone()),
                                    })
                                    .collect(),
                            }),
                    )
                    .await?;
                println!("upserted {} indicators (source {source})", resp.upserted);
                if auto_hunt {
                    let hashes: Vec<String> = iocs
                        .iter()
                        .filter(|i| i.ioc_type == "sha256")
                        .map(|i| i.value.clone())
                        .collect();
                    let hunt: HashHuntResponse = client
                        .send(
                            client
                                .req(reqwest::Method::POST, "/api/v1/intel/hash-hunt")
                                .json(&HashHuntRequest {
                                    hashes: hashes.clone(),
                                }),
                        )
                        .await?;
                    println!(
                        "hash hunt over endpoint-scope artifacts: {} hashes queried, {} hits",
                        hashes.len(),
                        hunt.hits.len()
                    );
                    for hit in hunt.hits {
                        println!(
                            "HIT {} artifact {} committed {}",
                            hit.value, hit.artifact_id, hit.first_committed_at
                        );
                    }
                }
            }
        },

        Cmd::Backfill {
            root,
            observed_at,
            host,
            snapshot_times_file,
        } => match (root, observed_at, snapshot_times_file) {
            (Some(root), Some(ts), None) => {
                println!("backfilling {root} as of {ts} (host {host})");
                import_dir(
                    &client,
                    &root,
                    &ImportOptions {
                        capture_reason: "historical_backfill".into(),
                        host: Some(host),
                        observed_at: Some(ts),
                    },
                )
                .await?;
            }
            (None, None, Some(file)) => {
                let text =
                    std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
                let mut entries: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
                for (lineno, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (dir, ts) = line.rsplit_once(char::is_whitespace).with_context(|| {
                        format!("line {}: expected '<dir> <rfc3339>'", lineno + 1)
                    })?;
                    let ts = chrono::DateTime::parse_from_rfc3339(ts)
                        .with_context(|| format!("line {}: bad rfc3339 {ts:?}", lineno + 1))?
                        .with_timezone(&chrono::Utc);
                    entries.push((ts, dir.trim().to_string()));
                }
                entries.sort_by_key(|(ts, _)| *ts);
                for (ts, dir) in entries {
                    println!("backfilling {dir} as of {ts} (host {host})");
                    import_dir(
                        &client,
                        &dir,
                        &ImportOptions {
                            capture_reason: "historical_backfill".into(),
                            host: Some(host.clone()),
                            observed_at: Some(ts),
                        },
                    )
                    .await?;
                }
            }
            _ => {
                bail!("use either --root <dir> --observed-at <ts> or --snapshot-times-file <file>")
            }
        },

        Cmd::Rules { cmd } => match cmd {
            RulesCmd::Add { file } => {
                let source =
                    std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
                let rule: RuleResponse = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/rules")
                            .json(&RuleCreateRequest { source }),
                    )
                    .await?;
                println!(
                    "rule_id: {} stable_id: {} state: {}",
                    rule.id, rule.stable_id, rule.state
                );
            }
            RulesCmd::List => {
                let rules: Vec<RuleResponse> = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/rules"))
                    .await?;
                for r in rules {
                    println!("{} {} {} {}", r.id, r.namespace, r.stable_id, r.state);
                }
            }
        },

        Cmd::Bundles { cmd } => match cmd {
            BundlesCmd::Publish { rules, activate } => {
                let rule_ids = resolve_rule_ids(&client, &rules).await?;
                let published: BundlePublishResponse = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/bundles")
                            .json(&BundlePublishRequest { rule_ids, activate }),
                    )
                    .await?;
                let bundle = &published.bundle;
                println!(
                    "bundle_digest: {} rules: {} active: {} engine: {}",
                    bundle.digest, bundle.rule_count, bundle.active, bundle.engine_version
                );
                if let Some(hid) = published.continuous_retro_hunt_id {
                    println!("continuous_retro_hunt_id: {hid}");
                }
            }
            BundlesCmd::List => {
                let bundles: Vec<BundleResponse> = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/bundles"))
                    .await?;
                for b in bundles {
                    println!(
                        "{} rules={} active={} scope={}",
                        b.digest, b.rule_count, b.active, b.scope
                    );
                }
            }
        },

        Cmd::Hunts { cmd } => match cmd {
            HuntsCmd::Create { bundle } => {
                let hunt: HuntResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/hunts").json(
                        &HuntCreateRequest {
                            bundle_digest: bundle,
                        },
                    ))
                    .await?;
                println!("hunt_id: {} state: {}", hunt.id, hunt.state);
            }
            HuntsCmd::Run {
                hunt_id,
                no_wait,
                wait_secs,
            } => {
                let hunt: HuntResponse = client
                    .send(client.req(
                        reqwest::Method::POST,
                        &format!("/api/v1/hunts/{hunt_id}/run"),
                    ))
                    .await?;
                if no_wait {
                    print_hunt(&hunt);
                } else {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
                    let mut hunt = hunt;
                    loop {
                        if matches!(
                            hunt.state.as_str(),
                            "COMPLETED" | "COMPLETED_PARTIAL" | "FAILED"
                        ) {
                            break;
                        }
                        if std::time::Instant::now() > deadline {
                            bail!("hunt {hunt_id} still {} after {wait_secs}s", hunt.state);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        hunt = client
                            .send(
                                client
                                    .req(reqwest::Method::GET, &format!("/api/v1/hunts/{hunt_id}")),
                            )
                            .await?;
                    }
                    print_hunt(&hunt);
                }
            }
            HuntsCmd::Status { hunt_id } => {
                let hunt: HuntResponse = client
                    .send(client.req(reqwest::Method::GET, &format!("/api/v1/hunts/{hunt_id}")))
                    .await?;
                print_hunt(&hunt);
            }
            HuntsCmd::List => {
                let hunts: Vec<HuntResponse> = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/hunts"))
                    .await?;
                for h in hunts {
                    println!(
                        "{} {} {} bundle={} watermark={:?} matched={}",
                        h.id, h.kind, h.state, h.bundle_digest, h.corpus_watermark, h.matched
                    );
                }
            }
        },

        Cmd::Report { cmd } => match cmd {
            ReportCmd::BlastRadius {
                hunt,
                sha256,
                expand_variants,
            } => {
                let path = match (hunt, &sha256) {
                    (Some(id), None) => {
                        format!("/api/v1/reports/blast-radius?hunt_id={id}&expand_variants={expand_variants}")
                    }
                    (None, Some(sha)) => {
                        format!("/api/v1/reports/blast-radius?sha256={sha}&expand_variants={expand_variants}")
                    }
                    _ => bail!("provide exactly one of --hunt or --sha256"),
                };
                let report: BlastRadiusReport =
                    client.send(client.req(reqwest::Method::GET, &path)).await?;
                if let Some(a) = &report.attestation {
                    println!(
                        "NO MATCH: 0 hits across {} artifacts evaluated at corpus watermark {} (scope: {}, evaluated {})",
                        a.artifacts_evaluated, a.corpus_watermark, a.scope, a.evaluated_at
                    );
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },

        Cmd::Investigate { sha256, hunt } => {
            let path = match (sha256, hunt) {
                (Some(sha), None) => format!("/api/v1/investigate?sha256={sha}"),
                (None, Some(id)) => format!("/api/v1/investigate?hunt_id={id}"),
                _ => bail!("provide exactly one of --sha256 or --hunt"),
            };
            let report: InvestigationReport =
                client.send(client.req(reqwest::Method::GET, &path)).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }

        Cmd::Detections => {
            let rows: Vec<DetectionEventView> = client
                .send(client.req(reqwest::Method::GET, "/api/v1/detections"))
                .await?;
            for d in rows {
                println!(
                    "{} {} {} {} {:?}",
                    d.created_at.to_rfc3339(),
                    d.severity,
                    d.source,
                    d.title,
                    d.mitre_techniques
                );
            }
        }

        Cmd::Continuous => {
            let rows: Vec<serde_json::Value> = client
                .send(client.req(reqwest::Method::GET, "/api/v1/continuous"))
                .await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }

        Cmd::Metrics => {
            let m: PlatformMetrics = client
                .send(client.req(reqwest::Method::GET, "/api/v1/metrics"))
                .await?;
            println!("{}", serde_json::to_string_pretty(&m)?);
        }

        Cmd::Similar { sha256 } => {
            let resp: SimilarResponse = client
                .send(client.req(
                    reqwest::Method::GET,
                    &format!("/api/v1/artifacts/{sha256}/similar"),
                ))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Cmd::Variants { sha256 } => {
            let resp: VariantsResponse = client
                .send(client.req(
                    reqwest::Method::GET,
                    &format!("/api/v1/artifacts/{sha256}/variants"),
                ))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Cmd::Similarity { cmd } => match cmd {
            SimilarityCmd::Backfill => {
                let resp: BackfillResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/similarity/backfill"))
                    .await?;
                println!("analyzed: {}", resp.analyzed);
            }
            SimilarityCmd::Neighborhood {
                seed,
                edge_types,
                model_version,
                min_score,
                max_depth,
                max_nodes,
                max_edges,
                no_weak,
            } => {
                let mut url = format!(
                    "/api/v1/similarity/neighborhood?seed={seed}&min_score={min_score}&max_depth={max_depth}&max_nodes={max_nodes}&max_edges={max_edges}&include_weak={}",
                    !no_weak
                );
                if let Some(et) = edge_types {
                    url.push_str(&format!("&edge_types={et}"));
                }
                if let Some(mv) = model_version {
                    url.push_str(&format!("&model_version={mv}"));
                }
                let resp: serde_json::Value = client
                    .send(client.req(reqwest::Method::GET, &url))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            SimilarityCmd::Export {
                seed,
                group_id,
                format,
                max_depth,
                max_nodes,
            } => {
                let mut url = format!(
                    "/api/v1/similarity/export?format={format}&max_depth={max_depth}&max_nodes={max_nodes}"
                );
                if let Some(s) = seed {
                    url.push_str(&format!("&seed={s}"));
                }
                if let Some(g) = group_id {
                    url.push_str(&format!("&group_id={g}"));
                }
                let resp: serde_json::Value = client
                    .send(client.req(reqwest::Method::GET, &url))
                    .await?;
                if let Some(body) = resp.get("body").and_then(|b| b.as_str()) {
                    print!("{body}");
                } else {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }
            SimilarityCmd::Evidence {
                artifact_a,
                artifact_b,
                max_pairs,
            } => {
                let url = format!(
                    "/api/v1/similarity/evidence/{artifact_a}/{artifact_b}?max_pairs={max_pairs}"
                );
                let resp: serde_json::Value = client
                    .send(client.req(reqwest::Method::GET, &url))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            SimilarityCmd::Analyzers => {
                let resp: serde_json::Value = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/similarity/analyzers"))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            SimilarityCmd::Cleanup {
                artifact_id,
                dry_run,
                execute,
            } => {
                let dry = if execute { false } else { dry_run };
                let url = format!(
                    "/api/v1/artifacts/{artifact_id}/similarity-cleanup?dry_run={dry}"
                );
                let resp: serde_json::Value = client
                    .send(client.req(reqwest::Method::POST, &url))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        },

        Cmd::Prevalence { sha256 } => {
            let p: serde_json::Value = client
                .send(client.req(
                    reqwest::Method::GET,
                    &format!("/api/v1/artifacts/{sha256}/prevalence"),
                ))
                .await?;
            println!("{}", serde_json::to_string_pretty(&p)?);
        }

        Cmd::Detonate { sha256 } => {
            let resp = client
                .req(
                    reqwest::Method::POST,
                    &format!("/api/v1/artifacts/{sha256}/detonate"),
                )
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                bail!("detonation failed: {status}: {body}");
            }
            let v: serde_json::Value = serde_json::from_str(&body)?;
            println!("analysis_run: {}", v["analysis_run_id"]);
            println!("findings (DYNAMIC_BEHAVIOR): {}", v["finding_count"]);
            for f in v["findings"].as_array().unwrap_or(&vec![]) {
                println!(
                    "  [{}] {}",
                    f["category"].as_str().unwrap_or("-"),
                    f["summary"].as_str().unwrap_or("-")
                );
            }
        }

        Cmd::Search {
            max_hosts,
            since,
            opinion,
            limit,
        } => {
            let mut path = format!("/api/v1/search?max_hosts={max_hosts}&limit={limit}");
            if let Some(s) = &since {
                path.push_str(&format!("&since={s}"));
            }
            if let Some(o) = &opinion {
                path.push_str(&format!("&opinion={o}"));
            }
            let hits: serde_json::Value =
                client.send(client.req(reqwest::Method::GET, &path)).await?;
            println!("{}", serde_json::to_string_pretty(&hits)?);
        }

        Cmd::Opinion { cmd } => match cmd {
            OpinionCmd::Set {
                sha256,
                level,
                reason,
                actor,
            } => {
                let o: serde_json::Value = client
                    .send(
                        client
                            .req(
                                reqwest::Method::POST,
                                &format!("/api/v1/artifacts/{sha256}/opinion"),
                            )
                            .json(&OpinionSetRequest {
                                opinion: level,
                                reason,
                                actor,
                            }),
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&o)?);
            }
            OpinionCmd::Get { sha256 } => {
                let o: serde_json::Value = client
                    .send(client.req(
                        reqwest::Method::GET,
                        &format!("/api/v1/artifacts/{sha256}/opinion"),
                    ))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&o)?);
            }
            OpinionCmd::History { sha256 } => {
                let o: serde_json::Value = client
                    .send(client.req(
                        reqwest::Method::GET,
                        &format!("/api/v1/artifacts/{sha256}/opinion/history"),
                    ))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&o)?);
            }
        },

        Cmd::Triggers { cmd } => match cmd {
            TriggersCmd::Create {
                name,
                condition,
                webhook_url,
                secret,
            } => {
                let resp: TriggerCreateResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/triggers").json(
                        &TriggerCreateRequest {
                            name,
                            condition,
                            webhook_url,
                            secret,
                        },
                    ))
                    .await?;
                println!(
                    "trigger_id: {} condition: {}",
                    resp.trigger.id, resp.trigger.condition
                );
                println!("hmac_secret: {}", resp.hmac_secret);
            }
            TriggersCmd::List => {
                let rows: Vec<TriggerView> = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/triggers"))
                    .await?;
                for r in rows {
                    println!("{} {} {} enabled={}", r.id, r.name, r.condition, r.enabled);
                }
            }
            TriggersCmd::Test { trigger_id } => {
                client
                    .req(
                        reqwest::Method::POST,
                        &format!("/api/v1/triggers/{trigger_id}/test"),
                    )
                    .send()
                    .await?;
                println!("test event queued for {trigger_id}");
            }
        },

        Cmd::Hunt { cmd } => match cmd {
            HuntCmd::Droppers {
                sha256,
                max_hosts,
                window_hours,
            } => {
                let resp: serde_json::Value = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/hunts/droppers")
                            .json(&serde_json::json!({
                                "sha256": sha256,
                                "max_hosts": max_hosts,
                                "window_hours": window_hours,
                            })),
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        },

        Cmd::Ca { cmd } => match cmd {
            CaCmd::Init => {
                let ca_dir = std::env::var("CORPUS_CA_DIR").unwrap_or_else(|_| "./data/ca".into());
                let ca = corpus_core::mtls::load_or_create_ca(std::path::Path::new(&ca_dir), &[])?;
                let fp = corpus_core::hash::sha256_hex(ca.cert_pem.as_bytes());
                println!("ca_dir: {}", ca.dir.display());
                println!("ca_fingerprint_sha256: {fp}");
                println!("agents must pin this CA (enrollment delivers it to the agent)");
            }
        },

        Cmd::EnrollToken { cmd } => match cmd {
            EnrollTokenCmd::Create { label, ttl_secs } => {
                let tok: EnrollmentTokenResponse = client
                    .send(
                        client
                            .req(reqwest::Method::POST, "/api/v1/enrollment-tokens")
                            .json(&EnrollmentTokenCreateRequest {
                                label: Some(label),
                                ttl_secs,
                            }),
                    )
                    .await?;
                println!("enrollment_token: {}", tok.token);
                if let Some(exp) = tok.expires_at {
                    println!("expires_at: {exp}");
                }
            }
        },

        Cmd::Agents { cmd } => match cmd {
            AgentsCmd::List => {
                let agents: Vec<AgentStatusResponse> = client
                    .send(client.req(reqwest::Method::GET, "/api/v1/agents"))
                    .await?;
                for a in agents {
                    let hb = a
                        .last_heartbeat_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "never".into());
                    println!(
                        "{} {} v{} baseline={}({:.0}%) queue={:?} spool={:?} sensor={:?} last_heartbeat={}",
                        a.id,
                        a.host_name,
                        a.version,
                        a.baseline_state.as_deref().unwrap_or("-"),
                        a.baseline_percent.unwrap_or(0.0),
                        a.queue_depth,
                        a.spool_bytes,
                        a.sensor,
                        hb
                    );
                }
            }
            AgentsCmd::Status { agent_id } => {
                let a: AgentStatusResponse = client
                    .send(client.req(reqwest::Method::GET, &format!("/api/v1/agents/{agent_id}")))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&a)?);
            }
        },

        Cmd::Coverage { cmd } => match cmd {
            CoverageCmd::Gaps { outcome, limit } => {
                let mut path = format!("/api/v1/coverage/gaps?limit={limit}");
                if let Some(o) = &outcome {
                    path.push_str(&format!("&outcome={o}"));
                }
                let gaps: Vec<CoverageGapRow> =
                    client.send(client.req(reqwest::Method::GET, &path)).await?;
                let empty = gaps.is_empty();
                for g in &gaps {
                    println!(
                        "{} {} {} {} {} {}",
                        g.observed_at.to_rfc3339(),
                        g.terminal_outcome,
                        g.host_name,
                        g.path.as_deref().unwrap_or("-"),
                        g.detail_code.as_deref().unwrap_or(""),
                        g.capture_reason
                    );
                }
                if empty {
                    println!("no coverage gaps recorded");
                }
            }
        },
    }
    Ok(())
}

fn print_hunt(h: &HuntResponse) {
    println!(
        "hunt {} state={} watermark={:?} planned={} scanned={} cache_hits={} matched={} timed_out={} failed={}",
        h.id, h.state, h.corpus_watermark, h.planned_artifacts, h.scanned, h.cache_hits,
        h.matched, h.timed_out, h.failed
    );
}
