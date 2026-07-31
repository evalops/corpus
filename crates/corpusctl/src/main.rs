//! corpusctl: thin administrative/CLI client. All writes go through the
//! server's REST API; the CLI only classifies, hashes, and uploads bytes.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use corpus_core::classify;
use corpus_core::dto::*;
use corpus_core::hash;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "corpusctl", about = "Corpus platform CLI (Milestone 0)")]
struct Cli {
    /// Server base URL.
    #[arg(long, env = "CORPUS_SERVER_URL", default_value = "http://127.0.0.1:8080")]
    server: String,

    /// Tenant UUID or slug. Defaults server-side to the seeded `default` tenant
    /// when omitted. Prefer an explicit value for multi-tenant work.
    #[arg(long, env = "CORPUS_TENANT")]
    tenant: Option<String>,

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
    /// Mint one-time agent enrollment tokens.
    EnrollToken {
        #[command(subcommand)]
        cmd: EnrollTokenCmd,
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
    /// Show typed similarity edges for an artifact (spec 16.4).
    Similar { sha256: String },
    /// Show variant-group members for an artifact (spec 16.6).
    Variants { sha256: String },
    /// Similarity maintenance.
    Similarity {
        #[command(subcommand)]
        cmd: SimilarityCmd,
    },
}

#[derive(Subcommand)]
enum SimilarityCmd {
    /// Compute features + edges for artifacts that predate M3a.
    Backfill,
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
    Add { file: String },
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
    /// Execute a hunt on the server (single-node, synchronous).
    Run { hunt_id: Uuid },
    Status { hunt_id: Uuid },
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
}

impl Client {
    fn new(base: String, tenant: Option<String>) -> Self {
        Client {
            http: reqwest::Client::new(),
            base,
            tenant,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let b = self.http.request(method, format!("{}{path}", self.base));
        match &self.tenant {
            Some(t) => b.header("x-corpus-tenant", t),
            None => b,
        }
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

async fn cmd_import(client: &Client, dir: &str, capture_reason: &str) -> Result<()> {
    let host = hostname();
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
            observed_at: chrono::Utc::now(),
            file_size: bytes.len() as i64,
            file_mtime: mtime,
            capture_reason: capture_reason.to_string(),
        };

        let announce: AnnounceResponse = client
            .send(client.req(reqwest::Method::POST, "/api/v1/artifacts/announce").json(&AnnounceRequest {
                sha256: sha.clone(),
                size_bytes: bytes.len() as i64,
                occurrence: occ.clone(),
            }))
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
                    .send(client.req(reqwest::Method::POST, "/api/v1/artifacts/finalize").json(&FinalizeRequest {
                        upload_id,
                        sha256: sha.clone(),
                        size_bytes: bytes.len() as i64,
                        occurrence: occ,
                    }))
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
    println!("import complete: {captured} captured, {already_present} already present, {failed} failed");
    Ok(())
}

async fn resolve_rule_ids(client: &Client, specs: &[String]) -> Result<Vec<Uuid>> {
    let rules: Vec<RuleResponse> = client.send(client.req(reqwest::Method::GET, "/api/v1/rules")).await?;
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
    let client = Client::new(cli.server.trim_end_matches('/').to_string(), cli.tenant);

    match cli.cmd {
        Cmd::Tenants { cmd } => match cmd {
            TenantsCmd::Create { slug, name } => {
                // Tenant create is global; no X-Corpus-Tenant required.
                let bare = Client::new(client.base.clone(), None);
                let t: TenantResponse = bare
                    .send(
                        bare.req(reqwest::Method::POST, "/api/v1/tenants")
                            .json(&TenantCreateRequest { slug, name }),
                    )
                    .await?;
                println!("tenant_id: {} slug: {} name: {} status: {}", t.id, t.slug, t.name, t.status);
            }
            TenantsCmd::List => {
                let bare = Client::new(client.base.clone(), None);
                let tenants: Vec<TenantResponse> =
                    bare.send(bare.req(reqwest::Method::GET, "/api/v1/tenants")).await?;
                for t in tenants {
                    println!("{} {} {} {}", t.id, t.slug, t.status, t.name);
                }
            }
            TenantsCmd::Get { id_or_slug } => {
                let bare = Client::new(client.base.clone(), None);
                let t: TenantResponse = bare
                    .send(bare.req(reqwest::Method::GET, &format!("/api/v1/tenants/{id_or_slug}")))
                    .await?;
                println!("{} {} {} {}", t.id, t.slug, t.status, t.name);
            }
        },

        Cmd::Import { dir, capture_reason } => cmd_import(&client, &dir, &capture_reason).await?,

        Cmd::Rules { cmd } => match cmd {
            RulesCmd::Add { file } => {
                let source = std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
                let rule: RuleResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/rules").json(&RuleCreateRequest { source }))
                    .await?;
                println!("rule_id: {} stable_id: {} state: {}", rule.id, rule.stable_id, rule.state);
            }
            RulesCmd::List => {
                let rules: Vec<RuleResponse> =
                    client.send(client.req(reqwest::Method::GET, "/api/v1/rules")).await?;
                for r in rules {
                    println!("{} {} {} {}", r.id, r.namespace, r.stable_id, r.state);
                }
            }
        },

        Cmd::Bundles { cmd } => match cmd {
            BundlesCmd::Publish { rules, activate } => {
                let rule_ids = resolve_rule_ids(&client, &rules).await?;
                let bundle: BundleResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/bundles").json(&BundlePublishRequest {
                        rule_ids,
                        activate,
                    }))
                    .await?;
                println!(
                    "bundle_digest: {} rules: {} active: {} engine: {}",
                    bundle.digest, bundle.rule_count, bundle.active, bundle.engine_version
                );
            }
            BundlesCmd::List => {
                let bundles: Vec<BundleResponse> =
                    client.send(client.req(reqwest::Method::GET, "/api/v1/bundles")).await?;
                for b in bundles {
                    println!("{} rules={} active={} scope={}", b.digest, b.rule_count, b.active, b.scope);
                }
            }
        },

        Cmd::Hunts { cmd } => match cmd {
            HuntsCmd::Create { bundle } => {
                let hunt: HuntResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/hunts").json(&HuntCreateRequest {
                        bundle_digest: bundle,
                    }))
                    .await?;
                println!("hunt_id: {} state: {}", hunt.id, hunt.state);
            }
            HuntsCmd::Run { hunt_id } => {
                let hunt: HuntResponse = client
                    .send(client.req(reqwest::Method::POST, &format!("/api/v1/hunts/{hunt_id}/run")))
                    .await?;
                print_hunt(&hunt);
            }
            HuntsCmd::Status { hunt_id } => {
                let hunt: HuntResponse =
                    client.send(client.req(reqwest::Method::GET, &format!("/api/v1/hunts/{hunt_id}"))).await?;
                print_hunt(&hunt);
            }
            HuntsCmd::List => {
                let hunts: Vec<HuntResponse> =
                    client.send(client.req(reqwest::Method::GET, "/api/v1/hunts")).await?;
                for h in hunts {
                    println!(
                        "{} {} {} bundle={} watermark={:?} matched={}",
                        h.id, h.kind, h.state, h.bundle_digest, h.corpus_watermark, h.matched
                    );
                }
            }
        },

        Cmd::Report { cmd } => match cmd {
            ReportCmd::BlastRadius { hunt, sha256, expand_variants } => {
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
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },

        Cmd::Similar { sha256 } => {
            let resp: SimilarResponse = client
                .send(client.req(reqwest::Method::GET, &format!("/api/v1/artifacts/{sha256}/similar")))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Cmd::Variants { sha256 } => {
            let resp: VariantsResponse = client
                .send(client.req(reqwest::Method::GET, &format!("/api/v1/artifacts/{sha256}/variants")))
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
        },

        Cmd::EnrollToken { cmd } => match cmd {
            EnrollTokenCmd::Create { label, ttl_secs } => {
                let tok: EnrollmentTokenResponse = client
                    .send(client.req(reqwest::Method::POST, "/api/v1/enrollment-tokens").json(
                        &EnrollmentTokenCreateRequest { label: Some(label), ttl_secs },
                    ))
                    .await?;
                println!("enrollment_token: {}", tok.token);
                if let Some(exp) = tok.expires_at {
                    println!("expires_at: {exp}");
                }
            }
        },

        Cmd::Agents { cmd } => match cmd {
            AgentsCmd::List => {
                let agents: Vec<AgentStatusResponse> =
                    client.send(client.req(reqwest::Method::GET, "/api/v1/agents")).await?;
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
