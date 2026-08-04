# Architecture

Cross-cutting map of the Corpus control plane. Local module behavior is in
rustdoc; product *why* is in [intent.md](intent.md); guarantees are in
[invariants.md](invariants.md).

## Processes

| Binary | Role | Durable writes |
|--------|------|----------------|
| `corpus-server` | HTTP control plane (axum) | Postgres + filesystem CAS |
| `corpus-agent` | Endpoint observer | Local SQLite WAL + encrypted spool only |
| `corpusctl` | Operator CLI | None (HTTP client) |
| `corpus-scanner` | Out-of-process YARA-X helper | None (stdin/stdout job) |

`corpus-core` is a library: domain logic shared by server and (pure pieces)
by agent/CLI. The server is the only process that commits artifacts.

## Deployment sketch

```text
┌─────────────────────────────┐     mTLS :8443      ┌──────────────────────────────┐
│  corpus-agent (endpoint)    │────────────────────▶│  corpus-server               │
│  sensors → capture → spool  │   enroll on :8080   │  admin/CLI :8080             │
│  SQLite queue               │                     │  agent listener :8443        │
└─────────────────────────────┘                     │         │          │         │
                                                    │    PostgreSQL 16   CAS fs    │
┌─────────────────────────────┐     bearer :8080    │         │          │         │
│  corpusctl / automation     │────────────────────▶│  spawn corpus-scanner       │
└─────────────────────────────┘                     │  optional CAPE / Merlin      │
                                                    └──────────────────────────────┘
```

Listeners (see [ADR-0001](adrs/0001-two-listeners.md)):

- **Admin / CLI** — `CORPUS_LISTEN` (default `127.0.0.1:8080`)
- **Agents (mTLS)** — `CORPUS_AGENT_LISTEN` (default `127.0.0.1:8443`)

## Trust boundaries

| Boundary | Mechanism |
|----------|-----------|
| Admin API | Loopback free for demos; non-loopback requires `CORPUS_ADMIN_TOKEN` |
| Agent API | mTLS with deployment CA; enrollment token is one-time bootstrap |
| Tenant isolation | `tenant_id` on durable rows; `X-Corpus-Tenant` resolves scope (not auth) |
| Sample execution | YARA in `corpus-scanner` under seatbelt/landlock or gVisor tier |
| Sample egress | CAPE detonation off unless `CORPUS_DETONATION_ENABLED=1` |
| Agent host | Observe-only; spool encrypted at rest; no server-pushed commands |

Tenant header selects a tenant; it does **not** authenticate the caller.
Put the admin listener behind a gateway in production ([deploy.md](deploy.md)).

## Planes

### Data plane (ingest)

```text
announce(sha256, size, occurrence?)
    → disposition: already present | need upload
stage(upload_id, bytes)
finalize(upload_id, sha256, …)
    → server rehash (invariant #1)
    → CAS commit objects/{tenant}/{sha256}
    → artifact + occurrence_event + capture_attempt
    → hooks: forward_scan, similarity analyze, optional continuous work
```

Code: `corpus_core::ingest`, `corpus_core::cas`. Protocol: spec 11.1 / 11.2.

### Control plane (rules & hunts)

```text
rule source → create_rule (compile-validate)
    → publish_bundle (immutable digest = sources + compiler config + engine)
    → activate_bundle (pointer for forward coverage)
    → create_hunt / enqueue / execute
          scan_cache key: (artifact, bundle_digest, engine_version)
```

Code: `corpus_core::rules`, `registry`, `scan`, `sandbox`, `hunts`.

Hunt states: `DRAFT → QUEUED → PLANNED → RUNNING → COMPLETED|COMPLETED_PARTIAL|FAILED`.

### Analysis plane (similarity)

Post-ingest (and backfill):

1. **Byte path** — ssdeep, structural hashes, LSH candidates, typed edges  
   (`similarity::extract`, `fuzzy`, `lsh`, `edges`)
2. **Semantic path** — triage → functions → suppress → 1:1 coverage → strong/weak  
   (`semantic::*`, model thresholds in `similarity::model::MODEL_V1`)
3. **Receipts** — content-derived analysis_receipt rows (no sample bytes)

Analyst APIs: neighborhood, export, evidence, cleanup, analyzers.

### Analyst / automation plane

- Prevalence, rarity search, opinions (`analyst`, `opinions`)
- Investigation report assembly (`investigate`)
- Detection events from forward/retro/intel (`detect`, `continuous`)
- Webhook triggers on hunt_match / malicious_verdict / detection_event
  (`triggers`)
- Optional MCP read-only endpoint (`/mcp`)

### Integration plane

| Integration | Direction | Note |
|-------------|-----------|------|
| Merlin | inbound segments/observations | Separate from occurrence ledger |
| OCI | pull layers → ingest blobs | Provenance on artifact |
| CAPE | submit sample → poll report | Findings typed `DYNAMIC_BEHAVIOR` |
| TAXII / hash intel | indicators → exact hash hunt | Continuous when enabled |

## Multi-tenancy

- Default tenant uuid `00000000-0000-0000-0000-000000000001` (slug `default`), seeded by migration
- Missing `X-Corpus-Tenant` → default tenant
- CAS object keys: `objects/{tenant_id}/{sha256_hex}`
- Similarity indexes and edges never query without `tenant_id`

## Storage

| Store | Contents |
|-------|----------|
| PostgreSQL 16 | Catalog, ledger, rules, hunts, similarity, agents, audit |
| Filesystem CAS | Immutable sample bytes under `CORPUS_CAS_ROOT` |
| Agent SQLite | Local capture queue, sensors cursors, sequence |
| Agent spool | Encrypted staged files pending upload |

`CasBackend` trait ([ADR-0007](adrs/0007-filesystem-cas-trait.md)): `FsCas` production, `MemoryCas` tests.

## Crate map

```text
corpus-server  ──uses──▶  corpus-core  ◀──  corpusctl (DTOs, hash, classify)
     │                        ▲
     │ spawns                 │
     ▼                        │
corpus-scanner          corpus-agent (dto + hash + classify only for pure bits)
```

Module index for `corpus-core` is in the crate rustdoc (`lib.rs`).

## Sequence: new file on endpoint

```text
sensor event → agent state enqueue
    → stable_read (retry on mutation)
    → spool encrypt
    → announce / upload / finalize (mTLS)
    → server: artifact committed
    → forward_scan(active bundles)
    → similarity analyze_artifact (+ semantic analyze_and_link)
    → optional detection_event / triggers
```

## Sequence: rule activation

```text
publish_bundle → activate
    → persistent forward hunt for post-commit scans
    → if CORPUS_AUTO_RETRO_ON_ACTIVATE: enqueue full retro-hunt
    → continuous_reanalysis row tracks progress
```

## Related

- [invariants.md](invariants.md)
- [data-model.md](data-model.md)
- [adrs/](adrs/)
- [deploy.md](deploy.md)
