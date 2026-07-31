# Corpus

Corpus retains one copy of every unique code-bearing artifact per tenant in a
content-addressed store and keeps an append-only ledger of where and when
those bytes were observed. New intelligence (YARA-X rules, hashes, intel
feeds) is evaluated against bytes retained before it existed, and matches
join back to host occurrences for blast-radius reporting and analyst
workflow.

Apache-2.0.

## Quickstart

```sh
docker compose up -d postgres     # PostgreSQL 16 on :5434
cargo run -p corpus-server        # migrates, serves 127.0.0.1:8080
bash scripts/first-hunt.sh        # import → rule → hunt → report
```

Other demos: `just demo`, `just demo-agent`, `just demo-similarity`,
`just demo-bootstrap`, `just demo-analyst`.

## Architecture

```
endpoint (Linux / Windows)           control plane
┌───────────────────────┐            ┌──────────────────────────────────┐
│ corpus-agent          │            │ corpus-server (axum, /api/v1)    │
│  fanotify / RDCW /    │  REST      │  tenants, enroll/heartbeat/gaps  │
│  poll scan            │──────────▶ │  ingest, rules/bundles, hunts    │
│  capture state mach.  │  mTLS      │  similarity, reports, opinions,  │
│  stable read + spool  │            │  triggers, MCP (read-only)       │
│  SQLite WAL queue     │            │        │          │              │
└───────────────────────┘            │  PostgreSQL 16   filesystem CAS  │
                                     └──────▲───────────────────────────┘
                                            │ REST
                                     corpusctl (import, backfill, OCI,
                                     intel, hunts, reports, opinions,
                                     triggers, search, detonate, MCP)
```

## What it does

| Area | Capabilities |
|---|---|
| **Corpus** | Content-addressed store, multi-tenant, announce-before-upload with server rehash, YARA-X immutable bundles, watermarked retro-hunts, scan cache, blast-radius |
| **Continuous re-analysis** | Activating a bundle enqueues a full retro-hunt over retained history; sha256 intel IOCs auto hash-hunt; durable hunt worker |
| **Autonomous detection** | Forward coverage and retro matches write `detection_event` rows (severity, optional MITRE heuristic) without a prior external alert |
| **Investigation** | `corpusctl investigate --sha256\|--hunt` → campaign report: detections, blast radius + variants, MITRE labels, recommended actions |
| **Agents** | Linux (fanotify + poll) and Windows (user-mode RDCW + USN); mTLS enrollment; encrypted spool; coverage gaps |
| **Similarity** | PE/ELF features, ssdeep + banded LSH candidates, typed edges, variant groups; pure-Rust function-level semantic matching (x86-64) |
| **Bootstrap** | Snapshot backfill, OCI import, TAXII / MalwareBazaar intel |
| **Analyst** | Prevalence, rarity search, opinions, webhook triggers, dropper leads, proof-of-absence, read-only MCP, `GET /api/v1/metrics` |
| **Detonation** | Optional CAPEv2 adapter; sample egress off by default |

Corpus is a self-hosted private longitudinal corpus and retro-hunt control plane. Investigation output is API/CLI JSON for tools you already run.

## Security (defaults)

- **Agents:** mTLS on `CORPUS_AGENT_LISTEN` (`:8443`). Legacy agent bearer needs `CORPUS_AGENT_LEGACY_BEARER=1`.
- **Admin API:** loopback may run without a token for demos. Non-loopback binds refuse to start without `CORPUS_ADMIN_TOKEN`. When set, admin routes need `Authorization: Bearer`.
- **MCP:** `CORPUS_MCP_TOKEN` (default `mcp-dev-token` only on loopback; rejected off loopback).
- **Spool:** XChaCha20-Poly1305 at rest; OS key wrap (Keychain / 0600 file).
- **Scans:** out-of-process `corpus-scanner` under seatbelt/landlock by default. Set `CORPUS_SCANNER_TIER=gvisor` on a Linux host with `runsc` for a stronger boundary; `CORPUS_MIN_SCANNER_TIER=gvisor` refuses weaker tiers.

Subprocess + seatbelt/landlock is **not** a hostile-malware boundary. Put the admin listener behind a gateway; the tenant header is not authentication.

Details: [docs/deploy.md](docs/deploy.md), [docs/hardening-decisions.md](docs/hardening-decisions.md).

## Docs

| Doc | Contents |
|---|---|
| [docs/deploy.md](docs/deploy.md) | Env vars, auth policy, first hunt, gVisor, reverse proxy |
| [docs/openapi.json](docs/openapi.json) | HTTP API (`GET /api/v1/openapi.json`) |
| [docs/hardening-decisions.md](docs/hardening-decisions.md) | mTLS, spool crypto, sandbox research |
| [docs/semantic-similarity-design.md](docs/semantic-similarity-design.md) | Function-level matching |
| [docs/detonation-design.md](docs/detonation-design.md) | CAPE adapter |

## Testing

```sh
cargo test --workspace
cargo clippy --all-targets
CORPUS_TEST_DATABASE_URL=postgres://corpus:corpus@127.0.0.1:5434/corpus \
    cargo test --workspace
```

## License

Apache-2.0. See `LICENSE`.
