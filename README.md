# Corpus — longitudinal executable corpus & retro-hunt platform

Corpus retains one copy of every unique code-bearing artifact per tenant in a
content-addressed store and keeps an append-only ledger of where and when
those bytes were observed. New intelligence (YARA-X rules, hashes, intel
feeds) is evaluated against bytes retained before it existed, and matches
join back to host occurrences for blast-radius reporting and analyst
workflow.

Status: M0 + M1 + M3a + M4 + M5 merged. Apache-2.0.

> Dev-profile warning: the Compose stack, filesystem CAS, and bearer-token
> agent auth are development conveniences. They are not a safe production
> trust boundary for hostile samples (spec 8.4, invariant #14).

## Quickstart

```sh
docker compose up -d postgres     # PostgreSQL 16 on :5434
cargo run -p corpus-server        # migrates, serves 127.0.0.1:8080
cargo run -p corpusctl -- import <dir>
just demo                         # M0 end-to-end; also demo-agent,
                                  # demo-similarity, demo-bootstrap, demo-analyst
```

## Architecture

```
endpoint (Linux)                     control plane
┌───────────────────────┐            ┌──────────────────────────────────┐
│ corpus-agent          │            │ corpus-server (axum, /api/v1)    │
│  fanotify / poll scan │  REST      │  tenants, enroll/heartbeat/gaps  │
│  capture state mach.  │──────────▶ │  ingest, rules/bundles, hunts    │
│  stable read + spool  │  bearer    │  similarity, reports, opinions,  │
│  SQLite WAL queue     │            │  triggers, MCP (read-only)       │
└───────────────────────┘            │        │          │              │
                                     │  PostgreSQL 16   filesystem CAS  │
                                     └──────▲───────────────────────────┘
                                            │ REST
                                     corpusctl (import, backfill, OCI,
                                     intel, hunts, reports, opinions,
                                     triggers, search, MCP clients)
```

## Feature tour by milestone

- **M0 — corpus proof**: announce-before-upload ingest with server-side
  rehash (client hash is a hint, invariant #1), magic-byte classification,
  YARA-X rule registry with immutable bundles, retro-hunts pinned to a
  corpus watermark, scan cache
  `(tenant, artifact, bundle digest, engine, config)`, forward coverage,
  blast-radius JSON. First-class multi-tenancy (tenant registry, slug or
  UUID header, FK-scoped tables).
- **M1 — Linux agent**: enrollment (one-time token → bearer), YAML policy,
  checkpointed resumable baseline, fanotify sensor with poll-reconcile
  fallback, stable-read capture state machine (OBSERVED → … → COMPLETE or
  GAP_RECORDED), SQLite WAL local state, bounded spool, heartbeats,
  coverage-gap reporting (TOO_LARGE, PERMISSION_DENIED,
  CHANGED_DURING_READ, SENSOR_OVERFLOW, …).
- **M3a — similarity**: versioned features (PE Authentihash, imphash,
  ELF build ID, import hashes, ssdeep-compatible fuzzy digest, entropy,
  section layout), typed edges with evidence + model version
  (`exact_copy`, `normalized_equivalent`, `byte_similar`,
  `shared_provenance`), deterministic variant groups over strong edges
  only — fuzzy never merges groups (28.5). `similar`, `variants`,
  `similarity backfill`, `report blast-radius --expand-variants`.
- **M4 — vault bootstrap**: snapshot backfill with backdated `observed_at`
  (`received_at` stays truthful), OCI image ingestion via the registry
  HTTP API (or `docker save`), MalwareBazaar + TAXII 2.1 intel connectors,
  `artifact.scope` ('endpoint'|'intel'), exact-hash hunts over endpoint
  scope.
- **M5 — analyst surface**: fleet prevalence (host/path counts,
  first/last seen) on reports, `prevalence`, and rarity `search`;
  append-only human opinions (TRUSTED/GRAYWARE/VULNERABLE/MALICIOUS/
  SUSPICIOUS) with audit events; webhook triggers (exactly three
  conditions: hunt match, malicious/suspicious verdict, variant-group
  join) with HMAC-SHA256-signed delivery outbox; proof-of-absence
  attestations on no-match reports ("0 hits across N artifacts at
  watermark W"); dropper heuristic (`hunt droppers` — lead generator, not
  a verdict); read-only MCP server (`/mcp`, JSON-RPC, bearer auth).

## Bootstrapping your vault

- **Snapshots**: mount ZFS/btrfs/VSS/Time-Machine snapshots
  oldest-to-newest; `corpusctl backfill --root <dir> --observed-at <ts>
  --host <name>` or `--snapshot-times-file`. Dedup makes repeats nearly
  free; occurrence ranges emerge across snapshots.
- **OCI images**: `corpusctl import-oci alpine:3.20` or
  `--from-tar saved.tar`. Image/layer digests land in
  `artifact.provenance`; tag history backfills versioned executables.
- **Intel**: `corpusctl intel taxii --url <srv> --collection <id>
  [--auto-hunt]`, `corpusctl intel malwarebazaar --limit N` (live
  malware — CAS-only, never execute, scope=intel, no occurrences).

## Limitations and deviations (consolidated)

- **Auth**: enrollment token → bearer token over plain HTTP; no mTLS
  until M4-hardening. **Not acceptable for hostile-network/production
  use.** Admin/CLI endpoints are unauthenticated beyond the tenant header;
  MCP uses a static env token.
- **Scale**: fuzzy-similarity candidates are brute-force per tenant
  (fine at ~10⁴–10⁵ artifacts; LSH index is follow-up). Retro-hunts are
  synchronous single-node. TAXII polling is single-page.
- **Auth model for ingest**: agent endpoints are bearer-authenticated
  with server-enforced identity; the no-bearer dev path for
  `corpusctl import`/`gaps` remains open in dev.
- **fanotify**: FAN_MOVED_TO unsupported on mount marks (renames covered
  by reconcile scan); requires CAP_SYS_ADMIN (root or privileged
  container); macOS builds run poll-sensor only.
- **Spool** is plaintext with 0600/0700 perms (encryption is M4 scope).
- **Similarity**: ssdeep is ppdeep-compatible (pure Rust port, not
  libfuzzy); import-hash equality merges variant groups (can over-group
  trivial same-runtime binaries); goblin can't read macOS chained-fixups
  imports or LC_CODE_SIGNATURE; BSim/semantic is an unpopulated schema
  slot (no Ghidra/JVM).
- **Scope rules**: retro-hunts enumerate endpoint scope only; similarity
  analyzes all scopes; variant groups may span scopes; intel artifacts
  never gain occurrences.
- **Dropper heuristic** is a lead generator — its output is evidence for
  an analyst, never an automatic verdict.
- Rule lifecycle is compile-validation only (one rule per file);
  bandwidth token buckets are config-only; no management-task channel to
  agents.

## Testing

```sh
cargo test --workspace                                # unit tests, hermetic
cargo clippy --all-targets                            # expected: 0 warnings
CORPUS_TEST_DATABASE_URL=postgres://corpus:corpus@127.0.0.1:5434/corpus \
    cargo test --workspace                            # + real-DB integration tests
```

Integration suites cover ingest→hunt→report with cross-tenant isolation,
agent enroll→heartbeat→gaps→dedup, authenticated agent ingest, similarity
pipeline, bootstrap importers (mock OCI registry/TAXII), and the full
analyst narrative (prevalence → rarity → opinions/audit → HMAC-verified
trigger delivery → dropper hunt → proof of absence). Demo scripts:
`scripts/demo{,-agent,-similarity,-bootstrap,-analyst}.sh`.

## Roadmap (spec 27.1)

- **M2 — Windows beta**: user-mode fallback first, then signed
  minifilter; journal replay, process/image telemetry, packaging.
- **M4 — macOS & v1 hardening**: Endpoint Security extension, mTLS
  enrollment, spool encryption, threat-model review, parser sandbox
  audit, upgrade/rollback, stable APIs.
- **Similarity depth**: Ghidra/BSim semantic plugin slot (schema ready),
  banded LSH for fuzzy candidates, variant-group analyst overrides.
- **Response**: dynamic detonation sandbox, OCSF export, action broker,
  current-state verification (17.2), reference connectors.

## License

Apache-2.0. See `LICENSE`.
