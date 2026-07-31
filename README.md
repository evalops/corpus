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
cargo run -p corpusctl -- import <dir>
just demo                         # end-to-end demos: demo-agent,
                                  # demo-similarity, demo-bootstrap, demo-analyst
```

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

## Features

### Ingest and corpus

- Announce-before-upload ingest with server-side rehash (client hash is a hint).
- Magic-byte classification; content-addressed store; multi-tenant registry
  (slug or UUID header, FK-scoped tables).
- YARA-X rule registry with immutable bundles; retro-hunts pinned to a
  corpus watermark; scan cache
  `(tenant, artifact, bundle digest, engine, config)`.
- Forward coverage and blast-radius JSON. Hunt reruns replay the scan cache
  without rereading bytes; cached terminal states (timeout/error) still count
  toward `timed_out`/`failed`.

### Linux agent

- Enrollment (one-time token → short-lived mTLS client cert).
- YAML policy; checkpointed resumable baseline; fanotify with poll-reconcile
  fallback; stable-read capture state machine; SQLite WAL local state;
  bounded encrypted spool; heartbeats; coverage-gap reporting
  (`TOO_LARGE`, `PERMISSION_DENIED`, `CHANGED_DURING_READ`,
  `SENSOR_OVERFLOW`, …).

### Windows agent (user-mode)

- Poll/reconcile collector; builds on Windows (`x86_64-pc-windows-gnu`
  cross-compile; `windows-latest` CI runs the agent test suite natively).
- **ReadDirectoryChangesW** watcher (recursive; file-name / last-write /
  security) with bounds-checked in-place record parsing. Queue overflow
  becomes a `SENSOR_OVERFLOW` coverage gap.
- **USN change journal** as downtime-recovery signal with a persisted
  `(journal_id, next_usn)` cursor. Journal recreation or a truncated cursor
  forces full reconciliation. Without volume read access, degrades to the
  periodic poll sensor.
- **File identity** via `GetFileInformationByHandle` (volume serial + file
  index) in the stable-read re-stat.
- **ADS** recorded as occurrence provenance (`artifact.provenance.ads`).
- **DPAPI** spool-key wrap (`CryptProtectData`, CurrentUser).
- Shared with Linux: capture state machine, stable read, baseline, mTLS
  enrollment, encrypted spool, heartbeats.

Windows coverage limits:

- No process-execution observation; capture is write-priority
  (close-write / rename). Executed-but-never-written artifacts are captured
  only at write time.
- No kernel minifilter: pre-write and deleted-before-close can race the
  user-mode watcher. Journal + reconcile bounds the loss but does not
  eliminate it.
- USN records are a change signal only (file-reference → path resolution
  is not implemented).
- Stable-read mutation detection is timestamp-limited: NTFS write
  timestamps have ~10–15 ms granularity, so a content-identical rewrite
  within the same tick is undetectable by (size, mtime, index) alone.
- Live-host caveat: RDCW / USN / DPAPI paths are verified by cross-compile,
  unit tests, and `windows-latest` CI. They have not been exercised on a
  staging Windows host outside CI.

### Similarity

Versioned features (PE Authentihash, imphash, ELF build ID, import hashes,
ssdeep-compatible fuzzy digest, entropy, section layout). Typed edges with
evidence and model version (`exact_copy`, `normalized_equivalent`,
`byte_similar`, `shared_provenance`). Deterministic variant groups over
strong edges only — fuzzy never merges groups. CLI: `similar`, `variants`,
`similarity backfill`, `report blast-radius --expand-variants`.

### Semantic similarity

Function-level matching in pure Rust (no Ghidra/JVM). Design notes:
`docs/semantic-similarity-design.md`.

- **Extraction**: ELF `STT_FUNC` symbols, PE x64 `.pdata`, or
  prologue-pattern scan; iced-x86 disassembly.
- **Signatures**: Jaccard similarity over mnemonic-family unigram/bigram
  multisets, instruction-mix histograms, block/call estimates.
  Significance filter (≥5 instructions, no thunks) suppresses stubs.
- **Edges**: `semantic_variant_strong` (bidirectional coverage ≥ 0.60 and
  ≥ 3 matched pairs — merges variant groups), `semantic_variant_weak`
  (≥ 0.35 — leads). Evidence carries the top-5 function pairs with offsets
  and scores.
- **Limits**: x86-64 only; no decompiler; thresholds are hand-set;
  packed/high-entropy code records an `analysis_limitation` instead of an
  edge. Per-function scoring is brute-force per tenant.

Validation corpus (`tests/semantic.rs`, fixtures compiled at test time):
same C source at `-O0`/`-O2`/`-Os` → strong edges + one variant group;
small source tweak → edge with non-identical pair scores; unrelated
program → no edge; high-entropy sample → limitation.

### Vault bootstrap

- **Snapshots**: mount ZFS/btrfs/VSS/Time-Machine snapshots
  oldest-to-newest; `corpusctl backfill --root <dir> --observed-at <ts>
  --host <name>` or `--snapshot-times-file`. Dedup makes repeats cheap;
  occurrence ranges emerge across snapshots.
- **OCI images**: `corpusctl import-oci alpine:3.20` or
  `--from-tar saved.tar`. Image/layer digests land in
  `artifact.provenance`.
- **Intel**: `corpusctl intel taxii --url <srv> --collection <id>
  [--auto-hunt]`, `corpusctl intel malwarebazaar --limit N` (CAS-only,
  never execute, `scope=intel`, no occurrences).
- `artifact.scope` is `'endpoint'` or `'intel'`. Exact-hash hunts run over
  endpoint scope.

### Analyst surface

- Fleet prevalence (host/path counts, first/last seen) on reports,
  `prevalence`, and rarity `search`.
- Append-only human opinions (`TRUSTED` / `GRAYWARE` / `VULNERABLE` /
  `MALICIOUS` / `SUSPICIOUS`) with audit events.
- Webhook triggers (hunt match, malicious/suspicious verdict,
  variant-group join) with HMAC-SHA256-signed delivery outbox.
- Proof-of-absence attestations on no-match reports
  (`0 hits across N artifacts at watermark W`).
- Dropper heuristic (`hunt droppers`): lead generator for low-prevalence
  artifacts whose first observation on a host falls within ±24h
  (configurable) of the seed or its variant group on the same host. Output
  is evidence for an analyst, not a verdict.
- Read-only MCP server (`/mcp`, JSON-RPC, bearer auth).

### Detonation

Dynamic evidence from an external sandbox. Corpus orchestrates; the sandbox
detonates. Static analysis stays the default. Design notes:
`docs/detonation-design.md`.

- **Provider interface** (`DetonationProvider`): `capabilities()`,
  `submit(sample) → job`, `poll(job) → report`.
- **CAPEv2** (self-hosted default): set `CORPUS_CAPE_URL` and
  `CORPUS_CAPE_TOKEN`. Sample egress is off by default — set
  `CORPUS_DETONATION_ENABLED=1` to allow it.
- **Trigger**: `corpusctl detonate <sha256>` (audited), or optional
  auto-submit for suspicious/malicious opinions
  (`CORPUS_DETONATION_AUTO=1`, default off).
- **Evidence**: CAPE signatures/TTPs land as `finding` rows with
  `evidence_type = DYNAMIC_BEHAVIOR` under an `analysis_run`
  (`analyzer_name='cape'`, pinned adapter version). Blast-radius surfaces
  findings alongside matched rules.

## Security posture

Enforced by default:

- **Agent authentication is mTLS.** The server generates a per-deployment
  CA on first run (`corpusctl ca init` prints its fingerprint). Agents
  enroll with a one-time token and receive a short-lived signed client
  cert (30-day TTL; rotatable via `POST /agents/renew`). Agent traffic
  (heartbeats, gaps, artifact ingest) uses a dedicated mTLS listener
  (`CORPUS_AGENT_LISTEN`, default `:8443`) requiring a CA-signed client
  cert. The bearer path requires `CORPUS_AGENT_LEGACY_BEARER=1` and is
  rejected by default. `corpusctl import` remains an unauthenticated
  localhost dev path.
- **Agent spool is encrypted at rest.** XChaCha20-Poly1305, chunked for
  bounded-memory streaming. The key is generated at enrollment and wrapped
  by the macOS Keychain (Linux: 0600 key file; kernel keyring/TPM not
  implemented). Plaintext exists only in memory during upload. Tampered
  chunks fail AEAD verification.
- **Analysis runs out of process.** YARA-X scanning executes in a
  `corpus-scanner` subprocess under an OS sandbox: macOS seatbelt (no
  network, write confinement), Linux landlock (best-effort read-only
  filesystem view). Timeout and output caps are enforced by the parent.
  `CORPUS_SCANNER_TIER=inprocess` restores in-process scanning for local
  dev; `gvisor` is a config tier for Linux hosts with `runsc`.

Production limits you must configure around:

- **Subprocess + seatbelt/landlock is not a hostile-malware boundary**
  (shared kernel, no resource isolation; on macOS the profile does not
  narrow filesystem reads). Scanning hostile samples in production needs
  gVisor (tier 2) or Kata/microVM-class isolation (tier 3, not built).
  See `docs/hardening-decisions.md`.
- The admin/CLI REST surface on `:8080` is unauthenticated beyond the
  tenant header. Bind it to localhost or put it behind a gateway/VPN; the
  tenant header is not a security boundary.
- Enrollment bootstrap (one-time token exchange) happens over the plain
  listener; deliver tokens out of band and bind `:8080` accordingly.

## Limitations

- **Auth**: mTLS for agent traffic is the default. Admin/CLI endpoints and
  MCP remain unauthenticated / static-token — gateway them in production.
- **Analysis isolation**: tier-1 subprocess sandboxing has the limits
  above; the subprocess tier recompiles the bundle per artifact.
- **Scale**: fuzzy-similarity candidates are brute-force per tenant
  (acceptable near 10⁴–10⁵ artifacts). Retro-hunts are synchronous
  single-node. TAXII polling is single-page.
- **fanotify**: `FAN_MOVED_TO` unsupported on mount marks (renames covered
  by reconcile scan); requires `CAP_SYS_ADMIN`. macOS builds use the poll
  sensor only.
- **Spool key wrapping**: Linux uses a 0600 key file; macOS uses the
  Keychain.
- **Similarity**: ssdeep is ppdeep-compatible (pure Rust, not libfuzzy);
  import-hash equality merges variant groups (can over-group same-runtime
  binaries); goblin cannot read macOS chained-fixups imports or
  `LC_CODE_SIGNATURE`.
- **Scope**: retro-hunts enumerate endpoint scope only; similarity
  analyzes all scopes; variant groups may span scopes; intel artifacts
  never gain occurrences.
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

Integration suites cover ingest → hunt → report with cross-tenant
isolation, agent enroll → heartbeat → gaps → dedup, authenticated agent
ingest, similarity, bootstrap importers (mock OCI registry/TAXII), and the
analyst path (prevalence → rarity → opinions/audit → HMAC-verified trigger
delivery → dropper hunt → proof of absence). Demo scripts:
`scripts/demo{,-agent,-similarity,-bootstrap,-analyst}.sh`.

## License

Apache-2.0. See `LICENSE`.
