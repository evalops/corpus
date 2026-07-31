# Corpus — longitudinal executable corpus & retro-hunt platform

Corpus retains one copy of every unique code-bearing artifact per tenant in a
content-addressed store and keeps an append-only ledger of where and when
those bytes were observed. New intelligence (YARA-X rules, hashes, intel
feeds) is evaluated against bytes retained before it existed, and matches
join back to host occurrences for blast-radius reporting and analyst
workflow.

Status: M0 + M1 + M3a + M4 + M5 + M6 (hardening) merged. Apache-2.0.

## Security posture (M6)

What is enforced today, by default:

- **Agent authentication is mTLS.** The server generates a per-deployment
  CA on first run (`corpusctl ca init` prints its fingerprint); agents
  enroll with a one-time token and receive a short-lived signed client
  cert (30-day TTL, rotatable via `POST /agents/renew`). All agent
  traffic (heartbeats, gaps, artifact ingest) runs over a dedicated mTLS
  listener (`CORPUS_AGENT_LISTEN`, default :8443) requiring a CA-signed
  client cert. The bearer token survives only behind
  `CORPUS_AGENT_LEGACY_BEARER=1` for local dev; it is rejected by
  default. `corpusctl import` remains an unauthenticated localhost dev
  path.
- **Agent spool is encrypted at rest.** XChaCha20-Poly1305, chunked for
  bounded-memory streaming; the key is generated at enrollment and
  wrapped by the macOS Keychain (Linux: 0600 key file fallback; kernel
  keyring/TPM are later scope). Plaintext exists only in memory during
  upload. Tampered chunks fail AEAD verification — never silently used.
- **Analysis runs out of process.** YARA-X scanning executes in a
  `corpus-scanner` subprocess under an OS sandbox: macOS seatbelt (no
  network, write confinement — see honesty note), Linux landlock
  (best-effort read-only filesystem view). Timeout and output caps are
  enforced by the parent. `CORPUS_SCANNER_TIER=inprocess` restores the
  old dev behavior; `gvisor` is a config tier for real Linux hosts with
  runsc (not available under Colima).

What production deployments MUST still configure (honest limits):

- **Subprocess + seatbelt/landlock is NOT a hostile-malware boundary**
  (shared kernel, no resource isolation; on macOS the profile does not
  narrow filesystem *reads*). Spec invariant #14 stands: scanning hostile
  samples in production requires gVisor (tier 2) or Kata/microVM-class
  isolation (tier 3, not built).
- The admin/CLI REST surface on :8080 is unauthenticated beyond the
  tenant header. Bind it to localhost or put it behind your own
  gateway/VPN; the tenant header is not a security boundary.
- Enrollment's bootstrap step (one-time token exchange) happens over the
  plain listener; deliver tokens out of band and bind :8080 accordingly.

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
- **M6 — hardening**: mTLS agent auth with per-deployment CA and
  short-lived client certs, AEAD-encrypted agent spool with OS-wrapped
  key, out-of-process sandboxed analysis (`corpus-scanner` subprocess
  under seatbelt/landlock, tiered toward gVisor/Kata). See
  `docs/hardening-decisions.md` for the research and the honest limits.
- **M8 — semantic similarity**: pure-Rust function-level matching
  (iced-x86 disassembly, mnemonic-family signatures, Jaccard scoring,
  bidirectional coverage, strong/weak edges). No Ghidra/JVM; x86-64
  only in v1.
- **M2 — Windows agent (user-mode)**: ReadDirectoryChangesW watcher, USN
  journal recovery signal, handle-based file identity, DPAPI spool-key
  wrap, ADS metadata. User-mode coverage gaps (no exec observation, no
  minifilter) are documented in the Windows section.

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

## Semantic similarity (M8)

Function-level matching in pure Rust — no Ghidra/JVM (spec 16.2/16.5;
design and rationale in `docs/semantic-similarity-design.md`).

- **Extraction**: function boundaries from ELF `STT_FUNC` symbols, PE x64
  `.pdata`, or prologue-pattern scan; iced-x86 disassembly.
- **Signatures**: Jaccard similarity over a token multiset of mnemonic
  *family* unigrams/bigrams (opt-stable structure), instruction-mix
  histograms, block/call estimates. Significance filter (≥5 insns, no
  thunks) suppresses stubs (our v1 stand-in for known-library
  suppression).
- **Edges**: `semantic_variant_strong` (bidirectional coverage ≥ 0.60 and
  ≥ 3 matched pairs — merges variant groups), `semantic_variant_weak`
  (≥ 0.35 — leads). Evidence carries the top-5 function pairs with
  offsets and scores. Bidirectional coverage stops small-loader-matches-
  big-benign false edges (16.5 step 4).
- **Honest limits**: x86-64 only (arm64 follow-up); no decompiler; opt
  drift (-O0/-O2) is handled at family level but tiny functions still
  blur; thresholds are hand-set, not calibrated against large corpora;
  packed/high-entropy code records an `analysis_limitation` instead of
  a confident edge (16.7). Per-function scoring is brute-force per
  tenant (banded LSH index is the follow-up).

Validation corpus (`tests/semantic.rs`, fixtures compiled at test time,
never committed): same C source at -O0/-O2/-Os → strong edges + one
variant group; small source tweak → edge with non-identical pair
scores; unrelated program → no edge; high-entropy sample → limitation.

## Windows agent (M2, user-mode fallback)

`corpus-agent` builds and runs on Windows (x86_64-pc-windows-gnu
cross-compile via mingw-w64; `windows-latest` CI job builds and runs the
agent test suite natively — that job is our only live Windows execution
environment, see caveat below).

Implemented (user mode, spec 10.10 fallback path):

- **ReadDirectoryChangesW watcher** (recursive, file-name/last-write/
  security) feeding the standard candidate pipeline; queue overflow is a
  `SENSOR_OVERFLOW` coverage gap.
- **USN change journal** (FSCTL_READ_JOURNAL) as a downtime-recovery
  signal: records trigger an immediate reconciliation scan. Without
  volume read access it degrades cleanly to the periodic poll sensor.
- **File identity** via GetFileInformationByHandle (volume serial + file
  index, the Windows analog of dev/inode) in the stable-read re-stat.
- **ADS awareness** at the metadata level: non-default streams are
  recorded as occurrence provenance (`artifact.provenance.ads`).
- **DPAPI key wrapping** for the spool key (CryptProtectData,
  CurrentUser), matching macOS Keychain / Linux key-file roles.
- Everything else is shared code: capture state machine, stable read,
  baseline, mTLS enrollment, encrypted spool, heartbeats.

Coverage gaps vs the spec's preferred production design (signed
minifilter + ETW, 10.10 Windows):

- **No process-execution observation.** Win32_ProcessStartTrace requires
  admin + COM/WMI plumbing; exec-priority capture (10.8 #1) degrades to
  write-priority (close-write/rename). Executed-but-never-written
  artifacts are captured only at write time.
- **No kernel minifilter**: pre-write and deleted-before-close events can
  race the user-mode watcher; the journal + reconcile bounds the loss but
  cannot eliminate it. The signed minifilter, journal replay in-kernel,
  and process/image ETW telemetry are the M2-production follow-up, along
  with code signing/attestation (org-level: driver signing, installer
  signing, release certification).
- **USN records are used as a change signal**, not resolved to paths
  (file-reference → path resolution is follow-up).
- **Stable-read mutation detection on Windows is timestamp-limited**:
  NTFS write timestamps have ~10-15ms granularity, so a content-identical
  rewrite within the same tick is undetectable by (size, mtime, index)
  alone. Same tradeoff every user-mode collector makes; size-changing or
  later-tick mutations are caught (this exact case surfaced as a
  windows-latest CI test failure and is covered by a granularity-crossing
  regression test).
- **Live-test caveat**: no Windows machine was available during
  development. Verification is cross-compilation
  (`x86_64-pc-windows-gnu`, mingw-w64), cfg-gated unit tests, and the
  windows-latest CI job. RDCW/USN/DPAPI code paths have NOT been
  exercised on a live Windows host yet; treat them as unproven until the
  CI job and a staging host confirm them.

## Limitations and deviations (consolidated)

- **Auth**: mTLS for agent traffic is the default (see Security posture);
  the legacy bearer path needs `CORPUS_AGENT_LEGACY_BEARER=1`. Admin/CLI
  endpoints and MCP remain unauthenticated/static-token — gateway them in
  production.
- **Analysis isolation**: tier 1 subprocess sandboxing has the honest
  limits above; the subprocess tier recompiles the bundle per artifact
  (correctness first; batch-scan optimization is follow-up).
- **Scale**: fuzzy-similarity candidates are brute-force per tenant
  (fine at ~10⁴–10⁵ artifacts; LSH index is follow-up). Retro-hunts are
  synchronous single-node. TAXII polling is single-page.
- **Auth model for ingest**: agent endpoints are bearer-authenticated
  with server-enforced identity; the no-bearer dev path for
  `corpusctl import`/`gaps` remains open in dev.
- **fanotify**: FAN_MOVED_TO unsupported on mount marks (renames covered
  by reconcile scan); requires CAP_SYS_ADMIN (root or privileged
  container); macOS builds run poll-sensor only.
- **Spool key wrapping**: Linux uses a 0600 key file (kernel keyring and
  TPM2 are later scope); macOS uses the Keychain.
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
- **v1 hardening (remaining)**: Endpoint Security extension for macOS,
  gVisor/Kata analysis isolation in production, threat-model review,
  parser sandbox audit, upgrade/rollback, stable APIs.
- **Similarity depth**: Ghidra/BSim semantic plugin slot (schema ready),
  banded LSH for fuzzy candidates, variant-group analyst overrides.
- **Response**: dynamic detonation sandbox, OCSF export, action broker,
  current-state verification (17.2), reference connectors.

## License

Apache-2.0. See `LICENSE`.
