# Corpus — longitudinal executable corpus & retro-hunt platform

Corpus retains one copy of every unique code-bearing artifact per tenant in a
content-addressed store and keeps an append-only ledger of where and when
those bytes were observed. New intelligence (YARA-X rules, hashes) can then
be evaluated against bytes retained before the intelligence existed, and
matches are joined back to host occurrences for blast-radius reporting.

Status: Milestone 1 (Linux agent). Apache-2.0.

> Dev-profile warning: the Compose stack, filesystem CAS, and bearer-token
> agent auth are development conveniences. They are not a safe production
> trust boundary for hostile samples (spec 8.4, invariant #14).

## Architecture

```
endpoint (Linux)                     control plane
┌───────────────────────┐            ┌──────────────────────────────────┐
│ corpus-agent          │            │ corpus-server (axum, /api/v1)    │
│  fanotify / poll scan │  REST      │  enroll/heartbeat/gaps           │
│  capture state mach.  │──────────▶ │  ingest: announce/upload/finalize│
│  stable read + spool  │  bearer    │  rules/bundles, hunts, reports   │
│  SQLite WAL queue     │            │        │          │              │
└───────────────────────┘            │  PostgreSQL 16   filesystem CAS  │
                                     └──────▲───────────────────────────┘
                                            │ REST
                                     corpusctl (import, rules, bundles,
                                     hunts, blast-radius, agents, gaps)
```

- `crates/corpus-core` — shared types/logic: classification, CAS, ingest,
  registry, hunt engine, reports, agent endpoints.
- `crates/corpus-server` — REST API; owns all writes; runs migrations.
- `crates/corpusctl` — operator CLI.
- `crates/corpus-agent` — Linux user-mode agent (spec 10): enrollment,
  checkpointed baseline, fanotify sensor with poll-reconcile fallback,
  stable-read capture state machine, SQLite local state, heartbeats.

## Quickstart

Prereqs: Rust, Docker, `just` (optional), `cc` (fixtures only).

```sh
docker compose up -d postgres     # PostgreSQL 16 on :5433
cargo run -p corpus-server        # migrates, serves 127.0.0.1:8080
```

M0 flow — CLI import, rule, retro-hunt, blast radius:

```sh
bash scripts/gen-testdata.sh testdata
cargo run -p corpusctl -- import testdata
cargo run -p corpusctl -- rules add testdata/corpus_demo_marker.yar
cargo run -p corpusctl -- bundles publish --rule CorpusDemoMarker --activate
cargo run -p corpusctl -- hunts create --bundle <digest>
cargo run -p corpusctl -- hunts run <hunt-id>
cargo run -p corpusctl -- report blast-radius --hunt <hunt-id>
```

M1 flow — agent on Linux (as root; fanotify needs CAP_SYS_ADMIN):

```sh
cargo run -p corpusctl -- enroll-token create --label my-host
# write agent.yaml (example in scripts/demo-agent.sh), then:
corpus-agent --config agent.yaml run

corpusctl agents list               # fleet health from heartbeats
corpusctl coverage gaps             # TOO_LARGE / PERMISSION_DENIED / ...
```

Scripted end-to-end demos: `just demo` (M0), `just demo-agent` (M1; runs
the agent in a privileged Linux container). Other recipes: `just up`,
`down`, `build`, `test`, `clippy`, `serve`, `reset`.

## Design invariants honored so far

- Server recomputes SHA-256 from uploaded bytes; client hash is a hint
  (invariant #1). Mismatches reject the commit and are recorded as gaps.
- Dedup is tenant-scoped; a dedup hit still records occurrence + capture
  attempt (11.1, 11.3 dev keying).
- Occurrences are append-only with observed/received timestamps and
  per-agent boot/sequence ordering (12.4).
- Bundles are immutable, digest-addressed (14.5); hunts pin a corpus
  watermark (15.1); scan cache keyed by (tenant, artifact, bundle digest,
  engine version, scan config) (15.4); matches commit idempotently (#8).
- Coverage gaps are data: TOO_LARGE, PERMISSION_DENIED,
  DELETED_BEFORE_READ, CHANGED_DURING_READ, SENSOR_OVERFLOW, SPOOL_FULL,
  UPLOAD_FAILED all land in `capture_attempt` (2.2).

## Agent notes (spec 10, M1)

- **Capture state machine** (10.4): OBSERVED → DEBOUNCING → OPENING →
  COPYING_AND_HASHING → HASHED → ANNOUNCED → DEDUP_HIT | UPLOAD_REQUIRED →
  UPLOADING → FINALIZING → OCCURRENCE_QUEUED → COMPLETE, or GAP_RECORDED.
  Transitions are transactional in SQLite; the machine resumes mid-state
  after a crash or network outage.
- **Stable read** (10.5): `O_NOFOLLOW` open, stream to spool while
  hashing, re-stat compare (dev/inode/size/mtime/ctime), retry, terminal
  `CHANGED_DURING_READ`.
- **Baseline** (10.7): checkpointed per top-level entry of each watch
  root, lowest priority, yields to live events (10.8).
- **fanotify mount-mark scope**: a mark applies to the *mount* containing
  the watch path. A watch path on the root filesystem marks the whole
  root mount (verified on an LXC: exec_open fires host-wide). Use
  dedicated mounts/partitions for watch dirs, or exclusions.
- **LXC/containers**: fanotify requires CAP_SYS_ADMIN. On a privileged
  LXC the agent must run as root (uid 1000 gets EPERM from
  `fanotify_init` and the agent falls back to the poll sensor). On an
  *unprivileged* LXC even root cannot use fanotify — run the agent in a
  privileged docker container there, or accept poll-only coverage.
- **macOS dev builds** compile with the poll sensor only (fanotify is
  Linux-only, cfg-gated).

## Deviations from the spec (M0/M1, deliberate)

- **Auth**: enrollment token → bearer token over plain HTTP; no mTLS yet
  (M1-production hardening). Admin/CLI endpoints are unauthenticated in
  dev. Tenant is a header stub (`X-Corpus-Tenant`, one default tenant);
  `tenant_id` is threaded through every table and query.
- **Spool**: plaintext with 0600/0700 permissions; encryption and key
  wrapping deferred (10.3 staged approach).
- **fanotify FAN_MOVED_TO**: rejected (EINVAL) on mount marks on tested
  kernels (6.x, tmpfs + ext4-on-LXC); renames into watched trees are
  caught by the reconciliation scanner instead.
- **No BLAKE3** on the hash path (SHA-256 only, matches the M0 schema);
  bandwidth token buckets from 10.9 are config-only, not enforced.
- **Baseline checkpoint granularity** is the top-level entry of each
  watch root; journal replay (10.7 step 6) is approximated by the
  always-on reconcile scanner.
- **Rule lifecycle**: compile-validation only (14.4 step 1); profiling,
  corpus tests, and review gates are later scope. One rule per file.
- **No management tasks**: the agent polls nothing and executes no
  server-supplied commands.
- Forward-coverage hunts use state `ACTIVE_FORWARD` (spec 15.2's enum
  has no persistent forward state).

## Testing

```sh
cargo test --workspace                                # 30 unit tests, hermetic
cargo clippy --all-targets                            # expected: 0 warnings
CORPUS_TEST_DATABASE_URL=postgres://corpus:corpus@127.0.0.1:5433/corpus \
    cargo test -p corpus-core                         # +2 real-DB integration tests
```

Unit tests: hash recompute/mismatch, bundle digest determinism,
magic-byte classification, scan cache key, CAS create-if-absent, capture
state machine durability, stable-read mutation detection (injected
mid-read mutation), baseline checkpoint resume after a simulated crash,
reconcile change detection, gap batching. Integration tests: full
ingest→hunt→report path; enroll→heartbeat→gaps→dedup-occurrence path.

Verified on real hosts (2026-07-30): agent on macOS (poll sensor) and on
a Debian x86_64 LXC over LAN (fanotify, root) against the dev server —
enrollment, baseline, sub-poll-interval fanotify capture, TOO_LARGE
gaps, and heartbeats all confirmed end-to-end.

## Roadmap (spec 27.1)

- **M2 — Windows beta**: user-mode fallback first, then signed
  minifilter; journal replay, process/image telemetry, enterprise
  packaging and health.
- **M3 — similarity & incident workflow**: Ghidra/BSim variants, variant
  groups + evidence, current-state verification, OCSF export, action
  broker, reference connectors.
- **M4 — macOS & v1 hardening**: Endpoint Security extension, FSEvents
  fallback, threat-model review, parser sandbox audit, mTLS enrollment,
  spool encryption, upgrade/rollback, stable APIs.

## License

Apache-2.0. See `LICENSE`.
