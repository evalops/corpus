# Corpus — longitudinal executable corpus & retro-hunt platform (Milestone 0)

Corpus retains one copy of every unique code-bearing artifact per tenant in a
content-addressed store, keeps an append-only ledger of where and when those
bytes were observed, and lets you retro-hunt the retained bytes with YARA-X
rules that did not exist when the artifacts were collected.

This repository is the **Milestone 0 "corpus proof"** from the engineering
spec: CLI/manual ingestion, tenant-scoped CAS, fast classification, YARA-X
scanning, a rule registry with immutable bundles, single-node retro-hunts,
and a basic blast-radius JSON report. There is no endpoint agent yet.

> Dev-profile warning (spec 8.4): the Docker Compose setup and filesystem CAS
> are for development. They are not a safe production trust boundary for
> hostile samples.

## Layout

- `crates/corpus-core` — shared library: types, DTOs, migrations runner,
  magic-byte classification, filesystem CAS, ingest (announce/finalize),
  rule registry, bundle digests, hunt engine, blast-radius reporter.
- `crates/corpus-server` — axum REST API (`/api/v1`), owns all writes.
- `crates/corpusctl` — thin CLI client (`import`, `rules`, `bundles`,
  `hunts`, `report`).
- `migrations/` — SQL migrations (applied by the server at boot).
- `scripts/demo.sh` — full end-to-end demo.
- `scripts/gen-testdata.sh` — builds demo fixtures (nothing binary is committed).

## Quickstart

Prereqs: Rust toolchain, Docker, `just` (optional), `cc` (for fixtures).

```sh
docker compose up -d postgres          # PostgreSQL 16 on :5433
cargo run -p corpus-server             # applies migrations, serves :8080
```

In another terminal:

```sh
bash scripts/gen-testdata.sh testdata
cargo run -p corpusctl -- import testdata
cargo run -p corpusctl -- rules add testdata/corpus_demo_marker.yar
cargo run -p corpusctl -- bundles publish --rule CorpusDemoMarker --activate
cargo run -p corpusctl -- hunts create --bundle <digest-from-publish>
cargo run -p corpusctl -- hunts run <hunt-id>
cargo run -p corpusctl -- report blast-radius --hunt <hunt-id>
```

Or run the whole thing, including a real-database integration test:

```sh
just demo        # or: bash scripts/demo.sh
```

Other `just` recipes: `just up`, `just down`, `just build`, `just test`,
`just clippy`, `just serve`, `just reset` (drops the compose volume).

## Configuration

`corpus-server` (env):

| Var | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://corpus:corpus@127.0.0.1:5433/corpus` | PostgreSQL DSN |
| `CORPUS_CAS_ROOT` | `./data/cas` | filesystem CAS root (dev backend) |
| `CORPUS_LISTEN` | `127.0.0.1:8080` | bind address |

`corpusctl` (env / flags): `CORPUS_SERVER_URL` / `--server`,
`CORPUS_TENANT` / `--tenant`.

## Key behaviors (spec references)

- **Announce-before-upload** (11.1): `corpusctl import` announces each file's
  SHA-256 first; bytes are uploaded only on `UPLOAD_REQUIRED`. A dedup hit
  still records an occurrence and a capture attempt.
- **Server-side rehash** (invariant #1): the server recomputes SHA-256 from
  the uploaded bytes; a mismatch rejects the commit and is persisted as a
  `HASH_MISMATCH` capture attempt. The client hash is only a hint.
- **Classification by magic bytes** (2.3/10.6): PE, ELF, Mach-O (thin/fat),
  shebang scripts. Extensions are ignored.
- **Immutable bundles** (14.5): digest over canonically ordered rule sources
  plus compiler configuration; re-publishing the same set returns the same
  digest.
- **Retro-hunt** (15.1/15.2): a hunt pins `corpus_watermark` = max committed
  artifact sequence at plan time and scans exactly that set. Timeouts or
  unreadable artifacts force `COMPLETED_PARTIAL`.
- **Scan cache** (15.4): keyed by `(tenant_id, artifact_sha256,
  rule_bundle_digest, yara_x_engine_version, scan_config_digest)`; re-running
  a hunt never rereads bytes and match commitment is idempotent.
- **Forward coverage** (15.9): a bundle published with `--activate` scans
  every newly committed artifact post-commit, filling the same cache and
  match tables via a persistent `forward` hunt.
- **Blast radius** (17.1): joins hunt matches or an exact hash to the
  occurrence ledger — hosts, paths, first/last observation. Historical
  observation only; current-state verification (17.2) is post-M0 and the
  report says so in `verification_state`.

## Tenancy

M0 is single-tenant: requests without an `X-Corpus-Tenant` header use a
fixed default tenant UUID. Every table carries `tenant_id` and every query
is tenant-scoped, so multi-tenancy is a data-model given, not a feature.

## Testing

```sh
cargo test                                   # unit tests (hermetic)
CORPUS_TEST_DATABASE_URL=postgres://corpus:corpus@127.0.0.1:5433/corpus \
    cargo test -p corpus-core --test ingest_hunt   # real-DB integration test
```

Unit tests cover SHA-256 recompute/mismatch rejection, bundle digest
determinism, magic-byte classification, cache-key correctness, and CAS
create-if-absent. The integration test covers the full
import → dedup → mismatch-rejection → bundle → hunt → re-run idempotency →
forward coverage → blast-radius path.

## License

Apache-2.0. See `LICENSE`.
