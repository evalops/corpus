# Deploy

Production-shaped path for Corpus: PostgreSQL, server, mTLS agents, and the
first retro-hunt. Design notes for hardening, semantic similarity, and
detonation live beside this file.

## Prerequisites

- Docker (PostgreSQL 16) or a managed Postgres 16 instance
- Rust stable (for building from source)
- Linux hosts for agents and for gVisor isolation
- Optional: CAPEv2 if you enable detonation

## Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://corpus:corpus@127.0.0.1:5434/corpus` | Postgres connection |
| `CORPUS_CAS_ROOT` | `./data/cas` | Content-addressed store root |
| `CORPUS_LISTEN` | `127.0.0.1:8080` | Admin/CLI REST bind |
| `CORPUS_AGENT_LISTEN` | `127.0.0.1:8443` | mTLS agent bind |
| `CORPUS_CA_DIR` | `./data/ca` | Deployment CA material |
| `CORPUS_CA_SANS` | (empty) | Extra SANs for server cert (comma-separated) |
| `CORPUS_ADMIN_TOKEN` | (unset) | Required for non-loopback admin API |
| `CORPUS_REQUIRE_ADMIN` | (unset) | Force admin auth even on loopback |
| `CORPUS_ALLOW_DEV_INGEST` | (unset) | Allow unauthenticated import when admin token is set |
| `CORPUS_DENY_DEV_INGEST` | (unset) | Disable unauthenticated import on loopback |
| `CORPUS_MCP_TOKEN` | `mcp-dev-token` on loopback only | MCP bearer; required non-default off loopback |
| `CORPUS_SCANNER_TIER` | `subprocess` | `inprocess` \| `subprocess` \| `gvisor` |
| `CORPUS_MIN_SCANNER_TIER` | (unset) | Floor: `subprocess` or `gvisor` |
| `CORPUS_SCANNER_BIN` | auto | Path to `corpus-scanner` |
| `CORPUS_HUNT_SYNC` | (unset) | If set, `/hunts/{id}/run` runs in-request |
| `CORPUS_DETONATION_ENABLED` | off | Allow sample egress to CAPE |
| `CORPUS_CAPE_URL` | (unset) | CAPEv2 base URL |
| `CORPUS_CAPE_TOKEN` | (unset) | CAPE auth token (required when detonation enabled) |
| `CORPUS_CAPE_ALLOW_NO_AUTH` | (unset) | Permit CAPE without token (local only) |
| `CORPUS_DETONATION_AUTO` | off | Auto-submit on malicious/suspicious opinion |
| `CORPUS_AGENT_LEGACY_BEARER` | off | Accept agent bearer on plain listener |
| `CORPUS_SERVER_URL` | `http://127.0.0.1:8080` | corpusctl client base |
| `CORPUS_TENANT` | (unset) | corpusctl default tenant header |

## Auth policy

1. Bind `CORPUS_LISTEN` to `127.0.0.1` or put a reverse proxy in front.
2. Non-loopback binds **refuse to start** without `CORPUS_ADMIN_TOKEN`.
3. When the token is set, every admin route needs `Authorization: Bearer <token>`.
4. Agent traffic uses mTLS on `CORPUS_AGENT_LISTEN`. Enrollment (one-time token) is the only unauthenticated agent bootstrap on the plain listener.
5. MCP requires `CORPUS_MCP_TOKEN`. The string `mcp-dev-token` is rejected on non-loopback binds.

```sh
export CORPUS_ADMIN_TOKEN="$(openssl rand -hex 32)"
export CORPUS_MCP_TOKEN="$(openssl rand -hex 32)"
export CORPUS_LISTEN=0.0.0.0:8080   # only behind a gateway you control
export CORPUS_AGENT_LISTEN=0.0.0.0:8443
```

`corpusctl` reads `CORPUS_ADMIN_TOKEN` from the environment and sends it as a Bearer token.

## Compose (local / single host)

```sh
docker compose up -d postgres
export DATABASE_URL=postgres://corpus:corpus@127.0.0.1:5434/corpus
export CORPUS_CAS_ROOT=./data/cas
export CORPUS_LISTEN=127.0.0.1:8080
cargo run -p corpus-server
```

For a hardened single-host sketch with an explicit admin token, see
`deploy/compose/`.

## First hunt

```sh
bash scripts/first-hunt.sh
```

That script: starts Postgres if needed, builds, starts the server on loopback,
imports `testdata/`, publishes a demo rule bundle, runs a retro-hunt, and
prints the blast-radius JSON.

Manual equivalent:

```sh
cargo run -p corpusctl -- import testdata
cargo run -p corpusctl -- rules add testdata/corpus_demo_marker.yar
cargo run -p corpusctl -- bundles publish --rule CorpusDemoMarker --activate
# note digest from output
cargo run -p corpusctl -- hunts create --bundle <digest>
cargo run -p corpusctl -- hunts run <hunt_id>   # polls until COMPLETED*
cargo run -p corpusctl -- report blast-radius --hunt <hunt_id>
```

Hunts enqueue asynchronously by default. `corpusctl hunts run` polls status.
Pass `?sync=1` on the HTTP API or set `CORPUS_HUNT_SYNC=1` for in-request
execution.

## Agent enrollment (Linux)

```sh
# On the control plane:
cargo run -p corpusctl -- ca init          # prints CA fingerprint
cargo run -p corpusctl -- enroll-token create --ttl-secs 3600

# On the endpoint (with the one-time token and server URL/CA):
# configure agent YAML with enroll URL on :8080 and mTLS endpoint on :8443
```

## Scanner isolation (gVisor)

`CORPUS_SCANNER_TIER=subprocess` (default) is **not** a hostile-malware
boundary. For production malware scanning on Linux:

1. Install [gVisor](https://gvisor.dev/) `runsc` and register it with Docker:
   ```sh
   # after installing runsc
   sudo runsc install
   sudo systemctl reload docker
   docker info | grep -i runsc
   ```
2. Build `corpus-scanner` and ensure it is next to `corpus-server` or set
   `CORPUS_SCANNER_BIN`.
3. Set:
   ```sh
   export CORPUS_SCANNER_TIER=gvisor
   export CORPUS_MIN_SCANNER_TIER=gvisor   # refuse weaker tiers
   ```

macOS and Colima hosts typically only ship `runc`; gVisor is a real Linux
host configuration.

## Detonation (optional)

Sample egress is off by default.

```sh
export CORPUS_DETONATION_ENABLED=1
export CORPUS_CAPE_URL=https://cape.example
export CORPUS_CAPE_TOKEN=...
cargo run -p corpusctl -- detonate <sha256>
```

The server refuses to start if detonation is enabled without URL/token
(unless `CORPUS_CAPE_ALLOW_NO_AUTH=1` for a local CAPE).

## Reverse proxy sketch

- Terminate TLS for admin on the proxy; forward to `127.0.0.1:8080`.
- Do not expose `:8080` on a public interface without `CORPUS_ADMIN_TOKEN`.
- Expose `:8443` (mTLS) only to agents; keep the deployment CA private.

## Related docs

- `docs/hardening-decisions.md` — mTLS, spool crypto, sandbox tiers
- `docs/semantic-similarity-design.md` — function-level matching
- `docs/detonation-design.md` — CAPE adapter
- `docs/openapi.json` — HTTP surface (also at `GET /api/v1/openapi.json`)
