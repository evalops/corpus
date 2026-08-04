# ADR-0001: Separate admin and agent listeners

## Status

Accepted (M6).

## Context

Agent authentication requires mTLS with a deployment-only CA. Admin/CLI
traffic uses bearer tokens and often runs on loopback without TLS in dev.
axum-server did not expose peer certificates cleanly for per-route TLS
policy (see hardening notes).

## Decision

Run **two listeners**:

- Plain HTTP(S) admin/CLI on `CORPUS_LISTEN`
- mTLS agent listener on `CORPUS_AGENT_LISTEN` with a hand-built
  `tokio_rustls::TlsAcceptor`

Enrollment (one-time token) remains on the plain listener as the
documented bootstrap path; renew uses mTLS.

## Consequences

- Route tables are duplicated for agent ingest/heartbeat/gaps.
- Ops must open/monitor two ports.
- Clear trust split: agent identity ≠ admin token.

## References

- [hardening-decisions.md](../hardening-decisions.md) §1
- `corpus-server` dual bind in `main.rs`
