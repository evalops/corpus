# ADR-0008: Observe-only agent

## Status

Accepted (M1; product hard rule).

## Context

A control plane that can run arbitrary commands on endpoints is an RCE
product. IR value must not require that surface.

## Decision

`corpus-agent`:

- Discovers and uploads code-bearing files
- Reports heartbeats and gaps
- **Never** receives server-side command payloads for execution
- **Never** blocks process start

## Consequences

- No remote response actions (kill process, quarantine) in this tree
- Capture failure modes become gap rows, not silent drops
- Security review focuses on steal-credentials and DoS, not command inject

## References

- [intent.md](../intent.md) non-goals
- [invariants.md](../invariants.md) §9–10
