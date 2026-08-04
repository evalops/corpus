# ADR-0009: Tiered scan isolation

## Status

Accepted (M6).

## Context

YARA on hostile bytes can attack the scanner. Full microVM isolation is
heavy for default single-node deploy. Need a ladder of controls.

## Decision

Tiers via `CORPUS_SCANNER_TIER`:

| Tier | Mechanism |
|------|-----------|
| `inprocess` | Dev only; same process as API |
| `subprocess` (default) | `corpus-scanner` + seatbelt/landlock where available |
| `gvisor` | `runsc` when configured |

`CORPUS_MIN_SCANNER_TIER` refuses weaker tiers at startup.

## Consequences

- Default is stronger than in-process, weaker than Kata.
- Docs must not claim microVM isolation for default installs.
- Operator can raise the floor on multi-tenant hosts.

## References

- [hardening-decisions.md](../hardening-decisions.md) §3
- [invariants.md](../invariants.md) §14
- [threat-model.md](../threat-model.md)
