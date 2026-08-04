# ADR-0003: Immutable content-addressed rule bundles

## Status

Accepted (M0 / M3).

## Context

Retro-hunts must name the exact rule set and engine that produced a match
months later. Mutable “current rules” pointers make historical results
unverifiable.

## Decision

- Individual rules are compile-validated and stored.
- A **bundle** freezes sorted sources + `COMPILER_CONFIG` + engine version
  into a digest.
- Activation is a pointer for forward coverage; digests never rewrite.
- Scan cache keys include bundle digest and engine version.

## Consequences

- Rule edits require a new bundle publish.
- Engine upgrades invalidate cache entries by construction.
- Hunts pin digests, not “latest”.

## References

- `corpus_core::rules`, `registry`
- [invariants.md](../invariants.md) §6–7
