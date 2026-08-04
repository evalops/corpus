# ADR-0004: Typed edges; weak never merge groups

## Status

Accepted (M3a); reaffirmed for semantic weak edges.

## Context

ssdeep and weak semantic scores produce useful **leads** but high false
family membership if they auto-cluster.

## Decision

- Persist **typed** edges with explicit `edge_type` and `model_version`.
- Only strong types merge variant groups (`merges_groups`).
- `byte_similar`, `shared_provenance`, `semantic_variant_weak` never merge.

## Consequences

- Analyst UIs must show weak edges as leads.
- Group membership stays high-precision.
- Spec 28.5 encoded as a unit test.

## References

- `similarity::model::merges_groups`
- [invariants.md](../invariants.md) §3
