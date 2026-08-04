# ADR-0007: Filesystem CAS + CasBackend trait

## Status

Accepted (M0 filesystem; trait in investigation foundation).

## Context

Need put-if-absent object storage without requiring S3 for single-node
homelab/dev. Future object stores should not rewrite ingest.

## Decision

- Default `FsCas` under `CORPUS_CAS_ROOT` (`objects/`, `staging/`).
- `CasBackend` trait for stage/commit/read/delete.
- `MemoryCas` + `conformance_suite` for tests.
- Digest verification remains in ingest (caller), not inside `commit`.

## Consequences

- Ops is directory backup + permissions.
- S3/MinIO can implement the trait later without changing announce flow.
- No built-in CAS GC yet (tracked separately).

## References

- `corpus_core::cas`
- [architecture.md](../architecture.md) storage section
