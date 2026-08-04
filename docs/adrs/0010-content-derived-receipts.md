# ADR-0010: Content-derived analysis receipts

## Status

Accepted (similarity investigation foundation).

## Context

Analysts need “what analyzer/model saw this artifact?” without re-reading
samples. Random UUID receipts make concurrent re-analysis noisy and hard
to upsert.

## Decision

- `AnalysisReceipt` JSON without sample bytes
- `receipt_id` = truncated SHA-256 over tenant, artifact, analyzer,
  versions, config digest, input sha256, status, function_count
- Upsert on id for idempotent concurrent runs

## Consequences

- Same inputs → same receipt row
- Different function counts → different ids (history preserved)
- Edge evidence can embed `receipt_id` for join

## References

- `similarity::receipts`
- [invariants.md](../invariants.md) §19
- migration `0010_receipts_and_cleanup.sql`
