# ADR-0006: One-to-one greedy function matching

## Status

Accepted (similarity investigation foundation).

## Context

Many-to-one assignment lets one popular CRT-like function inflate coverage
for many peers (false strong edges).

## Decision

- Candidate pairs with Jaccard ≥ τ sorted by score, then offsets.
- Greedy assignment: each function used at most once.
- Strong edges require coverage floors **and** min matched pair count.

## Consequences

- Slightly lower scores vs many-to-one inflation (documented in PR notes).
- Contested/unmatched sets available for explainability.
- Deterministic ties for stable receipts.

## References

- `semantic::edges::coverage`
- [semantic-similarity-design.md](../semantic-similarity-design.md)
