# ADR-0005: Pure-Rust semantic matching (no Ghidra)

## Status

Accepted (M8).

## Context

Spec 16.2/16.5 describes Ghidra BSim-class capability. Embedding a JVM
Ghidra service adds ops weight and Windows CI friction.

## Decision

Implement function-level matching in-process with **iced-x86** + goblin:

- x86-64 only for v1
- Heuristic + symbol/pdata boundaries
- Mnemonic-family tokens + Jaccard; simhash retained for future indexing

Document honest limits (no decompiler CFG, no AArch64 yet, uncalibrated τ).

## Consequences

- Same process as server (resource bounds required).
- AArch64 and calibration tracked as follow-ups.
- Design doc thresholds locked to `MODEL_V1` via CI test.

## References

- [semantic-similarity-design.md](../semantic-similarity-design.md)
- `semantic::*`
