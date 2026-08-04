# Architecture decision records

Short, durable decisions. Milestone research writeups stay in parent docs;
ADRs capture the choice and consequences.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-two-listeners.md) | Separate admin and agent listeners | Accepted |
| [0002](0002-server-owned-writes.md) | Server owns all durable writes | Accepted |
| [0003](0003-immutable-rule-bundles.md) | Immutable content-addressed rule bundles | Accepted |
| [0004](0004-typed-edges-not-fuzzy-families.md) | Typed edges; weak never merge groups | Accepted |
| [0005](0005-pure-rust-semantic.md) | Pure-Rust semantic matching (no Ghidra) | Accepted |
| [0006](0006-one-to-one-function-matching.md) | One-to-one greedy function matching | Accepted |
| [0007](0007-filesystem-cas-trait.md) | Filesystem CAS + CasBackend trait | Accepted |
| [0008](0008-observe-only-agent.md) | Observe-only agent | Accepted |
| [0009](0009-tiered-scan-isolation.md) | Tiered scan isolation | Accepted |
| [0010](0010-content-derived-receipts.md) | Content-derived analysis receipts | Accepted |

## Format

Each ADR: **Context → Decision → Consequences → References**.
