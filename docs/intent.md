# Intent: why Corpus exists

## Problem

Code-bearing files appear on endpoints, get deleted or overwritten, and
disappear from investigator reach. Threat intel (YARA rules, hash IOCs)
usually arrives **after** the first observation window. Without retained
bytes and a durable observation ledger, retro-hunting is limited to
whatever still sits on disk or in a backup.

## Thesis

For each tenant, Corpus keeps:

1. **One content-addressed copy** of every unique code-bearing artifact
   (sha256 of the uploaded bytes is identity).
2. **An append-only occurrence ledger** of where and when those bytes were
   observed (host, path, agent, boot id, sequence).
3. **Versioned intelligence** (immutable YARA-X rule bundles, hash
   indicators) that can be re-run over retained history.

When new intelligence lands, matches join back to occurrences for
blast-radius and investigation without re-collecting the fleet.

## Users

| Role | Primary interface | Job |
|------|-------------------|-----|
| Endpoint agent | `corpus-agent` | Observe, capture, upload; never block or execute server commands |
| Operator / IR | `corpusctl`, admin HTTP API | Rules, hunts, reports, opinions, triggers |
| Automation | webhooks, MCP (read-only), continuous re-analysis | Fan out on hunt match / verdict / detection |

## What ships today (capability map)

Documented in the root [README](../README.md) table. In short:

- Multi-tenant CAS + announce-before-upload (server rehash)
- Linux/Windows agents (fanotify / RDCW+USN, mTLS, encrypted spool)
- Immutable YARA-X bundles, retro-hunts, forward coverage, scan cache
- Continuous re-analysis on bundle activate / hash intel
- Byte + semantic similarity (typed edges, variant groups, neighborhood)
- Analyst surface: prevalence, rarity, opinions, investigation report
- Optional CAPE detonation (off by default; sample egress explicit)
- Optional Merlin telemetry bridge (observations ≠ verified file hashes)

## Non-goals

These are deliberate exclusions, not missing tickets:

| Non-goal | Rationale |
|----------|-----------|
| EDR / real-time block | Agent is observe-only (spec 10); no kill-switch surface |
| Server-commanded agent execution | Prevents the control plane from becoming RCE |
| Full decompiler / Ghidra JVM | Semantic path is pure Rust x86-64; see [semantic-similarity-design.md](semantic-similarity-design.md) |
| Public malware sharing / multi-tenant sample exchange | CAS keys are tenant-scoped; digests do not cross tenants |
| Treating path/process telemetry as file identity | Merlin observations stay separate from the occurrence ledger |
| Building an in-house sandbox | Detonation is an external adapter ([detonation-design.md](detonation-design.md)) |
| Fuzzy hash as automatic family membership | Spec 28.5; weak edges never merge groups ([invariants.md](invariants.md) §3) |

## Product loop

```text
retain bytes + occurrences
        │
        ▼
new intel (bundle activate, IOC, model)
        │
        ▼
re-evaluate history (forward + retro + continuous)
        │
        ▼
detection / hunt match
        │
        ▼
blast radius + investigation + optional trigger
```

## Success criteria (operational)

A deployment is doing its job when:

- Agents heartbeats are current and coverage gaps are visible, not silent
- Newly committed artifacts receive forward scan under the active bundle
- Activating a bundle enqueues retro coverage over retained history
  (`CORPUS_AUTO_RETRO_ON_ACTIVATE`, default on)
- Investigation for a sha256 returns detections, occurrences, and
  similarity context without returning sample bytes to the client

## Related docs

- [architecture.md](architecture.md) — how processes and planes fit
- [invariants.md](invariants.md) — guarantees that encode this intent in code
- [threat-model.md](threat-model.md) — what we assume about attackers
