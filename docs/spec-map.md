# Spec map

Product requirements are referenced in code as “spec §N” / “spec N.M”.
The full product specification is maintained outside this repository
(EvalOps internal). This map is the in-repo index: **section → intent →
implementation**.

If you change behavior that a row claims, update the row in the same PR.

## Identity & corpus (2–3, 11–12)

| Spec | Topic | Code / docs |
|------|-------|-------------|
| 2.2 | Coverage gaps are first-class data | `capture_attempt`, `agents::record_gaps`, agent gap batching |
| 2.3 | Code-bearing classification; extensions not authority | `classify`, corpusctl import filters |
| 3 | SHA-256 artifact identity | `hash`, `ingest::finalize` |
| 5.5 | Human opinions separate from scores | `opinions`, `artifact_opinion` |
| 11.1–11.2 | Announce-before-upload, two-phase commit | `ingest` |
| 12.2 | Analysis run records | `analysis_run` (detonation migration) |
| 12.4 | Boot id + per-boot sequence | agent `state`, occurrence columns |

## Agents (10)

| Spec | Topic | Code / docs |
|------|-------|-------------|
| 10 | Observe-only endpoint agent | `corpus-agent` |
| 10.1 | Enrollment, gap reporting | `agents` |
| 10.4 | Capture state machine | agent `state` |
| 10.5 | Stable read / no symlink follow | agent `stable_read` |
| 10.6 | Classification at capture | shared `classify` |
| 10.7 | Baseline walk | agent `baseline` |
| 10.8 | Capture priorities | agent `state` priorities |
| 10.9 | Size / spool policy defaults | agent `config` |
| 10.10 | Sensor fallbacks (poll / RDCW) | agent `sensors` |
| 10.11 | Heartbeat / fleet health | `agents::heartbeat`, corpusctl |

## Rules & hunts (14–15)

| Spec | Topic | Code / docs |
|------|-------|-------------|
| 14.3–14.5 | Rule validate, immutable bundles | `rules`, `registry` |
| 14.6 | Hash intel → exact hunt | `intel` |
| 15 | Retro-hunt engine | `hunts` |
| 15.1–15.2 | Plan/execute; COMPLETED_PARTIAL on timeout | `hunts::execute_hunt` |
| 15.4 | Scan cache key | `scan` |
| 15.9 | Forward coverage on commit / bundle | `ingest` hooks, `registry` activate |

## Similarity (16, 28.5)

| Spec | Topic | Code / docs |
|------|-------|-------------|
| 16 | Feature families, edges, groups | `similarity::*` |
| 16.2 | Function-level features | `semantic::extract`, `features` |
| 16.4 | Typed edges | `similarity::model::edge_type` |
| 16.5 | Coverage aggregation, suppression | `semantic::edges`, `suppress` |
| 16.6 | Variant groups | `similarity::edges::union_groups` |
| 16.7 | Packed binaries: no false confidence | `semantic::triage` |
| 28.5 | Fuzzy alone ≠ family membership | `merges_groups`, tests |

## Investigation & evidence (17, 20, 24)

| Spec | Topic | Code / docs |
|------|-------|-------------|
| 17.1 | Blast radius | `report` |
| 17.2 | Verification tasks (later) | noted in DTOs; not full product yet |
| 17.4 | Evidence typing (e.g. DYNAMIC_BEHAVIOR) | `finding`, detonation |
| 20.6 | External analysis declares sample egress | `detonate`, env flags |
| 24.3 | Audit events | `audit_event` |

## Hardening notes

Isolation class for hostile samples (spec invariant #14 in product language)
is implemented as **tiered** scanner isolation, not microVM-by-default.
See [hardening-decisions.md](hardening-decisions.md) and
[invariants.md](invariants.md) §14.

## Open product gaps (tracked as GitHub issues historically)

Examples still called out in code/design:

- Semantic calibration fixtures (#16)
- AArch64 semantic (#18)
- CFG / unwind features (#19–#21)
- CAS GC (#41)
- BinExport (#42)

Prefer linking issues from ADRs or design docs when closing a gap.

## Related

- [intent.md](intent.md)
- [invariants.md](invariants.md)
