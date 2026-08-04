# Data model

PostgreSQL holds the catalog and ledger. Sample bytes live only in the CAS.
Migrations are ordered under `migrations/`; two files share prefix `0010_`
(Merlin vs receipts) and both apply via `sqlx::migrate!`.

## Glossary

| Term | Meaning |
|------|---------|
| **Tenant** | Isolation unit; every business row carries `tenant_id` |
| **Artifact** | One unique sha256 within a tenant; points at a CAS object key |
| **Occurrence** | Observation of an artifact (or intended path) on a host at a time |
| **Capture attempt** | Agent/server record of a capture outcome (including gaps) |
| **Upload session** | Staging handle between announce and finalize |
| **Rule** | Single YARA source, compile-validated, stable id |
| **Bundle** | Immutable set of rules + compiler/engine config, content-digested |
| **Hunt** | Retro or forward scan job over a planned artifact set |
| **Hunt match** | Rule hit on an artifact under a hunt |
| **Scan cache** | Memo of scan outcome keyed by artifact × bundle × engine |
| **Detection event** | First-class “something lit up” without requiring external SIEM |
| **Opinion** | Human verdict on an artifact (separate from analyzer scores) |
| **Similarity feature** | Versioned extracted attribute (ssdeep, import hash, triage, …) |
| **Similarity edge** | Typed link between two artifacts under a model version |
| **Variant group** | Partition of artifacts merged by strong edges |
| **Function row** | Per-function semantic signature for one artifact |
| **Analysis receipt** | Deterministic audit of an analysis pass (no sample bytes) |
| **Finding** | Analyzer output row (e.g. CAPE dynamic behavior) |
| **Merlin observation** | Telemetry event; not a verified file hash |

## Core tables (by migration)

### 0001 init

| Table | Role |
|-------|------|
| `tenant` | id, slug, name, status |
| `artifact` | sha256, size, class, storage_state, object_key, provenance |
| `upload_session` | announce staging |
| `occurrence_event` | ledger: host, agent, boot, sequence, path, times |
| `capture_attempt` | terminal outcomes including gaps |
| `rule` | YARA sources |
| `rule_bundle` / `rule_bundle_rule` | immutable publication |
| `hunt` / `hunt_match` | retro/forward jobs and hits |
| `scan_cache` | (artifact, bundle, engine) → outcome |

### 0002 agents

| Table | Role |
|-------|------|
| `enrollment_token` | one-time bootstrap (hashed) |
| `agent` | identity, cert serial, heartbeat fields |

### 0003–0006 / 0008 / 0010–0011 similarity

| Table | Role |
|-------|------|
| `similarity_feature` | family/name/version → JSON value |
| `similarity_edge` | src, dst, edge_type, model_version, score, evidence |
| `variant_group` / `variant_group_member` | strong-edge partitions |
| `similarity_function` | func_offset, sig (packed token hashes), version |
| `similarity_lsh_band` | byte fuzzy candidate index |
| `similarity_function_band` | function-level candidate index |
| `analysis_receipt` | content-derived id + body JSON |
| `similarity_cleanup_log` | destructive cleanup audit |

### 0004 bootstrap / 0005 analyst

| Table | Role |
|-------|------|
| `intel_indicator` | hash/string IOCs + provenance |
| `artifact_opinion` | human verdicts |
| `trigger_rule` / `trigger_outbox` | webhook automation |
| `audit_event` | control-plane audit |

### 0007 detonation

| Table | Role |
|-------|------|
| `analysis_run` | external/internal analyzer job |
| `finding` | typed findings (`DYNAMIC_BEHAVIOR`, …) |

### 0008–0009 hunts continuous

| Table | Role |
|-------|------|
| `hunt_job` | worker queue |
| `detection_event` | autonomous detections |
| `continuous_reanalysis` | progress for always-on re-hunt |

### 0010 Merlin

| Table | Role |
|-------|------|
| `merlin_segment` | accepted JSONL segment identity |
| `merlin_observation` | events within a segment |

## Relationships (conceptual)

```text
tenant
  ├── artifact ──┬── occurrence_event
  │              ├── similarity_feature / similarity_function
  │              ├── similarity_edge (src|dst)
  │              ├── variant_group_member
  │              ├── analysis_receipt / analysis_run / finding
  │              └── detection_event
  ├── rule ── rule_bundle ── hunt ── hunt_match
  ├── agent ── enrollment_token
  ├── intel_indicator
  └── merlin_segment ── merlin_observation
```

CAS: `object_key = objects/{tenant_id}/{sha256_hex}` → file bytes. The DB
row is not the sample.

## Identity rules

| Entity | Identity |
|--------|----------|
| Artifact within tenant | `sha256` (unique per tenant) |
| Occurrence | `(tenant_id, agent_id, boot_id, agent_sequence)` |
| Edge | `(tenant, src, dst, edge_type, model_version)` with `src < dst` |
| Bundle | content digest of sorted sources + compiler config |
| Receipt | SHA-256 truncated over analysis identity fields |
| Function signature row | `(tenant, artifact, func_offset, version)` |

## JSON evidence conventions

Edge `evidence` and receipt `body` are JSON. Conventions:

- Never embed raw sample bytes or full disassembly
- Prefer digests, counts, offsets, version strings
- Supersession flags: `superseded`, `superseded_by`, `superseded_at`
- Semantic edges include `tau`, `matched_pairs`, `receipt_id`, `matching`

## Related

- Migrations under `migrations/`
- [architecture.md](architecture.md)
- [invariants.md](invariants.md)
