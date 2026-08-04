# Core invariants

These are product guarantees. Breaking one is a bug even if tests are green
for an unrelated path. Each maps to code and usually a unit or integration
test.

| # | Invariant | Primary code | How it fails closed |
|---|-----------|--------------|---------------------|
| **1** | **Server recomputes SHA-256.** Client digest is a hint. Mismatch rejects commit. | `hash::verify_upload`, `ingest::finalize` | `Error::HashMismatch` |
| **2** | **Magic bytes classify; extensions do not.** | `classify::classify` | Unknown class; no “trust .exe” path |
| **3** | **Weak edges never merge variant groups.** Only `exact_copy`, `normalized_equivalent`, `semantic_variant_strong` call union. | `similarity::model::merges_groups` | Test `fuzzy_never_merges_groups` |
| **4** | **Analyst graph APIs never return sample bytes.** Neighborhood, export, evidence, receipts: digests + metadata only. | `neighborhood`, `export`, `semantic::edges::function_pair_evidence`, `receipts` | Evidence strips bulky fields; size caps |
| **5** | **Every durable query is tenant-scoped.** | All `corpus_core` SQL | Missing tenant → wrong default or NotFound, not cross-read |
| **6** | **Rule bundles are immutable.** Digest covers sources + `COMPILER_CONFIG` + engine version. | `rules`, `registry::publish_bundle` | New engine/config → new digest; old cache entries unused |
| **7** | **Scan cache identity includes engine version.** | `scan::ScanCacheKey`, `ENGINE_VERSION` | Engine bump invalidates cache semantics |
| **8** | **Hunt matches insert idempotently.** | `hunts` match insert | `ON CONFLICT DO NOTHING` / unique key |
| **9** | **Agents are observe-only.** No server-command channel; no process kill API. | `corpus-agent` | Architecture; no route exists |
| **10** | **Coverage gaps are data.** Failed capture is recorded, not dropped. | `capture_attempt`, agent gap batching | Spec 2.2 taxonomy |
| **11** | **Occurrence identity is (tenant, agent_id, boot_id, agent_sequence).** | `ingest` occurrence insert | Idempotent on conflict |
| **12** | **Packed/virtualized binaries do not get confident semantic edges.** | `semantic::triage`, `edges::extract_and_store` | `block_semantic` → limitation receipt, empty functions |
| **13** | **Similarity model thresholds are single-sourced.** Design doc matches `MODEL_V1`. | `similarity::model` | Test `design_doc_matches_model_config` |
| **14** | **Hostile-sample isolation is tiered and explicit.** Default subprocess+OS sandbox; gVisor optional floor. MicroVM-class is documented future, not claimed today. | `sandbox`, `CORPUS_SCANNER_TIER` | Weaker than min tier → refuse start when configured |
| **15** | **Sample egress is opt-in.** Detonation requires `CORPUS_DETONATION_ENABLED`. | `detonate` | Default off |
| **16** | **Merlin telemetry is not file identity.** Observations/segments do not invent artifact rows. | `merlin` | Separate tables; join is best-effort |
| **17** | **Supersession does not delete history.** Old model edges get evidence flags; new version writes new rows. | `similarity::invalidation` | Auditability |
| **18** | **Legal hold blocks destructive similarity cleanup.** | `similarity::lifecycle` | `Error::Conflict` unless dry-run |
| **19** | **Analysis receipts store no sample bytes.** Content-derived id; digests and counts only. | `similarity::receipts` | Schema + serializers |
| **20** | **Enrollment tokens are one-time and hashed at rest.** | `agents::create_enrollment_token` | Plaintext returned once |

## Edge type reference (invariant #3)

| Edge type | Merges groups? |
|-----------|----------------|
| `exact_copy` | yes |
| `normalized_equivalent` | yes |
| `semantic_variant_strong` | yes |
| `semantic_variant_weak` | no |
| `byte_similar` | no |
| `shared_provenance` | no |

Thresholds for semantic classification: [semantic-similarity-design.md](semantic-similarity-design.md) and `MODEL_V1`.

## Changing an invariant

1. Update this file and the enforcing code in the same PR.
2. Add or adjust a test that fails if the invariant regresses.
3. If the change is intentional product movement, add an ADR under [adrs/](adrs/).

## Related

- [architecture.md](architecture.md)
- [spec-map.md](spec-map.md)
