-- Function-level LSH bands for semantic candidate generation (issue #14).
--
-- Populated by corpus_core::semantic::func_index::store_function_bands.
-- Queried by func_index::candidates with cold-index fallback to a full
-- similarity_function scan when empty or non-overlapping.
--
-- band_idx packs per-function local bands as
--   func_ordinal * FUNC_BAND_COUNT + local_idx
-- so the primary key stays unique without a separate function id.
-- Lookups use band_key + (band_idx % FUNC_BAND_COUNT) for local semantics.
--
-- All rows are tenant- and extractor-version-scoped. No cross-tenant index.

CREATE TABLE IF NOT EXISTS similarity_function_band (
  tenant_id     uuid NOT NULL REFERENCES tenant (id),
  artifact_id   uuid NOT NULL,
  version       text NOT NULL,
  band_idx      int  NOT NULL,
  band_key      text NOT NULL,
  func_offset   bigint NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id, version, band_idx, func_offset)
);

CREATE INDEX IF NOT EXISTS idx_sim_func_lsh_lookup
  ON similarity_function_band (tenant_id, version, band_key);
