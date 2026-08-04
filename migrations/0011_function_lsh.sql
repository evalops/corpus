-- Function-level LSH bands for semantic candidate generation (issue #14).

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
