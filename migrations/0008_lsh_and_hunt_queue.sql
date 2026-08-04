-- Banded LSH index for fuzzy (ssdeep) candidate generation.
-- Each artifact contributes fixed band keys derived from its ssdeep digest;
-- candidate queries join on (tenant_id, band_idx, band_key) instead of a
-- full per-class table scan.
--
-- LSH band index for byte-similar candidates; hunt worker queue.

CREATE TABLE IF NOT EXISTS similarity_lsh_band (
  tenant_id     uuid NOT NULL REFERENCES tenant (id),
  artifact_id   uuid NOT NULL,
  band_idx      int  NOT NULL,
  band_key      text NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id, band_idx)
);

CREATE INDEX IF NOT EXISTS idx_sim_lsh_lookup
  ON similarity_lsh_band (tenant_id, band_idx, band_key);

-- Optional hunt job queue for async workers. Hunts still use hunt.state
-- (QUEUED/RUNNING/COMPLETED*); this table records enqueue metadata and
-- supports multi-worker claim in a later step.
CREATE TABLE IF NOT EXISTS hunt_job (
  hunt_id       uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenant (id),
  enqueued_at   timestamptz NOT NULL,
  claimed_at    timestamptz,
  claimed_by    text,
  finished_at   timestamptz,
  last_error    text
);

CREATE INDEX IF NOT EXISTS idx_hunt_job_pending
  ON hunt_job (enqueued_at)
  WHERE finished_at IS NULL AND claimed_at IS NULL;
