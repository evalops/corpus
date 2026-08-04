-- Analysis receipts (deterministic, no sample bytes) and similarity cleanup audit.

CREATE TABLE IF NOT EXISTS analysis_receipt (
  id                  text PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  analyzer_name       text NOT NULL,
  analyzer_version    text NOT NULL,
  model_version       text NOT NULL,
  config_digest       text NOT NULL,
  status              text NOT NULL,
  body                jsonb NOT NULL,
  created_at          timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipt_artifact
  ON analysis_receipt (tenant_id, artifact_id, created_at DESC);

CREATE TABLE IF NOT EXISTS similarity_cleanup_log (
  id                  bigserial PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  dry_run             boolean NOT NULL DEFAULT false,
  counts              jsonb NOT NULL,
  created_at          timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cleanup_log_artifact
  ON similarity_cleanup_log (tenant_id, artifact_id);
