-- Milestone M10: detonation findings (spec 13.4, 17.4).
--
-- External sandbox job records and behavioral result storage.

-- Analyzer runs (spec 12.2 sketch; the table was deferred from the M0
-- subset until the first producer — detonation — needed it).
CREATE TABLE analysis_run (
  id                    uuid PRIMARY KEY,
  tenant_id             uuid NOT NULL REFERENCES tenant (id),
  artifact_id           uuid NOT NULL,
  analyzer_name         text NOT NULL,
  analyzer_version      text NOT NULL,
  analyzer_image_digest text NOT NULL,
  config_digest         bytea NOT NULL,
  support_data_digest   bytea NOT NULL,
  status                text NOT NULL,
  started_at            timestamptz,
  completed_at          timestamptz,
  raw_report_object_key text,
  error_code            text,
  UNIQUE (
    tenant_id, artifact_id, analyzer_name, analyzer_image_digest,
    config_digest, support_data_digest
  )
);

-- Analyzer findings with evidence typing. The first producer of
-- DYNAMIC_BEHAVIOR evidence in the platform.
CREATE TABLE finding (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  analysis_run_id     uuid NOT NULL REFERENCES analysis_run (id),
  evidence_type       text NOT NULL,          -- STATIC_CAPABILITY | STATIC_INDICATOR | DYNAMIC_BEHAVIOR | HOST_TELEMETRY_OBSERVED | ANALYST_ASSERTED
  category            text NOT NULL,          -- signature | attack | network | file | registry | process
  summary             text NOT NULL,
  detail              jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL
);
CREATE INDEX idx_finding_artifact ON finding (tenant_id, artifact_id);
