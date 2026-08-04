-- Milestone 4 (vault bootstrap): snapshot backfill, OCI ingestion,
-- intel-corpus connectors.

-- Artifact scope separates endpoint-collected bytes from intel imports.
-- Default queries (retro hunts, blast radius occurrence views) cover
-- 'endpoint' only; intel artifacts carry no host occurrences.
ALTER TABLE artifact ADD COLUMN scope text NOT NULL DEFAULT 'endpoint';
ALTER TABLE artifact ADD COLUMN provenance jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX idx_artifact_scope ON artifact (tenant_id, scope);

-- External indicators (TAXII/STIX, manual feeds). Hash IOCs can be
-- hash-hunted against endpoint-scope artifacts.
CREATE TABLE intel_indicator (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  source              text NOT NULL,          -- taxii:<url> | manual | malwarebazaar
  ioc_type            text NOT NULL,          -- sha256 | sha1 | md5 | domain | url
  value               text NOT NULL,
  raw                 jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen          timestamptz NOT NULL,
  last_seen           timestamptz NOT NULL,
  UNIQUE (tenant_id, source, ioc_type, value)
);
CREATE INDEX idx_intel_indicator_value ON intel_indicator (tenant_id, ioc_type, value);
