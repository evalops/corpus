-- Merlin telemetry bridge. Raw events remain separate from the verified
-- artifact occurrence ledger; event identity is still durable and replay-safe.
--
-- Merlin segment/observation bridge tables (separate from occurrence ledger).

CREATE TABLE IF NOT EXISTS merlin_segment (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenant (id),
  host_name       text NOT NULL,
  segment         text NOT NULL,
  segment_sha256  text NOT NULL CHECK (segment_sha256 ~ '^[a-fA-F0-9]{64}$'),
  schema_version  integer NOT NULL,
  received_at     timestamptz NOT NULL,
  event_count     bigint NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  UNIQUE (tenant_id, host_name, segment)
);

CREATE INDEX IF NOT EXISTS idx_merlin_segment_tenant_received
  ON merlin_segment (tenant_id, received_at DESC);

CREATE TABLE IF NOT EXISTS merlin_observation (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenant (id),
  segment_id       uuid NOT NULL REFERENCES merlin_segment (id),
  host_name        text NOT NULL,
  segment          text NOT NULL,
  event_id         text NOT NULL,
  boot_id          text NOT NULL,
  source_seq       bigint,
  kind             text NOT NULL,
  process_key      text,
  artifact_sha256  text CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[a-fA-F0-9]{64}$'),
  observed_at      timestamptz,
  received_at      timestamptz NOT NULL,
  payload          jsonb NOT NULL,
  UNIQUE (tenant_id, host_name, event_id)
);

CREATE INDEX IF NOT EXISTS idx_merlin_observation_tenant_host_time
  ON merlin_observation (tenant_id, host_name, observed_at DESC NULLS LAST, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_merlin_observation_artifact
  ON merlin_observation (tenant_id, artifact_sha256)
  WHERE artifact_sha256 IS NOT NULL;
