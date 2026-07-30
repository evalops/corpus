-- Milestone 0 schema: tenant-scoped CAS catalog, occurrence ledger,
-- rule registry, immutable bundles, hunts, matches, scan cache.
-- All tables carry tenant_id even though M0 is single-tenant.

CREATE TABLE artifact (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  seq                 BIGSERIAL NOT NULL,
  sha256              bytea NOT NULL,
  size_bytes          bigint NOT NULL CHECK (size_bytes >= 0),
  artifact_class      text NOT NULL,
  storage_state       text NOT NULL,          -- storage_pending | committed
  object_key          text,
  first_committed_at  timestamptz NOT NULL,
  UNIQUE (tenant_id, sha256)
);
CREATE INDEX idx_artifact_tenant_seq ON artifact (tenant_id, seq);

-- Upload sessions allocated by announce (spec 11.2 two-phase commit).
CREATE TABLE upload_session (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  announced_sha256    bytea NOT NULL,
  announced_size      bigint NOT NULL,
  staging_key         text NOT NULL,
  state               text NOT NULL,          -- open | committed | failed
  created_at          timestamptz NOT NULL
);

CREATE TABLE occurrence_event (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  host_name           text NOT NULL,
  agent_id            uuid NOT NULL,
  boot_id             uuid NOT NULL,
  agent_sequence      bigint NOT NULL,
  artifact_id         uuid,
  artifact_sha256     bytea,
  event_type          text NOT NULL,
  capture_reason      text NOT NULL,
  observed_at         timestamptz NOT NULL,
  received_at         timestamptz NOT NULL,
  path                text,
  file_size           bigint,
  file_mtime          timestamptz,
  process_evidence    jsonb,
  UNIQUE (agent_id, boot_id, agent_sequence)
);
CREATE INDEX idx_occurrence_artifact ON occurrence_event (tenant_id, artifact_id);
CREATE INDEX idx_occurrence_host ON occurrence_event (tenant_id, host_name);

CREATE TABLE capture_attempt (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  host_name           text NOT NULL,
  agent_id            uuid NOT NULL,
  observed_at         timestamptz NOT NULL,
  capture_reason      text NOT NULL,
  terminal_outcome    text NOT NULL,
  artifact_sha256     bytea,
  path                text,
  detail_code         text,
  detail              jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_capture_attempt_tenant ON capture_attempt (tenant_id);

CREATE TABLE rule (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  namespace           text NOT NULL DEFAULT 'default',
  stable_id           text NOT NULL,
  source              text NOT NULL,
  state               text NOT NULL,          -- DRAFT | VALIDATED | ACTIVE | REVOKED
  created_at          timestamptz NOT NULL,
  updated_at          timestamptz NOT NULL,
  UNIQUE (tenant_id, namespace, stable_id)
);

CREATE TABLE rule_bundle (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  digest              text NOT NULL,
  scope               text NOT NULL DEFAULT 'tenant',
  engine_version      text NOT NULL,
  active              boolean NOT NULL DEFAULT false,  -- forward coverage flag (spec 15.9)
  created_at          timestamptz NOT NULL,
  UNIQUE (tenant_id, digest)
);

CREATE TABLE rule_bundle_rule (
  bundle_id           uuid NOT NULL REFERENCES rule_bundle (id),
  rule_id             uuid NOT NULL REFERENCES rule (id),
  position            integer NOT NULL,
  PRIMARY KEY (bundle_id, rule_id)
);

CREATE TABLE hunt (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL,
  kind                text NOT NULL,          -- retro | forward
  bundle_id           uuid NOT NULL REFERENCES rule_bundle (id),
  bundle_digest       text NOT NULL,
  state               text NOT NULL,
  corpus_watermark    bigint,
  planned_artifacts   bigint NOT NULL DEFAULT 0,
  scanned             bigint NOT NULL DEFAULT 0,
  cache_hits          bigint NOT NULL DEFAULT 0,
  matched             bigint NOT NULL DEFAULT 0,
  timed_out           bigint NOT NULL DEFAULT 0,
  failed              bigint NOT NULL DEFAULT 0,
  error               text,
  created_at          timestamptz NOT NULL,
  started_at          timestamptz,
  completed_at        timestamptz
);

CREATE TABLE hunt_match (
  hunt_id             uuid NOT NULL REFERENCES hunt (id),
  tenant_id           uuid NOT NULL,
  artifact_id         uuid NOT NULL,
  rule_id             text NOT NULL,
  engine_version      text NOT NULL,
  match_summary       jsonb NOT NULL,
  created_at          timestamptz NOT NULL,
  PRIMARY KEY (hunt_id, artifact_id, rule_id)
);

-- Scan result cache (spec 15.4):
-- (tenant_id, artifact_sha256, rule_bundle_digest, yara_x_engine_version, scan_config_digest)
CREATE TABLE scan_cache (
  tenant_id           uuid NOT NULL,
  artifact_sha256     bytea NOT NULL,
  rule_bundle_digest  text NOT NULL,
  engine_version      text NOT NULL,
  scan_config_digest  text NOT NULL,
  status              text NOT NULL,          -- clean | matched | timeout | error
  matched_rule_ids    jsonb NOT NULL DEFAULT '[]'::jsonb,
  duration_ms         bigint NOT NULL DEFAULT 0,
  error_code          text,
  created_at          timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, artifact_sha256, rule_bundle_digest, engine_version, scan_config_digest)
);
