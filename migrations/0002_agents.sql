-- Milestone 1: agent enrollment, identity, and health (spec 10.1, 10.11).
-- Tenant-scoped like every other data table (0001 tenant registry).

-- One-time enrollment tokens minted by operators via corpusctl.
CREATE TABLE enrollment_token (
  token_sha256        bytea PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  label               text NOT NULL DEFAULT '',
  created_at          timestamptz NOT NULL,
  expires_at          timestamptz,
  consumed_by         uuid,
  consumed_at         timestamptz
);

-- Enrolled agents. token_sha256 authenticates bearer requests; the
-- plaintext token is shown exactly once at enrollment.
CREATE TABLE agent (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  host_name           text NOT NULL,
  token_sha256        bytea NOT NULL,
  version             text NOT NULL,
  enrolled_at         timestamptz NOT NULL,
  last_heartbeat_at   timestamptz,
  last_upload_at      timestamptz,
  policy_digest       text,
  baseline_state      text,
  baseline_percent    double precision,
  queue_depth         bigint,
  spool_bytes         bigint,
  oldest_pending_secs bigint,
  sensor              text,
  outcome_counts      jsonb NOT NULL DEFAULT '{}'::jsonb,
  clock_offset_ms     bigint
);
