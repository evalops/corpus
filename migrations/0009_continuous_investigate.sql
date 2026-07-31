-- Continuous re-analysis tracking, autonomous detection events, and
-- investigation scaffolding for the continuous re-analysis product loop:
-- retain → detect → re-hunt history → blast radius → recommended actions.

CREATE TABLE IF NOT EXISTS detection_event (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenant (id),
  artifact_id       uuid NOT NULL,
  source            text NOT NULL,
  severity          text NOT NULL,
  title             text NOT NULL,
  detail            jsonb NOT NULL,
  mitre_techniques  text[] NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detection_tenant_created
  ON detection_event (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_artifact
  ON detection_event (tenant_id, artifact_id);

CREATE TABLE IF NOT EXISTS continuous_reanalysis (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenant (id),
  trigger_kind    text NOT NULL,
  trigger_ref     text,
  hunt_id         uuid,
  state           text NOT NULL,
  detail          jsonb NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL,
  completed_at    timestamptz
);

CREATE INDEX IF NOT EXISTS idx_continuous_tenant
  ON continuous_reanalysis (tenant_id, created_at DESC);
