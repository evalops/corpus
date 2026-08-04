-- Milestone 5: analyst surface — opinions, triggers, audit.
-- (Prevalence and dropper hunts are pure SQL over the occurrence ledger;
-- proof-of-absence is computed, not stored.)

-- Human verdicts, separate from analyzer scores (spec 5.5). Append-only;
-- the current opinion for an artifact is the latest row.
CREATE TABLE artifact_opinion (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  opinion             text NOT NULL,          -- trusted | grayware | vulnerable | malicious | suspicious
  actor               text NOT NULL,
  reason              text NOT NULL DEFAULT '',
  created_at          timestamptz NOT NULL,
  superseded_by       uuid
);
CREATE INDEX idx_opinion_artifact ON artifact_opinion (tenant_id, artifact_id, created_at DESC);

-- Exactly three trigger conditions (no general event system):
-- hunt_match | malicious_verdict | variant_join
CREATE TABLE trigger_rule (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  name                text NOT NULL,
  condition           text NOT NULL,
  webhook_url         text NOT NULL,
  hmac_secret         text NOT NULL,
  enabled             boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL
);

-- Delivery outbox polled by the server (no external broker).
CREATE TABLE trigger_outbox (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  trigger_id          uuid NOT NULL REFERENCES trigger_rule (id),
  event               jsonb NOT NULL,
  attempts            integer NOT NULL DEFAULT 0,
  next_attempt_at     timestamptz NOT NULL,
  delivered_at        timestamptz,
  last_error          text,
  created_at          timestamptz NOT NULL
);
CREATE INDEX idx_outbox_due ON trigger_outbox (next_attempt_at) WHERE delivered_at IS NULL;

-- Audit events (spec 24.3).
CREATE TABLE audit_event (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  actor               text NOT NULL,
  action              text NOT NULL,
  target              text NOT NULL,
  detail              jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL
);
CREATE INDEX idx_audit_tenant_time ON audit_event (tenant_id, created_at);
