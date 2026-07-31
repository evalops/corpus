-- Milestone M8: per-function semantic signatures (spec 16.2/16.5).

CREATE TABLE similarity_function (
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  func_offset         bigint NOT NULL,         -- file offset of the function start
  func_size           bigint NOT NULL,
  name                text,
  insn_count          bigint NOT NULL,
  sig                 bytea NOT NULL,          -- 256-bit simhash
  version             text NOT NULL,           -- semantic:v1
  created_at          timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id, func_offset, version)
);
-- Candidate band filter: first signature byte before hamming comparison.
CREATE INDEX idx_simfunc_band ON similarity_function (tenant_id, version, (substring(sig from 1 for 1)));
