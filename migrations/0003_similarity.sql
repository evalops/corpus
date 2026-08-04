-- Milestone 3a: similarity features, typed edges, variant groups (spec 16).

-- Versioned features per artifact. family: exact | normalized | byte |
-- structural | semantic (plugin slot, unpopulated in M3a) | provenance.
CREATE TABLE similarity_feature (
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  artifact_id         uuid NOT NULL,
  family              text NOT NULL,
  name                text NOT NULL,
  version             text NOT NULL,
  value               jsonb NOT NULL,
  created_at          timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id, family, name, version)
);
-- Candidate-generation lookup: normalized hash index (spec 16.3 layer 1).
CREATE INDEX idx_simfeature_hash
  ON similarity_feature (tenant_id, family, name, ((value->>'hash')));

-- Typed, versioned edges with component evidence (spec 16.4). Stored once
-- per unordered pair (src < dst) since edges here are symmetric.
CREATE TABLE similarity_edge (
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  src_artifact        uuid NOT NULL,
  dst_artifact        uuid NOT NULL,
  edge_type           text NOT NULL,
  model_version       text NOT NULL,
  score               double precision NOT NULL,
  evidence            jsonb NOT NULL,
  created_at          timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, src_artifact, dst_artifact, edge_type, model_version),
  CHECK (src_artifact < dst_artifact)
);
CREATE INDEX idx_simedge_dst ON similarity_edge (tenant_id, dst_artifact);
CREATE INDEX idx_simedge_src ON similarity_edge (tenant_id, src_artifact);

-- Deterministic connected components over strong edges (spec 16.6).
-- Weak edges never create or merge groups.
CREATE TABLE variant_group (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  created_at          timestamptz NOT NULL
);

CREATE TABLE variant_group_member (
  tenant_id           uuid NOT NULL REFERENCES tenant (id),
  group_id            uuid NOT NULL REFERENCES variant_group (id),
  artifact_id         uuid NOT NULL,
  -- One group per artifact: group membership is a partition.
  PRIMARY KEY (tenant_id, artifact_id)
);
CREATE INDEX idx_vgm_group ON variant_group_member (tenant_id, group_id);
