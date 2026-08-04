-- Keep migration 0002 immutable; add tenant referential integrity separately.
-- NOT VALID avoids blocking startup on legacy rows while enforcing the
-- relationship for all new writes. The constraints can be validated after
-- existing data is audited.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'enrollment_token_tenant_id_fkey'
  ) THEN
    ALTER TABLE enrollment_token
      ADD CONSTRAINT enrollment_token_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES tenant (id) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_tenant_id_fkey'
  ) THEN
    ALTER TABLE agent
      ADD CONSTRAINT agent_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES tenant (id) NOT VALID;
  END IF;
END $$;
