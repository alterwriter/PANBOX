ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scm_base_url text NOT NULL DEFAULT '';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS default_branch_source text NOT NULL DEFAULT 'manual';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_provider_provider_project_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS repositories_active_scm_uq
  ON repositories(provider, scm_base_url, provider_project_id) WHERE archived_at IS NULL;
