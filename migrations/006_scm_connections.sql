CREATE TABLE IF NOT EXISTS scm_connections (
  id text PRIMARY KEY,
  provider text NOT NULL CHECK (provider IN ('gitlab','github')),
  label text NOT NULL,
  base_url text NOT NULL DEFAULT '',
  secret_ciphertext bytea NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  auto_enroll boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_sync_at timestamptz
);
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scm_connection_id text REFERENCES scm_connections(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS repositories_scm_connection_idx ON repositories(scm_connection_id);
CREATE TABLE IF NOT EXISTS scm_ignored_repositories (
  connection_id text NOT NULL REFERENCES scm_connections(id) ON DELETE CASCADE,
  provider_project_id text NOT NULL,
  PRIMARY KEY(connection_id,provider_project_id)
);
