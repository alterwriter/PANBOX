CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY, email text NOT NULL UNIQUE, password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), disabled boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS roles (
  name text PRIMARY KEY, description text NOT NULL DEFAULT '', built_in boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_name text NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
  permission text NOT NULL, PRIMARY KEY(role_name, permission)
);
CREATE TABLE IF NOT EXISTS user_roles (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_name text NOT NULL REFERENCES roles(name), PRIMARY KEY(user_id, role_name)
);
CREATE TABLE IF NOT EXISTS credentials (
  id text PRIMARY KEY, owner_id text NOT NULL REFERENCES users(id), kind text NOT NULL CHECK(kind IN ('api','access','scan')),
  label text NOT NULL, secret_hash text NOT NULL UNIQUE,
  scopes jsonb NOT NULL DEFAULT '[]', repository_id text,
  expires_at timestamptz, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  secret_hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id),
  csrf_hash text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
  id text PRIMARY KEY, name text NOT NULL, provider text NOT NULL,
  provider_project_id text NOT NULL, default_branch text NOT NULL DEFAULT 'main',
  owner text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(provider, provider_project_id)
);
CREATE TABLE IF NOT EXISTS repository_members (
  repository_id text NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(repository_id, user_id)
);
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='credentials_repository_fk') THEN
    ALTER TABLE credentials ADD CONSTRAINT credentials_repository_fk FOREIGN KEY (repository_id) REFERENCES repositories(id);
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS scans (
  id text PRIMARY KEY, client_scan_id text NOT NULL, repository_id text NOT NULL REFERENCES repositories(id),
  branch text NOT NULL, commit_sha text NOT NULL, base_sha text NOT NULL DEFAULT '',
  status text NOT NULL CHECK(status IN ('complete','partial','error')),
  module_status jsonb NOT NULL, gate_pass boolean, gate_revision integer NOT NULL DEFAULT 1,
  policy_version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(repository_id, client_scan_id)
);
CREATE INDEX IF NOT EXISTS scans_latest_idx ON scans(repository_id, branch, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_base_idx ON scans(repository_id, commit_sha) WHERE status='complete';
CREATE TABLE IF NOT EXISTS findings (
  id text PRIMARY KEY, repository_id text NOT NULL REFERENCES repositories(id), module text NOT NULL,
  fingerprint text NOT NULL, rule_id text NOT NULL, path text NOT NULL DEFAULT '',
  message text NOT NULL DEFAULT '', first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(), UNIQUE(repository_id, module, fingerprint)
);
CREATE TABLE IF NOT EXISTS occurrences (
  scan_id text NOT NULL REFERENCES scans(id), finding_id text NOT NULL REFERENCES findings(id),
  raw_severity text NOT NULL, effective_severity text NOT NULL,
  baseline_status text NOT NULL, line integer NOT NULL DEFAULT 0,
  PRIMARY KEY(scan_id, finding_id)
);
CREATE TABLE IF NOT EXISTS gate_evaluations (
  scan_id text NOT NULL REFERENCES scans(id), revision integer NOT NULL,
  policy_version integer NOT NULL, passed boolean, reasons jsonb NOT NULL DEFAULT '[]',
  evaluated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(scan_id, revision)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id text PRIMARY KEY, actor_id text, action text NOT NULL, target text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
