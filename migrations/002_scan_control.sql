CREATE TABLE IF NOT EXISTS repository_scan_configs (
  repository_id text PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT true,
  vaccin boolean NOT NULL DEFAULT true,
  enetron boolean NOT NULL DEFAULT true,
  gate_severity text NOT NULL DEFAULT 'high' CHECK (gate_severity IN ('info','low','medium','high','critical')),
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_recasts (
  id text PRIMARY KEY,
  finding_id text NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  actor_id text NOT NULL REFERENCES users(id),
  from_severity text NOT NULL,
  to_severity text NOT NULL,
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_recasts_history_idx ON finding_recasts(finding_id,created_at DESC);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS recast_severity text;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS gate_severity text NOT NULL DEFAULT 'high';
