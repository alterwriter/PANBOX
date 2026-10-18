CREATE TABLE IF NOT EXISTS finding_dispositions (
  finding_id text PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  status text NOT NULL CHECK(status IN ('open','false_positive','accepted_risk','closed')),
  reason text NOT NULL DEFAULT '',
  actor_id text REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_disposition_events (
  id text PRIMARY KEY,
  finding_id text NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  from_status text NOT NULL,
  to_status text NOT NULL,
  reason text NOT NULL,
  actor_id text REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_disposition_events_idx ON finding_disposition_events(finding_id,created_at DESC);
