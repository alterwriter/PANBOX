CREATE TABLE IF NOT EXISTS ai_review_settings (
  id integer PRIMARY KEY CHECK (id=1), enabled boolean NOT NULL DEFAULT false,
  provider text NOT NULL DEFAULT 'openai' CHECK (provider IN ('openai','anthropic')),
  model text NOT NULL DEFAULT '', max_findings integer NOT NULL DEFAULT 3 CHECK (max_findings BETWEEN 1 AND 10),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO ai_review_settings(id) VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ai_review_runs (
  id text PRIMARY KEY, scan_id text NOT NULL REFERENCES scans(id), repository_id text NOT NULL REFERENCES repositories(id),
  provider text NOT NULL, model text NOT NULL, status text NOT NULL CHECK(status IN ('queued','running','completed','partial','failed','cancelled')),
  max_findings integer NOT NULL, error_code text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz, finished_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_review_runs_queue_idx ON ai_review_runs(status,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS ai_review_one_active_scan_idx ON ai_review_runs(scan_id) WHERE status IN ('queued','running');
CREATE TABLE IF NOT EXISTS ai_review_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, run_id text NOT NULL REFERENCES ai_review_runs(id),
  stage text NOT NULL, message text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_review_events_run_idx ON ai_review_events(run_id,id);
CREATE TABLE IF NOT EXISTS ai_review_assessments (
  run_id text NOT NULL REFERENCES ai_review_runs(id), finding_id text NOT NULL REFERENCES findings(id),
  verdict text NOT NULL CHECK(verdict IN ('needs_review','likely_true_positive','likely_false_positive')),
  confidence text NOT NULL CHECK(confidence IN ('low','medium','high')),
  explanation text NOT NULL, remediation text NOT NULL, evidence text NOT NULL,
  PRIMARY KEY(run_id,finding_id)
);
