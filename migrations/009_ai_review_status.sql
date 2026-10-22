ALTER TABLE ai_review_worker_health
  ADD COLUMN IF NOT EXISTS auth_status text NOT NULL DEFAULT 'login_required'
    CHECK (auth_status IN ('ready','login_required'));
ALTER TABLE ai_review_worker_health
  ADD COLUMN IF NOT EXISTS auth_checked_at timestamptz;
CREATE INDEX IF NOT EXISTS ai_review_runs_scan_created_idx ON ai_review_runs(scan_id,created_at DESC);
