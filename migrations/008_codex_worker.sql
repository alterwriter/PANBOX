ALTER TABLE ai_review_settings DROP CONSTRAINT IF EXISTS ai_review_settings_provider_check;
ALTER TABLE ai_review_settings ADD CONSTRAINT ai_review_settings_provider_check CHECK (provider IN ('openai','anthropic','codex'));
ALTER TABLE ai_review_settings ALTER COLUMN provider SET DEFAULT 'codex';
UPDATE ai_review_settings SET provider='codex' WHERE enabled=false AND provider='openai' AND model='';

CREATE TABLE IF NOT EXISTS ai_review_worker_health (
  provider text PRIMARY KEY,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
