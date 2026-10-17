ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scm_check_status text NOT NULL DEFAULT 'manual_required';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scm_checked_at timestamptz;
