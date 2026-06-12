ALTER TABLE scan_jobs
    ADD COLUMN asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    ADD COLUMN reason TEXT,
    ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'dns_baseline',
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN next_run_at TIMESTAMPTZ,
    ADD COLUMN locked_at TIMESTAMPTZ;

CREATE INDEX idx_scan_jobs_queue_claim
    ON scan_jobs(status, next_run_at, created_at)
    WHERE status = 'queued';

CREATE INDEX idx_scan_jobs_asset_id ON scan_jobs(asset_id);
