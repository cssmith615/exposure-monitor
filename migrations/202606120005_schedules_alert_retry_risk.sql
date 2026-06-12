CREATE TYPE scan_cadence AS ENUM ('manual', 'daily', 'weekly');
CREATE TYPE scan_profile AS ENUM ('dns_baseline', 'http_probe', 'dns_policy', 'full_domain_baseline');

CREATE TABLE scheduled_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cadence scan_cadence NOT NULL,
    profile scan_profile NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    next_run_at TIMESTAMPTZ,
    last_enqueued_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, profile)
);

ALTER TABLE alerts
ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3,
ADD COLUMN next_attempt_at TIMESTAMPTZ,
ADD COLUMN locked_at TIMESTAMPTZ;

ALTER TABLE findings
ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1,
ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0,
ADD COLUMN risk_factors JSONB NOT NULL DEFAULT '{}';

CREATE INDEX idx_scheduled_scans_due ON scheduled_scans(enabled, next_run_at)
WHERE enabled = true;

CREATE INDEX idx_scheduled_scans_org_asset ON scheduled_scans(organization_id, asset_id);

CREATE INDEX idx_alerts_queue_claim ON alerts(status, next_attempt_at, created_at)
WHERE status IN ('queued', 'failed');

CREATE INDEX idx_findings_attention ON findings(organization_id, status, risk_score DESC, last_seen_at DESC);
