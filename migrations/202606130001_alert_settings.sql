CREATE TABLE organization_alert_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    minimum_severity severity NOT NULL DEFAULT 'high',
    suppression_window_hours INTEGER NOT NULL DEFAULT 24,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT organization_alert_settings_suppression_window_check
        CHECK (suppression_window_hours BETWEEN 1 AND 720)
);

INSERT INTO organization_alert_settings (organization_id)
SELECT id
FROM organizations
ON CONFLICT (organization_id) DO NOTHING;
