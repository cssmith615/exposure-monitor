ALTER TABLE users
ADD COLUMN email_verified_at TIMESTAMPTZ,
ADD COLUMN password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE users
SET email_verified_at = now()
WHERE email_verified_at IS NULL;

ALTER TABLE sessions
ADD COLUMN last_seen_at TIMESTAMPTZ;

CREATE UNIQUE INDEX idx_sessions_token_hash_unique ON sessions(token_hash);
CREATE INDEX idx_sessions_active ON sessions(id, token_hash, expires_at)
WHERE revoked_at IS NULL;

CREATE TABLE auth_rate_limits (
    bucket TEXT NOT NULL,
    rate_key TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket, rate_key)
);

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_rate_limits_updated_at ON auth_rate_limits(updated_at);
CREATE INDEX idx_email_verification_tokens_user_id_created_at
    ON email_verification_tokens(user_id, created_at DESC);
CREATE INDEX idx_password_reset_tokens_user_id_created_at
    ON password_reset_tokens(user_id, created_at DESC);
