-- +goose Up
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL CHECK (password_hash <> ''),
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '' CHECK (char_length(bio) <= 1000),
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'muted', 'frozen', 'banned', 'deleted')),
    muted_until TIMESTAMPTZ NULL,
    violation_count INTEGER NOT NULL DEFAULT 0 CHECK (violation_count >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= created_at),
    deleted_at TIMESTAMPTZ NULL CHECK (deleted_at IS NULL OR deleted_at >= created_at),
    CHECK (email <> ''),
    CHECK (email = lower(btrim(email))),
    CHECK (octet_length(email) <= 320),
    CHECK (char_length(display_name) BETWEEN 1 AND 100),
    CHECK (display_name = btrim(display_name)),
    CHECK ((status = 'muted') = (muted_until IS NOT NULL)),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

CREATE UNIQUE INDEX users_email_uidx ON users (email);

CREATE TABLE user_sessions (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    user_id BIGINT NOT NULL REFERENCES users(id),
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX user_sessions_user_created_idx ON user_sessions (user_id, created_at DESC);
CREATE INDEX user_sessions_active_user_idx ON user_sessions (user_id, id) WHERE revoked_at IS NULL;

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system')),
    actor_id BIGINT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action <> ''),
    target_type TEXT NOT NULL CHECK (target_type <> ''),
    target_id BIGINT NOT NULL CHECK (target_id > 0),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    CHECK ((actor_type = 'system') = (actor_id IS NULL))
);

CREATE INDEX audit_logs_target_created_idx ON audit_logs (target_type, target_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS users;
