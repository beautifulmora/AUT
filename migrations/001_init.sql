CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY, email text NOT NULL, username text NOT NULL, first_name text NOT NULL, last_name text NOT NULL,
 password_hash text, avatar text, active boolean NOT NULL DEFAULT true, verified boolean NOT NULL DEFAULT false,
 last_login_at timestamptz, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, deleted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users(lower(email)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq ON users(lower(username)) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS identities (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, provider text NOT NULL,
 provider_subject text NOT NULL, email text NOT NULL DEFAULT '', display_name text NOT NULL DEFAULT '', avatar text NOT NULL DEFAULT '', created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS identities_provider_subject_uq ON identities(provider,provider_subject);
CREATE INDEX IF NOT EXISTS identities_user_idx ON identities(user_id);
CREATE TABLE IF NOT EXISTS sessions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash text NOT NULL UNIQUE,
 family_id uuid NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_family_idx ON sessions(family_id);
