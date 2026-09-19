// UserDO SQLite schema (spec §4.2), versioned for lazy migration. Each entry
// is one idempotent step; `migrate()` applies the steps above the stored version.

export const USER_SCHEMA_VERSION = 1;

export const USER_SCHEMA_STEPS: readonly string[] = [
  `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user (
  id             TEXT PRIMARY KEY,
  email          TEXT,
  email_norm     TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name   TEXT,
  groups         TEXT NOT NULL DEFAULT '[]',
  disabled_at    INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
  id              TEXT PRIMARY KEY,
  credential_id   TEXT NOT NULL UNIQUE,
  public_key      BLOB NOT NULL,
  alg             INTEGER NOT NULL,
  counter         INTEGER NOT NULL DEFAULT 0,
  transports      TEXT NOT NULL DEFAULT '[]',
  aaguid          TEXT,
  backup_eligible INTEGER NOT NULL,
  backed_up       INTEGER NOT NULL,
  name            TEXT,
  created_via     TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS identities (
  id             TEXT PRIMARY KEY,
  issuer         TEXT NOT NULL,
  subject        TEXT NOT NULL,
  email          TEXT,
  email_verified INTEGER,
  name           TEXT,
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER,
  UNIQUE (issuer, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
  sid                 TEXT PRIMARY KEY,
  secret_hash         BLOB NOT NULL UNIQUE,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,
  idle_expires_at     INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  auth_time           INTEGER NOT NULL,
  amr                 TEXT NOT NULL,
  acr                 TEXT NOT NULL,
  upstream            TEXT,
  ip_hash             TEXT,
  ua_family           TEXT,
  country             TEXT,
  revoked_at          INTEGER,
  revoke_reason       TEXT
);
CREATE TABLE IF NOT EXISTS session_clients (
  sid       TEXT NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  first_at  INTEGER NOT NULL,
  PRIMARY KEY (sid, client_id)
);
CREATE TABLE IF NOT EXISTS auth_codes (
  secret_hash     BLOB PRIMARY KEY,
  client_id       TEXT NOT NULL,
  redirect_uri    TEXT NOT NULL,
  scope           TEXT NOT NULL,
  nonce           TEXT,
  code_challenge  TEXT NOT NULL,
  sid             TEXT NOT NULL,
  auth_time       INTEGER NOT NULL,
  amr             TEXT NOT NULL,
  acr             TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER
);
CREATE INDEX IF NOT EXISTS auth_codes_expires ON auth_codes(expires_at);
CREATE TABLE IF NOT EXISTS refresh_families (
  id                  TEXT PRIMARY KEY,
  client_id           TEXT NOT NULL,
  client_created_at   INTEGER NOT NULL,
  kind                TEXT NOT NULL CHECK (kind IN ('session','offline')),
  sid                 TEXT,
  scope               TEXT NOT NULL,
  auth_time           INTEGER NOT NULL,
  amr                 TEXT NOT NULL,
  acr                 TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  idle_expires_at     INTEGER NOT NULL,
  current_serial      INTEGER NOT NULL DEFAULT 1,
  revoked_at          INTEGER,
  revoke_reason       TEXT
);
CREATE INDEX IF NOT EXISTS refresh_families_client ON refresh_families(client_id);
CREATE INDEX IF NOT EXISTS refresh_families_sid    ON refresh_families(sid);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  secret_hash  BLOB PRIMARY KEY,
  family_id    TEXT NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
  serial       INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens(family_id, serial);
CREATE TABLE IF NOT EXISTS grants (
  client_id         TEXT PRIMARY KEY,
  client_created_at INTEGER NOT NULL,
  scopes            TEXT NOT NULL,
  granted_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);
`,
];
