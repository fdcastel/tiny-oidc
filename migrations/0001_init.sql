-- Tiny OIDC D1 directory schema, migration 0001 (spec §4.1).
-- users: registry of existence. UserDO is the source of truth for content.
CREATE TABLE users (
  id              TEXT PRIMARY KEY,                 -- UUID v7
  email           TEXT,                             -- mirror, as given
  email_norm      TEXT,                             -- mirror, normalized (lowercase NFC trim)
  email_verified  INTEGER NOT NULL DEFAULT 0,
  display_name    TEXT,
  status          TEXT NOT NULL CHECK (status IN ('creating','active','disabled','deleting')),
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_verified_email ON users(email_norm) WHERE email_verified = 1 AND email_norm IS NOT NULL;
CREATE INDEX users_email_norm ON users(email_norm);
CREATE INDEX users_created   ON users(created_at, id);
CREATE INDEX users_status    ON users(status, updated_at);

CREATE TABLE groups (
  id          TEXT PRIMARY KEY,                     -- UUID v7
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  system      INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE group_members (
  group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  added_at  INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);

CREATE TABLE passkey_index (
  credential_id TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL
);
CREATE INDEX passkey_index_user ON passkey_index(user_id);

CREATE TABLE identity_index (
  issuer     TEXT NOT NULL,
  subject    TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX identity_index_user ON identity_index(user_id);

CREATE TABLE clients (
  client_id                   TEXT PRIMARY KEY,
  client_name                 TEXT NOT NULL,
  client_uri                  TEXT,
  logo_uri                    TEXT,
  redirect_uris               TEXT NOT NULL,        -- JSON array
  post_logout_redirect_uris   TEXT NOT NULL DEFAULT '[]',
  backchannel_logout_uri      TEXT,
  grant_types                 TEXT NOT NULL,        -- JSON array ⊆ ["authorization_code","refresh_token","client_credentials"]
  token_endpoint_auth_method  TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none','client_secret_basic','client_secret_post','private_key_jwt')),
  client_secret_hash          BLOB,                 -- SHA-256 of the secret; NULL unless method is client_secret_basic or client_secret_post
  jwks                        TEXT,                 -- JSON JWK Set for private_key_jwt (either jwks or jwks_uri)
  jwks_uri                    TEXT,
  scopes_allowed              TEXT NOT NULL,        -- JSON array
  audiences                   TEXT NOT NULL DEFAULT '[]',   -- JSON array of resource identifiers placed in aud (TIO-TOKEN-033)
  allowed_groups              TEXT,                 -- NULL = everyone; JSON array of group names otherwise
  skip_consent                INTEGER NOT NULL DEFAULT 0,
  require_par                 INTEGER NOT NULL DEFAULT 0,
  offline_access              INTEGER NOT NULL DEFAULT 0,
  access_token_ttl            INTEGER,              -- seconds; NULL = setting default
  id_token_ttl                INTEGER,
  refresh_token_ttl           INTEGER,              -- absolute, offline families
  refresh_idle_ttl            INTEGER,
  disabled_at                 INTEGER,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);

CREATE TABLE upstreams (
  alias                       TEXT PRIMARY KEY,
  issuer                      TEXT NOT NULL UNIQUE,
  display_name                TEXT NOT NULL,
  client_id                   TEXT NOT NULL,
  token_endpoint_auth_method  TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_basic','client_secret_post','private_key_jwt')),
  client_secret_enc           BLOB,                 -- AES-GCM under MASTER_KEYS (keystore info)
  client_jwk_enc              BLOB,                 -- private JWK for private_key_jwt, encrypted
  scopes                      TEXT NOT NULL DEFAULT 'openid email profile',
  discovery                   TEXT NOT NULL,        -- JSON: {"mode":"auto"} | {"mode":"manual", authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint?}
  use_userinfo                INTEGER NOT NULL DEFAULT 0,
  trust_email_verified        INTEGER NOT NULL DEFAULT 0,
  claims_map                  TEXT NOT NULL DEFAULT '{}',   -- {"email":"email","email_verified":"email_verified","name":"name"}
  required_claims             TEXT NOT NULL DEFAULT '{}',   -- {"hd":"example.com"} equality checks
  extra_authorize_params      TEXT NOT NULL DEFAULT '{}',
  enabled                     INTEGER NOT NULL DEFAULT 1,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);

CREATE TABLE signing_keys (
  kid             TEXT PRIMARY KEY,                 -- RFC 7638 JWK thumbprint (TIO-KEYS-014)
  alg             TEXT NOT NULL CHECK (alg = 'ES256'),
  public_jwk      TEXT NOT NULL,
  private_jwk_enc BLOB,                             -- NULL once retired
  created_at      INTEGER NOT NULL,
  activates_at    INTEGER NOT NULL,                 -- signs from this instant; role is derived (§10.3)
  retired_at      INTEGER
);
CREATE INDEX signing_keys_active ON signing_keys(retired_at, activates_at);

CREATE TABLE invitations (
  id               TEXT PRIMARY KEY,                -- UUID v7
  token_hash       BLOB NOT NULL UNIQUE,
  kind             TEXT NOT NULL CHECK (kind IN ('register','recover')),
  user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,  -- recover: target user
  email            TEXT,
  email_verified   INTEGER NOT NULL DEFAULT 0,
  display_name     TEXT,
  groups           TEXT NOT NULL DEFAULT '[]',
  expires_at       INTEGER NOT NULL,
  used_at          INTEGER,
  used_by_user_id  TEXT,
  created_by       TEXT NOT NULL,                   -- actor id
  created_at       INTEGER NOT NULL
);
CREATE INDEX invitations_expires ON invitations(expires_at);
CREATE INDEX invitations_user    ON invitations(user_id);

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,                         -- JSON
  updated_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE audit_hot (
  id          TEXT PRIMARY KEY,                     -- UUID v7 (time-ordered)
  ts          INTEGER NOT NULL,
  type        TEXT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('success','failure')),
  actor_kind  TEXT NOT NULL,
  actor_id    TEXT,
  user_id     TEXT,
  client_id   TEXT,
  upstream    TEXT,
  ip_hash     TEXT,
  data        TEXT NOT NULL                         -- JSON, bounded 4 KB
);
CREATE INDEX audit_hot_ts     ON audit_hot(ts, id);
CREATE INDEX audit_hot_user   ON audit_hot(user_id, ts);
CREATE INDEX audit_hot_client ON audit_hot(client_id, ts);
CREATE INDEX audit_hot_type   ON audit_hot(type, ts);
