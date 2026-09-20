import { DurableObject } from "cloudflare:workers";
import { z } from "zod";
import {
  type AssertionExpectations,
  counterPolicy,
  verifyAssertionSignature,
} from "../auth/passkey.ts";
import { sha256 } from "../crypto/hash.ts";
import type { Env } from "../env.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { parseJson } from "../util/json.ts";
import { type DoResult, fail } from "./errors.ts";
import { USER_SCHEMA_STEPS, USER_SCHEMA_VERSION } from "./schema.ts";

// One object per user: the source of truth for everything about that user
// (spec §2.3, §4.2). Every state change runs inside one synchronous SQL
// sequence with no await between statements (TIO-DATA-020); anything that
// needs Web Crypto (PKCE) is computed before the transaction starts.

export interface UserProfile {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface InitProfile {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
}

/** Purge windows (TIO-DATA-019, §4.7). */
export const PURGE_INTERVAL_SECONDS = 60;
export const PURGE_GRACE_SECONDS = 86_400;

/** Authorization codes live 60 s (§5.7.4). */
export const CODE_TTL_SECONDS = 60;

export type UserDoError =
  | "user_not_initialized"
  | "user_destroyed"
  | "user_id_mismatch"
  | "user_disabled"
  | "user_not_allowed"
  | "session_invalid"
  | "invalid_grant"
  | "invalid_scope"
  | "passkey_exists"
  | "passkey_limit_reached"
  | "passkey_verification_failed"
  | "passkey_counter_regression"
  | "identity_exists"
  | "last_login_method"
  | "too_many_attempts";

/** Self-service passkey registration attempts per user (§6.7). */
export const PASSKEY_ATTEMPT_LIMIT = 10;
export const PASSKEY_ATTEMPT_WINDOW_SECONDS = 600;
const AttemptWindowSchema = z.object({ since: z.int(), count: z.int() });

/**
 * Who asks for a removal: the Admin API may remove any passkey or identity;
 * a user keeps at least one way to sign in (TIO-PK-040, TIO-FED-051).
 */
export type RemovalActor = "admin" | "self";

interface UserRow extends Record<string, SqlStorageValue> {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: number;
  display_name: string | null;
  groups: string;
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  sid: string;
  secret_hash: ArrayBuffer;
  created_at: number;
  last_seen_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  auth_time: number;
  amr: string;
  acr: string;
  upstream: string | null;
  ip_hash: string | null;
  ua_family: string | null;
  country: string | null;
  revoked_at: number | null;
  revoke_reason: string | null;
}

interface CodeRow extends Record<string, SqlStorageValue> {
  secret_hash: ArrayBuffer;
  client_id: string;
  redirect_uri: string;
  scope: string;
  nonce: string | null;
  code_challenge: string;
  sid: string;
  auth_time: number;
  amr: string;
  acr: string;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

interface FamilyRow extends Record<string, SqlStorageValue> {
  id: string;
  client_id: string;
  client_created_at: number;
  code_secret_hash: ArrayBuffer | null;
  kind: "session" | "offline";
  sid: string | null;
  scope: string;
  auth_time: number;
  amr: string;
  acr: string;
  created_at: number;
  absolute_expires_at: number;
  idle_expires_at: number;
  current_serial: number;
  revoked_at: number | null;
  revoke_reason: string | null;
}

interface TokenRow extends Record<string, SqlStorageValue> {
  secret_hash: ArrayBuffer;
  family_id: string;
  serial: number;
  created_at: number;
  consumed_at: number | null;
}

interface GrantRow extends Record<string, SqlStorageValue> {
  client_id: string;
  client_created_at: number;
  scopes: string;
  granted_at: number;
  updated_at: number;
}

interface PasskeyRow extends Record<string, SqlStorageValue> {
  id: string;
  credential_id: string;
  public_key: ArrayBuffer;
  alg: number;
  counter: number;
  transports: string;
  aaguid: string | null;
  backup_eligible: number;
  backed_up: number;
  name: string | null;
  created_via: string;
  created_at: number;
  last_used_at: number | null;
}

interface IdentityRow extends Record<string, SqlStorageValue> {
  id: string;
  issuer: string;
  subject: string;
  email: string | null;
  email_verified: number | null;
  name: string | null;
  created_at: number;
  last_login_at: number | null;
}

const Strings = z.array(z.string());

/** Stored JSON arrays are written by this object; anything else reads as empty. */
function parseStrings(text: string): string[] {
  const parsed = parseJson(Strings, text);
  return parsed.ok ? parsed.value : [];
}

/** The client fields the object needs to evaluate a request (the caller resolves the client record). */
export interface ClientRef {
  client_id: string;
  /** The client's `created_at`; a stored record with another value belongs to a deleted, re-created client (TIO-CLIENT-005). */
  created_at: number;
  skip_consent: boolean;
  allowed_groups: string[] | null;
}

/** Authentication context recorded on sessions, codes and families. */
export interface AuthContext {
  auth_time: number;
  amr: string[];
  acr: string;
  upstream: string | null;
}

export interface SessionSnapshot {
  sid: string;
  auth_time: number;
  amr: string[];
  acr: string;
  upstream: string | null;
  created_at: number;
  last_seen_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  clients: string[];
  country: string | null;
  ua_family: string | null;
}

export interface SessionMetadata {
  ip_hash: string | null;
  ua_family: string | null;
  country: string | null;
}

export interface NewSession {
  sid: string;
  secret_hash: Uint8Array;
  auth: AuthContext;
  metadata: SessionMetadata;
  idle_ttl: number;
  absolute_ttl: number;
}

export interface CodeInput {
  secret_hash: Uint8Array;
  client_id: string;
  redirect_uri: string;
  scope: string[];
  nonce: string | null;
  code_challenge: string;
}

/** The claims a token endpoint needs, as snapshotted at issuance time. */
export interface GrantContext {
  sub: string;
  scope: string[];
  sid: string | null;
  auth_time: number;
  amr: string[];
  acr: string;
  profile: UserProfile;
}

export interface AuthorizeWithSessionInput {
  sid: string;
  secret_hash: Uint8Array;
  now: number;
  client: ClientRef;
  scope: string[];
  prompt_login: boolean;
  prompt_consent: boolean;
  max_age: number | null;
  /** Code to issue when the session and consent are satisfied; null only evaluates. */
  code: CodeInput | null;
  session_idle_ttl: number;
}

export type AuthorizeOutcome =
  | {
      ok: true;
      outcome: "authorized" | "login_required" | "consent_required";
      session: SessionSnapshot;
      profile: UserProfile;
    }
  | { ok: false; error: UserDoError };

export interface FinalizeLoginInput {
  now: number;
  /** Create a new session, or rotate the secret and authentication context of the given one (same user re-authenticating). */
  session:
    | { create: NewSession }
    | { rotate: { sid: string; secret_hash: Uint8Array; auth: AuthContext } };
  code: CodeInput | null;
  client: ClientRef | null;
  session_idle_ttl: number;
}

export interface ExchangeCodeInput {
  secret_hash: Uint8Array;
  client: ClientRef;
  redirect_uri: string;
  code_verifier: string;
  now: number;
  /** The first refresh token of the family; null when the client has no refresh_token grant. */
  refresh: {
    secret_hash: Uint8Array;
    family_id: string;
    /** The client's `offline_access` flag: with `offline_access` in the code's scope the family is offline (TIO-TOKEN-014). */
    offline_allowed: boolean;
    idle_ttl: number;
    absolute_ttl: number;
  } | null;
}

export type ExchangeOutcome =
  | {
      ok: true;
      grant: GrantContext;
      nonce: string | null;
      family_id: string | null;
      kind: "session" | "offline" | null;
    }
  | { ok: false; error: UserDoError; replay?: boolean };

export interface RotateRefreshInput {
  family_id: string;
  secret_hash: Uint8Array;
  client: ClientRef;
  now: number;
  requested_scope: string[] | null;
  new_secret_hash: Uint8Array;
  idle_ttl: number;
  session_idle_ttl: number;
  reuse_window: number;
}

export type RotateOutcome =
  | { ok: true; grant: GrantContext; serial: number; kind: "session" | "offline" }
  | {
      ok: false;
      error: UserDoError;
      reuse_detected?: boolean;
      revoked_session_clients?: string[];
    };

export interface NewPasskey {
  id: string;
  credential_id: string;
  public_key: Uint8Array;
  alg: number;
  counter: number;
  transports: string[];
  aaguid: string | null;
  backup_eligible: boolean;
  backed_up: boolean;
  name: string | null;
  created_via: "interaction" | "me" | "recovery";
}

export interface PasskeyRecord extends NewPasskey {
  created_at: number;
  last_used_at: number | null;
}

export interface NewIdentity {
  id: string;
  issuer: string;
  subject: string;
  email: string | null;
  email_verified: boolean | null;
  name: string | null;
}

export interface IdentityRecord extends NewIdentity {
  created_at: number;
  last_login_at: number | null;
}

export interface GrantRecord {
  client_id: string;
  client_created_at: number;
  scopes: string[];
  granted_at: number;
  updated_at: number;
}

/** A signature counter that went backwards (TIO-PK-023): what the audit event reports. */
export interface CounterRegression {
  ok: false;
  error: "passkey_counter_regression";
  regression: { passkey_id: string; stored: number; observed: number };
}

export interface RevokedSession {
  sid: string;
  clients: string[];
}

/** A partial profile update from the Admin API; `email_norm` accompanies `email`. */
export interface ProfilePatch {
  email?: string | null;
  email_norm?: string | null;
  email_verified?: boolean;
  display_name?: string | null;
}

/** A refresh family as the APIs list it: no token hashes (TIO-ADMIN-003). */
export interface FamilySnapshot {
  id: string;
  client_id: string;
  kind: "session" | "offline";
  sid: string | null;
  scope: string[];
  auth_time: number;
  amr: string[];
  acr: string;
  created_at: number;
  absolute_expires_at: number;
  idle_expires_at: number;
  current_serial: number;
}

export interface UserCounts {
  passkeys: number;
  identities: number;
  sessions: number;
  refresh_families: number;
  grants: number;
}

/** The data-portability export (TIO-PRIV-002). */
export interface UserExport {
  exported_at: number;
  profile: UserProfile;
  passkeys: Omit<PasskeyRecord, "public_key">[];
  identities: IdentityRecord[];
  sessions: (SessionSnapshot &
    SessionMetadata & { revoked_at: number | null; revoke_reason: string | null })[];
  refresh_families: (FamilySnapshot & {
    revoked_at: number | null;
    revoke_reason: string | null;
  })[];
  grants: GrantRecord[];
}

const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

const bytes = (buffer: ArrayBuffer): Uint8Array => new Uint8Array(buffer);
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

export class UserDO extends DurableObject<Env> {
  private migrated = false;
  private destroyed = false;
  private lastPurgeAt = -Infinity;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /** Lazy, idempotent schema migration on first access after a deploy (§4.2). */
  private migrate(): void {
    if (this.migrated) return;
    const sql = this.ctx.storage.sql;
    sql.exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
    const row = sql
      .exec<{ value: string }>("SELECT value FROM meta WHERE key = 'schema_version'")
      .toArray()[0];
    const current = row ? Number(row.value) : 0;
    this.ctx.storage.transactionSync(() => {
      for (let version = current; version < USER_SCHEMA_VERSION; version++) {
        sql.exec(USER_SCHEMA_STEPS[version] as string);
      }
      sql.exec(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        String(USER_SCHEMA_VERSION),
      );
    });
    this.migrated = true;
  }

  private readUser(): UserRow | undefined {
    return this.ctx.storage.sql.exec<UserRow>("SELECT * FROM user LIMIT 1").toArray()[0];
  }

  /** Guard of TIO-DATA-021: every method but init() and destroy() needs an initialized, undestroyed object. */
  private guard(): UserRow | UserDoError {
    if (this.destroyed) return "user_destroyed";
    this.migrate();
    return this.readUser() ?? "user_not_initialized";
  }

  private static profile(row: UserRow): UserProfile {
    return {
      id: row.id,
      email: row.email,
      email_norm: row.email_norm,
      email_verified: row.email_verified === 1,
      display_name: row.display_name,
      groups: parseStrings(row.groups),
      disabled_at: row.disabled_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Creates the user record (step 2 of user creation, §4.6), with the upstream
   * identities claimed at creation in the same transaction: one call per new
   * user, which is what the bulk import's throughput hangs on (a Worker holds
   * six outbound calls at a time). Idempotent for the same id so the repair
   * cron may retry (the identities are then left to it); a different id is refused.
   */
  init(
    profile: InitProfile,
    now: number,
    identities: NewIdentity[] = [],
  ): DoResult<{ profile: UserProfile }, UserDoError> {
    if (this.destroyed) return fail("user_destroyed");
    this.migrate();
    const existing = this.readUser();
    if (existing) {
      return existing.id === profile.id
        ? { ok: true, profile: UserDO.profile(existing) }
        : fail("user_id_mismatch");
    }
    return this.ctx.storage.transactionSync(() => this.insertUser(profile, now, identities));
  }

  private insertUser(
    profile: InitProfile,
    now: number,
    identities: NewIdentity[],
  ): DoResult<{ profile: UserProfile }, UserDoError> {
    const groups = JSON.stringify([...profile.groups].sort());
    this.ctx.storage.sql.exec(
      "INSERT INTO user (id, email, email_norm, email_verified, display_name, groups, disabled_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
      profile.id,
      profile.email,
      profile.email_norm,
      profile.email_verified ? 1 : 0,
      profile.display_name,
      groups,
      now,
      now,
    );
    this.ctx.storage.sql.exec(
      "INSERT INTO meta (key, value) VALUES ('user_id', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      profile.id,
    );
    for (const identity of identities) {
      this.ctx.storage.sql.exec(
        "INSERT INTO identities (id, issuer, subject, email, email_verified, name, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        identity.id,
        identity.issuer,
        identity.subject,
        identity.email,
        identity.email_verified === null ? null : identity.email_verified ? 1 : 0,
        identity.name,
        now,
      );
    }
    return { ok: true, profile: UserDO.profile(this.readUser() as UserRow) };
  }

  /** Deletes everything (`deleteAll`) and refuses every later call except destroy() itself (TIO-DATA-010, TIO-DATA-021). */
  async destroy(): Promise<{ ok: true }> {
    await this.ctx.storage.deleteAll();
    this.destroyed = true;
    this.migrated = false;
    return { ok: true };
  }

  getProfile(): DoResult<{ profile: UserProfile }, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    return { ok: true, profile: UserDO.profile(row) };
  }

  /** Replaces the group list (TIO-DATA-013); the D1 mirror is the caller's second write. */
  setGroups(groups: string[], now: number): DoResult<{ profile: UserProfile }, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    this.ctx.storage.sql.exec(
      "UPDATE user SET groups = ?, updated_at = ? WHERE id = ?",
      JSON.stringify([...new Set(groups)].sort()),
      now,
      row.id,
    );
    return { ok: true, profile: UserDO.profile(this.readUser() as UserRow) };
  }

  /**
   * Disables (revoking every session and family in the same transaction,
   * TIO-DATA-009) or re-enables the user. Returns the sessions revoked so the
   * caller can send back-channel logout.
   */
  setDisabled(
    disabledAt: number | null,
    now: number,
  ): DoResult<{ profile: UserProfile; revoked: RevokedSession[] }, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        "UPDATE user SET disabled_at = ?, updated_at = ? WHERE id = ?",
        disabledAt,
        now,
        row.id,
      );
      let revoked: RevokedSession[] = [];
      if (disabledAt !== null) {
        const sids = this.ctx.storage.sql
          .exec<{ sid: string }>("SELECT sid FROM sessions WHERE revoked_at IS NULL")
          .toArray()
          .map((r) => r.sid);
        revoked = sids.map((sid) => ({
          sid,
          clients: this.revokeSessionRows(sid, now, "disabled"),
        }));
        this.ctx.storage.sql.exec(
          "UPDATE refresh_families SET revoked_at = ?, revoke_reason = 'disabled' WHERE revoked_at IS NULL",
          now,
        );
      }
      return { ok: true, profile: UserDO.profile(this.readUser() as UserRow), revoked };
    });
  }

  // ---------------------------------------------------------------------------
  // Purge (TIO-DATA-019)
  // ---------------------------------------------------------------------------

  /**
   * Purge on write, at most once per 60 s: expired codes, consumed refresh
   * tokens past the reuse window, families and sessions expired or revoked
   * more than 24 h ago. Logical expiry is always checked on read; this only
   * bounds storage. Called inside every state-changing transaction.
   */
  private purgeIfDue(now: number, reuseWindow: number): void {
    if (now - this.lastPurgeAt < PURGE_INTERVAL_SECONDS) return;
    this.lastPurgeAt = now;
    const sql = this.ctx.storage.sql;
    const grace = now - PURGE_GRACE_SECONDS;
    sql.exec("DELETE FROM auth_codes WHERE expires_at < ?", now);
    sql.exec(
      "DELETE FROM refresh_tokens WHERE consumed_at IS NOT NULL AND consumed_at < ?",
      now - reuseWindow,
    );
    sql.exec(
      "DELETE FROM refresh_families WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR absolute_expires_at < ? OR idle_expires_at < ?",
      grace,
      grace,
      grace,
    );
    sql.exec(
      "DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR absolute_expires_at < ? OR idle_expires_at < ?",
      grace,
      grace,
      grace,
    );
    sql.exec("DELETE FROM challenges WHERE expires_at < ?", now);
  }

  /** Runs the purge as a write would. */
  touch(now: number, reuseWindow: number): DoResult<Record<never, never>, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    this.ctx.storage.transactionSync(() => this.purgeIfDue(now, reuseWindow));
    return { ok: true };
  }

  // ---------------------------------------------------------------------------
  // Sessions (§6.2)
  // ---------------------------------------------------------------------------

  private sessionRow(sid: string): SessionRow | undefined {
    return this.ctx.storage.sql
      .exec<SessionRow>("SELECT * FROM sessions WHERE sid = ?", sid)
      .toArray()[0];
  }

  private sessionClients(sid: string): string[] {
    return this.ctx.storage.sql
      .exec<{ client_id: string }>(
        "SELECT client_id FROM session_clients WHERE sid = ? ORDER BY first_at, client_id",
        sid,
      )
      .toArray()
      .map((r) => r.client_id);
  }

  private snapshot(row: SessionRow): SessionSnapshot {
    return {
      sid: row.sid,
      auth_time: row.auth_time,
      amr: parseStrings(row.amr),
      acr: row.acr,
      upstream: row.upstream,
      created_at: row.created_at,
      last_seen_at: row.last_seen_at,
      idle_expires_at: row.idle_expires_at,
      absolute_expires_at: row.absolute_expires_at,
      clients: this.sessionClients(row.sid),
      country: row.country,
      ua_family: row.ua_family,
    };
  }

  /** A session usable at `now`: exists, secret matches, not revoked, not expired (TIO-SESS-003, TIO-SESS-004). */
  private liveSession(sid: string, secretHash: Uint8Array, now: number): SessionRow | null {
    const row = this.sessionRow(sid);
    if (!row || row.revoked_at !== null) return null;
    if (!sameBytes(bytes(row.secret_hash), secretHash)) return null;
    if (row.idle_expires_at <= now || row.absolute_expires_at <= now) return null;
    return row;
  }

  /** Extends idle expiry to now + idle_ttl, never beyond the absolute expiry (TIO-SESS-003). */
  private touchSession(row: SessionRow, now: number, idleTtl: number): void {
    const idle = Math.min(now + idleTtl, row.absolute_expires_at);
    this.ctx.storage.sql.exec(
      "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE sid = ?",
      now,
      idle,
      row.sid,
    );
  }

  private insertSession(input: NewSession, now: number): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO sessions (sid, secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, auth_time, amr, acr, upstream, ip_hash, ua_family, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      input.sid,
      input.secret_hash,
      now,
      now,
      Math.min(now + input.idle_ttl, now + input.absolute_ttl),
      now + input.absolute_ttl,
      input.auth.auth_time,
      JSON.stringify(input.auth.amr),
      input.auth.acr,
      input.auth.upstream,
      input.metadata.ip_hash,
      input.metadata.ua_family,
      input.metadata.country,
    );
  }

  /** Ends a session: revokes it and its session-bound families, returns the clients to notify (TIO-LOGOUT-005, TIO-SESS-006). */
  private revokeSessionRows(sid: string, now: number, reason: string): string[] {
    const sql = this.ctx.storage.sql;
    sql.exec(
      "UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE sid = ? AND revoked_at IS NULL",
      now,
      reason,
      sid,
    );
    sql.exec(
      "UPDATE refresh_families SET revoked_at = ?, revoke_reason = ? WHERE sid = ? AND kind = 'session' AND revoked_at IS NULL",
      now,
      reason,
      sid,
    );
    return this.sessionClients(sid);
  }

  private issueCodeRows(code: CodeInput, session: SessionRow, now: number, idleTtl: number): void {
    const sql = this.ctx.storage.sql;
    sql.exec(
      "INSERT INTO auth_codes (secret_hash, client_id, redirect_uri, scope, nonce, code_challenge, sid, auth_time, amr, acr, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      code.secret_hash,
      code.client_id,
      code.redirect_uri,
      code.scope.join(" "),
      code.nonce,
      code.code_challenge,
      session.sid,
      session.auth_time,
      session.amr,
      session.acr,
      now,
      now + CODE_TTL_SECONDS,
    );
    // TIO-AUTHZ-023: record the client under the session and touch it.
    sql.exec(
      "INSERT INTO session_clients (sid, client_id, first_at) VALUES (?, ?, ?) ON CONFLICT(sid, client_id) DO NOTHING",
      session.sid,
      code.client_id,
      now,
    );
    this.touchSession(session, now, idleTtl);
  }

  /** Whether the user satisfies the client's `allowed_groups` (TIO-AUTHZ-017). */
  private static allowed(user: UserRow, client: ClientRef): boolean {
    if (client.allowed_groups === null) return true;
    const groups = parseStrings(user.groups);
    return client.allowed_groups.some((g) => groups.includes(g));
  }

  /** TIO-SCOPE-002: the admin scope needs live membership of `admins`. */
  private static adminAllowed(user: UserRow, scope: readonly string[]): boolean {
    return !scope.includes("admin") || parseStrings(user.groups).includes("admins");
  }

  /** The stored grant for a client, deleting one left by a deleted, re-created client (TIO-CLIENT-005). */
  private grantFor(client: ClientRef): GrantRow | null {
    const sql = this.ctx.storage.sql;
    const row = sql
      .exec<GrantRow>("SELECT * FROM grants WHERE client_id = ?", client.client_id)
      .toArray()[0];
    if (!row) return null;
    if (row.client_created_at !== client.created_at) {
      sql.exec("DELETE FROM grants WHERE client_id = ?", client.client_id);
      return null;
    }
    return row;
  }

  /**
   * The session-hit path of `/authorize` (§2.5.2, TIO-AUTHZ-014..017): one hop
   * that evaluates the session, `prompt`, `max_age`, `allowed_groups` and
   * consent, and issues the code when everything is satisfied. Nothing is
   * touched unless a code is issued (TIO-AUTHZ-015).
   */
  authorizeWithSession(input: AuthorizeWithSessionInput): AuthorizeOutcome {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync((): AuthorizeOutcome => {
      const session = this.liveSession(input.sid, input.secret_hash, input.now);
      if (!session) return fail("session_invalid");
      if (user.disabled_at !== null) return fail("user_disabled");
      if (!UserDO.allowed(user, input.client)) return fail("user_not_allowed");
      if (!UserDO.adminAllowed(user, input.scope)) return fail("user_not_allowed");
      const profile = UserDO.profile(user);
      const snapshot = this.snapshot(session);
      const stale = input.max_age !== null && session.auth_time + input.max_age <= input.now;
      if (input.prompt_login || stale) {
        return { ok: true, outcome: "login_required", session: snapshot, profile };
      }
      if (!input.client.skip_consent) {
        const grant = this.grantFor(input.client);
        const granted = grant ? parseStrings(grant.scopes) : [];
        const covered = input.scope.every((s) => granted.includes(s));
        if (input.prompt_consent || !covered) {
          return { ok: true, outcome: "consent_required", session: snapshot, profile };
        }
      }
      if (input.code) {
        this.purgeIfDue(input.now, PURGE_GRACE_SECONDS);
        this.issueCodeRows(input.code, session, input.now, input.session_idle_ttl);
      }
      return {
        ok: true,
        outcome: "authorized",
        session: this.snapshot(this.sessionRow(session.sid) as SessionRow),
        profile,
      };
    });
  }

  /**
   * `/complete` (TIO-IX-060, TIO-SESS-002): creates the session or rotates the
   * existing one for the same user, then issues the code, in one transaction.
   */
  finalizeLogin(
    input: FinalizeLoginInput,
  ): DoResult<{ sid: string; session: SessionSnapshot; profile: UserProfile }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    if (user.disabled_at !== null) return fail("user_disabled");
    if (input.client && !UserDO.allowed(user, input.client)) return fail("user_not_allowed");
    if (input.code && !UserDO.adminAllowed(user, input.code.scope)) return fail("user_not_allowed");
    return this.ctx.storage.transactionSync(() => {
      this.purgeIfDue(input.now, PURGE_GRACE_SECONDS);
      let sid: string;
      if ("create" in input.session) {
        sid = input.session.create.sid;
        this.insertSession(input.session.create, input.now);
      } else {
        const rotate = input.session.rotate;
        const existing = this.sessionRow(rotate.sid);
        if (
          !existing ||
          existing.revoked_at !== null ||
          existing.absolute_expires_at <= input.now
        ) {
          return fail("session_invalid");
        }
        this.ctx.storage.sql.exec(
          "UPDATE sessions SET secret_hash = ?, auth_time = ?, amr = ?, acr = ?, upstream = ?, last_seen_at = ?, idle_expires_at = ? WHERE sid = ?",
          rotate.secret_hash,
          rotate.auth.auth_time,
          JSON.stringify(rotate.auth.amr),
          rotate.auth.acr,
          rotate.auth.upstream,
          input.now,
          Math.min(input.now + input.session_idle_ttl, existing.absolute_expires_at),
          rotate.sid,
        );
        sid = rotate.sid;
      }
      const session = this.sessionRow(sid) as SessionRow;
      if (input.code) this.issueCodeRows(input.code, session, input.now, input.session_idle_ttl);
      return {
        ok: true,
        sid,
        session: this.snapshot(this.sessionRow(sid) as SessionRow),
        profile: UserDO.profile(user),
      };
    });
  }

  /** Validates a session cookie without touching it (navigation endpoints, §5.10). */
  getSession(
    sid: string,
    secretHash: Uint8Array,
    now: number,
  ): DoResult<{ session: SessionSnapshot; profile: UserProfile }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const session = this.liveSession(sid, secretHash, now);
    if (!session) return fail("session_invalid");
    if (user.disabled_at !== null) return fail("user_disabled");
    return { ok: true, session: this.snapshot(session), profile: UserDO.profile(user) };
  }

  /** Ends one session (any path): TIO-LOGOUT-005, TIO-SESS-006. Idempotent; returns the clients to notify. */
  revokeSession(
    sid: string,
    now: number,
    reason: string,
  ): DoResult<{ revoked: RevokedSession | null }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      this.purgeIfDue(now, PURGE_GRACE_SECONDS);
      const row = this.sessionRow(sid);
      if (!row || row.revoked_at !== null) return { ok: true, revoked: null };
      const clients = this.revokeSessionRows(sid, now, reason);
      return { ok: true, revoked: { sid, clients } };
    });
  }

  /** Every session not yet expired or revoked. */
  listSessions(now: number): DoResult<{ sessions: SessionSnapshot[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const rows = this.ctx.storage.sql
      .exec<SessionRow>(
        "SELECT * FROM sessions WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ? ORDER BY created_at",
        now,
        now,
      )
      .toArray();
    return { ok: true, sessions: rows.map((r) => this.snapshot(r)) };
  }

  /** Revokes every live session but `except` (the Self-service API, §8); families of those sessions go with them. */
  revokeSessions(
    except: string | null,
    now: number,
    reason: string,
  ): DoResult<{ revoked: RevokedSession[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      this.purgeIfDue(now, PURGE_GRACE_SECONDS);
      const sids = this.ctx.storage.sql
        .exec<{ sid: string }>(
          "SELECT sid FROM sessions WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ? ORDER BY created_at",
          now,
          now,
        )
        .toArray()
        .map((r) => r.sid)
        .filter((sid) => sid !== except);
      const revoked = sids.map((sid) => ({
        sid,
        clients: this.revokeSessionRows(sid, now, reason),
      }));
      return { ok: true, revoked };
    });
  }

  /**
   * Counts one Self-service passkey registration attempt (§6.7: 10 per 10 minutes per
   * user). The window starts at the first attempt and resets once it has elapsed.
   */
  countPasskeyAttempt(now: number): DoResult<{ remaining: number }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const sql = this.ctx.storage.sql;
    const row = sql
      .exec<{ value: string }>("SELECT value FROM meta WHERE key = 'passkey_attempts'")
      .toArray()[0];
    const parsed = row === undefined ? null : parseJson(AttemptWindowSchema, row.value);
    let window = parsed?.ok ? parsed.value : { since: now, count: 0 };
    if (now - window.since >= PASSKEY_ATTEMPT_WINDOW_SECONDS) window = { since: now, count: 0 };
    if (window.count >= PASSKEY_ATTEMPT_LIMIT) return fail("too_many_attempts");
    window = { since: window.since, count: window.count + 1 };
    sql.exec(
      "INSERT INTO meta (key, value) VALUES ('passkey_attempts', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      JSON.stringify(window),
    );
    return { ok: true, remaining: PASSKEY_ATTEMPT_LIMIT - window.count };
  }

  /** Stores a single-use WebAuthn challenge under `key` (a session or token id), replacing any previous one (§8). */
  putChallenge(
    key: string,
    value: string,
    expiresAt: number,
  ): DoResult<Record<never, never>, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    this.ctx.storage.sql.exec(
      "INSERT INTO challenges (key, value, expires_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at",
      key,
      value,
      expiresAt,
    );
    return { ok: true };
  }

  /** Takes the challenge stored under `key`, once; null when there is none or it expired. */
  takeChallenge(key: string, now: number): DoResult<{ value: string | null }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      const row = sql
        .exec<{ value: string; expires_at: number }>(
          "SELECT value, expires_at FROM challenges WHERE key = ?",
          key,
        )
        .toArray()[0];
      sql.exec("DELETE FROM challenges WHERE key = ?", key);
      return { ok: true, value: row !== undefined && row.expires_at > now ? row.value : null };
    });
  }

  /** Revokes every session and every family (disable, delete, recovery: TIO-DATA-009, TIO-REG-004). */
  revokeAll(now: number, reason: string): DoResult<{ revoked: RevokedSession[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const sids = this.ctx.storage.sql
        .exec<{ sid: string }>("SELECT sid FROM sessions WHERE revoked_at IS NULL")
        .toArray()
        .map((r) => r.sid);
      const revoked = sids.map((sid) => ({
        sid,
        clients: this.revokeSessionRows(sid, now, reason),
      }));
      this.ctx.storage.sql.exec(
        "UPDATE refresh_families SET revoked_at = ?, revoke_reason = ? WHERE revoked_at IS NULL",
        now,
        reason,
      );
      return { ok: true, revoked };
    });
  }

  // ---------------------------------------------------------------------------
  // Authorization codes and refresh tokens (§5.6)
  // ---------------------------------------------------------------------------

  private familyRow(id: string): FamilyRow | undefined {
    return this.ctx.storage.sql
      .exec<FamilyRow>("SELECT * FROM refresh_families WHERE id = ?", id)
      .toArray()[0];
  }

  private revokeFamily(id: string, now: number, reason: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE refresh_families SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL",
      now,
      reason,
      id,
    );
  }

  private static grantContext(
    user: UserRow,
    scope: string,
    sid: string | null,
    authTime: number,
    amr: string,
    acr: string,
  ): GrantContext {
    return {
      sub: user.id,
      scope: scope.split(" ").filter((s) => s.length > 0),
      sid,
      auth_time: authTime,
      amr: parseStrings(amr),
      acr,
      profile: UserDO.profile(user),
    };
  }

  /**
   * Code exchange (§2.5.3, TIO-TOKEN-011..014): every check and the family
   * creation happen atomically; a replayed code revokes the families it created
   * (TIO-TOKEN-012). The PKCE hash is computed before the transaction.
   */
  async exchangeCode(input: ExchangeCodeInput): Promise<ExchangeOutcome> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    // RFC 7636 §4.6: verifier alphabet and length are part of the check.
    const expectedChallenge = PKCE_VERIFIER.test(input.code_verifier)
      ? encodeBase64Url(await sha256(input.code_verifier))
      : null;
    return this.ctx.storage.transactionSync((): ExchangeOutcome => {
      this.purgeIfDue(input.now, PURGE_GRACE_SECONDS);
      const sql = this.ctx.storage.sql;
      const code = sql
        .exec<CodeRow>("SELECT * FROM auth_codes WHERE secret_hash = ?", input.secret_hash)
        .toArray()[0];
      if (!code) return fail("invalid_grant");
      if (code.consumed_at !== null) {
        // RFC 6749 §4.1.2: replay revokes everything the code produced.
        sql.exec(
          "UPDATE refresh_families SET revoked_at = ?, revoke_reason = 'code_replay' WHERE code_secret_hash = ? AND revoked_at IS NULL",
          input.now,
          input.secret_hash,
        );
        return { ok: false, error: "invalid_grant", replay: true };
      }
      if (code.expires_at <= input.now) return fail("invalid_grant");
      if (code.client_id !== input.client.client_id) return fail("invalid_grant");
      // RFC 6749 §4.1.3: redirect_uri must match the one bound to the code, byte for byte.
      if (code.redirect_uri !== input.redirect_uri) return fail("invalid_grant");
      if (expectedChallenge === null || expectedChallenge !== code.code_challenge) {
        return fail("invalid_grant");
      }
      if (user.disabled_at !== null) return fail("invalid_grant");
      if (!UserDO.allowed(user, input.client)) return fail("invalid_grant");
      if (!UserDO.adminAllowed(user, code.scope.split(" "))) return fail("invalid_grant");
      const session = this.sessionRow(code.sid);
      if (!session || session.revoked_at !== null) return fail("invalid_grant");
      sql.exec(
        "UPDATE auth_codes SET consumed_at = ? WHERE secret_hash = ?",
        input.now,
        input.secret_hash,
      );
      let familyId: string | null = null;
      let kind: "session" | "offline" | null = null;
      if (input.refresh) {
        const r = input.refresh;
        // TIO-TOKEN-014: offline only when granted and allowed for the client.
        kind =
          r.offline_allowed && code.scope.split(" ").includes("offline_access")
            ? "offline"
            : "session";
        familyId = r.family_id;
        // TIO-RT-010: session families end with the session; offline ones have their own lifetime.
        const absolute =
          kind === "session" ? session.absolute_expires_at : input.now + r.absolute_ttl;
        const idle = Math.min(input.now + r.idle_ttl, absolute);
        sql.exec(
          "INSERT INTO refresh_families (id, client_id, client_created_at, code_secret_hash, kind, sid, scope, auth_time, amr, acr, created_at, absolute_expires_at, idle_expires_at, current_serial) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
          r.family_id,
          input.client.client_id,
          input.client.created_at,
          input.secret_hash,
          kind,
          kind === "session" ? code.sid : null,
          code.scope,
          code.auth_time,
          code.amr,
          code.acr,
          input.now,
          absolute,
          idle,
        );
        sql.exec(
          "INSERT INTO refresh_tokens (secret_hash, family_id, serial, created_at) VALUES (?, ?, 1, ?)",
          r.secret_hash,
          r.family_id,
          input.now,
        );
      }
      const grant = UserDO.grantContext(
        user,
        code.scope,
        code.sid,
        code.auth_time,
        code.amr,
        code.acr,
      );
      return { ok: true, grant, nonce: code.nonce, family_id: familyId, kind };
    });
  }

  /**
   * Refresh-token rotation (§2.5.4, TIO-RT-002..006): exactly-once under
   * concurrency because the whole check-and-rotate runs in one transaction.
   */
  rotateRefreshToken(input: RotateRefreshInput): RotateOutcome {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync((): RotateOutcome => {
      this.purgeIfDue(input.now, input.reuse_window);
      const sql = this.ctx.storage.sql;
      const family = this.familyRow(input.family_id);
      if (!family || family.revoked_at !== null) return fail("invalid_grant");
      if (family.absolute_expires_at <= input.now || family.idle_expires_at <= input.now) {
        return fail("invalid_grant");
      }
      if (family.client_id !== input.client.client_id) return fail("invalid_grant");
      // TIO-CLIENT-005: a re-created client id does not inherit the family.
      if (family.client_created_at !== input.client.created_at) {
        sql.exec("DELETE FROM refresh_families WHERE id = ?", family.id);
        return fail("invalid_grant");
      }
      const token = sql
        .exec<TokenRow>(
          "SELECT * FROM refresh_tokens WHERE secret_hash = ? AND family_id = ?",
          input.secret_hash,
          family.id,
        )
        .toArray()[0];
      if (!token) return fail("invalid_grant");
      if (token.consumed_at !== null) {
        // Reuse detected: the family dies, and its session when session-bound.
        this.revokeFamily(family.id, input.now, "reuse");
        const failure: RotateOutcome = { ok: false, error: "invalid_grant", reuse_detected: true };
        // Session-bound families carry their sid; offline ones have none.
        if (family.sid !== null) {
          failure.revoked_session_clients = this.revokeSessionRows(
            family.sid,
            input.now,
            "refresh_reuse",
          );
        }
        return failure;
      }
      if (token.serial !== family.current_serial) return fail("invalid_grant");
      if (user.disabled_at !== null) return fail("invalid_grant");
      if (!UserDO.allowed(user, input.client)) return fail("invalid_grant");
      let session: SessionRow | undefined;
      if (family.sid !== null) {
        session = this.sessionRow(family.sid);
        if (
          !session ||
          session.revoked_at !== null ||
          session.idle_expires_at <= input.now ||
          session.absolute_expires_at <= input.now
        ) {
          return fail("invalid_grant");
        }
      }
      const familyScope = family.scope.split(" ").filter((s) => s.length > 0);
      let scope = familyScope;
      if (input.requested_scope !== null) {
        // TIO-RT-004: narrowing only; the family keeps its scope.
        if (!input.requested_scope.every((s) => familyScope.includes(s))) {
          return fail("invalid_scope");
        }
        scope = input.requested_scope;
      }
      if (!UserDO.adminAllowed(user, scope)) return fail("invalid_grant");
      const serial = family.current_serial + 1;
      const idle = Math.min(input.now + input.idle_ttl, family.absolute_expires_at);
      sql.exec(
        "UPDATE refresh_tokens SET consumed_at = ? WHERE secret_hash = ?",
        input.now,
        input.secret_hash,
      );
      sql.exec(
        "INSERT INTO refresh_tokens (secret_hash, family_id, serial, created_at) VALUES (?, ?, ?, ?)",
        input.new_secret_hash,
        family.id,
        serial,
        input.now,
      );
      sql.exec(
        "UPDATE refresh_families SET current_serial = ?, idle_expires_at = ? WHERE id = ?",
        serial,
        idle,
        family.id,
      );
      if (session) this.touchSession(session, input.now, input.session_idle_ttl);
      const grant = UserDO.grantContext(
        user,
        scope.join(" "),
        family.sid,
        family.auth_time,
        family.amr,
        family.acr,
      );
      return { ok: true, grant, serial, kind: family.kind };
    });
  }

  /** Revokes a family (revocation endpoint, self-service, admin). Idempotent. */
  revokeFamilyById(
    familyId: string,
    now: number,
    reason: string,
    clientId: string | null,
  ): DoResult<{ revoked: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const family = this.familyRow(familyId);
      if (!family || family.revoked_at !== null) return { ok: true, revoked: false };
      // TIO-REV-002: a token of another client is ignored.
      if (clientId !== null && family.client_id !== clientId) return { ok: true, revoked: false };
      this.revokeFamily(familyId, now, reason);
      return { ok: true, revoked: true };
    });
  }

  /** Revokes every family of a client bound to a session (TIO-REV-003). */
  revokeSessionFamiliesOfClient(
    sid: string,
    clientId: string,
    now: number,
  ): DoResult<{ revoked: number }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const result = this.ctx.storage.sql.exec(
      "UPDATE refresh_families SET revoked_at = ?, revoke_reason = 'client_revoke' WHERE sid = ? AND client_id = ? AND revoked_at IS NULL",
      now,
      sid,
      clientId,
    );
    return { ok: true, revoked: result.rowsWritten };
  }

  // ---------------------------------------------------------------------------
  // Consent grants (§6.6)
  // ---------------------------------------------------------------------------

  private static grantRecord(row: GrantRow): GrantRecord {
    return {
      client_id: row.client_id,
      client_created_at: row.client_created_at,
      scopes: parseStrings(row.scopes),
      granted_at: row.granted_at,
      updated_at: row.updated_at,
    };
  }

  /** Stores the union of the existing grant and `scopes` (TIO-CONSENT-003). */
  grantConsent(
    client: ClientRef,
    scopes: string[],
    now: number,
  ): DoResult<{ grant: GrantRecord }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const existing = this.grantFor(client);
      const union = [
        ...new Set([...(existing ? parseStrings(existing.scopes) : []), ...scopes]),
      ].sort();
      this.ctx.storage.sql.exec(
        "INSERT INTO grants (client_id, client_created_at, scopes, granted_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET scopes = excluded.scopes, updated_at = excluded.updated_at",
        client.client_id,
        client.created_at,
        JSON.stringify(union),
        existing?.granted_at ?? now,
        now,
      );
      return { ok: true, grant: UserDO.grantRecord(this.grantFor(client) as GrantRow) };
    });
  }

  /** The clients the user holds grants for, so a caller can resolve their records before listGrants(). */
  grantClientIds(): DoResult<{ client_ids: string[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const rows = this.ctx.storage.sql
      .exec<{ client_id: string }>("SELECT client_id FROM grants ORDER BY granted_at, client_id")
      .toArray();
    return { ok: true, client_ids: rows.map((r) => r.client_id) };
  }

  /** Grants whose client the caller confirms as current (TIO-CLIENT-005); others are deleted on discovery. */
  listGrants(clients: ClientRef[]): DoResult<{ grants: GrantRecord[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const known = new Map(clients.map((c) => [c.client_id, c]));
      const rows = this.ctx.storage.sql
        .exec<GrantRow>("SELECT * FROM grants ORDER BY granted_at, client_id")
        .toArray();
      const grants: GrantRecord[] = [];
      for (const row of rows) {
        const client = known.get(row.client_id);
        if (!client || client.created_at !== row.client_created_at) {
          this.ctx.storage.sql.exec("DELETE FROM grants WHERE client_id = ?", row.client_id);
          continue;
        }
        grants.push(UserDO.grantRecord(row));
      }
      return { ok: true, grants };
    });
  }

  /** Deletes the grant and revokes every family of that client (TIO-CONSENT-004). */
  revokeGrant(clientId: string, now: number): DoResult<{ revoked: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      const deleted = sql.exec("DELETE FROM grants WHERE client_id = ?", clientId).rowsWritten;
      sql.exec(
        "UPDATE refresh_families SET revoked_at = ?, revoke_reason = 'consent_revoked' WHERE client_id = ? AND revoked_at IS NULL",
        now,
        clientId,
      );
      return { ok: true, revoked: deleted > 0 };
    });
  }

  // ---------------------------------------------------------------------------
  // Passkeys and identities (storage; the ceremonies live in src/auth)
  // ---------------------------------------------------------------------------

  private static passkeyRecord(row: PasskeyRow): PasskeyRecord {
    return {
      id: row.id,
      credential_id: row.credential_id,
      public_key: bytes(row.public_key),
      alg: row.alg,
      counter: row.counter,
      transports: parseStrings(row.transports),
      aaguid: row.aaguid,
      backup_eligible: row.backup_eligible === 1,
      backed_up: row.backed_up === 1,
      name: row.name,
      created_via: row.created_via as PasskeyRecord["created_via"],
      created_at: row.created_at,
      last_used_at: row.last_used_at,
    };
  }

  addPasskey(
    passkey: NewPasskey,
    now: number,
    maxPerUser: number,
  ): DoResult<{ passkey: PasskeyRecord }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      const count = (
        sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM passkeys").toArray()[0] as { n: number }
      ).n;
      if (count >= maxPerUser) return fail("passkey_limit_reached");
      const dup = sql
        .exec(
          "SELECT 1 FROM passkeys WHERE credential_id = ? OR id = ?",
          passkey.credential_id,
          passkey.id,
        )
        .toArray();
      if (dup.length > 0) return fail("passkey_exists");
      sql.exec(
        "INSERT INTO passkeys (id, credential_id, public_key, alg, counter, transports, aaguid, backup_eligible, backed_up, name, created_via, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
        passkey.id,
        passkey.credential_id,
        passkey.public_key,
        passkey.alg,
        passkey.counter,
        JSON.stringify(passkey.transports),
        passkey.aaguid,
        passkey.backup_eligible ? 1 : 0,
        passkey.backed_up ? 1 : 0,
        passkey.name,
        passkey.created_via,
        now,
      );
      const row = sql
        .exec<PasskeyRow>("SELECT * FROM passkeys WHERE id = ?", passkey.id)
        .toArray()[0] as PasskeyRow;
      return { ok: true, passkey: UserDO.passkeyRecord(row) };
    });
  }

  /**
   * Assertion verification (TIO-PK-022): the signature is checked against the
   * stored public key, then the counter policy (TIO-PK-030) and the
   * `counter`/`last_used_at` update run in one transaction against the
   * freshly re-read row, so two concurrent assertions cannot both advance it.
   * The profile snapshot is returned for the caller's disabled and group checks.
   */
  async verifyAssertion(input: {
    response: unknown;
    credential_id: string;
    expected: AssertionExpectations;
    now: number;
  }): Promise<
    DoResult<{ profile: UserProfile; passkey: PasskeyRecord }, UserDoError> | CounterRegression
  > {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const stored = this.ctx.storage.sql
      .exec<PasskeyRow>("SELECT * FROM passkeys WHERE credential_id = ?", input.credential_id)
      .toArray()[0];
    if (!stored) return fail("passkey_verification_failed");
    const verified = await verifyAssertionSignature(
      input.response,
      { credential_id: stored.credential_id, public_key: bytes(stored.public_key) },
      input.expected,
    );
    if (!verified.ok) return fail(verified.error);
    return this.ctx.storage.transactionSync(() => {
      const row = this.ctx.storage.sql
        .exec<PasskeyRow>("SELECT * FROM passkeys WHERE credential_id = ?", input.credential_id)
        .toArray()[0];
      if (!row) return fail("passkey_verification_failed");
      if (counterPolicy(row.counter, verified.newCounter) === "regression") {
        const regression: CounterRegression = {
          ok: false,
          error: "passkey_counter_regression",
          regression: { passkey_id: row.id, stored: row.counter, observed: verified.newCounter },
        };
        return regression;
      }
      this.ctx.storage.sql.exec(
        "UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?",
        verified.newCounter,
        input.now,
        row.id,
      );
      const updated = this.ctx.storage.sql
        .exec<PasskeyRow>("SELECT * FROM passkeys WHERE id = ?", row.id)
        .toArray()[0] as PasskeyRow;
      return {
        ok: true,
        profile: UserDO.profile(this.readUser() as UserRow),
        passkey: UserDO.passkeyRecord(updated),
      };
    });
  }

  listPasskeys(): DoResult<{ passkeys: PasskeyRecord[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const rows = this.ctx.storage.sql
      .exec<PasskeyRow>("SELECT * FROM passkeys ORDER BY created_at, id")
      .toArray();
    return { ok: true, passkeys: rows.map((r) => UserDO.passkeyRecord(r)) };
  }

  removePasskey(
    id: string,
    actor: RemovalActor = "admin",
  ): DoResult<{ removed: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    if (actor === "self" && this.isLastLoginMethod("passkey", id)) return fail("last_login_method");
    const removed = this.ctx.storage.sql.exec("DELETE FROM passkeys WHERE id = ?", id).rowsWritten;
    return { ok: true, removed: removed > 0 };
  }

  /** True when `id` exists and is the user's only passkey or identity (TIO-PK-040, TIO-FED-051). */
  private isLastLoginMethod(kind: "passkey" | "identity", id: string): boolean {
    const count = (statement: string, ...binds: SqlStorageValue[]): number =>
      (this.ctx.storage.sql.exec<{ n: number }>(statement, ...binds).toArray()[0] as { n: number })
        .n;
    const present =
      kind === "passkey"
        ? count("SELECT COUNT(*) AS n FROM passkeys WHERE id = ?", id)
        : count("SELECT COUNT(*) AS n FROM identities WHERE id = ?", id);
    if (present !== 1) return false;
    return (
      count("SELECT COUNT(*) AS n FROM passkeys") +
        count("SELECT COUNT(*) AS n FROM identities") ===
      1
    );
  }

  renamePasskey(id: string, name: string | null): DoResult<{ renamed: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const renamed = this.ctx.storage.sql.exec(
      "UPDATE passkeys SET name = ? WHERE id = ?",
      name,
      id,
    ).rowsWritten;
    return { ok: true, renamed: renamed > 0 };
  }

  private static identityRecord(row: IdentityRow): IdentityRecord {
    return {
      id: row.id,
      issuer: row.issuer,
      subject: row.subject,
      email: row.email,
      email_verified: row.email_verified === null ? null : row.email_verified === 1,
      name: row.name,
      created_at: row.created_at,
      last_login_at: row.last_login_at,
    };
  }

  addIdentity(
    identity: NewIdentity,
    now: number,
  ): DoResult<{ identity: IdentityRecord }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    return this.ctx.storage.transactionSync(() => {
      const sql = this.ctx.storage.sql;
      const dup = sql
        .exec(
          "SELECT 1 FROM identities WHERE (issuer = ? AND subject = ?) OR id = ?",
          identity.issuer,
          identity.subject,
          identity.id,
        )
        .toArray();
      if (dup.length > 0) return fail("identity_exists");
      sql.exec(
        "INSERT INTO identities (id, issuer, subject, email, email_verified, name, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        identity.id,
        identity.issuer,
        identity.subject,
        identity.email,
        identity.email_verified === null ? null : identity.email_verified ? 1 : 0,
        identity.name,
        now,
      );
      const row = sql
        .exec<IdentityRow>("SELECT * FROM identities WHERE id = ?", identity.id)
        .toArray()[0] as IdentityRow;
      return { ok: true, identity: UserDO.identityRecord(row) };
    });
  }

  /** Records a federated login on an identity (TIO-FED-040 step 1); `found` is false when the pair is not linked. */
  touchIdentity(
    issuer: string,
    subject: string,
    claims: { email: string | null; email_verified: boolean; name: string | null },
    now: number,
  ): DoResult<{ found: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const written = this.ctx.storage.sql.exec(
      "UPDATE identities SET email = ?, email_verified = ?, name = ?, last_login_at = ? WHERE issuer = ? AND subject = ?",
      claims.email,
      claims.email_verified ? 1 : 0,
      claims.name,
      now,
      issuer,
      subject,
    ).rowsWritten;
    return { ok: true, found: written > 0 };
  }

  listIdentities(): DoResult<{ identities: IdentityRecord[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const rows = this.ctx.storage.sql
      .exec<IdentityRow>("SELECT * FROM identities ORDER BY created_at, id")
      .toArray();
    return { ok: true, identities: rows.map((r) => UserDO.identityRecord(r)) };
  }

  removeIdentity(
    id: string,
    actor: RemovalActor = "admin",
  ): DoResult<{ removed: boolean }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    if (actor === "self" && this.isLastLoginMethod("identity", id))
      return fail("last_login_method");
    const removed = this.ctx.storage.sql.exec(
      "DELETE FROM identities WHERE id = ?",
      id,
    ).rowsWritten;
    return { ok: true, removed: removed > 0 };
  }
  // ---------------------------------------------------------------------------
  // Administration (§9.4): profile updates, listings, export and recovery
  // ---------------------------------------------------------------------------

  /**
   * Applies a partial profile update (TIO-DATA-008: a changed email resets
   * `email_verified` unless the caller sets it). The D1 mirror is the
   * caller's second write.
   */
  updateProfile(patch: ProfilePatch, now: number): DoResult<{ profile: UserProfile }, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    const email = patch.email === undefined ? row.email : patch.email;
    const emailNorm = patch.email === undefined ? row.email_norm : (patch.email_norm ?? null);
    const emailChanged = email !== row.email;
    const verified =
      patch.email_verified !== undefined
        ? patch.email_verified
        : emailChanged
          ? false
          : row.email_verified === 1;
    this.ctx.storage.sql.exec(
      "UPDATE user SET email = ?, email_norm = ?, email_verified = ?, display_name = ?, updated_at = ? WHERE id = ?",
      email,
      emailNorm,
      verified ? 1 : 0,
      patch.display_name === undefined ? row.display_name : patch.display_name,
      now,
      row.id,
    );
    return { ok: true, profile: UserDO.profile(this.readUser() as UserRow) };
  }

  private static familySnapshot(row: FamilyRow): FamilySnapshot {
    return {
      id: row.id,
      client_id: row.client_id,
      kind: row.kind,
      sid: row.sid,
      scope: row.scope.split(" ").filter((s) => s.length > 0),
      auth_time: row.auth_time,
      amr: parseStrings(row.amr),
      acr: row.acr,
      created_at: row.created_at,
      absolute_expires_at: row.absolute_expires_at,
      idle_expires_at: row.idle_expires_at,
      current_serial: row.current_serial,
    };
  }

  /** Every family not yet revoked or expired, oldest first; never a token hash. */
  listFamilies(now: number): DoResult<{ families: FamilySnapshot[] }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const rows = this.ctx.storage.sql
      .exec<FamilyRow>(
        "SELECT * FROM refresh_families WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ? ORDER BY created_at, id",
        now,
        now,
      )
      .toArray();
    return { ok: true, families: rows.map((r) => UserDO.familySnapshot(r)) };
  }

  /** Revokes every live family of a client (admin `DELETE /refresh-families?client_id=`). */
  revokeFamiliesOfClient(
    clientId: string,
    now: number,
    reason: string,
  ): DoResult<{ revoked: number }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const result = this.ctx.storage.sql.exec(
      "UPDATE refresh_families SET revoked_at = ?, revoke_reason = ? WHERE client_id = ? AND revoked_at IS NULL",
      now,
      reason,
      clientId,
    );
    return { ok: true, revoked: result.rowsWritten };
  }

  /** The counts shown next to a profile (`GET /admin/users/{id}`). */
  counts(now: number): DoResult<{ counts: UserCounts }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const sql = this.ctx.storage.sql;
    const count = (statement: string, ...binds: SqlStorageValue[]): number =>
      (sql.exec<{ n: number }>(statement, ...binds).toArray()[0] as { n: number }).n;
    return {
      ok: true,
      counts: {
        passkeys: count("SELECT COUNT(*) AS n FROM passkeys"),
        identities: count("SELECT COUNT(*) AS n FROM identities"),
        sessions: count(
          "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?",
          now,
          now,
        ),
        refresh_families: count(
          "SELECT COUNT(*) AS n FROM refresh_families WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?",
          now,
          now,
        ),
        grants: count("SELECT COUNT(*) AS n FROM grants"),
      },
    };
  }

  /**
   * Everything the object holds about the user, for data portability
   * (TIO-PRIV-002): no secret hashes, no token material, no public keys
   * (TIO-ADMIN-003).
   */
  exportState(now: number): DoResult<{ export: UserExport }, UserDoError> {
    const user = this.guard();
    if (typeof user === "string") return fail(user);
    const sql = this.ctx.storage.sql;
    const passkeys = sql
      .exec<PasskeyRow>("SELECT * FROM passkeys ORDER BY created_at, id")
      .toArray()
      .map((row) => {
        const { public_key: _key, ...rest } = UserDO.passkeyRecord(row);
        return rest;
      });
    const identities = sql
      .exec<IdentityRow>("SELECT * FROM identities ORDER BY created_at, id")
      .toArray()
      .map((row) => UserDO.identityRecord(row));
    const sessions = sql
      .exec<SessionRow>("SELECT * FROM sessions ORDER BY created_at, sid")
      .toArray()
      .map((row) => ({
        ...this.snapshot(row),
        ip_hash: row.ip_hash,
        ua_family: row.ua_family,
        country: row.country,
        revoked_at: row.revoked_at,
        revoke_reason: row.revoke_reason,
      }));
    const families = sql
      .exec<FamilyRow>("SELECT * FROM refresh_families ORDER BY created_at, id")
      .toArray()
      .map((row) => ({
        ...UserDO.familySnapshot(row),
        revoked_at: row.revoked_at,
        revoke_reason: row.revoke_reason,
      }));
    const grants = sql
      .exec<GrantRow>("SELECT * FROM grants ORDER BY granted_at, client_id")
      .toArray()
      .map((row) => UserDO.grantRecord(row));
    return {
      ok: true,
      export: {
        exported_at: now,
        profile: UserDO.profile(user),
        passkeys,
        identities,
        sessions,
        refresh_families: families,
        grants,
      },
    };
  }

  /**
   * Point-in-time recovery (TIO-DEPLOY-003): the next session of this object
   * starts from the storage as it was at `bookmarkTime` (Unix seconds), and
   * the object ends right after answering so the restore takes effect at once.
   */
  async restore(
    bookmarkTime: number,
  ): Promise<DoResult<{ bookmark: string }, "restore_unavailable">> {
    try {
      return await this.applyBookmark(
        await this.ctx.storage.getBookmarkForTime(bookmarkTime * 1000),
      );
    } catch {
      return fail("restore_unavailable");
    }
  }

  /* istanbul ignore next -- reason: the local Durable Object backend implements no point-in-time recovery, so no bookmark is ever applied in tests */
  private async applyBookmark(bookmark: string): Promise<DoResult<{ bookmark: string }, never>> {
    await this.ctx.storage.onNextSessionRestoreBookmark(bookmark);
    this.ctx.waitUntil(
      Promise.resolve().then(() => this.ctx.abort("restored by an administrator")),
    );
    return { ok: true, bookmark };
  }
}
