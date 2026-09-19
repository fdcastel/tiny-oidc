import { DurableObject } from "cloudflare:workers";
import { z } from "zod";
import type { Env } from "../env.ts";
import { parseJson } from "../util/json.ts";
import { type DoResult, fail } from "./errors.ts";
import { USER_SCHEMA_STEPS, USER_SCHEMA_VERSION } from "./schema.ts";

// One object per user: the source of truth for everything about that user
// (spec §2.3, §4.2). Every state change runs inside one synchronous SQL
// sequence with no await between statements (TIO-DATA-020).

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

export type UserDoError = "user_not_initialized" | "user_destroyed" | "user_id_mismatch";

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

const GroupsSchema = z.array(z.string());

/** Stored groups are written by this object as a sorted JSON array; anything else reads as no groups. */
function parseGroups(text: string): string[] {
  const parsed = parseJson(GroupsSchema, text);
  return parsed.ok ? parsed.value : [];
}

export class UserDO extends DurableObject<Env> {
  private migrated = false;
  private destroyed = false;
  private lastPurgeAt = -Infinity;

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
      groups: parseGroups(row.groups),
      disabled_at: row.disabled_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  /**
   * Creates the user record (step 2 of user creation, §4.6). Idempotent for the
   * same id so the repair cron may retry; a different id is refused.
   */
  init(profile: InitProfile, now: number): DoResult<{ profile: UserProfile }, UserDoError> {
    if (this.destroyed) return fail("user_destroyed");
    this.migrate();
    const existing = this.readUser();
    if (existing) {
      return existing.id === profile.id
        ? { ok: true, profile: UserDO.profile(existing) }
        : fail("user_id_mismatch");
    }
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

  /**
   * Purge on write, at most once per 60 s (TIO-DATA-019): expired codes,
   * consumed refresh tokens past the reuse window, families and sessions
   * expired or revoked more than 24 h ago. Logical expiry is always checked on
   * read; this only bounds storage. Called by every state-changing method.
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
  }

  /** Runs the purge as a write would (used by tests and by later write methods). */
  touch(now: number, reuseWindow: number): DoResult<Record<never, never>, UserDoError> {
    const row = this.guard();
    if (typeof row === "string") return fail(row);
    this.ctx.storage.transactionSync(() => this.purgeIfDue(now, reuseWindow));
    return { ok: true };
  }
}
