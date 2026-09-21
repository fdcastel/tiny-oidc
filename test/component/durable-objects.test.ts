import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { InteractionDO, InteractionDocument } from "../../src/do/InteractionDO.ts";
import { USER_SCHEMA_VERSION } from "../../src/do/schema.ts";
import { PURGE_GRACE_SECONDS, PURGE_INTERVAL_SECONDS, type UserDO } from "../../src/do/UserDO.ts";
import { FAKE_EPOCH, FakeClock } from "../support/clock.ts";
import { userProfile } from "../support/factories.ts";
import { env } from "../support/op.ts";

const docOf = (result: { ok: true; doc: InteractionDocument } | { ok: false; error: string }) => {
  if (!result.ok) throw new Error(result.error);
  return result.doc;
};

const userStub = (name: string) => env.USER_DO.get(env.USER_DO.idFromName(name));
const interactionStub = (name: string) =>
  env.INTERACTION_DO.get(env.INTERACTION_DO.idFromName(name));

const profile = (id: string) =>
  userProfile(new FakeClock(), {
    id,
    email: "Alice@Example.com",
    email_norm: "alice@example.com",
    email_verified: true,
    display_name: "Alice",
    groups: ["staff", "admins"],
  });

describe("UserDO", () => {
  it("[TIO-DATA-021] refuses every method except init() before initialization and except destroy() after destruction", async () => {
    const stub = userStub("guards");
    expect(await stub.getProfile()).toEqual({ ok: false, error: "user_not_initialized" });
    expect(await stub.touch(FAKE_EPOCH, 86_400)).toEqual({
      ok: false,
      error: "user_not_initialized",
    });
    const created = await stub.init(profile("u1"), FAKE_EPOCH);
    expect(created).toEqual({
      ok: true,
      profile: {
        id: "u1",
        email: "Alice@Example.com",
        email_norm: "alice@example.com",
        email_verified: true,
        display_name: "Alice",
        groups: ["admins", "staff"],
        disabled_at: null,
        created_at: FAKE_EPOCH,
        updated_at: FAKE_EPOCH,
      },
    });
    // init is idempotent for the same id (cron repair) and refused for another id.
    expect(await stub.init(profile("u1"), FAKE_EPOCH + 500)).toEqual(created);
    expect(await stub.init(profile("u2"), FAKE_EPOCH + 500)).toEqual({
      ok: false,
      error: "user_id_mismatch",
    });
    expect((await stub.getProfile()).ok).toBe(true);
    expect(await stub.destroy()).toEqual({ ok: true });
    expect(await stub.getProfile()).toEqual({ ok: false, error: "user_destroyed" });
    expect(await stub.init(profile("u1"), FAKE_EPOCH + 600)).toEqual({
      ok: false,
      error: "user_destroyed",
    });
    expect(await stub.touch(FAKE_EPOCH + 600, 86_400)).toEqual({
      ok: false,
      error: "user_destroyed",
    });
    expect(await stub.destroy()).toEqual({ ok: true });
    // Storage is empty after destroy.
    await runInDurableObject(stub, async (_instance: UserDO, state) => {
      expect((await state.storage.list()).size).toBe(0);
    });
  });

  it("migrates the §4.2 schema lazily and idempotently and records the version; the version 3 rebuild of auth_codes keeps a live code (rows inserted directly to construct the earlier schema)", async () => {
    const stub = userStub("schema");
    await stub.init({ ...profile("u3"), email_verified: false }, FAKE_EPOCH);
    const first = await stub.getProfile();
    expect(first.ok && first.profile.email_verified).toBe(false);
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      const tables = state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf%' ESCAPE '\\' AND name NOT LIKE 'sqlite%' ORDER BY name",
        )
        .toArray()
        .map((r) => r.name);
      expect(tables).toEqual([
        "auth_codes",
        "challenges",
        "grants",
        "identities",
        "meta",
        "passkeys",
        "refresh_families",
        "refresh_tokens",
        "session_clients",
        "sessions",
        "user",
      ]);
      const meta = Object.fromEntries(
        state.storage.sql
          .exec<{ key: string; value: string }>("SELECT key, value FROM meta")
          .toArray()
          .map((r) => [r.key, r.value]),
      );
      expect(meta).toEqual({ schema_version: String(USER_SCHEMA_VERSION), user_id: "u3" });
    });
    // A new instance (after eviction) finds the recorded version and skips the steps; groups stored as JSON survive a bad value.
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("UPDATE user SET groups = 'not json'");
    });
    await evictDurableObject(stub);
    const again = await stub.getProfile();
    expect(again.ok && again.profile.groups).toEqual([]);
    // An object left at version 1 by an earlier deploy gets only the later steps.
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("DROP TABLE challenges");
      state.storage.sql.exec("UPDATE meta SET value = '1' WHERE key = 'schema_version'");
    });
    await evictDurableObject(stub);
    expect(await stub.putChallenge("k", "v", FAKE_EPOCH + 100)).toEqual({ ok: true });
    expect(await stub.takeChallenge("k", FAKE_EPOCH)).toEqual({ ok: true, value: "v" });
    expect(await stub.takeChallenge("k", FAKE_EPOCH)).toEqual({ ok: true, value: null });
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      const version = state.storage.sql
        .exec<{ value: string }>("SELECT value FROM meta WHERE key = 'schema_version'")
        .toArray()[0];
      expect(version?.value).toBe(String(USER_SCHEMA_VERSION));
    });
    // An object at version 2 (auth_codes.code_challenge NOT NULL) holding a live code: the
    // version 3 rebuild copies the row, keeps the index and admits a challenge-less code.
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      const sql = state.storage.sql;
      sql.exec("DROP TABLE auth_codes");
      sql.exec(
        "CREATE TABLE auth_codes (secret_hash BLOB PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, nonce TEXT, code_challenge TEXT NOT NULL, sid TEXT NOT NULL, auth_time INTEGER NOT NULL, amr TEXT NOT NULL, acr TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)",
      );
      sql.exec("CREATE INDEX auth_codes_expires ON auth_codes(expires_at)");
      sql.exec(
        "INSERT INTO auth_codes VALUES (?, 'c1', 'https://rp.example.com/cb', 'openid', NULL, 'challenge-1', 'sid-1', 1, '[\"pk\"]', 'urn:x', 1, ?, NULL)",
        new Uint8Array([1, 2, 3]),
        FAKE_EPOCH + 60,
      );
      sql.exec("UPDATE meta SET value = '2' WHERE key = 'schema_version'");
    });
    await evictDurableObject(stub);
    expect(await stub.putChallenge("k2", "v", FAKE_EPOCH + 100)).toEqual({ ok: true });
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      const sql = state.storage.sql;
      const rows = sql
        .exec<{ client_id: string; code_challenge: string | null }>(
          "SELECT client_id, code_challenge FROM auth_codes ORDER BY client_id",
        )
        .toArray();
      expect(rows).toEqual([{ client_id: "c1", code_challenge: "challenge-1" }]);
      expect(
        sql
          .exec<{ name: string }>(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'auth_codes' AND sql IS NOT NULL",
          )
          .toArray()
          .map((r) => r.name),
      ).toEqual(["auth_codes_expires"]);
      sql.exec(
        "INSERT INTO auth_codes VALUES (?, 'c2', 'https://rp.example.com/cb', 'openid', NULL, NULL, 'sid-1', 1, '[]', 'urn:x', 1, ?, NULL)",
        new Uint8Array([4, 5, 6]),
        FAKE_EPOCH + 60,
      );
      expect(
        sql.exec("SELECT count(*) AS n FROM auth_codes WHERE code_challenge IS NULL").one()["n"],
      ).toBe(1);
      expect(
        sql.exec<{ value: string }>("SELECT value FROM meta WHERE key = 'schema_version'").one()
          .value,
      ).toBe(String(USER_SCHEMA_VERSION));
    });
  });

  it("[TIO-DATA-019] purges expired codes, consumed tokens past the reuse window, and stale families and sessions on write, at most once per 60 s (rows inserted directly to construct the state)", async () => {
    const stub = userStub("purge");
    const clock = new FakeClock(1_800_000_000);
    const now = clock.now();
    const reuseWindow = 86_400;
    await stub.init(profile("u4"), now);
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      const sql = state.storage.sql;
      const code = (hash: string, expires: number) =>
        sql.exec(
          "INSERT INTO auth_codes (secret_hash, client_id, redirect_uri, scope, code_challenge, sid, auth_time, amr, acr, created_at, expires_at) VALUES (?, 'c', 'https://rp/cb', 'openid', 'x', 's', 0, '[]', 'a', 0, ?)",
          new TextEncoder().encode(hash),
          expires,
        );
      code("code-expired", now - 1);
      code("code-live", now + 30);
      const family = (id: string, revoked: number | null, absolute: number, idle: number) =>
        sql.exec(
          "INSERT INTO refresh_families (id, client_id, client_created_at, kind, scope, auth_time, amr, acr, created_at, absolute_expires_at, idle_expires_at, revoked_at) VALUES (?, 'c', 0, 'offline', 'openid', 0, '[]', 'a', 0, ?, ?, ?)",
          id,
          absolute,
          idle,
          revoked,
        );
      family("fam-revoked-old", now - PURGE_GRACE_SECONDS - 1, now + 1000, now + 1000);
      family("fam-revoked-recent", now - 10, now + 1000, now + 1000);
      family("fam-absolute-old", null, now - PURGE_GRACE_SECONDS - 1, now + 1000);
      family("fam-idle-old", null, now + 1000, now - PURGE_GRACE_SECONDS - 1);
      family("fam-live", null, now + 1000, now + 1000);
      const token = (hash: string, familyId: string, consumed: number | null) =>
        sql.exec(
          "INSERT INTO refresh_tokens (secret_hash, family_id, serial, created_at, consumed_at) VALUES (?, ?, 1, 0, ?)",
          new TextEncoder().encode(hash),
          familyId,
          consumed,
        );
      token("tok-consumed-old", "fam-live", now - reuseWindow - 1);
      token("tok-consumed-recent", "fam-live", now - 10);
      token("tok-current", "fam-live", null);
      const session = (sid: string, revoked: number | null, absolute: number, idle: number) =>
        sql.exec(
          "INSERT INTO sessions (sid, secret_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, auth_time, amr, acr, revoked_at) VALUES (?, ?, 0, 0, ?, ?, 0, '[]', 'a', ?)",
          sid,
          new TextEncoder().encode(sid),
          idle,
          absolute,
          revoked,
        );
      session("sess-revoked-old", now - PURGE_GRACE_SECONDS - 1, now + 1000, now + 1000);
      session(
        "sess-expired-old",
        null,
        now - PURGE_GRACE_SECONDS - 1,
        now - PURGE_GRACE_SECONDS - 1,
      );
      session("sess-live", null, now + 1000, now + 1000);
    });
    // init() ran the migration but no purge; the first write purges.
    expect(await stub.touch(now, reuseWindow)).toEqual({ ok: true });
    const remaining = async () =>
      runInDurableObject(stub, (_instance: UserDO, state) => {
        const sql = state.storage.sql;
        const names = (table: string, column: string) =>
          sql
            .exec<{ v: string | ArrayBuffer }>(`SELECT ${column} AS v FROM ${table} ORDER BY 1`)
            .toArray()
            .map((r) => (typeof r.v === "string" ? r.v : new TextDecoder().decode(r.v)))
            .sort();
        return {
          codes: names("auth_codes", "secret_hash"),
          families: names("refresh_families", "id"),
          tokens: names("refresh_tokens", "secret_hash"),
          sessions: names("sessions", "sid"),
        };
      });
    expect(await remaining()).toEqual({
      codes: ["code-live"],
      families: ["fam-live", "fam-revoked-recent"],
      tokens: ["tok-consumed-recent", "tok-current"],
      sessions: ["sess-live"],
    });
    // Within 60 s a second write does not purge again, even if rows became stale.
    await runInDurableObject(stub, (_instance: UserDO, state) => {
      state.storage.sql.exec("UPDATE auth_codes SET expires_at = ?", now - 1);
    });
    clock.advance(PURGE_INTERVAL_SECONDS - 1);
    expect(await stub.touch(clock.now(), reuseWindow)).toEqual({ ok: true });
    expect((await remaining()).codes).toEqual(["code-live"]);
    clock.advance(1);
    expect(await stub.touch(clock.now(), reuseWindow)).toEqual({ ok: true });
    expect((await remaining()).codes).toEqual([]);
  });
});

describe("InteractionDO", () => {
  const create = (stub: DurableObjectStub<InteractionDO>, now: number, ttl = 600) =>
    stub.create(
      {
        id: "ix1",
        kind: "authorize",
        status: "login_required",
        binding_hash: "bh",
        client_id: "web",
      },
      now,
      ttl,
    );

  it("[TIO-DATA-022] expires 600 s after creation: the alarm deletes all storage and the document is not found afterwards", async () => {
    const stub = interactionStub("expiry");
    const now = FAKE_EPOCH;
    const created = await create(stub, now);
    expect(docOf(created)).toMatchObject({
      id: "ix1",
      status: "login_required",
      created_at: now,
      expires_at: now + 600,
      attempts: 0,
    });
    expect(await create(stub, now)).toEqual({ ok: false, error: "interaction_exists" });
    expect((await stub.get(now + 599)).ok).toBe(true);
    expect(await stub.get(now + 600)).toEqual({ ok: false, error: "interaction_not_found" });
    await runInDurableObject(stub, async (_instance: InteractionDO, state) => {
      expect(await state.storage.getAlarm()).toBe((now + 600) * 1000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance: InteractionDO, state) => {
      expect((await state.storage.list()).size).toBe(0);
    });
    expect(await stub.get(now)).toEqual({ ok: false, error: "interaction_not_found" });
    expect(await stub.apply("abort", "failed", {}, now)).toEqual({
      ok: false,
      error: "interaction_not_found",
    });
  });

  it("[TIO-DATA-022] completed and failed interactions are deleted 60 s after reaching that state", async () => {
    const stub = interactionStub("terminal");
    const now = FAKE_EPOCH;
    await create(stub, now);
    const failed = await stub.apply(
      "abort",
      "failed",
      { error: { error: "access_denied", error_description: "aborted" } },
      now + 10,
    );
    expect(docOf(failed).expires_at).toBe(now + 70);
    await runInDurableObject(stub, async (_instance: InteractionDO, state) => {
      expect(await state.storage.getAlarm()).toBe((now + 70) * 1000);
    });
    expect((await stub.get(now + 69)).ok).toBe(true);
    expect(await stub.get(now + 70)).toEqual({ ok: false, error: "interaction_not_found" });
    // A terminal state reached close to the natural expiry never extends it.
    const late = interactionStub("terminal-late");
    await create(late, now);
    const done = await late.apply("fail", "failed", {}, now + 580);
    expect(docOf(done).expires_at).toBe(now + 600);
  });

  it("[TIO-IX-010] [TIO-DATA-023] validates every transition against §7.2 and leaves the document unchanged on an invalid one (interaction_invalid_state)", async () => {
    const stub = interactionStub("transitions");
    const now = FAKE_EPOCH;
    await create(stub, now);
    const invalid = await stub.apply("consent", "ready", { consent: { scopes: ["openid"] } }, now);
    expect(invalid).toEqual({ ok: false, error: "interaction_invalid_state" });
    const unchanged = await stub.get(now);
    expect(docOf(unchanged).status).toBe("login_required");
    expect(docOf(unchanged).consent).toBeNull();
    const authenticated = {
      uid: "u1",
      method: "passkey" as const,
      amr: ["hwk", "user"],
      acr: "urn:tinyoidc:acr:passkey",
      upstream: null,
      auth_time: now + 1,
      new_session: true,
    };
    const auth = await stub.apply(
      "authenticate",
      "consent_required",
      { auth: authenticated },
      now + 1,
    );
    expect(docOf(auth).status).toBe("consent_required");
    expect(docOf(auth).auth).toEqual(authenticated);
    // A permitted operation to a status not listed for it is refused as well.
    expect(await stub.apply("consent", "completed", {}, now + 2)).toEqual({
      ok: false,
      error: "interaction_invalid_state",
    });
    const ready = await stub.apply(
      "consent",
      "ready",
      { consent: { scopes: ["openid"] } },
      now + 2,
    );
    expect(docOf(ready).status).toBe("ready");
    const completed = await stub.apply("complete", "completed", {}, now + 3);
    expect(docOf(completed).status).toBe("completed");
    expect(await stub.apply("complete", "completed", {}, now + 4)).toEqual({
      ok: false,
      error: "interaction_invalid_state",
    });
  });
});
