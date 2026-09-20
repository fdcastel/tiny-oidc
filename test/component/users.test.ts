import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup, listGroups } from "../../src/db/groups.ts";
import {
  claimCredential,
  findVerifiedUser,
  getUser,
  lookupCredential,
  releaseCredential,
} from "../../src/db/users.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { createUser, createUsers, userStub } from "../../src/users/create.ts";
import { EMAIL_MAX_LENGTH, isValidEmail, normalizeEmail } from "../../src/users/email.ts";
import { registerPasskey, unregisterPasskey } from "../../src/users/passkeys.ts";
import { FakeClock } from "../support/clock.ts";
import { unique } from "../support/factories.ts";
import { env } from "../support/op.ts";

const clock = new FakeClock(1_800_000_000);
const uuids = new UuidV7(clock);
const db = Db.from(env.DB);

const input = (overrides: Record<string, unknown> = {}) => ({
  id: uuids.next(),
  email: `${unique("u")}@Example.com`,
  email_verified: true,
  display_name: "Alice",
  groups: [] as string[],
  ...overrides,
});

const passkey = (credentialId: string) => ({
  id: uuids.next(),
  credential_id: credentialId,
  public_key: new Uint8Array([1, 2, 3]),
  alg: -7,
  counter: 0,
  transports: ["internal"],
  aaguid: "00000000-0000-0000-0000-000000000000",
  backup_eligible: true,
  backed_up: true,
  name: null,
  created_via: "interaction" as const,
});

describe("email rules", () => {
  it("[TIO-DATA-005] emails are trimmed, NFC-normalized and lower-cased for comparison, at most 254 characters and syntactically valid", () => {
    expect(normalizeEmail("  Alice@Example.COM ")).toBe("alice@example.com");
    expect(normalizeEmail("é@x.io")).toBe("é@x.io");
    expect(isValidEmail("alice@example.com")).toBe(true);
    expect(isValidEmail(" alice@example.com ")).toBe(true);
    expect(isValidEmail("a.b+c@sub.example.co")).toBe(true);
    for (const bad of [
      "",
      " ",
      "alice",
      "alice@",
      "@example.com",
      "a@-b.com",
      "a b@example.com",
      `${"a".repeat(250)}@x.io`,
    ]) {
      expect(isValidEmail(bad), bad).toBe(false);
    }
    expect(EMAIL_MAX_LENGTH).toBe(254);
  });
});

describe("createUser", () => {
  it("[TIO-DATA-001] [TIO-DATA-006] creates the D1 row, the memberships and the Durable Object, then activates the row; a second verified email is account_exists while unverified duplicates are fine", async () => {
    await insertGroup(
      db,
      { id: uuids.next(), name: "staff", description: null, system: false },
      clock.now(),
    );
    expect(
      await insertGroup(
        db,
        { id: uuids.next(), name: "admins", description: "System", system: true },
        clock.now(),
      ),
    ).toBe("created");
    expect(
      await insertGroup(
        db,
        { id: uuids.next(), name: "staff", description: null, system: false },
        clock.now(),
      ),
    ).toBe("group_exists");
    const groups = await listGroups(db);
    expect(groups.map((g) => [g.name, g.system])).toEqual([
      ["admins", true],
      ["staff", false],
    ]);
    const first = input({ groups: ["staff"] });
    const created = await createUser(env, db, first, clock.now());
    expect(created.ok && created.profile).toMatchObject({
      id: first.id,
      email: first.email,
      email_norm: first.email.toLowerCase(),
      email_verified: true,
      display_name: "Alice",
      groups: ["staff"],
      disabled_at: null,
    });
    expect(await getUser(db, first.id)).toMatchObject({
      id: first.id,
      email_norm: first.email.toLowerCase(),
      email_verified: true,
      status: "active",
    });
    expect((await findVerifiedUser(db, first.email.toLowerCase()))?.id).toBe(first.id);
    const members = await db
      .prepare("SELECT user_id FROM group_members WHERE group_id = ?")
      .bind(groups[1]?.id)
      .all<{ user_id: string }>();
    expect(members.results.map((m) => m.user_id)).toEqual([first.id]);
    // Same verified email: refused, and nothing is left behind.
    const dup = input({ email: first.email.toUpperCase() });
    expect(await createUser(env, db, dup, clock.now())).toEqual({
      ok: false,
      error: "account_exists",
    });
    expect(await getUser(db, dup.id)).toBeNull();
    // Unverified holders of the same email are unlimited (TIO-DATA-006).
    for (let i = 0; i < 2; i++) {
      const unverified = await createUser(
        env,
        db,
        input({ email: first.email, email_verified: false }),
        clock.now(),
      );
      expect(unverified.ok).toBe(true);
    }
    expect((await findVerifiedUser(db, first.email.toLowerCase()))?.id).toBe(first.id);
    // Validation.
    expect(await createUser(env, db, input({ email: "nope" }), clock.now())).toEqual({
      ok: false,
      error: "email_invalid",
    });
    expect(await createUser(env, db, input({ groups: ["ghosts"] }), clock.now())).toEqual({
      ok: false,
      error: "group_unknown",
    });
    const anonymous = await createUser(
      env,
      db,
      input({ email: null, display_name: null }),
      clock.now(),
    );
    expect(anonymous.ok && anonymous.profile.email).toBeNull();
    expect(await findVerifiedUser(db, "nobody@example.com")).toBeNull();
  });

  it("[TIO-ADMIN-021] creates a group with one claim batch and one activation batch, falls back to one claim per user on a duplicate, and lets any other storage failure through", async () => {
    const statements: string[][] = [];
    const counting = {
      prepare: (sql: string) => env.DB.prepare(sql),
      batch: (batch: D1PreparedStatement[]) => {
        statements.push(batch.map(() => "stmt"));
        return env.DB.batch(batch);
      },
    } as unknown as D1Database;
    const three = [input({ groups: [] }), input({ groups: [] }), input({ groups: [] })];
    const created = await createUsers(env, Db.from(counting), three, clock.now());
    expect(created.every((r) => r.ok)).toBe(true);
    // One claim batch (a row per user) and one activation batch.
    expect(statements.map((s) => s.length)).toEqual([3, 3]);
    for (const user of three) expect((await getUser(db, user.id))?.status).toBe("active");
    // A duplicate inside the group: the batch fails, the claims go one by one, the loser is told.
    const twin = input({ groups: [] });
    const mixed = [input({ groups: [] }), { ...input({ groups: [] }), email: twin.email }, twin];
    const outcomes = await createUsers(env, db, mixed, clock.now());
    expect(outcomes.map((r) => (r.ok ? "ok" : r.error))).toEqual(["ok", "ok", "account_exists"]);
    // A failure that is not a uniqueness violation, in the group batch or in the fallback, propagates.
    let batches = 0;
    const failing = {
      prepare: (sql: string) => env.DB.prepare(sql),
      batch: (batch: D1PreparedStatement[]) => {
        batches++;
        if (batches === 1) throw new Error("UNIQUE constraint failed: users.email_norm");
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    await expect(
      createUsers(env, Db.from(failing), [input({ groups: [] })], clock.now()),
    ).rejects.toThrow("D1 down");
    const down = {
      prepare: (sql: string) => env.DB.prepare(sql),
      batch: () => {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    await expect(
      createUsers(env, Db.from(down), [input({ groups: [] })], clock.now()),
    ).rejects.toThrow("D1 down");
  });

  it("[TIO-DATA-021] leaves the row in `creating` when the Durable Object cannot be initialized", async () => {
    const destroyed = input();
    await runInDurableObject(userStub(env, destroyed.id), async (instance: UserDO) => {
      await instance.destroy();
    });
    expect(await createUser(env, db, destroyed, clock.now())).toEqual({
      ok: false,
      error: "temporarily_unavailable",
    });
    expect((await getUser(db, destroyed.id))?.status).toBe("creating");
    const broken = {
      ...env,
      USER_DO: {
        idFromName: () => ({}) as DurableObjectId,
        get: () => {
          throw new Error("DO unavailable");
        },
      },
    } as unknown as Env;
    const unreachable = input();
    expect(await createUser(broken, db, unreachable, clock.now())).toEqual({
      ok: false,
      error: "temporarily_unavailable",
    });
    expect((await getUser(db, unreachable.id))?.status).toBe("creating");
    // Other D1 failures propagate.
    const brokenDb = Db.from({
      prepare: () => ({ all: async () => ({ results: [] }), bind: () => ({}) }),
      batch: async () => {
        throw new Error("D1 down");
      },
    } as unknown as D1Database);
    await expect(createUser(env, brokenDb, input(), clock.now())).rejects.toThrow("D1 down");
  });
});

describe("registerPasskey", () => {
  it("[TIO-PK-012] adds the passkey to the Durable Object and claims the credential id in the index; duplicates anywhere are passkey_exists and the limit is enforced", async () => {
    const user = input();
    await createUser(env, db, user, clock.now());
    const first = passkey("cred-a");
    const added = await registerPasskey(env, db, user.id, first, clock.now(), 2);
    expect(added.ok && added.passkey.credential_id).toBe("cred-a");
    expect(await lookupCredential(db, "cred-a")).toBe(user.id);
    // Same credential on another user: refused before the DO is touched.
    const other = input();
    await createUser(env, db, other, clock.now());
    expect(await registerPasskey(env, db, other.id, passkey("cred-a"), clock.now(), 2)).toEqual({
      ok: false,
      error: "passkey_exists",
    });
    const otherKeys = await userStub(env, other.id).listPasskeys();
    expect(otherKeys.ok && otherKeys.passkeys).toEqual([]);
    // Same id in the DO but not the index (index lost): still passkey_exists from the DO.
    await releaseCredential(db, "cred-a");
    expect(
      await registerPasskey(
        env,
        db,
        user.id,
        { ...passkey("cred-a"), id: first.id },
        clock.now(),
        2,
      ),
    ).toEqual({ ok: false, error: "passkey_exists" });
    await claimCredential(db, "cred-a", user.id, clock.now());
    // Limit.
    expect((await registerPasskey(env, db, user.id, passkey("cred-b"), clock.now(), 2)).ok).toBe(
      true,
    );
    expect(await registerPasskey(env, db, user.id, passkey("cred-c"), clock.now(), 2)).toEqual({
      ok: false,
      error: "passkey_limit_reached",
    });
    // Unknown user.
    expect(await registerPasskey(env, db, uuids.next(), passkey("cred-d"), clock.now(), 2)).toEqual(
      { ok: false, error: "user_not_available" },
    );
    // Removal: DO first, then the index.
    const record = added.ok ? added.passkey : (undefined as never);
    expect(await unregisterPasskey(env, db, user.id, record)).toBe(true);
    expect(await lookupCredential(db, "cred-a")).toBeNull();
    expect(await unregisterPasskey(env, db, user.id, record)).toBe(false);
    expect(await unregisterPasskey(env, db, uuids.next(), record)).toBe(false);
  });

  it("[TIO-DATA-026] rolls the passkey back when the index cannot be claimed, retrying a D1 hiccup once", async () => {
    const user = input();
    await createUser(env, db, user, clock.now());
    // Another user claims the id between the lookup and the claim: rolled back as passkey_exists.
    const rival = input();
    await createUser(env, db, rival, clock.now());
    let raced = false;
    const racing = Db.from({
      prepare: (sql: string) => {
        const real = env.DB.prepare(sql);
        if (sql.startsWith("SELECT user_id FROM passkey_index") && !raced) {
          raced = true;
          return {
            bind: () => ({
              first: async () => {
                await claimCredential(db, "cred-r", rival.id, clock.now());
                return null;
              },
            }),
          };
        }
        return real;
      },
      batch: (statements: D1PreparedStatement[]) => env.DB.batch(statements),
    } as unknown as D1Database);
    expect(await registerPasskey(env, racing, user.id, passkey("cred-r"), clock.now(), 5)).toEqual({
      ok: false,
      error: "passkey_exists",
    });
    const keys = await userStub(env, user.id).listPasskeys();
    expect(keys.ok && keys.passkeys).toEqual([]);
    // One failing INSERT is retried; two fail the request and roll back.
    let failures = 0;
    const flaky = (times: number) => {
      failures = 0;
      return Db.from({
        prepare: (sql: string) => {
          const real = env.DB.prepare(sql);
          if (sql.startsWith("INSERT OR IGNORE INTO passkey_index") && failures < times) {
            failures += 1;
            return {
              bind: () => ({
                run: async () => {
                  throw new Error("D1 hiccup");
                },
              }),
            };
          }
          return real;
        },
        batch: (statements: D1PreparedStatement[]) => env.DB.batch(statements),
      } as unknown as D1Database);
    };
    expect(
      (await registerPasskey(env, flaky(1), user.id, passkey("cred-h"), clock.now(), 5)).ok,
    ).toBe(true);
    expect(await lookupCredential(db, "cred-h")).toBe(user.id);
    expect(
      await registerPasskey(env, flaky(2), user.id, passkey("cred-i"), clock.now(), 5),
    ).toEqual({ ok: false, error: "temporarily_unavailable" });
    const after = await userStub(env, user.id).listPasskeys();
    expect(after.ok && after.passkeys.map((p) => p.credential_id)).toEqual(["cred-h"]);
  });
});
