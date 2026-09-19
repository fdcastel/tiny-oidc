import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { sealedUnderVersion, sealSecret } from "../../src/crypto/secretbox.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { insertIdentityStatement } from "../../src/db/identities.ts";
import { listSigningKeys } from "../../src/db/keys.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { getUpstream, updateUpstreamSecrets } from "../../src/db/upstreams.ts";
import {
  getUser,
  insertUserStatement,
  lookupCredential,
  setUserStatus,
} from "../../src/db/users.ts";
import type { Env } from "../../src/env.ts";
import { userStub } from "../../src/users/create.ts";
import { createInvitation } from "../../src/users/invitations.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, brokenDoFor, failingD1, sabotageDo } from "./faults.ts";

// Keys, settings, stats and maintenance endpoints (spec §9.4): the key
// lifecycle by hand (TIO-KEYS-012, TIO-KEYS-013), settings validated as a
// whole (TIO-CFG-003), and the cron body on demand (TIO-CRYPTO-011).

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let token: string;
let rootId: string;

interface Key {
  kid: string;
  alg: string;
  role: string;
  public_jwk: Record<string, unknown>;
  created_at: number;
  activates_at: number;
  retired_at: number | null;
}

type Effective = Record<string, { value: unknown; source: "default" | "setting" }>;

const call = (method: string, path: string, body?: unknown, options: { env?: Env } = {}) =>
  admin(h, token, path, {
    method,
    ...(body === undefined ? {} : { body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });

const lastEvent = (type: string): AuditEvent =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type)
    .at(-1) as AuditEvent;

/** A new admin token; the fake clock outruns token lifetimes in the maintenance tests. */
async function relogin(): Promise<void> {
  const fresh = await adminUser(h);
  token = fresh.access_token;
  rootId = fresh.user.profile.id;
}

const keysOf = async (): Promise<Key[]> =>
  ((await (await call("GET", "keys")).json()) as { items: Key[] }).items;

describe("keys", () => {
  it("[TIO-KEYS-012] [TIO-KEYS-013] lists keys with derived roles and public JWKs only; rotation prepublishes or activates at once; retirement is refused for the only active key and audited otherwise", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    const initial = await keysOf();
    expect(initial).toHaveLength(1);
    expect(initial[0]).toMatchObject({
      role: "signing",
      alg: "ES256",
      public_jwk: { kty: "EC", crv: "P-256" },
      retired_at: null,
    });
    expect(JSON.stringify(initial)).not.toMatch(/"d"|private/);
    const first = (initial[0] as Key).kid;

    const prepublished = await call("POST", "keys/rotate", {});
    expect(prepublished.status).toBe(201);
    const next = (await prepublished.json()) as Key;
    expect(next).toMatchObject({ role: "next", activates_at: clock.now() + 86_400 });
    expect(lastEvent("key.created")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      data: { target: `kid:${next.kid}`, immediate: false },
    });
    expect((await keysOf()).map((k) => k.role)).toEqual(["signing", "next"]);
    // The only active key cannot be retired; the next one can.
    const refused = await call("DELETE", `keys/${first}`);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: "last_active_key" });
    const retiredNext = await call("DELETE", `keys/${next.kid}`);
    expect(retiredNext.status).toBe(200);
    expect(await retiredNext.json()).toMatchObject({ role: "retired", retired_at: clock.now() });
    expect(lastEvent("key.retired")).toMatchObject({
      data: { target: `kid:${next.kid}`, emergency: true },
    });
    expect((await call("DELETE", `keys/${next.kid}`)).status).toBe(404);
    expect((await call("DELETE", "keys/unknown-kid")).status).toBe(404);

    // An emergency rotation signs at once; the previous key verifies and can then be retired.
    clock.advance(1);
    const immediate = (await (
      await call("POST", "keys/rotate", { immediate: true })
    ).json()) as Key;
    expect(immediate).toMatchObject({ role: "signing", activates_at: clock.now() });
    const roles = Object.fromEntries((await keysOf()).map((k) => [k.kid, k.role]));
    expect(roles).toEqual({
      [first]: "verifying",
      [next.kid]: "retired",
      [immediate.kid]: "signing",
    });
    expect(((await (await call("DELETE", `keys/${first}`)).json()) as Key).role).toBe("retired");
    // The retired key no longer signs anything: a fresh token carries the new kid.
    const fresh = await adminUser(h);
    const header = JSON.parse(atob(fresh.access_token.split(".")[0] as string)) as { kid: string };
    expect(header.kid).toBe(immediate.kid);
    // The old token was signed with the retired key and is refused from now on (TIO-KEYS-013).
    expect((await call("GET", "keys")).status).toBe(401);
    token = fresh.access_token;
    rootId = fresh.user.profile.id;

    expect((await call("POST", "keys/rotate", { immediate: "yes" })).status).toBe(400);
    expect((await call("POST", "keys/rotate", "{oops")).status).toBe(400);
    expect(
      (await call("POST", "keys/rotate", {}, { env: { ...env, DB: brokenD1 } as Env })).status,
    ).toBe(503);
    expect(
      (
        await call("DELETE", `keys/${immediate.kid}`, undefined, {
          env: { ...env, DB: brokenD1 } as Env,
        })
      ).status,
    ).toBe(503);
    expect(
      (
        await call("GET", "keys", undefined, {
          env: { ...env, DB: failingD1(/FROM signing_keys/) } as Env,
        })
      ).status,
    ).toBe(503);
    // A retired row whose public JWK no longer parses lists as an empty JWK.
    await db
      .prepare("UPDATE signing_keys SET public_jwk = 'oops' WHERE kid = ?")
      .bind(next.kid)
      .run();
    expect((await keysOf()).find((k) => k.kid === next.kid)?.public_jwk).toEqual({});
  });
});

describe("settings", () => {
  it("[TIO-CFG-003] shows every setting with its source, applies a patch only when the whole validates, returns a key to its default with null, and refuses unknown or system-managed keys", async () => {
    const before = (await (await call("GET", "settings")).json()) as Effective;
    expect(before["login_url"]).toEqual({ value: `${LOGIN_ORIGIN}/`, source: "setting" });
    expect(before["registration.mode"]).toEqual({ value: "invite", source: "default" });
    expect(before["bootstrapped_at"]).toEqual({ value: null, source: "default" });
    expect(Object.keys(before)).toContain("keys.retire_after_seconds");

    const patched = await call("PATCH", "settings", {
      "registration.mode": "open",
      "tokens.access_ttl": 900,
    });
    expect(patched.status).toBe(200);
    const after = (await patched.json()) as Effective;
    expect(after["registration.mode"]).toEqual({ value: "open", source: "setting" });
    expect(after["tokens.access_ttl"]).toEqual({ value: 900, source: "setting" });
    expect(lastEvent("settings.updated")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      data: {
        target: "settings",
        keys: ["registration.mode", "tokens.access_ttl"],
        diff: {
          "registration.mode": { from: "invite", to: "open" },
          "tokens.access_ttl": { from: 600, to: 900 },
        },
      },
    });
    // A cross-field violation rejects the whole patch; nothing is written.
    const invalid = await call("PATCH", "settings", {
      "tokens.id_ttl": 1200,
      "keys.retire_after_seconds": 4000,
    });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({
      error: "invalid_settings",
      error_description: expect.stringContaining("keys.retire_after_seconds"),
    });
    expect(
      ((await (await call("GET", "settings")).json()) as Effective)["tokens.id_ttl"],
    ).toMatchObject({
      source: "default",
    });
    expect(
      await (await call("PATCH", "settings", { "tokens.access_ttl": "long" })).json(),
    ).toMatchObject({
      error: "invalid_settings",
    });
    expect(await (await call("PATCH", "settings", { colour: "blue" })).json()).toMatchObject({
      error: "invalid_request",
      error_description: "unknown settings: colour",
    });
    expect((await call("PATCH", "settings", { bootstrapped_at: 1 })).status).toBe(400);
    expect((await call("PATCH", "settings", {})).status).toBe(400);
    expect((await call("PATCH", "settings", "[1]")).status).toBe(400);
    // null returns a key to its default.
    const reset = (await (
      await call("PATCH", "settings", { "registration.mode": null })
    ).json()) as Effective;
    expect(reset["registration.mode"]).toEqual({ value: "invite", source: "default" });
    // Stored settings that no longer validate have no "before" in the audit record, but a fixing patch lands.
    await writeSettings(db, { "tokens.access_ttl": 5 }, "test", clock.now());
    const repaired = await call("PATCH", "settings", { "tokens.access_ttl": 600 });
    expect(repaired.status).toBe(200);
    expect(lastEvent("settings.updated").data["diff"]).toMatchObject({
      "tokens.access_ttl": { from: null, to: 600 },
    });
    expect(
      (
        await call(
          "PATCH",
          "settings",
          { "tokens.access_ttl": 600 },
          { env: { ...env, DB: brokenD1 } as Env },
        )
      ).status,
    ).toBe(503);
    const fresh = harness(clock);
    expect(
      (
        await admin(fresh, token, "settings", {
          env: { ...env, DB: failingD1(/FROM settings/) } as Env,
        })
      ).status,
    ).toBe(503);
  });
});

describe("stats and maintenance", () => {
  it("[TIO-CFG-010] [TIO-CRYPTO-011] the purge runs the cron body once: old audit rows, expired invitations, creating and deleting users, key retirement and re-encryption; stats reflect the state", async () => {
    // An invitation that expires long before the run; 31 days on it is beyond its grace.
    const expired = await createInvitation(
      db,
      testKeys(),
      {
        kind: "register",
        user_id: null,
        email: null,
        email_verified: false,
        display_name: null,
        groups: [],
        expires_in: 3600,
        created_by: "test",
      },
      clock,
    );
    if (!expired.ok) throw new Error(expired.error);
    clock.advance(31 * 86_400);
    await relogin();
    // Old and fresh audit rows, users stuck mid-creation and mid-deletion.
    const insertAudit = (id: string, ts: number) =>
      db
        .prepare(
          "INSERT INTO audit_hot (id, ts, type, outcome, actor_kind, actor_id, user_id, client_id, upstream, ip_hash, data) VALUES (?, ?, 'x', 'success', 'system', NULL, NULL, NULL, NULL, NULL, '{}')",
        )
        .bind(id, ts);
    await db.batch([
      insertAudit("a-old-1", clock.now() - 400 * 86_400),
      insertAudit("a-old-2", clock.now() - 400 * 86_400),
      insertAudit("a-new", clock.now()),
    ]);
    const repairable = new UuidV7(clock).next();
    const droppable = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        {
          id: repairable,
          email: "Repair@Example.com",
          email_norm: "repair@example.com",
          email_verified: true,
          display_name: "Repaired",
        },
        clock.now() - 120,
      ),
      db
        .prepare(
          "INSERT INTO group_members (group_id, user_id, added_at) SELECT id, ?, ? FROM groups WHERE name = 'admins'",
        )
        .bind(repairable, clock.now()),
      // A pair claimed by the creation (§4.6 step 1) that the object never received.
      insertIdentityStatement(
        db,
        "https://idp.example.com",
        "repaired-at-idp",
        repairable,
        clock.now(),
      ),
      insertUserStatement(
        db,
        { id: droppable, email: null, email_norm: null, email_verified: false, display_name: null },
        clock.now() - 7200,
      ),
    ]);
    const halfDeleted = await userWithPasskey(clock);
    await setUserStatus(db, halfDeleted.profile.id, "deleting", clock.now());
    const statsBefore = (await (await call("GET", "stats")).json()) as Record<string, unknown>;
    expect(statsBefore).toMatchObject({
      users: { creating: 2, deleting: 1 },
      audit_hot_rows: 3,
      keys: { signing: 1, next: 0, verifying: 0, retired: 2 },
      last_cron_run: null,
    });
    expect(statsBefore["clients"]).toBeGreaterThan(0);

    const purged = await call("POST", "maintenance/purge");
    expect(purged.status).toBe(200);
    const report = (await purged.json()) as Record<string, unknown>;
    expect(report).toMatchObject({
      audit_rows_purged: 2,
      invitations_deleted: 1,
      users_repaired: 1,
      users_dropped: 1,
      users_deleted: 1,
      keys: { created: null, retired: [], deleted: 0 },
      rekeyed: { signing_keys: 0, upstreams: 0, unrecoverable: 0, remaining: 0 },
      skipped: [],
    });
    expect(lastEvent("system.cron_run")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      outcome: "success",
      data: { users_repaired: 1 },
    });
    expect(await getUser(db, repairable)).toMatchObject({ status: "active" });
    const repairedProfile = await userStub(env, repairable).getProfile();
    expect(repairedProfile.ok && repairedProfile.profile).toMatchObject({
      email: "Repair@Example.com",
      groups: ["admins"],
    });
    // The claimed pair is linked into the object, so the index row is confirmed from now on.
    const repairedIdentities = await userStub(env, repairable).listIdentities();
    expect(repairedIdentities.ok && repairedIdentities.identities).toEqual([
      expect.objectContaining({
        issuer: "https://idp.example.com",
        subject: "repaired-at-idp",
        email: null,
        email_verified: null,
        name: null,
      }),
    ]);
    expect(await getUser(db, droppable)).toBeNull();
    expect(await getUser(db, halfDeleted.profile.id)).toBeNull();
    expect(await halfDeleted.stub.getProfile()).toEqual({ ok: false, error: "user_destroyed" });
    const statsAfter = (await (await call("GET", "stats")).json()) as Record<string, unknown>;
    expect(statsAfter).toMatchObject({
      users: { creating: 0, deleting: 0 },
      audit_hot_rows: 1,
      last_cron_run: clock.now(),
    });
    // A second run has nothing left to do.
    expect(await (await call("POST", "maintenance/purge")).json()).toMatchObject({
      audit_rows_purged: 0,
      invitations_deleted: 0,
      users_repaired: 0,
      users_deleted: 0,
    });
    expect(
      (
        await call("POST", "maintenance/purge", undefined, {
          env: { ...env, DB: failingD1(/audit_hot/) } as Env,
        })
      ).status,
    ).toBe(503);
    expect(
      (await call("GET", "stats", undefined, { env: { ...env, DB: failingD1(/COUNT/) } as Env }))
        .status,
    ).toBe(503);
    // A creating row whose object was destroyed cannot be repaired; one whose object is
    // unreachable is left for the next run.
    const destroyed = await userWithPasskey(clock);
    await destroyed.stub.destroy();
    await setUserStatus(db, destroyed.profile.id, "creating", clock.now() - 120);
    await db
      .prepare("UPDATE users SET created_at = ? WHERE id = ?")
      .bind(clock.now() - 120, destroyed.profile.id)
      .run();
    const unreachable = new UuidV7(clock).next();
    await db.batch([
      insertUserStatement(
        db,
        {
          id: unreachable,
          email: null,
          email_norm: null,
          email_verified: false,
          display_name: null,
        },
        clock.now() - 120,
      ),
    ]);
    const stuck = (await (
      await call("POST", "maintenance/purge", undefined, { env: brokenDoFor(unreachable) })
    ).json()) as Record<string, unknown>;
    expect(stuck).toMatchObject({ users_repaired: 0, users_dropped: 0 });
    expect((await getUser(db, destroyed.profile.id))?.status).toBe("creating");
    expect((await getUser(db, unreachable))?.status).toBe("creating");
    await db
      .prepare("DELETE FROM users WHERE id IN (?, ?)")
      .bind(destroyed.profile.id, unreachable)
      .run();
    // A creation that got past step 2 (the object holds the pair) is activated as is; one
    // whose object refuses the pair stays for the next run.
    const halfway = new UuidV7(clock).next();
    const unlinkable = new UuidV7(clock).next();
    const blank = { email: null, email_norm: null, email_verified: false, display_name: null };
    await db.batch([
      insertUserStatement(db, { id: halfway, ...blank }, clock.now() - 120),
      insertIdentityStatement(
        db,
        "https://idp.example.com",
        "halfway-at-idp",
        halfway,
        clock.now(),
      ),
      insertUserStatement(db, { id: unlinkable, ...blank }, clock.now() - 120),
      insertIdentityStatement(
        db,
        "https://idp.example.com",
        "unlinkable-at-idp",
        unlinkable,
        clock.now(),
      ),
    ]);
    await userStub(env, halfway).init({ id: halfway, ...blank, groups: [] }, clock.now());
    await userStub(env, halfway).addIdentity(
      {
        id: new UuidV7(clock).next(),
        issuer: "https://idp.example.com",
        subject: "halfway-at-idp",
        email: "halfway@example.com",
        email_verified: true,
        name: "Halfway",
      },
      clock.now(),
    );
    const partial = (await (
      await call("POST", "maintenance/purge", undefined, {
        env: sabotageDo(unlinkable, "addIdentity"),
      })
    ).json()) as Record<string, unknown>;
    expect(partial).toMatchObject({ users_repaired: 1, users_dropped: 0 });
    expect((await getUser(db, halfway))?.status).toBe("active");
    const halfwayIdentities = await userStub(env, halfway).listIdentities();
    expect(halfwayIdentities.ok && halfwayIdentities.identities).toEqual([
      expect.objectContaining({ subject: "halfway-at-idp", email: "halfway@example.com" }),
    ]);
    expect((await getUser(db, unlinkable))?.status).toBe("creating");
    await db.prepare("DELETE FROM users WHERE id = ?").bind(unlinkable).run();
    // A full batch of old audit rows takes a second batch to finish.
    const bulk = [];
    for (let i = 0; i < 1000; i++) bulk.push(insertAudit(`bulk-${i}`, clock.now() - 400 * 86_400));
    for (let i = 0; i < bulk.length; i += 500) await db.batch(bulk.slice(i, i + 500));
    expect(await (await call("POST", "maintenance/purge")).json()).toMatchObject({
      audit_rows_purged: 1000,
    });
  });

  it("[TIO-CRYPTO-011] [TIO-KEYS-012] a new active master-key version re-encrypts signing keys and upstream secrets chunk by chunk; automatic rotation creates the next key when due", async () => {
    const manual = {
      mode: "manual",
      authorization_endpoint: "https://m.example.net/a",
      token_endpoint: "https://m.example.net/t",
      jwks_uri: "https://m.example.net/j",
    };
    expect(
      (
        await call("POST", "upstreams", {
          alias: "sealed",
          issuer: "https://m.example.net",
          display_name: "Sealed",
          client_id: "c",
          token_endpoint_auth_method: "client_secret_basic",
          client_secret: "under-v1",
          discovery: manual,
        })
      ).status,
    ).toBe(201);
    expect(
      sealedUnderVersion((await getUpstream(db, "sealed"))?.client_secret_enc as Uint8Array),
    ).toBe(1);
    // Material sealed under a version the secret no longer holds is reported, not touched.
    expect(
      (
        await call("POST", "upstreams", {
          alias: "keyed",
          issuer: "https://k.example.net",
          display_name: "Keyed",
          client_id: "c",
          token_endpoint_auth_method: "private_key_jwt",
          client_jwk: { kty: "EC", kid: "k", d: "d" },
          discovery: { ...manual, jwks_uri: "https://k.example.net/j" },
        })
      ).status,
    ).toBe(201);
    const underV2 = (text: string) => sealSecret(testKeys("2"), new TextEncoder().encode(text));
    await updateUpstreamSecrets(db, "sealed", await underV2("lost"), null);
    await updateUpstreamSecrets(db, "keyed", null, await underV2("{}"));
    const v1Only = {
      ...env,
      MASTER_KEYS: JSON.stringify({
        "1": (JSON.parse(env.MASTER_KEYS as string) as Record<string, string>)["1"],
      }),
    } as Env;
    expect(
      await (await call("POST", "maintenance/rekey", undefined, { env: v1Only })).json(),
    ).toMatchObject({
      upstreams: 0,
      unrecoverable: 2,
      remaining: 0,
    });
    await updateUpstreamSecrets(
      db,
      "sealed",
      await sealSecret(testKeys(), new TextEncoder().encode("under-v1")),
      null,
    );
    await updateUpstreamSecrets(
      db,
      "keyed",
      null,
      await sealSecret(testKeys(), new TextEncoder().encode("{}")),
    );
    const v2 = { ...env, MASTER_KEY_ACTIVE: "2" } as Env;
    const rekeyed = await call("POST", "maintenance/rekey", undefined, { env: v2 });
    expect(rekeyed.status).toBe(200);
    const report = (await rekeyed.json()) as {
      signing_keys: string[];
      upstreams: number;
      unrecoverable: number;
      remaining: number;
    };
    expect(report.signing_keys.length).toBeGreaterThan(0);
    expect(report).toMatchObject({ upstreams: 2, unrecoverable: 0, remaining: 0 });
    expect(lastEvent("masterkey.rekeyed")).toMatchObject({ data: { target: "2", upstreams: 2 } });
    expect(
      sealedUnderVersion((await getUpstream(db, "sealed"))?.client_secret_enc as Uint8Array),
    ).toBe(2);
    for (const row of await listSigningKeys(db)) {
      if (row.private_jwk_enc !== null) expect(sealedUnderVersion(row.private_jwk_enc)).toBe(2);
    }
    // Nothing left; and a blob sealed under a version the secret no longer holds is reported, not touched.
    expect(
      await (await call("POST", "maintenance/rekey", undefined, { env: v2 })).json(),
    ).toMatchObject({ signing_keys: [], upstreams: 0 });
    const onlyV3 = {
      ...env,
      MASTER_KEYS: JSON.stringify({ "3": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" }),
      MASTER_KEY_ACTIVE: "3",
    } as Env;
    const lost = await admin(harness(clock), token, "maintenance/rekey", {
      method: "POST",
      env: onlyV3,
    });
    // The token itself was signed under a key this secret cannot open, so the guard refuses first.
    expect([401, 503]).toContain(lost.status);
    expect(
      (
        await call("POST", "maintenance/rekey", undefined, {
          env: { ...env, DB: failingD1(/FROM upstreams/) } as Env,
        })
      ).status,
    ).toBe(503);

    // Automatic rotation: with the signing key older than rotation_days and no next key, the purge creates one.
    await call("PATCH", "settings", { "keys.rotation_days": 1 });
    clock.advance(2 * 86_400);
    await relogin();
    const rotated = (await (await call("POST", "maintenance/purge")).json()) as {
      keys: { created: string | null };
    };
    expect(rotated.keys.created).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect((await keysOf()).map((k) => k.role).filter((r) => r === "next")).toHaveLength(1);
  });

  it("[TIO-DATA-027] the maintenance reindex walks users 100 per call in creation order, resumable by cursor, reporting users whose object is gone", async () => {
    const statements = [];
    for (let i = 0; i < 100; i++) {
      const id = `0192eeee-0000-7000-8000-${String(i).padStart(12, "0")}`;
      statements.push(
        insertUserStatement(
          db,
          { id, email: null, email_norm: null, email_verified: false, display_name: null },
          clock.now() - 86_400 * 400 + i,
        ),
      );
    }
    await db.batch(statements);
    await db.prepare("UPDATE users SET status = 'active' WHERE id LIKE '0192eeee-%'").run();
    const real = await userWithPasskey(clock);
    await db.prepare("DELETE FROM passkey_index WHERE user_id = ?").bind(real.profile.id).run();
    const first = await call("POST", "maintenance/reindex", {});
    expect(first.status).toBe(200);
    const page1 = (await first.json()) as {
      processed: number;
      failed: string[];
      next_cursor: string | null;
    };
    expect(page1.processed).toBe(100);
    expect(page1.failed).toHaveLength(100);
    expect(page1.next_cursor).toEqual(expect.any(String));
    expect(lastEvent("system.repair")).toMatchObject({
      data: { target: "reindex", processed: 100, failed: 100, more: true },
    });
    const second = (await (
      await call("POST", "maintenance/reindex", { cursor: page1.next_cursor })
    ).json()) as typeof page1;
    expect(second.processed).toBeGreaterThan(0);
    expect(second.processed).toBeLessThan(100);
    expect(second.next_cursor).toBeNull();
    expect(second.failed).not.toContain(real.profile.id);
    expect(await lookupCredential(db, real.credentialId)).toBe(real.profile.id);
    expect((await call("POST", "maintenance/reindex", { cursor: "bad" })).status).toBe(400);
    expect((await call("POST", "maintenance/reindex", { offset: 1 })).status).toBe(400);
    expect(
      (await call("POST", "maintenance/reindex", {}, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
  });
});

describe("administrative reads", () => {
  it("[TIO-ARCH-013] GET /admin/settings and /admin/clients/{id} read D1 directly while the protocol endpoints keep their isolate caches; stored settings that no longer validate are reported", async () => {
    await relogin();
    // A setting written behind the cache shows at once on the admin read.
    await writeSettings(db, { "registration.mode": "closed" }, "test", clock.now());
    const shown = (await (await call("GET", "settings")).json()) as Effective;
    expect(shown["registration.mode"]).toEqual({ value: "closed", source: "setting" });
    // A client disabled behind the cache shows at once, while the token endpoint still serves the cached record.
    const created = (await (
      await call("POST", "clients", {
        client_id: "cached-app",
        client_name: "Cached",
        redirect_uris: [],
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        scopes_allowed: ["admin"],
      })
    ).json()) as { client_secret: string };
    const basic = `Basic ${btoa(`cached-app:${created.client_secret}`)}`;
    const mint = () =>
      h.send("/token", {
        method: "POST",
        origin: null,
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic },
        body: "grant_type=client_credentials&scope=admin",
      });
    expect((await mint()).status).toBe(200);
    await db
      .prepare("UPDATE clients SET disabled_at = ? WHERE client_id = 'cached-app'")
      .bind(clock.now())
      .run();
    expect(
      ((await (await call("GET", "clients/cached-app")).json()) as Key & { disabled_at: number })
        .disabled_at,
    ).toBe(clock.now());
    expect((await mint()).status).toBe(200);
    clock.advance(60);
    expect((await mint()).status).toBe(401);
    // Settings that no longer validate as stored.
    await writeSettings(db, { "tokens.access_ttl": 5 }, "test", clock.now());
    const broken = await call("GET", "settings");
    expect(broken.status).toBe(500);
    expect(await broken.json()).toMatchObject({ error: "invalid_settings" });
    await writeSettings(
      db,
      { "tokens.access_ttl": null, "registration.mode": null },
      "test",
      clock.now(),
    );
  });
});
