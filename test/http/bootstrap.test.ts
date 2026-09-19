import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
  ADMIN_CLI_CLIENT_ID,
  ADMIN_CLI_POST_LOGOUT_URI,
  ADMIN_CLI_REDIRECT_URI,
} from "../../src/admin/bootstrap.ts";
import type { AuditEvent } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { getClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import {
  countMembers,
  deleteGroup,
  getGroupByName,
  insertGroup,
  listGroups,
  renameGroup,
} from "../../src/db/groups.ts";
import { listInvitations } from "../../src/db/invitations.ts";
import { readAllSettings, writeSettings } from "../../src/db/settings.ts";
import type { Env } from "../../src/env.ts";
import { createClient } from "../../src/oidc/clients.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { ensureAdminsGroup, setUserGroups } from "../../src/users/groups.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { env } from "../support/op.ts";
import { newUser, userWithPasskey } from "../support/passkeys.ts";
import { resetStorage } from "../support/reset.ts";
import { VirtualAuthenticator } from "../support/virtual-authenticator.ts";

const ISSUER = "https://auth.example.com";
const TOKEN = env.ADMIN_BOOTSTRAP_TOKEN as string;
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

interface BootstrapResponse {
  invitation: string;
  invitation_url: string | null;
  invitation_expires_at: number;
  client: Record<string, unknown>;
}

const bootstrap = (
  body: unknown,
  options: { token?: string | null; ip?: string; env?: Env } = {},
) => {
  const headers: Record<string, string> = {};
  if (options.token !== null) headers["authorization"] = `Bearer ${options.token ?? TOKEN}`;
  if (options.ip !== undefined) headers["cf-connecting-ip"] = options.ip;
  const init: Parameters<typeof h.send>[1] = { method: "POST", origin: null, headers, body };
  if (options.env) init.env = options.env;
  return h.send("/api/v1/admin/bootstrap", init);
};

describe("POST /api/v1/admin/bootstrap", () => {
  it("[TIO-ADMIN-011] [TIO-GEN-004] the bootstrap token is compared in constant time; a wrong or missing token is 401 and rate-limited per IP; the token works nowhere else", async () => {
    await resetStorage();
    for (const token of [null, "", "wrong", `${TOKEN}x`, TOKEN.slice(0, -1)]) {
      const res = await bootstrap({ email: "root@example.com" }, { token });
      expect(res.status, String(token)).toBe(401);
      expect(await res.json(), String(token)).toMatchObject({ error: "unauthorized" });
    }
    const basic = await h.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Basic ${btoa(`x:${TOKEN}`)}` },
      body: { email: "root@example.com" },
    });
    expect(basic.status).toBe(401);
    // Elsewhere the token is just an invalid bearer token.
    const elsewhere = await h.send("/userinfo", {
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(elsewhere.status).toBe(401);
    // Per IP.
    while ((await env.RL_IP.limit({ key: limitKey("ip_bootstrap", "198.51.100.5") })).success) {
      // exhaust
    }
    const limited = await bootstrap(
      { email: "root@example.com" },
      { token: "wrong", ip: "198.51.100.5" },
    );
    expect(limited.status).toBe(429);
    // Without a configured token nothing is accepted.
    const unconfigured = await bootstrap(
      { email: "root@example.com" },
      { env: { ...env, ADMIN_BOOTSTRAP_TOKEN: undefined } as unknown as Env },
    );
    expect(unconfigured.status).toBe(401);
  });

  it("[TIO-ADMIN-010] [TIO-DATA-012] bootstraps once: admins system group, admin-cli client, a register invitation into admins, bootstrapped_at set; later calls are 410", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    const bad = await bootstrap({ email: "not-an-email" });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "email_invalid" });
    expect((await bootstrap({})).status).toBe(400);
    expect((await bootstrap("{")).status).toBe(400);
    expect(await getGroupByName(db, "admins")).toMatchObject({ system: true });
    const res = await bootstrap({ email: "Root@Example.com", display_name: "Root" });
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as BootstrapResponse;
    expect(
      h.lines
        .filter((l) => l["msg"] === "audit")
        .map((l) => l["event"] as AuditEvent)
        .find((e) => e.type === "admin.bootstrap"),
    ).toMatchObject({
      outcome: "success",
      actor: { kind: "admin", id: null },
      client_id: ADMIN_CLI_CLIENT_ID,
      data: { client_id: ADMIN_CLI_CLIENT_ID },
    });
    expect(body.invitation).toMatch(/^tio_iv_/);
    expect(body.invitation_url).toBe(`${LOGIN_ORIGIN}/?invitation=${body.invitation}`);
    expect(body.invitation_expires_at).toBe(clock.now() + 7 * 86_400);
    expect(body.client).toMatchObject({
      client_id: ADMIN_CLI_CLIENT_ID,
      redirect_uris: [ADMIN_CLI_REDIRECT_URI],
      post_logout_redirect_uris: [ADMIN_CLI_POST_LOGOUT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      skip_consent: true,
    });
    expect((body.client["scopes_allowed"] as string[]).sort()).toEqual([
      "account",
      "admin",
      "email",
      "groups",
      "offline_access",
      "openid",
      "profile",
    ]);
    expect(body.client).not.toHaveProperty("client_secret_hash");
    expect(JSON.stringify(body)).not.toContain(TOKEN);
    const invitations = await listInvitations(db);
    expect(invitations).toHaveLength(1);
    expect(invitations[0]).toMatchObject({
      kind: "register",
      email: "Root@Example.com",
      email_verified: true,
      display_name: "Root",
      groups: ["admins"],
      created_by: "bootstrap",
    });
    expect((await readAllSettings(db))["bootstrapped_at"]).toBe(clock.now());
    expect((await getClient(db, ADMIN_CLI_CLIENT_ID))?.client_name).toBe("Tiny OIDC admin CLI");
    // Closed for good, even with a valid token.
    const again = await bootstrap({ email: "other@example.com" });
    expect(again.status).toBe(410);
    expect(await again.json()).toMatchObject({ error: "bootstrap_completed" });
    expect(await listInvitations(db)).toHaveLength(1);
  });

  it("[TIO-ADMIN-010] [TIO-SCOPE-002] the invited administrator registers, lands in admins, and receives the admin scope from admin-cli", async () => {
    // The invitation token is shown once, so the situation is rebuilt from scratch.
    await resetStorage();
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    const fresh = harness(clock);
    const res = await fresh.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "admin@example.com", display_name: "Admin" },
    });
    expect(res.status).toBe(201);
    const { invitation } = (await res.json()) as BootstrapResponse;
    const adminCli = (await getClient(db, ADMIN_CLI_CLIENT_ID)) as NonNullable<
      Awaited<ReturnType<typeof getClient>>
    >;
    const started = await fresh.start(adminCli, {
      redirect_uri: "http://127.0.0.1:43123/callback",
      scope: "openid email admin",
    });
    const options = await fresh.post(started, "register/options", { invitation });
    expect(options.status).toBe(200);
    const { publicKey } = (await options.json()) as {
      publicKey: PublicKeyCredentialCreationOptionsJSON;
    };
    const authenticator = new VirtualAuthenticator();
    const verify = await fresh.post(started, "register/verify", {
      response: await authenticator.register(publicKey, LOGIN_ORIGIN),
      name: "Admin key",
    });
    expect(await verify.json()).toMatchObject({ status: "ready" });
    const complete = await fresh.send(`/interactions/${started.id}/complete`, {
      origin: null,
      cookie: started.cookie,
    });
    const location = new URL(complete.headers.get("location") as string);
    expect(location.origin).toBe("http://127.0.0.1:43123");
    const code = location.searchParams.get("code") as string;
    const token = await fresh.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: ADMIN_CLI_CLIENT_ID,
        code,
        redirect_uri: "http://127.0.0.1:43123/callback",
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      }).toString(),
    });
    expect(token.status).toBe(200);
    const tokens = (await token.json()) as { access_token: string; scope: string };
    expect(tokens.scope).toBe("openid email admin");
    const jwks = createLocalJWKSet(
      await (await fresh.send("/.well-known/jwks.json", { origin: null })).json(),
    );
    const { payload } = await jwtVerify(tokens.access_token, jwks, {
      issuer: ISSUER,
      audience: ISSUER,
      currentDate: clock.nowDate(),
    });
    expect(payload["aud"]).toEqual([ADMIN_CLI_CLIENT_ID, ISSUER]);
    // The administrator is a member of admins in both stores; bootstrap is closed.
    const admins = await getGroupByName(db, "admins");
    expect(await countMembers(db, admins?.id as string)).toBe(1);
    expect((await listInvitations(db))[0]?.used_at).toBe(clock.now());
    const closed = await fresh.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "x@example.com" },
    });
    expect(closed.status).toBe(410);
  });

  it("resumes after a partial earlier attempt and fails closed when storage is down", async () => {
    await resetStorage();
    await writeSettings(db, { login_url: null, login_origins: null }, "test", clock.now());
    clock.advance(61);
    const fresh = harness(clock);
    // A leftover admin-cli client from an attempt that died before bootstrapped_at was set.
    const leftover = await createClient(
      db,
      {
        client_id: ADMIN_CLI_CLIENT_ID,
        client_name: "Leftover",
        redirect_uris: [ADMIN_CLI_REDIRECT_URI],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scopes_allowed: ["openid"],
      },
      { issuer: ISSUER, actorHasAdmin: true, existingGroups: new Set() },
      clock.now(),
    );
    expect(leftover.ok).toBe(true);
    const res = await fresh.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "admin@example.com" },
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as BootstrapResponse;
    expect(body.invitation_url).toBeNull();
    expect(body.client["client_name"]).toBe("Leftover");
    // A cached miss for admin-cli in the isolate while the row exists: fail closed.
    await resetStorage();
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    const stale = harness(clock);
    const miss = await stale.send(`/authorize?client_id=${ADMIN_CLI_CLIENT_ID}`, { origin: null });
    expect(miss.headers.get("location")).toContain("unknown");
    await createClient(
      db,
      {
        client_id: ADMIN_CLI_CLIENT_ID,
        client_name: "Leftover",
        redirect_uris: [ADMIN_CLI_REDIRECT_URI],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scopes_allowed: ["openid"],
      },
      { issuer: ISSUER, actorHasAdmin: true, existingGroups: new Set() },
      clock.now(),
    );
    const staleRes = await stale.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "admin@example.com" },
    });
    expect(staleRes.status).toBe(503);
    // Members already in admins (no bootstrapped_at): closed as well.
    await resetStorage();
    const admins = await ensureAdminsGroup(db, clock);
    const member = await newUser(clock, { groups: ["admins"] });
    expect(member.groups).toEqual(["admins"]);
    expect(await countMembers(db, admins.id)).toBe(1);
    const other = harness(clock);
    const withMember = await other.send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "admin@example.com" },
    });
    expect(withMember.status).toBe(410);
    // Storage down.
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const down = await harness(clock).send("/api/v1/admin/bootstrap", {
      method: "POST",
      origin: null,
      headers: { authorization: `Bearer ${TOKEN}` },
      body: { email: "admin@example.com" },
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(down.status).toBe(503);
  });
});

describe("groups", () => {
  it("[TIO-DATA-011] [TIO-DATA-012] groups are flat rows; admins is system-defined, cannot be renamed or deleted, and ensureAdminsGroup is idempotent", async () => {
    await resetStorage();
    const admins = await ensureAdminsGroup(db, clock);
    expect(admins).toMatchObject({ name: "admins", system: true });
    expect((await ensureAdminsGroup(db, clock)).id).toBe(admins.id);
    expect(await renameGroup(db, admins.id, "root", clock.now())).toBe("system_group");
    expect(await deleteGroup(db, admins.id)).toBe("system_group");
    const staffId = new UuidV7(clock).next();
    await insertGroup(
      db,
      { id: staffId, name: "staff", description: "Staff", system: false },
      clock.now(),
    );
    expect(await renameGroup(db, staffId, "crew", clock.now())).toBe("changed");
    expect((await listGroups(db)).map((g) => g.name)).toEqual(["admins", "crew"]);
    expect(await renameGroup(db, "nope", "x", clock.now())).toBe("not_found");
    expect(await deleteGroup(db, "nope")).toBe("not_found");
    // Flat: the schema has no parent column and memberships link users to groups only.
    const columns = await db.prepare("PRAGMA table_info(groups)").all<{ name: string }>();
    expect(columns.results.map((c) => c.name)).toEqual([
      "id",
      "name",
      "description",
      "system",
      "created_at",
      "updated_at",
    ]);
    expect(await deleteGroup(db, staffId)).toBe("changed");
  });

  it("[TIO-DATA-013] a membership change writes the UserDO first and mirrors D1; a failed mirror write is reported as partial_failure", async () => {
    const admins = await ensureAdminsGroup(db, clock);
    const staffId = new UuidV7(clock).next();
    await insertGroup(
      db,
      { id: staffId, name: "staff", description: null, system: false },
      clock.now(),
    );
    const user = await userWithPasskey(clock);
    const changed = await setUserGroups(
      env,
      db,
      user.profile.id,
      ["staff", "admins", "staff"],
      clock.now(),
    );
    expect(changed.ok && changed.profile.groups).toEqual(["admins", "staff"]);
    expect(await countMembers(db, admins.id)).toBe(1);
    expect(await countMembers(db, staffId)).toBe(1);
    const profile = await user.stub.getProfile();
    expect(profile.ok && profile.profile.groups).toEqual(["admins", "staff"]);
    const cleared = await setUserGroups(env, db, user.profile.id, [], clock.now());
    expect(cleared.ok).toBe(true);
    expect(await countMembers(db, admins.id)).toBe(0);
    expect(await setUserGroups(env, db, user.profile.id, ["ghosts"], clock.now())).toEqual({
      ok: false,
      error: "group_unknown",
    });
    expect(await setUserGroups(env, db, new UuidV7(clock).next(), ["staff"], clock.now())).toEqual({
      ok: false,
      error: "user_not_available",
    });
    const flaky = Db.from({
      prepare: (sql: string) => env.DB.prepare(sql),
      batch: async () => {
        throw new Error("D1 down");
      },
    } as unknown as D1Database);
    const partial = await setUserGroups(env, flaky, user.profile.id, ["staff"], clock.now());
    expect(partial).toMatchObject({
      ok: false,
      error: "partial_failure",
      profile: { groups: ["staff"] },
    });
    expect(await countMembers(db, staffId)).toBe(0);
  });
});
