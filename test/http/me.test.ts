import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { signJwt } from "../../src/crypto/jwt.ts";
import { KeyStore } from "../../src/crypto/keystore.ts";
import { Db } from "../../src/db/db.ts";
import { insertIdentityStatement, lookupIdentity } from "../../src/db/identities.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { claimCredential, lookupCredential } from "../../src/db/users.ts";
import type { Env } from "../../src/env.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { adminSettings, adminUser, serviceAdmin } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { registerUpstream } from "../support/federation.ts";
import { mountOrigin } from "../support/fetch-allowlist.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import {
  brokenD1,
  brokenDoFor,
  failingD1,
  interceptDo,
  sabotageDo,
  throwingDo,
  zeroChangesD1,
} from "./faults.ts";

// The Self-service API (spec §8) end to end: a person signs in at a
// first-party app, receives a token with scope `account`, and manages their
// own profile, passkeys, sessions, identities and grants with it.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const RP = "https://rp.example.com";
const ISSUER = "https://auth.example.com";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const received: string[] = [];
mountOrigin(RP, async (request) => {
  received.push(new URLSearchParams(await request.text()).get("logout_token") ?? "");
  return new Response(null, { status: 200 });
});

let app: Client;

interface Session {
  user: PasskeyUser;
  cookie: string;
  access_token: string;
  refresh_token: string | undefined;
  sid: string | null;
}

const events = (type: string): AuditEvent[] =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type);

/** A passkey login of `user` at `app`: the session cookie and the tokens. */
async function login(
  user: PasskeyUser,
  options: { scope?: string; sessionCookie?: string; client?: Client } = {},
): Promise<Session> {
  const client = options.client ?? app;
  const started = await h.start(
    client,
    {
      scope: options.scope ?? "openid email account",
      ...(options.sessionCookie === undefined ? {} : { prompt: "login" }),
    },
    options.sessionCookie,
  );
  const { publicKey } = (await (await h.post(started, "passkey/options", {})).json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const verified = await h.post(started, "passkey/verify", {
    response: await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
  });
  expect(verified.status).toBe(200);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: [started.cookie, options.sessionCookie].filter(Boolean).join("; "),
  });
  expect(complete.status).toBe(303);
  const setCookie = complete.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`) && !c.includes("Max-Age=0"));
  const cookie = setCookie
    ? setCookie.slice(0, setCookie.indexOf(";"))
    : (options.sessionCookie as string);
  const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
  const tokens = await h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: client.client_id,
      code: code as string,
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });
  expect(tokens.status).toBe(200);
  const body = (await tokens.json()) as { access_token: string; refresh_token?: string };
  const sid = decodeJwt(body.access_token)["sid"];
  return {
    user,
    cookie,
    access_token: body.access_token,
    refresh_token: body.refresh_token,
    sid: typeof sid === "string" ? sid : null,
  };
}

/** A request to the Self-service API with a bearer token (null sends none). */
const me = (
  token: string | null,
  path = "",
  options: { method?: string; body?: unknown; headers?: Record<string, string>; env?: Env } = {},
) =>
  h.send(`/api/v1/me${path}`, {
    method: options.method ?? "GET",
    origin: null,
    headers: {
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...(options.body === undefined ? {} : { body: options.body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });

type CreationOptions = Parameters<PasskeyUser["authenticator"]["register"]>[0];

/** Registration options for the person, from the API. */
async function options(session: Session): Promise<CreationOptions> {
  const res = await me(session.access_token, "/passkeys/options", { method: "POST" });
  expect(res.status).toBe(200);
  return ((await res.json()) as { publicKey: CreationOptions }).publicKey;
}

describe("the guard", () => {
  it("[TIO-ME-001] needs a user token with scope account of a non-disabled user, and is rate limited per IP", async () => {
    await adminSettings(h);
    app = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "account", "offline_access"],
        backchannel_logout_uri: `${RP}/backchannel`,
      })
    ).client;
    const none = await me(null);
    expect(none.status).toBe(401);
    expect(none.headers.get("WWW-Authenticate")).toBe("Bearer");
    expect((await me(null, "", { headers: { authorization: "Basic abc" } })).status).toBe(401);
    const garbage = await me("not-a-token");
    expect(garbage.status).toBe(401);
    expect(garbage.headers.get("WWW-Authenticate")).toBe('Bearer error="invalid_token"');
    expect(await garbage.json()).toMatchObject({ error: "invalid_token" });
    const alice = await userWithPasskey(clock, { email: "alice@example.com" });
    // Without the account scope the token's audience does not even name the OP.
    const plain = await login(alice, { scope: "openid email" });
    expect((await me(plain.access_token)).status).toBe(401);
    // An admin token names the OP but lacks the scope.
    const operator = await adminUser(h);
    const scoped = await me(operator.access_token);
    expect(scoped.status).toBe(403);
    expect(scoped.headers.get("WWW-Authenticate")).toBe('Bearer error="insufficient_scope"');
    expect(await scoped.json()).toMatchObject({ error: "insufficient_scope" });
    // A service client's token names nobody: /token never mints one with the scope, and a
    // token that claims it is refused all the same.
    const service = await serviceAdmin(h);
    const keys = await new KeyStore(clock).get(db, testKeys());
    const forged = await signJwt(keys, "at+jwt", {
      iss: ISSUER,
      sub: service.client.client_id,
      aud: ISSUER,
      exp: clock.now() + 60,
      iat: clock.now(),
      jti: "forged-service-token",
      client_id: service.client.client_id,
      scope: "account",
    });
    expect((await me(forged)).status).toBe(401);
    // Disabled since the token was issued.
    const session = await login(alice);
    expect((await me(session.access_token)).status).toBe(200);
    await alice.stub.setDisabled(clock.now(), clock.now());
    expect((await me(session.access_token)).status).toBe(401);
    await alice.stub.setDisabled(null, clock.now());
    // Storage trouble.
    expect(
      (await me(session.access_token, "", { env: brokenDoFor(alice.profile.id) })).status,
    ).toBe(503);
    const fresh = harness(clock);
    const noKeys = await fresh.send("/api/v1/me", {
      origin: null,
      headers: { authorization: `Bearer ${session.access_token}` },
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(noKeys.status).toBe(503);
    // Per IP.
    const ip = "203.0.113.42";
    while ((await env.RL_IP.limit({ key: limitKey("ip_me", ip) })).success) {
      // keep counting
    }
    const throttled = await me(session.access_token, "", { headers: { "cf-connecting-ip": ip } });
    expect(throttled.status).toBe(429);
    // The path without a trailing segment and one with a method the table lacks.
    expect((await me(session.access_token, "/nowhere")).status).toBe(404);
  });
});

describe("profile", () => {
  it("[TIO-ME-002] GET returns the profile; PATCH changes the display name and, only when allowed, the email (left unverified), audited as the person from the app", async () => {
    const bob = await userWithPasskey(clock, {
      email: "bob@example.com",
      email_verified: true,
      display_name: "Bob",
    });
    const session = await login(bob);
    const profile = await me(session.access_token);
    expect(await profile.json()).toEqual({
      id: bob.profile.id,
      email: "bob@example.com",
      email_verified: true,
      display_name: "Bob",
      groups: [],
      created_at: bob.profile.created_at,
      updated_at: expect.any(Number),
    });
    const patch = (body: unknown, extra: { env?: Env } = {}) =>
      me(session.access_token, "", { method: "PATCH", body, ...extra });
    expect((await patch({})).status).toBe(400);
    expect((await patch({ groups: ["admins"] })).status).toBe(400);
    expect((await patch({ display_name: "" })).status).toBe(400);
    const renamed = await patch({ display_name: "Robert" });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toMatchObject({ display_name: "Robert", email_verified: true });
    expect(events("user.updated").at(-1)).toMatchObject({
      actor: { kind: "user", id: bob.profile.id },
      user_id: bob.profile.id,
      client_id: app.client_id,
      outcome: "success",
      data: { fields: ["display_name"] },
    });
    // Email changes are off by default.
    const refused = await patch({ email: "robert@example.com" });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: "email_change_not_allowed" });
    await writeSettings(db, { "me.allow_email_change": true }, "test", clock.now());
    clock.advance(61);
    expect((await patch({ email: "not an email" })).status).toBe(400);
    const changed = await patch({ email: "robert@example.com" });
    expect(changed.status).toBe(200);
    expect(await changed.json()).toMatchObject({
      email: "robert@example.com",
      email_verified: false,
    });
    const row = await db
      .prepare("SELECT email, email_verified FROM users WHERE id = ?")
      .bind(bob.profile.id)
      .first<{ email: string; email_verified: number }>();
    expect(row).toEqual({ email: "robert@example.com", email_verified: 0 });
    // The object changes and the mirror does not: reported, not refused.
    const partial = await patch(
      { display_name: "Rob" },
      { env: { ...env, DB: failingD1(/UPDATE users/) } as Env },
    );
    expect(partial.status).toBe(200);
    expect(events("user.updated").at(-1)).toMatchObject({
      outcome: "failure",
      reason: "partial_failure",
    });
    // A vanished object, before or during the update; settings nobody can read.
    expect(
      (await patch({ display_name: "x" }, { env: sabotageDo(bob.profile.id, "updateProfile") }))
        .status,
    ).toBe(503);
    const gone = await userWithPasskey(clock);
    const goneToken = (await login(gone)).access_token;
    expect(
      (
        await me(goneToken, "", {
          method: "PATCH",
          body: { display_name: "x" },
          env: throwingDo(gone.profile.id, "updateProfile"),
        })
      ).status,
    ).toBe(503);
    expect(
      (
        await me(goneToken, "", {
          method: "PATCH",
          body: { display_name: "x" },
          env: sabotageDo(gone.profile.id, "getProfile", 2),
        })
      ).status,
    ).toBe(503);
    // Settings nobody can read (an app with nothing cached; the sabotaged users above are gone).
    const blind = harness(clock);
    const intact = (await login(await userWithPasskey(clock))).access_token;
    const noSettings = { ...env, DB: failingD1(/FROM settings/) } as Env;
    for (const [method, path, body] of [
      ["PATCH", "", { display_name: "x" }],
      ["POST", "/passkeys/options", undefined],
      ["POST", "/passkeys", { response: {} }],
    ] as const) {
      const res = await blind.send(`/api/v1/me${path}`, {
        method,
        origin: null,
        headers: { authorization: `Bearer ${intact}` },
        ...(body === undefined ? {} : { body }),
        env: noSettings,
      });
      expect(res.status, `${method} ${path}`).toBe(503);
    }
    await writeSettings(db, { "me.allow_email_change": null }, "test", clock.now());
    clock.advance(61);
  });
});

describe("passkeys", () => {
  it("[TIO-ME-003] [TIO-PK-040] [TIO-PK-041] registration needs a recent authentication and a single-use challenge on the person's object; names are 1-64 characters; the last passkey stays unless an identity is linked", async () => {
    const carol = await userWithPasskey(clock, { email: "carol@example.com" });
    const session = await login(carol);
    const listed = await me(session.access_token, "/passkeys");
    expect(listed.status).toBe(200);
    const { items } = (await listed.json()) as { items: Record<string, unknown>[] };
    expect(items).toHaveLength(1);
    expect(items[0]).not.toHaveProperty("public_key");
    expect(items[0]).toMatchObject({
      credential_id: carol.credentialId,
      created_via: "interaction",
    });
    // Options exclude the existing credential; the challenge lives on the object, keyed by sid.
    const creation = await options(session);
    expect(creation.excludeCredentials?.map((c) => c.id)).toEqual([carol.credentialId]);
    expect(creation.user).toMatchObject({ name: "carol@example.com", displayName: "Alice" });
    const register = (body: unknown, token = session.access_token) =>
      me(token, "/passkeys", { method: "POST", body });
    expect((await register({ response: {}, name: 5 })).status).toBe(400);
    expect((await register({ response: {}, name: " " })).status).toBe(400);
    // Wrong origin: refused, and the challenge is spent.
    const elsewhere = await carol.authenticator.register(creation, "https://evil.example");
    const wrongOrigin = await register({ response: elsewhere });
    expect(wrongOrigin.status).toBe(401);
    expect(await wrongOrigin.json()).toMatchObject({ error: "passkey_verification_failed" });
    const right = await carol.authenticator.register(creation, LOGIN_ORIGIN);
    expect((await register({ response: right })).status).toBe(401);
    // A fresh challenge, then a credential already known elsewhere, then success.
    const second = await options(session);
    const claimed = await carol.authenticator.register(second, LOGIN_ORIGIN);
    const other = await userWithPasskey(clock);
    await claimCredential(db, claimed.id, other.profile.id, clock.now());
    expect((await register({ response: claimed })).status).toBe(401);
    const third = await options(session);
    const good = await carol.authenticator.register(third, LOGIN_ORIGIN);
    const registered = await register({ response: good, name: "  Laptop  " });
    expect(registered.status).toBe(201);
    const passkey = (await registered.json()) as { id: string; name: string; created_via: string };
    expect(passkey).toMatchObject({ name: "Laptop", created_via: "me" });
    expect(passkey).not.toHaveProperty("public_key");
    expect(await lookupCredential(db, good.id)).toBe(carol.profile.id);
    expect(events("passkey.registered").at(-1)).toMatchObject({
      actor: { kind: "user", id: carol.profile.id },
      client_id: app.client_id,
      data: { passkey_id: passkey.id },
    });
    // Only the latest challenge counts, and it expires.
    await options(session);
    const stale = await carol.authenticator.register(await options(session), LOGIN_ORIGIN);
    const before = await options(session);
    expect((await register({ response: stale })).status).toBe(401);
    clock.advance(301);
    expect(
      (await register({ response: await carol.authenticator.register(before, LOGIN_ORIGIN) }))
        .status,
    ).toBe(401);
    // A non-discoverable credential is 400.
    const resident = await carol.authenticator.register(await options(session), LOGIN_ORIGIN, {
      residentKey: false,
    });
    const notDiscoverable = await register({ response: resident });
    expect(notDiscoverable.status).toBe(400);
    expect(await notDiscoverable.json()).toMatchObject({ error: "passkey_not_discoverable" });
    // Rename: 1-64 characters after trimming, verbatim; unknown ids are 404.
    const rename = (id: string, name: unknown) =>
      me(session.access_token, `/passkeys/${id}`, { method: "PATCH", body: { name } });
    expect((await rename(passkey.id, "")).status).toBe(400);
    expect(
      (await me(session.access_token, `/passkeys/${passkey.id}`, { method: "PATCH", body: {} }))
        .status,
    ).toBe(400);
    expect((await rename(passkey.id, "x".repeat(65))).status).toBe(400);
    expect((await rename(passkey.id, " Work laptop ")).status).toBe(204);
    expect((await rename("00000000-0000-7000-8000-000000000000", "x")).status).toBe(404);
    const after = (await (await me(session.access_token, "/passkeys")).json()) as {
      items: { id: string; name: string | null }[];
    };
    expect(after.items.map((p) => p.name).sort()).toEqual(["Work laptop", null].sort());
    expect(events("passkey.renamed").at(-1)).toMatchObject({ data: { passkey_id: passkey.id } });
    // The limit.
    await writeSettings(db, { "passkeys.max_per_user": 2 }, "test", clock.now());
    clock.advance(61);
    const full = await register({
      response: await carol.authenticator.register(await options(session), LOGIN_ORIGIN),
    });
    expect(full.status).toBe(403);
    expect(await full.json()).toMatchObject({ error: "passkey_limit_reached" });
    await writeSettings(db, { "passkeys.max_per_user": null }, "test", clock.now());
    clock.advance(61);
    // Deletion: the second goes, the last stays until an identity is linked.
    const remove = (id: string) =>
      me(session.access_token, `/passkeys/${id}`, { method: "DELETE" });
    expect((await remove("00000000-0000-7000-8000-000000000000")).status).toBe(404);
    expect((await remove(passkey.id)).status).toBe(204);
    expect(await lookupCredential(db, good.id)).toBeNull();
    expect(events("passkey.deleted").at(-1)).toMatchObject({ data: { passkey_id: passkey.id } });
    const first = items[0]?.["id"] as string;
    const last = await remove(first);
    expect(last.status).toBe(409);
    expect(await last.json()).toMatchObject({ error: "last_login_method" });
    await registerUpstream(clock);
    await insertIdentityStatement(
      db,
      "https://idp.example.com",
      "carol-at-idp",
      carol.profile.id,
      clock.now(),
    ).run();
    const linked = await carol.stub.addIdentity(
      {
        id: "00000000-0000-7000-8000-00000000c001",
        issuer: "https://idp.example.com",
        subject: "carol-at-idp",
        email: "carol@example.com",
        email_verified: true,
        name: "Carol",
      },
      clock.now(),
    );
    expect(linked.ok).toBe(true);
    expect((await remove(first)).status).toBe(204);
    // Reauthentication: past me.passkey_add_max_auth_age the token no longer allows adding.
    await writeSettings(db, { "me.passkey_add_max_auth_age": 60 }, "test", clock.now());
    clock.advance(61);
    const tooOld = await me(session.access_token, "/passkeys/options", { method: "POST" });
    expect(tooOld.status).toBe(403);
    expect(await tooOld.json()).toMatchObject({ error: "reauthentication_required" });
    const tooOldRegister = await register({ response: {} });
    expect(await tooOldRegister.json()).toMatchObject({ error: "reauthentication_required" });
    await writeSettings(db, { "me.passkey_add_max_auth_age": null }, "test", clock.now());
    clock.advance(61);
  });

  it("[TIO-ME-003] an offline token (no sid) keys its challenge by the token; a session that vanished is 503", async () => {
    const dan = await userWithPasskey(clock, { email: "dan@example.com", display_name: null });
    const offline = await login(dan, { scope: "openid email account offline_access" });
    expect(offline.sid).toBeNull();
    const creation = await options(offline);
    // Without a display name the authenticator shows the user name.
    expect(creation.user.displayName).toBe("dan@example.com");
    const res = await me(offline.access_token, "/passkeys", {
      method: "POST",
      body: { response: await dan.authenticator.register(creation, LOGIN_ORIGIN) },
    });
    expect(res.status).toBe(201);
    // Storage failures along the way.
    for (const [method, path, init] of [
      ["listPasskeys", "/passkeys", { method: "GET" }],
      ["putChallenge", "/passkeys/options", { method: "POST" }],
      ["takeChallenge", "/passkeys", { method: "POST", body: { response: {} } }],
      [
        "renamePasskey",
        "/passkeys/00000000-0000-7000-8000-000000000000",
        { method: "PATCH", body: { name: "x" } },
      ],
      ["listPasskeys", "/passkeys/00000000-0000-7000-8000-000000000000", { method: "DELETE" }],
    ] as const) {
      const lost = await me(offline.access_token, path, {
        ...init,
        env: throwingDo(dan.profile.id, method),
      });
      expect(lost.status, `${method} ${path}`).toBe(503);
    }
    // A credential claimed by another user between the object and the index: refused.
    const raced = await me(offline.access_token, "/passkeys", {
      method: "POST",
      body: {
        response: await dan.authenticator.register(await options(offline), LOGIN_ORIGIN),
      },
      env: { ...env, DB: zeroChangesD1(/INSERT OR IGNORE INTO passkey_index/) } as Env,
    });
    expect(raced.status).toBe(401);
    // Objects that vanish between the guard and the call.
    for (const [method, path, init] of [
      ["listPasskeys", "/passkeys", { method: "GET" }],
      ["listPasskeys", "/passkeys/options", { method: "POST" }],
      ["putChallenge", "/passkeys/options", { method: "POST" }],
      ["takeChallenge", "/passkeys", { method: "POST", body: { response: {} } }],
      [
        "renamePasskey",
        "/passkeys/00000000-0000-7000-8000-000000000000",
        { method: "PATCH", body: { name: "x" } },
      ],
      ["listPasskeys", "/passkeys/00000000-0000-7000-8000-000000000000", { method: "DELETE" }],
    ] as const) {
      const victim = await userWithPasskey(clock);
      const token = (await login(victim)).access_token;
      const vanished = await me(token, path, {
        ...init,
        env: sabotageDo(victim.profile.id, method),
      });
      expect(vanished.status, `${method} ${path}`).toBe(503);
    }
    // The object refuses the registration itself, and vanishes during a removal.
    const short = await userWithPasskey(clock);
    const shortSession = await login(short);
    const refused = await me(shortSession.access_token, "/passkeys", {
      method: "POST",
      body: {
        response: await short.authenticator.register(await options(shortSession), LOGIN_ORIGIN),
      },
      env: sabotageDo(short.profile.id, "addPasskey"),
    });
    expect(refused.status).toBe(503);
    const vanishing = await userWithPasskey(clock);
    const vanishingSession = await login(vanishing);
    const held = (await (await me(vanishingSession.access_token, "/passkeys")).json()) as {
      items: { id: string }[];
    };
    const heldId = held.items[0]?.id as string;
    expect(
      (
        await me(vanishingSession.access_token, `/passkeys/${heldId}`, {
          method: "DELETE",
          env: sabotageDo(vanishing.profile.id, "removePasskey"),
        })
      ).status,
    ).toBe(503);
    // Removed by someone else between the listing and the removal.
    const racing = await userWithPasskey(clock);
    const racingSession = await login(racing);
    const second = await me(racingSession.access_token, "/passkeys", {
      method: "POST",
      body: {
        response: await racing.authenticator.register(await options(racingSession), LOGIN_ORIGIN),
      },
    });
    const secondId = ((await second.json()) as { id: string }).id;
    expect(
      (
        await me(racingSession.access_token, `/passkeys/${secondId}`, {
          method: "DELETE",
          env: interceptDo(racing.profile.id, "removePasskey", async (stub) => {
            await stub.removePasskey(secondId);
          }),
        })
      ).status,
    ).toBe(404);
  });
});

describe("sessions, identities and grants", () => {
  it("[TIO-LOGOUT-013] [TIO-CONSENT-004] sessions are listed with the current one flagged and ended one by one or all at once with back-channel logout; identities never show the subject and unlink under the last-method rule; grants revoke with their families", async () => {
    const erin = await userWithPasskey(clock, { email: "erin@example.com" });
    const phone = await login(erin);
    const laptop = await login(erin, { scope: "openid email account offline_access" });
    const listed = (await (await me(phone.access_token, "/sessions")).json()) as {
      items: { sid: string; current: boolean; clients: string[]; amr: string[] }[];
    };
    expect(listed.items).toHaveLength(2);
    expect(listed.items.find((s) => s.sid === phone.sid)).toMatchObject({
      current: true,
      clients: [app.client_id],
      amr: expect.arrayContaining(["user"]),
      country: null,
      ua_family: null,
    });
    const laptopSid = listed.items.find((s) => !s.current)?.sid as string;
    received.length = 0;
    expect(
      (await me(phone.access_token, `/sessions/${laptopSid}`, { method: "DELETE" })).status,
    ).toBe(204);
    expect(received.map((t) => decodeJwt(t)["sid"])).toEqual([laptopSid]);
    expect(
      (await me(phone.access_token, `/sessions/${laptopSid}`, { method: "DELETE" })).status,
    ).toBe(404);
    expect(events("session.revoked").at(-1)).toMatchObject({
      actor: { kind: "user", id: erin.profile.id },
      client_id: app.client_id,
      sid: laptopSid,
      reason: "self",
    });
    // The offline family of the laptop's token survives its session; a session family does not.
    expect(laptop.refresh_token).toBeDefined();
    // Every other session: two more logins, then all but the current.
    await login(erin);
    await login(erin);
    received.length = 0;
    const others = await me(phone.access_token, "/sessions", { method: "DELETE" });
    expect(await others.json()).toEqual({ revoked: 2 });
    expect(received).toHaveLength(2);
    const remaining = (await (await me(phone.access_token, "/sessions")).json()) as {
      items: { sid: string }[];
    };
    expect(remaining.items.map((s) => s.sid)).toEqual([phone.sid]);
    const all = await me(phone.access_token, "/sessions?include_current=true", {
      method: "DELETE",
    });
    expect(await all.json()).toEqual({ revoked: 1 });
    expect((await (await me(phone.access_token, "/sessions")).json()) as unknown).toEqual({
      items: [],
    });
    // Identities.
    const upstreamIssuer = "https://idp.example.com";
    await insertIdentityStatement(
      db,
      upstreamIssuer,
      "erin-at-idp",
      erin.profile.id,
      clock.now(),
    ).run();
    await erin.stub.addIdentity(
      {
        id: "00000000-0000-7000-8000-00000000e001",
        issuer: upstreamIssuer,
        subject: "erin-at-idp",
        email: "erin@idp.example",
        email_verified: true,
        name: "Erin",
      },
      clock.now(),
    );
    await erin.stub.addIdentity(
      {
        id: "00000000-0000-7000-8000-00000000e002",
        issuer: "https://unknown.example.net",
        subject: "erin-elsewhere",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    const identities = await me(phone.access_token, "/identities");
    expect(await identities.json()).toEqual({
      items: [
        {
          id: "00000000-0000-7000-8000-00000000e001",
          upstream: "idp",
          issuer: upstreamIssuer,
          email: "erin@idp.example",
          name: "Erin",
          created_at: clock.now(),
          last_login_at: null,
        },
        {
          id: "00000000-0000-7000-8000-00000000e002",
          upstream: null,
          issuer: "https://unknown.example.net",
          email: null,
          name: null,
          created_at: clock.now(),
          last_login_at: null,
        },
      ],
    });
    expect(
      JSON.stringify(await (await me(phone.access_token, "/identities")).json()),
    ).not.toContain("erin-at-idp");
    const unlink = (id: string) =>
      me(phone.access_token, `/identities/${id}`, { method: "DELETE" });
    expect((await unlink("00000000-0000-7000-8000-00000000e009")).status).toBe(404);
    expect((await unlink("00000000-0000-7000-8000-00000000e001")).status).toBe(204);
    expect(await lookupIdentity(db, upstreamIssuer, "erin-at-idp")).toBeNull();
    expect(events("identity.unlinked").at(-1)).toMatchObject({
      actor: { kind: "user", id: erin.profile.id },
      upstream: upstreamIssuer,
    });
    // With the passkey gone, the last identity stays.
    const passkeys = await erin.stub.listPasskeys();
    expect(
      passkeys.ok &&
        (await erin.stub.removePasskey((passkeys.ok ? passkeys.passkeys[0]?.id : "") as string)).ok,
    ).toBe(true);
    const lastIdentity = await unlink("00000000-0000-7000-8000-00000000e002");
    expect(lastIdentity.status).toBe(409);
    expect(await lastIdentity.json()).toMatchObject({ error: "last_login_method" });
    // Grants: the consent recorded for the app, revoked with its families.
    const fresh = await userWithPasskey(clock, { email: "frank@example.com" });
    const consenting = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        offline_access: true,
        scopes_allowed: ["openid", "email", "account", "offline_access"],
      })
    ).client;
    const started = await h.start(consenting, { scope: "openid email account offline_access" });
    const { publicKey } = (await (await h.post(started, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    expect(
      await (
        await h.post(started, "passkey/verify", {
          response: await fresh.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
        })
      ).json(),
    ).toMatchObject({ status: "consent_required" });
    expect(
      (
        await h.post(started, "consent", {
          decision: "grant",
          scopes: ["openid", "email", "account", "offline_access"],
        })
      ).status,
    ).toBe(200);
    const complete = await h.send(`/interactions/${started.id}/complete`, {
      origin: null,
      cookie: started.cookie,
    });
    const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
    const tokens = (await (
      await h.send("/token", {
        method: "POST",
        origin: null,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: consenting.client_id,
          code: code as string,
          redirect_uri: RP_REDIRECT,
          code_verifier: VERIFIER,
        }).toString(),
      })
    ).json()) as { access_token: string; refresh_token: string };
    const grants = await me(tokens.access_token, "/grants");
    expect(await grants.json()).toEqual({
      items: [
        {
          client_id: consenting.client_id,
          scopes: ["account", "email", "offline_access", "openid"],
          granted_at: clock.now(),
          updated_at: clock.now(),
        },
      ],
    });
    expect((await me(tokens.access_token, "/grants/nobody", { method: "DELETE" })).status).toBe(
      404,
    );
    expect(
      (await me(tokens.access_token, `/grants/${consenting.client_id}`, { method: "DELETE" }))
        .status,
    ).toBe(204);
    expect(events("consent.revoked").at(-1)).toMatchObject({
      actor: { kind: "user", id: fresh.profile.id },
      client_id: consenting.client_id,
      data: { grant_client_id: consenting.client_id },
    });
    expect(await (await me(tokens.access_token, "/grants")).json()).toEqual({ items: [] });
    const refreshed = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: consenting.client_id,
        refresh_token: tokens.refresh_token,
      }).toString(),
    });
    expect(refreshed.status).toBe(400);
    expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    // A grant whose client is gone is not listed.
    await fresh.stub.grantConsent(
      { client_id: "phantom", created_at: 0, skip_consent: false, allowed_groups: null },
      ["openid"],
      clock.now(),
    );
    expect(await (await me(tokens.access_token, "/grants")).json()).toEqual({ items: [] });
    // Events wait for the audit endpoints.
    expect((await me(tokens.access_token, "/events")).status).toBe(501);
    // Storage failures along the way.
    for (const [method, path, init] of [
      ["listSessions", "/sessions", { method: "GET" }],
      ["revokeSession", "/sessions/x", { method: "DELETE" }],
      ["revokeSessions", "/sessions", { method: "DELETE" }],
      ["listIdentities", "/identities", { method: "GET" }],
      ["listIdentities", "/identities/00000000-0000-7000-8000-00000000e002", { method: "DELETE" }],
      ["grantClientIds", "/grants", { method: "GET" }],
      ["revokeGrant", "/grants/x", { method: "DELETE" }],
    ] as const) {
      const lost = await me(tokens.access_token, path, {
        ...init,
        env: throwingDo(fresh.profile.id, method),
      });
      expect(lost.status, `${method} ${path}`).toBe(503);
    }
    for (const [method, path, init] of [
      ["listSessions", "/sessions", { method: "GET" }],
      ["revokeSessions", "/sessions", { method: "DELETE" }],
      ["listIdentities", "/identities", { method: "GET" }],
      ["listIdentities", "/identities/00000000-0000-7000-8000-00000000e002", { method: "DELETE" }],
      ["grantClientIds", "/grants", { method: "GET" }],
      ["listGrants", "/grants", { method: "GET" }],
      ["revokeGrant", "/grants/x", { method: "DELETE" }],
    ] as const) {
      const victim = await userWithPasskey(clock);
      const token = (await login(victim)).access_token;
      const vanished = await me(token, path, {
        ...init,
        env: sabotageDo(victim.profile.id, method),
      });
      expect(vanished.status, `${method} ${path}`).toBe(503);
    }
    // Unlinking on an object that vanished, and a removal the object refuses for another reason.
    const ghost = await userWithPasskey(clock);
    const ghostToken = (await login(ghost)).access_token;
    await ghost.stub.addIdentity(
      {
        id: "00000000-0000-7000-8000-00000000f001",
        issuer: upstreamIssuer,
        subject: "ghost-at-idp",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    expect(
      (
        await me(ghostToken, "/identities/00000000-0000-7000-8000-00000000f001", {
          method: "DELETE",
          env: interceptDo(ghost.profile.id, "removeIdentity", async (stub) => {
            await stub.removeIdentity("00000000-0000-7000-8000-00000000f001");
          }),
        })
      ).status,
    ).toBe(404);
    await ghost.stub.addIdentity(
      {
        id: "00000000-0000-7000-8000-00000000f002",
        issuer: upstreamIssuer,
        subject: "ghost-again",
        email: null,
        email_verified: null,
        name: null,
      },
      clock.now(),
    );
    expect(
      (
        await me(ghostToken, "/identities/00000000-0000-7000-8000-00000000f002", {
          method: "DELETE",
          env: sabotageDo(ghost.profile.id, "removeIdentity"),
        })
      ).status,
    ).toBe(503);
  });
});
