import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { newInteractionId, newSecret } from "../../src/crypto/random.ts";
import { deleteClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { InteractionDocument } from "../../src/do/InteractionDO.ts";
import { ATTEMPT_LIMIT, maskEmail, SCOPE_DESCRIPTIONS } from "../../src/interaction/api.ts";
import type { LogLine } from "../../src/obs/log.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { sealBindingHandle } from "../../src/oidc/handles.ts";
import { interactionStub, startInteraction } from "../../src/oidc/interactions.ts";
import { createApp } from "../../src/router/app.ts";
import { bindingCookieName } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient, userProfile } from "../support/factories.ts";
import { testKeys } from "../support/keys.ts";
import { env, url } from "../support/op.ts";
import { loggedIn } from "../support/sessions.ts";

const ISSUER = "https://auth.example.com";
const LOGIN_ORIGIN = "https://login.example.com";
const RP = "https://rp.example.com/cb";
const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);
const keys = testKeys();
const lines: LogLine[] = [];
const app = createApp({ clock, sink: (line) => lines.push(line) });

interface Started {
  id: string;
  /** The binding cookie as a `Cookie` header value. */
  cookie: string;
}

interface CallOptions {
  method?: string;
  origin?: string | null;
  cookie?: string | null;
  headers?: Record<string, string>;
  body?: unknown;
}

async function send(path: string, options: CallOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { ...options.headers };
  if (options.origin !== null) headers["origin"] = options.origin ?? LOGIN_ORIGIN;
  if (options.cookie !== null && options.cookie !== undefined) headers["cookie"] = options.cookie;
  const init: RequestInit = { method: options.method ?? "GET", headers };
  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }
  const ctx = createExecutionContext();
  const res = await app.fetch(new Request(url(path), init), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

const api = (id: string) => `/api/v1/interactions/${id}`;
const get = (started: Started, options: CallOptions = {}) =>
  send(api(started.id), { cookie: started.cookie, ...options });
const post = (started: Started, op: string, body?: unknown, options: CallOptions = {}) =>
  send(`${api(started.id)}/${op}`, { method: "POST", cookie: started.cookie, body, ...options });

/** Starts an interaction through /authorize and returns its id and binding cookie. */
async function start(
  client: Client,
  overrides: Record<string, string> = {},
  sessionCookie?: string,
): Promise<Started> {
  const params = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: RP,
    response_type: "code",
    scope: "openid email profile",
    state: "st-1",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    nonce: "n-1",
    ...overrides,
  });
  const headers: Record<string, string> = {};
  if (sessionCookie !== undefined) headers["cookie"] = sessionCookie;
  const ctx = createExecutionContext();
  const res = await app.fetch(new Request(url(`/authorize?${params}`), { headers }), env, ctx);
  await waitOnExecutionContext(ctx);
  expect(res.status).toBe(303);
  const location = new URL(res.headers.get("location") as string);
  const id = location.searchParams.get("interaction");
  if (id === null) throw new Error(`no interaction: ${location.href}`);
  const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-tio_ix_"));
  if (setCookie === undefined) throw new Error("no binding cookie");
  return { id, cookie: setCookie.slice(0, setCookie.indexOf(";")) };
}

async function doc(id: string): Promise<InteractionDocument> {
  const got = await interactionStub(env, id).get(clock.now());
  if (!got.ok) throw new Error(got.error);
  return got.doc;
}

let web: Client;
let consentful: Client;

describe("Interaction API guard", () => {
  it("[TIO-IX-001] with no login_origins configured every origin is refused, and preflights get no CORS headers", async () => {
    const id = newInteractionId();
    const res = await send(api(id));
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "origin_not_allowed" });
    const preflight = await send(api(id), {
      method: "OPTIONS",
      headers: { "access-control-request-method": "GET" },
      cookie: null,
    });
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
    clock.advance(61);
  });

  it("[TIO-IX-002] malformed ids are 404 interaction_not_found without a Durable Object access", async () => {
    await writeSettings(
      db,
      {
        login_url: `${LOGIN_ORIGIN}/`,
        login_origins: [LOGIN_ORIGIN, "https://login2.example.com"],
      },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP], skip_consent: true })).client;
    consentful = (
      await createTestClient(db, clock, {
        redirect_uris: [RP],
        skip_consent: false,
        client_uri: "https://rp.example.com",
        logo_uri: "https://rp.example.com/logo.png",
      })
    ).client;
    for (const id of [
      "short",
      "x".repeat(44),
      `${"x".repeat(42)}!`,
      "../../etc",
      "x".repeat(43).replace("x", " "),
    ]) {
      const res = await send(`/api/v1/interactions/${encodeURIComponent(id)}`);
      expect(res.status, id).toBe(404);
      expect(await res.json(), id).toMatchObject({ error: "interaction_not_found" });
      expect(lines.at(-1)?.["do_calls"], id).toBe(0);
    }
  });

  it("[TIO-IX-001] refuses origins outside login_origins and requests without the interaction's binding cookie, without revealing whether it exists", async () => {
    const started = await start(web);
    const okRes = await get(started);
    expect(okRes.status).toBe(200);
    expect((await get(started, { origin: "https://login2.example.com" })).status).toBe(200);
    // (a) Origin.
    const origins: [string | null, string | undefined, number, string][] = [
      ["https://evil.example.net", undefined, 403, "origin_not_allowed"],
      ["https://login.example.com.evil.net", undefined, 403, "origin_not_allowed"],
      ["null", undefined, 403, "origin_not_allowed"],
      [null, undefined, 403, "origin_not_allowed"],
      [null, "cross-site", 403, "origin_not_allowed"],
      [null, "none", 403, "origin_not_allowed"],
      [null, "same-origin", 200, ""],
      [null, "same-site", 200, ""],
    ];
    for (const [origin, fetchSite, status, error] of origins) {
      const headers: Record<string, string> = {};
      if (fetchSite !== undefined) headers["sec-fetch-site"] = fetchSite;
      const res = await get(started, { origin, headers });
      expect(res.status, `${origin} ${fetchSite}`).toBe(status);
      if (error) expect(await res.json()).toMatchObject({ error });
    }
    // A POST without Origin is never same-site enough.
    const post1 = await post(started, "abort", undefined, {
      origin: null,
      headers: { "sec-fetch-site": "same-origin" },
    });
    expect(post1.status).toBe(403);
    expect(await post1.json()).toMatchObject({ error: "origin_not_allowed" });
    // (b) Binding cookie.
    const other = await start(web);
    const forgedSecret = await sealBindingHandle(keys, started.id, newSecret());
    const bindings: [string | null, string][] = [
      [null, "absent"],
      [`${bindingCookieName(started.id)}=garbage`, "garbage"],
      [
        `${bindingCookieName(started.id)}=${other.cookie.split("=")[1]}`,
        "another interaction's handle",
      ],
      [other.cookie, "another interaction's cookie name"],
      [`${bindingCookieName(started.id)}=${forgedSecret}`, "right id, wrong secret"],
    ];
    for (const [cookie, name] of bindings) {
      const res = await get(started, { cookie });
      expect(res.status, name).toBe(403);
      expect(await res.json(), name).toMatchObject({ error: "interaction_binding_failed" });
    }
    // The same answer for an interaction that does not exist.
    const unknown = newInteractionId();
    const ghost = await send(api(unknown));
    expect(ghost.status).toBe(403);
    expect(await ghost.json()).toMatchObject({ error: "interaction_binding_failed" });
    expect(lines.at(-1)?.["do_calls"]).toBe(0);
    const ghostOrigin = await send(api(unknown), { origin: "https://evil.example.net" });
    expect(await ghostOrigin.json()).toMatchObject({ error: "origin_not_allowed" });
  });

  it("[TIO-IX-003] unknown, expired and completed interactions are 404 for every endpoint, except that GET serves failed and completed documents for 60 s", async () => {
    const unknown = newInteractionId();
    const cookie = `${bindingCookieName(unknown)}=${await sealBindingHandle(keys, unknown, newSecret())}`;
    const res = await send(api(unknown), { cookie });
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "interaction_not_found" });
    // Pushed requests are not interactions.
    const pushedId = newInteractionId();
    const pushedSecret = newSecret();
    await startInteraction(
      env,
      keys,
      pushedId,
      { kind: "par", status: "pushed", client_id: web.client_id },
      clock.now(),
      60,
    );
    const pushedCookie = `${bindingCookieName(pushedId)}=${await sealBindingHandle(keys, pushedId, pushedSecret)}`;
    expect((await send(api(pushedId), { cookie: pushedCookie })).status).toBe(404);
    // Expiry.
    const expiring = await start(web);
    clock.advance(600);
    expect((await get(expiring)).status).toBe(404);
    expect((await post(expiring, "abort")).status).toBe(404);
    // Terminal: failed via abort is readable for 60 s, then gone; every POST is 404 at once.
    const aborted = await start(web);
    expect((await post(aborted, "abort")).status).toBe(200);
    expect((await get(aborted)).status).toBe(200);
    expect((await post(aborted, "abort")).status).toBe(404);
    expect((await post(aborted, "consent", { decision: "deny" })).status).toBe(404);
    clock.advance(59);
    expect((await get(aborted)).status).toBe(200);
    clock.advance(1);
    expect((await get(aborted)).status).toBe(404);
  });

  it("[TIO-HTTP-003] CORS on the Interaction API reflects login origins with credentials and gives other origins nothing", async () => {
    const started = await start(web);
    const preflight = await send(api(started.id), {
      method: "OPTIONS",
      headers: { "access-control-request-method": "GET" },
      cookie: null,
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe(LOGIN_ORIGIN);
    expect(preflight.headers.get("access-control-allow-credentials")).toBe("true");
    expect(preflight.headers.get("access-control-allow-methods")).toBe("GET");
    const postPreflight = await send(`${api(started.id)}/abort`, {
      method: "OPTIONS",
      headers: { "access-control-request-method": "POST" },
      cookie: null,
    });
    expect(postPreflight.headers.get("access-control-allow-methods")).toBe("POST");
    // A method the path does not have gets no CORS headers.
    const wrongMethod = await send(api(started.id), {
      method: "OPTIONS",
      headers: { "access-control-request-method": "DELETE" },
      cookie: null,
    });
    expect(wrongMethod.headers.get("access-control-allow-origin")).toBeNull();
    expect(preflight.headers.get("access-control-allow-headers")).toBe(
      "Authorization, Content-Type",
    );
    expect(preflight.headers.get("access-control-max-age")).toBe("600");
    expect(preflight.headers.get("vary")).toBe("Origin");
    const foreign = await send(api(started.id), {
      method: "OPTIONS",
      origin: "https://evil.example.net",
      cookie: null,
    });
    expect(foreign.status).toBe(204);
    expect(foreign.headers.get("access-control-allow-origin")).toBeNull();
    const actual = await get(started);
    expect(actual.headers.get("access-control-allow-origin")).toBe(LOGIN_ORIGIN);
    expect(actual.headers.get("access-control-allow-credentials")).toBe("true");
    expect(actual.headers.get("access-control-expose-headers")).toBe("X-Request-Id");
    const refused = await get(started, { origin: "https://evil.example.net" });
    expect(refused.headers.get("access-control-allow-origin")).toBeNull();
    expect(refused.headers.get("access-control-allow-credentials")).toBeNull();
  });
});

describe("GET /api/v1/interactions/{id}", () => {
  it("[TIO-RL-001] answers 429 when the IP exceeds the interactions limit, and 503 when settings cannot be read", async () => {
    const started = await start(web);
    while ((await env.RL_IP.limit({ key: limitKey("ip_interactions", "198.51.100.7") })).success) {
      // exhaust
    }
    const limitedRes = await get(started, { headers: { "cf-connecting-ip": "198.51.100.7" } });
    expect(limitedRes.status).toBe(429);
    expect(limitedRes.headers.get("retry-after")).toBe("10");
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const fresh = createApp({ clock, sink: () => undefined });
    const broken = { ...env, DB: brokenD1 } as typeof env;
    const run = async (path: string, init: RequestInit) => {
      const ctx = createExecutionContext();
      const res = await fresh.fetch(new Request(url(path), init), broken, ctx);
      await waitOnExecutionContext(ctx);
      return res;
    };
    const down = await run(api(started.id), {
      headers: { origin: LOGIN_ORIGIN, cookie: started.cookie },
    });
    expect(down.status).toBe(503);
    expect(await down.json()).toMatchObject({ error: "temporarily_unavailable" });
    const preflight = await run(api(started.id), {
      method: "OPTIONS",
      headers: { origin: LOGIN_ORIGIN, "access-control-request-method": "GET" },
    });
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
    // Settings cached, client directory down: the document has no client.
    const ctx = createExecutionContext();
    await fresh.fetch(new Request(url("/api/v1/health")), env, ctx);
    await waitOnExecutionContext(ctx);
    const warm = await run("/api/v1/health", {});
    expect(warm.status).toBe(503);
    const okCtx = createExecutionContext();
    const settingsWarm = await fresh.fetch(
      new Request(url(api(started.id)), {
        headers: { origin: LOGIN_ORIGIN, cookie: started.cookie },
      }),
      env,
      okCtx,
    );
    await waitOnExecutionContext(okCtx);
    expect(settingsWarm.status).toBe(200);
    const other = (await createTestClient(db, clock, { redirect_uris: [RP], skip_consent: true }))
      .client;
    const otherStarted = await start(other);
    const noClient = await run(api(otherStarted.id), {
      headers: { origin: LOGIN_ORIGIN, cookie: otherStarted.cookie },
    });
    expect(noClient.status).toBe(200);
    expect(((await noClient.json()) as { client: unknown }).client).toBeNull();
  });

  it("shows consent details but no session_user for a user authenticated inside the interaction", async () => {
    const user = await loggedIn(clock);
    const started = await start(consentful);
    const authenticated = await interactionStub(env, started.id).apply(
      "authenticate",
      "consent_required",
      {
        auth: {
          uid: user.profile.id,
          method: "passkey",
          amr: ["hwk", "user"],
          acr: "urn:tinyoidc:acr:passkey",
          upstream: null,
          auth_time: clock.now(),
          new_session: true,
        },
      },
      clock.now(),
    );
    expect(authenticated.ok).toBe(true);
    const body = (await (await get(started)).json()) as Record<string, unknown>;
    expect(body["session_user"]).toBeNull();
    expect(body["consent"]).toMatchObject({
      scopes: [{ name: "openid" }, { name: "email" }, { name: "profile" }],
    });
    const granted = await post(started, "consent", {
      decision: "grant",
      scopes: ["email", "profile"],
    });
    expect(granted.status).toBe(200);
    const grants = await user.stub.listGrants([
      {
        client_id: consentful.client_id,
        created_at: consentful.created_at,
        skip_consent: false,
        allowed_groups: null,
      },
    ]);
    expect(grants.ok && grants.grants[0]?.scopes).toEqual(["email", "openid", "profile"]);
  });

  it("serves a document without client or request sections when the interaction has none", async () => {
    const id = newInteractionId();
    const bare = await startInteraction(
      env,
      keys,
      id,
      { kind: "authorize", status: "consent_required", client_id: null },
      clock.now(),
      600,
    );
    const body = (await (
      await get({ id, cookie: bare.cookie.slice(0, bare.cookie.indexOf(";")) })
    ).json()) as Record<string, unknown>;
    expect(body).toMatchObject({ client: null, request: null, consent: null, session_user: null });
  });

  it("[TIO-IX-020] [TIO-IX-021] the login_required document carries the client summary, request hints and methods, and never the state, nonce, code_challenge, redirect_uri, user id, email or any handle", async () => {
    const started = await start(consentful, {
      login_hint: "alice@example.com",
      ui_locales: "pt-BR",
      acr_values: "urn:tinyoidc:acr:passkey",
      prompt: "login",
      max_age: "300",
    });
    const res = await get(started);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = await res.json();
    expect(body).toEqual({
      id: started.id,
      kind: "authorize",
      status: "login_required",
      expires_at: clock.now() + 600,
      client: {
        client_id: consentful.client_id,
        client_name: "Test Client",
        client_uri: "https://rp.example.com",
        logo_uri: "https://rp.example.com/logo.png",
      },
      request: {
        scopes: ["openid", "email", "profile"],
        prompt: ["login"],
        max_age: 300,
        login_hint: "alice@example.com",
        ui_locales: "pt-BR",
        acr_values: ["urn:tinyoidc:acr:passkey"],
      },
      methods: { passkey: true, registration: "invite", upstreams: [] },
      session_user: null,
      consent: null,
      link: null,
      logout: null,
      error: null,
      attempts_remaining: ATTEMPT_LIMIT,
    });
    const text = JSON.stringify(body);
    for (const forbidden of [
      "st-1",
      "n-1",
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      RP,
      "tio_",
      "binding",
    ]) {
      expect(text, forbidden).not.toContain(forbidden);
    }
    expect(maskEmail("alice@example.com")).toBe("a***@example.com");
    expect(maskEmail("a@b.co")).toBe("a***@b.co");
    expect(maskEmail("weird")).toBe("***");
    expect(maskEmail("@nolocal")).toBe("***");
    expect(maskEmail(null)).toBeNull();
  });

  it("[TIO-IX-020] the document of a consent_required interaction started from a session shows the masked user, the consent scopes with descriptions and granted flags, and the failed document shows its error", async () => {
    const user = await loggedIn(
      clock,
      userProfile(clock, { email: "Carol@Example.com", display_name: "Carol" }),
    );
    const started = await start(consentful, {}, user.cookie);
    const body = (await (await get(started)).json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      status: "consent_required",
      session_user: { display_name: "Carol", email_masked: "C***@Example.com" },
      consent: {
        scopes: [
          { name: "openid", description: SCOPE_DESCRIPTIONS["openid"], granted: false },
          { name: "email", description: SCOPE_DESCRIPTIONS["email"], granted: false },
          { name: "profile", description: SCOPE_DESCRIPTIONS["profile"], granted: false },
        ],
      },
    });
    const text = JSON.stringify(body);
    expect(text).not.toContain(user.profile.id);
    expect(text).not.toContain("Carol@Example.com");
    // A partial earlier grant is reflected.
    await user.stub.grantConsent(
      {
        client_id: consentful.client_id,
        created_at: consentful.created_at,
        skip_consent: false,
        allowed_groups: null,
      },
      ["openid", "email"],
      clock.now(),
    );
    const again = (await (await get(started)).json()) as {
      consent: { scopes: { name: string; granted: boolean }[] };
    };
    expect(again.consent.scopes.map((s) => [s.name, s.granted])).toEqual([
      ["openid", true],
      ["email", true],
      ["profile", false],
    ]);
    // Failed: the error is shown.
    await post(started, "abort");
    const failed = (await (await get(started)).json()) as Record<string, unknown>;
    expect(failed).toMatchObject({
      status: "failed",
      error: { error: "access_denied", error_description: "aborted by the user" },
      consent: null,
      session_user: null,
    });
    expect(Object.keys(SCOPE_DESCRIPTIONS).sort()).toEqual([
      "account",
      "admin",
      "email",
      "groups",
      "offline_access",
      "openid",
      "profile",
    ]);
  });

  it("degrades to a null client when the client record is gone and to no consent details when the user is gone", async () => {
    const user = await loggedIn(clock);
    const doomed = (await createTestClient(db, clock, { redirect_uris: [RP], skip_consent: false }))
      .client;
    const started = await start(doomed, {}, user.cookie);
    await deleteClient(db, doomed.client_id);
    clock.advance(61);
    const body = (await (await get(started)).json()) as Record<string, unknown>;
    expect(body["client"]).toBeNull();
    expect(body["consent"]).toBeNull();
    // A consent_required interaction whose user was never initialized.
    const orphanId = newInteractionId();
    const orphan = await startInteraction(
      env,
      keys,
      orphanId,
      {
        kind: "authorize",
        status: "consent_required",
        client_id: consentful.client_id,
        request: {
          redirect_uri: RP,
          scope: ["openid", "email"],
          state: "s",
          nonce: null,
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          prompt: [],
          max_age: null,
          login_hint: null,
          ui_locales: null,
          acr_values: [],
        },
        existing_session: { uid: "0192abcd-1234-7000-8000-000000000009", sid: "x", auth_time: 1 },
      },
      clock.now(),
      600,
    );
    const orphanStarted = {
      id: orphanId,
      cookie: orphan.cookie.slice(0, orphan.cookie.indexOf(";")),
    };
    const orphanBody = (await (await get(orphanStarted)).json()) as Record<string, unknown>;
    expect(orphanBody["consent"]).toEqual({
      scopes: [
        { name: "openid", description: SCOPE_DESCRIPTIONS["openid"], granted: false },
        { name: "email", description: SCOPE_DESCRIPTIONS["email"], granted: false },
      ],
    });
    expect(orphanBody["session_user"]).toBeNull();
    const grant = await post(orphanStarted, "consent", { decision: "grant", scopes: ["email"] });
    expect(grant.status).toBe(403);
    expect(await grant.json()).toMatchObject({
      error: "access_denied",
      error_description: "user_not_initialized",
    });
  });
});

describe("POST …/abort and …/consent", () => {
  it("[TIO-IX-041] abort fails the interaction with access_denied from any non-terminal status and returns the completion URL", async () => {
    for (const client of [web, consentful]) {
      const started = await start(client);
      const res = await post(started, "abort");
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        status: "failed",
        redirect_to: `${ISSUER}/interactions/${started.id}/complete`,
      });
      const stored = await doc(started.id);
      expect(stored.status).toBe("failed");
      expect(stored.error).toEqual({
        error: "access_denied",
        error_description: "aborted by the user",
      });
      expect(stored.expires_at).toBe(clock.now() + 60);
    }
    const user = await loggedIn(clock);
    const consenting = await start(consentful, {}, user.cookie);
    expect((await doc(consenting.id)).status).toBe("consent_required");
    expect((await post(consenting, "abort")).status).toBe(200);
    expect((await doc(consenting.id)).status).toBe("failed");
  });

  it("[TIO-CONSENT-001] [TIO-CONSENT-002] [TIO-CONSENT-003] consent is asked when the grant does not cover the request or prompt says so; granting stores the union with openid and continues to ready; denying fails", async () => {
    const user = await loggedIn(clock);
    const clientRef = {
      client_id: consentful.client_id,
      created_at: consentful.created_at,
      skip_consent: false,
      allowed_groups: null,
    };
    const first = await start(consentful, {}, user.cookie);
    // Wrong bodies.
    for (const body of [
      undefined,
      "not json",
      {},
      { decision: "maybe" },
      { decision: "grant" },
      { decision: "grant", scopes: ["openid", "groups"] },
    ]) {
      const res = await post(first, "consent", body);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(await res.json(), JSON.stringify(body)).toMatchObject({ error: "invalid_request" });
    }
    // A subset is granted; openid is implied; the interaction is ready.
    const granted = await post(first, "consent", { decision: "grant", scopes: ["email"] });
    expect(granted.status).toBe(200);
    expect(await granted.json()).toEqual({
      status: "ready",
      redirect_to: `${ISSUER}/interactions/${first.id}/complete`,
    });
    const stored = await doc(first.id);
    expect(stored.status).toBe("ready");
    expect(stored.consent).toEqual({ scopes: ["openid", "email"] });
    const grants = await user.stub.listGrants([clientRef]);
    expect(grants.ok && grants.grants[0]?.scopes).toEqual(["email", "openid"]);
    // Consent again in ready is not allowed.
    const again = await post(first, "consent", { decision: "grant", scopes: [] });
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ error: "interaction_invalid_state" });
    // The grant covers openid+email: a request for those is a session hit; profile still needs consent.
    const covered = await start(consentful, { scope: "openid email" }, user.cookie).catch(
      (e: Error) => e,
    );
    expect(covered).toBeInstanceOf(Error);
    const second = await start(consentful, {}, user.cookie);
    expect((await doc(second.id)).status).toBe("consent_required");
    // Granting the rest stores the union.
    await post(second, "consent", { decision: "grant", scopes: ["profile", "openid"] });
    const union = await user.stub.listGrants([clientRef]);
    expect(union.ok && union.grants[0]?.scopes).toEqual(["email", "openid", "profile"]);
    // prompt=consent asks again although the grant covers everything; denying fails the interaction.
    const forced = await start(consentful, { prompt: "consent" }, user.cookie);
    const denied = await post(forced, "consent", { decision: "deny" });
    expect(await denied.json()).toEqual({
      status: "failed",
      redirect_to: `${ISSUER}/interactions/${forced.id}/complete`,
    });
    expect((await doc(forced.id)).error).toEqual({
      error: "access_denied",
      error_description: "consent denied",
    });
    // Consent on a login_required interaction is refused.
    const fresh = await start(consentful);
    const early = await post(fresh, "consent", { decision: "grant", scopes: ["email"] });
    expect(early.status).toBe(409);
    // The client vanished between the start and the decision.
    const doomed = (await createTestClient(db, clock, { redirect_uris: [RP], skip_consent: false }))
      .client;
    const doomedStart = await start(doomed, {}, user.cookie);
    await deleteClient(db, doomed.client_id);
    clock.advance(61);
    const gone = await post(doomedStart, "consent", { decision: "grant", scopes: ["email"] });
    expect(gone.status).toBe(503);
  });
});

describe("attempt counting", () => {
  it("[TIO-RL-002] [TIO-IX-030] the attempt that exceeds the per-interaction limit fails the interaction with too_many_attempts", async () => {
    const started = await start(web);
    const stub = interactionStub(env, started.id);
    for (let i = 1; i <= ATTEMPT_LIMIT; i++) {
      const counted = await stub.attempt(clock.now(), ATTEMPT_LIMIT);
      expect(counted.ok && counted.remaining, String(i)).toBe(ATTEMPT_LIMIT - i);
    }
    const body = (await (await get(started)).json()) as { attempts_remaining: number };
    expect(body.attempts_remaining).toBe(0);
    expect(await stub.attempt(clock.now(), ATTEMPT_LIMIT)).toEqual({
      ok: false,
      error: "too_many_attempts",
    });
    const stored = await doc(started.id);
    expect(stored.status).toBe("failed");
    expect(stored.error).toEqual({
      error: "too_many_attempts",
      error_description: "too many attempts",
    });
    expect(stored.attempts).toBe(ATTEMPT_LIMIT + 1);
    expect(await stub.attempt(clock.now(), ATTEMPT_LIMIT)).toEqual({
      ok: false,
      error: "interaction_invalid_state",
    });
    expect(await stub.patch({ attempts: 0 }, clock.now())).toEqual({
      ok: false,
      error: "interaction_invalid_state",
    });
    const patched = await interactionStub(env, (await start(web)).id).patch(
      { attempts: 3 },
      clock.now(),
    );
    expect(patched.ok && patched.doc.attempts).toBe(3);
    expect(await interactionStub(env, newInteractionId()).patch({}, clock.now())).toEqual({
      ok: false,
      error: "interaction_not_found",
    });
    expect(await interactionStub(env, newInteractionId()).attempt(clock.now(), 1)).toEqual({
      ok: false,
      error: "interaction_not_found",
    });
  });
});
