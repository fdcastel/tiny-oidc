import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { sha256 } from "../../src/crypto/hash.ts";
import { newInteractionId, newSecret } from "../../src/crypto/random.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { setClientDisabled } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { InteractionDocument } from "../../src/do/InteractionDO.ts";
import type { ClientRef, InitProfile } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import type { LogLine } from "../../src/obs/log.ts";
import type { AuthorizeRequest } from "../../src/oidc/authorize.ts";
import { REQUEST_URI_PREFIX } from "../../src/oidc/authorize-endpoint.ts";
import { ACR } from "../../src/oidc/capabilities.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { openBindingHandle, openCodeHandle, sealSessionHandle } from "../../src/oidc/handles.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { createApp } from "../../src/router/app.ts";
import { bindingCookieName, SESSION_COOKIE } from "../../src/router/cookies.ts";
import { encodeBase64Url } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient, userProfile } from "../support/factories.ts";
import { testKeys } from "../support/keys.ts";
import { env, url } from "../support/op.ts";
import { resetStorage } from "../support/reset.ts";
import { loggedIn as loggedInUser } from "../support/sessions.ts";

const ISSUER = "https://auth.example.com";
const LOGIN_URL = "https://login.example.com/app";
const RP = "https://rp.example.com/cb";
const clock = new FakeClock(1_800_000_000);
const uuids = new UuidV7(clock);
const keys = testKeys();
const db = Db.from(env.DB);
const lines: LogLine[] = [];
const app = createApp({ clock, sink: (line) => lines.push(line) });

/** GET /authorize through the app with the fake clock; redirects are not followed. */
async function authorize(
  params: Record<string, string> | string,
  init: { cookie?: string } = {},
): Promise<Response> {
  const query = typeof params === "string" ? params : new URLSearchParams(params).toString();
  const ctx = createExecutionContext();
  const headers: Record<string, string> = {};
  if (init.cookie !== undefined) headers["cookie"] = init.cookie;
  const res = await app.fetch(new Request(url(`/authorize?${query}`), { headers }), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

/** POST /authorize with a form body (or another content type) through the app. */
async function authorizePost(
  params: Record<string, string> | string,
  contentType = "application/x-www-form-urlencoded",
): Promise<Response> {
  const body = typeof params === "string" ? params : new URLSearchParams(params).toString();
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(url("/authorize"), {
      method: "POST",
      headers: { "content-type": contentType },
      body,
    }),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

const location = (res: Response): URL => {
  expect(res.status).toBe(303);
  return new URL(res.headers.get("location") as string);
};
const query = (res: Response): Record<string, string> =>
  Object.fromEntries(location(res).searchParams);
const cookiesOf = (res: Response): string[] => res.headers.getSetCookie();

/** A valid request for `client` with the minimum parameters; overrides may delete keys with undefined. */
function valid(client: Client, overrides: Record<string, string | undefined> = {}) {
  const params: Record<string, string> = {
    client_id: client.client_id,
    redirect_uri: RP,
    response_type: "code",
    scope: "openid email",
    state: "st-123",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete params[k];
    else params[k] = v;
  }
  return params;
}

let web: Client;
let consentful: Client;
let grouped: Client;
let unpinned: Client;

const loggedIn = (profile?: InitProfile) => loggedInUser(clock, profile);

async function interactionDoc(id: string): Promise<InteractionDocument> {
  const got = await interactionStub(env, id).get(clock.now());
  if (!got.ok) throw new Error(got.error);
  return got.doc;
}

const clientRef = (client: Client): ClientRef => ({
  client_id: client.client_id,
  created_at: client.created_at,
  skip_consent: client.skip_consent,
  allowed_groups: client.allowed_groups,
});

describe("GET /authorize", () => {
  it("[TIO-CFG-004] answers 503 not_configured as JSON until login_url and login_origins are effective", async () => {
    await resetStorage();
    const res = await authorize({ client_id: "web" });
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "not_configured" });
    await writeSettings(
      db,
      { login_url: LOGIN_URL, login_origins: ["https://login.example.com"] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP, "http://127.0.0.1:8080/cb", "https://rp.example.com/cb?x=1"],
        skip_consent: true,
      })
    ).client;
    consentful = (await createTestClient(db, clock, { redirect_uris: [RP], skip_consent: false }))
      .client;
    grouped = (
      await createTestClient(
        db,
        clock,
        { redirect_uris: [RP], skip_consent: true, allowed_groups: ["staff"] },
        { existingGroups: new Set(["staff"]) },
      )
    ).client;
    unpinned = (
      await createTestClient(db, clock, {
        redirect_uris: [RP],
        skip_consent: true,
        token_endpoint_auth_method: "client_secret_basic",
        require_pkce: false,
      })
    ).client;
    expect((await authorize({ client_id: "nobody" })).status).toBe(303);
  });

  it("[TIO-AUTHZ-001] rejects duplicate parameters and methods other than GET and POST; the router bounds the query at 8 KB", async () => {
    const dup = await authorize(`client_id=${web.client_id}&client_id=${web.client_id}`);
    expect(location(dup).origin + location(dup).pathname).toBe(LOGIN_URL);
    expect(query(dup)).toEqual({
      error: "invalid_request",
      error_description: "duplicate parameter",
    });
    const ctx = createExecutionContext();
    const put = await app.fetch(new Request(url("/authorize"), { method: "PUT" }), env, ctx);
    await waitOnExecutionContext(ctx);
    expect(put.status).toBe(405);
    expect(put.headers.get("allow")).toBe("GET, POST");
    const long = await authorize(`client_id=${web.client_id}&state=${"a".repeat(9_000)}`);
    expect(long.status).toBe(414);
  });

  it("[TIO-AUTHZ-001] POST /authorize reads the same parameters from a form body (OIDC Core §3.1.2.1): it starts the interaction, refuses duplicates and any other content type", async () => {
    const posted = await authorizePost(valid(web));
    const target = location(posted);
    expect(target.origin + target.pathname).toBe(LOGIN_URL);
    expect(target.searchParams.get("interaction")).toMatch(/^[A-Za-z0-9_-]+$/);
    const doc = await interactionDoc(target.searchParams.get("interaction") as string);
    expect(doc.client_id).toBe(web.client_id);
    expect((doc.request as AuthorizeRequest).state).toBe("st-123");
    const dup = await authorizePost(`client_id=${web.client_id}&client_id=${web.client_id}`);
    expect(query(dup)).toEqual({
      error: "invalid_request",
      error_description: "duplicate parameter",
    });
    const json = await authorizePost(JSON.stringify(valid(web)), "application/json");
    expect(query(json)).toEqual({
      error: "invalid_request",
      error_description: "unsupported content type",
    });
    // The redirectable errors of a POST go back to the client like a GET's.
    const bad = await authorizePost(valid(web, { response_type: "token" }));
    expect(location(bad).origin + location(bad).pathname).toBe(RP);
    expect(query(bad)).toMatchObject({ error: "unsupported_response_type", state: "st-123" });
  });

  it("[TIO-AUTHZ-002] [TIO-AUTHZ-018] a missing, unknown, disabled or code-less client is reported to the login app without touching the redirect_uri", async () => {
    const disabled = await createTestClient(db, clock);
    await setClientDisabled(db, disabled.client.client_id, clock.now(), clock.now());
    const credentialsOnly = await createTestClient(db, clock, {
      grant_types: ["client_credentials"],
      token_endpoint_auth_method: "client_secret_basic",
      redirect_uris: [],
    });
    const cases: [Record<string, string>, string, string][] = [
      [valid(web, { client_id: undefined }), "invalid_request", "client_id is required"],
      [valid(web, { client_id: "nobody" }), "invalid_request", "unknown client"],
      [valid(web, { client_id: disabled.client.client_id }), "invalid_request", "unknown client"],
      [
        valid(web, { client_id: credentialsOnly.client.client_id }),
        "unauthorized_client",
        "client cannot use the authorization code grant",
      ],
    ];
    for (const [params, error, description] of cases) {
      const res = await authorize({ ...params, redirect_uri: "https://evil.example.net/steal" });
      const target = location(res);
      expect(`${target.origin}${target.pathname}`, description).toBe(LOGIN_URL);
      expect(query(res)).toEqual({ error, error_description: description });
      expect(res.headers.get("content-type")).toBeNull();
      expect(await res.text()).toBe("");
      expect(res.headers.get("location")).not.toContain("evil");
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    }
  });

  it("[TIO-AUTHZ-005] the redirect_uri must match a registered one exactly, except for the loopback port; failures never redirect to it", async () => {
    const bad = [
      undefined,
      "https://rp.example.com/cb/",
      "https://rp.example.com/cb2",
      "https://RP.example.com/cb",
      "https://rp.example.com/cb?x=2",
      "https://rp.example.com/callback",
      "https://rp.example.com/c",
      "http://rp.example.com/cb",
      "https://evil.example.net/cb",
      "http://localhost:8080/cb",
    ];
    for (const redirect_uri of bad) {
      const res = await authorize(valid(web, { redirect_uri }));
      expect(location(res).origin, String(redirect_uri)).toBe("https://login.example.com");
      expect(query(res)["error"]).toBe("invalid_request");
      expect(query(res)["error_description"]).toMatch(/redirect_uri/);
    }
    // Loopback: another port is accepted, and later errors go to the requested port.
    const loopback = await authorize(
      valid(web, { redirect_uri: "http://127.0.0.1:49152/cb", response_type: "token" }),
    );
    expect(location(loopback).origin).toBe("http://127.0.0.1:49152");
    expect(query(loopback)["error"]).toBe("unsupported_response_type");
    // A registered URI with a query keeps it and gets the parameters appended.
    const withQuery = await authorize(
      valid(web, { redirect_uri: "https://rp.example.com/cb?x=1", response_type: "token" }),
    );
    expect(withQuery.headers.get("location")).toMatch(
      /^https:\/\/rp\.example\.com\/cb\?x=1&error=/,
    );
  });

  it("[TIO-AUTHZ-006] [TIO-AUTHZ-019] a response_type other than code is unsupported_response_type, redirected with state and iss", async () => {
    for (const response_type of [undefined, "token", "code id_token", "Code"]) {
      const r = await authorize(valid(web, { response_type }));
      expect(query(r), String(response_type)).toEqual({
        error: "unsupported_response_type",
        error_description: "response_type must be code",
        state: "st-123",
        iss: ISSUER,
      });
      expect(r.headers.get("cache-control")).toBe("no-store");
    }
  });

  it("[TIO-AUTHZ-025] a request object by value is request_not_supported — redirected with state and iss when the redirect_uri is registered, to the login app otherwise — and its contents never stand in for the query", async () => {
    // An unsigned request object carrying every parameter the query lacks (what the suite sends).
    const claims = Buffer.from(
      JSON.stringify({ state: "inside", nonce: "n", scope: "openid", response_type: "code" }),
    ).toString("base64url");
    const requestObject = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${claims}.`;
    const redirected = await authorize(valid(web, { request: requestObject }));
    expect(query(redirected)).toEqual({
      error: "request_not_supported",
      error_description: "request objects are not supported",
      state: "st-123",
      iss: ISSUER,
    });
    // Without state or scope in the query, the object does not supply them: still request_not_supported.
    const bare = await authorize({
      client_id: web.client_id,
      redirect_uri: web.redirect_uris[0] as string,
      request: requestObject,
    });
    expect(query(bare)).toEqual({
      error: "request_not_supported",
      error_description: "request objects are not supported",
      iss: ISSUER,
    });
    const untrusted = await authorize({ client_id: web.client_id, request: requestObject });
    expect(location(untrusted).origin).toBe("https://login.example.com");
    expect(query(untrusted)["error"]).toBe("invalid_request");
  });

  it("[TIO-AUTHZ-007] state is required, 1-2048 printable ASCII characters, and is echoed only when valid", async () => {
    for (const state of [undefined, "", "a".repeat(2_049), "tab\there", "café"]) {
      const r = await authorize(valid(web, { state }));
      expect(query(r), JSON.stringify(state)).toEqual({
        error: "invalid_request",
        error_description: "state is required: 1-2048 printable ASCII characters",
        iss: ISSUER,
      });
    }
    const max = "s".repeat(2_048);
    const r = await authorize(valid(web, { state: max, response_type: "token" }));
    expect(query(r)["state"]).toBe(max);
  });

  it("[TIO-AUTHZ-008] code_challenge is required with 43-128 PKCE characters and code_challenge_method must be S256; plain and a missing method are refused", async () => {
    const challenge = (n: number) => "a".repeat(n);
    for (const code_challenge of [undefined, challenge(42), challenge(129), `${challenge(42)}!`]) {
      const r = await authorize(valid(web, { code_challenge }));
      expect(query(r)["error"], String(code_challenge?.length)).toBe("invalid_request");
      expect(query(r)["error_description"]).toMatch(/code_challenge is required/);
    }
    for (const code_challenge_method of [undefined, "plain", "s256"]) {
      const r = await authorize(valid(web, { code_challenge_method }));
      expect(query(r)).toMatchObject({
        error: "invalid_request",
        error_description: "code_challenge_method must be S256",
      });
    }
    for (const code_challenge of [
      challenge(43),
      challenge(128),
      "-._~AZaz09-._~AZaz09-._~AZaz09-._~AZaz09-._",
    ]) {
      const r = await authorize(valid(web, { code_challenge, response_type: "token" }));
      expect(query(r)["error"]).toBe("unsupported_response_type");
    }
  });

  it("[TIO-AUTHZ-008] a client registered with require_pkce = 0 may omit both PKCE parameters (the code then binds no challenge); whatever it does send is validated in full", async () => {
    const none = await authorize(
      valid(unpinned, { code_challenge: undefined, code_challenge_method: undefined }),
    );
    const id = location(none).searchParams.get("interaction") as string;
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect((await interactionDoc(id)).request).toMatchObject({ code_challenge: null });
    const withBoth = await authorize(valid(unpinned));
    const bothId = location(withBoth).searchParams.get("interaction") as string;
    expect((await interactionDoc(bothId)).request).toMatchObject({
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    });
    const methodOnly = await authorize(valid(unpinned, { code_challenge: undefined }));
    expect(query(methodOnly)["error"]).toBe("invalid_request");
    expect(query(methodOnly)["error_description"]).toMatch(/code_challenge is required/);
    const challengeOnly = await authorize(valid(unpinned, { code_challenge_method: undefined }));
    expect(query(challengeOnly)).toMatchObject({
      error: "invalid_request",
      error_description: "code_challenge_method must be S256",
    });
    for (const code_challenge of ["a".repeat(42), `${"a".repeat(42)}!`]) {
      const r = await authorize(valid(unpinned, { code_challenge }));
      expect(query(r)["error_description"]).toMatch(/code_challenge is required/);
    }
    const plain = await authorize(valid(unpinned, { code_challenge_method: "plain" }));
    expect(query(plain)["error_description"]).toBe("code_challenge_method must be S256");
    // The default client still requires both.
    const pinned = await authorize(
      valid(web, { code_challenge: undefined, code_challenge_method: undefined }),
    );
    expect(query(pinned)["error_description"]).toMatch(/code_challenge is required/);
  });

  it("[TIO-AUTHZ-009] [TIO-SCOPE-001] scope must be present, include openid, hold only supported scopes allowed for the client, without duplicates", async () => {
    const cases: [string | undefined, string][] = [
      [undefined, "scope is required"],
      ["", "scope is required"],
      ["openid  email", "scope is required"],
      ["email profile", "scope must include openid"],
      ["openid unknown", "scope contains an unknown value"],
      ["openid email email", "scope contains duplicates"],
      ["openid admin", "scope is not allowed for this client"],
      ["openid account", "scope is not allowed for this client"],
      ["openid offline_access", "offline_access is not enabled for this client"],
    ];
    for (const [scope, description] of cases) {
      const r = await authorize(valid(web, { scope }));
      expect(query(r), String(scope)).toMatchObject({
        error: "invalid_scope",
        error_description: description,
      });
    }
    const r = await authorize(
      valid(web, { scope: "openid profile email groups", response_type: "token" }),
    );
    expect(query(r)["error"]).toBe("unsupported_response_type");
    // TIO-TOKEN-014: offline_access needs the client flag.
    const offline = (
      await createTestClient(db, clock, { redirect_uris: [RP], offline_access: true })
    ).client;
    const allowed = await authorize(
      valid(offline, { scope: "openid offline_access", response_type: "token" }),
    );
    expect(query(allowed)["error"]).toBe("unsupported_response_type");
  });

  it("[TIO-AUTHZ-010] nonce (1-512), login_hint (<= 256), ui_locales (<= 64) and acr_values (<= 256) are bounded and otherwise passed through to the interaction verbatim", async () => {
    const cases: [Record<string, string>, string][] = [
      [{ nonce: "" }, "nonce must be 1-512 characters"],
      [{ nonce: "n".repeat(513) }, "nonce must be 1-512 characters"],
      [{ login_hint: "h".repeat(257) }, "login_hint exceeds 256 characters"],
      [{ ui_locales: "l".repeat(65) }, "ui_locales exceeds 64 characters"],
      [{ acr_values: "a".repeat(257) }, "acr_values exceeds 256 characters"],
    ];
    for (const [overrides, description] of cases) {
      const r = await authorize(valid(web, overrides));
      expect(query(r), description).toMatchObject({
        error: "invalid_request",
        error_description: description,
      });
    }
    const r = await authorize(
      valid(web, {
        nonce: "n".repeat(512),
        login_hint: "alice@example.com <b>",
        ui_locales: "pt-BR en",
        acr_values: `${ACR.passkey} urn:example:x`,
        resource: "https://api.example.com",
      }),
    );
    const doc = await interactionDoc(query(r)["interaction"] as string);
    expect(doc.request).toEqual({
      redirect_uri: RP,
      scope: ["openid", "email"],
      state: "st-123",
      nonce: "n".repeat(512),
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      prompt: [],
      max_age: null,
      login_hint: "alice@example.com <b>",
      ui_locales: "pt-BR en",
      acr_values: [ACR.passkey, "urn:example:x"],
    });
  });

  it("[TIO-AUTHZ-011] [TIO-AUTHZ-012] prompt is a subset of none, login, consent, select_account with none alone (select_account means login); max_age is a non-negative integer", async () => {
    const bad: [Record<string, string>, string][] = [
      [{ prompt: "banana" }, "prompt contains an unknown value"],
      [{ prompt: "" }, "prompt contains an unknown value"],
      [{ prompt: "login  consent" }, "prompt contains an unknown value"],
      [{ prompt: "none login" }, "prompt=none cannot be combined with other values"],
      [{ prompt: "login login" }, "prompt contains duplicates"],
      [{ max_age: "-1" }, "max_age must be a non-negative integer"],
      [{ max_age: "abc" }, "max_age must be a non-negative integer"],
      [{ max_age: "1.5" }, "max_age must be a non-negative integer"],
      [{ max_age: "01" }, "max_age must be a non-negative integer"],
      [{ max_age: "1".repeat(11) }, "max_age must be a non-negative integer"],
    ];
    for (const [overrides, description] of bad) {
      const r = await authorize(valid(web, overrides));
      expect(query(r), description).toMatchObject({
        error: "invalid_request",
        error_description: description,
      });
    }
    const r = await authorize(valid(web, { prompt: "select_account consent login", max_age: "0" }));
    const doc = await interactionDoc(query(r)["interaction"] as string);
    expect(doc.request?.prompt).toEqual(["login", "consent"]);
    expect(doc.request?.max_age).toBe(0);
    const none = await authorize(valid(web, { prompt: "none" }));
    expect(query(none)["error"]).toBe("login_required");
  });

  it("[TIO-AUTHZ-016] [TIO-AUTHZ-020] without a session, an interaction is created in login_required and the browser is sent to login_url with the id and the binding cookie", async () => {
    const r = await authorize(valid(web, { nonce: "n1" }));
    const target = location(r);
    expect(`${target.origin}${target.pathname}`).toBe(LOGIN_URL);
    const id = target.searchParams.get("interaction") as string;
    expect([...target.searchParams.keys()]).toEqual(["interaction"]);
    expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const cookies = cookiesOf(r);
    expect(cookies).toHaveLength(1);
    const cookie = cookies[0] as string;
    expect(cookie).toMatch(
      new RegExp(
        `^${bindingCookieName(id)}=tio_ix_[A-Za-z0-9_-]+; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$`,
      ),
    );
    expect(bindingCookieName(id)).toBe(`__Host-tio_ix_${id.slice(0, 16)}`);
    const handle = cookie.slice(cookie.indexOf("=") + 1, cookie.indexOf(";"));
    const binding = await openBindingHandle(keys, handle);
    const doc = await interactionDoc(id);
    expect(binding?.interaction_id).toBe(id);
    expect(doc).toMatchObject({
      id,
      kind: "authorize",
      status: "login_required",
      client_id: web.client_id,
      binding_hash: encodeBase64Url(binding?.secret_hash as Uint8Array),
      existing_session: null,
      expires_at: clock.now() + 600,
    });
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    expect(lines.at(-1)).toMatchObject({ route: "/authorize", status: 303, do_calls: 1 });
  });

  it("[TIO-AUTHZ-014] [TIO-AUTHZ-021] [TIO-AUTHZ-022] [TIO-AUTHZ-023] a usable session with consent satisfied issues a tio_ac code bound to the request and redirects with code, state and iss, touching the session", async () => {
    const user = await loggedIn();
    clock.advance(100);
    const r = await authorize(valid(web, { nonce: "n-1" }), { cookie: user.cookie });
    const target = location(r);
    expect(`${target.origin}${target.pathname}`).toBe(RP);
    const params = Object.fromEntries(target.searchParams);
    expect(Object.keys(params).sort()).toEqual(["code", "iss", "state"]);
    expect(params).toMatchObject({ state: "st-123", iss: ISSUER });
    expect(params["code"]).toMatch(/^tio_ac_/);
    expect(cookiesOf(r)).toEqual([]);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const code = await openCodeHandle(keys, params["code"] as string);
    expect(code?.uid).toBe(user.profile.id);
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions[0]).toMatchObject({
      sid: user.sid,
      clients: [web.client_id],
      last_seen_at: clock.now(),
      idle_expires_at: clock.now() + 86_400,
    });
    // The code redeems with the verifier of this request only, with its nonce and scope.
    const exchanged = await user.stub.exchangeCode({
      secret_hash: code?.secret_hash as Uint8Array,
      client: clientRef(web),
      redirect_uri: RP,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      now: clock.now(),
      refresh: null,
    });
    expect(exchanged.ok && exchanged.nonce).toBe("n-1");
    expect(exchanged.ok && exchanged.grant.scope).toEqual(["openid", "email"]);
    expect(exchanged.ok && exchanged.grant.sid).toBe(user.sid);
  });

  it("[TIO-AUTHZ-024] two requests on one session bind their own nonce and code_challenge: the second code redeems only with the second verifier and carries the second nonce", async () => {
    const user = await loggedIn();
    const first = query(await authorize(valid(web, { nonce: "first" }), { cookie: user.cookie }));
    const secondVerifier = "second-verifier-second-verifier-second-verifier-x";
    const second = query(
      await authorize(
        valid(web, {
          nonce: "second",
          code_challenge: encodeBase64Url(await sha256(secondVerifier)),
          state: "st-2",
        }),
        { cookie: user.cookie },
      ),
    );
    expect(second["state"]).toBe("st-2");
    const secondCode = await openCodeHandle(keys, second["code"] as string);
    const wrongVerifier = await user.stub.exchangeCode({
      secret_hash: secondCode?.secret_hash as Uint8Array,
      client: clientRef(web),
      redirect_uri: RP,
      code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      now: clock.now(),
      refresh: null,
    });
    expect(wrongVerifier.ok).toBe(false);
    const rightVerifier = await user.stub.exchangeCode({
      secret_hash: secondCode?.secret_hash as Uint8Array,
      client: clientRef(web),
      redirect_uri: RP,
      code_verifier: secondVerifier,
      now: clock.now(),
      refresh: null,
    });
    expect(rightVerifier.ok && rightVerifier.nonce).toBe("second");
    expect(first["code"]).not.toBe(second["code"]);
  });

  it("[TIO-AUTHZ-015] prompt=none never creates an interaction nor touches the session: login_required without a usable session, consent_required when consent is missing", async () => {
    const before = (await authorize(valid(web, { prompt: "none" }))).headers;
    expect(before.get("location")).toContain("error=login_required");
    expect(before.getSetCookie()).toEqual([]);
    const user = await loggedIn();
    const seen = (await user.stub.listSessions(clock.now())).ok;
    expect(seen).toBe(true);
    clock.advance(50);
    const consent = await authorize(valid(consentful, { prompt: "none" }), { cookie: user.cookie });
    expect(query(consent)).toEqual({
      error: "consent_required",
      error_description: "prompt=none and consent required",
      state: "st-123",
      iss: ISSUER,
    });
    const stale = await authorize(valid(web, { prompt: "none", max_age: "10" }), {
      cookie: user.cookie,
    });
    expect(query(stale)["error"]).toBe("login_required");
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions[0]).toMatchObject({
      last_seen_at: user.auth_time,
      clients: [],
    });
    const bogus = await authorize(valid(web, { prompt: "none" }), {
      cookie: `${SESSION_COOKIE}=tio_ss_garbage`,
    });
    expect(query(bogus)["error"]).toBe("login_required");
    expect(cookiesOf(bogus)).toEqual([
      `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    // With everything satisfied, prompt=none is a normal session hit.
    const hit = await authorize(valid(web, { prompt: "none" }), { cookie: user.cookie });
    expect(query(hit)["code"]).toMatch(/^tio_ac_/);
  });

  it("[TIO-AUTHZ-016] a usable session that needs re-authentication (prompt=login, max_age) or consent starts an interaction carrying existing_session", async () => {
    const user = await loggedIn();
    clock.advance(30);
    const login = await authorize(valid(web, { prompt: "login" }), { cookie: user.cookie });
    const loginDoc = await interactionDoc(query(login)["interaction"] as string);
    expect(loginDoc.status).toBe("login_required");
    expect(loginDoc.existing_session).toEqual({
      uid: user.profile.id,
      sid: user.sid,
      auth_time: user.auth_time,
    });
    const aged = await authorize(valid(web, { max_age: "10" }), { cookie: user.cookie });
    expect((await interactionDoc(query(aged)["interaction"] as string)).status).toBe(
      "login_required",
    );
    const fresh = await authorize(valid(web, { max_age: "60" }), { cookie: user.cookie });
    expect(query(fresh)["code"]).toMatch(/^tio_ac_/);
    const consent = await authorize(valid(consentful), { cookie: user.cookie });
    const consentDoc = await interactionDoc(query(consent)["interaction"] as string);
    expect(consentDoc.status).toBe("consent_required");
    expect(consentDoc.existing_session?.sid).toBe(user.sid);
    // prompt=consent forces the consent step even for a covering grant; prompt=login wins over it.
    await user.stub.grantConsent(clientRef(consentful), ["openid", "email"], clock.now());
    expect(query(await authorize(valid(consentful), { cookie: user.cookie }))["code"]).toMatch(
      /^tio_ac_/,
    );
    const forced = await authorize(valid(consentful, { prompt: "consent" }), {
      cookie: user.cookie,
    });
    expect((await interactionDoc(query(forced)["interaction"] as string)).status).toBe(
      "consent_required",
    );
    const both = await authorize(valid(consentful, { prompt: "login consent" }), {
      cookie: user.cookie,
    });
    expect((await interactionDoc(query(both)["interaction"] as string)).status).toBe(
      "login_required",
    );
  });

  it("[TIO-AUTHZ-017] a user outside allowed_groups with a usable session is sent back with access_denied and user_not_allowed", async () => {
    const user = await loggedIn();
    const r = await authorize(valid(grouped), { cookie: user.cookie });
    expect(query(r)).toEqual({
      error: "access_denied",
      error_description: "user_not_allowed",
      state: "st-123",
      iss: ISSUER,
    });
    const member = await loggedIn(userProfile(clock, { groups: ["staff"] }));
    expect(query(await authorize(valid(grouped), { cookie: member.cookie }))["code"]).toMatch(
      /^tio_ac_/,
    );
  });

  it("[TIO-SESS-004] [TIO-SESS-003] an undecryptable, unknown, revoked or expired session cookie, or one of a disabled user, is treated as absent and cleared; a hit extends the idle expiry", async () => {
    const cleared = `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
    const expectAbsent = async (cookie: string, name: string) => {
      const r = await authorize(valid(web), { cookie });
      expect(query(r)["interaction"], name).toBeDefined();
      expect(
        cookiesOf(r).filter((c) => c.startsWith(SESSION_COOKIE)),
        name,
      ).toEqual([cleared]);
      const doc = await interactionDoc(query(r)["interaction"] as string);
      expect(doc.existing_session, name).toBeNull();
    };
    await expectAbsent(`${SESSION_COOKIE}=not-a-handle`, "garbage");
    await expectAbsent(`${SESSION_COOKIE}=tio_ac_${"A".repeat(80)}`, "wrong type");
    const stranger = await loggedIn();
    const forged = await sealSessionHandle(keys, stranger.profile.id, uuids.next(), newSecret());
    await expectAbsent(`${SESSION_COOKIE}=${forged}`, "unknown sid");
    const revoked = await loggedIn();
    await revoked.stub.revokeSession(revoked.sid, clock.now(), "test");
    await expectAbsent(revoked.cookie, "revoked");
    const disabled = await loggedIn();
    await disabled.stub.setDisabled(clock.now(), clock.now());
    await expectAbsent(disabled.cookie, "disabled");
    const nobody = await sealSessionHandle(keys, uuids.next(), uuids.next(), newSecret());
    await expectAbsent(`${SESSION_COOKIE}=${nobody}`, "no such user");
    const idle = await loggedIn();
    clock.advance(86_401);
    await expectAbsent(idle.cookie, "idle expired");
    // Other cookies are ignored; a live session is not cleared.
    const live = await loggedIn();
    const r = await authorize(valid(web), {
      cookie: `other=1; ${live.cookie}; ${SESSION_COOKIE}=dup`,
    });
    expect(cookiesOf(r)).toEqual([]);
    clock.advance(1_000);
    await authorize(valid(web), { cookie: live.cookie });
    const sessions = await live.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions[0]?.idle_expires_at).toBe(clock.now() + 86_400);
  });

  it("[TIO-AUTHZ-003] [TIO-AUTHZ-004] a request_uri replaces the query, is single-use and bound to its client; a require_par client cannot skip it", async () => {
    const parClient = (
      await createTestClient(db, clock, {
        redirect_uris: [RP],
        require_par: true,
        skip_consent: true,
      })
    ).client;
    const noPar = await authorize(valid(parClient));
    expect(query(noPar)).toEqual({
      error: "invalid_request",
      error_description: "this client must use pushed authorization requests",
    });
    const request: AuthorizeRequest = {
      redirect_uri: RP,
      scope: ["openid"],
      state: "par-state",
      nonce: "par-nonce",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      prompt: [],
      max_age: null,
      login_hint: null,
      ui_locales: null,
      acr_values: [],
    };
    const push = async (client: Client, overrides: Partial<AuthorizeRequest> = {}) => {
      const id = newInteractionId();
      const created = await interactionStub(env, id).create(
        {
          id,
          kind: "par",
          status: "pushed",
          binding_hash: "placeholder",
          client_id: client.client_id,
          request: { ...request, ...overrides },
        },
        clock.now(),
        60,
      );
      expect(created.ok).toBe(true);
      return `${REQUEST_URI_PREFIX}${id}`;
    };
    const requestUri = await push(parClient);
    const bad: [Record<string, string>, string, string?][] = [
      [
        { client_id: parClient.client_id, request_uri: "urn:other" },
        "request_uri values other than pushed authorization requests are not supported",
        "request_uri_not_supported",
      ],
      [
        { client_id: parClient.client_id, request_uri: "https://rp.example.com/request.jwt" },
        "request_uri values other than pushed authorization requests are not supported",
        "request_uri_not_supported",
      ],
      [
        { client_id: parClient.client_id, request_uri: `${REQUEST_URI_PREFIX}short` },
        "request_uri is malformed",
      ],
      [
        {
          client_id: parClient.client_id,
          request_uri: `${REQUEST_URI_PREFIX}${newInteractionId()}`,
        },
        "request_uri is unknown, expired or already used",
      ],
      [
        { client_id: web.client_id, request_uri: requestUri },
        "request_uri is unknown, expired or already used",
      ],
      [
        { client_id: parClient.client_id, request_uri: requestUri, state: "x" },
        "request_uri allows no other parameter than client_id",
      ],
    ];
    for (const [params, description, error = "invalid_request"] of bad) {
      const r = await authorize(params);
      expect(location(r).origin, description).toBe("https://login.example.com");
      expect(query(r)).toEqual({ error, error_description: description });
    }
    // Consumption: the pushed document becomes the login interaction with a fresh binding and TTL.
    const r = await authorize({ client_id: parClient.client_id, request_uri: requestUri });
    const id = requestUri.slice(REQUEST_URI_PREFIX.length);
    expect(query(r)["interaction"]).toBe(id);
    expect(cookiesOf(r)[0]).toContain(bindingCookieName(id));
    const doc = await interactionDoc(id);
    expect(doc).toMatchObject({
      kind: "authorize",
      status: "login_required",
      request,
      par_consumed: true,
      expires_at: clock.now() + 600,
    });
    expect(doc.binding_hash).not.toBe("placeholder");
    const again = await authorize({ client_id: parClient.client_id, request_uri: requestUri });
    expect(query(again)["error_description"]).toBe(
      "request_uri is unknown, expired or already used",
    );
    // Expiry after 60 s.
    const expiring = await push(parClient);
    clock.advance(61);
    expect(
      query(await authorize({ client_id: parClient.client_id, request_uri: expiring }))[
        "error_description"
      ],
    ).toBe("request_uri is unknown, expired or already used");
    // A session hit through PAR completes the pushed document and issues the code.
    const user = await loggedIn();
    const hit = await authorize(
      { client_id: parClient.client_id, request_uri: await push(parClient) },
      { cookie: user.cookie },
    );
    expect(query(hit)).toMatchObject({ state: "par-state", iss: ISSUER });
    expect(query(hit)["code"]).toMatch(/^tio_ac_/);
    // prompt=none through PAR fails the pushed document instead of starting an interaction.
    const none = await push(parClient, { prompt: ["none"] });
    const noneRes = await authorize({ client_id: parClient.client_id, request_uri: none });
    expect(query(noneRes)["error"]).toBe("login_required");
    expect((await interactionDoc(none.slice(REQUEST_URI_PREFIX.length))).status).toBe("failed");
    const stranger = await loggedIn();
    const denied = await authorize(
      { client_id: parClient.client_id, request_uri: await push(grouped) },
      { cookie: stranger.cookie },
    );
    expect(query(denied)["error_description"]).toBe(
      "request_uri is unknown, expired or already used",
    );
    const groupedUri = await push(grouped);
    const notAllowed = await authorize(
      { client_id: grouped.client_id, request_uri: groupedUri },
      { cookie: stranger.cookie },
    );
    expect(query(notAllowed)["error"]).toBe("access_denied");
    const failedDoc = await interactionDoc(groupedUri.slice(REQUEST_URI_PREFIX.length));
    expect(failedDoc.status).toBe("failed");
    expect(failedDoc.error).toEqual({
      error: "access_denied",
      error_description: "user_not_allowed",
    });
  });

  it("[TIO-ARCH-012] [TIO-ARCH-014] fails closed when D1 is unreachable: 503 JSON without settings, temporarily_unavailable through login_url without the client directory", async () => {
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const brokenEnv = { ...env, DB: brokenD1 } as Env;
    const send = async (
      application: ReturnType<typeof createApp>,
      target: Env,
      params: Record<string, string>,
    ) => {
      const ctx = createExecutionContext();
      const res = await application.fetch(
        new Request(url(`/authorize?${new URLSearchParams(params)}`)),
        target,
        ctx,
      );
      await waitOnExecutionContext(ctx);
      return res;
    };
    const fresh = createApp({ clock, sink: () => undefined });
    const noSettings = await send(fresh, brokenEnv, valid(web));
    expect(noSettings.status).toBe(503);
    expect(await noSettings.json()).toMatchObject({ error: "temporarily_unavailable" });
    // Settings cached (served stale while D1 is down); a client never cached cannot be looked up.
    expect((await send(fresh, env, valid(web))).status).toBe(303);
    clock.advance(61);
    const noClients = await send(fresh, brokenEnv, valid(consentful));
    expect(query(noClients)).toEqual({
      error: "temporarily_unavailable",
      error_description: "client directory unavailable",
    });
    // The cached client is still served stale.
    expect(query(await send(fresh, brokenEnv, valid(web)))["interaction"]).toBeDefined();
  });
});
