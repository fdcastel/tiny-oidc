import { runInDurableObject } from "cloudflare:test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { setClientDisabled } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { insertGroup } from "../../src/db/groups.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { atHash } from "../../src/oidc/tokens.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";

const ISSUER = "https://auth.example.com";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

let web: Client;
let offlineClient: Client;
let noRefresh: Client;
let confidential: { client: Client; secret: string | null };

interface TokenBody {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope: string;
}

interface Options {
  authorization?: string;
  contentType?: string;
  ip?: string;
  env?: Env;
}

async function token(body: Record<string, string> | string, options: Options = {}) {
  const headers: Record<string, string> = {
    "content-type": options.contentType ?? "application/x-www-form-urlencoded",
  };
  if (options.authorization !== undefined) headers["authorization"] = options.authorization;
  if (options.ip !== undefined) headers["cf-connecting-ip"] = options.ip;
  const init: Parameters<typeof h.send>[1] = {
    method: "POST",
    origin: null,
    headers,
    body: typeof body === "string" ? body : new URLSearchParams(body).toString(),
  };
  if (options.env) init.env = options.env;
  return h.send("/token", init);
}

/** A full login through /authorize, the passkey ceremony and /complete; returns the code and session cookie. */
async function login(
  client: Client,
  user: PasskeyUser,
  overrides: Record<string, string> = {},
  sessionCookie?: string,
): Promise<{ code: string; session: string; started: Started }> {
  const started = await h.start(client, overrides, sessionCookie);
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  const verified = await h.post(started, "passkey/verify", { response });
  expect(verified.status).toBe(200);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  expect(complete.status).toBe(303);
  const location = new URL(complete.headers.get("location") as string);
  const code = location.searchParams.get("code");
  if (code === null) throw new Error(`no code: ${location.href}`);
  const session = complete.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`)) as string;
  return { code, session: session.slice(0, session.indexOf(";")), started };
}

const exchange = (client: Client, code: string, extra: Record<string, string> = {}) =>
  token({
    grant_type: "authorization_code",
    client_id: client.client_id,
    code,
    redirect_uri: RP_REDIRECT,
    code_verifier: VERIFIER,
    ...extra,
  });

const refresh = (client: Client, refreshToken: string, extra: Record<string, string> = {}) =>
  token({
    grant_type: "refresh_token",
    client_id: client.client_id,
    refresh_token: refreshToken,
    ...extra,
  });

async function jwks() {
  const res = await h.send("/.well-known/jwks.json", { origin: null });
  return createLocalJWKSet(await res.json());
}

async function verify(jwt: string, typ: string, audience: string) {
  const { payload, protectedHeader } = await jwtVerify(jwt, await jwks(), {
    issuer: ISSUER,
    audience,
    typ,
    currentDate: clock.nowDate(),
  });
  return { payload, header: protectedHeader };
}

describe("POST /token: authorization_code", () => {
  it("[TIO-TOKEN-013] [TIO-TOKEN-005] [TIO-TOKEN-030] [TIO-TOKEN-032] [TIO-ARCH-004] [TIO-ARCH-005] exchanges the code for an ID token, an access token and a refresh token in one Durable Object call and no D1 write", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        audiences: ["https://api.example.com"],
      })
    ).client;
    offlineClient = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "offline_access"],
      })
    ).client;
    noRefresh = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        grant_types: ["authorization_code"],
        access_token_ttl: 120,
        id_token_ttl: 90,
      })
    ).client;
    confidential = await createTestClient(db, clock, {
      redirect_uris: [RP_REDIRECT],
      skip_consent: true,
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes_allowed: ["openid", "email", "admin"],
    });
    // The first request to an empty store creates the signing key (TIO-KEYS-010), a one-off write.
    await jwks();
    const user = await userWithPasskey(clock, { display_name: "Alice" });
    const { code } = await login(web, user, { nonce: "n-42", scope: "openid email profile" });
    clock.advance(3);
    const res = await exchange(web, code);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    const body = (await res.json()) as TokenBody;
    expect(body).toMatchObject({
      token_type: "Bearer",
      expires_in: 600,
      scope: "openid email profile",
    });
    expect(body.refresh_token).toMatch(/^tio_rt_/);
    const at = await verify(body.access_token, "at+jwt", "https://api.example.com");
    expect(at.header).toEqual({ alg: "ES256", typ: "at+jwt", kid: expect.any(String) });
    expect(at.payload).toEqual({
      iss: ISSUER,
      sub: user.profile.id,
      aud: "https://api.example.com",
      exp: clock.now() + 600,
      iat: clock.now(),
      jti: expect.stringMatching(/^[0-9a-f-]{36}$/),
      client_id: web.client_id,
      scope: "openid email profile",
      sid: expect.any(String),
      auth_time: clock.now() - 3,
      acr: "urn:tinyoidc:acr:passkey",
      amr: ["swk", "user"],
    });
    const id = await verify(body.id_token as string, "JWT", web.client_id);
    expect(id.payload).toEqual({
      iss: ISSUER,
      sub: user.profile.id,
      aud: web.client_id,
      exp: clock.now() + 600,
      iat: clock.now(),
      auth_time: clock.now() - 3,
      nonce: "n-42",
      acr: "urn:tinyoidc:acr:passkey",
      amr: ["swk", "user"],
      sid: at.payload["sid"],
      at_hash: await atHash(body.access_token),
      name: "Alice",
      updated_at: user.profile.updated_at,
      email: user.profile.email,
      email_verified: true,
    });
    const line = h.lines.filter((l) => l["route"] === "/token").at(-1);
    expect(line).toMatchObject({ route: "/token", status: 200, do_calls: 1, d1_writes: 0 });
    // A client without the refresh_token grant gets no refresh token and its own TTLs.
    const bare = await login(noRefresh, user, { scope: "openid" });
    const bareBody = (await (await exchange(noRefresh, bare.code)).json()) as TokenBody;
    expect(bareBody.refresh_token).toBeUndefined();
    expect(bareBody.expires_in).toBe(120);
    expect(
      (await verify(bareBody.id_token as string, "JWT", noRefresh.client_id)).payload["exp"],
    ).toBe(clock.now() + 90);
    expect(
      (await verify(bareBody.access_token, "at+jwt", noRefresh.client_id)).payload["aud"],
    ).toBe(noRefresh.client_id);
  });

  it("[TIO-TOKEN-010] [TIO-TOKEN-011] [TIO-TOKEN-012] rejects malformed codes without storage access, mismatched redirect_uri, verifier or client, and a replayed code revokes the family it created", async () => {
    const user = await userWithPasskey(clock);
    const malformed = await exchange(web, "tio_ac_nope");
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ error: "invalid_grant" });
    expect(h.lines.at(-1)).toMatchObject({ do_calls: 0 });
    expect(((await (await exchange(web, "")).json()) as { error: string }).error).toBe(
      "invalid_grant",
    );
    const noCode = await token({
      grant_type: "authorization_code",
      client_id: web.client_id,
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(await noCode.json()).toMatchObject({ error: "invalid_grant" });
    const { code } = await login(web, user, { scope: "openid" });
    const cases: [string, Record<string, string>][] = [
      ["redirect_uri", { redirect_uri: "https://rp.example.com/other" }],
      ["no redirect_uri", { redirect_uri: "" }],
      ["verifier", { code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-wrong" }],
      ["short verifier", { code_verifier: "short" }],
      ["no verifier", { code_verifier: "" }],
      ["bad verifier chars", { code_verifier: `${"a".repeat(42)}!` }],
    ];
    for (const [name, extra] of cases) {
      const params: Record<string, string> = {
        grant_type: "authorization_code",
        client_id: web.client_id,
        code,
        redirect_uri: RP_REDIRECT,
        code_verifier: VERIFIER,
        ...extra,
      };
      if (extra["redirect_uri"] === "") delete params["redirect_uri"];
      if (extra["code_verifier"] === "") delete params["code_verifier"];
      const res = await token(params);
      expect(res.status, name).toBe(400);
      expect(await res.json(), name).toMatchObject({ error: "invalid_grant" });
    }
    const otherClient = await exchange(offlineClient, code);
    expect(await otherClient.json()).toMatchObject({ error: "invalid_grant" });
    // The code still works once, then never again; the replay kills the family.
    const first = (await (await exchange(web, code)).json()) as TokenBody;
    expect(first.refresh_token).toMatch(/^tio_rt_/);
    const replay = await exchange(web, code);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ error: "invalid_grant" });
    const rotated = await refresh(web, first.refresh_token as string);
    expect(rotated.status).toBe(400);
    expect(await rotated.json()).toMatchObject({ error: "invalid_grant" });
    // Expired codes.
    const late = await login(web, user, { scope: "openid" });
    clock.advance(60);
    expect(await (await exchange(web, late.code)).json()).toMatchObject({ error: "invalid_grant" });
  });

  it("[TIO-TOKEN-014] [TIO-RT-010] offline_access with an enabled client makes the family offline: no sid in the tokens and survival of the session's end", async () => {
    const user = await userWithPasskey(clock);
    const { code, session } = await login(offlineClient, user, {
      scope: "openid email offline_access",
    });
    const body = (await (await exchange(offlineClient, code)).json()) as TokenBody;
    const at = await verify(body.access_token, "at+jwt", offlineClient.client_id);
    expect(at.payload).not.toHaveProperty("sid");
    const id = await verify(body.id_token as string, "JWT", offlineClient.client_id);
    expect(id.payload).not.toHaveProperty("sid");
    // Revoke the session: the offline family still rotates.
    const sessions = await user.stub.listSessions(clock.now());
    for (const s of sessions.ok ? sessions.sessions : [])
      await user.stub.revokeSession(s.sid, clock.now(), "test");
    const rotated = await refresh(offlineClient, body.refresh_token as string);
    expect(rotated.status).toBe(200);
    const rotatedBody = (await rotated.json()) as TokenBody;
    // Reuse on an offline family revokes it without any session to end.
    const reused = await refresh(offlineClient, body.refresh_token as string);
    expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
    expect(h.lines.find((l) => l["msg"] === "refresh token reuse detected")).toMatchObject({
      revoked_session_clients: [],
    });
    expect(
      (await verify(rotatedBody.id_token as string, "JWT", offlineClient.client_id)).payload,
    ).not.toHaveProperty("sid");
    expect(session).toMatch(/^__Host-tio_session=/);
    // The same client without offline_access in the request gets a session family.
    const bound = await login(offlineClient, user, { scope: "openid email" });
    const boundBody = (await (await exchange(offlineClient, bound.code)).json()) as TokenBody;
    expect(
      (await verify(boundBody.access_token, "at+jwt", offlineClient.client_id)).payload["sid"],
    ).toBeDefined();
  });
});

describe("POST /token: refresh_token", () => {
  it("[TIO-RT-001] [TIO-RT-002] [TIO-RT-003] [TIO-RT-005] [TIO-RT-006] rotates the token, keeps the session context in the new ID token without a nonce, detects reuse and ends session-bound families with the session", async () => {
    const user = await userWithPasskey(clock);
    const { code } = await login(web, user, { nonce: "n-1", scope: "openid email" });
    const first = (await (await exchange(web, code)).json()) as TokenBody;
    clock.advance(30);
    const rotated = await refresh(web, first.refresh_token as string);
    expect(rotated.status).toBe(200);
    expect(rotated.headers.get("cache-control")).toBe("no-store");
    const second = (await rotated.json()) as TokenBody;
    expect(second.refresh_token).toMatch(/^tio_rt_/);
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(second.scope).toBe("openid email");
    const id = await verify(second.id_token as string, "JWT", web.client_id);
    const original = await verify(first.id_token as string, "JWT", web.client_id);
    expect(id.payload).not.toHaveProperty("nonce");
    expect(id.payload["auth_time"]).toBe(original.payload["auth_time"]);
    expect(id.payload["sid"]).toBe(original.payload["sid"]);
    expect(id.payload["amr"]).toEqual(["swk", "user"]);
    expect(id.payload["iat"]).toBe(clock.now());
    expect(h.lines.filter((l) => l["route"] === "/token").at(-1)).toMatchObject({
      route: "/token",
      status: 200,
      do_calls: 1,
      d1_writes: 0,
    });
    // Malformed or missing handles never reach storage.
    const garbage = await refresh(web, "tio_rt_garbage");
    expect(await garbage.json()).toMatchObject({ error: "invalid_grant" });
    expect(h.lines.at(-1)).toMatchObject({ do_calls: 0 });
    const missing = await token({ grant_type: "refresh_token", client_id: web.client_id });
    expect(await missing.json()).toMatchObject({ error: "invalid_grant" });
    // Reuse of the consumed token: the family and its session are gone.
    const reuse = await refresh(web, first.refresh_token as string);
    expect(reuse.status).toBe(400);
    expect(await reuse.json()).toMatchObject({ error: "invalid_grant" });
    const afterReuse = await refresh(web, second.refresh_token as string);
    expect(await afterReuse.json()).toMatchObject({ error: "invalid_grant" });
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toEqual([]);
    // Session-bound families die with the session.
    const again = await login(web, user, { scope: "openid" });
    const bound = (await (await exchange(web, again.code)).json()) as TokenBody;
    const live = await user.stub.listSessions(clock.now());
    for (const s of live.ok ? live.sessions : [])
      await user.stub.revokeSession(s.sid, clock.now(), "logout");
    expect(await (await refresh(web, bound.refresh_token as string)).json()).toMatchObject({
      error: "invalid_grant",
    });
    // Another client cannot use the token.
    const mine = await login(web, user, { scope: "openid" });
    const mineBody = (await (await exchange(web, mine.code)).json()) as TokenBody;
    expect(
      await (await refresh(offlineClient, mineBody.refresh_token as string)).json(),
    ).toMatchObject({ error: "invalid_grant" });
  });

  it("[TIO-RT-004] a scope parameter narrows the issued tokens only; widening or unknown scopes are invalid_scope", async () => {
    const user = await userWithPasskey(clock);
    const { code } = await login(web, user, { scope: "openid email profile" });
    const first = (await (await exchange(web, code)).json()) as TokenBody;
    const narrowed = await refresh(web, first.refresh_token as string, { scope: "openid" });
    expect(narrowed.status).toBe(200);
    const narrowedBody = (await narrowed.json()) as TokenBody;
    expect(narrowedBody.scope).toBe("openid");
    expect(
      (await verify(narrowedBody.id_token as string, "JWT", web.client_id)).payload,
    ).not.toHaveProperty("email");
    const widened = await refresh(web, narrowedBody.refresh_token as string, {
      scope: "openid email groups",
    });
    expect(widened.status).toBe(400);
    expect(await widened.json()).toMatchObject({ error: "invalid_scope" });
    const unknown = await refresh(web, narrowedBody.refresh_token as string, {
      scope: "openid banana",
    });
    expect(await unknown.json()).toMatchObject({ error: "invalid_scope" });
    const dup = await refresh(web, narrowedBody.refresh_token as string, {
      scope: "openid openid",
    });
    expect(await dup.json()).toMatchObject({ error: "invalid_scope" });
    // The family kept its full scope.
    const full = (await (
      await refresh(web, narrowedBody.refresh_token as string)
    ).json()) as TokenBody;
    expect(full.scope).toBe("openid email profile");
    // A token without openid in scope: none issued here since codes always carry openid; narrowing to email alone drops the ID token.
    const noOpenid = (await (
      await refresh(web, full.refresh_token as string, { scope: "email" })
    ).json()) as TokenBody;
    expect(noOpenid.id_token).toBeUndefined();
    expect(noOpenid.scope).toBe("email");
  });
});

describe("POST /token: client_credentials and common rules", () => {
  it("[TIO-TOKEN-020] [TIO-TOKEN-021] [TIO-TOKEN-033] issues a client token with sub = client_id and no ID or refresh token; user scopes are refused; admin adds the issuer audience", async () => {
    const basic = `Basic ${btoa(`${confidential.client.client_id}:${confidential.secret}`)}`;
    const res = await token(
      { grant_type: "client_credentials", scope: "admin" },
      { authorization: basic },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenBody;
    expect(body).toEqual({
      access_token: expect.any(String),
      token_type: "Bearer",
      expires_in: 600,
      scope: "admin",
    });
    const at = await verify(body.access_token, "at+jwt", ISSUER);
    expect(at.payload).toEqual({
      iss: ISSUER,
      sub: confidential.client.client_id,
      aud: [confidential.client.client_id, ISSUER],
      exp: clock.now() + 600,
      iat: clock.now(),
      jti: expect.any(String),
      client_id: confidential.client.client_id,
      scope: "admin",
    });
    const empty = (await (
      await token({ grant_type: "client_credentials" }, { authorization: basic })
    ).json()) as TokenBody;
    expect(empty.scope).toBe("");
    expect(
      (await verify(empty.access_token, "at+jwt", confidential.client.client_id)).payload["aud"],
    ).toBe(confidential.client.client_id);
    for (const scope of [
      "openid",
      "admin email",
      "offline_access",
      "groups",
      "account",
      "profile",
    ]) {
      const refused = await token(
        { grant_type: "client_credentials", scope },
        { authorization: basic },
      );
      expect(refused.status, scope).toBe(400);
      expect(await refused.json(), scope).toMatchObject({ error: "invalid_scope" });
    }
    expect(
      await (
        await token(
          { grant_type: "client_credentials", scope: "admin admin" },
          { authorization: basic },
        )
      ).json(),
    ).toMatchObject({ error: "invalid_scope" });
    // A client without the grant.
    const noGrant = await token({ grant_type: "client_credentials", client_id: web.client_id });
    expect(noGrant.status).toBe(400);
    expect(await noGrant.json()).toMatchObject({ error: "unauthorized_client" });
  });

  it("[TIO-TOKEN-001] [TIO-TOKEN-002] [TIO-TOKEN-005] refuses other content types, duplicate parameters, unknown grants and bad credentials with the RFC 6749 statuses", async () => {
    expect(
      (await token({ grant_type: "authorization_code" }, { contentType: "application/json" }))
        .status,
    ).toBe(400);
    const dup = await token(
      `grant_type=authorization_code&grant_type=refresh_token&client_id=${web.client_id}`,
    );
    expect(await dup.json()).toMatchObject({
      error: "invalid_request",
      error_description: "duplicate parameter",
    });
    const unsupported = await token({ grant_type: "password", client_id: web.client_id });
    expect(unsupported.status).toBe(400);
    expect(await unsupported.json()).toMatchObject({ error: "unsupported_grant_type" });
    const missing = await token({ client_id: web.client_id });
    expect(await missing.json()).toMatchObject({ error: "unsupported_grant_type" });
    const badSecret = await token(
      { grant_type: "client_credentials" },
      { authorization: `Basic ${btoa(`${confidential.client.client_id}:wrong`)}` },
    );
    expect(badSecret.status).toBe(401);
    expect(badSecret.headers.get("www-authenticate")).toBe('Basic realm="tiny-oidc"');
    expect(await badSecret.json()).toMatchObject({ error: "invalid_client" });
    const unknown = await token({ grant_type: "authorization_code", client_id: "nobody" });
    expect(unknown.status).toBe(401);
  });

  it("[TIO-ARCH-015] [TIO-RL-001] [TIO-TOKEN-004] answers 503 when storage is unavailable and 429 when the client exceeds its limit or an address fails client authentication too often, while its successful traffic is untouched", async () => {
    const user = await userWithPasskey(clock);
    const { code } = await login(web, user, { scope: "openid" });
    const brokenDo = {
      ...env,
      USER_DO: {
        idFromName: () => ({}) as DurableObjectId,
        get: () => {
          throw new Error("DO unavailable");
        },
      },
    } as unknown as Env;
    const down = await exchange(web, code);
    expect(down.status).toBe(200);
    const again = await login(web, user, { scope: "openid" });
    const unavailable = await token(
      {
        grant_type: "authorization_code",
        client_id: web.client_id,
        code: again.code,
        redirect_uri: RP_REDIRECT,
        code_verifier: VERIFIER,
      },
      { env: brokenDo },
    );
    expect(unavailable.status).toBe(503);
    expect(await unavailable.json()).toMatchObject({ error: "temporarily_unavailable" });
    const first = (await down.json()) as TokenBody;
    const refreshDown = await token(
      {
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: first.refresh_token as string,
      },
      { env: brokenDo },
    );
    expect(refreshDown.status).toBe(503);
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    // A fresh isolate with the client and settings cached but the signing keys never loaded.
    const fresh = harness(clock);
    const warm = await fresh.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=password&client_id=${web.client_id}`,
    });
    expect(warm.status).toBe(400);
    const keysDown = await fresh.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=authorization_code&client_id=${web.client_id}`,
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(keysDown.status).toBe(503);
    expect(await keysDown.json()).toMatchObject({
      error: "temporarily_unavailable",
      error_description: "keys or settings unavailable",
    });
    // The address class counts failed client authentication only (TIO-TOKEN-004, ADR 0012): once
    // exhausted, a wrong credential from that address is 429, a right one still gets a token.
    while ((await env.RL_IP.limit({ key: limitKey("ip_auth_failed", "198.51.100.44") })).success) {
      // exhaust
    }
    const limitedIp = await token(
      { grant_type: "client_credentials", client_id: web.client_id, client_secret: "wrong" },
      { ip: "198.51.100.44" },
    );
    expect(limitedIp.status).toBe(429);
    const stillServed = await token(
      {
        grant_type: "authorization_code",
        client_id: web.client_id,
        code: "tio_ac_x",
        redirect_uri: RP_REDIRECT,
        code_verifier: VERIFIER,
      },
      { ip: "198.51.100.44" },
    );
    expect(stillServed.status).toBe(400);
    expect(await stillServed.json()).toMatchObject({ error: "invalid_grant" });
    while ((await env.RL_CLIENT.limit({ key: limitKey("client_token", web.client_id) })).success) {
      // exhaust
    }
    const limitedClient = await exchange(web, "tio_ac_x");
    expect(limitedClient.status).toBe(429);
    expect(limitedClient.headers.get("retry-after")).toBe("10");
  });
});

describe("admin scope", () => {
  it("[TIO-SCOPE-002] [TIO-AUTHZ-009] the admin scope is granted only to members of admins at authentication (passkey and session hit), at the exchange and at every refresh", async () => {
    await insertGroup(
      db,
      { id: new UuidV7(clock).next(), name: "admins", description: null, system: true },
      clock.now(),
    );
    const adminClient = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        scopes_allowed: ["openid", "admin"],
      })
    ).client;
    const outsider = await userWithPasskey(clock);
    // Fresh authentication by a non-member fails the interaction.
    const started = await h.start(adminClient, { scope: "openid admin" });
    const options = await h.post(started, "passkey/options", {});
    const { publicKey } = (await options.json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const response = await outsider.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
    const verified = await h.post(started, "passkey/verify", { response });
    expect(await verified.json()).toMatchObject({ status: "failed" });
    // A session hit by a non-member is access_denied.
    const plain = await login(web, outsider, { scope: "openid" });
    const hit = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: adminClient.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid admin",
        state: "s",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
      })}`,
      { origin: null, cookie: plain.session },
    );
    expect(new URL(hit.headers.get("location") as string).searchParams.get("error")).toBe(
      "access_denied",
    );
    // A member gets the scope; losing membership breaks the refresh.
    const admin = await userWithPasskey(clock, { groups: ["admins"] });
    const { code } = await login(adminClient, admin, { scope: "openid admin" });
    const issued = (await (await exchange(adminClient, code)).json()) as TokenBody;
    expect(issued.scope).toBe("openid admin");
    const at = await verify(issued.access_token, "at+jwt", ISSUER);
    expect(at.payload["aud"]).toEqual([adminClient.client_id, ISSUER]);
    await runInDurableObject(admin.stub, (instance: UserDO) => {
      instance.setGroups([], clock.now());
    });
    const refreshed = await refresh(adminClient, issued.refresh_token as string);
    expect(await refreshed.json()).toMatchObject({ error: "invalid_grant" });
    // Membership lost between the code and its exchange.
    const demoted = await userWithPasskey(clock, { groups: ["admins"] });
    const late = await login(adminClient, demoted, { scope: "openid admin" });
    await runInDurableObject(demoted.stub, (instance: UserDO) => {
      instance.setGroups([], clock.now());
    });
    expect(await (await exchange(adminClient, late.code)).json()).toMatchObject({
      error: "invalid_grant",
    });
  });
});

describe("disabled clients", () => {
  it("[TIO-CLIENT-004] [TIO-ARCH-011] a disabled client fails at /par, the code, client-credentials and refresh grants within 60 s; its refresh families are revoked on use and stay dead after the client is enabled again", async () => {
    const created = await createTestClient(db, clock, {
      redirect_uris: [RP_REDIRECT],
      skip_consent: true,
    });
    const client = created.client;
    const user = await userWithPasskey(clock);
    const { code } = await login(client, user, { scope: "openid" });
    const first = (await (await exchange(client, code)).json()) as TokenBody;
    const survivor = (await (
      await exchange(client, (await login(client, user, { scope: "openid" })).code)
    ).json()) as TokenBody;
    const parBody = {
      client_id: client.client_id,
      redirect_uri: RP_REDIRECT,
      response_type: "code",
      scope: "openid",
      state: "s",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
    };
    const par = () =>
      h.send("/par", {
        method: "POST",
        origin: null,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(parBody).toString(),
      });
    expect((await par()).status).toBe(201);

    await setClientDisabled(db, client.client_id, clock.now(), clock.now());
    // The isolate cache still says enabled for up to 60 s (TIO-ARCH-011).
    expect((await par()).status).toBe(201);
    clock.advance(60);
    const pushed = await par();
    expect(pushed.status).toBe(401);
    expect(await pushed.json()).toMatchObject({ error: "invalid_client" });
    const pending = await login(client, user, { scope: "openid" }).catch(() => null);
    expect(pending).toBeNull();
    const credentials = await token({
      grant_type: "client_credentials",
      client_id: client.client_id,
    });
    expect(credentials.status).toBe(401);
    // The refresh grant answers invalid_grant and revokes the family it presents.
    const rotated = await refresh(client, first.refresh_token as string);
    expect(rotated.status).toBe(400);
    expect(await rotated.json()).toMatchObject({
      error: "invalid_grant",
      error_description: "client is disabled",
    });
    for (const body of [
      { grant_type: "refresh_token", client_id: client.client_id, refresh_token: "tio_rt_x" },
      { grant_type: "refresh_token", client_id: client.client_id },
    ]) {
      const garbage = await token(body);
      expect(garbage.status).toBe(400);
      expect(await garbage.json()).toMatchObject({
        error: "invalid_grant",
        error_description: "refresh_token is invalid",
      });
    }
    const brokenDo = {
      ...env,
      USER_DO: {
        idFromName: () => ({}) as DurableObjectId,
        get: () => {
          throw new Error("DO unavailable");
        },
      },
    } as unknown as Env;
    const down = await token(
      {
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: survivor.refresh_token as string,
      },
      { env: brokenDo },
    );
    expect(down.status).toBe(503);

    await setClientDisabled(db, client.client_id, null, clock.now());
    clock.advance(60);
    expect((await par()).status).toBe(201);
    // The family used while disabled is gone for good; the untouched one still rotates.
    const dead = await refresh(client, first.refresh_token as string);
    expect(dead.status).toBe(400);
    expect(await dead.json()).toMatchObject({
      error: "invalid_grant",
      error_description: "refresh_token is invalid, expired or revoked",
    });
    expect((await refresh(client, survivor.refresh_token as string)).status).toBe(200);
    const reasons = await runInDurableObject(user.stub, (_instance: UserDO, state) =>
      state.storage.sql
        .exec<{ revoke_reason: string | null }>("SELECT revoke_reason FROM refresh_families")
        .toArray()
        .map((row) => row.revoke_reason)
        .sort(),
    );
    expect(reasons).toHaveLength(2);
    expect(reasons).toContain("client_disabled");
    expect(reasons).toContain(null);
  });
});
