import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { KeyStore } from "../../src/crypto/keystore.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { UserDO } from "../../src/do/UserDO.ts";
import type { Env } from "../../src/env.ts";
import { verifyAccessToken } from "../../src/oidc/bearer.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";

const ISSUER = "https://auth.example.com";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

interface TokenBody {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  scope: string;
}

let web: Client;
let api: Client;
let confidential: { client: Client; secret: string | null };

async function tokensFor(
  client: Client,
  user: PasskeyUser,
  scope: string,
): Promise<TokenBody & { session: string }> {
  const started = await h.start(client, { scope });
  const options = await h.post(started, "passkey/options", {});
  const { publicKey } = (await options.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  expect((await h.post(started, "passkey/verify", { response })).status).toBe(200);
  const complete = await h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie: started.cookie,
  });
  const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
  const session = complete.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`)) as string;
  const res = await h.send("/token", {
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
  expect(res.status).toBe(200);
  return { ...((await res.json()) as TokenBody), session: session.slice(0, session.indexOf(";")) };
}

const userinfo = (
  init: {
    method?: string;
    bearer?: string;
    form?: string;
    query?: string;
    headers?: Record<string, string>;
    env?: Env;
  } = {},
) => {
  const headers: Record<string, string> = { ...init.headers };
  if (init.bearer !== undefined) headers["authorization"] = `Bearer ${init.bearer}`;
  const options: Parameters<typeof h.send>[1] = {
    method: init.method ?? "GET",
    origin: null,
    headers,
  };
  if (init.form !== undefined) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    options.body = init.form;
  }
  if (init.env) options.env = init.env;
  return h.send(`/userinfo${init.query ?? ""}`, options);
};

const revoke = (client: Client, body: Record<string, string>, authorization?: string) => {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (authorization !== undefined) headers["authorization"] = authorization;
  return h.send("/revoke", {
    method: "POST",
    origin: null,
    headers,
    body: new URLSearchParams({ client_id: client.client_id, ...body }).toString(),
  });
};

const clientCredentials = async (scope: string) => {
  const res = await h.send("/token", {
    method: "POST",
    origin: null,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${confidential.client.client_id}:${confidential.secret}`)}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope }).toString(),
  });
  return ((await res.json()) as TokenBody).access_token;
};

describe("GET|POST /userinfo", () => {
  it("[TIO-UINFO-001] [TIO-UINFO-002] [TIO-TOKEN-034] answers the current profile filtered by the token's scope, from the bearer header or the POST form, and refuses query-string tokens", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    api = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        audiences: ["https://api.example.com"],
      })
    ).client;
    confidential = await createTestClient(db, clock, {
      redirect_uris: [RP_REDIRECT],
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes_allowed: ["openid", "admin"],
    });
    const user = await userWithPasskey(clock, { display_name: "Alice" });
    const tokens = await tokensFor(web, user, "openid email profile");
    const res = await userinfo({ bearer: tokens.access_token });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(await res.json()).toEqual({
      sub: user.profile.id,
      name: "Alice",
      updated_at: user.profile.updated_at,
      email: user.profile.email,
      email_verified: true,
    });
    // Fresh from the DO, not from the token.
    await user.stub.setGroups(["staff"], clock.now());
    const groupsToken = await tokensFor(web, user, "openid groups");
    const withGroups = await userinfo({ bearer: groupsToken.access_token });
    expect(await withGroups.json()).toEqual({ sub: user.profile.id, groups: ["staff"] });
    await user.stub.setGroups(["staff", "admins"], clock.now());
    expect(await (await userinfo({ bearer: groupsToken.access_token })).json()).toEqual({
      sub: user.profile.id,
      groups: ["admins", "staff"],
    });
    const onlyOpenid = await tokensFor(web, user, "openid");
    expect(await (await userinfo({ bearer: onlyOpenid.access_token })).json()).toEqual({
      sub: user.profile.id,
    });
    // POST with the form field, POST with the header, and the query string refused.
    const viaForm = await userinfo({ method: "POST", form: `access_token=${tokens.access_token}` });
    expect(viaForm.status).toBe(200);
    const viaHeaderPost = await userinfo({ method: "POST", bearer: tokens.access_token });
    expect(viaHeaderPost.status).toBe(200);
    const viaQuery = await userinfo({ query: `?access_token=${tokens.access_token}` });
    expect(viaQuery.status).toBe(401);
    expect(viaQuery.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
    // A token whose audience is only the client's API is not for the OP (TIO-TOKEN-033/034);
    // the account scope adds the issuer and makes it acceptable.
    const apiTokens = await tokensFor(api, user, "openid");
    expect((await userinfo({ bearer: apiTokens.access_token })).status).toBe(401);
    const accountClient = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        audiences: ["https://api.example.com"],
        scopes_allowed: ["openid", "account"],
      })
    ).client;
    const accountTokens = await tokensFor(accountClient, user, "openid account");
    expect((await userinfo({ bearer: accountTokens.access_token })).status).toBe(200);
  });

  it("[TIO-UINFO-001] [TIO-UINFO-003] [TIO-TOKEN-034] rejects missing, malformed, expired, foreign, ID and client tokens and disabled users with 401 invalid_token and no details", async () => {
    const user = await userWithPasskey(clock);
    const tokens = await tokensFor(web, user, "openid email");
    const cases: [string, Parameters<typeof userinfo>[0]][] = [
      ["no credentials", {}],
      ["basic scheme", { headers: { authorization: "Basic abc" } }],
      ["garbage", { bearer: "garbage" }],
      ["id token", { bearer: tokens.id_token as string }],
      ["refresh token", { bearer: tokens.refresh_token as string }],
      ["client token", { bearer: await clientCredentials("admin") }],
      ["json body", { method: "POST", headers: { "content-type": "application/json" } }],
      ["bare POST", { method: "POST" }],
      ["empty form", { method: "POST", form: "" }],
    ];
    for (const [name, init] of cases) {
      const res = await userinfo(init);
      expect(res.status, name).toBe(401);
      expect(res.headers.get("www-authenticate"), name).toBe('Bearer error="invalid_token"');
      const body = (await res.json()) as Record<string, string>;
      expect(body, name).toMatchObject({
        error: "invalid_token",
        error_description: "invalid token",
      });
    }
    // Expiry with no leeway.
    clock.advance(600);
    const expired = await userinfo({ bearer: tokens.access_token });
    expect(expired.status).toBe(401);
    // Disabled user.
    const other = await userWithPasskey(clock);
    const otherTokens = await tokensFor(web, other, "openid");
    await other.stub.setDisabled(clock.now(), clock.now());
    expect((await userinfo({ bearer: otherTokens.access_token })).status).toBe(401);
    // Keys unavailable.
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const fresh = harness(clock);
    const down = await fresh.send("/userinfo", {
      origin: null,
      headers: { authorization: `Bearer ${otherTokens.access_token}` },
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(down.status).toBe(503);
  });
});

describe("verifyAccessToken for the OP's own APIs", () => {
  it("[TIO-TOKEN-034] accepts only tokens whose audience contains the issuer when the client audience is not acceptable", async () => {
    const user = await userWithPasskey(clock);
    const keys = await new KeyStore(clock).get(db, testKeys());
    const clientOnly = await tokensFor(web, user, "openid");
    expect(await verifyAccessToken(keys, clientOnly.access_token, ISSUER, clock, false)).toBeNull();
    const admin = await clientCredentials("admin");
    const accepted = await verifyAccessToken(keys, admin, ISSUER, clock, false);
    expect(accepted).toMatchObject({
      client_id: confidential.client.client_id,
      scopes: ["admin"],
      auth_time: null,
      sid: null,
    });
  });
});

describe("POST /revoke", () => {
  it("[TIO-REV-001] [TIO-REV-002] revokes the whole family of the client's refresh token, ignores tokens of other clients and unknown tokens, always with 200 and an empty body", async () => {
    const user = await userWithPasskey(clock);
    const tokens = await tokensFor(web, user, "openid");
    const res = await revoke(web, {
      token: tokens.refresh_token as string,
      token_type_hint: "refresh_token",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const rotate = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: tokens.refresh_token as string,
      }).toString(),
    });
    expect(await rotate.json()).toMatchObject({ error: "invalid_grant" });
    // Again, and unknown tokens: still 200.
    expect((await revoke(web, { token: tokens.refresh_token as string })).status).toBe(200);
    expect((await revoke(web, { token: "tio_rt_garbage" })).status).toBe(200);
    expect((await revoke(web, { token: "not-a-token" })).status).toBe(200);
    expect((await revoke(web, { token: "a.b.c" })).status).toBe(200);
    // A token of another client is ignored.
    const mine = await tokensFor(web, user, "openid");
    expect((await revoke(api, { token: mine.refresh_token as string })).status).toBe(200);
    expect(h.lines.at(-1)).toMatchObject({ route: "/revoke", status: 200 });
    expect(h.lines.some((l) => l["msg"] === "token.revoke_foreign")).toBe(true);
    const stillValid = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: mine.refresh_token as string,
      }).toString(),
    });
    expect(stillValid.status).toBe(200);
    // Request rules: client authentication and the token parameter.
    const noToken = await revoke(web, {});
    expect(noToken.status).toBe(400);
    expect(await noToken.json()).toMatchObject({ error: "invalid_request" });
    const badClient = await revoke(
      confidential.client,
      { token: "x" },
      `Basic ${btoa(`${confidential.client.client_id}:wrong`)}`,
    );
    expect(badClient.status).toBe(401);
    const badForm = await h.send("/revoke", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(badForm.status).toBe(400);
  });

  it("[TIO-REV-003] an access token with a sid revokes the client's session-bound family; other access tokens are accepted with no effect", async () => {
    const user = await userWithPasskey(clock);
    const tokens = await tokensFor(web, user, "openid");
    expect(
      (await revoke(web, { token: tokens.access_token, token_type_hint: "access_token" })).status,
    ).toBe(200);
    const rotate = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: tokens.refresh_token as string,
      }).toString(),
    });
    expect(await rotate.json()).toMatchObject({ error: "invalid_grant" });
    // The session itself survives.
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toHaveLength(1);
    // Another client's access token: no effect on the first client's families.
    const again = await tokensFor(web, user, "openid");
    const theirs = await tokensFor(api, user, "openid");
    expect((await revoke(web, { token: theirs.access_token })).status).toBe(200);
    const stillValid = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: web.client_id,
        refresh_token: again.refresh_token as string,
      }).toString(),
    });
    expect(stillValid.status).toBe(200);
    // A client token has no sid: accepted, nothing to revoke.
    const clientToken = await clientCredentials("admin");
    expect(
      (
        await revoke(
          confidential.client,
          { token: clientToken },
          `Basic ${btoa(`${confidential.client.client_id}:${confidential.secret}`)}`,
        )
      ).status,
    ).toBe(200);
    // A token of a user whose object is gone: nothing to revoke, still 200.
    const ghost = await userWithPasskey(clock);
    const ghostTokens = await tokensFor(web, ghost, "openid");
    await runInDurableObject(ghost.stub, async (instance: UserDO) => {
      await instance.destroy();
    });
    expect((await revoke(web, { token: ghostTokens.access_token })).status).toBe(200);
    // Per-address limit on failed client authentication only (TIO-TOKEN-004): a public client's
    // well-formed revocation from that address still answers 200.
    while ((await env.RL_IP.limit({ key: limitKey("ip_auth_failed", "198.51.100.77") })).success) {
      // exhaust
    }
    const fromAddress = (body: string) =>
      h.send("/revoke", {
        method: "POST",
        origin: null,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": "198.51.100.77",
        },
        body,
      });
    const limitedRes = await fromAddress(`client_id=${web.client_id}&client_secret=wrong&token=x`);
    expect(limitedRes.status).toBe(429);
    expect((await fromAddress(`client_id=${web.client_id}&token=x`)).status).toBe(200);
    // Keys unavailable while checking a JWT.
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const fresh = harness(clock);
    const warm = await fresh.send("/revoke", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${web.client_id}`,
    });
    expect(warm.status).toBe(400);
    const down = await fresh.send("/revoke", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${web.client_id}&token=${tokens.access_token}`,
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(down.status).toBe(503);
  });
});
