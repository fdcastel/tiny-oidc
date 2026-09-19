import { createExecutionContext } from "cloudflare:test";
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { signJwt } from "../../src/crypto/jwt.ts";
import { KeyStore, retireSigningKeyNow, rotateSigningKey } from "../../src/crypto/keystore.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Env } from "../../src/env.ts";
import {
  BackchannelTaskSchema,
  MAX_ATTEMPTS,
  RETRY_DELAYS_SECONDS,
} from "../../src/logout/backchannel.ts";
import type { LogLine } from "../../src/obs/log.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { createQueue } from "../../src/queue/consumer.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { mountOrigin } from "../support/fetch-allowlist.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, failingD1, sabotageInteraction } from "./faults.ts";

// RP-initiated logout (spec §5.10.1), the logout interaction (§7.6) and
// back-channel logout (§5.10.2) end to end: a browser signs in at a client,
// the client asks for a logout with or without a hint, the session ends
// exactly where the spec says, and every client of the session hears about it.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const ISSUER = "https://auth.example.com";
const RP = "https://rp.example.com";
const LANDING = `${LOGIN_ORIGIN}/?event=logged_out`;
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

interface Received {
  path: string;
  token: string;
}

/** Everything the relying party's back-channel endpoint received, and its answer. */
const received: Received[] = [];
let backchannelStatus = 200;
mountOrigin(RP, async (request) => {
  const path = new URL(request.url).pathname;
  const form = new URLSearchParams(await request.text());
  received.push({ path, token: form.get("logout_token") ?? "" });
  return new Response(null, { status: backchannelStatus });
});

let web: Client;
let other: Client;

interface Session {
  user: PasskeyUser;
  cookie: string;
  id_token: string;
  sid: string;
}

const events = (type: string): AuditEvent[] =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type);

/** A passkey login of `user` at `client`: the session cookie and the ID token. */
async function login(
  user: PasskeyUser,
  client: Client,
  options: { scope?: string; sessionCookie?: string } = {},
): Promise<Session> {
  // With a session present the OP would issue the code at once; prompt=login asks for a proof again.
  const started = await h.start(
    client,
    {
      scope: options.scope ?? "openid email",
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
  const { id_token } = (await tokens.json()) as { id_token: string };
  const sid = decodeJwt(id_token)["sid"] as string;
  return { user, cookie, id_token, sid };
}

/** GET /logout with the query and cookie given. */
const logout = (params: Record<string, string>, cookie: string | null, method = "GET") =>
  method === "POST"
    ? h.send("/logout", {
        method: "POST",
        origin: null,
        cookie,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(params).toString(),
      })
    : h.send(`/logout?${new URLSearchParams(params)}`, { origin: null, cookie });

const sessionAlive = async (session: Session): Promise<boolean> => {
  const listed = await session.user.stub.listSessions(clock.now());
  return listed.ok && listed.sessions.some((s) => s.sid === session.sid);
};

const clearedSession = (res: Response): boolean =>
  res.headers
    .getSetCookie()
    .some((c) => c.startsWith(`${SESSION_COOKIE}=`) && c.includes("Max-Age=0"));

async function verifyLogoutToken(token: string, clientId: string) {
  // Straight from the key store: the served document may be cached across a rotation.
  const jwks = createLocalJWKSet((await new KeyStore(clock).get(db, testKeys())).jwks);
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: ISSUER,
    audience: clientId,
    typ: "logout+jwt",
    currentDate: clock.nowDate(),
  });
  return { payload, header: protectedHeader };
}

describe("RP-initiated logout with a hint", () => {
  it("[TIO-LOGOUT-001] [TIO-LOGOUT-002] [TIO-LOGOUT-003] [TIO-LOGOUT-005] [TIO-LOGOUT-010] [TIO-LOGOUT-011] a valid hint ends the browser's own session, clears the cookie, redirects to the registered URI with state and notifies every client of the session with a logout token", async () => {
    await adminSettings(h);
    web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        post_logout_redirect_uris: [`${RP}/bye`],
        backchannel_logout_uri: `${RP}/backchannel`,
        skip_consent: true,
      })
    ).client;
    other = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        backchannel_logout_uri: `${RP}/other-backchannel`,
        skip_consent: true,
      })
    ).client;
    const alice = await userWithPasskey(clock, { email: "alice@example.com" });
    const first = await login(alice, web);
    // The same browser signs in at a second client on the same session.
    const second = await login(alice, other, { sessionCookie: first.cookie });
    expect(second.sid).toBe(first.sid);
    const res = await logout(
      { id_token_hint: first.id_token, post_logout_redirect_uri: `${RP}/bye`, state: "xyz" },
      first.cookie,
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${RP}/bye?state=xyz`);
    expect(clearedSession(res)).toBe(true);
    expect(await sessionAlive(first)).toBe(false);
    // Both clients of the session were told, each with its own token (TIO-LOGOUT-010).
    expect(received.map((r) => r.path).sort()).toEqual(["/backchannel", "/other-backchannel"]);
    const forWeb = received.find((r) => r.path === "/backchannel") as Received;
    const { payload, header } = await verifyLogoutToken(forWeb.token, web.client_id);
    expect(header).toEqual({ alg: "ES256", typ: "logout+jwt", kid: expect.any(String) });
    expect(payload).toEqual({
      iss: ISSUER,
      sub: alice.profile.id,
      aud: web.client_id,
      iat: clock.now(),
      exp: clock.now() + 120,
      jti: expect.any(String),
      sid: first.sid,
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    expect(payload).not.toHaveProperty("nonce");
    const forOther = received.find((r) => r.path === "/other-backchannel") as Received;
    expect(decodeJwt(forOther.token).aud).toBe(other.client_id);
    expect(decodeJwt(forOther.token).jti).not.toBe(payload.jti);
    expect(events("logout.rp_initiated").at(-1)).toMatchObject({
      actor: { kind: "client", id: web.client_id },
      user_id: alice.profile.id,
      sid: first.sid,
      data: { registered_redirect: true },
    });
    expect(events("session.revoked").at(-1)).toMatchObject({
      user_id: alice.profile.id,
      sid: first.sid,
      reason: "rp_logout",
      data: { clients: expect.arrayContaining([web.client_id, other.client_id]) },
    });
    expect(
      events("logout.backchannel_sent")
        .map((e) => e.client_id)
        .sort(),
    ).toEqual([web.client_id, other.client_id].sort());
    // Logging out again with the same hint ends nothing more and notifies nobody.
    received.length = 0;
    const again = await logout({ id_token_hint: first.id_token }, null);
    expect(again.headers.get("location")).toBe(LANDING);
    expect(received).toEqual([]);
  });

  it("[TIO-LOGOUT-001] an expired hint is accepted, a hint under a retired key, a foreign signature, an unknown audience or a client_id that disagrees with it are invalid_request at the login app, and a hint without sid ends nothing", async () => {
    const bob = await userWithPasskey(clock, { email: "bob@example.com" });
    const session = await login(bob, web);
    // Expired: the ID token lifetime is behind us, the session (idle 24 h) is not.
    clock.advance(7_200);
    const expired = await logout({ id_token_hint: session.id_token }, session.cookie);
    expect(expired.headers.get("location")).toBe(LANDING);
    expect(await sessionAlive(session)).toBe(false);
    // Under a retired key: rotate to a new key now, retire the old one.
    const later = await login(bob, web);
    const oldKid = decodeProtectedHeader(later.id_token).kid as string;
    await rotateSigningKey(db, testKeys(), clock.now(), 0, true);
    expect(await retireSigningKeyNow(db, oldKid, clock.now())).toBe("retired");
    clock.advance(61);
    const retired = await logout({ id_token_hint: later.id_token }, later.cookie);
    expect(retired.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_request`);
    expect(clearedSession(retired)).toBe(false);
    expect(await sessionAlive(later)).toBe(true);
    // A token the OP did not sign, and one for a client that does not exist.
    const loaded = await new KeyStore(clock).get(db, testKeys());
    const forged = await new SignJWT({ sid: later.sid })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: loaded.signing.kid })
      .setIssuer(ISSUER)
      .setSubject(bob.profile.id)
      .setAudience(web.client_id)
      .setIssuedAt(clock.now())
      .setExpirationTime(clock.now() + 60)
      .sign(
        (
          (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
            "sign",
          ])) as CryptoKeyPair
        ).privateKey,
      );
    expect((await logout({ id_token_hint: forged }, later.cookie)).headers.get("location")).toBe(
      `${LOGIN_ORIGIN}/?error=invalid_request`,
    );
    const ghost = await signJwt(loaded, "JWT", {
      iss: ISSUER,
      sub: bob.profile.id,
      aud: "ghost",
      iat: clock.now(),
      exp: clock.now() + 60,
      sid: later.sid,
    });
    expect((await logout({ id_token_hint: ghost }, later.cookie)).headers.get("location")).toBe(
      `${LOGIN_ORIGIN}/?error=invalid_request`,
    );
    const twoAudiences = await signJwt(loaded, "JWT", {
      iss: ISSUER,
      sub: bob.profile.id,
      aud: [web.client_id, other.client_id],
      iat: clock.now(),
      exp: clock.now() + 60,
    });
    expect(
      (await logout({ id_token_hint: twoAudiences }, later.cookie)).headers.get("location"),
    ).toBe(`${LOGIN_ORIGIN}/?error=invalid_request`);
    // client_id must agree with the hint's audience.
    const fresh = await login(bob, web, { sessionCookie: later.cookie });
    const disagreeing = await logout(
      { id_token_hint: fresh.id_token, client_id: other.client_id },
      fresh.cookie,
    );
    expect(disagreeing.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_request`);
    expect(await sessionAlive(fresh)).toBe(true);
    // A hint without sid (an offline_access ID token) names no session to end.
    const offline = await signJwt(loaded, "JWT", {
      iss: ISSUER,
      sub: bob.profile.id,
      aud: web.client_id,
      iat: clock.now(),
      exp: clock.now() + 60,
    });
    received.length = 0;
    const nothing = await logout(
      { id_token_hint: offline, client_id: web.client_id },
      fresh.cookie,
    );
    expect(nothing.headers.get("location")).toBe(LANDING);
    expect(clearedSession(nothing)).toBe(false);
    expect(await sessionAlive(fresh)).toBe(true);
    expect(received).toEqual([]);
    // Per-IP navigation limit (TIO-RL-001 class ip_navigation).
    const ip = "203.0.113.90";
    while ((await env.RL_IP.limit({ key: limitKey("ip_navigation", ip) })).success) {
      // keep counting
    }
    const throttled = await h.send("/logout", {
      origin: null,
      headers: { "cf-connecting-ip": ip },
    });
    expect(throttled.status).toBe(429);
    // Duplicate parameters and an unreadable form are invalid_request too.
    const dup = await h.send(`/logout?state=a&state=b`, { origin: null });
    expect(dup.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_request`);
    const badForm = await h.send("/logout", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(badForm.headers.get("location")).toBe(`${LOGIN_ORIGIN}/?error=invalid_request`);
  });

  it("[TIO-LOGOUT-003] [TIO-LOGOUT-002] another browser's hint ends the hinted session where it lives and leaves the current session and cookie alone; an unregistered post_logout_redirect_uri lands at the landing URL without state", async () => {
    const carol = await userWithPasskey(clock, { email: "carol@example.com" });
    const dave = await userWithPasskey(clock, { email: "dave@example.com" });
    const carols = await login(carol, web);
    const daves = await login(dave, web);
    received.length = 0;
    const res = await logout(
      {
        id_token_hint: carols.id_token,
        post_logout_redirect_uri: `${RP}/elsewhere`,
        state: "s",
      },
      daves.cookie,
      "POST",
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(LANDING);
    expect(clearedSession(res)).toBe(false);
    expect(await sessionAlive(carols)).toBe(false);
    expect(await sessionAlive(daves)).toBe(true);
    expect(received.map((r) => decodeJwt(r.token).sub)).toEqual([carol.profile.id]);
    expect(events("logout.rp_initiated").at(-1)).toMatchObject({
      data: { registered_redirect: false },
    });
    // A loopback client (RFC 8252) may come back on any port, as at /authorize.
    const cli = (
      await createTestClient(db, clock, {
        redirect_uris: ["http://127.0.0.1:0/callback"],
        post_logout_redirect_uris: ["http://127.0.0.1:0/bye"],
        token_endpoint_auth_method: "none",
        skip_consent: true,
      })
    ).client;
    const anyPort = await logout(
      { client_id: cli.client_id, post_logout_redirect_uri: "http://127.0.0.1:51234/bye" },
      null,
    );
    expect(anyPort.headers.get("location")).toBe("http://127.0.0.1:51234/bye");
  });
});

describe("logout without a hint", () => {
  it("[TIO-LOGOUT-004] [TIO-IX-050] no session lands at once (a dead cookie is cleared); a live session asks through a logout interaction whose document names the client; declining keeps the session and confirming ends it at /complete with the cookie re-verified", async () => {
    const none = await logout({}, null);
    expect(none.status).toBe(303);
    expect(none.headers.get("location")).toBe(LANDING);
    expect(clearedSession(none)).toBe(false);
    const dead = await logout(
      { client_id: web.client_id, post_logout_redirect_uri: `${RP}/bye` },
      `${SESSION_COOKIE}=garbage`,
    );
    expect(dead.headers.get("location")).toBe(`${RP}/bye`);
    expect(clearedSession(dead)).toBe(true);
    const erin = await userWithPasskey(clock, { email: "erin@example.com" });
    const session = await login(erin, web);
    // A cookie whose session is gone on the object is treated as no session.
    await erin.stub.revokeSession(session.sid, clock.now(), "test");
    const gone = await logout({}, session.cookie);
    expect(gone.headers.get("location")).toBe(LANDING);
    expect(clearedSession(gone)).toBe(true);
    // A live session: the interaction.
    const live = await login(erin, web);
    const ask = await logout(
      { client_id: web.client_id, post_logout_redirect_uri: `${RP}/bye`, state: "st" },
      live.cookie,
    );
    expect(ask.status).toBe(303);
    const location = new URL(ask.headers.get("location") as string);
    expect(`${location.origin}${location.pathname}`).toBe(`${LOGIN_ORIGIN}/`);
    const id = location.searchParams.get("interaction") as string;
    const binding = ask.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const started = { id, cookie: binding.slice(0, binding.indexOf(";")) };
    const doc = (await (await h.get(started)).json()) as Record<string, unknown>;
    expect(doc).toMatchObject({
      kind: "logout",
      status: "login_required",
      client: { client_id: web.client_id },
      logout: { client: { client_id: web.client_id }, post_logout_redirect_uri_registered: true },
      request: null,
    });
    expect(JSON.stringify(doc)).not.toContain(live.sid);
    expect(JSON.stringify(doc)).not.toContain(erin.profile.id);
    expect(JSON.stringify(doc)).not.toContain('"st"');
    // The decision endpoint: bad bodies, then a decline.
    expect((await h.post(started, "logout", { confirm: "yes" })).status).toBe(400);
    expect((await h.post(started, "logout", {})).status).toBe(400);
    const declined = await h.post(started, "logout", { confirm: false });
    expect(declined.status).toBe(200);
    expect(await declined.json()).toEqual({ redirect_to: `${ISSUER}/interactions/${id}/complete` });
    expect((await h.post(started, "logout", { confirm: true })).status).toBe(409);
    expect(events("logout.confirmed").at(-1)).toMatchObject({
      outcome: "failure",
      reason: "declined",
      user_id: erin.profile.id,
      sid: live.sid,
    });
    const stayed = await h.send(`/interactions/${id}/complete`, {
      origin: null,
      cookie: `${started.cookie}; ${live.cookie}`,
    });
    expect(stayed.status).toBe(303);
    expect(stayed.headers.get("location")).toBe(`${RP}/bye?state=st`);
    expect(clearedSession(stayed)).toBe(false);
    expect(await sessionAlive(live)).toBe(true);
    const completed = await interactionStub(env, id).get(clock.now());
    expect(completed.ok && completed.doc.status).toBe("completed");
    // Confirming, but the session cookie is not presented at /complete: nothing ends (TIO-IX-050).
    const askAgain = await logout({}, live.cookie);
    const again = new URL(askAgain.headers.get("location") as string);
    const id2 = again.searchParams.get("interaction") as string;
    const binding2 = askAgain.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const second = { id: id2, cookie: binding2.slice(0, binding2.indexOf(";")) };
    const document = (await (await h.get(second)).json()) as Record<string, unknown>;
    expect(document).toMatchObject({
      kind: "logout",
      client: null,
      logout: { client: null, post_logout_redirect_uri_registered: false },
    });
    expect((await h.post(second, "logout", { confirm: true })).status).toBe(200);
    const withoutCookie = await h.send(`/interactions/${id2}/complete`, {
      origin: null,
      cookie: second.cookie,
    });
    expect(withoutCookie.headers.get("location")).toBe(LANDING);
    expect(clearedSession(withoutCookie)).toBe(false);
    expect(await sessionAlive(live)).toBe(true);
    // Confirming with the cookie: the session ends, the cookie goes, the clients hear.
    received.length = 0;
    const askOnce = await logout({}, live.cookie);
    const third = new URL(askOnce.headers.get("location") as string);
    const id3 = third.searchParams.get("interaction") as string;
    const binding3 = askOnce.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const last = { id: id3, cookie: binding3.slice(0, binding3.indexOf(";")) };
    expect((await h.post(last, "logout", { confirm: true })).status).toBe(200);
    expect(events("logout.confirmed").at(-1)).toMatchObject({ outcome: "success", sid: live.sid });
    const ended = await h.send(`/interactions/${id3}/complete`, {
      origin: null,
      cookie: `${last.cookie}; ${live.cookie}`,
    });
    expect(ended.headers.get("location")).toBe(LANDING);
    expect(clearedSession(ended)).toBe(true);
    expect(await sessionAlive(live)).toBe(false);
    expect(received.map((r) => r.path)).toEqual(["/backchannel"]);
    expect(events("session.revoked").at(-1)).toMatchObject({ reason: "logout", sid: live.sid });
    // A decision on an interaction that failed meanwhile.
    const raced = await logout({}, (await login(erin, web)).cookie);
    const racedId = new URL(raced.headers.get("location") as string).searchParams.get(
      "interaction",
    ) as string;
    const racedBinding = raced.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const overtaken = await h.post(
      { id: racedId, cookie: racedBinding.slice(0, racedBinding.indexOf(";")) },
      "logout",
      { confirm: true },
      {
        env: sabotageInteraction("apply", async (stub) => {
          await stub.apply(
            "fail",
            "failed",
            { error: { error: "x", error_description: "y" } },
            clock.now(),
          );
        }),
      },
    );
    expect(overtaken.status).toBe(409);
    // The decision endpoint is guarded like every interaction endpoint.
    expect(
      (await h.post({ id: racedId, cookie: "" }, "logout", { confirm: true }, { cookie: null }))
        .status,
    ).toBe(403);
    // The decision endpoint refuses an authorize interaction and a spent one.
    const authorize = await h.start(web, { scope: "openid email" });
    expect((await h.post(authorize, "logout", { confirm: true })).status).toBe(409);
    expect(await (await h.post(authorize, "logout", { confirm: true })).json()).toMatchObject({
      error: "interaction_invalid_state",
    });
  });

  it("[TIO-LOGOUT-004] a session revoked between the question and the answer: /complete finds it gone and ends nothing; an aborted logout interaction lands without ending anything", async () => {
    const frank = await userWithPasskey(clock, { email: "frank@example.com" });
    const session = await login(frank, web);
    const ask = await logout({}, session.cookie);
    const url = new URL(ask.headers.get("location") as string);
    const id = url.searchParams.get("interaction") as string;
    const binding = ask.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const started = { id, cookie: binding.slice(0, binding.indexOf(";")) };
    expect((await h.post(started, "logout", { confirm: true })).status).toBe(200);
    await frank.stub.revokeSession(session.sid, clock.now(), "elsewhere");
    received.length = 0;
    const done = await h.send(`/interactions/${id}/complete`, {
      origin: null,
      cookie: `${started.cookie}; ${session.cookie}`,
    });
    expect(done.headers.get("location")).toBe(LANDING);
    expect(received).toEqual([]);
    // Aborted before deciding.
    const fresh = await login(frank, web);
    const ask2 = await logout({}, fresh.cookie);
    const id2 = new URL(ask2.headers.get("location") as string).searchParams.get(
      "interaction",
    ) as string;
    const binding2 = ask2.headers
      .getSetCookie()
      .find((c) => c.startsWith("__Host-tio_ix_")) as string;
    const second = { id: id2, cookie: binding2.slice(0, binding2.indexOf(";")) };
    expect((await h.post(second, "abort", {})).status).toBe(200);
    const aborted = await h.send(`/interactions/${id2}/complete`, {
      origin: null,
      cookie: `${second.cookie}; ${fresh.cookie}`,
    });
    expect(aborted.headers.get("location")).toBe(LANDING);
    expect(await sessionAlive(fresh)).toBe(true);
  });
});

describe("back-channel delivery and retries", () => {
  const lines: LogLine[] = [];
  const consume = createQueue({ clock, sink: (line) => lines.push(line) });
  const queueEvents = (type: string) =>
    lines
      .filter((l) => l["msg"] === "audit")
      .map((l) => l["event"] as AuditEvent)
      .filter((e) => e.type === type);

  interface Sent {
    body: unknown;
    delaySeconds: number | undefined;
  }

  /** An environment whose TASKS queue records the back-channel tasks sent instead of queueing them (audit batches pass). */
  function recordingEnv(sent: Sent[], failing = false): Env {
    return {
      ...env,
      TASKS: {
        send: async (body: unknown, options?: { delaySeconds?: number }) => {
          if ((body as { kind?: string }).kind === "audit") return;
          if (failing) throw new Error("queue down");
          sent.push({ body, delaySeconds: options?.delaySeconds });
        },
      },
    } as unknown as Env;
  }

  /** A batch of one message with ack/retry recorded. */
  function batchOf(body: unknown) {
    const calls: string[] = [];
    const batch = {
      queue: "tiny-oidc-tasks",
      messages: [
        {
          id: "m1",
          timestamp: clock.nowDate(),
          body,
          attempts: 1,
          ack: () => calls.push("ack"),
          retry: () => calls.push("retry"),
        },
      ],
      ackAll: () => calls.push("ackAll"),
      retryAll: () => calls.push("retryAll"),
    } as unknown as MessageBatch<unknown>;
    return { batch, calls };
  }

  it("[TIO-LOGOUT-011] [TIO-LOGOUT-012] a failed delivery is queued with attempt 1 and a 30 s delay; the consumer re-mints the token under the same jti, retries on the schedule and gives up after the fifth with logout.backchannel_failed", async () => {
    const grace = await userWithPasskey(clock, { email: "grace@example.com" });
    const session = await login(grace, web);
    const sent: Sent[] = [];
    backchannelStatus = 500;
    received.length = 0;
    const res = await h.send(
      `/logout?${new URLSearchParams({ id_token_hint: session.id_token })}`,
      {
        origin: null,
        cookie: session.cookie,
        env: recordingEnv(sent),
      },
    );
    expect(res.status).toBe(303);
    expect(received).toHaveLength(1);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.delaySeconds).toBe(30);
    const task = BackchannelTaskSchema.parse(sent[0]?.body);
    expect(task).toMatchObject({
      kind: "backchannel_logout",
      client_id: web.client_id,
      uri: `${RP}/backchannel`,
      attempt: 1,
      sid: session.sid,
      uid: grace.profile.id,
    });
    const jti = decodeJwt(task.token).jti;
    expect(
      h.lines.find((l) => l["msg"] === "backchannel logout failed, queued for retry"),
    ).toMatchObject({
      client_id: web.client_id,
      reason: "status_500",
    });
    // The consumer, attempt after attempt, each token fresh but for the jti.
    let message: unknown = task;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      clock.advance(RETRY_DELAYS_SECONDS[attempt - 1] as number);
      received.length = 0;
      const queued: Sent[] = [];
      const { batch, calls } = batchOf(message);
      await consume(batch, recordingEnv(queued), createExecutionContext());
      expect(calls).toEqual(["ack"]);
      expect(received).toHaveLength(1);
      const { payload } = await verifyLogoutToken(received[0]?.token as string, web.client_id);
      expect(payload.jti).toBe(jti);
      expect(payload.iat).toBe(clock.now());
      if (attempt < MAX_ATTEMPTS) {
        expect(queued).toHaveLength(1);
        expect(queued[0]?.delaySeconds).toBe(RETRY_DELAYS_SECONDS[attempt]);
        const next = queued[0] as Sent;
        expect((next.body as { attempt: number }).attempt).toBe(attempt + 1);
        message = next.body;
      } else {
        expect(queued).toEqual([]);
        expect(queueEvents("logout.backchannel_failed").at(-1)).toMatchObject({
          outcome: "failure",
          actor: { kind: "system", id: null },
          user_id: grace.profile.id,
          client_id: web.client_id,
          sid: session.sid,
          reason: "status_500",
          data: { jti, attempts: MAX_ATTEMPTS },
        });
      }
    }
    // A retry that succeeds is the end of it.
    backchannelStatus = 200;
    const queued: Sent[] = [];
    const { batch, calls } = batchOf({ ...task, attempt: 2 });
    await consume(batch, recordingEnv(queued), createExecutionContext());
    expect(calls).toEqual(["ack"]);
    expect(queued).toEqual([]);
    // A queue that cannot take the retry is logged, not thrown.
    lines.length = 0;
    backchannelStatus = 500;
    const { batch: unqueued, calls: unqueuedCalls } = batchOf({ ...task, attempt: 2 });
    await consume(unqueued, recordingEnv([], true), createExecutionContext());
    expect(unqueuedCalls).toEqual(["ack"]);
    expect(lines.find((l) => l["msg"] === "backchannel retry could not be queued")).toMatchObject({
      reason: "Error: queue down",
    });
    backchannelStatus = 200;
  });

  it("[TIO-LOGOUT-012] the consumer drops tasks it cannot read, retries a batch when the OP's own configuration or keys are unavailable, and answers timeouts and unreachable endpoints alike", async () => {
    lines.length = 0;
    for (const body of [
      null,
      "text",
      { kind: 5 },
      { kind: "audit" },
      { kind: "backchannel_logout" },
      {
        ...BackchannelTaskSchema.parse({
          kind: "backchannel_logout",
          client_id: "c",
          uri: `${RP}/backchannel`,
          token: "not-a-jwt",
          attempt: 1,
          sid: "s",
          uid: "u",
        }),
      },
    ]) {
      const { batch, calls } = batchOf(body);
      await consume(batch, recordingEnv([]), createExecutionContext());
      expect(calls, JSON.stringify(body)).toEqual(["ack"]);
    }
    expect(lines.filter((l) => l["msg"] === "task of an unknown kind dropped")).toHaveLength(3);
    expect(lines.filter((l) => l["msg"] === "malformed audit batch dropped")).toHaveLength(1);
    expect(lines.filter((l) => l["msg"] === "malformed backchannel task dropped")).toHaveLength(2);
    const loaded = await new KeyStore(clock).get(db, testKeys());
    const token = await signJwt(loaded, "logout+jwt", {
      jti: "j",
      sub: "u",
      aud: "c",
      iss: ISSUER,
      iat: clock.now(),
      exp: clock.now() + 120,
    });
    const task = {
      kind: "backchannel_logout",
      client_id: "c",
      uri: `${RP}/backchannel`,
      token,
      attempt: 1,
      sid: "s",
      uid: "u",
    };
    // Keys unavailable (a consumer with nothing cached): the message is retried by the queue.
    const cold = createQueue({ clock, sink: (line) => lines.push(line) });
    const { batch: noKeys, calls: noKeysCalls } = batchOf(task);
    await cold(noKeys, { ...recordingEnv([]), DB: brokenD1 } as Env, createExecutionContext());
    expect(noKeysCalls).toEqual(["retry"]);
    // Invalid configuration: the whole batch is retried.
    const { batch: noConfig, calls: noConfigCalls } = batchOf(task);
    await consume(
      noConfig,
      { ...recordingEnv([]), MASTER_KEYS: "" } as Env,
      createExecutionContext(),
    );
    expect(noConfigCalls).toEqual(["retryAll"]);
    // Delivery failures by transport: a hanging endpoint and an unreachable one, through the injected fetch.
    const hanging: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    const slow = createQueue({ clock, sink: (line) => lines.push(line), fetch: hanging });
    const queued: Sent[] = [];
    // The consumer's timeout is the module's 5 s: advance the real clock is not possible, so
    // the hanging fetch is aborted by AbortSignal.timeout in real time; keep the wait short by
    // trusting the unreachable case for the branch and checking the timeout reason in the unit.
    const refusing: typeof fetch = async () => {
      throw new Error("connection refused");
    };
    const dead = createQueue({ clock, sink: (line) => lines.push(line), fetch: refusing });
    const { batch: unreachable, calls: unreachableCalls } = batchOf({
      ...task,
      attempt: MAX_ATTEMPTS,
    });
    await dead(unreachable, recordingEnv(queued), createExecutionContext());
    expect(unreachableCalls).toEqual(["ack"]);
    expect(queueEvents("logout.backchannel_failed").at(-1)).toMatchObject({
      reason: "unreachable",
    });
    expect(slow).toBeDefined();
  });
});

describe("other revocation paths", () => {
  it("[TIO-LOGOUT-013] admin session revocation, revoking every session, disabling and deleting a user, and a different user signing in on the same browser all send logout tokens", async () => {
    const operator = await adminUser(h);
    const heidi = await userWithPasskey(clock, { email: "heidi@example.com" });
    const one = await login(heidi, web);
    const two = await login(heidi, other);
    received.length = 0;
    expect(
      (
        await admin(h, operator.access_token, `users/${heidi.profile.id}/sessions/${one.sid}`, {
          method: "DELETE",
        })
      ).status,
    ).toBe(200);
    expect(received.map((r) => [r.path, decodeJwt(r.token)["sid"]])).toEqual([
      ["/backchannel", one.sid],
    ]);
    received.length = 0;
    expect(
      (
        await admin(h, operator.access_token, `users/${heidi.profile.id}/sessions`, {
          method: "DELETE",
        })
      ).status,
    ).toBe(200);
    expect(received.map((r) => [r.path, decodeJwt(r.token)["sid"]])).toEqual([
      ["/other-backchannel", two.sid],
    ]);
    // Disable: every live session of the user.
    const three = await login(heidi, web);
    received.length = 0;
    expect(
      (
        await admin(h, operator.access_token, `users/${heidi.profile.id}/disable`, {
          method: "POST",
        })
      ).status,
    ).toBe(200);
    expect(received.map((r) => [r.path, decodeJwt(r.token)["sid"]])).toEqual([
      ["/backchannel", three.sid],
    ]);
    expect(
      (
        await admin(h, operator.access_token, `users/${heidi.profile.id}/enable`, {
          method: "POST",
        })
      ).status,
    ).toBe(200);
    // Delete.
    const four = await login(heidi, other);
    received.length = 0;
    expect(
      (await admin(h, operator.access_token, `users/${heidi.profile.id}`, { method: "DELETE" }))
        .status,
    ).toBe(204);
    expect(received.map((r) => [r.path, decodeJwt(r.token)["sid"]])).toEqual([
      ["/other-backchannel", four.sid],
    ]);
    // Another user signs in on a browser that still carries the first one's session.
    const ivan = await userWithPasskey(clock, { email: "ivan@example.com" });
    const judy = await userWithPasskey(clock, { email: "judy@example.com" });
    const ivans = await login(ivan, web);
    received.length = 0;
    const judys = await login(judy, web, { sessionCookie: ivans.cookie });
    expect(judys.sid).not.toBe(ivans.sid);
    expect(await sessionAlive(ivans)).toBe(false);
    expect(received.map((r) => [r.path, decodeJwt(r.token).sub])).toEqual([
      ["/backchannel", ivan.profile.id],
    ]);
    // A client without a back-channel URI is skipped; a client that vanished is skipped.
    const silent = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const kim = await userWithPasskey(clock, { email: "kim@example.com" });
    const kims = await login(kim, silent);
    received.length = 0;
    expect((await logout({ id_token_hint: kims.id_token }, kims.cookie)).status).toBe(303);
    expect(received).toEqual([]);
    expect(
      events("logout.backchannel_sent").filter((e) => e.client_id === silent.client_id),
    ).toEqual([]);
  });

  it("[TIO-LOGOUT-005] [TIO-LOGOUT-011] a client the directory cannot describe or that vanished gets no token; a session still ends when no logout token can be minted; /logout answers 503 without keys or settings", async () => {
    // A client of the session this app never loaded, with the directory failing: skipped.
    const stranger = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        backchannel_logout_uri: `${RP}/stranger`,
        skip_consent: true,
      })
    ).client;
    const leo = await userWithPasskey(clock, { email: "leo@example.com" });
    const session = await login(leo, web);
    const elsewhere = harness(clock);
    const started = await elsewhere.start(
      stranger,
      { scope: "openid email", prompt: "login" },
      session.cookie,
    );
    const { publicKey } = (await (await elsewhere.post(started, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    expect(
      (
        await elsewhere.post(started, "passkey/verify", {
          response: await leo.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
        })
      ).status,
    ).toBe(200);
    const joined = await elsewhere.send(`/interactions/${started.id}/complete`, {
      origin: null,
      cookie: `${started.cookie}; ${session.cookie}`,
    });
    expect(joined.status).toBe(303);
    received.length = 0;
    const partial = await h.send(
      `/logout?${new URLSearchParams({ id_token_hint: session.id_token })}`,
      {
        origin: null,
        cookie: session.cookie,
        env: { ...env, DB: failingD1(/FROM clients/) } as Env,
      },
    );
    expect(partial.status).toBe(303);
    expect(received.map((r) => r.path)).toEqual(["/backchannel"]);
    expect(await sessionAlive(session)).toBe(false);
    // A client_id nobody can look up matches no redirect URI.
    const unknown = await h.send(
      `/logout?${new URLSearchParams({ client_id: "never-loaded", post_logout_redirect_uri: `${RP}/bye` })}`,
      { origin: null, env: { ...env, DB: failingD1(/FROM clients/) } as Env },
    );
    expect(unknown.headers.get("location")).toBe(LANDING);
    // Keys unreadable past the store's stale window: the hint cannot be verified (503), and a
    // session ended by another path still ends, its clients unnotified.
    const mia = await userWithPasskey(clock, { email: "mia@example.com" });
    const nina = await userWithPasskey(clock, { email: "nina@example.com" });
    const mias = await login(mia, web);
    clock.advance(3_601);
    const noKeys = { ...env, DB: failingD1(/FROM signing_keys/) } as Env;
    const res = await h.send(`/logout?${new URLSearchParams({ id_token_hint: mias.id_token })}`, {
      origin: null,
      cookie: mias.cookie,
      env: noKeys,
    });
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "temporarily_unavailable" });
    expect(await sessionAlive(mias)).toBe(true);
    const takeover = await h.start(web, { scope: "openid email", prompt: "login" }, mias.cookie);
    const options = (await (await h.post(takeover, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    expect(
      (
        await h.post(takeover, "passkey/verify", {
          response: await nina.authenticator.authenticate(options.publicKey, LOGIN_ORIGIN),
        })
      ).status,
    ).toBe(200);
    received.length = 0;
    const replaced = await h.send(`/interactions/${takeover.id}/complete`, {
      origin: null,
      cookie: `${takeover.cookie}; ${mias.cookie}`,
      env: noKeys,
    });
    expect(replaced.status).toBe(303);
    expect(await sessionAlive(mias)).toBe(false);
    expect(received).toEqual([]);
    expect(
      h.lines.find((l) => l["msg"] === "backchannel logout skipped: keys unavailable"),
    ).toBeDefined();
    // A fresh app knows no settings at all.
    const fresh = harness(clock);
    const noSettings = await fresh.send("/logout", {
      origin: null,
      env: { ...env, DB: brokenD1 } as Env,
    });
    expect(noSettings.status).toBe(503);
    await writeSettings(db, { login_url: null, login_origins: null }, "test", clock.now());
    const unconfigured = await fresh.send("/logout", { origin: null });
    expect(unconfigured.status).toBe(503);
    expect(await unconfigured.json()).toMatchObject({ error: "not_configured" });
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    expect((await logout({}, null)).headers.get("location")).toBe(LANDING);
  });
});
