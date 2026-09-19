import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { newInteractionId, newSecret } from "../../src/crypto/random.ts";
import { deleteClient } from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { InteractionDocument } from "../../src/do/InteractionDO.ts";
import type { ClientRef } from "../../src/do/UserDO.ts";
import { ipHash, sessionMetadata, uaFamily } from "../../src/obs/request-meta.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { openCodeHandle, openSessionHandle, sealBindingHandle } from "../../src/oidc/handles.ts";
import { interactionStub, startInteraction } from "../../src/oidc/interactions.ts";
import { createApp } from "../../src/router/app.ts";
import { bindingCookieName, SESSION_COOKIE } from "../../src/router/cookies.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT, type Started } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env, url } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { loggedIn } from "../support/sessions.ts";

const ISSUER = "https://auth.example.com";
const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

let web: Client;
let consentful: Client;

const ref = (client: Client): ClientRef => ({
  client_id: client.client_id,
  created_at: client.created_at,
  skip_consent: client.skip_consent,
  allowed_groups: client.allowed_groups,
});

/** GET /complete with the binding cookie (and optionally the session cookie); redirects are not followed. */
function complete(
  started: Started,
  extra: { session?: string; headers?: Record<string, string> } = {},
) {
  const cookie =
    extra.session === undefined ? started.cookie : `${started.cookie}; ${extra.session}`;
  return h.send(`/interactions/${started.id}/complete`, {
    origin: null,
    cookie,
    headers: {
      "user-agent":
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      "cf-connecting-ip": "203.0.113.9",
      ...extra.headers,
    },
  });
}

async function signIn(started: Started, user: PasskeyUser): Promise<void> {
  const res = await h.post(started, "passkey/options", {});
  const { publicKey } = (await res.json()) as {
    publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
  };
  const response = await user.authenticator.authenticate(publicKey, LOGIN_ORIGIN);
  const verified = await h.post(started, "passkey/verify", { response });
  expect(verified.status).toBe(200);
}

const location = (res: Response): URL => {
  expect(res.status).toBe(303);
  return new URL(res.headers.get("location") as string);
};
const query = (res: Response) => Object.fromEntries(location(res).searchParams);
const sessionCookieOf = (res: Response): string | undefined =>
  res.headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));

async function doc(id: string): Promise<InteractionDocument> {
  const got = await interactionStub(env, id).get(clock.now());
  if (!got.ok) throw new Error(got.error);
  return got.doc;
}

describe("GET /interactions/{id}/complete", () => {
  it("[TIO-IX-060] [TIO-SESS-001] [TIO-SESS-002] [TIO-SESS-005] a ready interaction after a passkey login creates the session, issues the code, clears the binding cookie and redirects to the RP", async () => {
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/app`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true }))
      .client;
    consentful = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: false })
    ).client;
    const user = await userWithPasskey(clock);
    const started = await h.start(web, { nonce: "nonce-1" });
    await signIn(started, user);
    clock.advance(5);
    const res = await complete(started);
    const target = location(res);
    expect(`${target.origin}${target.pathname}`).toBe(RP_REDIRECT);
    const params = query(res);
    expect(Object.keys(params).sort()).toEqual(["code", "iss", "state"]);
    expect(params).toMatchObject({ state: "st-1", iss: ISSUER });
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("permissions-policy")).toContain("publickey-credentials-get=()");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    const cookies = res.headers.getSetCookie();
    expect(cookies).toHaveLength(2);
    expect(cookies[0]).toBe(
      `${bindingCookieName(started.id)}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    );
    expect(cookies[1]).toMatch(
      /^__Host-tio_session=tio_ss_[A-Za-z0-9_-]+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000$/,
    );
    const handle = (cookies[1] as string)
      .slice(`${SESSION_COOKIE}=`.length)
      .split(";")[0] as string;
    const session = await openSessionHandle(keys, handle);
    expect(session?.uid).toBe(user.profile.id);
    expect((await doc(started.id)).status).toBe("completed");
    // The session carries the authentication context and the pseudonymized request metadata.
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toHaveLength(1);
    const stored = sessions.ok ? sessions.sessions[0] : undefined;
    expect(stored).toMatchObject({
      sid: session?.sid,
      auth_time: clock.now() - 5,
      amr: ["swk", "user"],
      acr: "urn:tinyoidc:acr:passkey",
      clients: [web.client_id],
      idle_expires_at: clock.now() + 86_400,
      absolute_expires_at: clock.now() + 2_592_000,
    });
    const got = await user.stub.getSession(
      session?.sid as string,
      session?.secret_hash as Uint8Array,
      clock.now(),
    );
    expect(got.ok).toBe(true);
    // The code redeems with this request's verifier and carries its nonce and sid.
    const code = await openCodeHandle(keys, params["code"] as string);
    const exchanged = await user.stub.exchangeCode({
      secret_hash: code?.secret_hash as Uint8Array,
      client: ref(web),
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
      now: clock.now(),
      refresh: null,
    });
    expect(exchanged.ok && exchanged.nonce).toBe("nonce-1");
    expect(exchanged.ok && exchanged.grant).toMatchObject({
      sub: user.profile.id,
      sid: session?.sid,
      scope: ["openid", "email", "profile"],
      amr: ["swk", "user"],
    });
    expect(await ipHash(keys, "203.0.113.9")).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(await ipHash(keys, null)).toBeNull();
    expect(
      uaFamily(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      ),
    ).toBe("Chrome/128");
    expect(
      uaFamily(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
      ),
    ).toBe("Edge/129");
    expect(
      uaFamily(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
      ),
    ).toBe("Safari/17");
    expect(uaFamily("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0")).toBe(
      "Firefox/130",
    );
    expect(
      uaFamily(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.98 Mobile/15E148 Safari/604.1",
      ),
    ).toBe("Chrome/128");
    expect(uaFamily("Mozilla/5.0 (iPhone) FxiOS/130.0 Mobile/15E148 Safari/605.1.15")).toBe(
      "Firefox/130",
    );
    expect(
      uaFamily(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
      ),
    ).toBe("Opera/114");
    expect(uaFamily("curl/8.9.1")).toBe("Other");
    expect(uaFamily(null)).toBeNull();
    const withCountry = await sessionMetadata(
      keys,
      new Request("https://auth.example.com/", { cf: { country: "BR" } } as RequestInit),
    );
    expect(withCountry).toEqual({ ip_hash: null, ua_family: null, country: "BR" });
    expect(
      (await sessionMetadata(keys, new Request("https://auth.example.com/"))).country,
    ).toBeNull();
  });

  it("[TIO-IX-060] a failed interaction redirects to the RP with the error, state and iss, clears the binding cookie and sets no session", async () => {
    const started = await h.start(web);
    await h.post(started, "abort", {});
    const res = await complete(started);
    expect(query(res)).toEqual({
      error: "access_denied",
      error_description: "aborted by the user",
      state: "st-1",
      iss: ISSUER,
    });
    expect(res.headers.getSetCookie()).toEqual([
      `${bindingCookieName(started.id)}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect((await doc(started.id)).status).toBe("completed");
    // A failed document without an error section reports server_error.
    const bareId = newInteractionId();
    const bare = await startInteraction(
      env,
      keys,
      bareId,
      {
        kind: "authorize",
        status: "login_required",
        client_id: web.client_id,
        request: {
          redirect_uri: RP_REDIRECT,
          scope: ["openid"],
          state: "s",
          nonce: null,
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          prompt: [],
          max_age: null,
          login_hint: null,
          ui_locales: null,
          acr_values: [],
        },
      },
      clock.now(),
      600,
    );
    await interactionStub(env, bareId).apply("fail", "failed", {}, clock.now());
    const bareStarted = { id: bareId, cookie: bare.cookie.slice(0, bare.cookie.indexOf(";")) };
    expect(query(await complete(bareStarted))["error"]).toBe("server_error");
  });

  it("[TIO-IX-061] an interaction that is not ready or failed sends the browser back to the login app; a completed one is reported as already completed", async () => {
    const started = await h.start(web);
    expect(location(await complete(started)).href).toBe(
      `${LOGIN_ORIGIN}/app?interaction=${started.id}`,
    );
    const user = await userWithPasskey(clock);
    const consenting = await h.start(consentful);
    await signIn(consenting, user);
    expect((await doc(consenting.id)).status).toBe("consent_required");
    expect(query(await complete(consenting))).toEqual({ interaction: consenting.id });
    await h.post(consenting, "consent", { decision: "grant", scopes: ["email"] });
    expect(query(await complete(consenting))["code"]).toMatch(/^tio_ac_/);
    expect(query(await complete(consenting))).toEqual({ error: "interaction_already_completed" });
    // The consented subset, not the request, is what the code carries.
    const consentDoc = await doc(consenting.id);
    expect(consentDoc.consent).toEqual({ scopes: ["openid", "email"] });
  });

  it("[TIO-IX-060] [TIO-IX-003] refuses a missing or foreign binding cookie, malformed and unknown ids and pushed requests, always through the login app", async () => {
    const started = await h.start(web);
    const cases: [string, string, string][] = [
      ["no cookie", `/interactions/${started.id}/complete`, "interaction_binding_failed"],
      ["malformed id", "/interactions/short/complete", "interaction_not_found"],
    ];
    for (const [name, path, error] of cases) {
      const res = await h.send(path, { origin: null, cookie: null });
      expect(query(res), name).toEqual({ error });
    }
    const other = await h.start(web);
    const swapped = await h.send(`/interactions/${started.id}/complete`, {
      origin: null,
      cookie: other.cookie,
    });
    expect(query(swapped)).toEqual({ error: "interaction_binding_failed" });
    const forged = await sealBindingHandle(keys, started.id, newSecret());
    const wrongSecret = await h.send(`/interactions/${started.id}/complete`, {
      origin: null,
      cookie: `${bindingCookieName(started.id)}=${forged}`,
    });
    expect(query(wrongSecret)).toEqual({ error: "interaction_binding_failed" });
    const unknown = newInteractionId();
    const ghost = await h.send(`/interactions/${unknown}/complete`, {
      origin: null,
      cookie: `${bindingCookieName(unknown)}=${await sealBindingHandle(keys, unknown, newSecret())}`,
    });
    expect(query(ghost)).toEqual({ error: "interaction_not_found" });
    const pushedId = newInteractionId();
    const pushed = await startInteraction(
      env,
      keys,
      pushedId,
      { kind: "par", status: "pushed", client_id: web.client_id },
      clock.now(),
      60,
    );
    const pushedRes = await h.send(`/interactions/${pushedId}/complete`, {
      origin: null,
      cookie: pushed.cookie.slice(0, pushed.cookie.indexOf(";")),
    });
    expect(query(pushedRes)).toEqual({ error: "interaction_not_found" });
    const expired = await h.start(web);
    clock.advance(600);
    expect(query(await complete(expired))).toEqual({ error: "interaction_not_found" });
  });

  it("[TIO-IX-062] consent given on an existing session issues the code on that session when its cookie is still presented, and restarts the interaction when the session is gone", async () => {
    const user = await userWithPasskey(clock);
    const session = await loggedIn(clock, user.profile);
    const started = await h.start(consentful, {}, session.cookie);
    expect((await doc(started.id)).status).toBe("consent_required");
    await h.post(started, "consent", { decision: "grant", scopes: ["email", "profile"] });
    const res = await complete(started, { session: session.cookie });
    expect(query(res)["code"]).toMatch(/^tio_ac_/);
    expect(sessionCookieOf(res)).toBeUndefined();
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions.map((s) => [s.sid, s.clients])).toEqual([
      [session.sid, [consentful.client_id]],
    ]);
    // Without the session cookie the code cannot be issued on it: restart.
    const noCookie = await h.start(consentful, { prompt: "consent" }, session.cookie);
    await h.post(noCookie, "consent", { decision: "grant", scopes: [] });
    const restarted = await complete(noCookie);
    expect(location(restarted).href).toBe(`${LOGIN_ORIGIN}/app?interaction=${noCookie.id}`);
    expect(restarted.headers.getSetCookie()).toEqual([
      `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    const restartedDoc = await doc(noCookie.id);
    expect(restartedDoc).toMatchObject({
      status: "login_required",
      existing_session: null,
      consent: null,
    });
    // The login app can then sign the user in, consent again (prompt=consent) and finish.
    await signIn(noCookie, user);
    expect(query(await complete(noCookie))).toEqual({ interaction: noCookie.id });
    await h.post(noCookie, "consent", { decision: "grant", scopes: [] });
    const finished = await complete(noCookie);
    expect(query(finished)["code"]).toMatch(/^tio_ac_/);
    expect(sessionCookieOf(finished)).toMatch(/^__Host-tio_session=tio_ss_/);
    // A session revoked after consent: restart as well.
    const revokedStart = await h.start(consentful, { prompt: "consent" }, session.cookie);
    await h.post(revokedStart, "consent", { decision: "grant", scopes: [] });
    await user.stub.revokeSession(session.sid, clock.now(), "test");
    expect(query(await complete(revokedStart, { session: session.cookie }))).toEqual({
      interaction: revokedStart.id,
    });
  });

  it("[TIO-SESS-002] [TIO-AUTHZ-024] re-authentication by the same user rotates the session; by another user replaces it; and a bare /authorize on the new session is a hit, never a loop", async () => {
    const user = await userWithPasskey(clock);
    const session = await loggedIn(clock, user.profile);
    clock.advance(100);
    const same = await h.start(web, { prompt: "login" }, session.cookie);
    await signIn(same, user);
    const rotated = await complete(same, { session: session.cookie });
    const rotatedCookie = sessionCookieOf(rotated) as string;
    expect(rotatedCookie).toBeDefined();
    const rotatedHandle = rotatedCookie.slice(`${SESSION_COOKIE}=`.length).split(";")[0] as string;
    expect((await openSessionHandle(keys, rotatedHandle))?.sid).toBe(session.sid);
    const sessions = await user.stub.listSessions(clock.now());
    expect(sessions.ok && sessions.sessions).toHaveLength(1);
    expect(sessions.ok && sessions.sessions[0]).toMatchObject({
      sid: session.sid,
      auth_time: clock.now(),
    });
    // The old cookie value no longer works; the new one is a session hit with fresh parameters.
    const oldCookie = await h.send(
      `/authorize?${new URLSearchParams({ client_id: web.client_id, redirect_uri: RP_REDIRECT, response_type: "code", scope: "openid", state: "x", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", prompt: "none" })}`,
      { origin: null, cookie: session.cookie },
    );
    expect(query(oldCookie)["error"]).toBe("login_required");
    const hit = await h.send(
      `/authorize?${new URLSearchParams({ client_id: web.client_id, redirect_uri: RP_REDIRECT, response_type: "code", scope: "openid", state: "again", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", nonce: "second" })}`,
      { origin: null, cookie: `${SESSION_COOKIE}=${rotatedHandle}` },
    );
    expect(query(hit)).toMatchObject({ state: "again" });
    expect(query(hit)["code"]).toMatch(/^tio_ac_/);
    expect(query(hit)["interaction"]).toBeUndefined();
    // Another user signing in on this browser ends the first user's session.
    const other = await userWithPasskey(clock);
    const swap = await h.start(web, { prompt: "login" }, `${SESSION_COOKIE}=${rotatedHandle}`);
    await signIn(swap, other);
    const swapped = await complete(swap, { session: `${SESSION_COOKIE}=${rotatedHandle}` });
    const swappedHandle = (sessionCookieOf(swapped) as string)
      .slice(`${SESSION_COOKIE}=`.length)
      .split(";")[0] as string;
    expect((await openSessionHandle(keys, swappedHandle))?.uid).toBe(other.profile.id);
    const gone = await user.stub.listSessions(clock.now());
    expect(gone.ok && gone.sessions).toEqual([]);
    const theirs = await other.stub.listSessions(clock.now());
    expect(theirs.ok && theirs.sessions).toHaveLength(1);
    // A rotation target that vanished meanwhile is replaced by a new session.
    const vanish = await h.start(web, { prompt: "login" }, `${SESSION_COOKIE}=${swappedHandle}`);
    await signIn(vanish, other);
    await other.stub.revokeAll(clock.now(), "test");
    const replaced = await complete(vanish);
    expect(query(replaced)["code"]).toMatch(/^tio_ac_/);
    const replacedSid = (
      await openSessionHandle(
        keys,
        (sessionCookieOf(replaced) as string)
          .slice(`${SESSION_COOKIE}=`.length)
          .split(";")[0] as string,
      )
    )?.sid;
    expect(replacedSid).not.toBe((await openSessionHandle(keys, swappedHandle))?.sid);
  });

  it("[TIO-PK-023] [TIO-AUTHZ-017] a user disabled or disallowed between authentication and completion is sent back with access_denied", async () => {
    const user = await userWithPasskey(clock);
    const started = await h.start(web);
    await signIn(started, user);
    await user.stub.setDisabled(clock.now(), clock.now());
    expect(query(await complete(started))).toEqual({
      error: "access_denied",
      error_description: "the user cannot sign in",
      state: "st-1",
      iss: ISSUER,
    });
    const grouped = (
      await createTestClient(
        db,
        clock,
        { redirect_uris: [RP_REDIRECT], skip_consent: true, allowed_groups: ["staff"] },
        { existingGroups: new Set(["staff"]) },
      )
    ).client;
    const outsider = await userWithPasskey(clock);
    const readyId = newInteractionId();
    const ready = await startInteraction(
      env,
      keys,
      readyId,
      {
        kind: "authorize",
        status: "login_required",
        client_id: grouped.client_id,
        request: {
          redirect_uri: RP_REDIRECT,
          scope: ["openid"],
          state: "s",
          nonce: null,
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          prompt: [],
          max_age: null,
          login_hint: null,
          ui_locales: null,
          acr_values: [],
        },
      },
      clock.now(),
      600,
    );
    await interactionStub(env, readyId).apply(
      "authenticate",
      "ready",
      {
        auth: {
          uid: outsider.profile.id,
          method: "passkey",
          amr: ["swk", "user"],
          acr: "urn:tinyoidc:acr:passkey",
          upstream: null,
          auth_time: clock.now(),
          new_session: true,
        },
      },
      clock.now(),
    );
    const readyStarted = { id: readyId, cookie: ready.cookie.slice(0, ready.cookie.indexOf(";")) };
    expect(query(await complete(readyStarted))).toMatchObject({
      error: "access_denied",
      error_description: "user_not_allowed",
    });
    // Rotation refused for a disabled user.
    const holder = await userWithPasskey(clock);
    const holderSession = await loggedIn(clock, holder.profile);
    const again = await h.start(web, { prompt: "login" }, holderSession.cookie);
    await signIn(again, holder);
    await holder.stub.setDisabled(clock.now(), clock.now());
    expect(query(await complete(again, { session: holderSession.cookie }))["error"]).toBe(
      "access_denied",
    );
  });

  it("fails closed when the client is gone, when the document names no user, and when settings cannot be read", async () => {
    const user = await userWithPasskey(clock);
    const doomed = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const started = await h.start(doomed);
    await signIn(started, user);
    await deleteClient(db, doomed.client_id);
    clock.advance(61);
    expect(query(await complete(started))).toMatchObject({
      error: "server_error",
      error_description: "client unavailable",
    });
    const orphanId = newInteractionId();
    const orphan = await startInteraction(
      env,
      keys,
      orphanId,
      {
        kind: "authorize",
        status: "ready",
        client_id: web.client_id,
        request: {
          redirect_uri: RP_REDIRECT,
          scope: ["openid"],
          state: "s",
          nonce: null,
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          prompt: [],
          max_age: null,
          login_hint: null,
          ui_locales: null,
          acr_values: [],
        },
      },
      clock.now(),
      600,
    );
    const orphanStarted = {
      id: orphanId,
      cookie: orphan.cookie.slice(0, orphan.cookie.indexOf(";")),
    };
    expect(query(await complete(orphanStarted))).toMatchObject({
      error: "server_error",
      error_description: "no user",
    });
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const fresh = createApp({ clock, sink: () => undefined });
    const ctx = createExecutionContext();
    const down = await fresh.fetch(
      new Request(url(`/interactions/${started.id}/complete`)),
      { ...env, DB: brokenD1 } as typeof env,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(down.status).toBe(503);
  });

  it("[TIO-CFG-004] answers 503 not_configured without a login_url", async () => {
    const fresh = createApp({ clock, sink: () => undefined });
    await writeSettings(db, { login_url: null, login_origins: null }, "test", clock.now());
    const ctx = createExecutionContext();
    const res = await fresh.fetch(
      new Request(url(`/interactions/${newInteractionId()}/complete`)),
      env,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "not_configured" });
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/app`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
  });
});
