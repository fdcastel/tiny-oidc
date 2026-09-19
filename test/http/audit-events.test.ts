import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { AUDIT_CATALOG } from "../../src/audit/catalog.ts";
import type { AuditEvent } from "../../src/audit/events.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { releaseCredential } from "../../src/db/users.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { SESSION_COOKIE } from "../../src/router/cookies.ts";
import { limitKey } from "../../src/router/rate-limit.ts";
import { createInvitation } from "../../src/users/invitations.ts";
import { adminSettings } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { type PasskeyUser, userWithPasskey } from "../support/passkeys.ts";
import { VirtualAuthenticator } from "../support/virtual-authenticator.ts";

// The events of the login, token and interaction flows (spec §11.2,
// TIO-AUDIT-001): each one triggered through the real endpoints and checked
// for type, outcome, actor and allow-listed data keys.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

let web: Client;

const events = (): AuditEvent[] =>
  h.lines.filter((l) => l["msg"] === "audit").map((l) => l["event"] as AuditEvent);
const last = (type: string): AuditEvent => {
  const found = events()
    .filter((e) => e.type === type)
    .at(-1);
  if (found === undefined) throw new Error(`no ${type} event`);
  return found;
};
/** The event's type, outcome and actor as asked, and only allow-listed data keys (TIO-AUDIT-001). */
function expectEvent(
  event: AuditEvent,
  shape: { outcome: AuditEvent["outcome"]; actor: AuditEvent["actor"] } & Partial<AuditEvent>,
): void {
  expect(event).toMatchObject(shape);
  const allowed = AUDIT_CATALOG[event.type as keyof typeof AUDIT_CATALOG] as readonly string[];
  for (const key of Object.keys(event.data)) expect(allowed, `${event.type}.${key}`).toContain(key);
}

interface Login {
  started: { id: string; cookie: string };
  cookie: string;
  tokens: { access_token: string; refresh_token?: string; id_token: string };
  sid: string;
}

const form = (params: Record<string, string>, headers: Record<string, string> = {}) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(params).toString(),
  });

async function login(
  user: PasskeyUser,
  client: Client,
  options: { scope?: string; sessionCookie?: string; authenticator?: VirtualAuthenticator } = {},
): Promise<Login> {
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
  const authenticator = options.authenticator ?? user.authenticator;
  const verified = await h.post(started, "passkey/verify", {
    response: await authenticator.authenticate(publicKey, LOGIN_ORIGIN),
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
  const res = await form({
    grant_type: "authorization_code",
    client_id: client.client_id,
    code: code as string,
    redirect_uri: RP_REDIRECT,
    code_verifier: VERIFIER,
  });
  expect(res.status).toBe(200);
  const tokens = (await res.json()) as Login["tokens"];
  return { started, cookie, tokens, sid: decodeJwt(tokens.id_token)["sid"] as string };
}

describe("login, session and token events", () => {
  it("[TIO-AUDIT-001] a passkey login emits interaction.created, passkey.auth_succeeded, session.created, authz.code_issued, interaction.completed and token.issued; a session hit and a re-authentication add authz.code_issued and session.rotated; refresh, reuse and replay have theirs", async () => {
    await adminSettings(h);
    web = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        skip_consent: true,
        offline_access: true,
        scopes_allowed: ["openid", "email", "offline_access"],
      })
    ).client;
    const alice = await userWithPasskey(clock, { email: "alice@example.com" });
    const first = await login(alice, web, { scope: "openid email offline_access" });
    const uid = alice.profile.id;
    // An offline family carries no sid in its tokens (TIO-TOKEN-014); the session event names it.
    const sid = last("session.created").sid as string;
    expectEvent(last("interaction.created"), {
      outcome: "success",
      actor: { kind: "anonymous", id: null },
      client_id: web.client_id,
      interaction_id: first.started.id,
      data: { kind: "authorize", status: "login_required" },
    });
    expectEvent(last("passkey.auth_succeeded"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      user_id: uid,
      interaction_id: first.started.id,
      data: { passkey_id: expect.any(String) },
    });
    expectEvent(last("session.created"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      sid,
      data: { amr: expect.arrayContaining(["user"]), upstream: null },
    });
    expectEvent(last("authz.code_issued"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      sid,
      data: { scopes: ["openid", "email", "offline_access"], session_hit: false },
    });
    expectEvent(last("interaction.completed"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      interaction_id: first.started.id,
      data: { kind: "authorize" },
    });
    expectEvent(last("token.issued"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      client_id: web.client_id,
      data: { grant_type: "authorization_code", kind: "offline" },
    });
    // A session hit issues the code without an interaction.
    const hit = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid email",
        state: "s",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { origin: null, cookie: first.cookie },
    );
    expect(hit.headers.get("location")).toContain("code=");
    expectEvent(last("authz.code_issued"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      sid,
      interaction_id: null,
      data: { scopes: ["openid", "email"], session_hit: true },
    });
    // The same user again on the same browser: the session rotates.
    const again = await login(alice, web, { sessionCookie: first.cookie });
    expect(again.sid).toBe(sid);
    expectEvent(last("session.rotated"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      sid,
    });
    // Refresh, then reuse of the consumed token, then a replayed code.
    const refreshed = await form({
      grant_type: "refresh_token",
      client_id: web.client_id,
      refresh_token: first.tokens.refresh_token as string,
    });
    expect(refreshed.status).toBe(200);
    expectEvent(last("token.refreshed"), {
      outcome: "success",
      actor: { kind: "user", id: uid },
      client_id: web.client_id,
      data: { kind: "offline" },
    });
    const reused = await form({
      grant_type: "refresh_token",
      client_id: web.client_id,
      refresh_token: first.tokens.refresh_token as string,
    });
    expect(reused.status).toBe(400);
    expectEvent(last("token.refresh_reuse"), {
      outcome: "failure",
      actor: { kind: "client", id: web.client_id },
      user_id: uid,
      data: { revoked_session_clients: [] },
    });
    const code = new URL(hit.headers.get("location") as string).searchParams.get("code") as string;
    const exchange = () =>
      form({
        grant_type: "authorization_code",
        client_id: web.client_id,
        code,
        redirect_uri: RP_REDIRECT,
        code_verifier: VERIFIER,
      });
    expect((await exchange()).status).toBe(200);
    expect((await exchange()).status).toBe(400);
    expectEvent(last("token.code_replay"), {
      outcome: "failure",
      actor: { kind: "client", id: web.client_id },
      user_id: uid,
    });
    // A client that cannot authenticate.
    const confidential = (
      await createTestClient(db, clock, {
        redirect_uris: [],
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        scopes_allowed: ["admin"],
      })
    ).client;
    const wrong = await form(
      { grant_type: "client_credentials", scope: "admin" },
      { authorization: `Basic ${btoa(`${confidential.client_id}:wrong`)}` },
    );
    expect(wrong.status).toBe(401);
    expectEvent(last("token.client_auth_failed"), {
      outcome: "failure",
      actor: { kind: "client", id: confidential.client_id },
      client_id: confidential.client_id,
    });
    expect((await form({ grant_type: "client_credentials" })).status).toBe(401);
    expectEvent(last("token.client_auth_failed"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      client_id: null,
    });
    // A cookie whose session no longer exists.
    await alice.stub.revokeSession(sid, clock.now(), "test");
    const stale = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid email",
        state: "s",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { origin: null, cookie: first.cookie },
    );
    expect(stale.headers.get("location")).toContain("interaction=");
    expectEvent(last("session.expired"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      client_id: web.client_id,
      reason: "cookie_without_session",
    });
  });

  it("[TIO-AUDIT-001] passkey failures and a cloned credential, an aborted interaction, a denied and a granted consent, a rate limit, an invitation and a denied authorization each leave their event", async () => {
    const bob = await userWithPasskey(clock, { email: "bob@example.com" });
    const started = await h.start(web, { scope: "openid email" });
    const { publicKey } = (await (await h.post(started, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    // A credential the OP no longer knows.
    const stranger = await userWithPasskey(clock);
    const listed = await stranger.stub.listPasskeys();
    await stranger.stub.removePasskey((listed.ok ? listed.passkeys[0]?.id : "") as string);
    await releaseCredential(db, stranger.credentialId);
    const unknown = await h.post(started, "passkey/verify", {
      response: await stranger.authenticator.authenticate(publicKey, LOGIN_ORIGIN),
    });
    expect(unknown.status).toBe(401);
    // The assertion names its user, whose object no longer holds the credential.
    expectEvent(last("passkey.auth_failed"), {
      outcome: "failure",
      actor: { kind: "user", id: stranger.profile.id },
      interaction_id: started.id,
      reason: "passkey_verification_failed",
      data: { step: "passkey_verification_failed" },
    });
    // An assertion nobody can route: no user handle and no index row.
    const retry = (await (await h.post(started, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const assertion = await stranger.authenticator.authenticate(retry.publicKey, LOGIN_ORIGIN);
    const { userHandle: _handle, ...withoutHandle } = assertion.response;
    const unroutable = await h.post(started, "passkey/verify", {
      response: { ...assertion, response: withoutHandle },
    });
    expect(unroutable.status).toBe(401);
    expectEvent(last("passkey.auth_failed"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      reason: "passkey_unknown",
      data: { step: "passkey_unknown" },
    });
    // A counter that went backwards: the credential was cloned (TIO-PK-023).
    const good = await login(bob, web);
    bob.authenticator.setCounter(bob.credentialId, 0);
    const cloned = await h.start(web, { scope: "openid email" });
    const options = (await (await h.post(cloned, "passkey/options", {})).json()) as {
      publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
    };
    const regressed = await h.post(cloned, "passkey/verify", {
      response: await bob.authenticator.authenticate(options.publicKey, LOGIN_ORIGIN),
    });
    expect(regressed.status).toBe(401);
    expectEvent(last("passkey.clone_suspected"), {
      outcome: "failure",
      actor: { kind: "user", id: bob.profile.id },
      user_id: bob.profile.id,
      reason: "counter_regression",
      data: { passkey_id: expect.any(String), stored: expect.any(Number), observed: 1 },
    });
    expectEvent(last("passkey.auth_failed"), {
      outcome: "failure",
      actor: { kind: "user", id: bob.profile.id },
      reason: "passkey_counter_regression",
    });
    expect(good.sid).toBeDefined();
    // Abort.
    expect((await h.post(cloned, "abort", {})).status).toBe(200);
    expectEvent(last("interaction.failed"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      interaction_id: cloned.id,
      reason: "aborted",
      data: { kind: "authorize", error: "access_denied" },
    });
    const denied = await h.send(`/interactions/${cloned.id}/complete`, {
      origin: null,
      cookie: cloned.cookie,
    });
    expect(denied.headers.get("location")).toContain("error=access_denied");
    expectEvent(last("authz.denied"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      interaction_id: cloned.id,
      reason: "access_denied",
      data: { error: "access_denied" },
    });
    // Consent denied, then granted.
    const asking = (
      await createTestClient(db, clock, {
        redirect_uris: [RP_REDIRECT],
        scopes_allowed: ["openid", "email"],
      })
    ).client;
    for (const [i, decision] of (["deny", "grant"] as const).entries()) {
      const consent = await h.start(asking, { scope: "openid email" });
      const opts = (await (await h.post(consent, "passkey/options", {})).json()) as {
        publicKey: Parameters<PasskeyUser["authenticator"]["authenticate"]>[0];
      };
      // Past the rewound counter of the clone above, and increasing (TIO-PK-023).
      bob.authenticator.setCounter(bob.credentialId, 1_000 * (i + 1));
      expect(
        await (
          await h.post(consent, "passkey/verify", {
            response: await bob.authenticator.authenticate(opts.publicKey, LOGIN_ORIGIN),
          })
        ).json(),
      ).toMatchObject({ status: "consent_required" });
      const answered = await h.post(
        consent,
        "consent",
        decision === "grant" ? { decision, scopes: ["openid", "email"] } : { decision },
      );
      expect(answered.status).toBe(200);
      if (decision === "deny") {
        expectEvent(last("consent.denied"), {
          outcome: "failure",
          actor: { kind: "user", id: bob.profile.id },
          client_id: asking.client_id,
          interaction_id: consent.id,
        });
        expectEvent(last("interaction.failed"), {
          outcome: "failure",
          actor: { kind: "user", id: bob.profile.id },
          reason: "consent_denied",
        });
      } else {
        expectEvent(last("consent.granted"), {
          outcome: "success",
          actor: { kind: "user", id: bob.profile.id },
          client_id: asking.client_id,
          data: { scopes: ["openid", "email"] },
        });
      }
    }
    // A denied authorization request never reaches an interaction.
    const badScope = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid profile",
        state: "s",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { origin: null },
    );
    expect(badScope.headers.get("location")).toContain("error=invalid_scope");
    expectEvent(last("authz.denied"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      reason: "invalid_scope",
    });
    // Too many attempts fail the interaction.
    const hammered = await h.start(web, { scope: "openid email" });
    let refused = 0;
    for (let i = 0; i < 12; i++) {
      const res = await h.post(hammered, "passkey/options", {});
      if (res.status === 403) refused += 1;
    }
    expect(refused).toBeGreaterThan(0);
    expectEvent(last("interaction.failed"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      interaction_id: hammered.id,
      reason: "attempt_limit",
      data: { kind: "authorize", error: "too_many_attempts" },
    });
    // A rate limit.
    const ip = "203.0.113.200";
    while ((await env.RL_IP.limit({ key: limitKey("ip_interactions", ip) })).success) {
      // keep counting
    }
    expect((await h.get(hammered, { headers: { "cf-connecting-ip": ip } })).status).toBe(429);
    expectEvent(last("ratelimit.exceeded"), {
      outcome: "failure",
      actor: { kind: "anonymous", id: null },
      reason: "ip_interactions",
      data: { class: "ip_interactions" },
    });
    // An invitation consumed by a registration.
    await writeSettings(db, { "registration.mode": "invite" }, "test", clock.now());
    clock.advance(61);
    const invitation = await createInvitation(
      db,
      testKeys(),
      {
        kind: "register",
        user_id: null,
        email: "carol@example.com",
        email_verified: true,
        display_name: "Carol",
        groups: [],
        expires_in: null,
        created_by: "test",
      },
      clock,
    );
    if (!invitation.ok) throw new Error(invitation.error);
    const signup = await h.start(web, { scope: "openid email" });
    const creation = (await (
      await h.post(signup, "register/options", { invitation: invitation.token })
    ).json()) as { publicKey: Parameters<VirtualAuthenticator["register"]>[0] };
    const device = new VirtualAuthenticator();
    const registered = await h.post(signup, "register/verify", {
      response: await device.register(creation.publicKey, LOGIN_ORIGIN),
    });
    expect(registered.status).toBe(200);
    expectEvent(last("invitation.used"), {
      outcome: "success",
      actor: { kind: "user", id: expect.any(String) },
      interaction_id: signup.id,
      data: { kind: "register", via: "interaction" },
    });
    expectEvent(last("passkey.registered"), {
      outcome: "success",
      actor: { kind: "user", id: expect.any(String) },
      interaction_id: signup.id,
      data: { passkey_id: expect.any(String), via: "interaction" },
    });
    await writeSettings(db, { "registration.mode": null }, "test", clock.now());
    clock.advance(61);
  });
});
