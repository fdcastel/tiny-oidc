import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import type { Env } from "../../src/env.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";

// Injection (spec §13.7, TIO-TEST-020, TIO-DATA-015): every string a caller
// controls reaches D1 as a bound parameter and never as SQL text (a spy on
// the binding reads every statement), redirects carry parameters encoded,
// and error bodies never echo request values.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

/** A payload every SQL grammar would choke on if it were ever pasted into a statement. */
const PAYLOAD = `x'); DROP TABLE users; -- "\` OR 1=1 /* \u0000`;
const CANARY = "CANARY_ECHO_9f3a";

/** A D1 whose statements are recorded, with the payload asserted absent from each. */
function spy(): { env: Env; statements: string[] } {
  const statements: string[] = [];
  const spied = {
    prepare(sql: string) {
      statements.push(sql);
      return env.DB.prepare(sql);
    },
    batch(list: D1PreparedStatement[]) {
      return env.DB.batch(list);
    },
    withSession(constraint: string) {
      const session = env.DB.withSession(constraint);
      return {
        prepare(sql: string) {
          statements.push(sql);
          return session.prepare(sql);
        },
        batch(list: D1PreparedStatement[]) {
          return session.batch(list);
        },
      };
    },
  } as unknown as D1Database;
  return { env: { ...env, DB: spied } as Env, statements };
}

describe("injection", () => {
  it("[TIO-TEST-020] [TIO-DATA-015] SQL metacharacters in every string parameter of the public, interaction, self-service and admin surfaces reach D1 only as bound parameters", async () => {
    await adminSettings(h);
    const operator = await adminUser(h, { scope: "openid account admin" });
    const token = operator.access_token;
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const { env: spied, statements } = spy();
    const p = encodeURIComponent(PAYLOAD);
    const bearer = { authorization: `Bearer ${token}` };
    // `stored: true` marks the requests whose payload-bearing parameter passes
    // validation and therefore must reach D1 (as a parameter); the others are
    // refused by shape checks before any statement runs.
    const requests: { name: string; stored: boolean; send: () => Promise<Response> }[] = [
      {
        name: "authorize: client_id lookup",
        stored: true,
        send: () =>
          h.send(
            `/authorize?client_id=${p}&redirect_uri=${p}&response_type=code&scope=${p}&state=${p}&code_challenge=${p}&code_challenge_method=S256&nonce=${p}&login_hint=${p}`,
            { origin: null, env: spied },
          ),
      },
      {
        name: "authorize: state and login_hint",
        stored: true,
        send: () =>
          h.send(
            `/authorize?client_id=${web.client_id}&redirect_uri=${encodeURIComponent(RP_REDIRECT)}&response_type=code&scope=openid%20email&state=${p}&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&login_hint=${p}`,
            { origin: null, env: spied },
          ),
      },
      {
        name: "token: authorization_code",
        stored: false,
        send: () =>
          h.send("/token", {
            method: "POST",
            origin: null,
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              client_id: PAYLOAD,
              code: PAYLOAD,
              redirect_uri: PAYLOAD,
              code_verifier: PAYLOAD,
            }).toString(),
            env: spied,
          }),
      },
      {
        name: "token: client_credentials with Basic",
        stored: false,
        send: () =>
          h.send("/token", {
            method: "POST",
            origin: null,
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              authorization: `Basic ${btoa(`${PAYLOAD}:${PAYLOAD}`)}`,
            },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              scope: PAYLOAD,
            }).toString(),
            env: spied,
          }),
      },
      {
        name: "logout",
        stored: false,
        send: () =>
          h.send(
            `/logout?client_id=${p}&post_logout_redirect_uri=${p}&state=${p}&id_token_hint=${p}`,
            { origin: null, env: spied },
          ),
      },
      {
        name: "federation callback",
        stored: false,
        send: () =>
          h.send(`/federation/callback?state=${p}&code=${p}&error=${p}`, {
            origin: null,
            env: spied,
          }),
      },
      {
        name: "admin: users filter",
        stored: true,
        send: () => admin(h, token, `users?email=${p}&group=${p}`, { env: spied }),
      },
      {
        name: "admin: user id",
        stored: false,
        send: () => admin(h, token, `users/${p}`, { env: spied }),
      },
      {
        name: "admin: create user",
        stored: false,
        send: () =>
          admin(h, token, "users", {
            method: "POST",
            body: { email: `${PAYLOAD}@example.com`, display_name: PAYLOAD, groups: [PAYLOAD] },
            env: spied,
          }),
      },
      {
        name: "admin: create group",
        stored: false,
        send: () =>
          admin(h, token, "groups", {
            method: "POST",
            body: { name: PAYLOAD, description: PAYLOAD },
            env: spied,
          }),
      },
      {
        name: "admin: create client",
        stored: false,
        send: () =>
          admin(h, token, "clients", {
            method: "POST",
            body: { client_id: PAYLOAD, client_name: PAYLOAD, redirect_uris: [PAYLOAD] },
            env: spied,
          }),
      },
      {
        name: "admin: create upstream",
        stored: false,
        send: () =>
          admin(h, token, "upstreams", {
            method: "POST",
            body: { alias: PAYLOAD, issuer: PAYLOAD, display_name: PAYLOAD, client_id: PAYLOAD },
            env: spied,
          }),
      },
      {
        name: "admin: upstream alias",
        stored: false,
        send: () => admin(h, token, `upstreams/${p}`, { env: spied }),
      },
      {
        name: "admin: create invitation with the payload as display_name",
        stored: true,
        send: () =>
          admin(h, token, "invitations", {
            method: "POST",
            body: { kind: "register", email: "invitee@example.com", display_name: PAYLOAD },
            env: spied,
          }),
      },
      {
        name: "admin: audit filters",
        stored: true,
        send: () =>
          admin(h, token, `audit?type=${p}&user_id=${p}&client_id=${p}&actor_id=${p}`, {
            env: spied,
          }),
      },
      {
        name: "admin: audit user_id filter",
        stored: true,
        send: () =>
          admin(h, token, `audit?type=${encodeURIComponent("token.issued")}&user_id=${p}`, {
            env: spied,
          }),
      },
      {
        name: "me: display_name",
        stored: true,
        send: () =>
          h.send("/api/v1/me", {
            method: "PATCH",
            origin: null,
            headers: bearer,
            body: { display_name: PAYLOAD },
            env: spied,
          }),
      },
      {
        name: "me: grant id",
        stored: false,
        send: () =>
          h.send(`/api/v1/me/grants/${p}`, {
            method: "DELETE",
            origin: null,
            headers: bearer,
            env: spied,
          }),
      },
    ];
    for (const request of requests) {
      const before = statements.length;
      const res = await request.send();
      // Any status but a crash: the request was handled, not executed.
      expect(res.status, request.name).toBeLessThan(500);
      if (request.stored) expect(statements.length, request.name).toBeGreaterThan(before);
    }
    // A registration with the payload as the email, through an interaction.
    const started = await h.start(web, { scope: "openid email" });
    const options = await h.post(
      started,
      "register/options",
      { email: `${PAYLOAD}@example.com`, display_name: PAYLOAD, invitation: PAYLOAD },
      { env: spied },
    );
    expect(options.status).toBeLessThan(500);
    for (const sql of statements) {
      expect(sql, sql).not.toContain("DROP TABLE");
      expect(sql, sql).not.toContain(CANARY);
      expect(sql, sql).not.toContain("\u0000");
    }
    // The payload that was accepted is stored verbatim as data, and the tables are intact.
    const me = (await (await h.send("/api/v1/me", { origin: null, headers: bearer })).json()) as {
      display_name: string;
    };
    expect(me.display_name).toBe(PAYLOAD);
    expect(
      await db.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>(),
    ).toMatchObject({ n: expect.any(Number) });
  });

  it("[TIO-TEST-020] [TIO-AUTHZ-019] [TIO-ERR-001] parameters are encoded into redirects and never echoed in error bodies", async () => {
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    // state travels back to the client encoded, whatever it holds (prompt=none
    // without a session is a redirectable login_required).
    const state = `a&b=c#frag ${CANARY}`;
    const denied = await h.send(
      `/authorize?${new URLSearchParams({
        client_id: web.client_id,
        redirect_uri: RP_REDIRECT,
        response_type: "code",
        scope: "openid profile",
        state,
        prompt: "none",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { origin: null },
    );
    const location = new URL(denied.headers.get("location") as string);
    expect(location.origin + location.pathname).toBe(RP_REDIRECT);
    expect(location.searchParams.get("error")).toBe("login_required");
    expect(location.searchParams.get("state")).toBe(state);
    expect(location.hash).toBe("");
    expect(location.searchParams.get("error_description")).not.toContain(CANARY);
    // The login app redirect carries only the interaction id or an error code.
    const toLogin = await h.send(
      `/authorize?client_id=${encodeURIComponent(CANARY)}&redirect_uri=${encodeURIComponent(RP_REDIRECT)}&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`,
      { origin: null },
    );
    const login = new URL(toLogin.headers.get("location") as string);
    expect(login.origin).toBe(LOGIN_ORIGIN);
    expect(login.href).not.toContain(CANARY);
    // JSON errors carry fixed descriptions.
    const errors = await Promise.all([
      h.send("/token", {
        method: "POST",
        origin: null,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: CANARY, client_id: CANARY }).toString(),
      }),
      h.send(`/api/v1/interactions/${CANARY.padEnd(43, "x")}`, { origin: LOGIN_ORIGIN }),
      h.send(`/api/v1/admin/users/${CANARY}`, { origin: null }),
    ]);
    for (const res of errors) {
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(await res.text()).not.toContain(CANARY);
    }
  });
});
