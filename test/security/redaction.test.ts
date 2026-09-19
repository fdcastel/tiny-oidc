import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";

// Redaction (spec §13.7, TIO-TEST-020, TIO-AUDIT-002, TIO-OBS-001, TIO-ERR-001):
// a canary planted in every caller-controlled position of every surface never
// reaches a log line, an audit event or an error body. The audit emitters are
// fed canaries directly in test/unit/audit-redaction.test.ts; this is the
// end-to-end net over the request path.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

const CANARY = "CANARY_LEAK_7c1e";
/** A canary shaped like a token, so shape-based scrubbing alone would not catch a plain word. */
const JWT_CANARY = `eyJhbGciOiJFUzI1NiIsImtpZCI6IkNBTkFSWSJ9.eyJzdWIiOiIke${CANARY}In0.c2lnbmF0dXJl`;
const TOKENS = [CANARY, JWT_CANARY];

const form = (path: string, params: Record<string, string>, headers: Record<string, string> = {}) =>
  h.send(path, {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(params).toString(),
  });

describe("redaction over the request path", () => {
  it("[TIO-TEST-020] [TIO-AUDIT-002] [TIO-OBS-001] [TIO-ERR-001] canaries in every query parameter, form field, JSON field, header, cookie and path segment reach no log line, audit event or error body", async () => {
    await adminSettings(h);
    const operator = await adminUser(h, { scope: "openid account admin" });
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const started = await h.start(web, { scope: "openid email" });
    h.lines.length = 0;
    const c = CANARY;
    const q = (params: Record<string, string>) => new URLSearchParams(params).toString();
    const responses: Response[] = [];
    for (const token of TOKENS) {
      const attempts: Promise<Response>[] = [
        // Navigation endpoints: every documented parameter.
        h.send(
          `/authorize?${q({
            client_id: token,
            redirect_uri: `https://${c}.example.com/cb`,
            response_type: token,
            scope: token,
            state: token,
            nonce: token,
            code_challenge: token,
            code_challenge_method: token,
            prompt: token,
            login_hint: token,
            ui_locales: token,
            acr_values: token,
            max_age: token,
            request_uri: token,
          })}`,
          { origin: null, cookie: `__Host-tio_s=${token}; ${c}=${c}` },
        ),
        h.send(
          `/authorize?${q({
            client_id: web.client_id,
            redirect_uri: RP_REDIRECT,
            response_type: "code",
            scope: `openid ${token}`,
            // state is echoed to the client by design (TIO-AUTHZ-019); the injection test covers its encoding.
            state: "s-1",
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            code_challenge_method: "S256",
            login_hint: token,
          })}`,
          { origin: null },
        ),
        h.send(
          `/logout?${q({ id_token_hint: token, post_logout_redirect_uri: `https://${c}.example.com/`, state: token, client_id: token })}`,
          { origin: null, cookie: `__Host-tio_s=${token}` },
        ),
        h.send(
          `/federation/callback?${q({ state: token, code: token, error: token, error_description: token })}`,
          { origin: null, cookie: `__Host-tio_ix_${c}=${token}` },
        ),
        h.send(`/interactions/${token}/complete`, {
          origin: null,
          cookie: `__Host-tio_ix_x=${token}`,
        }),
        h.send(`/federation/${token}`, { origin: null }),
        // Token, revocation, PAR, userinfo: every form field and both credential carriers.
        form("/token", {
          grant_type: token,
          client_id: token,
          client_secret: token,
          code: token,
          redirect_uri: token,
          code_verifier: token,
          refresh_token: token,
          scope: token,
          client_assertion_type: token,
          client_assertion: token,
        }),
        form(
          "/token",
          { grant_type: "authorization_code", code: token },
          {
            authorization: `Basic ${btoa(`${token}:${token}`)}`,
          },
        ),
        form("/token", {
          grant_type: "authorization_code",
          client_id: web.client_id,
          code: token,
          redirect_uri: RP_REDIRECT,
          code_verifier: token,
        }),
        form("/token", {
          grant_type: "refresh_token",
          client_id: web.client_id,
          refresh_token: token,
        }),
        form("/revoke", { token, client_id: token, token_type_hint: token }),
        form("/revoke", { token, client_id: web.client_id }),
        form("/par", { client_id: token, redirect_uri: token, state: token, scope: token }),
        h.send("/userinfo", { origin: null, headers: { authorization: `Bearer ${token}` } }),
        form("/userinfo", { access_token: token }),
        // Interaction API: path id, cookie, origin and every body field.
        h.send(`/api/v1/interactions/${token}`, { origin: LOGIN_ORIGIN, cookie: `x=${token}` }),
        h.get(started, { origin: `https://${c}.example.net` }),
        h.get(started, { cookie: `__Host-tio_ix_${started.id}=${token}` }),
        h.post(started, "passkey/verify", {
          response: { id: token, rawId: token, type: token, response: { clientDataJSON: token } },
        }),
        h.post(started, "register/options", {
          email: `${c}@example.com`,
          display_name: token,
          invitation: token,
        }),
        h.post(started, "register/verify", { response: { id: token }, name: token }),
        h.post(started, "consent", { decision: token, scopes: [token] }),
        h.post(started, `upstream/${token}`, {}),
        h.post(started, "logout", { decision: token }),
        // Self-service and Admin APIs: bearer, path segments, filters and bodies.
        h.send("/api/v1/me", { origin: null, headers: { authorization: `Bearer ${token}` } }),
        h.send(`/api/v1/me/passkeys/${token}`, {
          method: "DELETE",
          origin: null,
          headers: { authorization: `Bearer ${operator.access_token}` },
        }),
        h.send("/api/v1/me/passkeys/verify", {
          method: "POST",
          origin: null,
          headers: { authorization: `Bearer ${operator.access_token}` },
          body: { response: { id: token }, name: token },
        }),
        admin(h, token, "users"),
        admin(
          h,
          operator.access_token,
          `users?${q({ email: token, group: token, cursor: token })}`,
        ),
        admin(h, operator.access_token, `users/${token}`),
        admin(h, operator.access_token, `clients/${token}`),
        admin(h, operator.access_token, `groups/${token}`),
        admin(h, operator.access_token, `upstreams/${token}`),
        admin(h, operator.access_token, `invitations/${token}`),
        admin(
          h,
          operator.access_token,
          `audit?${q({ type: token, user_id: token, cursor: token })}`,
        ),
        admin(h, operator.access_token, "users", {
          method: "POST",
          body: { email: token, display_name: token, groups: [token] },
        }),
        admin(h, operator.access_token, "clients", {
          method: "POST",
          body: {
            client_id: token,
            client_name: token,
            redirect_uris: [token],
            client_secret: token,
          },
        }),
        admin(h, operator.access_token, "upstreams", {
          method: "POST",
          body: { alias: token, issuer: token, client_id: token, client_secret: token },
        }),
        admin(h, operator.access_token, "keys/rotate", { method: "POST", body: { mode: token } }),
        h.send("/api/v1/admin/bootstrap", {
          method: "POST",
          origin: null,
          headers: { authorization: `Bearer ${token}` },
          body: { login_url: token },
        }),
        // Headers the OP reads or might log.
        h.send("/api/v1/health", {
          origin: null,
          headers: {
            "user-agent": token,
            "x-forwarded-for": token,
            referer: token,
            "x-request-id": token,
          },
        }),
        h.send(`/${token}`, { origin: null }),
      ];
      responses.push(...(await Promise.all(attempts)));
    }
    // Nothing crashed and no body echoes a canary.
    for (const res of responses) {
      expect(res.status).toBeLessThan(500);
      const text = await res.text();
      for (const token of TOKENS) expect(text).not.toContain(token);
      const location = res.headers.get("location");
      if (location !== null) for (const token of TOKENS) expect(location).not.toContain(token);
    }
    // No log line and no audit event carries a canary, in any field.
    expect(h.lines.length).toBeGreaterThan(responses.length);
    const dumped = JSON.stringify(h.lines);
    for (const token of TOKENS) expect(dumped).not.toContain(token);
  });
});
