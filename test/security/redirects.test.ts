import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { adminSettings } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";
import { loggedIn } from "../support/sessions.ts";

// Redirects and PKCE (spec §13.7, TIO-TEST-020): the redirect_uri cases the
// unit matcher covers, seen from /authorize where a wrong answer would be an
// open redirect; the login_url handoff that cannot be steered by request
// parameters; and a code_challenge shared by two clients that binds each code
// to the client that asked for it.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

function authorize(client: Client, overrides: Record<string, string>, cookie?: string) {
  const params = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: RP_REDIRECT,
    response_type: "code",
    scope: "openid",
    state: "st-1",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    ...overrides,
  });
  return h.send(`/authorize?${params}`, { origin: null, cookie: cookie ?? null });
}

const location = (res: Response): URL => {
  expect(res.status).toBe(303);
  return new URL(res.headers.get("location") as string);
};

const exchange = (client: Client, code: string) =>
  h.send("/token", {
    method: "POST",
    origin: null,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: client.client_id,
      code,
      redirect_uri: RP_REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });

describe("redirects", () => {
  it("[TIO-TEST-020] [TIO-AUTHZ-005] [TIO-AUTHZ-018] [TIO-CLIENT-011] a redirect_uri with a fragment, userinfo, an https IP literal, a look-alike host or a percent-encoded twin is non-redirectable: the browser lands at login_url and the URI appears nowhere in the response", async () => {
    await adminSettings(h);
    const web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const cases = [
      "https://rp.example.com/cb#fragment",
      "https://user@rp.example.com/cb",
      "https://user:secret@rp.example.com/cb",
      "https://203.0.113.4/cb",
      "https://[2001:db8::1]/cb",
      "https://rp.example.com.evil.net/cb",
      "https://evil.net/https://rp.example.com/cb",
      "https://rp.example.com%2F@evil.net/cb",
      "https://rp.example.com/cb%2F",
      "https://rp.example.com/CB",
      "https://rp.example.com:443/cb",
      "//rp.example.com/cb",
      "rp.example.com/cb",
      "javascript:alert(1)",
    ];
    for (const redirect_uri of cases) {
      const res = await authorize(web, { redirect_uri, state: "s" });
      const target = location(res);
      expect(target.origin, redirect_uri).toBe(LOGIN_ORIGIN);
      expect(target.searchParams.get("error"), redirect_uri).toBe("invalid_request");
      expect(target.searchParams.get("interaction"), redirect_uri).toBeNull();
      expect(res.headers.get("location"), redirect_uri).not.toContain("rp.example.com");
      expect(res.headers.get("location"), redirect_uri).not.toContain("evil");
      expect(res.headers.get("content-type") ?? "", redirect_uri).not.toMatch(/html/);
      expect(await res.text(), redirect_uri).toBe("");
    }
  });

  it("[TIO-TEST-020] [TIO-AUTHZ-018] [TIO-AUTHZ-020] the login_url handoff cannot be steered: request parameters carrying URL syntax leave the Location at login_url with only the interaction id or a fixed error, and a login_url of its own query keeps it", async () => {
    const web = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const hostile = [
      "https://evil.net/#",
      "#@evil.net",
      "?interaction=stolen",
      "&error=none&interaction=x",
      "%0d%0aLocation:%20https://evil.net",
      "\r\nLocation: https://evil.net",
      "//evil.net",
      "\u0000",
    ];
    for (const value of hostile) {
      // Untrusted client: a non-redirectable error.
      const denied = location(await authorize(web, { client_id: value, redirect_uri: value }));
      expect(denied.origin, value).toBe(LOGIN_ORIGIN);
      expect(denied.pathname, value).toBe("/");
      expect([...denied.searchParams.keys()].sort(), value).toEqual(["error", "error_description"]);
      expect(denied.hash, value).toBe("");
      expect(denied.href, value).not.toContain("evil");
      // Trusted client, hostile login_hint: a normal interaction handoff carrying only the id.
      const started = location(await authorize(web, { login_hint: value }));
      expect(started.origin, value).toBe(LOGIN_ORIGIN);
      expect([...started.searchParams.keys()], value).toEqual(["interaction"]);
      expect(started.searchParams.get("interaction"), value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(started.hash, value).toBe("");
      // Trusted client, hostile state: either an interaction handoff or a redirectable
      // invalid_request at the registered URI without the state (TIO-AUTHZ-007); never elsewhere.
      const stated = await authorize(web, { state: value });
      const raw = stated.headers.get("location") as string;
      const target = location(stated);
      expect([LOGIN_ORIGIN, new URL(RP_REDIRECT).origin], value).toContain(target.origin);
      expect(raw, value).not.toMatch(/evil|[\r\n]/);
      expect(raw, value).not.toContain("\u0000");
      if (target.origin === LOGIN_ORIGIN) {
        expect([...target.searchParams.keys()], value).toEqual(["interaction"]);
      } else {
        expect(target.searchParams.get("error"), value).toBe("invalid_request");
        expect(target.searchParams.has("state"), value).toBe(false);
      }
    }
    // The error descriptions are the OP's fixed sentences, never the request's values.
    const sample = location(await authorize(web, { client_id: "https://evil.net/#" }));
    expect(sample.searchParams.get("error_description")).toMatch(/^[\x20-\x7e]{1,256}$/);
    expect(sample.searchParams.get("error_description")).not.toContain("evil");
    // A login_url carrying its own query keeps it and gets the handoff appended with `&`.
    await writeSettings(
      db,
      { login_url: `${LOGIN_ORIGIN}/app/?tenant=t1`, login_origins: [LOGIN_ORIGIN] },
      "test",
      clock.now(),
    );
    clock.advance(61);
    const appended = location(await authorize(web, { state: "https://evil.net/#" }));
    expect(appended.origin + appended.pathname).toBe(`${LOGIN_ORIGIN}/app/`);
    expect(appended.searchParams.get("tenant")).toBe("t1");
    expect([...appended.searchParams.keys()].sort()).toEqual(["interaction", "tenant"]);
    await adminSettings(h);
    clock.advance(61);
  });

  it("[TIO-TEST-020] [TIO-AUTHZ-008] [TIO-TOKEN-011] one code_challenge used by two clients binds each code to the client that requested it: a code redeems only at its own client, with the shared verifier", async () => {
    const a = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const b = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const user = await loggedIn(clock);
    const codeA = location(await authorize(a, {}, user.cookie)).searchParams.get("code") as string;
    const codeB = location(await authorize(b, {}, user.cookie)).searchParams.get("code") as string;
    expect(codeA).not.toBe(codeB);
    // Crossed: each client presents the other's code with the verifier that matches the challenge.
    const crossed = await Promise.all([exchange(b, codeA), exchange(a, codeB)]);
    for (const res of crossed) {
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: "invalid_grant" });
    }
    // A crossed attempt is a wrong-client failure, not a replay: the codes still redeem at home.
    const own = await Promise.all([exchange(a, codeA), exchange(b, codeB)]);
    for (const res of own) expect(res.status).toBe(200);
    const tokens = (await Promise.all(own.map((r) => r.json()))) as { access_token: string }[];
    expect(tokens[0]?.access_token).not.toBe(tokens[1]?.access_token);
  });
});
