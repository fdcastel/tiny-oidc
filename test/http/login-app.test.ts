import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import type { Env } from "../../src/env.ts";
import { matchRoute } from "../../src/router/routes.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const bundled = { ...env, BUNDLED_LOGIN_APP: "true" } as Env;

describe("bundled login app", () => {
  it("[TIO-IX-081] [TIO-GEN-001] serves examples/login-app under /login/ when BUNDLED_LOGIN_APP is true, with the security headers, a CSP for same-origin scripts and styles, and no WebAuthn denial", async () => {
    const index = await h.send("/login/", { origin: null, env: bundled });
    expect(index.status).toBe(200);
    expect(index.headers.get("content-type")).toMatch(/^text\/html/);
    const html = await index.text();
    expect(html).toContain('<script src="app.js">');
    expect(html).toContain('<link rel="stylesheet" href="style.css">');
    expect(html).toContain('name="tio-issuer"');
    const script = await h.send("/login/app.js", { origin: null, env: bundled });
    expect(script.status).toBe(200);
    expect(script.headers.get("content-type")).toMatch(/javascript/);
    expect(await script.text()).toContain("/api/v1/interactions/");
    const style = await h.send("/login/style.css", { origin: null, env: bundled });
    expect(style.status).toBe(200);
    for (const res of [index, script, style]) {
      expect(res.headers.get("cache-control")).toBe("public, max-age=300");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      expect(res.headers.get("strict-transport-security")).toBe(
        "max-age=31536000; includeSubDomains",
      );
      expect(res.headers.get("content-security-policy")).toBe(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      );
      expect(res.headers.get("permissions-policy")).toBeNull();
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
      expect(res.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    }
    // Deep paths and index resolution.
    expect((await h.send("/login/index.html", { origin: null, env: bundled })).status).toBe(200);
    const missing = await h.send("/login/nope.js", { origin: null, env: bundled });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: "not_found" });
    expect((await h.send("/login/", { origin: null, method: "POST", env: bundled })).status).toBe(
      405,
    );
    expect(matchRoute("GET", "/login/deep/er/file.css").route?.path).toBe("/login/*");
    expect(matchRoute("GET", "/loginx").route).toBeUndefined();
  });

  it("[TIO-IX-081] with the app bundled and no login_url stored, /authorize sends the browser to ISSUER/login/ and the app's origin may call the Interaction API", async () => {
    const client = (await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT] })).client;
    const fresh = harness(clock);
    const params = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri: RP_REDIRECT,
      response_type: "code",
      scope: "openid",
      state: "s",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
    });
    const res = await fresh.send(`/authorize?${params}`, { origin: null, env: bundled });
    expect(res.status).toBe(303);
    const location = new URL(res.headers.get("location") as string);
    expect(`${location.origin}${location.pathname}`).toBe("https://auth.example.com/login/");
    const id = location.searchParams.get("interaction") as string;
    const cookie = (res.headers.getSetCookie()[0] as string).split(";")[0] as string;
    const doc = await fresh.send(`/api/v1/interactions/${id}`, {
      origin: "https://auth.example.com",
      cookie,
      env: bundled,
    });
    expect(doc.status).toBe(200);
    expect(doc.headers.get("access-control-allow-origin")).toBe("https://auth.example.com");
    // Without the bundle the same deployment is not configured.
    expect((await harness(clock).send(`/authorize?${params}`, { origin: null })).status).toBe(503);
  });

  it("[TIO-IX-081] answers 404 under /login/ when the app is not bundled, and never serves the files", async () => {
    for (const path of ["/login/", "/login/app.js", "/login/index.html"]) {
      const res = await h.send(path, { origin: null });
      expect(res.status, path).toBe(404);
      expect(await res.json(), path).toMatchObject({ error: "not_found" });
      expect(res.headers.get("content-security-policy"), path).toBe(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      );
    }
  });
});
