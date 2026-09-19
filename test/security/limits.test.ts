import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { BODY_LIMITS, bodyClass, ROUTES } from "../../src/router/routes.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { createTestClient } from "../support/factories.ts";
import { harness, LOGIN_ORIGIN, RP_REDIRECT } from "../support/http.ts";
import { env } from "../support/op.ts";

// Size limits (spec §13.7, TIO-TEST-020, TIO-HTTP-004, TIO-AUTHZ-001): 413 on
// every body-accepting route of every limit class, 414 on every navigation
// endpoint, and a JSON body nested as deep as the limit allows is refused as
// malformed input rather than crashing the isolate.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

const bytes = (n: number) => "x".repeat(n);

describe("size limits", () => {
  it("[TIO-TEST-020] [TIO-HTTP-004] every body-accepting route answers 413 one byte over its class limit and lets a body at the limit through to the handler", async () => {
    await adminSettings(h);
    const writable = ROUTES.filter((r) => r.method !== "GET" && r.method !== "DELETE");
    const classes = new Set(writable.map((r) => bodyClass(r.path)));
    expect([...classes].sort()).toEqual(["api", "import", "protocol"]);
    for (const route of writable) {
      const limit = BODY_LIMITS[bodyClass(route.path)];
      const path = route.path.replace(/:[a-z_]+/g, "01a3185c-5000-7ccb-94dc-6d2f7475a31f");
      const label = `${route.method} ${route.path}`;
      const send = (size: number) =>
        h.send(path, {
          method: route.method,
          origin: LOGIN_ORIGIN,
          headers: { "content-type": "text/plain" },
          body: bytes(size),
        });
      const over = await send(limit + 1);
      expect(over.status, label).toBe(413);
      expect(await over.json(), label).toMatchObject({ error: "payload_too_large" });
      // At the limit the guard steps aside: whatever the handler says, it is not 413 and not a crash.
      const at = await send(limit);
      expect(at.status, label).not.toBe(413);
      expect(at.status, label).toBeLessThan(500);
    }
  });

  it("[TIO-TEST-020] [TIO-AUTHZ-001] every navigation endpoint answers 414 to a query string over 8 KB without reading it", async () => {
    const navigation = ROUTES.filter((r) => r.navigation && r.method === "GET");
    expect(navigation.map((r) => r.path).sort()).toEqual([
      "/authorize",
      "/federation/callback",
      "/interactions/:id/complete",
      "/logout",
    ]);
    for (const route of navigation) {
      const path = route.path.replace(":id", "01a3185c-5000-7ccb-94dc-6d2f7475a31f");
      const res = await h.send(`${path}?state=${bytes(8 * 1024 + 1)}`, { origin: null });
      expect(res.status, route.path).toBe(414);
      expect(await res.json(), route.path).toMatchObject({ error: "invalid_request" });
      // Just under the bound the endpoint itself answers.
      const under = await h.send(`${path}?state=${bytes(8 * 1024 - 32)}`, { origin: null });
      expect(under.status, route.path).not.toBe(414);
    }
    // POST navigation endpoints bound their query the same way.
    const post = await h.send(`/logout?state=${bytes(8 * 1024 + 1)}`, {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
    });
    expect(post.status).toBe(414);
  });

  it("[TIO-TEST-020] [TIO-HTTP-004] a JSON depth bomb within the body limit is 400 malformed input on the Interaction, Self-service and Admin APIs, never a 500", async () => {
    const operator = await adminUser(h, { scope: "openid account admin" });
    const web = (
      await createTestClient(db, clock, { redirect_uris: [RP_REDIRECT], skip_consent: true })
    ).client;
    const started = await h.start(web, { scope: "openid email" });
    const depth = 10_000;
    const bombs = [
      `${"[".repeat(depth)}${"]".repeat(depth)}`,
      `${'{"a":'.repeat(depth)}1${"}".repeat(depth)}`,
      `{"response":${"[".repeat(depth)}${"]".repeat(depth)}}`,
    ];
    for (const bomb of bombs) {
      expect(bomb.length).toBeLessThanOrEqual(BODY_LIMITS.api);
      const answers = await Promise.all([
        h.post(started, "consent", bomb),
        h.post(started, "passkey/verify", bomb),
        h.send("/api/v1/me", {
          method: "PATCH",
          origin: null,
          headers: { authorization: `Bearer ${operator.access_token}` },
          body: bomb,
        }),
        admin(h, operator.access_token, "users", { method: "POST", body: bomb }),
        admin(h, operator.access_token, "settings", { method: "PATCH", body: bomb }),
        h.send("/api/v1/admin/bootstrap", {
          method: "POST",
          origin: null,
          headers: { authorization: "Bearer nope" },
          body: bomb,
        }),
      ]);
      for (const res of answers) {
        expect(res.status).toBeGreaterThanOrEqual(400);
        expect(res.status).toBeLessThan(500);
        const body = (await res.json()) as { error: string; error_description: string };
        expect(body.error_description.length).toBeLessThanOrEqual(256);
      }
    }
    // A form body of the same shape on the protocol endpoints: bounded parameters, no crash.
    const form = await h.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=${"%5B".repeat(4_000)}`,
    });
    // Nobody is identified, so it is the usual 401; the point is that nothing crashed.
    expect(form.status).toBe(401);
  });
});
