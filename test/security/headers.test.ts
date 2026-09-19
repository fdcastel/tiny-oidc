import { describe, expect, it } from "vitest";
import { ROUTES, type Route } from "../../src/router/routes.ts";
import { adminSettings } from "../support/admin.ts";
import { harness, LOGIN_ORIGIN } from "../support/http.ts";
import { op } from "../support/op.ts";

// Headers and CORS (spec §13.7, TIO-TEST-020, TIO-HTTP-002, TIO-HTTP-003,
// TIO-HTTP-006): the full matrix of routes × required headers, driven by the
// route table so a new route cannot escape it. Requests carry no credentials:
// the headers are asserted whatever the status.

const h = harness();
const OTHER_ORIGIN = "https://evil.example.net";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SECURITY_CSP = "default-src 'none'; frame-ancestors 'none'";
const ASSETS_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const PERMISSIONS = "publickey-credentials-get=(), publickey-credentials-create=()";

/** A concrete path for a route pattern: ids of the right shape, a wildcard file. */
function concrete(route: Route): string {
  const ids: Record<string, string> = {
    id: "01a3185c-5000-7ccb-94dc-6d2f7475a31f",
    pid: "01a3185c-5000-7ccb-94dc-6d2f7475a31c",
    iid: "01a3185c-5000-7ccb-94dc-6d2f7475a31b",
    sid: "01a3185c-5000-7ccb-94dc-6d2f7475a31e",
    fid: "01a3185c-5000-7ccb-94dc-6d2f7475a31d",
    user_id: "01a3185c-5000-7ccb-94dc-6d2f7475a31a",
    client_id: "some-client",
    alias: "google",
    kid: "kid-1",
  };
  return route.path
    .replace(/:([a-z_]+)/g, (_, name: string) => ids[name] ?? "x")
    .replace("*", "index.html");
}

function expectSecurityHeaders(res: Response, route: Route, label: string): void {
  expect(res.headers.get("X-Content-Type-Options"), label).toBe("nosniff");
  expect(res.headers.get("Referrer-Policy"), label).toBe("no-referrer");
  expect(res.headers.get("Content-Security-Policy"), label).toBe(
    route.assets ? ASSETS_CSP : SECURITY_CSP,
  );
  expect(res.headers.get("Strict-Transport-Security"), label).toBe(
    "max-age=31536000; includeSubDomains",
  );
  expect(res.headers.get("X-Request-Id"), label).toMatch(UUID);
  expect(res.headers.get("Permissions-Policy"), label).toBe(route.navigation ? PERMISSIONS : null);
  const cache = res.headers.get("Cache-Control");
  if (route.cacheable && res.ok) expect(cache, label).toMatch(/^public, max-age=\d+$/);
  else expect(cache, label).toBe("no-store");
  expect(res.headers.get("Content-Type") ?? "", label).not.toMatch(/text\/html/);
}

const corsHeaders = (res: Response) => ({
  origin: res.headers.get("Access-Control-Allow-Origin"),
  credentials: res.headers.get("Access-Control-Allow-Credentials"),
  methods: res.headers.get("Access-Control-Allow-Methods"),
  expose: res.headers.get("Access-Control-Expose-Headers"),
  vary: res.headers.get("Vary"),
});

describe("headers and CORS matrix", () => {
  it("[TIO-TEST-020] [TIO-HTTP-002] [TIO-HTTP-003] every route in the table carries the security headers for its class, reflects only login origins on the Interaction API, answers public routes with a star and gives navigation endpoints no CORS at all", async () => {
    await adminSettings(h);
    expect(ROUTES.length).toBeGreaterThan(60);
    for (const route of ROUTES) {
      const path = concrete(route);
      const label = `${route.method} ${route.path}`;
      for (const origin of [LOGIN_ORIGIN, OTHER_ORIGIN]) {
        const res = await h.send(path, {
          method: route.method,
          origin,
          ...(route.method === "GET" || route.method === "DELETE" ? {} : { body: {} }),
        });
        expect(res.status, label).toBeLessThan(500);
        expectSecurityHeaders(res, route, `${label} from ${origin}`);
        const cors = corsHeaders(res);
        if (route.cors === "public") {
          expect(cors, label).toMatchObject({
            origin: "*",
            credentials: null,
            expose: "X-Request-Id",
          });
        } else if (route.cors === "interactions" && origin === LOGIN_ORIGIN) {
          expect(cors, label).toMatchObject({
            origin: LOGIN_ORIGIN,
            credentials: "true",
            expose: "X-Request-Id",
            vary: "Origin",
          });
        } else {
          expect(cors, `${label} from ${origin}`).toMatchObject({
            origin: null,
            credentials: null,
            expose: null,
          });
        }
        // Preflight for the route's method from the same origin.
        const preflight = await h.send(path, {
          method: "OPTIONS",
          origin,
          headers: { "Access-Control-Request-Method": route.method },
        });
        expect(preflight.status, label).toBe(204);
        const pre = corsHeaders(preflight);
        if (route.cors === "public") {
          expect(pre.origin, label).toBe("*");
          expect(pre.methods, label).toContain(route.method);
          expect(pre.credentials, label).toBeNull();
        } else if (route.cors === "interactions" && origin === LOGIN_ORIGIN) {
          expect(pre.origin, label).toBe(LOGIN_ORIGIN);
          expect(pre.credentials, label).toBe("true");
          expect(pre.methods, label).toContain(route.method);
        } else {
          expect(pre.origin, `${label} preflight from ${origin}`).toBeNull();
          expect(pre.methods, label).toBeNull();
        }
      }
    }
  });

  it("[TIO-TEST-020] [TIO-HTTP-006] a Host other than the issuer's is 421 on every route but health, before any handler runs", async () => {
    for (const route of ROUTES) {
      const res = await op(`${OTHER_ORIGIN}${concrete(route)}`, {
        method: route.method,
        headers: { origin: LOGIN_ORIGIN },
      });
      const label = `${route.method} ${route.path}`;
      if (route.path === "/api/v1/health" && route.method === "GET") {
        expect(res.status, label).toBe(200);
      } else {
        expect(res.status, label).toBe(421);
        expect(await res.json(), label).toMatchObject({ error: "invalid_host" });
      }
      expect(res.headers.get("X-Content-Type-Options"), label).toBe("nosniff");
    }
  });
});
