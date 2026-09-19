import { describe, expect, it } from "vitest";
import { applySecurityHeaders } from "../../src/router/headers.ts";
import {
  BODY_LIMITS,
  bodyClass,
  createMatcher,
  ROUTES,
  type Route,
} from "../../src/router/routes.ts";

const routes: Route[] = [
  {
    method: "GET",
    path: "/interactions/:id/complete",
    cors: "none",
    navigation: true,
    cacheable: false,
  },
  {
    method: "GET",
    path: "/.well-known/jwks.json",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  {
    method: "POST",
    path: "/api/v1/me/passkeys/:id",
    cors: "public",
    navigation: false,
    cacheable: false,
  },
  {
    method: "DELETE",
    path: "/api/v1/me/passkeys/:id",
    cors: "public",
    navigation: false,
    cacheable: false,
  },
];

describe("route table", () => {
  it("matches path templates with parameters, lists the methods of a path and escapes literal characters", () => {
    const match = createMatcher(routes);
    expect(match("GET", "/interactions/abc-123/complete")).toEqual({
      route: routes[0],
      methods: ["GET"],
      template: "/interactions/:id/complete",
    });
    expect(match("GET", "/interactions//complete").route).toBeUndefined();
    expect(match("GET", "/interactions/a/b/complete").route).toBeUndefined();
    expect(match("GET", "/.well-known/jwks.json").route).toBe(routes[1]);
    expect(match("GET", "/.well-known/jwksXjson").route).toBeUndefined();
    const del = match("DELETE", "/api/v1/me/passkeys/p1");
    expect(del.route).toBe(routes[3]);
    expect(del.methods).toEqual(["POST", "DELETE"]);
    const put = match("PUT", "/api/v1/me/passkeys/p1");
    expect(put.route).toBeUndefined();
    expect(put.methods).toEqual(["POST", "DELETE"]);
    expect(put.template).toBe("/api/v1/me/passkeys/:id");
    expect(match("GET", "/unknown")).toEqual({
      route: undefined,
      methods: [],
      template: undefined,
    });
  });

  it("[TIO-HTTP-004] classifies body limits by path", () => {
    expect(bodyClass("/token")).toBe("protocol");
    expect(bodyClass("/api/v1/me")).toBe("api");
    expect(bodyClass("/api/v1/admin/import/users")).toBe("import");
    expect(BODY_LIMITS).toEqual({ protocol: 16_384, api: 65_536, import: 8_388_608 });
  });

  it("[TIO-HTTP-002] navigation routes get the Permissions-Policy header and cacheable routes keep their Cache-Control", () => {
    const navigation = new Headers();
    applySecurityHeaders(navigation, routes[0]);
    expect(navigation.get("Permissions-Policy")).toBe(
      "publickey-credentials-get=(), publickey-credentials-create=()",
    );
    expect(navigation.get("Cache-Control")).toBe("no-store");
    const cached = new Headers({ "Cache-Control": "public, max-age=300" });
    applySecurityHeaders(cached, routes[1]);
    expect(cached.get("Cache-Control")).toBe("public, max-age=300");
    expect(cached.get("Permissions-Policy")).toBeNull();
    const overridden = new Headers({ "Cache-Control": "public, max-age=300" });
    applySecurityHeaders(overridden, routes[2]);
    expect(overridden.get("Cache-Control")).toBe("no-store");
    const unknown = new Headers();
    applySecurityHeaders(unknown, undefined);
    expect(unknown.get("Cache-Control")).toBe("no-store");
  });

  it("has no duplicate (method, path) entries", () => {
    const keys = ROUTES.map((r) => `${r.method} ${r.path}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
