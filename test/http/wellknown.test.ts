import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { rotateSigningKey } from "../../src/crypto/keystore.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Env } from "../../src/env.ts";
import type { LogLine } from "../../src/obs/log.ts";
import { CAPABILITIES } from "../../src/oidc/capabilities.ts";
import { createApp } from "../../src/router/app.ts";
import { ROUTES } from "../../src/router/routes.ts";
import { FakeClock } from "../support/clock.ts";
import { testKeys } from "../support/keys.ts";
import { env, op, url } from "../support/op.ts";
import { resetStorage } from "../support/reset.ts";

const ISSUER = "https://auth.example.com";

/** An app with a log collector, driven directly, so cache hits show up as d1_reads = 0. */
function harness(overrides: Partial<Env> = {}) {
  const lines: LogLine[] = [];
  const app = createApp({ clock: new FakeClock(), sink: (line) => lines.push(line) });
  const testEnv = { ...env, ...overrides } as Env;
  const fetch = async (path: string) => {
    const ctx = createExecutionContext();
    const res = await app.fetch(new Request(url(path)), testEnv, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  return { fetch, lines };
}

const uncache = (path: string) => caches.default.delete(new Request(url(path)));

describe("discovery", () => {
  beforeEach(async () => {
    await resetStorage();
    for (const path of [
      "/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server",
      "/.well-known/jwks.json",
      "/.well-known/webauthn",
    ]) {
      await uncache(path);
    }
  });

  it("[TIO-DISC-001] both well-known paths return the same document, built from ISSUER, with public caching", async () => {
    const oidc = await op("/.well-known/openid-configuration");
    const oauth = await op("/.well-known/oauth-authorization-server");
    expect(oidc.status).toBe(200);
    expect(oidc.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(oauth.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(oidc.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const a = (await oidc.json()) as Record<string, unknown>;
    const b = (await oauth.json()) as Record<string, unknown>;
    expect(a).toEqual(b);
    expect(a).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      pushed_authorization_request_endpoint: `${ISSUER}/par`,
      require_pushed_authorization_requests: false,
      token_endpoint: `${ISSUER}/token`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      revocation_endpoint: `${ISSUER}/revoke`,
      end_session_endpoint: `${ISSUER}/logout`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      subject_types_supported: ["public"],
      claims_parameter_supported: false,
      request_parameter_supported: false,
      authorization_response_iss_parameter_supported: true,
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true,
      frontchannel_logout_supported: false,
      ui_locales_supported: [],
    });
    expect(a["service_documentation"]).toMatch(/^https:\/\/github\.com\/.*TINY_OIDC_SPEC\.md$/);
  });

  it("[TIO-DISC-002] [TIO-DISC-004] every advertised list deep-equals the capabilities constant and every advertised endpoint is in the route table", async () => {
    const doc = (await (await op("/.well-known/openid-configuration")).json()) as Record<
      string,
      unknown
    >;
    for (const [key, value] of Object.entries(CAPABILITIES)) {
      expect(doc[key], key).toEqual(value);
    }
    const arrays = Object.entries(doc).filter(
      ([, v]) => Array.isArray(v) && (v as unknown[]).length > 0,
    );
    for (const [key, value] of arrays) {
      expect(
        CAPABILITIES[key as keyof typeof CAPABILITIES],
        `${key} must come from capabilities.ts`,
      ).toEqual(value);
    }
    const endpoints = Object.entries(doc).filter(
      ([k]) => k.endsWith("_endpoint") || k === "jwks_uri",
    );
    expect(endpoints.map(([k]) => k).sort()).toEqual([
      "authorization_endpoint",
      "end_session_endpoint",
      "jwks_uri",
      "pushed_authorization_request_endpoint",
      "revocation_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
    ]);
    for (const [key, value] of endpoints) {
      const path = new URL(value as string).pathname;
      expect(
        ROUTES.some((r) => r.path === path),
        `${key} → ${path} is routed`,
      ).toBe(true);
    }
  });

  it("[TIO-DISC-003] request_uri_parameter_supported is false while PAR is advertised", async () => {
    const doc = (await (await op("/.well-known/openid-configuration")).json()) as Record<
      string,
      unknown
    >;
    expect(doc["request_uri_parameter_supported"]).toBe(false);
    expect(doc["pushed_authorization_request_endpoint"]).toBe(`${ISSUER}/par`);
  });

  it("[TIO-DISC-001] the document is served from the Worker cache on the next request", async () => {
    const { fetch, lines } = harness();
    await fetch("/.well-known/openid-configuration");
    const second = await fetch("/.well-known/openid-configuration");
    expect(second.status).toBe(200);
    expect(second.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(second.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(lines.filter((l) => l.msg === "request")).toHaveLength(2);
  });
});

describe("JWKS", () => {
  beforeEach(async () => {
    await resetStorage();
    await uncache("/.well-known/jwks.json");
  });

  it("[TIO-KEYS-001] publishes every unretired key with kid, kty, crv, alg, use, x, y and never d", async () => {
    const res = await op("/.well-known/jwks.json");
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain('"d"');
    const { keys } = JSON.parse(text) as { keys: Record<string, unknown>[] };
    expect(keys).toHaveLength(1);
    expect(Object.keys(keys[0] as object).sort()).toEqual([
      "alg",
      "crv",
      "kid",
      "kty",
      "use",
      "x",
      "y",
    ]);
    expect(keys[0]).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
    const health = (await (await op("/api/v1/health")).json()) as { active_kid: string };
    expect(keys[0]?.["kid"]).toBe(health.active_kid);
  });

  it("[TIO-KEYS-002] carries Cache-Control public max-age=300 and is served from the Worker cache without touching D1", async () => {
    const { fetch, lines } = harness();
    const first = await fetch("/.well-known/jwks.json");
    expect(first.headers.get("Cache-Control")).toBe("public, max-age=300");
    const second = await fetch("/.well-known/jwks.json");
    expect(await second.json()).toEqual(await first.json());
    const requests = lines.filter((l) => l.msg === "request");
    expect(requests).toHaveLength(2);
    expect(requests[0]?.["d1_reads"]).toBeGreaterThan(0);
    expect(requests[1]?.["d1_reads"]).toBe(0);
    expect(requests[1]?.["d1_writes"]).toBe(0);
  });
});

describe("health and keys", () => {
  beforeEach(resetStorage);

  it("[TIO-OBS-003] health reports active_kid null while only a next key exists, and stays 200", async () => {
    await rotateSigningKey(Db.from(env.DB), testKeys(), new FakeClock().now() + 10, 3_600, false);
    const { fetch } = harness();
    const res = await fetch("/api/v1/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok", d1: "ok", active_kid: null });
  });
});

describe("WebAuthn related origins", () => {
  beforeEach(async () => {
    await resetStorage();
    await uncache("/.well-known/webauthn");
  });

  it("[TIO-PK-001] serves {origins} from webauthn_origins, cacheable, empty until configured", async () => {
    const empty = await op("/.well-known/webauthn");
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual({ origins: [] });
    expect(empty.headers.get("Cache-Control")).toBe("public, max-age=300");
    await writeSettings(
      Db.from(env.DB),
      {
        login_origins: ["https://login.example.com"],
        webauthn_origins: ["https://login.example.com", "https://app.example.com"],
      },
      "test",
      0,
    );
    await uncache("/.well-known/webauthn");
    const { fetch } = harness();
    expect(await (await fetch("/.well-known/webauthn")).json()).toEqual({
      origins: ["https://login.example.com", "https://app.example.com"],
    });
  });
});

describe("protocol endpoints before Phase 2", () => {
  it("answer 501 not_implemented on every route of the table that has no handler yet, with the right header class", async () => {
    const cases: [string, string, boolean][] = [
      ["GET", "/logout", true],
      ["POST", "/logout", true],
      ["GET", "/federation/callback", true],
      ["POST", "/federation/callback", true],
    ];
    for (const [method, path, navigation] of cases) {
      const res = await op(path, { method, headers: { Origin: "https://app.example.org" } });
      expect(res.status, `${method} ${path}`).toBe(501);
      expect(await res.json()).toMatchObject({ error: "not_implemented" });
      expect(res.headers.get("Permissions-Policy"), path).toBe(
        navigation ? "publickey-credentials-get=(), publickey-credentials-create=()" : null,
      );
      expect(res.headers.get("Access-Control-Allow-Origin"), path).toBe(navigation ? null : "*");
    }
    const preflight = await op("/authorize", {
      method: "OPTIONS",
      headers: { Origin: "https://app.example.org", "Access-Control-Request-Method": "GET" },
    });
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});
