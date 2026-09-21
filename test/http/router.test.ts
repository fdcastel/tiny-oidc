import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../../src/env.ts";
import type { LogLine } from "../../src/obs/log.ts";
import { createApp } from "../../src/router/app.ts";
import { ROUTES } from "../../src/router/routes.ts";
import { FakeClock } from "../support/clock.ts";
import { env, op, url } from "../support/op.ts";
import { gatedD1 } from "./faults.ts";

/** An app with a fake clock and a log collector, driven directly (not through SELF). */
function harness(overrides: Partial<Env> = {}) {
  const clock = new FakeClock();
  const lines: LogLine[] = [];
  const app = createApp({ clock, sink: (line) => lines.push(line) });
  const testEnv = { ...env, ...overrides } as Env;
  const fetch = async (input: string, init?: RequestInit) => {
    const ctx = createExecutionContext();
    const res = await app.fetch(new Request(input, init), testEnv, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  return { app, clock, lines, fetch };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("HTTP conventions", () => {
  it("[TIO-HTTP-001] unknown paths are 404 and known paths with an unlisted method are 405 with Allow", async () => {
    const missing = await op(url("/nope"));
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({
      error: "not_found",
      error_description: "no such endpoint",
    });
    const wrongMethod = await op(url("/api/v1/health"), { method: "POST" });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("Allow")).toBe("GET");
    expect(await wrongMethod.json()).toMatchObject({ error: "method_not_allowed" });
    const del = await op(url("/api/v1/openapi.json"), { method: "DELETE" });
    expect(del.status).toBe(405);
  });

  it("[TIO-HTTP-002] every response carries the security headers; cacheable routes keep their Cache-Control", async () => {
    const cases: [string, RequestInit | undefined, number][] = [
      ["/api/v1/health", undefined, 200],
      ["/api/v1/openapi.json", undefined, 200],
      ["/nope", undefined, 404],
      ["/api/v1/health", { method: "POST" }, 405],
    ];
    for (const [path, init, status] of cases) {
      const res = await op(url(path), init);
      expect(res.status, path).toBe(status);
      expect(res.headers.get("X-Content-Type-Options"), path).toBe("nosniff");
      expect(res.headers.get("Referrer-Policy"), path).toBe("no-referrer");
      expect(res.headers.get("Content-Security-Policy"), path).toBe(
        "default-src 'none'; frame-ancestors 'none'",
      );
      expect(res.headers.get("Strict-Transport-Security"), path).toBe(
        "max-age=31536000; includeSubDomains",
      );
      expect(res.headers.get("X-Request-Id"), path).toMatch(UUID);
      expect(res.headers.get("Permissions-Policy"), path).toBeNull();
      const route = ROUTES.find((r) => r.path === path && r.method === (init?.method ?? "GET"));
      expect(res.headers.get("Cache-Control"), path).toBe(
        route?.cacheable ? "public, max-age=300" : "no-store",
      );
    }
  });

  it("[TIO-HTTP-003] public routes answer preflights with a star origin and no credentials; unknown paths get no CORS headers", async () => {
    const preflight = await op(url("/api/v1/health"), {
      method: "OPTIONS",
      headers: { Origin: "https://app.example.org", "Access-Control-Request-Method": "GET" },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(preflight.headers.get("Access-Control-Allow-Methods")).toBe("GET");
    expect(preflight.headers.get("Access-Control-Allow-Headers")).toBe(
      "Authorization, Content-Type",
    );
    expect(preflight.headers.get("Access-Control-Max-Age")).toBe("600");
    expect(preflight.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    const actual = await op(url("/api/v1/openapi.json"), {
      headers: { Origin: "https://app.example.org" },
    });
    expect(actual.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(actual.headers.get("Access-Control-Expose-Headers")).toBe("X-Request-Id");
    const unknownPreflight = await op(url("/nope"), {
      method: "OPTIONS",
      headers: { Origin: "https://app.example.org", "Access-Control-Request-Method": "POST" },
    });
    expect(unknownPreflight.status).toBe(204);
    expect(unknownPreflight.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const implicit = await op(url("/api/v1/health"), {
      method: "OPTIONS",
      headers: { Origin: "https://x.example" },
    });
    expect(implicit.headers.get("Access-Control-Allow-Methods")).toBe("GET");
    const unknownActual = await op(url("/nope"), {
      headers: { Origin: "https://app.example.org" },
    });
    expect(unknownActual.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("[TIO-HTTP-004] bodies over the class limit are 413: 16 KB on protocol endpoints, 64 KB on JSON APIs, 8 MB on import", async () => {
    const big = (bytes: number) => "x".repeat(bytes);
    const post = (path: string, size: number) =>
      op(url(path), {
        method: "POST",
        body: big(size),
        headers: { "content-type": "text/plain" },
      });
    expect((await post("/token", 16 * 1024 + 1)).status).toBe(413);
    expect((await post("/token", 16 * 1024)).status).toBe(400);
    expect((await post("/api/v1/admin/users", 64 * 1024 + 1)).status).toBe(413);
    // Within the limit the guard answers (no token), not the router.
    expect((await post("/api/v1/admin/users", 64 * 1024)).status).toBe(401);
    expect((await post("/api/v1/admin/import/users", 64 * 1024 + 1)).status).toBe(401);
    const tooLarge = await post("/token", 20_000);
    expect(await tooLarge.json()).toMatchObject({ error: "payload_too_large" });
    // A chunked body without Content-Length is limited while streaming.
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(big(17 * 1024)));
        controller.close();
      },
    });
    const chunked = await op(url("/token"), {
      method: "POST",
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(chunked.status).toBe(413);
  });

  it("[TIO-AUTHZ-001] a query string over 8 KB is 414 invalid_request", async () => {
    const res = await op(url(`/api/v1/health?x=${"a".repeat(8 * 1024)}`));
    expect(res.status).toBe(414);
    expect(await res.json()).toMatchObject({ error: "invalid_request" });
    expect((await op(url(`/api/v1/health?x=${"a".repeat(8 * 1024 - 3)}`))).status).toBe(200);
  });

  it("[TIO-HTTP-005] every request gets a UUID v7 request id in the header and in error bodies", async () => {
    const a = await op(url("/nope"));
    const b = await op(url("/nope"));
    const idA = a.headers.get("X-Request-Id") as string;
    const idB = b.headers.get("X-Request-Id") as string;
    expect(idA).toMatch(UUID);
    expect(idB).toMatch(UUID);
    expect(idA).not.toBe(idB);
    expect(((await a.json()) as { request_id: string }).request_id).toBe(idA);
    const ok = await op(url("/api/v1/health"));
    expect(ok.headers.get("X-Request-Id")).toMatch(UUID);
  });

  it("[TIO-HTTP-006] a Host that differs from the issuer is 421 everywhere except health, which reports the mismatch", async () => {
    const other = await op("https://evil.example.net/api/v1/openapi.json");
    expect(other.status).toBe(421);
    expect(await other.json()).toMatchObject({ error: "invalid_host" });
    const missing = await op("https://evil.example.net/nope");
    expect(missing.status).toBe(421);
    const health = await op("https://evil.example.net/api/v1/health");
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({
      status: "ok",
      issuer_mismatch: "evil.example.net",
    });
    const post = await op("https://evil.example.net/api/v1/health", { method: "POST" });
    expect(post.status).toBe(421);
  });

  it("[TIO-ERR-001] JSON errors have exactly error, error_description (ASCII, ≤ 256) and request_id", async () => {
    const res = await op(url("/nope"));
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["error", "error_description", "request_id"]);
    expect(body["error_description"]).toMatch(/^[\x20-\x7e]{1,256}$/);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
  });
});

describe("health and observability", () => {
  it("[TIO-OBS-003] health reports ok, the version, D1 liveness and the clock time without touching a Durable Object", async () => {
    const { fetch, clock, lines } = harness({ VERSION: "abc1234" });
    const res = await fetch(url("/api/v1/health"));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      version: "abc1234",
      // The first request on an empty key store creates the signing key (TIO-KEYS-010).
      active_kid: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      d1: "ok",
      time: clock.now(),
    });
    const line = lines.find((l) => l.msg === "request") as LogLine;
    expect(line["do_calls"]).toBe(0);
    expect(line["d1_reads"]).toBeGreaterThanOrEqual(1);
    const dev = await op(url("/api/v1/health"));
    expect(await dev.json()).toMatchObject({ version: "dev" });
  });

  it("[TIO-OBS-003] health is degraded with 503 when D1 fails", async () => {
    const broken = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
      withSession() {
        return this;
      },
    } as unknown as D1Database;
    const { fetch } = harness({ DB: broken });
    const res = await fetch(url("/api/v1/health"));
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ status: "degraded", d1: "error" });
  });

  it("[TIO-OBS-001] every request produces exactly one structured log line with the route template and counters, and no query string or body", async () => {
    const { fetch, lines } = harness({ LOG_LEVEL: "debug" });
    // First call bootstraps the signing key; the line under test is the second, cached one.
    await fetch(url("/api/v1/health"));
    lines.length = 0;
    const res = await fetch(url("/api/v1/health?secret=1"), { headers: { "content-length": "0" } });
    expect(res.status).toBe(200);
    const requests = lines.filter((l) => l.msg === "request");
    expect(requests).toHaveLength(1);
    const line = requests[0] as LogLine;
    expect(line).toMatchObject({
      level: "info",
      route: "/api/v1/health",
      method: "GET",
      status: 200,
      do_calls: 0,
      d1_reads: 1,
      d1_writes: 0,
      content_length: 0,
    });
    expect(line["request_id"]).toBe(res.headers.get("X-Request-Id"));
    expect(typeof line["duration_ms"]).toBe("number");
    expect(JSON.stringify(line)).not.toContain("secret=1");
    expect(line["error"]).toBeUndefined();
    const notFound = await fetch(url("/does/not/exist"));
    const line2 = lines.filter((l) => l.msg === "request")[1] as LogLine;
    expect(line2).toMatchObject({
      route: "unmatched",
      status: 404,
      error: "not_found",
      content_length: null,
    });
    expect(notFound.status).toBe(404);
    expect(lines.filter((l) => l.msg === "request")).toHaveLength(2);
  });

  it("[TIO-ARCH-011] a cold isolate loads settings and keys in one round trip and concurrent requests share the load: both statements are in flight together, once, and every request answers when they land", async () => {
    // A warmed store, so the loads read rather than create.
    await harness().fetch(url("/api/v1/health"));
    const gate = gatedD1();
    const { fetch, lines } = harness({ DB: gate.db, LOG_LEVEL: "debug" });
    // Three concurrent requests on the cold isolate: two health checks, one discovery.
    const inFlight = [
      fetch(url("/api/v1/health")),
      fetch(url("/api/v1/health")),
      fetch(url("/.well-known/openid-configuration")),
    ];
    // Settings, keys and the two health pings are all at the gate before any answers:
    // the loads were started together, not one after the other, and once each.
    await gate.until(4);
    const started = gate.pending();
    expect(started.filter((sql) => /FROM settings/.test(sql))).toHaveLength(1);
    expect(started.filter((sql) => /FROM signing_keys/.test(sql))).toHaveLength(1);
    expect(started.filter((sql) => /^SELECT 1/.test(sql))).toHaveLength(2);
    gate.open();
    const answers = await Promise.all(inFlight);
    expect(answers.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(lines.filter((l) => l.msg === "request")).toHaveLength(3);
  });

  it("[TIO-OBS-002] writes one data point per request and one per audit event type and outcome when metrics are bound, and a refused write never fails the request", async () => {
    const points: { blobs: string[]; doubles: number[]; indexes: string[] }[] = [];
    const metrics = {
      writeDataPoint: (p: { blobs: string[]; doubles: number[]; indexes: string[] }) =>
        points.push(p),
    } as unknown as AnalyticsEngineDataset;
    const withMetrics = harness({ METRICS: metrics });
    // A refused client authentication is a request with one audit event.
    const res = await withMetrics.fetch(url("/token"), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=client_credentials&client_id=nobody&client_secret=x",
    });
    expect(res.status).toBe(401);
    expect(points).toEqual([
      {
        blobs: ["/token", "401", "invalid_client"],
        doubles: [expect.any(Number)],
        indexes: ["/token"],
      },
      {
        blobs: ["token.client_auth_failed", "failure"],
        doubles: [1],
        indexes: ["token.client_auth_failed"],
      },
    ]);
    // The binding refuses (its per-invocation write limit): logged, and the request still answers.
    const refusing = {
      writeDataPoint: () => {
        throw new Error("Analytics Engine write limit exceeded.");
      },
    } as unknown as AnalyticsEngineDataset;
    const overLimit = harness({ METRICS: refusing });
    expect((await overLimit.fetch(url("/api/v1/health"))).status).toBe(200);
    expect(overLimit.lines.at(-1)).toMatchObject({
      level: "warn",
      msg: "metrics write failed",
      reason: "Analytics Engine write limit exceeded.",
    });
  });

  it("[TIO-OBS-001] log lines below the configured level are dropped and metrics are written only when the binding exists", async () => {
    const { fetch, lines } = harness({ LOG_LEVEL: "error" });
    await fetch(url("/api/v1/health"));
    expect(lines).toEqual([]);
    const points: unknown[] = [];
    const metrics = {
      writeDataPoint: (p: unknown) => points.push(p),
    } as unknown as AnalyticsEngineDataset;
    const withMetrics = harness({ METRICS: metrics });
    await withMetrics.fetch(url("/nope"));
    expect(points).toEqual([
      {
        blobs: ["unmatched", "404", "not_found"],
        doubles: [expect.any(Number)],
        indexes: ["unmatched"],
      },
    ]);
    const { METRICS: _omitted, ...withoutMetrics } = env;
    const bare = createApp({ clock: new FakeClock(), sink: () => {} });
    const res = await bare.fetch(
      new Request(url("/api/v1/health")),
      withoutMetrics as Env,
      createExecutionContext(),
    );
    expect(res.status).toBe(200);
  });
});

describe("startup configuration", () => {
  it("[TIO-CRYPTO-010] with missing or malformed MASTER_KEYS every request, including health, fails with 500 server_error and a fatal log", async () => {
    const { MASTER_KEYS: _omitted, ...withoutKeys } = env;
    const lines: LogLine[] = [];
    const app = createApp({ clock: new FakeClock(), sink: (l) => lines.push(l) });
    for (const path of ["/api/v1/health", "/nope", "/api/v1/openapi.json"]) {
      const res = await app.fetch(
        new Request(url(path)),
        withoutKeys as Env,
        createExecutionContext(),
      );
      expect(res.status, path).toBe(500);
      expect(await res.json()).toMatchObject({
        error: "server_error",
        error_description: "server misconfigured",
      });
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(res.headers.get("X-Request-Id")).toMatch(UUID);
    }
    expect(
      lines.filter((l) => l.level === "error" && String(l.msg).startsWith("fatal")),
    ).toHaveLength(3);
    expect(lines[0]?.["reason"]).toMatch(/^invalid secrets: MASTER_KEYS/);
    const malformed = harness({ MASTER_KEYS: "{}" });
    expect((await malformed.fetch(url("/api/v1/health"))).status).toBe(500);
  });

  it("[TIO-CFG-002] an invalid ISSUER fails every request; the validation result is cached per configuration", async () => {
    const { fetch, lines } = harness({ ISSUER: "http://auth.example.com" });
    expect((await fetch(url("/api/v1/health"))).status).toBe(500);
    expect((await fetch(url("/api/v1/health"))).status).toBe(500);
    expect(lines.filter((l) => String(l.msg).startsWith("fatal"))).toHaveLength(2);
    expect(lines[0]?.["reason"]).toMatch(/TIO-CFG-002/);
  });

  it("[TIO-ARCH-014] an unhandled error maps to a generic 500 with details only in the log", async () => {
    const { app, lines } = harness();
    app.get("/boom", () => {
      throw new Error("kaboom: secret-detail");
    });
    const res = await app.fetch(new Request(url("/boom")), env as Env, createExecutionContext());
    expect(res.status).toBe(500);
    const body = await res.text();
    expect(body).not.toContain("kaboom");
    expect(JSON.parse(body)).toMatchObject({
      error: "server_error",
      error_description: "internal error",
    });
    expect(lines.find((l) => l.msg === "unhandled error")?.["message"]).toBe(
      "kaboom: secret-detail",
    );
  });
});

describe("OpenAPI", () => {
  it("serves an OpenAPI 3.1 document for the JSON APIs, cacheable for 5 minutes", async () => {
    const res = await op(url("/api/v1/openapi.json"));
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
    const doc = (await res.json()) as { openapi: string; paths: Record<string, unknown> };
    expect(doc.openapi).toBe("3.1.0");
    // Every documented path is in the route table (with {param} as :param), and the
    // Interaction and Admin APIs are documented completely.
    const documented = Object.keys(doc.paths);
    expect(documented.slice(0, 12)).toEqual([
      "/api/v1/health",
      "/api/v1/interactions/{id}",
      "/api/v1/interactions/{id}/passkey/options",
      "/api/v1/interactions/{id}/passkey/verify",
      "/api/v1/interactions/{id}/register/options",
      "/api/v1/interactions/{id}/register/verify",
      "/api/v1/interactions/{id}/upstream/{alias}",
      "/api/v1/interactions/{id}/consent",
      "/api/v1/interactions/{id}/abort",
      "/api/v1/interactions/{id}/logout",
      "/api/v1/me",
      "/api/v1/me/passkeys",
    ]);
    const tablePaths = new Set(ROUTES.map((r) => r.path));
    for (const path of documented) {
      expect(tablePaths.has(path.replace(/\{(\w+)\}/g, ":$1")), path).toBe(true);
    }
    // The 501 placeholders of later phases are documented when they arrive.
    const pending = new Set([
      "/api/v1/interactions/:id/upstream/:alias",
      "/api/v1/interactions/:id/logout",
    ]);
    const apiPaths = [...tablePaths].filter(
      (p) => p.startsWith("/api/v1/") && p !== "/api/v1/openapi.json" && !pending.has(p),
    );
    for (const path of apiPaths) {
      expect(documented).toContain(path.replace(/:(\w+)/g, "{$1}"));
    }
  });
});
