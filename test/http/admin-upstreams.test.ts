import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import { openSecret } from "../../src/crypto/secretbox.ts";
import { Db } from "../../src/db/db.ts";
import { getUpstream } from "../../src/db/upstreams.ts";
import type { Env } from "../../src/env.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { mountOrigin } from "../support/fetch-allowlist.ts";
import { harness } from "../support/http.ts";
import { testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { brokenD1, failingD1 } from "./faults.ts";

// The admin upstreams endpoints (spec §9.4 Upstreams, §6.4.1): discovery
// fetched and checked on create and update (TIO-FED-001), the callback URL
// reported (TIO-FED-002), secrets sealed and never returned (TIO-ADMIN-003).

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);
const keys = testKeys();
const ISSUER = "https://auth.example.com";
const IDP = "https://idp.example.com";

let token: string;
let rootId: string;

/** What the fake provider serves; tests change it between calls. */
const provider = {
  issuer: IDP,
  status: 200,
  body: null as string | null,
  jwksStatus: 200,
  jwks: JSON.stringify({
    keys: [
      { kty: "EC", kid: "k1" },
      { kty: "RSA", kid: "k2" },
    ],
  }),
};

mountOrigin(IDP, (request) => {
  const path = new URL(request.url).pathname;
  if (path === "/.well-known/openid-configuration") {
    const body =
      provider.body ??
      JSON.stringify({
        issuer: provider.issuer,
        authorization_endpoint: `${IDP}/authorize`,
        token_endpoint: `${IDP}/token`,
        jwks_uri: `${IDP}/jwks`,
        userinfo_endpoint: `${IDP}/userinfo`,
      });
    return new Response(body, {
      status: provider.status,
      headers: { "content-type": "application/json" },
    });
  }
  if (path === "/jwks") {
    return new Response(provider.jwks, {
      status: provider.jwksStatus,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response("not found", { status: 404 });
});

interface UpstreamBody {
  alias: string;
  issuer: string;
  display_name: string;
  client_id: string;
  token_endpoint_auth_method: string;
  has_client_secret: boolean;
  has_client_jwk: boolean;
  redirect_uri: string;
  enabled: boolean;
  discovery: { mode: string };
  created_at: number;
  updated_at: number;
  [key: string]: unknown;
}

interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

const call = (method: string, path: string, body?: unknown, options: { env?: Env } = {}) =>
  admin(h, token, path, {
    method,
    ...(body === undefined ? {} : { body }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });

const lastEvent = (type: string): AuditEvent =>
  h.lines
    .filter((l) => l["msg"] === "audit")
    .map((l) => l["event"] as AuditEvent)
    .filter((e) => e.type === type)
    .at(-1) as AuditEvent;

const input = (alias: string, overrides: Record<string, unknown> = {}) => ({
  alias,
  issuer: IDP,
  display_name: "Example IdP",
  client_id: "our-client-id",
  token_endpoint_auth_method: "client_secret_basic",
  client_secret: "s3cret-value",
  ...overrides,
});

describe("upstreams", () => {
  it("[TIO-FED-001] [TIO-FED-002] [TIO-ADMIN-003] creates an upstream after fetching and checking its discovery document, seals the secret, reports the callback URL and never returns secret material", async () => {
    await adminSettings(h);
    const root = await adminUser(h);
    token = root.access_token;
    rootId = root.user.profile.id;
    const created = await call("POST", "upstreams", input("idp"));
    expect(created.status).toBe(201);
    const idp = (await created.json()) as UpstreamBody;
    expect(idp).toMatchObject({
      alias: "idp",
      issuer: IDP,
      display_name: "Example IdP",
      token_endpoint_auth_method: "client_secret_basic",
      has_client_secret: true,
      has_client_jwk: false,
      redirect_uri: `${ISSUER}/federation/callback`,
      scopes: "openid email profile",
      discovery: { mode: "auto" },
      enabled: true,
      created_at: clock.now(),
    });
    expect(JSON.stringify(idp)).not.toMatch(/s3cret|client_secret_enc|client_jwk_enc/);
    const stored = await getUpstream(db, "idp");
    const opened = await openSecret(keys, stored?.client_secret_enc as Uint8Array);
    expect(new TextDecoder().decode(opened as Uint8Array)).toBe("s3cret-value");
    expect(lastEvent("upstream.created")).toMatchObject({
      actor: { kind: "admin", id: rootId },
      upstream: "idp",
      data: { target: "idp", diff: { issuer: { from: null, to: IDP } } },
    });
    expect(JSON.stringify(lastEvent("upstream.created"))).not.toContain("s3cret");
    expect(await (await call("GET", "upstreams/idp")).json()).toEqual(idp);

    // Duplicates by alias and by issuer; validation of the record.
    expect(await (await call("POST", "upstreams", input("idp"))).json()).toMatchObject({
      error: "upstream_exists",
    });
    expect((await call("POST", "upstreams", input("idp-2"))).status).toBe(409);
    const bad = async (body: unknown, fragment: string) => {
      const res = await call("POST", "upstreams", body);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({
        error: "invalid_upstream",
        error_description: expect.stringContaining(fragment),
      });
    };
    await bad(input("Bad Alias"), "alias");
    await bad(input("x", { client_secret: undefined }), "client_secret: required");
    await bad(
      input("x", { token_endpoint_auth_method: "private_key_jwt" }),
      "client_jwk: required",
    );
    await bad(input("x", { client_jwk: { kty: "EC", kid: "k", d: "d" } }), "client_jwk: only for");
    await bad(
      input("x", {
        token_endpoint_auth_method: "private_key_jwt",
        client_jwk: { kty: "EC", kid: "k", d: "d" },
        client_secret: "s",
      }),
      "client_secret: only for",
    );
    await bad(input("x", { scopes: "email profile" }), "scopes: must contain openid");
    await bad(input("x", { scopes: "openid openid" }), "scopes: duplicate");
    await bad(input("x", { issuer: `${IDP}/?x=1` }), "issuer:");
    await bad(
      input("x", {
        use_userinfo: true,
        discovery: {
          mode: "manual",
          authorization_endpoint: `${IDP}/a`,
          token_endpoint: `${IDP}/t`,
          jwks_uri: `${IDP}/j`,
        },
      }),
      "userinfo_endpoint",
    );
    await bad(input("x", { colour: "blue" }), "colour");
    expect((await call("POST", "upstreams", "[1]")).status).toBe(400);
    expect(
      (await call("POST", "upstreams", input("d1"), { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
  });

  it("[TIO-FED-001] discovery failures refuse the upstream and are audited: unreachable, non-200, not JSON, an incomplete document, non-https endpoints and an issuer that differs", async () => {
    const cases: [Partial<typeof provider> & { issuer?: string }, string][] = [
      [{ status: 500 }, "http_error"],
      [{ body: "not json" }, "not_json"],
      [{ body: JSON.stringify({ issuer: IDP }) }, "invalid_document"],
      [
        {
          body: JSON.stringify({
            issuer: IDP,
            authorization_endpoint: "http://idp.example.com/a",
            token_endpoint: `${IDP}/t`,
            jwks_uri: `${IDP}/j`,
          }),
        },
        "invalid_document",
      ],
      [{ issuer: `${IDP}/` }, "issuer_mismatch"],
    ];
    for (const [change, reason] of cases) {
      Object.assign(provider, { issuer: IDP, status: 200, body: null }, change);
      const res = await call("POST", "upstreams", input("failing"));
      expect(res.status, reason).toBe(400);
      expect(await res.json()).toMatchObject({
        error: "upstream_discovery_failed",
        error_description: expect.stringContaining(reason),
      });
      expect(lastEvent("upstream.discovery_failed")).toMatchObject({
        outcome: "failure",
        upstream: "failing",
        reason,
      });
    }
    Object.assign(provider, { issuer: IDP, status: 200, body: null });
    const unreachable = await call(
      "POST",
      "upstreams",
      input("gone", { issuer: "https://nowhere.example.net" }),
    );
    expect(await unreachable.json()).toMatchObject({
      error: "upstream_discovery_failed",
      error_description: expect.stringContaining("fetch_failed"),
    });
    // Every stored flag round-trips (a disabled upstream that reads userinfo).
    const flagged = await call(
      "POST",
      "upstreams",
      input("flagged", { issuer: IDP, use_userinfo: true, enabled: false, alias: "flagged" }),
    );
    expect(flagged.status).toBe(409);
    provider.issuer = "https://flagged.example.net";
    expect(
      (
        await call(
          "POST",
          "upstreams",
          input("flagged", {
            issuer: "https://flagged.example.net",
            use_userinfo: true,
            enabled: false,
            discovery: {
              mode: "manual",
              authorization_endpoint: "https://flagged.example.net/a",
              token_endpoint: "https://flagged.example.net/t",
              jwks_uri: "https://flagged.example.net/j",
              userinfo_endpoint: "https://flagged.example.net/u",
            },
          }),
        )
      ).status,
    ).toBe(201);
    provider.issuer = IDP;
    expect(await getUpstream(db, "flagged")).toMatchObject({ use_userinfo: true, enabled: false });
    // Manual discovery never fetches.
    const manual = await call(
      "POST",
      "upstreams",
      input("manual", {
        issuer: "https://manual.example.net",
        discovery: {
          mode: "manual",
          authorization_endpoint: "https://manual.example.net/a",
          token_endpoint: "https://manual.example.net/t",
          jwks_uri: "https://manual.example.net/j",
        },
      }),
    );
    expect(manual.status).toBe(201);
  });

  it("[TIO-ADMIN-004] lists upstreams by (created_at, alias) with cursors, skipping a row that no longer decodes", async () => {
    for (let i = 0; i < 2; i++) {
      clock.advance(1);
      expect(
        (
          await call(
            "POST",
            "upstreams",
            input(`listed-${i}`, {
              issuer: `https://listed-${i}.example.net`,
              discovery: {
                mode: "manual",
                authorization_endpoint: "https://x.example.net/a",
                token_endpoint: "https://x.example.net/t",
                jwks_uri: "https://x.example.net/j",
              },
            }),
          )
        ).status,
      ).toBe(201);
    }
    await db
      .prepare("UPDATE upstreams SET discovery = 'oops' WHERE alias = ?")
      .bind("listed-0")
      .run();
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: Page<UpstreamBody> = (await (
        await call("GET", `upstreams?limit=2${cursor === null ? "" : `&cursor=${cursor}`}`)
      ).json()) as Page<UpstreamBody>;
      expect(page.items.every((u) => !("client_secret_enc" in u))).toBe(true);
      seen.push(...page.items.map((u) => u.alias));
      cursor = page.next_cursor;
    } while (cursor !== null);
    expect(seen).toEqual(["flagged", "idp", "manual", "listed-1"]);
    expect((await call("GET", "upstreams?limit=0")).status).toBe(400);
    expect((await call("GET", "upstreams?cursor=bad")).status).toBe(400);
    expect((await call("GET", "upstreams?offset=1")).status).toBe(400);
    expect((await call("GET", "upstreams?limit=1&limit=2")).status).toBe(400);
    expect(
      (await call("GET", "upstreams", undefined, { env: { ...env, DB: brokenD1 } as Env })).status,
    ).toBe(503);
    expect((await call("GET", "upstreams/listed-0")).status).toBe(404);
    expect((await call("GET", "upstreams/Bad")).status).toBe(404);
    expect(
      (await call("GET", "upstreams/idp", undefined, { env: { ...env, DB: brokenD1 } as Env }))
        .status,
    ).toBe(503);
  });

  it("[TIO-FED-001] patches merge over the record, keep or replace the sealed material, refetch auto discovery, and refuse an alias change or a taken issuer", async () => {
    const renamed = await call("PATCH", "upstreams/idp", {
      display_name: "Example (renamed)",
      trust_email_verified: true,
    });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toMatchObject({
      display_name: "Example (renamed)",
      trust_email_verified: true,
      has_client_secret: true,
      updated_at: clock.now(),
    });
    expect(lastEvent("upstream.updated")).toMatchObject({
      upstream: "idp",
      data: {
        diff: { display_name: { from: "Example IdP", to: "Example (renamed)" } },
        secret_replaced: false,
        jwk_replaced: false,
      },
    });
    const before = (await getUpstream(db, "idp"))?.client_secret_enc;
    const reSecret = await call("PATCH", "upstreams/idp", { client_secret: "new-secret" });
    expect(reSecret.status).toBe(200);
    expect(lastEvent("upstream.updated")).toMatchObject({ data: { secret_replaced: true } });
    const after = (await getUpstream(db, "idp"))?.client_secret_enc as Uint8Array;
    expect(after).not.toEqual(before);
    expect(new TextDecoder().decode((await openSecret(keys, after)) as Uint8Array)).toBe(
      "new-secret",
    );
    // A switch to private_key_jwt needs a key and drops the secret; back again needs a secret.
    expect(
      await (
        await call("PATCH", "upstreams/idp", { token_endpoint_auth_method: "private_key_jwt" })
      ).json(),
    ).toMatchObject({
      error: "invalid_upstream",
      error_description: expect.stringContaining("client_jwk: required"),
    });
    const keyed = (await (
      await call("PATCH", "upstreams/idp", {
        token_endpoint_auth_method: "private_key_jwt",
        client_jwk: { kty: "EC", kid: "k1", crv: "P-256", x: "x", y: "y", d: "d" },
      })
    ).json()) as UpstreamBody;
    expect(keyed).toMatchObject({ has_client_secret: false, has_client_jwk: true });
    expect(JSON.stringify(keyed)).not.toContain('"d"');
    expect(
      await (
        await call("PATCH", "upstreams/idp", { token_endpoint_auth_method: "client_secret_post" })
      ).json(),
    ).toMatchObject({
      error_description: expect.stringContaining("client_secret: required"),
    });
    expect(
      await (
        await call("PATCH", "upstreams/idp", {
          token_endpoint_auth_method: "client_secret_post",
          client_secret: "again",
        })
      ).json(),
    ).toMatchObject({
      has_client_secret: true,
      has_client_jwk: false,
    });
    // Auto discovery is fetched again on update; a failure refuses the change.
    provider.status = 503;
    const failing = await call("PATCH", "upstreams/idp", { display_name: "Down" });
    expect(await failing.json()).toMatchObject({ error: "upstream_discovery_failed" });
    provider.status = 200;
    expect(((await (await call("GET", "upstreams/idp")).json()) as UpstreamBody).display_name).toBe(
      "Example (renamed)",
    );
    expect((await call("PATCH", "upstreams/idp", { alias: "other" })).status).toBe(400);
    expect(
      (
        await call("PATCH", "upstreams/idp", {
          issuer: "https://manual.example.net",
          discovery: {
            mode: "manual",
            authorization_endpoint: "https://manual.example.net/a",
            token_endpoint: "https://manual.example.net/t",
            jwks_uri: "https://manual.example.net/j",
          },
        })
      ).status,
    ).toBe(409);
    expect((await call("PATCH", "upstreams/idp", "{oops")).status).toBe(400);
    expect((await call("PATCH", "upstreams/nope", { display_name: "x" })).status).toBe(404);
    expect(
      (
        await call(
          "PATCH",
          "upstreams/idp",
          { display_name: "x" },
          { env: { ...env, DB: failingD1(/^UPDATE upstreams/) } as Env },
        )
      ).status,
    ).toBe(503);
    const vanishing = {
      prepare(sql: string) {
        if (sql.startsWith("UPDATE upstreams")) {
          return { bind: () => ({ run: async () => ({ meta: { changes: 0 } }) }) };
        }
        return env.DB.prepare(sql);
      },
      batch: (s: D1PreparedStatement[]) => env.DB.batch(s),
    } as unknown as D1Database;
    expect(
      (
        await call(
          "PATCH",
          "upstreams/idp",
          { display_name: "x" },
          { env: { ...env, DB: vanishing } as Env },
        )
      ).status,
    ).toBe(404);
  });

  it("[TIO-FED-001] the test endpoint refetches discovery and the JWKS and reports each step; deletion removes the record", async () => {
    const healthy = await call("POST", "upstreams/idp/test");
    expect(healthy.status).toBe(200);
    expect(await healthy.json()).toEqual({
      discovery: {
        ok: true,
        reason: null,
        metadata: {
          authorization_endpoint: `${IDP}/authorize`,
          token_endpoint: `${IDP}/token`,
          jwks_uri: `${IDP}/jwks`,
          userinfo_endpoint: `${IDP}/userinfo`,
        },
      },
      jwks: { ok: true, reason: null, keys: 2 },
    });
    provider.jwks = "{not json";
    expect(await (await call("POST", "upstreams/idp/test")).json()).toMatchObject({
      discovery: { ok: true },
      jwks: { ok: false, reason: "not_json", keys: null },
    });
    expect(lastEvent("upstream.discovery_failed")).toMatchObject({
      upstream: "idp",
      reason: "not_json",
      data: { step: "jwks" },
    });
    provider.jwks = JSON.stringify({ nokeys: true });
    expect(await (await call("POST", "upstreams/idp/test")).json()).toMatchObject({
      jwks: { ok: false, reason: "invalid_document" },
    });
    provider.jwksStatus = 500;
    expect(await (await call("POST", "upstreams/idp/test")).json()).toMatchObject({
      jwks: { ok: false, reason: "http_error" },
    });
    provider.jwksStatus = 200;
    provider.jwks = JSON.stringify({ keys: [] });
    provider.status = 404;
    expect(await (await call("POST", "upstreams/idp/test")).json()).toEqual({
      discovery: { ok: false, reason: "http_error", metadata: null },
      jwks: { ok: false, reason: "skipped", keys: null },
    });
    expect(lastEvent("upstream.discovery_failed")).toMatchObject({
      reason: "http_error",
      data: { step: "discovery" },
    });
    provider.status = 200;
    // A manual upstream tests its configured endpoints (the JWKS host is unreachable here).
    expect(await (await call("POST", "upstreams/manual/test")).json()).toMatchObject({
      discovery: { ok: true, metadata: { userinfo_endpoint: null } },
      jwks: { ok: false, reason: "fetch_failed" },
    });
    expect((await call("POST", "upstreams/nope/test")).status).toBe(404);

    const deleted = await call("DELETE", "upstreams/manual");
    expect(deleted.status).toBe(204);
    expect(lastEvent("upstream.deleted")).toMatchObject({
      upstream: "manual",
      data: { diff: { alias: { from: "manual", to: null } } },
    });
    expect((await call("GET", "upstreams/manual")).status).toBe(404);
    expect((await call("DELETE", "upstreams/manual")).status).toBe(404);
    expect(
      (
        await call("DELETE", "upstreams/idp", undefined, {
          env: { ...env, DB: failingD1(/^DELETE FROM upstreams/) } as Env,
        })
      ).status,
    ).toBe(503);
    const gone = {
      prepare(sql: string) {
        if (sql.startsWith("DELETE FROM upstreams")) {
          return { bind: () => ({ run: async () => ({ meta: { changes: 0 } }) }) };
        }
        return env.DB.prepare(sql);
      },
      batch: (s: D1PreparedStatement[]) => env.DB.batch(s),
    } as unknown as D1Database;
    expect(
      (await call("DELETE", "upstreams/idp", undefined, { env: { ...env, DB: gone } as Env }))
        .status,
    ).toBe(404);
  });
});
