import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import { REQUEST_URI_PREFIX } from "../../src/oidc/authorize-endpoint.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { createApp } from "../../src/router/app.ts";
import { ipKey, limitKey } from "../../src/router/rate-limit.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient } from "../support/factories.ts";
import { env, url } from "../support/op.ts";

const RP = "https://rp.example.com/cb";
const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);
const app = createApp({ clock, sink: () => undefined });

interface Options {
  authorization?: string;
  contentType?: string;
  ip?: string;
}

async function par(body: Record<string, string> | string, options: Options = {}) {
  const headers: Record<string, string> = {
    "content-type": options.contentType ?? "application/x-www-form-urlencoded",
  };
  if (options.authorization !== undefined) headers["authorization"] = options.authorization;
  if (options.ip !== undefined) headers["cf-connecting-ip"] = options.ip;
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(url("/par"), {
      method: "POST",
      headers,
      body: typeof body === "string" ? body : new URLSearchParams(body).toString(),
    }),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

async function authorize(params: Record<string, string>) {
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(url(`/authorize?${new URLSearchParams(params)}`)),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

function valid(client: Client, overrides: Record<string, string | undefined> = {}) {
  const params: Record<string, string> = {
    client_id: client.client_id,
    redirect_uri: RP,
    response_type: "code",
    scope: "openid",
    state: "st-1",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    nonce: "n-1",
  };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete params[k];
    else params[k] = v;
  }
  return params;
}

const basic = (id: string, secret: string) =>
  `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;

describe("POST /par", () => {
  it("[TIO-PAR-001] [TIO-PAR-003] accepts a form from an authenticated client, validates it like /authorize and answers 201 with a single-use request_uri that /authorize takes within 60 s", async () => {
    await writeSettings(
      db,
      { login_url: "https://login.example.com/", login_origins: ["https://login.example.com"] },
      "test",
      clock.now(),
    );
    const pub = (await createTestClient(db, clock, { redirect_uris: [RP] })).client;
    const res = await par(valid(pub));
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    const body = (await res.json()) as { request_uri: string; expires_in: number };
    expect(body.expires_in).toBe(60);
    expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/);
    const id = body.request_uri.slice(REQUEST_URI_PREFIX.length);
    const stored = await interactionStub(env, id).get(clock.now());
    expect(stored.ok && stored.doc).toMatchObject({
      kind: "par",
      status: "pushed",
      client_id: pub.client_id,
      expires_at: clock.now() + 60,
      request: { redirect_uri: RP, scope: ["openid"], state: "st-1", nonce: "n-1" },
    });
    // /authorize takes it once; the second use fails.
    const first = await authorize({ client_id: pub.client_id, request_uri: body.request_uri });
    expect(first.status).toBe(303);
    expect(new URL(first.headers.get("location") as string).searchParams.get("interaction")).toBe(
      id,
    );
    const second = await authorize({ client_id: pub.client_id, request_uri: body.request_uri });
    expect(new URL(second.headers.get("location") as string).searchParams.get("error")).toBe(
      "invalid_request",
    );
    // A confidential client authenticates as at /token.
    const confidential = await createTestClient(db, clock, {
      redirect_uris: [RP],
      token_endpoint_auth_method: "client_secret_basic",
    });
    const pushed = await par(valid(confidential.client, { client_id: undefined }), {
      authorization: basic(confidential.client.client_id, confidential.secret as string),
    });
    expect(pushed.status).toBe(201);
    // Expiry after 60 s.
    const expiring = (await (await par(valid(pub))).json()) as { request_uri: string };
    clock.advance(61);
    const late = await authorize({ client_id: pub.client_id, request_uri: expiring.request_uri });
    expect(
      new URL(late.headers.get("location") as string).searchParams.get("error_description"),
    ).toBe("request_uri is unknown, expired or already used");
  });

  it("[TIO-PAR-002] [TIO-PAR-001] errors are JSON 400 with the /authorize codes, 401 for failed client authentication, and never a redirect", async () => {
    const pub = (await createTestClient(db, clock, { redirect_uris: [RP] })).client;
    const confidential = await createTestClient(db, clock, {
      redirect_uris: [RP],
      token_endpoint_auth_method: "client_secret_basic",
    });
    const cases: [string, Record<string, string>, Options, number, string][] = [
      ["unknown client", valid(pub, { client_id: "nobody" }), {}, 401, "invalid_client"],
      [
        "wrong secret",
        valid(confidential.client, { client_id: undefined }),
        { authorization: basic(confidential.client.client_id, "wrong") },
        401,
        "invalid_client",
      ],
      ["request_uri pushed", valid(pub, { request_uri: "urn:x" }), {}, 400, "invalid_request"],
      [
        "request object (TIO-AUTHZ-025)",
        valid(pub, { request: "e30.e30." }),
        {},
        400,
        "request_not_supported",
      ],
      [
        "bad redirect",
        valid(pub, { redirect_uri: "https://evil.example.net/" }),
        {},
        400,
        "invalid_request",
      ],
      [
        "response_type",
        valid(pub, { response_type: "token" }),
        {},
        400,
        "unsupported_response_type",
      ],
      ["scope", valid(pub, { scope: "email" }), {}, 400, "invalid_scope"],
      ["state", valid(pub, { state: undefined }), {}, 400, "invalid_request"],
      ["prompt", valid(pub, { prompt: "none login" }), {}, 400, "invalid_request"],
    ];
    for (const [name, body, options, status, error] of cases) {
      const res = await par(body, options);
      expect(res.status, name).toBe(status);
      expect(await res.json(), name).toMatchObject({ error });
      expect(res.headers.get("location"), name).toBeNull();
    }
    const challenged = await par(valid(confidential.client, { client_id: undefined }), {
      authorization: basic(confidential.client.client_id, "wrong"),
    });
    expect(challenged.headers.get("www-authenticate")).toBe('Basic realm="tiny-oidc"');
    const credentialsOnly = (
      await createTestClient(db, clock, {
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_post",
        redirect_uris: [],
      })
    ).client;
    const noCode = await par({ client_id: credentialsOnly.client_id, client_secret: "x" });
    expect(noCode.status).toBe(401);
    // Form rules of TIO-TOKEN-001.
    expect((await par(valid(pub), { contentType: "application/json" })).status).toBe(400);
    expect((await par(`client_id=${pub.client_id}&client_id=${pub.client_id}`)).status).toBe(400);
    const duplicate = await par(`${new URLSearchParams(valid(pub))}&state=again`);
    expect(await duplicate.json()).toMatchObject({
      error: "invalid_request",
      error_description: "duplicate parameter",
    });
  });

  it("[TIO-ARCH-015] answers 503 temporarily_unavailable when the client directory is unreachable", async () => {
    const brokenD1 = {
      prepare() {
        throw new Error("D1 down");
      },
      batch() {
        throw new Error("D1 down");
      },
    } as unknown as D1Database;
    const ctx = createExecutionContext();
    const res = await app.fetch(
      new Request(url("/par"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "client_id=never-cached",
      }),
      { ...env, DB: brokenD1 } as typeof env,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "temporarily_unavailable" });
  });

  it("[TIO-PAR-002] a client without the authorization code grant is unauthorized_client", async () => {
    const credentialsOnly = await createTestClient(db, clock, {
      grant_types: ["client_credentials"],
      token_endpoint_auth_method: "client_secret_post",
      redirect_uris: [],
    });
    const res = await par({
      ...valid(credentialsOnly.client),
      client_secret: credentialsOnly.secret as string,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "unauthorized_client" });
  });

  it("[TIO-RL-003] [TIO-PAR-004] [TIO-TOKEN-004] failed client authentication is rate-limited per client id and every call per IP, answering 429 with Retry-After", async () => {
    const pub = (await createTestClient(db, clock, { redirect_uris: [RP] })).client;
    const confidential = await createTestClient(db, clock, {
      redirect_uris: [RP],
      token_endpoint_auth_method: "client_secret_post",
    });
    const id = confidential.client.client_id;
    // Exhaust the client's failed-authentication budget directly on the binding.
    const failKey = limitKey("client_auth_failed", id);
    while ((await env.RL_CLIENT.limit({ key: failKey })).success) {
      // keep counting
    }
    const blocked = await par({ ...valid(confidential.client), client_secret: "wrong" });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBe("10");
    expect(await blocked.json()).toMatchObject({ error: "rate_limited" });
    // A correct secret is not counted as a failure and still works.
    const fine = await par({
      ...valid(confidential.client),
      client_secret: confidential.secret as string,
    });
    expect(fine.status).toBe(201);
    // Per IP (IPv6 keyed by its /64).
    const ip = "2001:db8:1:2:aaaa:bbbb:cccc:dddd";
    expect(ipKey(new Request("https://x", { headers: { "cf-connecting-ip": ip } }))).toBe(
      "2001:0db8:0001:0002::/64",
    );
    while (
      (await env.RL_IP.limit({ key: limitKey("ip_navigation", "2001:0db8:0001:0002::/64") }))
        .success
    ) {
      // keep counting
    }
    const sibling = await par(valid(pub), { ip: "2001:db8:1:2::1" });
    expect(sibling.status).toBe(429);
    const other = await par(valid(pub), { ip: "2001:db8:1:3::1" });
    expect(other.status).toBe(201);
    for (const [raw, key] of [
      ["203.0.113.9", "203.0.113.9"],
      ["::1", "0000:0000:0000:0000::/64"],
      ["fe80::1:2:3", "fe80:0000:0000:0000::/64"],
      ["2001:db8::", "2001:0db8:0000:0000::/64"],
    ]) {
      expect(
        ipKey(new Request("https://x", { headers: { "cf-connecting-ip": raw as string } })),
        raw,
      ).toBe(key);
    }
    expect(ipKey(new Request("https://x"))).toBe("0.0.0.0");
  });
});
