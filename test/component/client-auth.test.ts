import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { Db } from "../../src/db/db.ts";
import {
  ASSERTION_ALGORITHMS,
  ASSERTION_JTI_MAX_LENGTH,
  ASSERTION_WINDOW_SECONDS,
  authenticateClient,
  BASIC_CHALLENGE,
  CLIENT_ASSERTION_TYPE,
  type ClientAuthContext,
  type ClientAuthResult,
  secretMatches,
} from "../../src/oidc/client-auth.ts";
import { ClientCache, ClientsUnavailableError } from "../../src/oidc/client-cache.ts";
import type { Client } from "../../src/oidc/clients.ts";
import {
  JWKS_CACHE_CAPACITY,
  JWKS_CACHE_MAX_AGE_MS,
  JWKS_FETCH_TIMEOUT_MS,
  JWKS_REFETCH_COOLDOWN_MS,
  RemoteJwksCache,
} from "../../src/oidc/jwks-cache.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient } from "../support/factories.ts";
import { mountOrigin } from "../support/fetch-allowlist.ts";
import { TEST_ENV } from "../support/keys.ts";
import { env } from "../support/op.ts";

const ISSUER = TEST_ENV.ISSUER;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);
const cache = new ClientCache(clock);
const jwks = new RemoteJwksCache();

const context = (overrides: Partial<ClientAuthContext> = {}): ClientAuthContext => ({
  lookup: (id) => cache.get(db, id),
  issuer: ISSUER,
  tokenEndpoint: TOKEN_ENDPOINT,
  clock,
  jwks,
  ...overrides,
});

const form = (entries: Record<string, string>) => new Map(Object.entries(entries));
const basic = (id: string, secret: string) =>
  `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;
const auth = (params: Record<string, string>, authorization: string | null = null) =>
  authenticateClient({ params: form(params), authorization }, context());
const confidential = (method: string, extra: Record<string, unknown> = {}) =>
  createTestClient(db, clock, {
    token_endpoint_auth_method: method,
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    ...extra,
  });

function expectRejected(
  result: ClientAuthResult,
  clientId: string | null,
  basicChallenge: boolean,
  reason?: string | RegExp,
) {
  expect(result).toMatchObject({
    ok: false,
    error: "invalid_client",
    client_id: clientId,
    basic_challenge: basicChallenge,
  });
  if (reason !== undefined && !result.ok) expect(result.reason).toMatch(reason);
}

interface Signer {
  alg: string;
  kid: string;
  privateKey: CryptoKey;
  jwk: JWK;
}

async function signer(alg: string, kid = `k-${alg}`): Promise<Signer> {
  const pair = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { alg, kid, privateKey: pair.privateKey, jwk: { ...jwk, kid } };
}

interface AssertionClaims {
  iss?: string | null;
  sub?: string | null;
  aud?: string | string[] | null;
  iat?: number | null;
  exp?: number | null;
  jti?: string | null;
}

/** A client assertion with every TIO-TOKEN-003 claim valid unless overridden (null omits the claim). */
async function assertion(s: Signer, clientId: string, claims: AssertionClaims = {}) {
  const now = clock.now();
  const jwt = new SignJWT({}).setProtectedHeader({ alg: s.alg, kid: s.kid });
  const set = <T>(value: T | null | undefined, fallback: T, apply: (v: T) => void) => {
    if (value === null) return;
    apply(value === undefined ? fallback : value);
  };
  set(claims.iss, clientId, (v) => jwt.setIssuer(v));
  set(claims.sub, clientId, (v) => jwt.setSubject(v));
  set(claims.aud, ISSUER, (v) => jwt.setAudience(v));
  set(claims.iat, now, (v) => jwt.setIssuedAt(v));
  set(claims.exp, now + 60, (v) => jwt.setExpirationTime(v));
  set(claims.jti, "jti-1", (v) => jwt.setJti(v));
  return jwt.sign(s.privateKey);
}

describe("client authentication methods", () => {
  it("[TIO-TOKEN-002] a `none` client sends client_id in the body and nothing else", async () => {
    const { client } = await createTestClient(db, clock);
    const ok = await auth({ client_id: client.client_id });
    expect(ok).toEqual({
      ok: true,
      client: expect.objectContaining({ client_id: client.client_id }),
    });
    expectRejected(await auth({}), null, false, "no client identification");
    expectRejected(
      await auth({ client_id: client.client_id, client_secret: "x" }),
      client.client_id,
      false,
      "none client presented client_secret",
    );
    expectRejected(
      await auth({ client_id: client.client_id }, basic(client.client_id, "x")),
      client.client_id,
      true,
      "Authorization header",
    );
    expectRejected(
      await auth({
        client_id: client.client_id,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: "a.b.c",
      }),
      client.client_id,
      false,
      "malformed client_assertion",
    );
    expectRejected(
      await auth({ client_id: client.client_id, client_assertion_type: CLIENT_ASSERTION_TYPE }),
      client.client_id,
      false,
      "client_assertion",
    );
  });

  it("[TIO-TOKEN-002] a `client_secret_basic` client sends an HTTP Basic header, compared by SHA-256 in constant time, and is refused with the secret in the body", async () => {
    const { client, secret } = await confidential("client_secret_basic");
    const id = client.client_id;
    const ok = await auth({}, basic(id, secret as string));
    expect(ok.ok).toBe(true);
    // The body may repeat the client id, but not the secret.
    expect((await auth({ client_id: id }, basic(id, secret as string))).ok).toBe(true);
    expectRejected(
      await auth({ client_id: id, client_secret: secret as string }),
      id,
      true,
      "client_secret",
    );
    expectRejected(
      await auth({ client_secret: secret as string }, basic(id, secret as string)),
      id,
      true,
      "client_secret_basic client presented client_secret",
    );
    expectRejected(await auth({ client_id: id }), id, true, "missing Authorization header");
    expectRejected(await auth({}, basic(id, "wrong")), id, true, "wrong client secret");
    expectRejected(await auth({}, basic(id, `${secret}x`)), id, true, "wrong client secret");
    expectRejected(
      await auth({ client_id: "other" }, basic(id, secret as string)),
      "other",
      true,
      "differs",
    );
    // Header forms: percent-encoded ids, other schemes and malformed values.
    expectRejected(
      await auth({}, `Bearer ${secret}`),
      null,
      true,
      "malformed Authorization header",
    );
    expectRejected(await auth({}, "Basic !!!"), null, true, "malformed Authorization header");
    expectRejected(await auth({}, "Basic a"), null, true, "malformed Authorization header");
    expectRejected(
      await auth({}, `Basic ${btoa("nocolon")}`),
      null,
      true,
      "malformed Authorization header",
    );
    expectRejected(
      await auth({}, `Basic ${btoa("%E0%A4%A:x")}`),
      null,
      true,
      "malformed Authorization header",
    );
    expect(BASIC_CHALLENGE).toBe('Basic realm="tiny-oidc"');
    expect(await secretMatches({ ...client, client_secret_hash: null }, secret as string)).toBe(
      false,
    );
  });

  it("[TIO-TOKEN-002] a `client_secret_post` client sends client_id and client_secret in the body and is refused with an Authorization header", async () => {
    const { client, secret } = await confidential("client_secret_post");
    const id = client.client_id;
    expect((await auth({ client_id: id, client_secret: secret as string })).ok).toBe(true);
    expectRejected(
      await auth({ client_id: id }, basic(id, secret as string)),
      id,
      true,
      "client_secret_post client presented Authorization header",
    );
    expectRejected(await auth({ client_id: id }), id, false, "missing client_id or client_secret");
    expectRejected(
      await auth({ client_id: id, client_secret: "wrong" }),
      id,
      false,
      "wrong client secret",
    );
    expectRejected(
      await auth({
        client_id: id,
        client_secret: secret as string,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
      }),
      id,
      false,
      "client_assertion",
    );
  });

  it("[TIO-TOKEN-002] a `private_key_jwt` client sends the assertion type and assertion, and nothing else", async () => {
    const s = await signer("ES256");
    const { client } = await confidential("private_key_jwt", { jwks: { keys: [s.jwk] } });
    const id = client.client_id;
    const jwt = await assertion(s, id);
    const ok = await auth({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt });
    expect(ok.ok).toBe(true);
    // client_id in the body is optional and must match the assertion's issuer.
    expect(
      (
        await auth({
          client_id: id,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: jwt,
        })
      ).ok,
    ).toBe(true);
    expectRejected(
      await auth({
        client_id: "other",
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: jwt,
      }),
      "other",
      false,
      "differs between assertion and body",
    );
    expectRejected(
      await auth({ client_assertion: jwt }),
      id,
      false,
      "missing or unsupported client_assertion_type",
    );
    expectRejected(
      await auth({ client_assertion_type: "urn:example:other", client_assertion: jwt }),
      id,
      false,
      "missing or unsupported client_assertion_type",
    );
    expectRejected(
      await auth({ client_id: id, client_assertion_type: CLIENT_ASSERTION_TYPE }),
      id,
      false,
      "missing client_assertion",
    );
    expectRejected(
      await auth(
        { client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt },
        basic(id, "x"),
      ),
      id,
      true,
      "private_key_jwt client presented Authorization header",
    );
    expectRejected(
      await auth({
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: jwt,
        client_secret: "x",
      }),
      id,
      false,
      "private_key_jwt client presented client_secret",
    );
  });

  it("[TIO-TOKEN-002] [TIO-ERR-002] unknown and disabled clients fail like wrong credentials, and an unreachable directory is temporarily_unavailable", async () => {
    expectRejected(await auth({ client_id: "nobody" }), "nobody", false, "unknown client");
    expectRejected(await auth({}, basic("nobody", "x")), "nobody", true, "unknown client");
    const { client, secret } = await confidential("client_secret_basic");
    const disabled = { ...client, disabled_at: clock.now() };
    const result = await authenticateClient(
      { params: form({}), authorization: basic(client.client_id, secret as string) },
      context({ lookup: async () => disabled }),
    );
    expectRejected(result, client.client_id, true, "client disabled");
    expect(
      await authenticateClient(
        { params: form({ client_id: "x" }), authorization: null },
        context({
          lookup: async () => {
            throw new ClientsUnavailableError(new Error("D1 down"));
          },
        }),
      ),
    ).toEqual({ ok: false, error: "temporarily_unavailable", reason: "clients unavailable" });
    await expect(
      authenticateClient(
        { params: form({ client_id: "x" }), authorization: null },
        context({
          lookup: async () => {
            throw new TypeError("bug");
          },
        }),
      ),
    ).rejects.toThrow("bug");
  });

  it("[TIO-TOKEN-004] failure reasons never contain the presented secret or assertion and name the client id for the rate-limit key", async () => {
    const { client, secret } = await confidential("client_secret_post");
    const s = await signer("ES256");
    const jwt = await assertion(s, client.client_id);
    const attempts: [Record<string, string>, string | null][] = [
      [{ client_id: client.client_id, client_secret: "wrong-secret-value" }, null],
      [{ client_id: client.client_id }, basic(client.client_id, secret as string)],
      [{ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt }, null],
      [{ client_id: "nobody", client_secret: "another-secret" }, null],
    ];
    for (const [params, authorization] of attempts) {
      const result = await auth(params, authorization);
      expect(result.ok).toBe(false);
      if (result.ok || result.error !== "invalid_client") throw new Error("unexpected");
      expect(result.client_id).toBe(params["client_id"] ?? client.client_id);
      for (const credential of ["wrong-secret-value", secret as string, jwt, "another-secret"]) {
        expect(result.reason).not.toContain(credential);
      }
      expect(JSON.stringify(result)).not.toContain(secret as string);
    }
  });
});

describe("private_key_jwt assertions", () => {
  it("[TIO-TOKEN-003] accepts ES256, ES384, EdDSA, PS256 and RS256 against the registered jwks, with aud = ISSUER or the token endpoint", async () => {
    for (const alg of ASSERTION_ALGORITHMS) {
      const s = await signer(alg);
      const { client } = await confidential("private_key_jwt", { jwks: { keys: [s.jwk] } });
      for (const aud of [ISSUER, TOKEN_ENDPOINT, [ISSUER, "https://other.example.com"]]) {
        const jwt = await assertion(s, client.client_id, { aud });
        const result = await auth({
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: jwt,
        });
        expect(result.ok, `${alg} ${String(aud)}`).toBe(true);
      }
    }
  });

  it("[TIO-TOKEN-003] rejects alg none, HS256 and unlisted algorithms, a missing alg, and signatures by keys outside the jwks", async () => {
    const s = await signer("ES256");
    const { client } = await confidential("private_key_jwt", { jwks: { keys: [s.jwk] } });
    const id = client.client_id;
    const present = (jwt: string) =>
      auth({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt });
    const b64 = (o: object) =>
      btoa(JSON.stringify(o)).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
    const now = clock.now();
    const payload = { iss: id, sub: id, aud: ISSUER, iat: now, exp: now + 60, jti: "j" };
    expectRejected(
      await present(`${b64({ alg: "none" })}.${b64(payload)}.`),
      id,
      false,
      "unsupported assertion alg",
    );
    expectRejected(
      await present(`${b64({ typ: "JWT" })}.${b64(payload)}.sig`),
      id,
      false,
      "unsupported assertion alg",
    );
    const hs256 = await new SignJWT(payload)
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("secret-secret-secret-secret-secret"));
    expectRejected(await present(hs256), id, false, "unsupported assertion alg");
    const es512 = await signer("ES512");
    expectRejected(
      await present(await assertion(es512, id)),
      id,
      false,
      "unsupported assertion alg",
    );
    const foreign = await signer("ES256", s.kid);
    expectRejected(
      await present(await assertion(foreign, id)),
      id,
      false,
      /signature verification failed/,
    );
    const unknownKid = await signer("ES256", "other-kid");
    expectRejected(await present(await assertion(unknownKid, id)), id, false, /no applicable key/);
    expectRejected(await present("not-a-jwt"), null, false, "malformed client_assertion");
    expectRejected(
      await present(`!!!.${b64(payload)}.sig`),
      id,
      false,
      "malformed client_assertion",
    );
    expectRejected(
      await present(`${b64({ alg: "ES256" })}.${b64({})}.sig`),
      null,
      false,
      "malformed client_assertion",
    );
    expectRejected(
      await present(`${b64({ alg: "ES256" })}.${b64({ iss: 5 })}.sig`),
      null,
      false,
      "malformed client_assertion",
    );
  });

  it("[TIO-TOKEN-003] checks iss, sub, aud, iat (mandatory, within 60 s either way), exp (mandatory, at most 60 s ahead, not past) and jti (mandatory, ≤ 255 chars), each separately", async () => {
    const s = await signer("EdDSA");
    const { client } = await confidential("private_key_jwt", { jwks: { keys: [s.jwk] } });
    const id = client.client_id;
    const now = clock.now();
    const W = ASSERTION_WINDOW_SECONDS;
    const present = async (claims: AssertionClaims) =>
      auth({
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await assertion(s, id, claims),
      });
    const cases: [string, AssertionClaims, RegExp][] = [
      ["sub differs", { sub: "someone-else" }, /"sub"/],
      ["sub absent", { sub: null }, /"sub"/],
      ["aud unknown", { aud: "https://other.example.com" }, /"aud"/],
      ["aud absent", { aud: null }, /"aud"/],
      ["iat absent", { iat: null }, /"iat"/],
      ["iat 61 s in the past", { iat: now - W - 1 }, /iat too old/],
      ["iat 61 s in the future", { iat: now + W + 1 }, /iat in the future/],
      ["exp absent", { exp: null }, /"exp"/],
      ["exp 61 s ahead", { exp: now + W + 1 }, /exp too far ahead/],
      ["exp passed", { exp: now - 1 }, /"exp"/],
      ["exp equals now", { exp: now }, /"exp"/],
      ["jti absent", { jti: null }, /"jti"/],
      ["jti too long", { jti: "j".repeat(ASSERTION_JTI_MAX_LENGTH + 1) }, /jti/],
      ["jti empty", { jti: "" }, /jti/],
    ];
    for (const [name, claims, reason] of cases) {
      const result = await present(claims);
      expect(result.ok, name).toBe(false);
      if (!result.ok && result.error === "invalid_client")
        expect(result.reason, name).toMatch(reason);
    }
    // An iss that is not this client routes to that other client (unknown here).
    expectRejected(
      await present({ iss: "someone-else", sub: "someone-else" }),
      "someone-else",
      false,
      "unknown client",
    );
    // The bounds themselves are accepted.
    for (const claims of [
      { iat: now - W },
      { iat: now + W },
      { exp: now + W },
      { exp: now + 1 },
      { jti: "j".repeat(ASSERTION_JTI_MAX_LENGTH) },
    ]) {
      expect((await present(claims)).ok, JSON.stringify(claims)).toBe(true);
    }
    // A replay inside the window is accepted by design (Appendix B #28).
    const jwt = await assertion(s, id);
    for (let i = 0; i < 2; i++) {
      expect(
        (await auth({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt })).ok,
      ).toBe(true);
    }
    // The assertion of a client registered without keys fails closed.
    const keyless = await authenticateClient(
      {
        params: form({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: jwt }),
        authorization: null,
      },
      context({ lookup: async () => ({ ...client, jwks: null, jwks_uri: null }) as Client }),
    );
    expectRejected(keyless, id, false, "client has no keys");
  });

  it("[TIO-TOKEN-003] resolves jwks_uri with a 5 s timeout, caches the set for an hour, refetches once on an unknown kid (spaced by a cooldown), and fails closed on fetch errors", async () => {
    const a = await signer("ES256", "kid-a");
    const b = await signer("ES256", "kid-b");
    const c = await signer("ES256", "kid-c");
    let keys: JWK[] = [a.jwk];
    let fetches = 0;
    let status = 200;
    mountOrigin("https://rp.example.com", () => {
      fetches += 1;
      return Response.json({ keys }, { status });
    });
    const { client } = await confidential("private_key_jwt", {
      jwks_uri: "https://rp.example.com/jwks.json",
    });
    const id = client.client_id;
    const present = async (s: Signer, remote: RemoteJwksCache) =>
      authenticateClient(
        {
          params: form({
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: await assertion(s, id),
          }),
          authorization: null,
        },
        context({ jwks: remote }),
      );
    const eager = new RemoteJwksCache({ cooldownMs: 0 });
    expect((await present(a, eager)).ok).toBe(true);
    expect(fetches).toBe(1);
    expect((await present(a, eager)).ok).toBe(true);
    expect(fetches).toBe(1);
    // An unknown kid triggers one refetch; the new key is then found.
    keys = [a.jwk, b.jwk];
    expect((await present(b, eager)).ok).toBe(true);
    expect(fetches).toBe(2);
    // A kid that is still unknown after the refetch fails; the set is refetched once, not twice.
    expectRejected(await present(c, eager), id, false, /no applicable key/);
    expect(fetches).toBe(3);
    // With the default cooldown, an unknown kid right after a fetch does not refetch.
    fetches = 0;
    keys = [a.jwk];
    const patient = new RemoteJwksCache();
    expect((await present(a, patient)).ok).toBe(true);
    keys = [a.jwk, b.jwk];
    expectRejected(await present(b, patient), id, false, /no applicable key/);
    expect(fetches).toBe(1);
    expect(patient.get("https://rp.example.com/jwks.json").coolingDown).toBe(true);
    // A fetch error fails closed.
    status = 500;
    const { client: other } = await confidential("private_key_jwt", {
      jwks_uri: "https://rp.example.com/other.json",
    });
    const result = await auth({
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await assertion(a, other.client_id),
    });
    expectRejected(result, other.client_id, false, /assertion rejected/);
    expect(JWKS_FETCH_TIMEOUT_MS).toBe(5_000);
    expect(JWKS_CACHE_MAX_AGE_MS).toBe(3_600_000);
    expect(JWKS_REFETCH_COOLDOWN_MS).toBe(30_000);
  });

  it("keeps at most 100 remote key sets per isolate, most recently used first", () => {
    const bounded = new RemoteJwksCache();
    const first = bounded.get("https://rp.example.com/0.json");
    const second = bounded.get("https://rp.example.com/1.json");
    for (let i = 2; i <= JWKS_CACHE_CAPACITY; i++) {
      // Re-using the first set keeps it warm ahead of the others.
      bounded.get("https://rp.example.com/0.json");
      bounded.get(`https://rp.example.com/${i}.json`);
    }
    expect(bounded.size).toBe(JWKS_CACHE_CAPACITY);
    expect(bounded.get("https://rp.example.com/0.json")).toBe(first);
    expect(bounded.get("https://rp.example.com/1.json")).not.toBe(second);
    expect(bounded.size).toBe(JWKS_CACHE_CAPACITY);
  });
});
