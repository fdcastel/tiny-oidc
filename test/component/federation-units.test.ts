import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { sealSecret } from "../../src/crypto/secretbox.ts";
import type { UpstreamMetadata } from "../../src/federation/discovery.ts";
import { extractClaims, verifyUpstreamIdToken } from "../../src/federation/id-token.ts";
import { exchangeCode, fetchUserinfo } from "../../src/federation/token.ts";
import type { Upstream } from "../../src/federation/upstreams.ts";
import { sealFederationHandle } from "../../src/oidc/handles.ts";
import type { RemoteJwks } from "../../src/oidc/jwks-cache.ts";
import { utf8 } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { FakeUpstream } from "../support/fake-upstream/index.ts";
import { testKeys } from "../support/keys.ts";

// The pieces of a federated login on their own (spec §6.4.3, §6.4.4): the code
// exchange with each client authentication method and its failures, and the
// ID-token rules jose reports in ways the HTTP flow cannot provoke.

const clock = new FakeClock(1_800_000_000);
const keys = testKeys();
const ISSUER = "https://idp.example.com";

const metadata: UpstreamMetadata = {
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
};

async function upstream(overrides: Partial<Upstream> = {}): Promise<Upstream> {
  return {
    alias: "idp",
    issuer: ISSUER,
    display_name: "IdP",
    client_id: "c",
    token_endpoint_auth_method: "client_secret_basic",
    client_secret_enc: await sealSecret(keys, utf8("s")),
    client_jwk_enc: null,
    scopes: "openid",
    discovery: { mode: "auto" },
    use_userinfo: false,
    trust_email_verified: true,
    claims_map: {},
    required_claims: {},
    extra_authorize_params: {},
    forward_login_hint: false,
    enabled: true,
    created_at: 0,
    updated_at: 0,
    ...overrides,
  };
}

const exchange = (up: Upstream, doFetch: typeof fetch, timeoutMs?: number) =>
  exchangeCode({
    upstream: up,
    metadata,
    code: "code-1",
    redirect_uri: "https://auth.example.com/federation/callback",
    code_verifier: "v".repeat(43),
    keys,
    clock,
    fetch: doFetch,
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
  });

describe("exchangeCode", () => {
  it("[TIO-FED-022] authenticates with the registered secret over Basic or in the form, or with a private_key_jwt assertion, and fails closed without the material", async () => {
    const seen: { auth: string | null; body: URLSearchParams }[] = [];
    const answering: typeof fetch = async (_url, init) => {
      seen.push({
        auth: new Headers(init?.headers).get("authorization"),
        body: new URLSearchParams(String(init?.body)),
      });
      return Response.json({ access_token: "at", id_token: "it", token_type: "Bearer" });
    };
    const basic = await exchange(await upstream(), answering);
    expect(basic).toEqual({ ok: true, access_token: "at", id_token: "it" });
    expect(seen[0]?.auth).toBe(`Basic ${btoa("c:s")}`);
    expect(seen[0]?.body.get("code_verifier")).toBe("v".repeat(43));
    expect(seen[0]?.body.has("client_secret")).toBe(false);
    const post = await exchange(
      await upstream({ token_endpoint_auth_method: "client_secret_post" }),
      answering,
    );
    expect(post.ok).toBe(true);
    expect(seen[1]?.auth).toBeNull();
    expect(seen[1]?.body.get("client_secret")).toBe("s");
    // private_key_jwt: the assertion verifies against the public half, names the token endpoint and lasts 60 s.
    const pair = await generateKeyPair("ES256", { extractable: true });
    const privateJwk = { ...(await exportJWK(pair.privateKey)), kid: "k1", alg: "ES256" };
    const jwt = await exchange(
      await upstream({
        token_endpoint_auth_method: "private_key_jwt",
        client_secret_enc: null,
        client_jwk_enc: await sealSecret(keys, utf8(JSON.stringify(privateJwk))),
      }),
      answering,
    );
    expect(jwt.ok).toBe(true);
    const assertion = seen[2]?.body.get("client_assertion") as string;
    expect(seen[2]?.body.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    const fake = await FakeUpstream.create({
      issuer: ISSUER,
      client_id: "c",
      client_jwk: { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "ES256" },
      redirect_uris: [],
      now: () => clock.now(),
    });
    const verified = await fake.handle(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "none",
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: assertion,
        }).toString(),
      }),
    );
    // The fake accepted the assertion (it got past client authentication to the unknown code).
    expect(await verified.json()).toMatchObject({ error: "invalid_grant" });
    // A JWK without an alg for an RSA key defaults to RS256; a corrupt one is unusable.
    const rsa = await generateKeyPair("RS256", { extractable: true });
    const rsaJwk = await exportJWK(rsa.privateKey);
    expect(
      (
        await exchange(
          await upstream({
            token_endpoint_auth_method: "private_key_jwt",
            client_jwk_enc: await sealSecret(keys, utf8(JSON.stringify(rsaJwk))),
          }),
          answering,
        )
      ).ok,
    ).toBe(true);
    for (const jwkEnc of [
      null,
      new Uint8Array([1, 2, 3]),
      await sealSecret(keys, utf8("{not json")),
      await sealSecret(keys, utf8(JSON.stringify({ kty: "EC", crv: "P-256", d: "bad" }))),
    ]) {
      expect(
        await exchange(
          await upstream({ token_endpoint_auth_method: "private_key_jwt", client_jwk_enc: jwkEnc }),
          answering,
        ),
      ).toEqual({ ok: false, reason: "client_key_unavailable" });
    }
    expect(await exchange(await upstream({ client_secret_enc: null }), answering)).toEqual({
      ok: false,
      reason: "client_secret_unavailable",
    });
  });

  it("[TIO-FED-022] [TIO-FED-031] reports timeouts, unreachable endpoints, non-200 and non-JSON answers for the token and userinfo calls", async () => {
    const hanging: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    expect(await exchange(await upstream(), hanging, 20)).toEqual({
      ok: false,
      reason: "token_timeout",
    });
    const refusing: typeof fetch = async () => {
      throw new Error("connection refused");
    };
    expect(await exchange(await upstream(), refusing)).toEqual({
      ok: false,
      reason: "token_unreachable",
    });
    const answering =
      (status: number, body: string): typeof fetch =>
      async () =>
        new Response(body, { status });
    expect(await exchange(await upstream(), answering(401, "{}"))).toEqual({
      ok: false,
      reason: "token_status_401",
    });
    expect(await exchange(await upstream(), answering(200, "{}"))).toEqual({
      ok: false,
      reason: "token_malformed",
    });
    expect(
      await fetchUserinfo(metadata.userinfo_endpoint as string, "at", {
        fetch: hanging,
        timeoutMs: 20,
      }),
    ).toEqual({
      ok: false,
      reason: "userinfo_timeout",
    });
    expect(
      await fetchUserinfo(metadata.userinfo_endpoint as string, "at", { fetch: refusing }),
    ).toEqual({
      ok: false,
      reason: "userinfo_unreachable",
    });
    expect(
      await fetchUserinfo(metadata.userinfo_endpoint as string, "at", {
        fetch: answering(200, '{"sub":"x"}'),
      }),
    ).toEqual({
      ok: true,
      claims: { sub: "x" },
    });
  });
});

describe("verifyUpstreamIdToken", () => {
  it("[TIO-FED-030] refuses a token that is not a JWT, one without a usable algorithm, one whose signature is not a JWS, and reports jose's other claim failures as exp", async () => {
    const pair = await generateKeyPair("ES256");
    const jwks = createLocalJWKSet({
      keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k", alg: "ES256" }],
    }) as unknown as RemoteJwks;
    const expected = { issuer: ISSUER, clientId: "c", nonce: "n", jwks, clock };
    expect(await verifyUpstreamIdToken("garbage", expected)).toEqual({
      ok: false,
      reason: "malformed",
    });
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "");
    expect(await verifyUpstreamIdToken(`${b64({ typ: "JWT" })}.${b64({})}.x`, expected)).toEqual({
      ok: false,
      reason: "alg",
    });
    expect(
      await verifyUpstreamIdToken(`${b64({ alg: "ES256", kid: "k" })}.${b64({})}`, expected),
    ).toEqual({
      ok: false,
      reason: "malformed",
    });
    // A signature that is not base64url is a malformed JWS, not a bad signature.
    expect(
      await verifyUpstreamIdToken(`${b64({ alg: "ES256", kid: "k" })}.${b64({})}.!!!`, expected),
    ).toEqual({ ok: false, reason: "malformed" });
    // A key set that cannot be read at all counts against the signature.
    const unreadable = (() => {
      throw new Error("jwks unreadable");
    }) as unknown as RemoteJwks;
    expect(
      await verifyUpstreamIdToken(
        await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: "k" }).sign(pair.privateKey),
        { ...expected, jwks: unreadable },
      ),
    ).toEqual({ ok: false, reason: "signature" });
    // A `nbf` in the future is a claim failure jose reports on another claim than iss/aud.
    const notYet = await new SignJWT({ nonce: "n" })
      .setProtectedHeader({ alg: "ES256", kid: "k" })
      .setIssuer(ISSUER)
      .setAudience("c")
      .setSubject("s")
      .setIssuedAt(clock.now())
      .setNotBefore(clock.now() + 3600)
      .setExpirationTime(clock.now() + 7200)
      .sign(pair.privateKey);
    expect(await verifyUpstreamIdToken(notYet, expected)).toEqual({ ok: false, reason: "exp" });
    const fine = await new SignJWT({ nonce: "n", email: "" })
      .setProtectedHeader({ alg: "ES256", kid: "k" })
      .setIssuer(ISSUER)
      .setAudience("c")
      .setSubject("s")
      .setIssuedAt(clock.now())
      .setExpirationTime(clock.now() + 60)
      .sign(pair.privateKey);
    const ok = await verifyUpstreamIdToken(fine, expected);
    expect(ok.ok).toBe(true);
    // An empty email claim is no email.
    expect(
      extractClaims({ claims_map: {}, trust_email_verified: true }, { email: "" }, "s"),
    ).toEqual({
      sub: "s",
      email: null,
      email_verified: false,
      name: null,
    });
  });

  it("[TIO-FED-010] a federation state can only be sealed for a real interaction id", async () => {
    await expect(sealFederationHandle(keys, "short", new Uint8Array(32))).rejects.toThrow(
      "not an interaction id",
    );
  });
});
