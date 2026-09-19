import { describe, expect, it } from "vitest";
import {
  CLIENT_ID_PATTERN,
  ClientInputSchema,
  clientFromInput,
  generateClientId,
  generateClientSecret,
  TTL_BOUNDS,
  usesSecret,
  type ValidationContext,
  validateClientInput,
} from "../../src/oidc/clients.ts";
import {
  isLoopbackRedirectUri,
  isRegistrableRedirectUri,
  matchRedirectUri,
} from "../../src/oidc/redirect-uri.ts";

const context: ValidationContext = {
  issuer: "https://auth.example.com",
  actorHasAdmin: false,
  existingGroups: new Set(["staff"]),
};

const base = {
  client_name: "Web",
  redirect_uris: ["https://app.example.com/cb"],
  grant_types: ["authorization_code"],
  token_endpoint_auth_method: "none",
  scopes_allowed: ["openid"],
};

const violations = (overrides: Record<string, unknown>, ctx: Partial<ValidationContext> = {}) => {
  const parsed = ClientInputSchema.safeParse({ ...base, ...overrides });
  if (!parsed.success) return parsed.error.issues.map((i) => `schema:${i.path.join(".")}`);
  return validateClientInput(parsed.data, { ...context, ...ctx });
};

describe("redirect URI rules", () => {
  it("[TIO-CLIENT-010] accepts https hosts, loopback http on any port and dotted private-use schemes; rejects everything else", () => {
    for (const ok of [
      "https://app.example.com/cb",
      "https://app.example.com",
      "https://app.example.com:8443/cb?x=1",
      "http://127.0.0.1/cb",
      "http://127.0.0.1:0/cb",
      "http://127.0.0.1:49152/cb",
      "http://[::1]:8080/cb",
      "com.example.app:/oauth2/callback",
      "com.example.app://callback",
    ]) {
      expect(isRegistrableRedirectUri(ok), ok).toBe(true);
    }
    for (const bad of [
      "http://localhost/cb",
      "http://localhost:3000/cb",
      "http://app.example.com/cb",
      "https://203.0.113.4/cb",
      "https://[2001:db8::1]/cb",
      "https://app.example.com/cb#frag",
      "https://app.example.com/*",
      "https://*.example.com/cb",
      "https://user:pw@app.example.com/cb",
      "https:///cb",
      "myapp:/cb",
      "javascript:alert(1)",
      "/relative/cb",
      "not a url",
      "https://App.Example.com/cb",
      "https://app.example.com/cb with space",
      "",
    ]) {
      expect(isRegistrableRedirectUri(bad), bad).toBe(false);
    }
  });

  it("[TIO-CLIENT-011] matches byte-for-byte with no tolerance except the loopback port", () => {
    const registered = [
      "https://app.example.com/cb",
      "http://127.0.0.1:8080/cb",
      "http://[::1]/cb",
    ];
    expect(matchRedirectUri(registered, "https://app.example.com/cb")).toBe(
      "https://app.example.com/cb",
    );
    for (const wrong of [
      "https://app.example.com/cb/",
      "https://app.example.com/cb?x=1",
      "https://app.example.com/callback",
      "https://app.example.com/c",
      "https://APP.example.com/cb",
      "https://app.example.com/cb#f",
      "https://app.example.com:443/cb",
      "http://app.example.com/cb",
      "https://app.example.com.evil.net/cb",
      "https://evil.net/https://app.example.com/cb",
      "https://app.example.com/cb%2F..",
      "",
    ]) {
      expect(matchRedirectUri(registered, wrong), wrong).toBeNull();
    }
    // Loopback: the port may differ, nothing else may.
    expect(matchRedirectUri(registered, "http://127.0.0.1:51234/cb")).toBe(
      "http://127.0.0.1:8080/cb",
    );
    expect(matchRedirectUri(registered, "http://127.0.0.1/cb")).toBe("http://127.0.0.1:8080/cb");
    expect(matchRedirectUri(registered, "http://[::1]:9/cb")).toBe("http://[::1]/cb");
    expect(matchRedirectUri(registered, "http://127.0.0.1:51234/cb/")).toBeNull();
    expect(matchRedirectUri(registered, "http://127.0.0.1:51234/other")).toBeNull();
    expect(matchRedirectUri(registered, "https://127.0.0.1:51234/cb")).toBeNull();
    expect(matchRedirectUri(registered, "http://127.0.0.2:8080/cb")).toBeNull();
    expect(matchRedirectUri(registered, "http://127.0.0.1:51234/cb?x")).toBeNull();
    expect(matchRedirectUri(registered, "http://u@127.0.0.1:51234/cb")).toBeNull();
    expect(matchRedirectUri(registered, "http://127.0.0.1:x/cb")).toBeNull();
    expect(matchRedirectUri(registered, "http://127.0.0.1:8080/CB")).toBeNull();
    expect(isLoopbackRedirectUri("http://127.0.0.1:8080/cb")).toBe(true);
    expect(isLoopbackRedirectUri("https://127.0.0.1/cb")).toBe(false);
    expect(isLoopbackRedirectUri("::")).toBe(false);
  });
});

describe("client validation (TIO-CLIENT-002)", () => {
  it("accepts a well-formed public client, a secret client and a private_key_jwt client", () => {
    expect(violations({})).toEqual([]);
    expect(
      violations({
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code", "refresh_token", "client_credentials"],
        scopes_allowed: ["openid", "offline_access"],
        audiences: ["https://api.example.com", "urn:example:api"],
        allowed_groups: ["staff"],
        backchannel_logout_uri: "https://app.example.com/logout",
        post_logout_redirect_uris: ["https://app.example.com/bye"],
        access_token_ttl: 300,
      }),
    ).toEqual([]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        grant_types: ["client_credentials"],
        redirect_uris: [],
        jwks: { keys: [{ kty: "EC", crv: "P-256", kid: "k1", x: "x", y: "y" }] },
      }),
    ).toEqual([]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://app.example.com/jwks.json",
      }),
    ).toEqual([]);
  });

  it("redirect_uris: 1–32 registrable, unique entries when authorization_code is granted, empty otherwise", () => {
    expect(violations({ redirect_uris: [] })).toEqual([
      "redirect_uris: required for authorization_code",
    ]);
    expect(
      violations({
        redirect_uris: Array.from({ length: 33 }, (_, i) => `https://a.example.com/${i}`),
      }),
    ).toEqual(["schema:redirect_uris"]);
    expect(
      violations({ redirect_uris: ["https://a.example.com/cb", "https://a.example.com/cb"] }),
    ).toEqual(["redirect_uris: duplicates"]);
    expect(violations({ redirect_uris: ["http://localhost/cb"] })).toEqual([
      'redirect_uris: "http://localhost/cb" is not registrable',
    ]);
    expect(
      violations({
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_post",
        redirect_uris: ["https://a.example.com/cb"],
      }),
    ).toEqual(["redirect_uris: must be empty without authorization_code"]);
  });

  it("post_logout_redirect_uris and backchannel_logout_uri follow the URI rules", () => {
    expect(
      violations({
        post_logout_redirect_uris: ["https://a.example.com/x", "https://a.example.com/x"],
      }),
    ).toEqual(["post_logout_redirect_uris: duplicates"]);
    expect(violations({ post_logout_redirect_uris: ["http://localhost/x"] })).toEqual([
      'post_logout_redirect_uris: "http://localhost/x" is not registrable',
    ]);
    expect(violations({ backchannel_logout_uri: "http://a.example.com/bc" })).toEqual([
      "backchannel_logout_uri: must be an https URL without a fragment",
    ]);
    expect(violations({ backchannel_logout_uri: "https://a.example.com/bc#x" })).toEqual([
      "backchannel_logout_uri: must be an https URL without a fragment",
    ]);
  });

  it("grant_types: non-empty subset; refresh_token requires authorization_code; client_credentials needs a confidential method", () => {
    expect(violations({ grant_types: [] })).toEqual(["schema:grant_types"]);
    expect(violations({ grant_types: ["password"] })).toEqual(["schema:grant_types.0"]);
    expect(violations({ grant_types: ["authorization_code", "authorization_code"] })).toEqual([
      "grant_types: duplicates",
    ]);
    expect(violations({ grant_types: ["refresh_token"], redirect_uris: [] })).toEqual([
      "grant_types: refresh_token requires authorization_code",
      "token_endpoint_auth_method: none requires grant_types of authorization_code with optional refresh_token",
    ]);
    expect(violations({ grant_types: ["authorization_code", "client_credentials"] })).toEqual([
      "token_endpoint_auth_method: none requires grant_types of authorization_code with optional refresh_token",
      "grant_types: client_credentials requires a confidential authentication method",
    ]);
  });

  it("token_endpoint_auth_method: keys only for private_key_jwt, exactly one of jwks or jwks_uri", () => {
    expect(violations({ token_endpoint_auth_method: "private_key_jwt" })).toEqual([
      "jwks: private_key_jwt requires exactly one of jwks or jwks_uri",
    ]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "RSA", kid: "r", n: "n", e: "e" }] },
        jwks_uri: "https://a.example.com/jwks",
      }),
    ).toEqual(["jwks: private_key_jwt requires exactly one of jwks or jwks_uri"]);
    expect(violations({ jwks_uri: "https://a.example.com/jwks" })).toEqual([
      "jwks: only private_key_jwt clients register keys",
    ]);
    expect(
      violations({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [] } }),
    ).toEqual(["schema:jwks.keys"]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "EC", crv: "P-256", x: "x", y: "y" }] },
      }),
    ).toEqual(["schema:jwks.keys.0.kid"]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "EC", kid: "k", crv: "P-256", x: "x", y: "y", d: "d" }] },
      }),
    ).toEqual(["schema:jwks.keys.0"]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: {
          keys: Array.from({ length: 9 }, (_, i) => ({
            kty: "EC",
            kid: `k${i}`,
            crv: "P-256",
            x: "x",
            y: "y",
          })),
        },
      }),
    ).toEqual(["schema:jwks.keys"]);
    expect(
      violations({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "http://a.example.com/jwks",
      }),
    ).toEqual(["schema:jwks_uri"]);
  });

  it("scopes_allowed: non-empty, known, unique; admin only from an administrator", () => {
    expect(violations({ scopes_allowed: [] })).toEqual(["schema:scopes_allowed"]);
    expect(violations({ scopes_allowed: ["openid", "read:all"] })).toEqual([
      "schema:scopes_allowed.1",
    ]);
    expect(violations({ scopes_allowed: ["openid", "openid"] })).toEqual([
      "scopes_allowed: duplicates",
    ]);
    expect(violations({ scopes_allowed: ["openid", "admin"] })).toEqual([
      "scopes_allowed: admin may only be granted by an administrator",
    ]);
    expect(violations({ scopes_allowed: ["openid", "admin"] }, { actorHasAdmin: true })).toEqual(
      [],
    );
  });

  it("audiences: 0–16 unique https URIs or URNs without fragments, never the issuer", () => {
    expect(
      violations({ audiences: ["https://api.example.com", "https://api.example.com"] }),
    ).toEqual(["audiences: duplicates"]);
    for (const bad of [
      "http://api.example.com",
      "https://api.example.com/#x",
      "api.example.com",
      "urn:",
      "https://API.example.com",
    ]) {
      expect(violations({ audiences: [bad] }), bad).toEqual([
        `audiences: "${bad}" is not an https URI or URN`,
      ]);
    }
    expect(violations({ audiences: ["https://auth.example.com"] })).toEqual([
      "audiences: the issuer is added by scope, never configured",
    ]);
    expect(
      violations({ audiences: Array.from({ length: 17 }, (_, i) => `https://a${i}.example.com`) }),
    ).toEqual(["schema:audiences"]);
  });

  it("allowed_groups: null or existing, unique group names", () => {
    expect(violations({ allowed_groups: ["staff", "staff"] })).toEqual([
      "allowed_groups: duplicates",
    ]);
    expect(violations({ allowed_groups: ["ghost"] })).toEqual([
      'allowed_groups: group "ghost" does not exist',
    ]);
    expect(violations({ allowed_groups: null })).toEqual([]);
  });

  it("TTL overrides stay within §5.7.4 and unknown fields are rejected", () => {
    expect(TTL_BOUNDS.access_token_ttl).toEqual([60, 3_600]);
    expect(violations({ access_token_ttl: 59 })).toEqual(["schema:access_token_ttl"]);
    expect(violations({ id_token_ttl: 3_601 })).toEqual(["schema:id_token_ttl"]);
    expect(violations({ refresh_token_ttl: 7_776_001 })).toEqual(["schema:refresh_token_ttl"]);
    expect(violations({ refresh_idle_ttl: 3_599 })).toEqual(["schema:refresh_idle_ttl"]);
    expect(violations({ refresh_idle_ttl: 3_600, refresh_token_ttl: 86_400 })).toEqual([]);
    expect(violations({ surprise: 1 })).toEqual(["schema:"]);
    expect(violations({ client_id: "Bad Id" })).toEqual(["schema:client_id"]);
    expect(violations({ client_name: "  " })).toEqual(["schema:client_name"]);
  });
});

describe("client identifiers and secrets", () => {
  it("[TIO-DATA-003] generated ids are c_ plus 22 lowercase alphanumerics and match the client id pattern", () => {
    const id = generateClientId();
    expect(id).toMatch(/^c_[a-z0-9]{22}$/);
    expect(CLIENT_ID_PATTERN.test(id)).toBe(true);
    expect(CLIENT_ID_PATTERN.test("web")).toBe(true);
    expect(CLIENT_ID_PATTERN.test("we")).toBe(false);
    expect(CLIENT_ID_PATTERN.test("-web")).toBe(false);
    expect(CLIENT_ID_PATTERN.test("Web")).toBe(false);
    expect(CLIENT_ID_PATTERN.test("a".repeat(65))).toBe(false);
    expect(generateClientId()).not.toBe(id);
  });

  it("[TIO-CLIENT-003] [TIO-CRYPTO-004] secrets are 32 random bytes base64url, stored only as SHA-256", async () => {
    const { secret, hash } = await generateClientSecret();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hash).toHaveLength(32);
    expect((await generateClientSecret()).secret).not.toBe(secret);
    expect(usesSecret("client_secret_basic")).toBe(true);
    expect(usesSecret("client_secret_post")).toBe(true);
    expect(usesSecret("none")).toBe(false);
    expect(usesSecret("private_key_jwt")).toBe(false);
    const parsed = ClientInputSchema.parse({
      ...base,
      token_endpoint_auth_method: "client_secret_basic",
    });
    const client = clientFromInput(parsed, "web", hash, 1_000);
    expect(client.client_secret_hash).toBe(hash);
    expect(client).toMatchObject({
      client_id: "web",
      disabled_at: null,
      created_at: 1_000,
      updated_at: 1_000,
      skip_consent: false,
    });
  });
});
