import { describe, expect, it } from "vitest";
import { ACR, CAPABILITIES, isScope, SIGNING_ALG } from "../../src/oidc/capabilities.ts";
import {
  accessTokenAudience,
  accessTokenClaims,
  atHash,
  idTokenClaims,
  LOGOUT_TOKEN_TTL,
  logoutTokenClaims,
  type ProfileClaims,
  scopedClaims,
  type UserContext,
} from "../../src/oidc/tokens.ts";

const ISSUER = "https://auth.example.com";
const user: UserContext = {
  sub: "0192aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
  auth_time: 1_790_000_000,
  acr: ACR.passkey,
  amr: ["hwk", "user"],
  sid: "0192aaaa-bbbb-7ccc-8ddd-ffffffffffff",
};
const profile: ProfileClaims = {
  name: "Alice",
  updated_at: 1_790_000_100,
  email: "alice@example.com",
  email_verified: true,
  groups: ["staff", "admins"],
};

describe("capabilities", () => {
  it("expose the fixed vocabularies of §5.2 and helpers over them", () => {
    expect(SIGNING_ALG).toBe("ES256");
    expect(ACR).toEqual({
      passkey: "urn:tinyoidc:acr:passkey",
      federated: "urn:tinyoidc:acr:federated",
    });
    expect(isScope("openid")).toBe(true);
    expect(isScope("read:all")).toBe(false);
    expect(CAPABILITIES.code_challenge_methods_supported).toEqual(["S256"]);
    expect(CAPABILITIES.response_types_supported).toEqual(["code"]);
  });
});

describe("ID token claims", () => {
  it("[TIO-TOKEN-030] carries iss, sub, aud, exp, iat, auth_time, nonce, acr, amr, sid, at_hash and scope-gated profile claims", async () => {
    const claims = await idTokenClaims({
      issuer: ISSUER,
      clientId: "web",
      now: 1_790_000_500,
      ttl: 600,
      user,
      nonce: "n-1",
      accessToken: "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
      scopes: ["openid", "profile", "email", "groups"],
      profile,
    });
    expect(claims).toEqual({
      iss: ISSUER,
      sub: user.sub,
      aud: "web",
      exp: 1_790_001_100,
      iat: 1_790_000_500,
      auth_time: user.auth_time,
      nonce: "n-1",
      acr: ACR.passkey,
      amr: ["hwk", "user"],
      sid: user.sid,
      at_hash: "77QmUPtjPfzWtF2AnpK9RQ",
      name: "Alice",
      updated_at: 1_790_000_100,
      email: "alice@example.com",
      email_verified: true,
      groups: ["admins", "staff"],
    });
  });

  it("[TIO-TOKEN-031] omits null claims, emits email_verified only with email, and gates claims by scope", async () => {
    const bare = await idTokenClaims({
      issuer: ISSUER,
      clientId: "web",
      now: 1,
      ttl: 600,
      user,
      nonce: null,
      accessToken: "at",
      scopes: ["openid", "profile", "email", "groups"],
      profile: { name: null, updated_at: null, email: null, email_verified: false, groups: [] },
    });
    expect(bare).not.toHaveProperty("nonce");
    expect(bare).not.toHaveProperty("name");
    expect(bare).not.toHaveProperty("updated_at");
    expect(bare).not.toHaveProperty("email");
    expect(bare).not.toHaveProperty("email_verified");
    expect(bare["groups"]).toEqual([]);
    expect(Object.values(bare)).not.toContain(null);
    // An offline family's ID token has no session to name (TIO-RT-005).
    const offline = await idTokenClaims({
      issuer: ISSUER,
      clientId: "web",
      now: 1,
      ttl: 600,
      user: { ...user, sid: null },
      nonce: null,
      accessToken: "at",
      scopes: ["openid"],
      profile,
    });
    expect(offline).not.toHaveProperty("sid");
    const onlyOpenid = scopedClaims(["openid"], profile);
    expect(onlyOpenid).toEqual({});
    expect(scopedClaims(["email"], profile)).toEqual({
      email: "alice@example.com",
      email_verified: true,
    });
    expect(scopedClaims(["profile"], { ...profile, updated_at: null })).toEqual({ name: "Alice" });
  });

  it("at_hash is the left-most 128 bits of SHA-256 of the access token, base64url", async () => {
    // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 ...
    expect(await atHash("abc")).toBe("ungWv48Bz-pBQUDeXa4iIw");
  });
});

describe("access token claims", () => {
  it("[TIO-TOKEN-032] carries the RFC 9068 claims, sid only for session families, and groups with the groups scope", () => {
    const base = {
      issuer: ISSUER,
      clientId: "web",
      now: 100,
      ttl: 600,
      jti: "j1",
      scopes: ["openid", "groups"] as const,
      audiences: [],
      user,
      groups: ["b", "a"],
    };
    expect(accessTokenClaims(base)).toEqual({
      iss: ISSUER,
      sub: user.sub,
      aud: "web",
      exp: 700,
      iat: 100,
      jti: "j1",
      client_id: "web",
      scope: "openid groups",
      sid: user.sid,
      auth_time: user.auth_time,
      acr: ACR.passkey,
      amr: ["hwk", "user"],
      groups: ["a", "b"],
    });
    const offline = accessTokenClaims({
      ...base,
      user: { ...user, sid: null },
      scopes: ["openid"],
    });
    expect(offline).not.toHaveProperty("sid");
    expect(offline).not.toHaveProperty("groups");
  });

  it("[TIO-TOKEN-021] client_credentials tokens have sub = client_id and no user claims", () => {
    const claims = accessTokenClaims({
      issuer: ISSUER,
      clientId: "svc",
      now: 100,
      ttl: 600,
      jti: "j2",
      scopes: ["admin"],
      audiences: [],
      user: null,
      groups: [],
    });
    expect(claims).toEqual({
      iss: ISSUER,
      sub: "svc",
      aud: ["svc", ISSUER],
      exp: 700,
      iat: 100,
      jti: "j2",
      client_id: "svc",
      scope: "admin",
    });
  });

  it("[TIO-TOKEN-033] aud is the client's audiences or the client id, plus ISSUER for account/admin, string when single", () => {
    expect(accessTokenAudience(ISSUER, "web", [], ["openid"])).toBe("web");
    expect(accessTokenAudience(ISSUER, "web", ["https://api.example.com"], ["openid"])).toBe(
      "https://api.example.com",
    );
    expect(
      accessTokenAudience(ISSUER, "web", ["https://api.example.com", "urn:x"], ["openid"]),
    ).toEqual(["https://api.example.com", "urn:x"]);
    expect(accessTokenAudience(ISSUER, "web", [], ["openid", "account"])).toEqual(["web", ISSUER]);
    expect(accessTokenAudience(ISSUER, "web", ["https://api.example.com"], ["admin"])).toEqual([
      "https://api.example.com",
      ISSUER,
    ]);
    expect(accessTokenAudience(ISSUER, "web", [ISSUER], ["admin"])).toBe(ISSUER);
  });
});

describe("logout token claims", () => {
  it("[TIO-LOGOUT-010] carries iss, sub, aud, iat, exp = iat + 120, jti, sid and the backchannel-logout event, and no nonce", () => {
    const claims = logoutTokenClaims({
      issuer: ISSUER,
      clientId: "web",
      sub: user.sub,
      sid: user.sid as string,
      jti: "j3",
      now: 1_000,
    });
    expect(claims).toEqual({
      iss: ISSUER,
      sub: user.sub,
      aud: "web",
      iat: 1_000,
      exp: 1_000 + LOGOUT_TOKEN_TTL,
      jti: "j3",
      sid: user.sid,
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    expect(LOGOUT_TOKEN_TTL).toBe(120);
    expect(claims).not.toHaveProperty("nonce");
  });
});
