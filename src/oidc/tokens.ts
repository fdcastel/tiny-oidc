import type { JWTPayload } from "jose";
import { sha256 } from "../crypto/hash.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import type { AcrValue, Scope } from "./capabilities.ts";

// Claim builders for the three token kinds the OP signs (spec §5.7). Pure:
// every input is explicit and no claim is ever emitted as null (TIO-TOKEN-031).

/** Logout tokens live 120 s (§5.7.4). */
export const LOGOUT_TOKEN_TTL = 120;

/** The profile claims an ID token or UserInfo response may carry, gated by scope. */
export interface ProfileClaims {
  name: string | null;
  updated_at: number | null;
  email: string | null;
  email_verified: boolean;
  groups: string[];
}

/** Claims shared by ID and access tokens issued to a user. */
export interface UserContext {
  sub: string;
  auth_time: number;
  acr: AcrValue;
  amr: string[];
  /** The session id; null for offline families, which are not bound to one (TIO-TOKEN-032). */
  sid: string | null;
}

/** Claims permitted by the scopes, from the current profile (§5.12). */
export function scopedClaims(scopes: readonly Scope[], profile: ProfileClaims): JWTPayload {
  const claims: JWTPayload = {};
  if (scopes.includes("profile")) {
    if (profile.name !== null) claims["name"] = profile.name;
    if (profile.updated_at !== null) claims["updated_at"] = profile.updated_at;
  }
  // email_verified is emitted only alongside email (TIO-TOKEN-031).
  if (scopes.includes("email") && profile.email !== null) {
    claims["email"] = profile.email;
    claims["email_verified"] = profile.email_verified;
  }
  if (scopes.includes("groups")) claims["groups"] = [...profile.groups].sort();
  return claims;
}

/** Left-most 128 bits of SHA-256 of the access token, base64url (§5.7.1). */
export async function atHash(accessToken: string): Promise<string> {
  return encodeBase64Url((await sha256(accessToken)).subarray(0, 16));
}

export interface IdTokenInput {
  issuer: string;
  clientId: string;
  now: number;
  ttl: number;
  user: UserContext;
  nonce: string | null;
  accessToken: string;
  scopes: readonly Scope[];
  profile: ProfileClaims;
}

/** ID token claims (TIO-TOKEN-030). */
export async function idTokenClaims(input: IdTokenInput): Promise<JWTPayload> {
  const claims: JWTPayload = {
    iss: input.issuer,
    sub: input.user.sub,
    aud: input.clientId,
    exp: input.now + input.ttl,
    iat: input.now,
    auth_time: input.user.auth_time,
    acr: input.user.acr,
    amr: input.user.amr,
    at_hash: await atHash(input.accessToken),
    ...scopedClaims(input.scopes, input.profile),
  };
  if (input.user.sid !== null) claims["sid"] = input.user.sid;
  if (input.nonce !== null) claims["nonce"] = input.nonce;
  return claims;
}

export interface AccessTokenInput {
  issuer: string;
  clientId: string;
  now: number;
  ttl: number;
  jti: string;
  scopes: readonly Scope[];
  /** The client's static `audiences` list (TIO-TOKEN-033). */
  audiences: readonly string[];
  /** Absent for client_credentials tokens (TIO-TOKEN-021). */
  user: UserContext | null;
  groups: readonly string[];
}

/** The `aud` of an access token: the client's audiences or the client id, plus ISSUER for the OP's own APIs; a string when single (TIO-TOKEN-033). */
export function accessTokenAudience(
  issuer: string,
  clientId: string,
  audiences: readonly string[],
  scopes: readonly Scope[],
): string | string[] {
  const aud = audiences.length > 0 ? [...audiences] : [clientId];
  if ((scopes.includes("account") || scopes.includes("admin")) && !aud.includes(issuer)) {
    aud.push(issuer);
  }
  return aud.length === 1 ? (aud[0] as string) : aud;
}

/** RFC 9068 access token claims (TIO-TOKEN-032). */
export function accessTokenClaims(input: AccessTokenInput): JWTPayload {
  const claims: JWTPayload = {
    iss: input.issuer,
    sub: input.user?.sub ?? input.clientId,
    aud: accessTokenAudience(input.issuer, input.clientId, input.audiences, input.scopes),
    exp: input.now + input.ttl,
    iat: input.now,
    jti: input.jti,
    client_id: input.clientId,
    scope: input.scopes.join(" "),
  };
  if (input.user) {
    if (input.user.sid !== null) claims["sid"] = input.user.sid;
    claims["auth_time"] = input.user.auth_time;
    claims["acr"] = input.user.acr;
    claims["amr"] = input.user.amr;
    if (input.scopes.includes("groups")) claims["groups"] = [...input.groups].sort();
  }
  return claims;
}

export interface LogoutTokenInput {
  issuer: string;
  clientId: string;
  sub: string;
  sid: string;
  jti: string;
  now: number;
}

/** Back-channel logout token claims (TIO-LOGOUT-010): no nonce, ever. */
export function logoutTokenClaims(input: LogoutTokenInput): JWTPayload {
  return {
    iss: input.issuer,
    sub: input.sub,
    aud: input.clientId,
    iat: input.now,
    exp: input.now + LOGOUT_TOKEN_TTL,
    jti: input.jti,
    sid: input.sid,
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  };
}
