import type { Context } from "hono";
import type { JWTPayload } from "jose";
import { verifyOwnJwt } from "../crypto/jwt.ts";
import type { LoadedKeys } from "../crypto/keystore.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import type { Scope } from "./capabilities.ts";

// Bearer access tokens on the OP's own resources (TIO-TOKEN-034): the JWT is
// one of ours (`at+jwt`, signature, iss, exp with no leeway) and its `aud`
// names the OP, or the client for /userinfo.

export interface AccessToken {
  payload: JWTPayload;
  sub: string;
  client_id: string;
  scopes: Scope[];
  /** Present on user tokens, absent on client_credentials tokens. */
  auth_time: number | null;
  sid: string | null;
}

/** The token presented as `Authorization: Bearer`, or on POST as the form field; query strings are refused (TIO-UINFO-001). */
export async function presentedBearer(c: Context<AppEnv>): Promise<string | null> {
  if (new URL(c.req.url).searchParams.has("access_token")) return null;
  const header = c.req.header("authorization");
  if (header !== undefined) {
    const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
    return match ? (match[1] as string) : null;
  }
  if (c.req.method !== "POST") return null;
  const contentType = c.req.header("content-type");
  if (contentType === undefined) return null;
  const type = (contentType.split(";")[0] as string).trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded") return null;
  const form = new URLSearchParams(await c.req.raw.text());
  return form.get("access_token");
}

/**
 * Verifies an access token for a resource: `aud` must contain `issuer` or,
 * when `acceptClient` is set (/userinfo, /revoke), the token's own client.
 * Null when anything fails. The claims of a token the OP signed itself are
 * the ones `accessTokenClaims` put there, so they are read without checks.
 */
export async function verifyAccessToken(
  keys: LoadedKeys,
  token: string,
  issuer: string,
  clock: Clock,
  acceptClient: boolean,
): Promise<AccessToken | null> {
  const payload = await verifyOwnJwt(keys, token, { issuer, typ: "at+jwt" }, clock);
  if (payload === null) return null;
  const clientId = payload["client_id"] as string;
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const accepted = acceptClient ? [issuer, clientId] : [issuer];
  if (!aud.some((a) => accepted.includes(a as string))) return null;
  return {
    payload,
    sub: payload.sub as string,
    client_id: clientId,
    scopes: (payload["scope"] as string).split(" ").filter((s) => s.length > 0) as Scope[],
    auth_time: typeof payload["auth_time"] === "number" ? payload["auth_time"] : null,
    sid: typeof payload["sid"] === "string" ? payload["sid"] : null,
  };
}

/** 401 with the RFC 6750 challenge and no details (TIO-UINFO-001). */
export function invalidToken(c: Context<AppEnv>): Response {
  return errorResponse(c, 401, "invalid_token", "invalid token", {
    "WWW-Authenticate": 'Bearer error="invalid_token"',
  });
}
