import type { MiddlewareHandler } from "hono";
import type { LoadedKeys } from "../crypto/keystore.ts";
import type { UserProfile } from "../do/UserDO.ts";
import type { Clock } from "../env.ts";
import { type AccessToken, verifyAccessToken } from "../oidc/bearer.ts";
import type { Scope } from "../oidc/capabilities.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { userStub } from "../users/create.ts";

// Authorization of `/api/v1/me/*` (spec §8, TIO-ME-001): a valid `at+jwt`
// of the OP's own audience with scope `account`, whose subject is a user (not
// a service client) that is not disabled right now. The profile read here
// serves the handlers too.

export const ACCOUNT_SCOPE: Scope = "account";

/** The person acting, for the handlers and their audit records (TIO-ME-002). */
export interface Account {
  token: AccessToken;
  profile: UserProfile;
  /** What the registration challenge is keyed by: the session, or the token for offline ones. */
  challengeKey: string;
}

function bearerHeader(header: string | undefined): string | null {
  if (header === undefined) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match ? (match[1] as string) : null;
}

const challenge = (error: string) => ({ "WWW-Authenticate": `Bearer error="${error}"` });

export function requireAccount(clock: Clock): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (await limited(c.env, "ip_me", ipKey(c.req.raw))) return rateLimited(c, "ip_me");
    const invalidToken = () =>
      errorResponse(c, 401, "invalid_token", "invalid token", challenge("invalid_token"));
    const presented = bearerHeader(c.req.header("authorization"));
    if (presented === null) {
      return errorResponse(c, 401, "invalid_token", "bearer token required", {
        "WWW-Authenticate": "Bearer",
      });
    }
    const config = c.get("config");
    let keys: LoadedKeys;
    try {
      keys = await c.get("keyStore").get(c.get("db"), config.keys);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "keys unavailable");
    }
    const token = await verifyAccessToken(keys, presented, config.issuerUrl, clock, false);
    // A service client's token names no person.
    if (token === null || token.sub === token.client_id) return invalidToken();
    if (!token.scopes.includes(ACCOUNT_SCOPE)) {
      return errorResponse(
        c,
        403,
        "insufficient_scope",
        "the account scope is required",
        challenge("insufficient_scope"),
      );
    }
    c.get("metrics").doCalls += 1;
    let profile: Awaited<ReturnType<ReturnType<typeof userStub>["getProfile"]>>;
    try {
      profile = await userStub(c.env, token.sub).getProfile();
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "user storage unavailable");
    }
    if (!profile.ok || profile.profile.disabled_at !== null) return invalidToken();
    c.set("me", {
      token,
      profile: profile.profile,
      challengeKey: token.sid ?? `jti:${token.payload.jti as string}`,
    });
    return next();
  };
}
