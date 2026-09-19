import type { MiddlewareHandler } from "hono";
import type { LoadedKeys } from "../crypto/keystore.ts";
import type { Clock } from "../env.ts";
import { type AccessToken, verifyAccessToken } from "../oidc/bearer.ts";
import type { Scope } from "../oidc/capabilities.ts";
import type { Client } from "../oidc/clients.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { limited, rateLimited } from "../router/rate-limit.ts";
import { userStub } from "../users/create.ts";
import { ADMINS_GROUP } from "../users/groups.ts";

// Authorization of `/api/v1/admin/*` (spec §9.1, TIO-ADMIN-001): a valid
// `at+jwt` of the OP's own audience with scope `admin`, whose subject still
// holds the privilege right now: a user who is a member of `admins` and not
// disabled (asked of `UserDO` on every request), or a service client with
// `admin` in `scopes_allowed` and not disabled. Bootstrap (§9.3) is the one
// path under the prefix with its own guard.

export const ADMIN_SCOPE: Scope = "admin";

/** Who is acting, for audit records (`actor = {kind: "admin", id: sub}`, TIO-ADMIN-002). */
export interface AdminActor {
  kind: "admin";
  id: string;
  subject: "user" | "client";
  token: AccessToken;
}

/** The token of `Authorization: Bearer`; the admin API accepts it nowhere else. */
function bearerHeader(header: string | undefined): string | null {
  if (header === undefined) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match ? (match[1] as string) : null;
}

const challenge = (error: string) => ({ "WWW-Authenticate": `Bearer error="${error}"` });

export function requireAdmin(clock: Clock): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const invalidToken = () =>
      errorResponse(c, 401, "invalid_token", "invalid token", challenge("invalid_token"));
    const insufficient = (description: string) =>
      errorResponse(c, 403, "insufficient_scope", description, challenge("insufficient_scope"));
    const presented = bearerHeader(c.req.header("authorization"));
    if (presented === null) {
      return errorResponse(c, 401, "invalid_token", "bearer token required", {
        "WWW-Authenticate": "Bearer",
      });
    }
    const config = c.get("config");
    const db = c.get("db");
    let keys: LoadedKeys;
    try {
      keys = await c.get("keyStore").get(db, config.keys);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "keys unavailable");
    }
    const token = await verifyAccessToken(keys, presented, config.issuerUrl, clock, false);
    if (token === null) return invalidToken();
    if (!token.scopes.includes(ADMIN_SCOPE)) return insufficient("the admin scope is required");
    // 600 per 60 s per token (§6.7). The key is the whole jti: a prefix of a UUID v7 is
    // its timestamp, shared by every token minted in the same millisecond.
    const jti = token.payload.jti as string;
    if (await limited(c.env, "admin_token", jti)) return rateLimited(c, "admin_token");

    if (token.sub === token.client_id) {
      // A service client (client_credentials): the current record decides.
      let client: Client | null;
      try {
        client = await c.get("clients").get(db, token.client_id);
      } catch {
        return errorResponse(c, 503, "temporarily_unavailable", "client directory unavailable");
      }
      if (client === null || client.disabled_at !== null) return invalidToken();
      if (!client.scopes_allowed.includes(ADMIN_SCOPE)) {
        return insufficient("the client may no longer use the admin scope");
      }
      c.set("admin", { kind: "admin", id: token.sub, subject: "client", token });
      return next();
    }
    // A user: membership of `admins` is read from the Durable Object, not the token.
    c.get("metrics").doCalls += 1;
    let profile: Awaited<ReturnType<ReturnType<typeof userStub>["getProfile"]>>;
    try {
      profile = await userStub(c.env, token.sub).getProfile();
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "user storage unavailable");
    }
    if (!profile.ok || profile.profile.disabled_at !== null) return invalidToken();
    if (!profile.profile.groups.includes(ADMINS_GROUP)) {
      return insufficient("the user is no longer an administrator");
    }
    c.set("admin", { kind: "admin", id: token.sub, subject: "user", token });
    return next();
  };
}
