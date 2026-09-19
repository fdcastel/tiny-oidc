import type { Handler } from "hono";
import type { LoadedKeys } from "../crypto/keystore.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { userStub } from "../users/create.ts";
import { invalidToken, presentedBearer, verifyAccessToken } from "./bearer.ts";
import { scopedClaims } from "./tokens.ts";

// GET|POST /userinfo (spec §5.8): the current profile from the UserDO, filtered
// by the token's scope; never claims copied from the token.

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" };

export function userinfoHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const token = await presentedBearer(c);
    if (token === null) return invalidToken(c);
    const config = c.get("config");
    let keys: LoadedKeys;
    try {
      keys = await c.get("keyStore").get(c.get("db"), config.keys);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "keys unavailable");
    }
    // OIDC Core: a token whose audience is the client itself is accepted here (TIO-TOKEN-034).
    const access = await verifyAccessToken(keys, token, config.issuerUrl, clock, true);
    if (access === null || access.auth_time === null) return invalidToken(c);
    c.get("metrics").doCalls += 1;
    const profile = await userStub(c.env, access.sub).getProfile();
    if (!profile.ok || profile.profile.disabled_at !== null) return invalidToken(c);
    const p = profile.profile;
    return c.json(
      {
        sub: p.id,
        ...scopedClaims(access.scopes, {
          name: p.display_name,
          updated_at: p.updated_at,
          email: p.email,
          email_verified: p.email_verified,
          groups: p.groups,
        }),
      },
      200,
      NO_STORE,
    );
  };
}
