import type { Handler } from "hono";
import { handleType } from "../crypto/envelope.ts";
import type { LoadedKeys } from "../crypto/keystore.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { userStub } from "../users/create.ts";
import { verifyAccessToken } from "./bearer.ts";
import { openRefreshHandle } from "./handles.ts";
import { authenticateFormClient, protocolForm } from "./token-common.ts";

// POST /revoke (RFC 7009, spec §5.9): always 200 for a well-formed request.
// A refresh token of the authenticated client ends its family; an access
// token with a `sid` ends the client's session-bound family; anything else
// is a no-op.

export function revokeHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    if (await limited(c.env, "ip_token", ipKey(c.req.raw))) return rateLimited(c, "ip_token");
    const form = await protocolForm(c);
    if (!form.ok) return form.response;
    const auth = await authenticateFormClient(c, form.params, clock);
    if (!auth.ok) return auth.response;
    const client = auth.client;
    const token = form.params.get("token");
    if (token === undefined) return errorResponse(c, 400, "invalid_request", "token is required");
    const config = c.get("config");
    const now = clock.now();
    const log = (event: string, fields: Record<string, unknown>) =>
      c.get("logger").log("info", event, {
        request_id: c.get("requestId"),
        client_id: client.client_id,
        ...fields,
      });
    const audit = (
      type: "token.revoked" | "token.revoke_foreign",
      uid: string,
      sid: string | null,
      data: Record<string, unknown>,
    ) =>
      c.get("audit").emit({
        type,
        outcome: type === "token.revoked" ? "success" : "failure",
        actor: { kind: "client", id: client.client_id },
        user_id: uid,
        client_id: client.client_id,
        sid,
        data,
      });
    // The hint is advisory (RFC 7009 §2.1); the token's own format decides.
    if (handleType(token) === "refresh") {
      const refresh = await openRefreshHandle(config.keys, token);
      if (refresh !== null) {
        c.get("metrics").doCalls += 1;
        const revoked = await userStub(c.env, refresh.uid).revokeFamilyById(
          refresh.family_id,
          now,
          "client_revoke",
          client.client_id,
        );
        const own = revoked.ok && revoked.revoked;
        log(own ? "token.revoke" : "token.revoke_foreign", { family_id: refresh.family_id });
        audit(own ? "token.revoked" : "token.revoke_foreign", refresh.uid, null, {
          family: refresh.family_id,
          hint: "refresh_token",
        });
      }
      return c.body(null, 200);
    }
    let keys: LoadedKeys;
    try {
      keys = await c.get("keyStore").get(c.get("db"), config.keys);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "keys unavailable");
    }
    const access = await verifyAccessToken(keys, token, config.issuerUrl, clock, true);
    if (access !== null && access.sid !== null && access.client_id === client.client_id) {
      c.get("metrics").doCalls += 1;
      const revoked = await userStub(c.env, access.sub).revokeSessionFamiliesOfClient(
        access.sid,
        client.client_id,
        now,
      );
      log("token.revoke", { sid: access.sid, families: revoked.ok ? revoked.revoked : 0 });
      audit("token.revoked", access.sub, access.sid, {
        families: revoked.ok ? revoked.revoked : 0,
        hint: "access_token",
      });
    } else if (access !== null) {
      log("token.revoke_foreign", { sid: access.sid });
      audit("token.revoke_foreign", access.sub, access.sid, { hint: "access_token" });
    }
    return c.body(null, 200);
  };
}
