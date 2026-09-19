import type { Handler } from "hono";
import { z } from "zod";
import type { LogoutRequest } from "../do/InteractionDO.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { readJsonBody } from "../util/json.ts";
import { guard, redirectTo } from "./api.ts";

// The logout interaction's one endpoint (spec §7.6): the person confirms or
// declines; either way the browser goes to /complete, which ends the session
// only on a confirmation (TIO-IX-050).

const DecisionBody = z.object({ confirm: z.boolean() }).strict();

export function logoutDecisionHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, stub, now, id } = guarded;
    if (doc.kind !== "logout" || doc.status !== "login_required" || doc.logout === null) {
      return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
    }
    const body = await readJsonBody(c.req.raw, DecisionBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const logout: LogoutRequest = {
      ...doc.logout,
      decision: body.value.confirm ? "confirm" : "decline",
    };
    c.get("metrics").doCalls += 1;
    const applied = await stub.apply("logout_decision", "ready", { logout }, now);
    if (!applied.ok) {
      return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
    }
    c.get("audit").emit({
      type: "logout.confirmed",
      outcome: body.value.confirm ? "success" : "failure",
      actor: { kind: "user", id: doc.logout.uid },
      user_id: doc.logout.uid,
      client_id: doc.client_id,
      sid: doc.logout.sid,
      interaction_id: id,
      reason: body.value.confirm ? null : "declined",
    });
    return c.json({ redirect_to: redirectTo(c, id) });
  };
}
