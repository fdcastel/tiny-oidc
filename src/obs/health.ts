import type { Handler } from "hono";
import type { Health } from "../api/definitions.ts";
import { pingDb } from "../db/settings.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";

// Health endpoint (TIO-OBS-003, TIO-HTTP-006): answers on any host, touches no
// Durable Object, reports D1 liveness and the build version.

export function healthHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const config = c.get("config");
    const d1 = await pingDb(c.get("db"));
    const body: Health = {
      status: d1 ? "ok" : "degraded",
      version: config.version,
      // Filled in Phase 1 when the key store exists.
      active_kid: null,
      d1: d1 ? "ok" : "error",
      time: clock.now(),
    };
    const host = new URL(c.req.url).host;
    if (host !== config.issuer.host) body.issuer_mismatch = host;
    return c.json(body, d1 ? 200 : 503);
  };
}
