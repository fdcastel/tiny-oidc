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
    // The signing key bootstraps on the first request of an empty store (TIO-KEYS-010);
    // any failure to load it is reported as a missing kid, never as a crash.
    let activeKid: string | null = null;
    if (d1) {
      try {
        activeKid = (await c.get("keyStore").get(c.get("db"), config.keys)).signing.kid;
      } catch {
        activeKid = null;
      }
    }
    const body: Health = {
      status: d1 ? "ok" : "degraded",
      version: config.version,
      active_kid: activeKid,
      d1: d1 ? "ok" : "error",
      time: clock.now(),
    };
    const host = new URL(c.req.url).host;
    if (host !== config.issuer.host) body.issuer_mismatch = host;
    return c.json(body, d1 ? 200 : 503);
  };
}
