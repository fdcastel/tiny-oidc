import type { Handler } from "hono";
import type { Health } from "../api/definitions.ts";
import { pingDb } from "../db/settings.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";

// Health endpoint (TIO-OBS-003, TIO-HTTP-006): answers on any host, touches no
// Durable Object, reports D1 liveness, whether the stored settings are usable
// and the build version. A deploy's smoke test reads it before the new version
// takes traffic, so settings this build cannot use — a changed Durable Object
// jurisdiction (TIO-CFG-006) above all — stop the rollout instead of every
// login after it.

export function healthHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const config = c.get("config");
    const d1 = await pingDb(c.get("db"));
    let settings = false;
    if (d1) {
      try {
        await c.get("settingsLoader").get(c.get("db"), config);
        settings = true;
      } catch (error) {
        // The loader throws SettingsUnavailableError with what went wrong (a D1
        // failure, a violated rule such as a changed jurisdiction) as its cause.
        c.get("logger").log("error", "settings unusable", {
          reason: String((error as Error).cause),
        });
      }
    }
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
      status: d1 && settings ? "ok" : "degraded",
      version: config.version,
      active_kid: activeKid,
      d1: d1 ? "ok" : "error",
      settings: settings ? "ok" : "error",
      time: clock.now(),
    };
    const host = new URL(c.req.url).host;
    if (host !== config.issuer.host) body.issuer_mismatch = host;
    return c.json(body, body.status === "ok" ? 200 : 503);
  };
}
