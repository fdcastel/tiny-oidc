import type { InteractionDO } from "./do/InteractionDO.ts";
import type { UserDO } from "./do/UserDO.ts";

// The single declaration of the Worker's bindings, vars and secrets (spec §2.2, §12.2).
// scripts/config-check.ts asserts that wrangler.jsonc declares exactly these bindings.
export interface Env {
  // Bindings (§2.2)
  DB: D1Database;
  USER_DO: DurableObjectNamespace<UserDO>;
  INTERACTION_DO: DurableObjectNamespace<InteractionDO>;
  TASKS: Queue<unknown>;
  AUDIT_BUCKET: R2Bucket;
  RL_IP: RateLimit;
  RL_CLIENT: RateLimit;
  METRICS?: AnalyticsEngineDataset;
  ASSETS: Fetcher;

  // Vars (§12.1, §12.2)
  ISSUER: string;
  RP_ID: string;
  RP_NAME: string;
  BUNDLED_LOGIN_APP: string;
  LOG_LEVEL: string;
  DO_JURISDICTION: string;
  VERSION?: string;

  // Secrets (§12.2)
  MASTER_KEYS?: string;
  MASTER_KEY_ACTIVE?: string;
  ADMIN_BOOTSTRAP_TOKEN?: string;
}

/**
 * Injected clock (TIO-TEST-005). Every time comparison in the OP flows through
 * this interface; `systemClock` below is the only place `Date.now()` is allowed.
 */
export interface Clock {
  /** Seconds since the Unix epoch (TIO-DATA-004). */
  now(): number;
  /** Milliseconds since the Unix epoch, for UUID v7 timestamps. */
  nowMs(): number;
}

export const systemClock: Clock = {
  nowMs: () => Date.now(),
  now: () => Math.floor(Date.now() / 1000),
};
