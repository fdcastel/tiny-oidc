import type { Context } from "hono";
import type { Env } from "../env.ts";
import { errorResponse } from "./errors.ts";

// Rate limits (spec §6.7, TIO-RL-001, TIO-RL-003) on the Rate Limiting
// bindings: coarse, per-colo and permissive. Each key class below is one row
// of the §6.7 table; the exact per-entity limits (attempts per interaction,
// registrations per user) live in the Durable Objects.
//
// Note: a binding carries a single limit (`RL_IP` 120 per 60 s, `RL_CLIENT`
// 2,000 per 10 s in §12.1), so every class on a binding shares that limit
// until the bindings are split per class (plan P6-05).

export type LimitClass = keyof typeof LIMIT_CLASSES;

export const LIMIT_CLASSES = {
  /** `/authorize`, `/par`, `/logout`, `/federation/callback` per IP. */
  ip_navigation: { binding: "RL_IP", prefix: "nav" },
  /** `/token`, `/revoke` per IP. */
  ip_token: { binding: "RL_IP", prefix: "tok" },
  /** `/api/v1/interactions/*` per IP. */
  ip_interactions: { binding: "RL_IP", prefix: "ix" },
  /** `/api/v1/me/*` per IP. */
  ip_me: { binding: "RL_IP", prefix: "me" },
  /** Failed client authentication at `/token`, `/par`, `/revoke` per client id (TIO-TOKEN-004). */
  client_auth_failed: { binding: "RL_CLIENT", prefix: "fail" },
  /** Successful `/token` calls per client id. */
  client_token: { binding: "RL_CLIENT", prefix: "tok" },
  /** `/api/v1/admin/*` per admin token (its `jti`). */
  admin_token: { binding: "RL_CLIENT", prefix: "adm" },
  /** Wrong bootstrap tokens per IP (TIO-ADMIN-010). */
  ip_bootstrap: { binding: "RL_IP", prefix: "boot" },
} as const satisfies Record<string, { binding: "RL_IP" | "RL_CLIENT"; prefix: string }>;

export const RETRY_AFTER_SECONDS = 10;

/** The binding key of a class and entity, so tests can exhaust it directly. */
export function limitKey(cls: LimitClass, entity: string): string {
  return `${LIMIT_CLASSES[cls].prefix}:${entity}`;
}

/** Counts one event against the class and entity; true when the limit is exceeded. */
export async function limited(env: Env, cls: LimitClass, entity: string): Promise<boolean> {
  const outcome = await env[LIMIT_CLASSES[cls].binding].limit({ key: limitKey(cls, entity) });
  return !outcome.success;
}

/**
 * The IP key of a request (TIO-RL-003): `CF-Connecting-IP`, with IPv6
 * addresses keyed by their /64 prefix. Absent header (never on Cloudflare)
 * keys everything together.
 */
export function ipKey(request: Request): string {
  const ip = request.headers.get("cf-connecting-ip") ?? "0.0.0.0";
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::") as [string, string?];
  const headParts = head.length > 0 ? head.split(":") : [];
  const tailParts = tail.length > 0 ? tail.split(":") : [];
  const zeros = Array.from(
    { length: Math.max(0, 8 - headParts.length - tailParts.length) },
    () => "0",
  );
  const groups = [...headParts, ...zeros, ...tailParts];
  return `${groups
    .slice(0, 4)
    .map((g) => g.toLowerCase().padStart(4, "0"))
    .join(":")}::/64`;
}

/** 429 with `Retry-After: 10` and `rate_limited` (TIO-RL-001). */
export function rateLimited(c: Context): Response {
  return errorResponse(c, 429, "rate_limited", "too many requests", {
    "Retry-After": String(RETRY_AFTER_SECONDS),
  });
}
