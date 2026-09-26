import type { Context } from "hono";
import { boundedDiff, PERSONAL_FIELDS } from "../audit/diff.ts";
import type { AuditEvent, AuditOutcome } from "../audit/events.ts";
import type { AppEnv } from "../router/context.ts";
import type { AdminActor } from "./auth.ts";

// The audit record of an admin mutation (TIO-ADMIN-002): the acting
// administrator, the target and a bounded, secret-free diff; a user record's
// diff names the personal fields that changed without their values
// (TIO-PRIV-002, ADR 0020).

export interface AdminMutation {
  type: string;
  outcome?: AuditOutcome;
  /** What was acted on, as an id or name. */
  target: string;
  user_id?: string | null;
  client_id?: string | null;
  upstream?: string | null;
  sid?: string | null;
  reason?: string | null;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  /** Allow-listed extra fields for the event type (§11.2). */
  data?: Record<string, unknown>;
}

export function auditAdmin(c: Context<AppEnv>, mutation: AdminMutation): AuditEvent {
  const actor = c.get("admin") as AdminActor;
  const data: Record<string, unknown> = { target: mutation.target, ...mutation.data };
  if (mutation.before !== undefined || mutation.after !== undefined) {
    const masked = mutation.type.startsWith("user.") ? PERSONAL_FIELDS : undefined;
    data["diff"] = boundedDiff(mutation.before ?? null, mutation.after ?? null, masked);
  }
  return c.get("audit").emit({
    type: mutation.type,
    outcome: mutation.outcome ?? "success",
    actor: { kind: "admin", id: actor.id },
    user_id: mutation.user_id ?? null,
    client_id: mutation.client_id ?? null,
    upstream: mutation.upstream ?? null,
    sid: mutation.sid ?? null,
    reason: mutation.reason ?? null,
    data,
  });
}
