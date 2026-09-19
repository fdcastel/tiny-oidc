import type { UuidV7 } from "../crypto/uuid.ts";
import type { Clock } from "../env.ts";
import type { Logger } from "../obs/log.ts";

// Audit events (spec §11.1): one record per security-relevant action, built
// per request from the request's pseudonymized metadata and handed to the
// sinks when the request ends. This phase feeds the structured log; the
// queue producer and `audit_hot` consumer arrive with §11.3 (Phase 6).

export type AuditOutcome = "success" | "failure";
export type ActorKind = "user" | "client" | "admin" | "system" | "anonymous";

export interface AuditActor {
  kind: ActorKind;
  id: string | null;
}

export interface AuditEvent {
  /** UUID v7 (TIO-DATA-002). */
  id: string;
  ts: number;
  type: string;
  outcome: AuditOutcome;
  actor: AuditActor;
  user_id: string | null;
  client_id: string | null;
  upstream: string | null;
  sid: string | null;
  interaction_id: string | null;
  ip_hash: string | null;
  country: string | null;
  ua_family: string | null;
  request_id: string;
  /** Machine-readable; never a description from an upstream. */
  reason: string | null;
  /** At most 4 KB once serialized; allow-listed keys per type (§11.2). */
  data: Record<string, unknown>;
}

/** What an emitter states; everything else comes from the request. */
export type AuditInput = Pick<AuditEvent, "type" | "outcome" | "actor"> &
  Partial<
    Pick<
      AuditEvent,
      "user_id" | "client_id" | "upstream" | "sid" | "interaction_id" | "reason" | "data"
    >
  >;

export interface RequestContext {
  request_id: string;
  ip_hash: string | null;
  country: string | null;
  ua_family: string | null;
}

export const MAX_DATA_BYTES = 4096;

/** Serialized size of `data` in bytes. */
function dataSize(data: Record<string, unknown>): number {
  return new TextEncoder().encode(JSON.stringify(data)).length;
}

/** Collects the events of one request. */
export class Auditor {
  readonly events: AuditEvent[] = [];
  private readonly context: RequestContext;
  private readonly uuids: UuidV7;
  private readonly clock: Clock;

  constructor(context: RequestContext, uuids: UuidV7, clock: Clock) {
    this.context = context;
    this.uuids = uuids;
    this.clock = clock;
  }

  emit(input: AuditInput): AuditEvent {
    const data = input.data ?? {};
    const event: AuditEvent = {
      id: this.uuids.next(),
      ts: this.clock.now(),
      type: input.type,
      outcome: input.outcome,
      actor: input.actor,
      user_id: input.user_id ?? null,
      client_id: input.client_id ?? null,
      upstream: input.upstream ?? null,
      sid: input.sid ?? null,
      interaction_id: input.interaction_id ?? null,
      ip_hash: this.context.ip_hash,
      country: this.context.country,
      ua_family: this.context.ua_family,
      request_id: this.context.request_id,
      reason: input.reason ?? null,
      // A payload past the bound is replaced, never trimmed field by field (the
      // allow-lists of §11.2 keep the normal case small).
      data: dataSize(data) <= MAX_DATA_BYTES ? data : { truncated: true },
    };
    this.events.push(event);
    return event;
  }

  /** Hands every collected event to the log sink (TIO-AUDIT-010 sink 2). */
  flush(logger: Logger): void {
    for (const event of this.events) logger.log("info", "audit", { event });
  }
}
