import type { AuditEvent } from "../audit/events.ts";
import { Auditor } from "../audit/events.ts";
import {
  AuditTaskSchema,
  hotStatementsFor,
  shipAuditEvents,
  storeAuditBatch,
} from "../audit/sink.ts";
import { KeyStore } from "../crypto/keystore.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import { Db } from "../db/db.ts";
import { buildConfig, type Clock, type Env } from "../env.ts";
import { retryBackchannel } from "../logout/backchannel.ts";
import { consoleSink, Logger, type LogSink } from "../obs/log.ts";

// The `queue()` handler (spec §4.5): every TASKS message names its `kind`.
// `audit` batches go to `audit_hot` and the R2 archive, acknowledged only
// once both are written (TIO-AUDIT-011); `backchannel_logout` retries run
// here (TIO-LOGOUT-012). A message the consumer cannot read is acknowledged
// and logged (nothing would change on redelivery); a failure of the OP's own
// infrastructure (storage, keys, configuration) retries the message.

/** Events per archive object: a queue batch's audit messages are written in groups of at most this many. */
export const ARCHIVE_GROUP_EVENTS = 1_000;
/**
 * `audit_hot` statements one invocation may send: Workers allow 1,000 D1
 * queries per invocation, and a bulk import can fill a batch with hot rows.
 * Groups beyond it are retried, to land in a later invocation.
 */
export const HOT_STATEMENTS_PER_INVOCATION = 800;

export interface QueueDeps {
  clock: Clock;
  /** ARCHIVE_GROUP_EVENTS and HOT_STATEMENTS_PER_INVOCATION, lowered by tests. */
  archiveGroupEvents?: number;
  hotStatementsPerInvocation?: number;
  sink?: LogSink;
  fetch?: typeof fetch;
}

export type QueueHandler = (
  batch: MessageBatch<unknown>,
  env: Env,
  ctx: ExecutionContext,
) => Promise<void>;

/** The `kind` of a task message, or null when it has none. */
function kindOf(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const kind = (body as { kind?: unknown }).kind;
  return typeof kind === "string" ? kind : null;
}

export function createQueue(deps: QueueDeps): QueueHandler {
  const sink = deps.sink ?? consoleSink;
  const keyStore = new KeyStore(deps.clock);
  const uuids = new UuidV7(deps.clock);
  const groupEvents = deps.archiveGroupEvents ?? ARCHIVE_GROUP_EVENTS;
  const statementBudget = deps.hotStatementsPerInvocation ?? HOT_STATEMENTS_PER_INVOCATION;
  return async (batch, env, ctx) => {
    const runId = uuids.next();
    const config = buildConfig(env);
    const logger = new Logger(sink, config.ok ? config.config.logLevel : "info");
    const base = { run_id: runId, queue: batch.queue, messages: batch.messages.length };
    if (!config.ok) {
      logger.log("error", "queue batch retried: invalid configuration", {
        ...base,
        reason: config.error,
      });
      batch.retryAll();
      return;
    }
    const db = Db.from(env.DB);
    const auditor = new Auditor(
      { request_id: runId, ip_hash: null, country: null, ua_family: null },
      uuids,
      deps.clock,
    );
    let handled = 0;
    type AuditMessage = { message: Message<unknown>; events: AuditEvent[] };
    const audit: AuditMessage[] = [];
    for (const message of batch.messages) {
      const kind = kindOf(message.body);
      if (kind === "audit") {
        const parsed = AuditTaskSchema.safeParse(message.body);
        if (!parsed.success) {
          logger.log("warn", "malformed audit batch dropped", { ...base, id: message.id });
          message.ack();
          continue;
        }
        audit.push({ message, events: parsed.data.events });
        continue;
      }
      if (kind !== "backchannel_logout") {
        logger.log("warn", "task of an unknown kind dropped", { ...base, kind, id: message.id });
        message.ack();
        continue;
      }
      try {
        const keys = await keyStore.get(db, config.config.keys);
        await retryBackchannel(
          {
            env,
            keys,
            issuer: config.config.issuerUrl,
            clock: deps.clock,
            audit: auditor,
            logger,
            ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
          },
          message.body,
        );
        message.ack();
        handled += 1;
      } catch (error) {
        logger.log("error", "task retried", { ...base, id: message.id, reason: String(error) });
        message.retry();
      }
    }
    // The audit messages, in groups of at most ARCHIVE_GROUP_EVENTS events: one D1 batch and
    // one archive object per group, its messages acknowledged only when both are written.
    const groups: AuditMessage[][] = [];
    for (const item of audit) {
      const last = groups.at(-1);
      const size = last?.reduce((n, m) => n + m.events.length, 0) ?? groupEvents;
      if (last !== undefined && size + item.events.length <= groupEvents) last.push(item);
      else groups.push([item]);
    }
    let statements = 0;
    for (const group of groups) {
      const events = group.flatMap((m) => m.events);
      statements += hotStatementsFor(events);
      if (statements > statementBudget) {
        logger.log("warn", "audit group deferred to a later invocation", {
          ...base,
          messages: group.length,
        });
        for (const m of group) m.message.retry();
        continue;
      }
      try {
        const { key, hot } = await storeAuditBatch(env, db, events, uuids.next());
        logger.log("info", "audit batch archived", {
          ...base,
          key,
          messages: group.length,
          events: events.length,
          hot,
        });
        for (const m of group) m.message.ack();
        handled += group.length;
      } catch (error) {
        logger.log("error", "audit batch retried", {
          ...base,
          messages: group.length,
          reason: String(error),
        });
        for (const m of group) m.message.retry();
      }
    }
    logger.log("info", "queue", { ...base, handled });
    auditor.flush(logger);
    if (auditor.events.length > 0) ctx.waitUntil(shipAuditEvents(env, logger, auditor.events));
  };
}
