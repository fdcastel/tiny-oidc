import { Auditor } from "../audit/events.ts";
import { AuditTaskSchema, shipAuditEvents, storeAuditBatch } from "../audit/sink.ts";
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

export interface QueueDeps {
  clock: Clock;
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
    for (const message of batch.messages) {
      const kind = kindOf(message.body);
      if (kind === "audit") {
        const parsed = AuditTaskSchema.safeParse(message.body);
        if (!parsed.success) {
          logger.log("warn", "malformed audit batch dropped", { ...base, id: message.id });
          message.ack();
          continue;
        }
        try {
          const { key } = await storeAuditBatch(env, db, parsed.data.events);
          logger.log("info", "audit batch archived", {
            ...base,
            key,
            events: parsed.data.events.length,
          });
          message.ack();
          handled += 1;
        } catch (error) {
          logger.log("error", "audit batch retried", {
            ...base,
            id: message.id,
            reason: String(error),
          });
          message.retry();
        }
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
    logger.log("info", "queue", { ...base, handled });
    auditor.flush(logger);
    if (auditor.events.length > 0) ctx.waitUntil(shipAuditEvents(env, logger, auditor.events));
  };
}
