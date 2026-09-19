import { z } from "zod";
import { insertAuditStatement } from "../db/audit.ts";
import type { Db } from "../db/db.ts";
import { dateOf, type Env } from "../env.ts";
import type { Logger } from "../obs/log.ts";
import type { AuditEvent } from "./events.ts";

// The queue sink of audit events (spec §11.3): the producer ships each
// request's events to TASKS in batches, after the response (TIO-AUDIT-010);
// the consumer writes every batch to `audit_hot` and to the R2 archive and
// acknowledges only when both are done (TIO-AUDIT-011). Inserts ignore
// duplicates and the object key follows from the first event, so a
// redelivered batch changes nothing (TIO-DATA-025). A queue that refuses a
// batch is logged and the request is unaffected (TIO-AUDIT-012).

/** Events per queue message (§4.5). */
export const AUDIT_BATCH_SIZE = 50;
/** Rows per INSERT statement inside a D1 batch: at most 9 (TIO-AUDIT-011), and 17 columns × 5 stays under D1's 100 bound variables. */
export const AUDIT_ROWS_PER_STATEMENT = 5;

const ActorSchema = z.object({
  kind: z.enum(["user", "client", "admin", "system", "anonymous"]),
  id: z.string().nullable(),
});

export const AuditEventSchema = z.object({
  id: z.string().min(1),
  ts: z.int(),
  type: z.string().min(1),
  outcome: z.enum(["success", "failure"]),
  actor: ActorSchema,
  user_id: z.string().nullable(),
  client_id: z.string().nullable(),
  upstream: z.string().nullable(),
  sid: z.string().nullable(),
  interaction_id: z.string().nullable(),
  ip_hash: z.string().nullable(),
  country: z.string().nullable(),
  ua_family: z.string().nullable(),
  request_id: z.string(),
  reason: z.string().nullable(),
  data: z.record(z.string(), z.unknown()),
});

export const AuditTaskSchema = z.object({
  kind: z.literal("audit"),
  events: z.array(AuditEventSchema).min(1).max(AUDIT_BATCH_SIZE),
});

export type AuditTask = z.infer<typeof AuditTaskSchema>;

/** Ships `events` to the queue in batches; failures are logged, never thrown (TIO-AUDIT-012). */
export async function shipAuditEvents(
  env: Env,
  logger: Logger,
  events: readonly AuditEvent[],
): Promise<void> {
  for (let start = 0; start < events.length; start += AUDIT_BATCH_SIZE) {
    const batch = events.slice(start, start + AUDIT_BATCH_SIZE);
    try {
      await env.TASKS.send({ kind: "audit", events: batch } satisfies AuditTask);
    } catch (error) {
      logger.log("error", "audit batch could not be queued", {
        events: batch.length,
        first_event_id: batch[0]?.id,
        reason: String(error),
      });
    }
  }
}

/** The archive key of a batch: the hour of its first event and that event's id (TIO-DATA-025). */
export function archiveKey(first: AuditEvent): string {
  const at = dateOf(first.ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `audit/${at.getUTCFullYear()}/${pad(at.getUTCMonth() + 1)}/${pad(at.getUTCDate())}/${pad(at.getUTCHours())}/${first.id}.ndjson.gz`;
}

/** One JSON object per line, gzip-compressed. */
export async function gzipNdjson(events: readonly AuditEvent[]): Promise<Uint8Array> {
  const text = `${events.map((e) => JSON.stringify(e)).join("\n")}\n`;
  const compressed = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(compressed).arrayBuffer());
}

/** Writes a batch to `audit_hot` (≤ 9 rows per statement, one D1 batch) and to R2. */
export async function storeAuditBatch(
  env: Env,
  db: Db,
  events: readonly AuditEvent[],
): Promise<{ key: string }> {
  const statements = [];
  for (let start = 0; start < events.length; start += AUDIT_ROWS_PER_STATEMENT) {
    statements.push(
      insertAuditStatement(db, events.slice(start, start + AUDIT_ROWS_PER_STATEMENT)),
    );
  }
  await db.batch(statements);
  const key = archiveKey(events[0] as AuditEvent);
  await env.AUDIT_BUCKET.put(key, await gzipNdjson(events), {
    httpMetadata: { contentType: "application/x-ndjson", contentEncoding: "gzip" },
  });
  return { key };
}
