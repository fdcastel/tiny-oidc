import { z } from "zod";
import { insertAuditStatement } from "../db/audit.ts";
import type { Db } from "../db/db.ts";
import { dateOf, type Env } from "../env.ts";
import type { Logger } from "../obs/log.ts";
import { isHotType } from "./catalog.ts";
import type { AuditEvent } from "./events.ts";

// The queue sink of audit events (spec §11.3): the producer ships each
// request's events to TASKS in batches, after the response (TIO-AUDIT-010);
// the consumer writes the events of a whole queue batch together — the hot
// ones to `audit_hot`, all of them to one R2 object — and acknowledges its
// messages only when both are done (TIO-AUDIT-011, TIO-AUDIT-013). Inserts
// ignore duplicates and every write gets a new archive key, so a redelivered
// batch adds no row and overwrites no object (TIO-DATA-025). A queue that
// refuses a batch is logged and the request is unaffected (TIO-AUDIT-012).

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

/**
 * The archive key of one write: Hive-style time segments from the first
 * event (so DuckDB prunes by `year=/month=/day=/hour=`), that event's id, and
 * `attempt`, fresh for every write (TIO-DATA-025, ADR 0022). A key is never
 * written twice: a redelivered or regrouped batch lands under a new key, the
 * archive may then hold an event twice, and readers deduplicate by `id`.
 * (A key reused for a regrouped batch would overwrite the earlier object's
 * events, and a bucket lock refuses the rewrite.)
 */
export function archiveKey(first: AuditEvent, attempt: string): string {
  const at = dateOf(first.ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `audit/year=${at.getUTCFullYear()}/month=${pad(at.getUTCMonth() + 1)}/day=${pad(at.getUTCDate())}/hour=${pad(at.getUTCHours())}/${first.id}-${attempt}.ndjson.gz`;
}

/** The key prefix of one UTC day (`YYYY-MM-DD`) in the archive. */
export function archiveDayPrefix(day: string): string {
  const [year, month, date] = day.split("-");
  return `audit/year=${year}/month=${month}/day=${date}/`;
}

/** One JSON object per line, gzip-compressed. */
export async function gzipNdjson(events: readonly AuditEvent[]): Promise<Uint8Array> {
  const text = `${events.map((e) => JSON.stringify(e)).join("\n")}\n`;
  const compressed = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(compressed).arrayBuffer());
}

/** How many `audit_hot` insert statements `events` need (TIO-AUDIT-013: hot types only). */
export function hotStatementsFor(events: readonly AuditEvent[]): number {
  return Math.ceil(events.filter((e) => isHotType(e.type)).length / AUDIT_ROWS_PER_STATEMENT);
}

/**
 * Writes one group of events: the hot ones to `audit_hot` (≤ 9 rows per
 * statement, one D1 batch; none when the group has no hot event) and all of
 * them to R2 as one object under a key unique to this write.
 */
export async function storeAuditBatch(
  env: Env,
  db: Db,
  events: readonly AuditEvent[],
  attempt: string,
): Promise<{ key: string; hot: number }> {
  const hot = events.filter((e) => isHotType(e.type));
  const statements = [];
  for (let start = 0; start < hot.length; start += AUDIT_ROWS_PER_STATEMENT) {
    statements.push(insertAuditStatement(db, hot.slice(start, start + AUDIT_ROWS_PER_STATEMENT)));
  }
  if (statements.length > 0) await db.batch(statements);
  const key = archiveKey(events[0] as AuditEvent, attempt);
  await env.AUDIT_BUCKET.put(key, await gzipNdjson(events), {
    httpMetadata: { contentType: "application/x-ndjson", contentEncoding: "gzip" },
  });
  return { key, hot: hot.length };
}
