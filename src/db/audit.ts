import { z } from "zod";
import type { AuditEvent } from "../audit/events.ts";
import { parseJson } from "../util/json.ts";
import type { Db, Statement } from "./db.ts";

// Repository for the D1 `audit_hot` table (spec §11.3): the hot window of
// audit events, written by the queue consumer (`INSERT OR IGNORE`, so a
// redelivered batch is harmless, TIO-DATA-025) and purged in bounded batches
// by the cron (TIO-CFG-010).

export const PURGE_BATCH_ROWS = 1_000;

const COLUMNS =
  "id, ts, type, outcome, actor_kind, actor_id, user_id, client_id, upstream, ip_hash, data, sid, interaction_id, country, ua_family, request_id, reason";

/** One INSERT OR IGNORE for up to a few events (the caller keeps it under D1's parameter bound). */
export function insertAuditStatement(db: Db, events: readonly AuditEvent[]): Statement {
  const row = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = events.flatMap((e) => [
    e.id,
    e.ts,
    e.type,
    e.outcome,
    e.actor.kind,
    e.actor.id,
    e.user_id,
    e.client_id,
    e.upstream,
    e.ip_hash,
    JSON.stringify(e.data),
    e.sid,
    e.interaction_id,
    e.country,
    e.ua_family,
    e.request_id,
    e.reason,
  ]);
  return db
    .prepare(
      // Placeholders only; every value is bound (TIO-DATA-015).
      [
        "INSERT OR IGNORE INTO audit_hot (",
        COLUMNS,
        ") VALUES ",
        events.map(() => row).join(", "),
      ].join(""),
    )
    .bind(...values);
}

/** Deletes at most `limit` events older than `cutoff`; returns how many went. */
export async function purgeAuditBatch(db: Db, cutoff: number, limit: number): Promise<number> {
  const result = await db
    .prepare("DELETE FROM audit_hot WHERE id IN (SELECT id FROM audit_hot WHERE ts < ? LIMIT ?)")
    .bind(cutoff, limit)
    .run();
  return result.meta.changes;
}

export interface AuditFilters {
  type?: string;
  user_id?: string;
  client_id?: string;
  actor_id?: string;
  outcome?: "success" | "failure";
  /** Inclusive bounds on `ts`. */
  since?: number;
  until?: number;
}

export interface AuditKeyset {
  ts: number;
  id: string;
}

interface AuditRow extends Record<string, unknown> {
  id: string;
  ts: number;
  type: string;
  outcome: "success" | "failure";
  actor_kind: AuditEvent["actor"]["kind"];
  actor_id: string | null;
  user_id: string | null;
  client_id: string | null;
  upstream: string | null;
  ip_hash: string | null;
  data: string;
  sid: string | null;
  interaction_id: string | null;
  country: string | null;
  ua_family: string | null;
  request_id: string;
  reason: string | null;
}

const DataSchema = z.record(z.string(), z.unknown());

/** A row back as the §11.1 event; unreadable `data` becomes an empty object. */
function rowToEvent(row: AuditRow): AuditEvent {
  const parsed = parseJson(DataSchema, row.data);
  const data = parsed.ok ? parsed.value : {};
  return {
    id: row.id,
    ts: row.ts,
    type: row.type,
    outcome: row.outcome,
    actor: { kind: row.actor_kind, id: row.actor_id },
    user_id: row.user_id,
    client_id: row.client_id,
    upstream: row.upstream,
    sid: row.sid,
    interaction_id: row.interaction_id,
    ip_hash: row.ip_hash,
    country: row.country,
    ua_family: row.ua_family,
    request_id: row.request_id,
    reason: row.reason,
    data,
  };
}

/**
 * Newest first, keyset on (ts, id): the rows strictly before `after`, at most
 * `limit`, under the filters of §9.4.
 */
export async function listAuditPage(
  db: Db,
  filters: AuditFilters,
  after: AuditKeyset | null,
  limit: number,
): Promise<AuditEvent[]> {
  const clauses: string[] = [];
  const binds: unknown[] = [];
  const equal = (column: string, value: string | undefined) => {
    if (value === undefined) return;
    clauses.push(`${column} = ?`);
    binds.push(value);
  };
  equal("type", filters.type);
  equal("user_id", filters.user_id);
  equal("client_id", filters.client_id);
  equal("actor_id", filters.actor_id);
  equal("outcome", filters.outcome);
  if (filters.since !== undefined) {
    clauses.push("ts >= ?");
    binds.push(filters.since);
  }
  if (filters.until !== undefined) {
    clauses.push("ts <= ?");
    binds.push(filters.until);
  }
  if (after !== null) {
    clauses.push("(ts < ? OR (ts = ? AND id < ?))");
    binds.push(after.ts, after.ts, after.id);
  }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await db
    .prepare(
      ["SELECT", COLUMNS, "FROM audit_hot", where, "ORDER BY ts DESC, id DESC LIMIT ?"].join(" "),
    )
    .bind(...binds, limit)
    .all<AuditRow>();
  return rows.results.map(rowToEvent);
}

export async function countAuditRows(db: Db): Promise<number> {
  const row = await db.prepare("SELECT COUNT(*) AS n FROM audit_hot").first<{ n: number }>();
  return (row as { n: number }).n;
}
