import type { Db } from "./db.ts";

// Repository for the D1 `audit_hot` table (spec §11.3): the hot window of
// audit events. Writing arrives with the queue consumer (§11.3); retention is
// enforced here in bounded batches (TIO-CFG-010).

export const PURGE_BATCH_ROWS = 1_000;

/** Deletes at most `limit` events older than `cutoff`; returns how many went. */
export async function purgeAuditBatch(db: Db, cutoff: number, limit: number): Promise<number> {
  const result = await db
    .prepare("DELETE FROM audit_hot WHERE id IN (SELECT id FROM audit_hot WHERE ts < ? LIMIT ?)")
    .bind(cutoff, limit)
    .run();
  return result.meta.changes;
}

export async function countAuditRows(db: Db): Promise<number> {
  const row = await db.prepare("SELECT COUNT(*) AS n FROM audit_hot").first<{ n: number }>();
  return (row as { n: number }).n;
}
