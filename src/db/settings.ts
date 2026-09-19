import { z } from "zod";
import { parseJson } from "../util/json.ts";
import type { Db } from "./db.ts";

// Repository for the D1 `settings` table (spec §4.1, §12.2): key → JSON value.

interface SettingsRow {
  key: string;
  value: string;
}

/** Every stored setting, JSON-decoded. A value that is not valid JSON is skipped as if unset. */
export async function readAllSettings(db: Db): Promise<Record<string, unknown>> {
  const rows = await db.prepare("SELECT key, value FROM settings").all<SettingsRow>();
  const out: Record<string, unknown> = {};
  for (const row of rows.results) {
    const parsed = parseJson(z.unknown(), row.value);
    if (parsed.ok) out[row.key] = parsed.value;
  }
  return out;
}

/** Upserts every entry in one transaction; a `null` value deletes the row (returns the key to its default). */
export async function writeSettings(
  db: Db,
  entries: Record<string, unknown>,
  actor: string,
  now: number,
): Promise<void> {
  const statements = Object.entries(entries).map(([key, value]) =>
    value === null
      ? db.prepare("DELETE FROM settings WHERE key = ?").bind(key)
      : db
          .prepare(
            "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
          )
          .bind(key, JSON.stringify(value), now, actor),
  );
  if (statements.length > 0) await db.batch(statements);
}

/**
 * Writes one entry only when no row holds the key yet, and tells whether this
 * call did: the atomic claim behind single-use steps such as the bootstrap
 * (TIO-ADMIN-010, TIO-TEST-010). A row set to its default is deleted, never
 * stored as null, so absence is the only "unset" state.
 */
export async function claimSetting(
  db: Db,
  key: string,
  value: unknown,
  actor: string,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO NOTHING",
    )
    .bind(key, JSON.stringify(value), now, actor)
    .run();
  return result.meta.changes === 1;
}

/** Liveness probe for the health endpoint (TIO-OBS-003). */
export async function pingDb(db: Db): Promise<boolean> {
  try {
    await db.prepare("SELECT 1 AS ok").first();
    return true;
  } catch {
    return false;
  }
}
