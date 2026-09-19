import type { Db } from "./db.ts";

// Repository for the D1 `groups` table (spec §3.5, §4.1): flat groups, of
// which `admins` is system-defined (TIO-DATA-012).

export interface GroupRow {
  id: string;
  name: string;
  description: string | null;
  system: boolean;
  created_at: number;
  updated_at: number;
}

interface RawGroupRow extends Record<string, unknown> {
  id: string;
  name: string;
  description: string | null;
  system: number;
  created_at: number;
  updated_at: number;
}

export type InsertGroupResult = "created" | "group_exists";

export async function insertGroup(
  db: Db,
  group: Pick<GroupRow, "id" | "name" | "description" | "system">,
  now: number,
): Promise<InsertGroupResult> {
  const result = await db
    .prepare(
      "INSERT OR IGNORE INTO groups (id, name, description, system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(group.id, group.name, group.description, group.system ? 1 : 0, now, now)
    .run();
  return result.meta.changes === 1 ? "created" : "group_exists";
}

export async function listGroups(db: Db): Promise<GroupRow[]> {
  const rows = await db
    .prepare(
      "SELECT id, name, description, system, created_at, updated_at FROM groups ORDER BY name",
    )
    .all<RawGroupRow>();
  return rows.results.map((row) => ({ ...row, system: row.system === 1 }));
}
