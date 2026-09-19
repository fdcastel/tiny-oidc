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

export async function getGroupByName(db: Db, name: string): Promise<GroupRow | null> {
  const raw = await db
    .prepare(
      "SELECT id, name, description, system, created_at, updated_at FROM groups WHERE name = ?",
    )
    .bind(name)
    .first<RawGroupRow>();
  return raw === null ? null : { ...raw, system: raw.system === 1 };
}

export type GroupChange = "changed" | "not_found" | "system_group";

/** Renames a group; system groups keep their name (TIO-DATA-012). */
export async function renameGroup(
  db: Db,
  id: string,
  name: string,
  now: number,
): Promise<GroupChange> {
  const result = await db
    .prepare("UPDATE groups SET name = ?, updated_at = ? WHERE id = ? AND system = 0")
    .bind(name, now, id)
    .run();
  if (result.meta.changes === 1) return "changed";
  return (await groupExists(db, id)) ? "system_group" : "not_found";
}

/** Deletes a group and its memberships; system groups stay (TIO-DATA-012). */
export async function deleteGroup(db: Db, id: string): Promise<GroupChange> {
  const result = await db.prepare("DELETE FROM groups WHERE id = ? AND system = 0").bind(id).run();
  if (result.meta.changes === 1) return "changed";
  return (await groupExists(db, id)) ? "system_group" : "not_found";
}

async function groupExists(db: Db, id: string): Promise<boolean> {
  const row = await db.prepare("SELECT 1 AS present FROM groups WHERE id = ?").bind(id).first();
  return row !== null;
}

/** Members of a group, for the mirror's authoritative question (TIO-DATA-013). */
export async function countMembers(db: Db, groupId: string): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?")
    .bind(groupId)
    .first<{ n: number }>();
  return (row as { n: number }).n;
}

/** Statements that replace a user's memberships with `groupIds`, for one batch. */
export function replaceMembershipStatements(
  db: Db,
  userId: string,
  groupIds: string[],
  now: number,
) {
  return [
    db.prepare("DELETE FROM group_members WHERE user_id = ?").bind(userId),
    ...groupIds.map((groupId) =>
      db
        .prepare("INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)")
        .bind(groupId, userId, now),
    ),
  ];
}

export async function listGroups(db: Db): Promise<GroupRow[]> {
  const rows = await db
    .prepare(
      "SELECT id, name, description, system, created_at, updated_at FROM groups ORDER BY name",
    )
    .all<RawGroupRow>();
  return rows.results.map((row) => ({ ...row, system: row.system === 1 }));
}
