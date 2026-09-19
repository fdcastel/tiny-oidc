import type { Db } from "./db.ts";

// Repository for the D1 `users` registry and the `passkey_index` (spec §4.1).
// `users` records existence and mirrors a few attributes for lookups; the
// UserDO is the source of truth for content (§2.3).

export type UserStatus = "creating" | "active" | "disabled" | "deleting";

export interface UserRow {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: boolean;
  display_name: string | null;
  status: UserStatus;
  created_at: number;
  updated_at: number;
}

interface RawUserRow extends Record<string, unknown> {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: number;
  display_name: string | null;
  status: UserStatus;
  created_at: number;
  updated_at: number;
}

function decode(raw: RawUserRow): UserRow {
  return { ...raw, email_verified: raw.email_verified === 1 };
}

export interface NewUserRow {
  id: string;
  email: string | null;
  email_norm: string | null;
  email_verified: boolean;
  display_name: string | null;
}

/** Statement claiming the row in status `creating` (§4.6 step 1); part of a batch with the group claims. */
export function insertUserStatement(db: Db, user: NewUserRow, now: number) {
  return db
    .prepare(
      "INSERT INTO users (id, email, email_norm, email_verified, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'creating', ?, ?)",
    )
    .bind(
      user.id,
      user.email,
      user.email_norm,
      user.email_verified ? 1 : 0,
      user.display_name,
      now,
      now,
    );
}

export async function setUserStatus(
  db: Db,
  id: string,
  status: UserStatus,
  now: number,
): Promise<void> {
  await db
    .prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?")
    .bind(status, now, id)
    .run();
}

export async function getUser(db: Db, id: string): Promise<UserRow | null> {
  const raw = await db
    .prepare(
      "SELECT id, email, email_norm, email_verified, display_name, status, created_at, updated_at FROM users WHERE id = ?",
    )
    .bind(id)
    .first<RawUserRow>();
  return raw === null ? null : decode(raw);
}

/** The active or disabled user holding this email as verified (TIO-DATA-007), if any. */
export async function findVerifiedUser(db: Db, emailNorm: string): Promise<UserRow | null> {
  const raw = await db
    .prepare(
      "SELECT id, email, email_norm, email_verified, display_name, status, created_at, updated_at FROM users WHERE email_norm = ? AND email_verified = 1 AND status IN ('active', 'disabled')",
    )
    .bind(emailNorm)
    .first<RawUserRow>();
  return raw === null ? null : decode(raw);
}

/** Statements claiming group memberships for a new user; `groupIds` were resolved by name beforehand. */
export function insertMembershipStatements(
  db: Db,
  userId: string,
  groupIds: string[],
  now: number,
) {
  return groupIds.map((groupId) =>
    db
      .prepare("INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)")
      .bind(groupId, userId, now),
  );
}

/** Every group id by name; groups are flat and few (TIO-DATA-011). */
export async function groupIdsByName(db: Db): Promise<Map<string, string>> {
  const rows = await db.prepare("SELECT id, name FROM groups").all<{ id: string; name: string }>();
  return new Map(rows.results.map((row) => [row.name, row.id]));
}

// --- passkey_index ----------------------------------------------------------

/** The user holding a credential id, from the index; null when unknown. */
export async function lookupCredential(db: Db, credentialId: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT user_id FROM passkey_index WHERE credential_id = ?")
    .bind(credentialId)
    .first<{ user_id: string }>();
  return row?.user_id ?? null;
}

/** Claims a credential id for a user; false when it is already indexed (TIO-PK-012). */
export async function claimCredential(
  db: Db,
  credentialId: string,
  userId: string,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "INSERT OR IGNORE INTO passkey_index (credential_id, user_id, created_at) VALUES (?, ?, ?)",
    )
    .bind(credentialId, userId, now)
    .run();
  return result.meta.changes === 1;
}

export async function releaseCredential(db: Db, credentialId: string): Promise<void> {
  await db.prepare("DELETE FROM passkey_index WHERE credential_id = ?").bind(credentialId).run();
}
