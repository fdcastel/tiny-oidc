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

// --- listing (spec §9.2, TIO-ADMIN-004) ---------------------------------------

/** Exact-match filters on indexed columns; `email` is the normalized form and matches verified emails only (TIO-DATA-007). */
export interface UserFilters {
  email_norm?: string;
  status?: UserStatus;
  group_id?: string;
  created_after?: number;
  created_before?: number;
}

export interface UserKeyset {
  created_at: number;
  id: string;
}

const USER_COLUMNS =
  "users.id, users.email, users.email_norm, users.email_verified, users.display_name, users.status, users.created_at, users.updated_at";

/**
 * The keyset query behind `GET /admin/users`: rows after `(created_at, id)`
 * in that order, `limit` of them, walking `users_created`. Rows in status
 * `creating` are invisible unless asked for by status (§3.4).
 */
export function listUsersStatement(
  db: Db,
  filters: UserFilters,
  after: UserKeyset | null,
  limit: number,
  explain = false,
) {
  const where: string[] = [];
  const binds: unknown[] = [];
  if (filters.email_norm !== undefined) {
    where.push("users.email_norm = ? AND users.email_verified = 1");
    binds.push(filters.email_norm);
  }
  if (filters.status !== undefined) {
    where.push("users.status = ?");
    binds.push(filters.status);
  } else {
    where.push("users.status <> 'creating'");
  }
  if (filters.group_id !== undefined) {
    where.push("group_members.group_id = ?");
    binds.push(filters.group_id);
  }
  if (filters.created_after !== undefined) {
    where.push("users.created_at >= ?");
    binds.push(filters.created_after);
  }
  if (filters.created_before !== undefined) {
    where.push("users.created_at <= ?");
    binds.push(filters.created_before);
  }
  if (after !== null) {
    where.push("(users.created_at, users.id) > (?, ?)");
    binds.push(after.created_at, after.id);
  }
  const join =
    filters.group_id === undefined ? "" : " JOIN group_members ON group_members.user_id = users.id";
  const sql =
    "SELECT " +
    USER_COLUMNS +
    " FROM users" +
    join +
    " WHERE " +
    where.join(" AND ") +
    " ORDER BY users.created_at, users.id LIMIT ?";
  return db.prepare((explain ? "EXPLAIN QUERY PLAN " : "") + sql).bind(...binds, limit);
}

export async function listUsers(
  db: Db,
  filters: UserFilters,
  after: UserKeyset | null,
  limit: number,
): Promise<UserRow[]> {
  const rows = await listUsersStatement(db, filters, after, limit).all<RawUserRow>();
  return rows.results.map(decode);
}

// --- mirror maintenance (§4.6) --------------------------------------------------

export interface UserMirror {
  email: string | null;
  email_norm: string | null;
  email_verified: boolean;
  display_name: string | null;
}

/** Statement rewriting the mirrored attributes of a row (profile update, reindex). */
export function updateUserMirrorStatement(db: Db, id: string, mirror: UserMirror, now: number) {
  return db
    .prepare(
      "UPDATE users SET email = ?, email_norm = ?, email_verified = ?, display_name = ?, updated_at = ? WHERE id = ?",
    )
    .bind(
      mirror.email,
      mirror.email_norm,
      mirror.email_verified ? 1 : 0,
      mirror.display_name,
      now,
      id,
    );
}

/** Removes the row; index rows, memberships and bound invitations cascade (TIO-DATA-010). */
export async function deleteUserRow(db: Db, id: string): Promise<boolean> {
  const result = await db.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  return result.meta.changes === 1;
}

/** Statements replacing a user's `passkey_index` rows with `credentialIds` (reindex). */
export function replacePasskeyIndexStatements(
  db: Db,
  userId: string,
  credentialIds: string[],
  now: number,
) {
  return [
    db.prepare("DELETE FROM passkey_index WHERE user_id = ?").bind(userId),
    ...credentialIds.map((credentialId) =>
      db
        .prepare(
          "INSERT OR REPLACE INTO passkey_index (credential_id, user_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(credentialId, userId, now),
    ),
  ];
}

/** Statements replacing a user's `identity_index` rows (reindex). */
export function replaceIdentityIndexStatements(
  db: Db,
  userId: string,
  identities: { issuer: string; subject: string }[],
  now: number,
) {
  return [
    db.prepare("DELETE FROM identity_index WHERE user_id = ?").bind(userId),
    ...identities.map((identity) =>
      db
        .prepare(
          "INSERT OR REPLACE INTO identity_index (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(identity.issuer, identity.subject, userId, now),
    ),
  ];
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
