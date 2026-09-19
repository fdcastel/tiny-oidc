import type { Db } from "./db.ts";
import type { UserStatus } from "./users.ts";

// Repository for the D1 `identity_index` (spec §4.1): which user holds an
// upstream (issuer, subject) pair. The UserDO holds the identity itself; the
// index only claims uniqueness and routes lookups (§4.6).

/** Statement claiming the pair for a user; part of the creation or linking batch. */
export function insertIdentityStatement(
  db: Db,
  issuer: string,
  subject: string,
  userId: string,
  now: number,
) {
  return db
    .prepare(
      "INSERT INTO identity_index (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(issuer, subject, userId, now);
}

export interface IdentityHolder {
  user_id: string;
  /** The holder's registry status; null when its `users` row is gone. */
  status: UserStatus | null;
}

/**
 * The user holding the pair, from the index; null when unknown. The status
 * tells a claim by a creation in flight (`creating`, §4.6 step 1) from a row
 * the object must confirm (TIO-DATA-026).
 */
export async function lookupIdentity(
  db: Db,
  issuer: string,
  subject: string,
): Promise<IdentityHolder | null> {
  return db
    .prepare(
      "SELECT identity_index.user_id AS user_id, users.status AS status FROM identity_index LEFT JOIN users ON users.id = identity_index.user_id WHERE identity_index.issuer = ? AND identity_index.subject = ?",
    )
    .bind(issuer, subject)
    .first<IdentityHolder>();
}

/** The pairs the index claims for a user (the repair of a `creating` row, §4.6). */
export async function identitiesOfUser(
  db: Db,
  userId: string,
): Promise<{ issuer: string; subject: string }[]> {
  const rows = await db
    .prepare(
      "SELECT issuer, subject FROM identity_index WHERE user_id = ? ORDER BY created_at, issuer, subject",
    )
    .bind(userId)
    .all<{ issuer: string; subject: string }>();
  return rows.results;
}

export async function releaseIdentity(db: Db, issuer: string, subject: string): Promise<void> {
  await db
    .prepare("DELETE FROM identity_index WHERE issuer = ? AND subject = ?")
    .bind(issuer, subject)
    .run();
}
