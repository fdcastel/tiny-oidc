import type { Db } from "./db.ts";

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

/** The user holding the pair, from the index; null when unknown. */
export async function lookupIdentity(
  db: Db,
  issuer: string,
  subject: string,
): Promise<string | null> {
  const row = await db
    .prepare("SELECT user_id FROM identity_index WHERE issuer = ? AND subject = ?")
    .bind(issuer, subject)
    .first<{ user_id: string }>();
  return row?.user_id ?? null;
}

export async function releaseIdentity(db: Db, issuer: string, subject: string): Promise<void> {
  await db
    .prepare("DELETE FROM identity_index WHERE issuer = ? AND subject = ?")
    .bind(issuer, subject)
    .run();
}
