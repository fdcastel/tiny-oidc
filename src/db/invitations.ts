import { z } from "zod";
import { parseJson } from "../util/json.ts";
import type { Db } from "./db.ts";

// Repository for the D1 `invitations` table (spec §4.1, §6.3): single-use
// register and recover tokens, stored as the SHA-256 of their secret
// (TIO-REG-002, TIO-CRYPTO-004).

export type InvitationKind = "register" | "recover";

export interface InvitationRow {
  id: string;
  token_hash: Uint8Array;
  kind: InvitationKind;
  user_id: string | null;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  expires_at: number;
  used_at: number | null;
  used_by_user_id: string | null;
  created_by: string;
  created_at: number;
}

interface RawInvitationRow extends Record<string, unknown> {
  id: string;
  token_hash: ArrayBuffer;
  kind: InvitationKind;
  user_id: string | null;
  email: string | null;
  email_verified: number;
  display_name: string | null;
  groups: string;
  expires_at: number;
  used_at: number | null;
  used_by_user_id: string | null;
  created_by: string;
  created_at: number;
}

const Groups = z.array(z.string());

/** Decodes a row; a corrupt groups column reads as no groups. */
function decode(raw: RawInvitationRow): InvitationRow {
  const groups = parseJson(Groups, raw.groups);
  return {
    ...raw,
    token_hash: new Uint8Array(raw.token_hash),
    email_verified: raw.email_verified === 1,
    groups: groups.ok ? groups.value : [],
  };
}

export type NewInvitationRow = Omit<InvitationRow, "used_at" | "used_by_user_id">;

export async function insertInvitation(db: Db, row: NewInvitationRow): Promise<void> {
  await db
    .prepare(
      "INSERT INTO invitations (id, token_hash, kind, user_id, email, email_verified, display_name, groups, expires_at, used_at, used_by_user_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
    )
    .bind(
      row.id,
      row.token_hash,
      row.kind,
      row.user_id,
      row.email,
      row.email_verified ? 1 : 0,
      row.display_name,
      JSON.stringify(row.groups),
      row.expires_at,
      row.created_by,
      row.created_at,
    )
    .run();
}

export async function getInvitation(db: Db, id: string): Promise<InvitationRow | null> {
  const raw = await db
    .prepare(
      "SELECT id, token_hash, kind, user_id, email, email_verified, display_name, groups, expires_at, used_at, used_by_user_id, created_by, created_at FROM invitations WHERE id = ?",
    )
    .bind(id)
    .first<RawInvitationRow>();
  return raw === null ? null : decode(raw);
}

/**
 * Consumes the invitation exactly once (TIO-REG-002): the update succeeds
 * only while it is unused and unexpired.
 */
export async function consumeInvitation(
  db: Db,
  id: string,
  usedBy: string,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE invitations SET used_at = ?, used_by_user_id = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
    )
    .bind(now, usedBy, id, now)
    .run();
  return result.meta.changes === 1;
}

export async function deleteInvitation(db: Db, id: string): Promise<boolean> {
  const result = await db.prepare("DELETE FROM invitations WHERE id = ?").bind(id).run();
  return result.meta.changes === 1;
}

export async function listInvitations(db: Db): Promise<InvitationRow[]> {
  const rows = await db
    .prepare(
      "SELECT id, token_hash, kind, user_id, email, email_verified, display_name, groups, expires_at, used_at, used_by_user_id, created_by, created_at FROM invitations ORDER BY created_at DESC, id",
    )
    .all<RawInvitationRow>();
  return rows.results.map(decode);
}

export interface InvitationFilters {
  kind?: InvitationKind;
  user_id?: string;
}

export interface InvitationKeyset {
  created_at: number;
  id: string;
}

const INVITATION_COLUMNS =
  "id, token_hash, kind, user_id, email, email_verified, display_name, groups, expires_at, used_at, used_by_user_id, created_by, created_at";

/** The keyset query behind `GET /admin/invitations`, walking `invitations_created`. */
export async function listInvitationsPage(
  db: Db,
  filters: InvitationFilters,
  after: InvitationKeyset | null,
  limit: number,
): Promise<InvitationRow[]> {
  const where: string[] = [];
  const binds: unknown[] = [];
  if (filters.kind !== undefined) {
    where.push("kind = ?");
    binds.push(filters.kind);
  }
  if (filters.user_id !== undefined) {
    where.push("user_id = ?");
    binds.push(filters.user_id);
  }
  if (after !== null) {
    where.push("(created_at, id) > (?, ?)");
    binds.push(after.created_at, after.id);
  }
  const sql = [
    "SELECT",
    INVITATION_COLUMNS,
    "FROM invitations",
    where.length === 0 ? "" : `WHERE ${where.join(" AND ")}`,
    "ORDER BY created_at, id LIMIT ?",
  ].join(" ");
  const rows = await db
    .prepare(sql)
    .bind(...binds, limit)
    .all<RawInvitationRow>();
  return rows.results.map(decode);
}

/** Removes invitations that expired before `cutoff` (TIO-CFG-010); returns how many went. */
export async function deleteExpiredInvitations(db: Db, cutoff: number): Promise<number> {
  const result = await db
    .prepare("DELETE FROM invitations WHERE expires_at < ?")
    .bind(cutoff)
    .run();
  return result.meta.changes;
}
