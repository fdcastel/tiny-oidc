import type { Db } from "./db.ts";

// Repository for the D1 `signing_keys` table (spec §4.1, §10.3). Keys carry no
// status column: roles are derived from `activates_at` and `retired_at`.

export interface SigningKeyRow {
  kid: string;
  alg: "ES256";
  public_jwk: string;
  private_jwk_enc: Uint8Array | null;
  created_at: number;
  activates_at: number;
  retired_at: number | null;
}

interface RawRow {
  kid: string;
  alg: "ES256";
  public_jwk: string;
  private_jwk_enc: ArrayBuffer | null;
  created_at: number;
  activates_at: number;
  retired_at: number | null;
}

function toRow(raw: RawRow): SigningKeyRow {
  return {
    ...raw,
    private_jwk_enc: raw.private_jwk_enc === null ? null : new Uint8Array(raw.private_jwk_enc),
  };
}

export interface NewSigningKey {
  kid: string;
  public_jwk: string;
  private_jwk_enc: Uint8Array;
  created_at: number;
  activates_at: number;
}

/** Every key, retired ones included, oldest activation first. */
export async function listSigningKeys(db: Db): Promise<SigningKeyRow[]> {
  const rows = await db
    .prepare(
      "SELECT kid, alg, public_jwk, private_jwk_enc, created_at, activates_at, retired_at FROM signing_keys ORDER BY activates_at ASC, kid ASC",
    )
    .all<RawRow>();
  return rows.results.map(toRow);
}

export async function insertSigningKey(db: Db, key: NewSigningKey): Promise<void> {
  await db
    .prepare(
      "INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk_enc, created_at, activates_at, retired_at) VALUES (?, 'ES256', ?, ?, ?, ?, NULL)",
    )
    .bind(key.kid, key.public_jwk, key.private_jwk_enc, key.created_at, key.activates_at)
    .run();
}

/**
 * Inserts the first key only while no unretired key exists, in one statement,
 * so concurrent isolates create at most one (TIO-KEYS-010). Returns whether
 * this call inserted it.
 */
export async function insertFirstSigningKey(db: Db, key: NewSigningKey): Promise<boolean> {
  const result = await db
    .prepare(
      "INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk_enc, created_at, activates_at, retired_at) SELECT ?, 'ES256', ?, ?, ?, ?, NULL WHERE NOT EXISTS (SELECT 1 FROM signing_keys WHERE retired_at IS NULL)",
    )
    .bind(key.kid, key.public_jwk, key.private_jwk_enc, key.created_at, key.activates_at)
    .run();
  return result.meta.changes === 1;
}

/** Retires a key: sets `retired_at` and deletes the private material (TIO-KEYS-012). */
export async function retireSigningKey(db: Db, kid: string, now: number): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE signing_keys SET retired_at = ?, private_jwk_enc = NULL WHERE kid = ? AND retired_at IS NULL",
    )
    .bind(now, kid)
    .run();
  return result.meta.changes === 1;
}

/** Deletes retired rows whose `retired_at` is before `cutoff` (§4.7: 90 days). */
export async function deleteRetiredSigningKeys(db: Db, cutoff: number): Promise<number> {
  const result = await db
    .prepare("DELETE FROM signing_keys WHERE retired_at IS NOT NULL AND retired_at < ?")
    .bind(cutoff)
    .run();
  return result.meta.changes;
}

/** Replaces the encrypted private JWK (master-key rotation, TIO-CRYPTO-011). */
export async function updatePrivateJwkEnc(db: Db, kid: string, enc: Uint8Array): Promise<void> {
  await db
    .prepare("UPDATE signing_keys SET private_jwk_enc = ? WHERE kid = ? AND retired_at IS NULL")
    .bind(enc, kid)
    .run();
}
