// The bounded diff an admin mutation records (TIO-ADMIN-002): which fields
// changed and how, never a secret (TIO-ADMIN-003, TIO-AUDIT-002), never
// more than a screenful.

/** Fields whose values never reach an audit record; only the fact that they changed does. */
export const SECRET_FIELDS: ReadonlySet<string> = new Set([
  "client_secret",
  "client_secret_hash",
  "client_secret_enc",
  "private_jwk",
  "jwks",
  "jwks_enc",
  "secret",
  "secret_hash",
  "public_key",
  "token",
  "token_hash",
]);

export const MAX_DIFF_FIELDS = 32;
export const MAX_DIFF_VALUE_CHARS = 256;

export type FieldChange = { from: unknown; to: unknown } | { changed: true };

type Record_ = Record<string, unknown>;

/** A value as the record shows it: JSON-comparable and no longer than a short line. */
function bounded(value: unknown): unknown {
  if (value === undefined) return null;
  const text = JSON.stringify(value);
  if (text.length <= MAX_DIFF_VALUE_CHARS) return value;
  return `${text.slice(0, MAX_DIFF_VALUE_CHARS)}…`;
}

/**
 * The fields that differ between two records (`null` for "absent": a creation
 * or a deletion), in key order, capped at MAX_DIFF_FIELDS entries.
 */
export function boundedDiff(
  before: Record_ | null,
  after: Record_ | null,
): Record<string, FieldChange> {
  const keys = [...new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])].sort();
  const diff: Record<string, FieldChange> = {};
  let count = 0;
  for (const key of keys) {
    const from = before?.[key];
    const to = after?.[key];
    if (JSON.stringify(from ?? null) === JSON.stringify(to ?? null)) continue;
    if (count === MAX_DIFF_FIELDS) {
      diff["…"] = { changed: true };
      break;
    }
    diff[key] = SECRET_FIELDS.has(key)
      ? { changed: true }
      : { from: bounded(from), to: bounded(to) };
    count++;
  }
  return diff;
}
