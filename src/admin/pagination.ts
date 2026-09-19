import { z } from "zod";
import { hmacSha256, secretsEqual } from "../crypto/hash.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { decodeBase64Url, encodeBase64Url, utf8 } from "../util/base64url.ts";
import { parseJson } from "../util/json.ts";

// Keyset pagination for the listing endpoints (spec §9.2, TIO-ADMIN-004):
// pages continue after `(created_at, id)` of the last item, never by offset,
// and the cursor that says where is signed under `tio/v1/cursor`, names the
// listing it belongs to and expires after an hour.

export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 200;
export const CURSOR_TTL_SECONDS = 3600;
const MAC_BYTES = 16;

export interface Keyset {
  created_at: number;
  id: string;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

const CursorPayload = z.tuple([z.string(), z.number().int(), z.string(), z.number().int()]);

async function mac(
  keys: DerivedKeys,
  version: number,
  payload: string,
): Promise<Uint8Array | null> {
  const key = keys.hmacKey("cursor", version);
  if (key === null) return null;
  return (await hmacSha256(await key, utf8(payload))).slice(0, MAC_BYTES);
}

/** `<key version>.<payload>.<mac>`; the payload is `[listing, created_at, id, expires_at]`. */
export async function sealCursor(
  keys: DerivedKeys,
  listing: string,
  keyset: Keyset,
  now: number,
): Promise<string> {
  const payload = encodeBase64Url(
    utf8(JSON.stringify([listing, keyset.created_at, keyset.id, now + CURSOR_TTL_SECONDS])),
  );
  const tag = (await mac(keys, keys.active, payload)) as Uint8Array;
  return `${keys.active}.${payload}.${encodeBase64Url(tag)}`;
}

/** The keyset a cursor names, or null for a forged, foreign, malformed or expired one. */
export async function openCursor(
  keys: DerivedKeys,
  listing: string,
  cursor: string,
  now: number,
): Promise<Keyset | null> {
  const parts = cursor.split(".");
  if (parts.length !== 3) return null;
  const [version, payload, tag] = parts as [string, string, string];
  if (!/^\d{1,3}$/.test(version)) return null;
  const presented = decodeBase64Url(tag);
  const bytes = decodeBase64Url(payload);
  if (presented === null || bytes === null) return null;
  const expected = await mac(keys, Number(version), payload);
  if (expected === null || !(await secretsEqual(presented, expected))) return null;
  const parsed = parseJson(CursorPayload, new TextDecoder().decode(bytes));
  if (!parsed.ok) return null;
  const [owner, createdAt, id, expiresAt] = parsed.value;
  if (owner !== listing || expiresAt <= now) return null;
  return { created_at: createdAt, id };
}

/** `limit` as an integer in 1..200 (default 50); null when the parameter is malformed. */
export function parseLimit(raw: string | undefined): number | null {
  if (raw === undefined) return DEFAULT_LIMIT;
  if (!/^\d{1,3}$/.test(raw)) return null;
  const limit = Number(raw);
  return limit >= 1 && limit <= MAX_LIMIT ? limit : null;
}

/**
 * Turns `limit + 1` fetched rows into a page: the extra row, if present,
 * means there is more, and the cursor names the last row returned.
 */
export async function page<T>(
  rows: T[],
  limit: number,
  keysetOf: (row: T) => Keyset,
  seal: (keyset: Keyset) => Promise<string>,
): Promise<Page<T>> {
  const items = rows.slice(0, limit);
  const last = items[items.length - 1];
  const more = rows.length > limit && last !== undefined;
  return { items, next_cursor: more ? await seal(keysetOf(last)) : null };
}
