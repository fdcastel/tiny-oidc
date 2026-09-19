import { describe, expect, it } from "vitest";
import {
  CURSOR_TTL_SECONDS,
  DEFAULT_LIMIT,
  MAX_LIMIT,
  openCursor,
  page,
  parseLimit,
  sealCursor,
} from "../../src/admin/pagination.ts";
import { hmacSha256 } from "../../src/crypto/hash.ts";
import { encodeBase64Url, utf8 } from "../../src/util/base64url.ts";
import { testKeys } from "../support/keys.ts";

// Keyset cursors of the Admin API (spec §9.2, TIO-ADMIN-004).

const keys = testKeys();
const NOW = 1_800_000_000;

describe("pagination cursors", () => {
  it("[TIO-ADMIN-004] a cursor names its listing and keyset, is signed under tio/v1/cursor, expires after an hour and opens under any key version still in the secret", async () => {
    const keyset = { created_at: 1_790_000_000, id: "0192aaaa-0000-7000-8000-000000000001" };
    const cursor = await sealCursor(keys, "users", keyset, NOW);
    expect(cursor).toMatch(/^\d+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
    expect(cursor.startsWith(`${keys.active}.`)).toBe(true);
    expect(await openCursor(keys, "users", cursor, NOW)).toEqual(keyset);
    expect(await openCursor(keys, "users", cursor, NOW + CURSOR_TTL_SECONDS - 1)).toEqual(keyset);
    expect(await openCursor(keys, "users", cursor, NOW + CURSOR_TTL_SECONDS)).toBeNull();
    expect(await openCursor(keys, "clients", cursor, NOW)).toBeNull();
    // Another key set cannot verify it; a rotated set that keeps the version still can.
    const other = testKeys("1", JSON.stringify({ "1": btoa("x".repeat(32)) }));
    expect(await openCursor(other, "users", cursor, NOW)).toBeNull();
    const [version, payload, mac] = cursor.split(".") as [string, string, string];
    expect(await openCursor(keys, "users", `${version}.${payload}.${mac}x`, NOW)).toBeNull();
    expect(await openCursor(keys, "users", `abc.${payload}.${mac}`, NOW)).toBeNull();
    expect(await openCursor(keys, "users", `${version}.${payload}`, NOW)).toBeNull();
    expect(await openCursor(keys, "users", `${version}.${payload}.***`, NOW)).toBeNull();
    // A payload that verifies but is not the expected tuple is refused as well.
    const odd = encodeBase64Url(utf8(JSON.stringify({ not: "a tuple" })));
    const key = await (keys.hmacKey("cursor") as Promise<CryptoKey>);
    const tag = encodeBase64Url((await hmacSha256(key, utf8(odd))).slice(0, 16));
    expect(await openCursor(keys, "users", `${keys.active}.${odd}.${tag}`, NOW)).toBeNull();
    expect(await openCursor(keys, "users", cursor.replace(payload, ""), NOW)).toBeNull();
  });

  it("[TIO-ADMIN-004] limits default to 50, accept 1..200 and refuse everything else; a page keeps limit rows and a cursor only when a row was left over", async () => {
    expect(parseLimit(undefined)).toBe(DEFAULT_LIMIT);
    expect(parseLimit("1")).toBe(1);
    expect(parseLimit("200")).toBe(MAX_LIMIT);
    for (const bad of ["0", "201", "-1", "1.5", "1e2", "", "abc", "1000"]) {
      expect(parseLimit(bad), bad).toBeNull();
    }
    const rows = [1, 2, 3, 4];
    const keysetOf = (n: number) => ({ created_at: n, id: `r${n}` });
    const seal = async (k: { created_at: number; id: string }) => `cursor:${k.id}`;
    expect(await page(rows, 3, keysetOf, seal)).toEqual({
      items: [1, 2, 3],
      next_cursor: "cursor:r3",
    });
    expect(await page(rows.slice(0, 3), 3, keysetOf, seal)).toEqual({
      items: [1, 2, 3],
      next_cursor: null,
    });
    expect(await page([], 3, keysetOf, seal)).toEqual({ items: [], next_cursor: null });
  });
});
