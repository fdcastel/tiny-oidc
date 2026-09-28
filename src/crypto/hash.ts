import { concatBytes, utf8 } from "../util/base64url.ts";

// Hashing and secret comparison over Web Crypto (spec §10.1).

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/**
 * Constant-time equality for secrets, hashes and MACs (TIO-CRYPTO-003):
 * `crypto.subtle.timingSafeEqual` on equal-length inputs; a length mismatch
 * returns false only after hashing both inputs to fixed length, so the time
 * taken does not reveal which case occurred.
 */
export async function secretsEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  if (a.length !== b.length) {
    await sha256(a);
    await sha256(b);
    return false;
  }
  return crypto.subtle.timingSafeEqual(a, b);
}

/** `secretsEqual` over text: a stored base64url hash against one just computed. */
export async function hashesEqual(a: string, b: string): Promise<boolean> {
  return secretsEqual(utf8(a), utf8(b));
}

/**
 * The synchronous form, for a Durable Object's `transactionSync`, which cannot
 * await a digest. Only for values whose length is public (a SHA-256 digest, a
 * client's own `code_challenge`), so a length mismatch returns false at once.
 */
export function publicLengthEqual(a: string, b: string): boolean {
  const x = utf8(a);
  const y = utf8(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

export async function hmacSha256(key: CryptoKey, ...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, concatBytes(...parts)));
}
