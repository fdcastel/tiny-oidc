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

export async function hmacSha256(key: CryptoKey, ...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, concatBytes(...parts)));
}
