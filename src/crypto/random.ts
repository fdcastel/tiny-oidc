import { encodeBase64Url } from "../util/base64url.ts";

// Every random value comes from the runtime CSPRNG (TIO-CRYPTO-002).

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A handle or credential secret: 32 random bytes, ≥ 256 bits of entropy (TIO-CRYPTO-004). */
export function newSecret(): Uint8Array {
  return randomBytes(32);
}

/** Interaction ids: 32 random bytes, base64url, 43 characters (TIO-DATA-002). */
export function newInteractionId(): string {
  return encodeBase64Url(randomBytes(32));
}
