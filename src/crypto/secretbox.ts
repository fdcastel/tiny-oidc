import { concatBytes } from "../util/base64url.ts";
import type { DerivedKeys } from "./master-keys.ts";
import { randomBytes } from "./random.ts";

// Encryption of secrets at rest in D1 (private signing JWKs, upstream client
// secrets and JWKs) under the `tio/v1/keystore` derived key (spec §10.2):
//   blob = format(1) || keyver(1) || nonce(12) || AES-256-GCM(plaintext, aad = format || keyver)
// The key version travels with the blob so master-key rotation can re-encrypt
// row by row (TIO-CRYPTO-011).

const FORMAT = 1;
const NONCE_LENGTH = 12;
const HEADER_LENGTH = 2;
const TAG_LENGTH = 16;

export async function sealSecret(keys: DerivedKeys, plaintext: Uint8Array): Promise<Uint8Array> {
  const header = new Uint8Array([FORMAT, keys.active]);
  const nonce = randomBytes(NONCE_LENGTH);
  const key = await (keys.aesKey("keystore") as Promise<CryptoKey>);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_LENGTH * 8 },
      key,
      plaintext,
    ),
  );
  return concatBytes(header, nonce, sealed);
}

/** The master-key version a blob was sealed under, or null for a malformed blob. */
export function sealedUnderVersion(blob: Uint8Array): number | null {
  if (blob.length < HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH || blob[0] !== FORMAT) return null;
  return blob[1] as number;
}

/** Decrypts a blob; null when it is malformed, tampered, or sealed under a version no longer in MASTER_KEYS (TIO-ARCH-008). */
export async function openSecret(keys: DerivedKeys, blob: Uint8Array): Promise<Uint8Array | null> {
  const version = sealedUnderVersion(blob);
  if (version === null) return null;
  const keyPromise = keys.aesKey("keystore", version);
  if (!keyPromise) return null;
  const header = blob.subarray(0, HEADER_LENGTH);
  const nonce = blob.subarray(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_LENGTH * 8 },
        await keyPromise,
        blob.subarray(HEADER_LENGTH + NONCE_LENGTH),
      ),
    );
  } catch {
    return null;
  }
}
