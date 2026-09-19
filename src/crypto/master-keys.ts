import { z } from "zod";
import { utf8 } from "../util/base64url.ts";
import { parseJson } from "../util/json.ts";

// Master keys and derived keys (spec §10.2). `MASTER_KEYS` is JSON
// `{ "<version>": "<base64 32 bytes>", ... }` and `MASTER_KEY_ACTIVE` names the
// version used for new encryptions. Every derived key is HKDF-SHA256 with an
// empty salt and a fixed `info` string, cached per isolate (TIO-CRYPTO-020).

export type KeyPurpose = "envelope" | "keystore" | "iphash" | "cursor";

const INFO: Record<KeyPurpose, string> = {
  envelope: "tio/v1/envelope",
  keystore: "tio/v1/keystore",
  iphash: "tio/v1/iphash",
  cursor: "tio/v1/cursor",
};

export interface MasterKeySet {
  active: number;
  versions: ReadonlyMap<number, Uint8Array>;
}

export type MasterKeyParse = { ok: true; keys: MasterKeySet } | { ok: false; error: string };

const VERSION = /^(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/;

function decodeBase64(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Validates the two secrets (TIO-CRYPTO-010): each value decodes to 32 bytes and the active version exists. */
export function parseMasterKeys(
  masterKeys: string | undefined,
  active: string | undefined,
): MasterKeyParse {
  if (masterKeys === undefined) return { ok: false, error: "MASTER_KEYS is not set" };
  if (active === undefined) return { ok: false, error: "MASTER_KEY_ACTIVE is not set" };
  const raw = parseJson(z.record(z.string(), z.unknown()), masterKeys);
  if (!raw.ok) return { ok: false, error: "MASTER_KEYS must be a JSON object" };
  const versions = new Map<number, Uint8Array>();
  for (const [version, value] of Object.entries(raw.value)) {
    if (!VERSION.test(version))
      return {
        ok: false,
        error: `MASTER_KEYS version "${version}" must be an integer from 1 to 255`,
      };
    const bytes = typeof value === "string" ? decodeBase64(value) : null;
    if (bytes?.length !== 32)
      return {
        ok: false,
        error: `MASTER_KEYS version "${version}" must be base64 of exactly 32 bytes`,
      };
    versions.set(Number(version), bytes);
  }
  if (versions.size === 0) return { ok: false, error: "MASTER_KEYS has no versions" };
  if (!VERSION.test(active) || !versions.has(Number(active)))
    return { ok: false, error: `MASTER_KEY_ACTIVE "${active}" is not a version in MASTER_KEYS` };
  return { ok: true, keys: { active: Number(active), versions } };
}

/** Derived keys per version and purpose, imported non-extractable and cached. */
export class DerivedKeys {
  readonly active: number;
  private readonly set: MasterKeySet;
  private readonly cache = new Map<string, Promise<CryptoKey>>();

  constructor(set: MasterKeySet) {
    this.set = set;
    this.active = set.active;
  }

  hasVersion(version: number): boolean {
    return this.set.versions.has(version);
  }

  /** AES-256-GCM key for envelopes or the key store; null for a version that is not in the secret (TIO-ARCH-008). */
  aesKey(
    purpose: "envelope" | "keystore",
    version: number = this.active,
  ): Promise<CryptoKey> | null {
    return this.derive(purpose, version, { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]);
  }

  /** HMAC-SHA256 key for IP pseudonymization or pagination cursors. */
  hmacKey(purpose: "iphash" | "cursor", version: number = this.active): Promise<CryptoKey> | null {
    return this.derive(purpose, version, { name: "HMAC", hash: "SHA-256" }, ["sign", "verify"]);
  }

  private derive(
    purpose: KeyPurpose,
    version: number,
    algorithm: SubtleCryptoImportKeyAlgorithm,
    usages: string[],
  ): Promise<CryptoKey> | null {
    const ikm = this.set.versions.get(version);
    if (!ikm) return null;
    const id = `${purpose}:${version}`;
    let key = this.cache.get(id);
    if (!key) {
      key = crypto.subtle
        .importKey("raw", ikm, "HKDF", false, ["deriveKey"])
        .then((base) =>
          crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(INFO[purpose]) },
            base,
            algorithm,
            false,
            usages,
          ),
        );
      this.cache.set(id, key);
    }
    return key;
  }
}
