import { concatBytes, decodeBase64Url, encodeBase64Url } from "../util/base64url.ts";
import type { DerivedKeys } from "./master-keys.ts";
import { randomBytes } from "./random.ts";

// Opaque handles (spec §2.4):
//   handle     = prefix "_" base64url( version(1) || keyver(1) || type(1) || nonce(12) || ciphertext || tag(16) )
//   ciphertext = AES-256-GCM( key = HKDF(MASTER_KEYS[keyver], "tio/v1/envelope"),
//                             aad = version || keyver || type, plaintext = fields )
// Garbage is rejected before any storage lookup (TIO-ARCH-006); decryption tries
// only the key version named in the handle (TIO-ARCH-008).

const ENVELOPE_VERSION = 1;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 3;

type FieldLayout = readonly (readonly [name: string, length: number])[];

interface HandleSpec {
  prefix: string;
  type: number;
  fields: FieldLayout;
}

/** One entry per handle type of §2.4, with the fixed-width plaintext layout. */
export const HANDLE_TYPES = {
  session: {
    prefix: "tio_ss",
    type: 0x01,
    fields: [
      ["uid", 16],
      ["sid", 16],
      ["secret", 32],
    ],
  },
  code: {
    prefix: "tio_ac",
    type: 0x02,
    fields: [
      ["uid", 16],
      ["secret", 32],
    ],
  },
  refresh: {
    prefix: "tio_rt",
    type: 0x03,
    fields: [
      ["uid", 16],
      ["family", 16],
      ["secret", 32],
    ],
  },
  interaction: {
    prefix: "tio_ix",
    type: 0x04,
    fields: [
      ["ixid", 32],
      ["secret", 32],
    ],
  },
  federation: {
    prefix: "tio_fs",
    type: 0x05,
    fields: [
      ["ixid", 32],
      ["secret", 32],
    ],
  },
  invitation: {
    prefix: "tio_iv",
    type: 0x06,
    fields: [
      ["invid", 16],
      ["secret", 32],
    ],
  },
} as const satisfies Record<string, HandleSpec>;

export type HandleType = keyof typeof HANDLE_TYPES;

type FieldNames<T extends HandleType> = (typeof HANDLE_TYPES)[T]["fields"][number][0];
export type HandleFields<T extends HandleType> = Record<FieldNames<T>, Uint8Array>;

function layout(spec: HandleSpec): number {
  return spec.fields.reduce((n, [, length]) => n + length, 0);
}

/** Encrypts the fields of a handle under the active master-key version. */
export async function sealHandle<T extends HandleType>(
  keys: DerivedKeys,
  type: T,
  fields: HandleFields<T>,
): Promise<string> {
  const spec: HandleSpec = HANDLE_TYPES[type];
  const plaintext = new Uint8Array(layout(spec));
  let offset = 0;
  for (const [name, length] of spec.fields) {
    const value = (fields as Record<string, Uint8Array>)[name] as Uint8Array;
    if (value.length !== length)
      throw new RangeError(`handle field ${name} must be ${length} bytes`);
    plaintext.set(value, offset);
    offset += length;
  }
  const header = new Uint8Array([ENVELOPE_VERSION, keys.active, spec.type]);
  const nonce = randomBytes(NONCE_LENGTH);
  const key = await (keys.aesKey("envelope") as Promise<CryptoKey>);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_LENGTH * 8 },
      key,
      plaintext,
    ),
  );
  return `${spec.prefix}_${encodeBase64Url(concatBytes(header, nonce, sealed))}`;
}

/** Decrypts a handle of the expected type; any structural or cryptographic failure yields null. */
export async function openHandle<T extends HandleType>(
  keys: DerivedKeys,
  type: T,
  handle: string,
): Promise<HandleFields<T> | null> {
  const spec: HandleSpec = HANDLE_TYPES[type];
  const prefix = `${spec.prefix}_`;
  if (!handle.startsWith(prefix)) return null;
  const bytes = decodeBase64Url(handle.slice(prefix.length));
  const plaintextLength = layout(spec);
  if (!bytes || bytes.length !== HEADER_LENGTH + NONCE_LENGTH + plaintextLength + TAG_LENGTH)
    return null;
  const header = bytes.subarray(0, HEADER_LENGTH);
  if (header[0] !== ENVELOPE_VERSION || header[2] !== spec.type) return null;
  const keyPromise = keys.aesKey("envelope", header[1] as number);
  if (!keyPromise) return null;
  const nonce = bytes.subarray(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_LENGTH * 8 },
        await keyPromise,
        bytes.subarray(HEADER_LENGTH + NONCE_LENGTH),
      ),
    );
  } catch {
    return null;
  }
  const fields: Record<string, Uint8Array> = {};
  let offset = 0;
  for (const [name, length] of spec.fields) {
    fields[name] = plaintext.slice(offset, offset + length);
    offset += length;
  }
  return fields as HandleFields<T>;
}

/** The type of a handle from its prefix, without decrypting; null when no prefix matches. */
export function handleType(handle: string): HandleType | null {
  for (const [type, spec] of Object.entries(HANDLE_TYPES)) {
    if (handle.startsWith(`${spec.prefix}_`)) return type as HandleType;
  }
  return null;
}
