import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { decodeBase64Url, encodeBase64Url, utf8 } from "../../src/util/base64url.ts";

// Software WebAuthn authenticator on Web Crypto (TIO-TEST-030): produces
// registration responses (`fmt: "none"`) and assertions for arbitrary origins,
// RP IDs, flags, counters and challenges, with fault injection for the
// negative cases of spec §13.7. It is itself verified with
// @simplewebauthn/server in test/unit/virtual-authenticator.test.ts.

export type CoseAlgorithm = -8 | -7 | -257;

// Web Crypto types spelled through the global, so this file compiles under
// both the Workers and the Node type sets (the e2e suite reuses it).
type Key = Parameters<typeof crypto.subtle.sign>[1];
type KeyPair = { privateKey: Key; publicKey: Key };
/** Algorithm dictionaries, loosely typed so that both type sets accept the same literals. */
type GenerateAlgorithm = { name: string } & Record<string, unknown>;
type SignAlgorithm = { name: string } & Record<string, unknown>;
type Jwk = { x?: string; y?: string; n?: string; e?: string };

export interface AuthenticatorFaults {
  /** Override the origin written into clientDataJSON. */
  origin?: string;
  /** Override the RP ID whose hash goes into authenticator data. */
  rpId?: string;
  /** Override the challenge written into clientDataJSON. */
  challenge?: string;
  /** Override the clientDataJSON `type`. */
  type?: string;
  userPresent?: boolean;
  userVerified?: boolean;
  backupEligible?: boolean;
  backedUp?: boolean;
  /** Signature counter to report. */
  counter?: number;
  /** `credProps.rk` extension output; omitted when undefined. */
  residentKey?: boolean;
  /** Flip a bit of the signature (of the assertion, or of a packed self-attestation). */
  corruptSignature?: boolean;
  /** Length of the generated credential id in bytes (default 32). */
  credentialIdLength?: number;
  /** Omit the userHandle from the assertion. */
  omitUserHandle?: boolean;
  /** Use a different key than the credential's when signing. */
  foreignKey?: boolean;
  /** Attestation format to declare; `packed` carries a self-attestation signed by the credential key. */
  fmt?: string;
}

interface Credential {
  id: Uint8Array;
  algorithm: CoseAlgorithm;
  privateKey: Key;
  publicKey: Key;
  rpId: string;
  userHandle: Uint8Array;
  counter: number;
}

// ---------------------------------------------------------------------------
// Minimal CBOR encoder: what attestation objects and COSE keys need.
// ---------------------------------------------------------------------------

type CborValue = number | string | Uint8Array | CborValue[] | Map<number | string, CborValue>;

function cborHead(major: number, value: number): Uint8Array {
  if (value < 24) return new Uint8Array([(major << 5) | value]);
  if (value < 0x100) return new Uint8Array([(major << 5) | 24, value]);
  if (value < 0x10000) return new Uint8Array([(major << 5) | 25, value >> 8, value & 0xff]);
  return new Uint8Array([
    (major << 5) | 26,
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function cborEncode(value: CborValue): Uint8Array {
  if (typeof value === "number") {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = utf8(value);
    return concat([cborHead(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return concat([cborHead(2, value.length), value]);
  if (Array.isArray(value)) return concat([cborHead(4, value.length), ...value.map(cborEncode)]);
  const entries = [...value.entries()];
  return concat([
    cborHead(5, entries.length),
    ...entries.flatMap(([k, v]) => [cborEncode(k), cborEncode(v)]),
  ]);
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

const KEY_PARAMS: Record<CoseAlgorithm, { gen: GenerateAlgorithm; sign: SignAlgorithm }> = {
  "-7": { gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
  "-8": { gen: { name: "Ed25519" }, sign: { name: "Ed25519" } },
  "-257": {
    gen: {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    sign: { name: "RSASSA-PKCS1-v1_5" },
  },
};

async function generate(algorithm: CoseAlgorithm): Promise<KeyPair> {
  return (await crypto.subtle.generateKey(
    KEY_PARAMS[algorithm].gen as Parameters<typeof crypto.subtle.generateKey>[0],
    true,
    ["sign", "verify"],
  )) as KeyPair;
}

async function coseKey(publicKey: Key, algorithm: CoseAlgorithm): Promise<Uint8Array> {
  const jwk = (await crypto.subtle.exportKey("jwk", publicKey)) as Jwk;
  const b64 = (s: string | undefined) => decodeBase64Url(s ?? "") as Uint8Array;
  const map = new Map<number, CborValue>();
  if (algorithm === -7) {
    map.set(1, 2).set(3, -7).set(-1, 1).set(-2, b64(jwk.x)).set(-3, b64(jwk.y));
  } else if (algorithm === -8) {
    map.set(1, 1).set(3, -8).set(-1, 6).set(-2, b64(jwk.x));
  } else {
    map.set(1, 3).set(3, -257).set(-1, b64(jwk.n)).set(-2, b64(jwk.e));
  }
  return cborEncode(map);
}

/** WebAuthn ES256 signatures are ASN.1 DER; Web Crypto produces raw r || s. */
function ecdsaToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const integer = (bytes: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let body: Uint8Array = new Uint8Array(bytes.slice(start));
    if ((body[0] as number) & 0x80) body = concat([new Uint8Array([0]), body]);
    return concat([new Uint8Array([0x02, body.length]), body]);
  };
  const r = integer(raw.slice(0, half));
  const s = integer(raw.slice(half));
  return concat([new Uint8Array([0x30, r.length + s.length]), r, s]);
}

async function sign(key: Key, algorithm: CoseAlgorithm, data: Uint8Array): Promise<Uint8Array> {
  const raw = new Uint8Array(
    await crypto.subtle.sign(
      KEY_PARAMS[algorithm].sign as Parameters<typeof crypto.subtle.sign>[0],
      key,
      data,
    ),
  );
  return algorithm === -7 ? ecdsaToDer(raw) : raw;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function flags(faults: AuthenticatorFaults, attested: boolean): number {
  let byte = 0;
  if (faults.userPresent ?? true) byte |= 0x01;
  if (faults.userVerified ?? true) byte |= 0x04;
  if (faults.backupEligible ?? true) byte |= 0x08;
  if (faults.backedUp ?? true) byte |= 0x10;
  if (attested) byte |= 0x40;
  return byte;
}

function counterBytes(counter: number): Uint8Array {
  return new Uint8Array([
    (counter >>> 24) & 0xff,
    (counter >>> 16) & 0xff,
    (counter >>> 8) & 0xff,
    counter & 0xff,
  ]);
}

// ---------------------------------------------------------------------------
// The authenticator
// ---------------------------------------------------------------------------

export class VirtualAuthenticator {
  readonly algorithm: CoseAlgorithm;
  private readonly store = new Map<string, Credential>();
  /** The AAGUID reported in attested credential data. */
  readonly aaguid = new Uint8Array(16);

  constructor(algorithm: CoseAlgorithm = -7) {
    this.algorithm = algorithm;
  }

  /** Credential ids this authenticator holds, in creation order. */
  credentials(): string[] {
    return [...this.store.keys()];
  }

  /** Signature counter of a credential (mutable, so tests can rewind it). */
  counter(credentialId: string): number {
    return (this.store.get(credentialId) as Credential).counter;
  }

  setCounter(credentialId: string, counter: number): void {
    (this.store.get(credentialId) as Credential).counter = counter;
  }

  /** Runs a registration ceremony for the options, at `origin`, with optional faults. */
  async register(
    options: PublicKeyCredentialCreationOptionsJSON,
    origin: string,
    faults: AuthenticatorFaults = {},
  ): Promise<RegistrationResponseJSON> {
    const pair = await generate(this.algorithm);
    const id = crypto.getRandomValues(new Uint8Array(faults.credentialIdLength ?? 32));
    const rpId = faults.rpId ?? options.rp.id ?? new URL(origin).hostname;
    const credential: Credential = {
      id,
      algorithm: this.algorithm,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      rpId,
      userHandle: decodeBase64Url(options.user.id) as Uint8Array,
      counter: faults.counter ?? 0,
    };
    const clientData = utf8(
      JSON.stringify({
        type: faults.type ?? "webauthn.create",
        challenge: faults.challenge ?? options.challenge,
        origin: faults.origin ?? origin,
        crossOrigin: false,
      }),
    );
    const publicKey = await coseKey(pair.publicKey, this.algorithm);
    const authData = concat([
      await sha256(utf8(rpId)),
      new Uint8Array([flags(faults, true)]),
      counterBytes(credential.counter),
      this.aaguid,
      new Uint8Array([id.length >> 8, id.length & 0xff]),
      id,
      publicKey,
    ]);
    const fmt = faults.fmt ?? "none";
    const attStmt = new Map<string, CborValue>();
    if (fmt === "packed") {
      const sig = await sign(
        pair.privateKey,
        this.algorithm,
        concat([authData, await sha256(clientData)]),
      );
      if (faults.corruptSignature) sig[sig.length - 1] = (sig[sig.length - 1] as number) ^ 0x01;
      attStmt.set("alg", this.algorithm).set("sig", sig);
    }
    const attestation = new Map<string, CborValue>();
    attestation.set("fmt", fmt);
    attestation.set("attStmt", attStmt);
    attestation.set("authData", authData);
    const encodedId = encodeBase64Url(id);
    this.store.set(encodedId, credential);
    const extensions: Record<string, unknown> = {};
    if (faults.residentKey !== undefined) extensions["credProps"] = { rk: faults.residentKey };
    return {
      id: encodedId,
      rawId: encodedId,
      type: "public-key",
      response: {
        clientDataJSON: encodeBase64Url(clientData),
        attestationObject: encodeBase64Url(cborEncode(attestation)),
        transports: ["internal"],
      },
      clientExtensionResults: extensions,
      authenticatorAttachment: "platform",
    };
  }

  /** Runs an authentication ceremony with the given credential (default: the newest). */
  async authenticate(
    options: PublicKeyCredentialRequestOptionsJSON,
    origin: string,
    faults: AuthenticatorFaults = {},
    credentialId?: string,
  ): Promise<AuthenticationResponseJSON> {
    const id = credentialId ?? this.credentials().at(-1);
    const credential = id === undefined ? undefined : this.store.get(id);
    if (!credential || id === undefined) throw new Error("no credential");
    if (faults.counter === undefined) credential.counter += 1;
    else credential.counter = faults.counter;
    const rpId = faults.rpId ?? options.rpId ?? credential.rpId;
    const clientData = utf8(
      JSON.stringify({
        type: faults.type ?? "webauthn.get",
        challenge: faults.challenge ?? options.challenge,
        origin: faults.origin ?? origin,
        crossOrigin: false,
      }),
    );
    const authData = concat([
      await sha256(utf8(rpId)),
      new Uint8Array([flags(faults, false)]),
      counterBytes(credential.counter),
    ]);
    const signingKey = faults.foreignKey
      ? (await generate(this.algorithm)).privateKey
      : credential.privateKey;
    const signature = await sign(
      signingKey,
      this.algorithm,
      concat([authData, await sha256(clientData)]),
    );
    if (faults.corruptSignature)
      signature[signature.length - 1] = (signature[signature.length - 1] as number) ^ 0x01;
    const response: AuthenticationResponseJSON["response"] = {
      clientDataJSON: encodeBase64Url(clientData),
      authenticatorData: encodeBase64Url(authData),
      signature: encodeBase64Url(signature),
    };
    if (!faults.omitUserHandle) response.userHandle = encodeBase64Url(credential.userHandle);
    return {
      id,
      rawId: id,
      type: "public-key",
      response,
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }
}
