import { calculateJwkThumbprint, importJWK, type JWK } from "jose";
import { z } from "zod";
import type { Db } from "../db/db.ts";
import {
  deleteRetiredSigningKeys,
  insertFirstSigningKey,
  insertSigningKey,
  listSigningKeys,
  retireSigningKey,
  type SigningKeyRow,
  updatePrivateJwkEnc,
} from "../db/keys.ts";
import type { Clock } from "../env.ts";
import { utf8 } from "../util/base64url.ts";
import { parseJson } from "../util/json.ts";
import { Refresher } from "../util/swr.ts";
import type { DerivedKeys } from "./master-keys.ts";
import { openSecret, sealedUnderVersion, sealSecret } from "./secretbox.ts";

// Signing-key store (spec §10.3): ES256 keys generated in the Worker, private
// JWKs encrypted under the keystore key in D1, imported non-extractable at
// runtime. A key's role is derived from `activates_at`, `retired_at` and the
// clock; there is no status column to drift.

export const KEY_ALG = "ES256";
/** Retired rows are deleted this long after `retired_at` (§4.7). */
export const RETIRED_KEY_RETENTION_SECONDS = 90 * 86_400;
/** Isolate cache of the loaded keys; a retired key stops verifying within this window (TIO-ARCH-011). */
export const KEYS_TTL_SECONDS = 60;
export const KEYS_STALE_SECONDS = 3_600;

export type KeyRole = "signing" | "next" | "verifying" | "retired";

const PublicJwkSchema = z.object({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  x: z.string(),
  y: z.string(),
});

const PrivateJwkSchema = PublicJwkSchema.extend({ d: z.string() });

type PublicJwk = z.infer<typeof PublicJwkSchema>;

/** The JWK as published in the JWKS: exactly kid, kty, crv, alg, use, x, y (TIO-KEYS-001). */
export function publishedJwk(kid: string, jwk: PublicJwk): JWK {
  return { kid, kty: jwk.kty, crv: jwk.crv, alg: KEY_ALG, use: "sig", x: jwk.x, y: jwk.y };
}

export interface GeneratedKey {
  kid: string;
  publicJwk: PublicJwk;
  privateJwk: z.infer<typeof PrivateJwkSchema>;
}

/** Generates an ES256 key pair; extractable only for this export step (TIO-KEYS-011); kid is the RFC 7638 thumbprint (TIO-KEYS-014). */
export async function generateSigningKey(): Promise<GeneratedKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const exportedPrivate = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const privateJwk = PrivateJwkSchema.parse(exportedPrivate);
  const publicJwk: PublicJwk = { kty: "EC", crv: "P-256", x: privateJwk.x, y: privateJwk.y };
  const kid = await calculateJwkThumbprint(publicJwk, "sha256");
  return { kid, publicJwk, privateJwk };
}

/** Role of a row at `now`, given the signing key's activation instant (§10.3). */
export function roleOf(
  row: SigningKeyRow,
  now: number,
  signingActivatesAt: number | null,
): KeyRole {
  if (row.retired_at !== null) return "retired";
  if (row.activates_at > now) return "next";
  if (signingActivatesAt !== null && row.activates_at < signingActivatesAt) return "verifying";
  return "signing";
}

export interface KeyRoles {
  signing: SigningKeyRow | null;
  next: SigningKeyRow[];
  verifying: SigningKeyRow[];
  retired: SigningKeyRow[];
}

/** Splits the rows by role: the signing key is the unretired key with the greatest `activates_at ≤ now` (ties: the newest row, then the greater kid). */
export function deriveRoles(rows: readonly SigningKeyRow[], now: number): KeyRoles {
  const unretired = rows.filter((r) => r.retired_at === null);
  const active = unretired.filter((r) => r.activates_at <= now);
  const signing = active.reduce<SigningKeyRow | null>(
    (best, r) =>
      best === null ||
      r.activates_at > best.activates_at ||
      (r.activates_at === best.activates_at &&
        (r.created_at > best.created_at || (r.created_at === best.created_at && r.kid > best.kid)))
        ? r
        : best,
    null,
  );
  const roles: KeyRoles = { signing, next: [], verifying: [], retired: [] };
  for (const row of rows) {
    const role = roleOf(row, now, signing?.activates_at ?? null);
    if (role === "next") roles.next.push(row);
    else if (role === "verifying") roles.verifying.push(row);
    else if (role === "retired") roles.retired.push(row);
  }
  return roles;
}

export class NoSigningKeyError extends Error {
  constructor() {
    super("no active signing key");
    this.name = "NoSigningKeyError";
  }
}

export class KeysUnavailableError extends Error {
  constructor(cause: unknown) {
    super("signing keys unavailable", { cause });
    this.name = "KeysUnavailableError";
  }
}

/** The keys an isolate signs and verifies with. */
/** The role of every row by kid (the Admin API's key listing and stats). */
export function rolesByKid(rows: readonly SigningKeyRow[], now: number): Map<string, KeyRole> {
  const signingAt = deriveRoles(rows, now).signing?.activates_at ?? null;
  return new Map(rows.map((row) => [row.kid, roleOf(row, now, signingAt)]));
}

export interface LoadedKeys {
  signing: { kid: string; privateKey: CryptoKey };
  /** Every unretired key (signing, next and verifying), for JWKS and verification. */
  jwks: { keys: JWK[] };
  /** The `activates_at` of the signing key, reported by health and the Admin API. */
  rows: SigningKeyRow[];
}

async function insertGenerated(
  db: Db,
  keys: DerivedKeys,
  activatesAt: number,
  now: number,
  first: boolean,
): Promise<string | null> {
  const generated = await generateSigningKey();
  const row = {
    kid: generated.kid,
    public_jwk: JSON.stringify(generated.publicJwk),
    private_jwk_enc: await sealSecret(keys, utf8(JSON.stringify(generated.privateJwk))),
    created_at: now,
    activates_at: activatesAt,
  };
  if (first) return (await insertFirstSigningKey(db, row)) ? generated.kid : null;
  await insertSigningKey(db, row);
  return generated.kid;
}

/**
 * Rotation only creates (TIO-KEYS-012): a key that activates after
 * `prepublishSeconds`, or immediately in an emergency. Returns its kid.
 */
export async function rotateSigningKey(
  db: Db,
  keys: DerivedKeys,
  now: number,
  prepublishSeconds: number,
  immediate: boolean,
): Promise<string> {
  return (await insertGenerated(
    db,
    keys,
    immediate ? now : now + prepublishSeconds,
    now,
    false,
  )) as string;
}

export type RetireResult = "retired" | "not_found" | "last_active_key";

/** Emergency retirement (TIO-KEYS-013): refused for the only unretired key that has activated. */
export async function retireSigningKeyNow(db: Db, kid: string, now: number): Promise<RetireResult> {
  const rows = await listSigningKeys(db);
  const target = rows.find((r) => r.kid === kid && r.retired_at === null);
  if (!target) return "not_found";
  const activeOthers = rows.filter(
    (r) => r.kid !== kid && r.retired_at === null && r.activates_at <= now,
  );
  if (target.activates_at <= now && activeOthers.length === 0) return "last_active_key";
  await retireSigningKey(db, kid, now);
  return "retired";
}

export interface MaintenanceResult {
  created: string | null;
  retired: string[];
  deleted: number;
  deleted_kids: string[];
}

export interface KeyMaintenanceSettings {
  "keys.rotation_days": number;
  "keys.prepublish_seconds": number;
  "keys.retire_after_seconds": number;
}

/**
 * The cron steps of §10.3 (TIO-KEYS-012): create the next key when rotation is
 * due and no `next` key exists; retire every key older than the signing key
 * once the signing key has signed for `retire_after_seconds`; delete retired
 * rows after 90 days. Each step is idempotent.
 */
export async function maintainSigningKeys(
  db: Db,
  keys: DerivedKeys,
  now: number,
  settings: KeyMaintenanceSettings,
): Promise<MaintenanceResult> {
  const roles = deriveRoles(await listSigningKeys(db), now);
  const result: MaintenanceResult = { created: null, retired: [], deleted: 0, deleted_kids: [] };
  const rotationSeconds = settings["keys.rotation_days"] * 86_400;
  if (
    roles.signing &&
    rotationSeconds > 0 &&
    now - roles.signing.activates_at >= rotationSeconds &&
    roles.next.length === 0
  ) {
    result.created = await rotateSigningKey(
      db,
      keys,
      now,
      settings["keys.prepublish_seconds"],
      false,
    );
  }
  if (roles.signing && now - roles.signing.activates_at >= settings["keys.retire_after_seconds"]) {
    for (const row of roles.verifying) {
      await retireSigningKey(db, row.kid, now);
      result.retired.push(row.kid);
    }
  }
  result.deleted_kids = await deleteRetiredSigningKeys(db, now - RETIRED_KEY_RETENTION_SECONDS);
  result.deleted = result.deleted_kids.length;
  return result;
}

/**
 * Re-encrypts every unretired private JWK sealed under a version other than
 * the active one (TIO-CRYPTO-011), at most `limit` rows per call. Rows sealed
 * under a version that is no longer in MASTER_KEYS are unrecoverable and are
 * reported, not touched.
 */
export async function rekeySigningKeys(
  db: Db,
  keys: DerivedKeys,
  limit: number,
): Promise<{ rekeyed: string[]; unrecoverable: string[]; remaining: number }> {
  const rows = (await listSigningKeys(db)).filter(
    (r) => r.private_jwk_enc !== null && sealedUnderVersion(r.private_jwk_enc) !== keys.active,
  );
  const rekeyed: string[] = [];
  const unrecoverable: string[] = [];
  for (const row of rows.slice(0, limit)) {
    const plaintext = await openSecret(keys, row.private_jwk_enc as Uint8Array);
    if (!plaintext) {
      unrecoverable.push(row.kid);
      continue;
    }
    await updatePrivateJwkEnc(db, row.kid, await sealSecret(keys, plaintext));
    rekeyed.push(row.kid);
  }
  return { rekeyed, unrecoverable, remaining: Math.max(0, rows.length - limit) };
}

/**
 * Per-isolate cache of the loaded keys: refreshed every 60 s, served stale for
 * at most one hour when D1 fails (TIO-ARCH-012), and bootstrapping the first
 * key on an empty store (TIO-KEYS-010).
 */
export class KeyStore {
  private cached: { loaded: LoadedKeys; at: number } | undefined;
  /** The blocking load in progress, shared by every request that finds no usable value (§2.8). */
  private loading: Promise<LoadedKeys> | undefined;
  private readonly clock: Clock;
  /** The early refresh (§2.8): the request path never waits for D1 while the keys are under the TTL. */
  readonly refresher = new Refresher();

  constructor(clock: Clock) {
    this.clock = clock;
  }

  async get(db: Db, keys: DerivedKeys): Promise<LoadedKeys> {
    const now = this.clock.now();
    const cached = this.cached;
    if (cached) {
      const verdict = Refresher.verdict(now - cached.at, KEYS_TTL_SECONDS);
      if (verdict !== "expired") {
        if (verdict === "early") this.refresher.start(() => this.refresh(db, keys, now));
        return cached.loaded;
      }
    }
    try {
      const shared = this.loading !== undefined;
      this.loading ??= this.loadNow(db, keys, now).finally(() => {
        this.loading = undefined;
      });
      if (shared) db.countSharedRead();
      return await this.loading;
    } catch (error) {
      if (error instanceof NoSigningKeyError || error instanceof KeysUnavailableError) throw error;
      if (cached && now - cached.at < KEYS_STALE_SECONDS) return cached.loaded;
      throw new KeysUnavailableError(error);
    }
  }

  /** The blocking path: the rows, then the loaded keys, cached as of `now`. */
  private async loadNow(db: Db, keys: DerivedKeys, now: number): Promise<LoadedKeys> {
    const rows = await this.rows(db, keys, now);
    const loaded = await this.load(rows, keys, now);
    this.cached = { loaded, at: now };
    return loaded;
  }

  /** The unretired rows, creating the first key on an empty store (guarded against concurrent isolates). */
  private async rows(db: Db, keys: DerivedKeys, now: number): Promise<SigningKeyRow[]> {
    let rows = await listSigningKeys(db);
    if (!rows.some((r) => r.retired_at === null)) {
      await insertGenerated(db, keys, now, now, true);
      rows = await listSigningKeys(db);
    }
    return rows;
  }

  private async refresh(db: Db, keys: DerivedKeys, now: number): Promise<void> {
    const loaded = await this.load(await this.rows(db, keys, now), keys, now);
    this.cached = { loaded, at: now };
  }

  private async load(rows: SigningKeyRow[], keys: DerivedKeys, now: number): Promise<LoadedKeys> {
    const roles = deriveRoles(rows, now);
    // Never sign with a `next` key: fail closed when no key has activated (TIO-KEYS-010).
    if (!roles.signing || roles.signing.private_jwk_enc === null) throw new NoSigningKeyError();
    const plaintext = await openSecret(keys, roles.signing.private_jwk_enc);
    const parsed = plaintext
      ? parseJson(PrivateJwkSchema, new TextDecoder().decode(plaintext))
      : null;
    if (!parsed?.ok) throw new KeysUnavailableError("signing key cannot be decrypted");
    const privateKey = (await importJWK(parsed.value, KEY_ALG, {
      extractable: false,
    })) as CryptoKey;
    const published: JWK[] = [];
    for (const row of rows) {
      if (row.retired_at !== null) continue;
      const jwk = parseJson(PublicJwkSchema, row.public_jwk);
      if (jwk.ok) published.push(publishedJwk(row.kid, jwk.value));
    }
    return { signing: { kid: roles.signing.kid, privateKey }, jwks: { keys: published }, rows };
  }

  invalidate(): void {
    this.cached = undefined;
  }
}
