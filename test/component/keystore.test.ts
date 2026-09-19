import { calculateJwkThumbprint, decodeProtectedHeader, type JWK } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { signJwt, verifyOwnJwt } from "../../src/crypto/jwt.ts";
import {
  deriveRoles,
  KEYS_STALE_SECONDS,
  KEYS_TTL_SECONDS,
  KeyStore,
  KeysUnavailableError,
  maintainSigningKeys,
  NoSigningKeyError,
  RETIRED_KEY_RETENTION_SECONDS,
  rekeySigningKeys,
  retireSigningKeyNow,
  rolesByKid,
  rotateSigningKey,
} from "../../src/crypto/keystore.ts";
import { openSecret, sealedUnderVersion, sealSecret } from "../../src/crypto/secretbox.ts";
import { Db } from "../../src/db/db.ts";
import { listSigningKeys } from "../../src/db/keys.ts";
import { utf8 } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { keysWithoutVersion2, testKeys } from "../support/keys.ts";
import { env } from "../support/op.ts";
import { resetStorage } from "../support/reset.ts";

const ISSUER = "https://auth.example.com";
const SETTINGS = {
  "keys.rotation_days": 90,
  "keys.prepublish_seconds": 86_400,
  "keys.retire_after_seconds": 604_800,
};
const DAY = 86_400;

const brokenD1 = (): D1Database =>
  ({
    prepare() {
      throw new Error("D1 down");
    },
    batch() {
      throw new Error("D1 down");
    },
    withSession() {
      return this;
    },
  }) as unknown as D1Database;

describe("key store", () => {
  beforeEach(resetStorage);

  it("[TIO-KEYS-010] the first request on an empty store creates exactly one key, even when two isolates race", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const [a, b] = await Promise.all([
      new KeyStore(clock).get(db, keys),
      new KeyStore(clock).get(db, keys),
    ]);
    const rows = await listSigningKeys(db);
    expect(rows).toHaveLength(1);
    expect(a.signing.kid).toBe(rows[0]?.kid);
    expect(b.signing.kid).toBe(rows[0]?.kid);
    expect(rows[0]).toMatchObject({ alg: "ES256", activates_at: clock.now(), retired_at: null });
  });

  it("[TIO-KEYS-010] fails closed when no unretired key has activated, rather than signing with a next key", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    await rotateSigningKey(db, keys, clock.now(), 3_600, false);
    await expect(new KeyStore(clock).get(db, keys)).rejects.toBeInstanceOf(NoSigningKeyError);
    clock.advance(3_600);
    expect((await new KeyStore(clock).get(db, keys)).signing.kid).toBeTruthy();
  });

  it("[TIO-KEYS-011] private keys are stored encrypted and imported non-extractable", async () => {
    const db = Db.from(env.DB);
    const keys = testKeys();
    const loaded = await new KeyStore(new FakeClock()).get(db, keys);
    expect(loaded.signing.privateKey.extractable).toBe(false);
    expect(loaded.signing.privateKey.type).toBe("private");
    const row = (await listSigningKeys(db))[0];
    const stored = new TextDecoder().decode(row?.private_jwk_enc as Uint8Array);
    expect(stored).not.toContain('"d"');
    expect(row?.public_jwk).not.toContain('"d"');
    const plaintext = await openSecret(keys, row?.private_jwk_enc as Uint8Array);
    expect(new TextDecoder().decode(plaintext as Uint8Array)).toContain('"d":');
    // A store whose master key cannot open the blob fails closed.
    const wrongKeys = testKeys(
      "1",
      JSON.stringify({ "1": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" }),
    );
    await expect(new KeyStore(new FakeClock()).get(db, wrongKeys)).rejects.toBeInstanceOf(
      KeysUnavailableError,
    );
  });

  it("[TIO-KEYS-014] kid is the RFC 7638 thumbprint of the published JWK, which any consumer can recompute", async () => {
    const loaded = await new KeyStore(new FakeClock()).get(Db.from(env.DB), testKeys());
    const jwk = loaded.jwks.keys[0] as JWK;
    expect(jwk.kid).toBe(loaded.signing.kid);
    const { kid: _kid, alg: _alg, use: _use, ...canonical } = jwk;
    expect(await calculateJwkThumbprint(canonical, "sha256")).toBe(loaded.signing.kid);
    expect(loaded.signing.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("[TIO-KEYS-001] the published JWK set carries exactly kid, kty, crv, alg, use, x, y for every unretired key and never d", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const store = new KeyStore(clock);
    await store.get(db, keys);
    await rotateSigningKey(db, keys, clock.now(), DAY, false);
    store.invalidate();
    const loaded = await store.get(db, keys);
    expect(loaded.jwks.keys).toHaveLength(2);
    for (const jwk of loaded.jwks.keys) {
      expect(Object.keys(jwk).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x", "y"]);
      expect(jwk).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
    }
  });

  it("[TIO-KEYS-012] [TIO-KEYS-013] three keys live through pre-publication, signing, verifying, retirement and deletion on the injected clock", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const store = new KeyStore(clock);
    const fresh = async () => {
      store.invalidate();
      return store.get(db, keys);
    };
    const t0 = clock.now();
    const k1 = (await fresh()).signing.kid;
    const tokenByK1 = await signJwt(await fresh(), "JWT", {
      iss: ISSUER,
      sub: "u",
      aud: "c",
      iat: t0,
      exp: t0 + 600,
    });

    // Rotation creates a next key that is published but does not sign.
    const k2 = await rotateSigningKey(db, keys, clock.now(), DAY, false);
    let loaded = await fresh();
    expect(loaded.signing.kid).toBe(k1);
    expect(loaded.jwks.keys.map((k) => k.kid)).toEqual([k1, k2]);
    let roles = deriveRoles(await listSigningKeys(db), clock.now());
    expect(roles.next.map((r) => r.kid)).toEqual([k2]);
    expect(roles.signing?.kid).toBe(k1);
    expect([...rolesByKid(await listSigningKeys(db), clock.now())]).toEqual([
      [k1, "signing"],
      [k2, "next"],
    ]);
    // Before anything activated there is no signing key and every row is next.
    expect([...rolesByKid(await listSigningKeys(db), t0 - 1)]).toEqual([
      [k1, "next"],
      [k2, "next"],
    ]);

    // After pre-publication the new key signs and the old one verifies.
    clock.advance(DAY);
    loaded = await fresh();
    expect(loaded.signing.kid).toBe(k2);
    roles = deriveRoles(await listSigningKeys(db), clock.now());
    expect(roles.verifying.map((r) => r.kid)).toEqual([k1]);
    // Judged at an instant where the token is unexpired, it verifies against the now-verifying key.
    clock.set(t0 + 100);
    expect(
      await verifyOwnJwt(loaded, tokenByK1, { issuer: ISSUER, typ: "JWT" }, clock),
    ).toMatchObject({ sub: "u" });
    clock.set(t0 + DAY);

    // Retirement: cron retires superseded keys once the signing key has signed for retire_after_seconds.
    let result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result).toEqual({ created: null, retired: [], deleted: 0, deleted_kids: [] });
    clock.advance(SETTINGS["keys.retire_after_seconds"]);
    result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result).toEqual({ created: null, retired: [k1], deleted: 0, deleted_kids: [] });
    const retiredRow = (await listSigningKeys(db)).find((r) => r.kid === k1);
    expect(retiredRow?.retired_at).toBe(clock.now());
    expect(retiredRow?.private_jwk_enc).toBeNull();
    loaded = await fresh();
    expect(loaded.jwks.keys.map((k) => k.kid)).toEqual([k2]);
    // Same unexpired instant as above: the token now fails because its key is retired, not because of time.
    clock.set(t0 + 100);
    expect(await verifyOwnJwt(loaded, tokenByK1, { issuer: ISSUER, typ: "JWT" }, clock)).toBeNull();
    clock.set(retiredRow?.retired_at as number);

    // Automatic rotation: due after rotation_days with no next key; a third key appears.
    clock.advance(SETTINGS["keys.rotation_days"] * DAY);
    result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result.created).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const k3 = result.created as string;
    result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result.created).toBeNull();
    roles = deriveRoles(await listSigningKeys(db), clock.now());
    expect(roles.next.map((r) => r.kid)).toEqual([k3]);
    expect(roles.retired.map((r) => r.kid)).toEqual([k1]);

    // Retired rows are deleted 90 days after retirement.
    clock.set((retiredRow?.retired_at as number) + RETIRED_KEY_RETENTION_SECONDS);
    result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result.deleted).toBe(0);
    clock.advance(1);
    result = await maintainSigningKeys(db, keys, clock.now(), SETTINGS);
    expect(result.deleted).toBe(1);
    expect((await listSigningKeys(db)).map((r) => r.kid).sort()).toEqual([k2, k3].sort());
    // Rotation disabled: nothing is created however old the signing key is.
    expect(
      (
        await maintainSigningKeys(db, keys, clock.now() + 1000 * DAY, {
          ...SETTINGS,
          "keys.rotation_days": 0,
        })
      ).created,
    ).toBeNull();
  });

  it("skips a key whose stored public JWK is corrupt (row edited directly to construct the inconsistency)", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const store = new KeyStore(clock);
    await store.get(db, keys);
    clock.advance(1);
    const k2 = await rotateSigningKey(db, keys, clock.now(), DAY, false);
    await db
      .prepare("UPDATE signing_keys SET public_jwk = ? WHERE kid = ?")
      .bind("{not json", k2)
      .run();
    store.invalidate();
    const loaded = await store.get(db, keys);
    expect(loaded.jwks.keys.map((k) => k.kid)).not.toContain(k2);
    expect(loaded.jwks.keys).toHaveLength(1);
  });

  it("[TIO-KEYS-013] emergency retirement refuses the last active key and retires any other", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const k1 = (await new KeyStore(clock).get(db, keys)).signing.kid;
    expect(await retireSigningKeyNow(db, k1, clock.now())).toBe("last_active_key");
    expect(await retireSigningKeyNow(db, "nope", clock.now())).toBe("not_found");
    const k2 = await rotateSigningKey(db, keys, clock.now(), 0, true);
    expect(await retireSigningKeyNow(db, k1, clock.now())).toBe("retired");
    expect(await retireSigningKeyNow(db, k1, clock.now())).toBe("not_found");
    expect(await retireSigningKeyNow(db, k2, clock.now())).toBe("last_active_key");
    const next = await rotateSigningKey(db, keys, clock.now(), DAY, false);
    expect(await retireSigningKeyNow(db, next, clock.now())).toBe("retired");
  });

  it("[TIO-ARCH-011] [TIO-ARCH-012] loaded keys refresh every 60 s, are served stale for an hour when D1 fails, then fail closed", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const store = new KeyStore(clock);
    const k1 = (await store.get(db, keys)).signing.kid;
    clock.advance(1);
    const k2 = await rotateSigningKey(db, keys, clock.now(), 0, true);
    expect((await store.get(db, keys)).signing.kid).toBe(k1);
    clock.advance(KEYS_TTL_SECONDS - 1);
    expect((await store.get(db, keys)).signing.kid).toBe(k2);
    const broken = Db.from(brokenD1());
    clock.advance(KEYS_TTL_SECONDS);
    expect((await store.get(broken, keys)).signing.kid).toBe(k2);
    clock.advance(KEYS_STALE_SECONDS);
    await expect(store.get(broken, keys)).rejects.toBeInstanceOf(KeysUnavailableError);
    await expect(new KeyStore(clock).get(broken, keys)).rejects.toBeInstanceOf(
      KeysUnavailableError,
    );
  });

  it("[TIO-CRYPTO-011] [TIO-ARCH-008] master-key rotation: add and activate a version, re-encrypt rows, then drop the old version", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    // Phase 1: everything sealed under version 1.
    const v1 = testKeys("1");
    const k1 = (await new KeyStore(clock).get(db, v1)).signing.kid;
    const k2 = await rotateSigningKey(db, v1, clock.now(), DAY, false);
    expect(
      (await listSigningKeys(db)).map((r) => sealedUnderVersion(r.private_jwk_enc as Uint8Array)),
    ).toEqual([1, 1]);
    // Phase 2: version 2 becomes active; old rows still open; rekey moves them one chunk at a time.
    const v2 = testKeys("2");
    expect((await new KeyStore(clock).get(db, v2)).signing.kid).toBe(k1);
    expect(await rekeySigningKeys(db, v2, 1)).toEqual({
      rekeyed: [k1],
      unrecoverable: [],
      remaining: 1,
    });
    expect(await rekeySigningKeys(db, v2, 10)).toEqual({
      rekeyed: [k2],
      unrecoverable: [],
      remaining: 0,
    });
    expect(await rekeySigningKeys(db, v2, 10)).toEqual({
      rekeyed: [],
      unrecoverable: [],
      remaining: 0,
    });
    expect(
      (await listSigningKeys(db)).map((r) => sealedUnderVersion(r.private_jwk_enc as Uint8Array)),
    ).toEqual([2, 2]);
    // Phase 3: version 1 removed from the secret; rows sealed under 2 load, a leftover row under 1 would not.
    const only2 = testKeys(
      "2",
      JSON.stringify({ "2": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" }),
    );
    expect((await new KeyStore(clock).get(db, only2)).signing.kid).toBe(k1);
    const leftover = await sealSecret(testKeys("1"), utf8("{}"));
    expect(await openSecret(only2, leftover)).toBeNull();
    // A row still sealed under the removed version is reported as unrecoverable, never modified.
    const k3 = await rotateSigningKey(db, testKeys("1"), clock.now(), DAY, false);
    expect(await rekeySigningKeys(db, only2, 10)).toEqual({
      rekeyed: [],
      unrecoverable: [k3],
      remaining: 0,
    });
    expect(
      sealedUnderVersion(
        (await listSigningKeys(db)).find((r) => r.kid === k3)?.private_jwk_enc as Uint8Array,
      ),
    ).toBe(1);
    expect(await openSecret(keysWithoutVersion2(), await sealSecret(v2, utf8("x")))).toBeNull();
  });
});

describe("secret box", () => {
  it("seals under the active version and rejects tampered, truncated or foreign blobs", async () => {
    const keys = testKeys("2");
    const blob = await sealSecret(keys, utf8("hello"));
    expect(sealedUnderVersion(blob)).toBe(2);
    expect(new TextDecoder().decode((await openSecret(keys, blob)) as Uint8Array)).toBe("hello");
    const tampered = blob.slice();
    tampered[20] = (tampered[20] as number) ^ 1;
    expect(await openSecret(keys, tampered)).toBeNull();
    expect(await openSecret(keys, blob.slice(0, 10))).toBeNull();
    expect(sealedUnderVersion(new Uint8Array([2, 1, ...new Array(40).fill(0)]))).toBeNull();
    expect(await openSecret(keys, new Uint8Array([2, 1, ...new Array(40).fill(0)]))).toBeNull();
  });
});

describe("JWT service", () => {
  beforeEach(resetStorage);

  it("[TIO-KEYS-015] every token the OP signs carries a header of exactly alg, typ and kid, under 512 bytes", async () => {
    const loaded = await new KeyStore(new FakeClock()).get(Db.from(env.DB), testKeys());
    for (const typ of ["JWT", "at+jwt", "logout+jwt"] as const) {
      const jwt = await signJwt(loaded, typ, { iss: ISSUER, sub: "u", aud: "c", iat: 1, exp: 2 });
      const header = decodeProtectedHeader(jwt);
      expect(Object.keys(header).sort()).toEqual(["alg", "kid", "typ"]);
      expect(header).toEqual({ alg: "ES256", typ, kid: loaded.signing.kid });
      const encoded = jwt.slice(0, jwt.indexOf("."));
      expect(encoded.length).toBeLessThanOrEqual(512);
      // {"alg":"ES256","typ":"<typ>","kid":"<43 chars>"} is 79, 82 or 86 bytes.
      expect(encoded.length).toBe(typ === "JWT" ? 106 : typ === "at+jwt" ? 110 : 115);
    }
  });

  it("[TIO-TOKEN-034] [TIO-KEYS-013] verifies own tokens by issuer, typ, audience and exp with 0 s leeway; rejects other keys, algorithms and claims", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const keys = testKeys();
    const store = new KeyStore(clock);
    const loaded = await store.get(db, keys);
    const claims = {
      iss: ISSUER,
      sub: "u",
      aud: ["c", ISSUER],
      iat: clock.now(),
      exp: clock.now() + 60,
    };
    const token = await signJwt(loaded, "at+jwt", claims);
    const verify = (
      t: string,
      options: Partial<Parameters<typeof verifyOwnJwt>[2]> = {},
      at = clock,
    ) =>
      verifyOwnJwt(loaded, t, { issuer: ISSUER, typ: "at+jwt", audience: ISSUER, ...options }, at);
    expect(await verify(token)).toMatchObject({ sub: "u" });
    expect(await verify(token, { audience: "c" })).toMatchObject({ sub: "u" });
    expect(await verify(token, { audience: "other" })).toBeNull();
    expect(await verify(token, { typ: "JWT" })).toBeNull();
    expect(await verify(token, { issuer: "https://other.example" })).toBeNull();
    clock.advance(59);
    expect(await verify(token)).not.toBeNull();
    clock.advance(1);
    expect(await verify(token)).toBeNull();
    clock.set(claims.iat);
    // Signed by a key the store does not know (retired or foreign).
    const other = await new KeyStore(clock).get(Db.from(env.DB), keys);
    clock.advance(1);
    const k2 = await rotateSigningKey(db, keys, clock.now(), 0, true);
    store.invalidate();
    const withK2 = await store.get(db, keys);
    expect(withK2.signing.kid).toBe(k2);
    const byK2 = await signJwt(withK2, "at+jwt", claims);
    expect(await verifyOwnJwt(loaded, byK2, { issuer: ISSUER, typ: "at+jwt" }, clock)).toBeNull();
    expect(
      await verifyOwnJwt(withK2, token, { issuer: ISSUER, typ: "at+jwt" }, clock),
    ).toMatchObject({ sub: "u" });
    expect(await verifyOwnJwt(other, byK2, { issuer: ISSUER, typ: "at+jwt" }, clock)).toBeNull();
    // Tampered payload, wrong algorithm, garbage.
    const [h, p, s] = token.split(".") as [string, string, string];
    expect(await verify(`${h}.${p.slice(0, -2)}xx.${s}`)).toBeNull();
    const noneHeader = btoa(
      JSON.stringify({ alg: "none", typ: "at+jwt", kid: loaded.signing.kid }),
    ).replace(/=+$/, "");
    expect(await verify(`${noneHeader}.${p}.`)).toBeNull();
    const hsHeader = btoa(
      JSON.stringify({ alg: "HS256", typ: "at+jwt", kid: loaded.signing.kid }),
    ).replace(/=+$/, "");
    expect(await verify(`${hsHeader}.${p}.${s}`)).toBeNull();
    expect(await verify("not.a.jwt")).toBeNull();
    expect(await verify("")).toBeNull();
    // Missing required claims.
    const noSub = await signJwt(loaded, "at+jwt", {
      iss: ISSUER,
      aud: ISSUER,
      iat: clock.now(),
      exp: clock.now() + 60,
    });
    expect(await verify(noSub)).toBeNull();
  });

  it("[TIO-LOGOUT-001] an expired token verifies when expiry is ignored, but every other check still applies", async () => {
    const clock = new FakeClock();
    const loaded = await new KeyStore(clock).get(Db.from(env.DB), testKeys());
    const claims = { iss: ISSUER, sub: "u", aud: "c", iat: clock.now(), exp: clock.now() + 60 };
    const token = await signJwt(loaded, "JWT", claims);
    clock.advance(3_600);
    const options = { issuer: ISSUER, typ: "JWT" as const };
    expect(await verifyOwnJwt(loaded, token, options, clock)).toBeNull();
    expect(
      await verifyOwnJwt(loaded, token, { ...options, ignoreExpiry: true }, clock),
    ).toMatchObject({ sub: "u" });
    expect(
      await verifyOwnJwt(loaded, token, { ...options, ignoreExpiry: true, audience: "x" }, clock),
    ).toBeNull();
    expect(
      await verifyOwnJwt(
        loaded,
        token,
        { ...options, ignoreExpiry: true, issuer: "https://x" },
        clock,
      ),
    ).toBeNull();
    const noIat = await signJwt(loaded, "JWT", { iss: ISSUER, sub: "u", aud: "c", exp: 1 });
    expect(await verifyOwnJwt(loaded, noIat, { ...options, ignoreExpiry: true }, clock)).toBeNull();
    // Not-yet-valid-looking tokens are not "expired": ignoreExpiry does not rescue them.
    const future = await signJwt(loaded, "JWT", {
      ...claims,
      iat: clock.now() + 100,
      exp: clock.now() + 200,
    });
    expect(
      await verifyOwnJwt(loaded, future, { ...options, ignoreExpiry: true }, clock),
    ).toMatchObject({ sub: "u" });
  });
});
