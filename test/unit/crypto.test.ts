import { describe, expect, it } from "vitest";
import { HANDLE_TYPES, handleType, openHandle, sealHandle } from "../../src/crypto/envelope.ts";
import { parseMasterKeys } from "../../src/crypto/master-keys.ts";
import { newInteractionId, newSecret, randomBytes } from "../../src/crypto/random.ts";
import { bytesToUuid, isUuid, UuidV7, uuidToBytes } from "../../src/crypto/uuid.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/util/base64url.ts";
import { FakeClock } from "../support/clock.ts";
import { keysWithoutVersion2, TEST_MASTER_KEYS, testKeys } from "../support/keys.ts";

describe("random", () => {
  it("[TIO-CRYPTO-002] [TIO-CRYPTO-004] draws every value from crypto.getRandomValues; secrets are 32 bytes", () => {
    const calls: number[] = [];
    const original = crypto.getRandomValues.bind(crypto);
    const spy = <T extends ArrayBufferView | null>(array: T): T => {
      if (array) calls.push(array.byteLength);
      return original(array as unknown as Uint8Array) as unknown as T;
    };
    Object.defineProperty(crypto, "getRandomValues", { value: spy, configurable: true });
    try {
      expect(newSecret()).toHaveLength(32);
      expect(randomBytes(7)).toHaveLength(7);
      expect(newInteractionId()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    } finally {
      Object.defineProperty(crypto, "getRandomValues", { value: original, configurable: true });
    }
    expect(calls).toEqual([32, 7, 32]);
    expect(newSecret()).not.toEqual(newSecret());
  });
});

describe("uuid v7", () => {
  it("[TIO-DATA-001] [TIO-DATA-002] generates lowercase 36-character UUID v7 values that follow the injected clock and stay monotonic", () => {
    const clock = new FakeClock(1_790_000_000);
    const uuids = new UuidV7(clock);
    const a = uuids.next();
    const b = uuids.next();
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(isUuid(a)).toBe(true);
    expect(b > a).toBe(true);
    // The first 48 bits are the clock's milliseconds.
    expect(Number.parseInt(a.replaceAll("-", "").slice(0, 12), 16)).toBe(1_790_000_000_000);
    clock.advance(1);
    const c = uuids.next();
    expect(c > b).toBe(true);
    expect(Number.parseInt(c.replaceAll("-", "").slice(0, 12), 16)).toBe(1_790_000_001_000);
  });

  it("[TIO-DATA-004] the clock reports integer seconds and the uuid round-trips through 16 bytes", () => {
    const clock = new FakeClock(1_790_000_000);
    clock.advance(0.75);
    expect(clock.now()).toBe(1_790_000_000);
    expect(Number.isInteger(clock.now())).toBe(true);
    const id = new UuidV7(clock).next();
    const bytes = uuidToBytes(id);
    expect(bytes).toHaveLength(16);
    expect(bytesToUuid(bytes as Uint8Array)).toBe(id);
    expect(uuidToBytes("not-a-uuid")).toBeNull();
    expect(uuidToBytes(id.toUpperCase())).toBeNull();
    expect(isUuid("")).toBe(false);
  });
});

describe("master keys", () => {
  it("[TIO-CRYPTO-010] accepts a well-formed secret pair and rejects every malformed variant", () => {
    const ok = parseMasterKeys(TEST_MASTER_KEYS, "2");
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.keys.active).toBe(2);
      expect([...ok.keys.versions.keys()]).toEqual([1, 2]);
      expect(ok.keys.versions.get(1)).toEqual(new Uint8Array(32).fill(1));
    }
    const short = JSON.stringify({ "1": "AQID" });
    const cases: [string | undefined, string | undefined, string][] = [
      [undefined, "1", "MASTER_KEYS is not set"],
      [TEST_MASTER_KEYS, undefined, "MASTER_KEY_ACTIVE is not set"],
      ["{", "1", "MASTER_KEYS must be a JSON object"],
      ["[]", "1", "MASTER_KEYS must be a JSON object"],
      ['"x"', "1", "MASTER_KEYS must be a JSON object"],
      ["{}", "1", "MASTER_KEYS has no versions"],
      [
        JSON.stringify({ "0": "x" }),
        "0",
        'MASTER_KEYS version "0" must be an integer from 1 to 255',
      ],
      [
        JSON.stringify({ "256": "x" }),
        "1",
        'MASTER_KEYS version "256" must be an integer from 1 to 255',
      ],
      [
        JSON.stringify({ "01": "x" }),
        "1",
        'MASTER_KEYS version "01" must be an integer from 1 to 255',
      ],
      [short, "1", 'MASTER_KEYS version "1" must be base64 of exactly 32 bytes'],
      [
        JSON.stringify({ "1": 5 }),
        "1",
        'MASTER_KEYS version "1" must be base64 of exactly 32 bytes',
      ],
      [
        JSON.stringify({ "1": "not base64!" }),
        "1",
        'MASTER_KEYS version "1" must be base64 of exactly 32 bytes',
      ],
      [
        JSON.stringify({ "1": "AQIDBA" }),
        "1",
        'MASTER_KEYS version "1" must be base64 of exactly 32 bytes',
      ],
      [TEST_MASTER_KEYS, "3", 'MASTER_KEY_ACTIVE "3" is not a version in MASTER_KEYS'],
      [TEST_MASTER_KEYS, "x", 'MASTER_KEY_ACTIVE "x" is not a version in MASTER_KEYS'],
    ];
    for (const [keys, active, error] of cases) {
      expect(parseMasterKeys(keys, active)).toEqual({ ok: false, error });
    }
  });

  it("[TIO-CRYPTO-020] derives one key per version and purpose, cached, non-extractable, and none for unknown versions", async () => {
    const keys = testKeys("1");
    expect(keys.hasVersion(2)).toBe(true);
    expect(keys.hasVersion(3)).toBe(false);
    const a = keys.aesKey("envelope");
    const b = keys.aesKey("envelope", 1);
    expect(a).toBe(b);
    const envelope1 = await (a as Promise<CryptoKey>);
    const envelope2 = await (keys.aesKey("envelope", 2) as Promise<CryptoKey>);
    const keystore1 = await (keys.aesKey("keystore", 1) as Promise<CryptoKey>);
    const iphash = await (keys.hmacKey("iphash") as Promise<CryptoKey>);
    const cursor = await (keys.hmacKey("cursor", 2) as Promise<CryptoKey>);
    for (const key of [envelope1, envelope2, keystore1, iphash, cursor])
      expect(key.extractable).toBe(false);
    expect(envelope1.algorithm).toEqual({ name: "AES-GCM", length: 256 });
    expect(iphash.algorithm).toMatchObject({ name: "HMAC" });
    expect(keys.aesKey("envelope", 3)).toBeNull();
    expect(keys.hmacKey("cursor", 9)).toBeNull();
    // Different purposes and versions produce different keys: the same plaintext encrypts differently.
    const iv = new Uint8Array(12);
    const data = new Uint8Array(4);
    const c1 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, envelope1, data),
    );
    const c2 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, envelope2, data),
    );
    const c3 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keystore1, data),
    );
    expect(c1).not.toEqual(c2);
    expect(c1).not.toEqual(c3);
  });
});

describe("envelope handles", () => {
  const keys = testKeys("1");
  const uid = new Uint8Array(16).fill(7);
  const sid = new Uint8Array(16).fill(8);
  const secret = new Uint8Array(32).fill(9);

  it("[TIO-ARCH-006] seals and opens every handle type with its prefix and fixed layout", async () => {
    const session = await sealHandle(keys, "session", { uid, sid, secret });
    expect(session).toMatch(/^tio_ss_[A-Za-z0-9_-]+$/);
    expect(await openHandle(keys, "session", session)).toEqual({ uid, sid, secret });
    const code = await sealHandle(keys, "code", { uid, secret });
    expect(code.startsWith("tio_ac_")).toBe(true);
    expect(await openHandle(keys, "code", code)).toEqual({ uid, secret });
    const family = new Uint8Array(16).fill(3);
    const refresh = await sealHandle(keys, "refresh", { uid, family, secret });
    expect(refresh.startsWith("tio_rt_")).toBe(true);
    expect(await openHandle(keys, "refresh", refresh)).toEqual({ uid, family, secret });
    const ixid = new Uint8Array(32).fill(4);
    const interaction = await sealHandle(keys, "interaction", { ixid, secret });
    expect(interaction.startsWith("tio_ix_")).toBe(true);
    expect(await openHandle(keys, "interaction", interaction)).toEqual({ ixid, secret });
    const federation = await sealHandle(keys, "federation", { ixid, secret });
    expect(federation.startsWith("tio_fs_")).toBe(true);
    expect(await openHandle(keys, "federation", federation)).toEqual({ ixid, secret });
    const invitation = await sealHandle(keys, "invitation", { invid: uid, secret });
    expect(invitation.startsWith("tio_iv_")).toBe(true);
    expect(await openHandle(keys, "invitation", invitation)).toEqual({ invid: uid, secret });
    // Two seals of the same fields differ (random nonce) and both open.
    expect(await sealHandle(keys, "code", { uid, secret })).not.toBe(code);
    expect(handleType(session)).toBe("session");
    expect(handleType(invitation)).toBe("invitation");
    expect(handleType("tio_zz_abc")).toBeNull();
    expect(Object.keys(HANDLE_TYPES)).toEqual([
      "session",
      "code",
      "refresh",
      "interaction",
      "federation",
      "invitation",
    ]);
  });

  it("[TIO-ARCH-006] rejects the wrong type, wrong prefix, wrong length, wrong version byte and garbage without throwing", async () => {
    const code = await sealHandle(keys, "code", { uid, secret });
    expect(await openHandle(keys, "session", code)).toBeNull();
    expect(await openHandle(keys, "code", `tio_ss_${code.slice(7)}`)).toBeNull();
    expect(await openHandle(keys, "code", "")).toBeNull();
    expect(await openHandle(keys, "code", "tio_ac_")).toBeNull();
    expect(await openHandle(keys, "code", "tio_ac_!!!")).toBeNull();
    expect(await openHandle(keys, "code", `${code}AAAA`)).toBeNull();
    expect(await openHandle(keys, "code", code.slice(0, -4))).toBeNull();
    // Version byte 2 is not the envelope version.
    const raw = code.slice(7);
    const bytes = decodeBase64Url(raw) as Uint8Array;
    bytes[0] = 2;
    expect(await openHandle(keys, "code", `tio_ac_${encodeBase64Url(bytes)}`)).toBeNull();
    // Type byte of another type inside a code-prefixed handle.
    const bytes2 = decodeBase64Url(raw) as Uint8Array;
    bytes2[2] = 1;
    expect(await openHandle(keys, "code", `tio_ac_${encodeBase64Url(bytes2)}`)).toBeNull();
    // Tampered ciphertext fails authentication.
    const bytes3 = decodeBase64Url(raw) as Uint8Array;
    bytes3[20] = (bytes3[20] as number) ^ 0x01;
    expect(await openHandle(keys, "code", `tio_ac_${encodeBase64Url(bytes3)}`)).toBeNull();
  });

  it("[TIO-ARCH-008] opens only with the key version named in the handle and rejects retired versions", async () => {
    const underV2 = await sealHandle(testKeys("2"), "code", { uid, secret });
    expect(await openHandle(testKeys("1"), "code", underV2)).toEqual({ uid, secret });
    expect(await openHandle(keysWithoutVersion2(), "code", underV2)).toBeNull();
    // A handle whose version byte names a key that never existed.
    const bytes = decodeBase64Url(underV2.slice(7)) as Uint8Array;
    bytes[1] = 200;
    expect(await openHandle(keys, "code", `tio_ac_${encodeBase64Url(bytes)}`)).toBeNull();
  });

  it("refuses to seal fields of the wrong length", async () => {
    await expect(sealHandle(keys, "code", { uid: new Uint8Array(3), secret })).rejects.toThrow(
      "handle field uid must be 16 bytes",
    );
  });
});
