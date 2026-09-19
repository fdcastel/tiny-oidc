import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { hmacSha256, secretsEqual, sha256 } from "../../src/crypto/hash.ts";
import { Db } from "../../src/db/db.ts";
import { pingDb, readAllSettings, writeSettings } from "../../src/db/settings.ts";
import {
  buildConfig,
  type Config,
  SETTINGS_STALE_SECONDS,
  SETTINGS_TTL_SECONDS,
  SettingsLoader,
  SettingsUnavailableError,
} from "../../src/env.ts";
import { utf8 } from "../../src/util/base64url.ts";
import { hex } from "../support/bytes.ts";
import { FakeClock } from "../support/clock.ts";
import { TEST_MASTER_KEYS, testKeys } from "../support/keys.ts";
import { resetStorage } from "../support/reset.ts";

const config = (): Config => {
  const result = buildConfig({
    ...env,
    ISSUER: "https://auth.example.com",
    RP_ID: "example.com",
    MASTER_KEYS: TEST_MASTER_KEYS,
    MASTER_KEY_ACTIVE: "1",
  });
  if (!result.ok) throw new Error(result.error);
  return result.config;
};

/** A D1 stand-in whose prepare() throws, to simulate an unavailable database. */
const brokenD1 = (): D1Database =>
  ({
    prepare() {
      throw new Error("D1 unavailable");
    },
    batch() {
      throw new Error("D1 unavailable");
    },
    withSession() {
      return this;
    },
  }) as unknown as D1Database;

describe("hash", () => {
  it("[TIO-CRYPTO-003] compares secrets in constant time and treats a length mismatch as unequal", async () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(1);
    const c = new Uint8Array(32).fill(2);
    expect(await secretsEqual(a, b)).toBe(true);
    expect(await secretsEqual(a, c)).toBe(false);
    expect(await secretsEqual(a, new Uint8Array(31).fill(1))).toBe(false);
    expect(await secretsEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it("hashes strings and bytes with SHA-256 and signs with HMAC-SHA256", async () => {
    const digest = await sha256("abc");
    expect(hex(digest)).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(await sha256(utf8("abc"))).toEqual(digest);
    const key = await (testKeys().hmacKey("iphash") as Promise<CryptoKey>);
    const mac1 = await hmacSha256(key, utf8("203.0."), utf8("113.9"));
    const mac2 = await hmacSha256(key, utf8("203.0.113.9"));
    expect(mac1).toEqual(mac2);
    expect(mac1).toHaveLength(32);
    expect(await hmacSha256(key, utf8("other"))).not.toEqual(mac1);
  });
});

describe("Db wrapper and settings repository", () => {
  beforeEach(resetStorage);

  it("[TIO-DATA-017] counts reads and writes, batches atomically and reads its own writes through the primary session", async () => {
    const db = Db.from(env.DB);
    expect(await readAllSettings(db)).toEqual({});
    expect(db.counters).toEqual({ reads: 1, writes: 0 });
    await writeSettings(
      db,
      { "registration.mode": "open", "tokens.access_ttl": 900 },
      "admin:test",
      1_790_000_000,
    );
    expect(db.counters).toEqual({ reads: 1, writes: 2 });
    const primary = db.primary();
    expect(await readAllSettings(primary)).toEqual({
      "registration.mode": "open",
      "tokens.access_ttl": 900,
    });
    expect(primary.primary()).toBe(primary);
    expect(db.counters.reads).toBe(2);
    // Upsert replaces, null deletes, an empty write is a no-op.
    await writeSettings(
      db,
      { "registration.mode": "closed", "tokens.access_ttl": null },
      "admin:test",
      1_790_000_100,
    );
    await writeSettings(db, {}, "admin:test", 1_790_000_100);
    expect(await readAllSettings(db)).toEqual({ "registration.mode": "closed" });
    const row = await db
      .prepare("SELECT updated_at, updated_by FROM settings WHERE key = ?")
      .bind("registration.mode")
      .first<{ updated_at: number; updated_by: string }>();
    expect(row).toEqual({ updated_at: 1_790_000_100, updated_by: "admin:test" });
    const all = await db.prepare("SELECT key FROM settings").all<{ key: string }>();
    expect(all.results).toEqual([{ key: "registration.mode" }]);
    const run = await db.prepare("DELETE FROM settings WHERE key = ?").bind("nope").run();
    expect(run.meta.changes).toBe(0);
  });

  it("[TIO-DATA-016] a failing statement in a batch rolls back the whole batch", async () => {
    const db = Db.from(env.DB);
    await expect(
      db.batch([
        db
          .prepare("INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)")
          .bind("a", "1", 0, "t"),
        db
          .prepare("INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)")
          .bind("a", "2", 0, "t"),
      ]),
    ).rejects.toThrow();
    expect(await readAllSettings(db)).toEqual({});
    const [count] = await db.batch<{ n: number }>([
      db.prepare("SELECT COUNT(*) AS n FROM settings"),
    ]);
    expect(count?.results[0]?.n).toBe(0);
    expect(db.counters.reads).toBe(2);
  });

  it("skips rows whose value is not JSON and reports D1 liveness", async () => {
    const db = Db.from(env.DB);
    await db
      .prepare("INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)")
      .bind("broken", "{not json", 0, "t")
      .run();
    await writeSettings(db, { ok: true }, "t", 0);
    expect(await readAllSettings(db)).toEqual({ ok: true });
    expect(await pingDb(db)).toBe(true);
    expect(await pingDb(Db.from(brokenD1()))).toBe(false);
  });
});

describe("SettingsLoader", () => {
  beforeEach(resetStorage);

  it("[TIO-ARCH-011] serves cached settings for 60 seconds and picks up a change on the next refresh", async () => {
    const clock = new FakeClock();
    const loader = new SettingsLoader(clock);
    const db = Db.from(env.DB);
    const first = await loader.get(db, config());
    expect(first["registration.mode"]).toBe("invite");
    await writeSettings(db, { "registration.mode": "open" }, "t", clock.now());
    clock.advance(SETTINGS_TTL_SECONDS - 1);
    expect((await loader.get(db, config()))["registration.mode"]).toBe("invite");
    expect(db.counters.reads).toBe(1);
    clock.advance(1);
    expect((await loader.get(db, config()))["registration.mode"]).toBe("open");
    expect(db.counters.reads).toBe(2);
    loader.invalidate();
    await loader.get(db, config());
    expect(db.counters.reads).toBe(3);
  });

  it("[TIO-ARCH-012] serves stale settings while D1 fails for at most one hour, then fails closed", async () => {
    const clock = new FakeClock();
    const loader = new SettingsLoader(clock);
    const good = Db.from(env.DB);
    await writeSettings(good, { "registration.mode": "open" }, "t", clock.now());
    expect((await loader.get(good, config()))["registration.mode"]).toBe("open");
    const broken = Db.from(brokenD1());
    clock.advance(SETTINGS_TTL_SECONDS);
    expect((await loader.get(broken, config()))["registration.mode"]).toBe("open");
    clock.advance(SETTINGS_STALE_SECONDS - SETTINGS_TTL_SECONDS - 1);
    expect((await loader.get(broken, config()))["registration.mode"]).toBe("open");
    clock.advance(1);
    await expect(loader.get(broken, config())).rejects.toBeInstanceOf(SettingsUnavailableError);
    // With nothing cached at all, a D1 failure fails closed immediately.
    await expect(new SettingsLoader(clock).get(broken, config())).rejects.toBeInstanceOf(
      SettingsUnavailableError,
    );
  });

  it("[TIO-CFG-003] treats stored settings that violate the rules as unavailable", async () => {
    const clock = new FakeClock();
    const db = Db.from(env.DB);
    await writeSettings(
      db,
      { "session.idle_ttl": 2_592_000, "session.absolute_ttl": 3_600 },
      "t",
      clock.now(),
    );
    await expect(new SettingsLoader(clock).get(db, config())).rejects.toThrow(
      "settings unavailable",
    );
  });
});
