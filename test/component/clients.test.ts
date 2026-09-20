import { beforeEach, describe, expect, it } from "vitest";
import { sha256 } from "../../src/crypto/hash.ts";
import {
  decodeClientRow,
  deleteClient,
  getClient,
  insertClient,
  setClientDisabled,
  updateClientSecretHash,
} from "../../src/db/clients.ts";
import { Db } from "../../src/db/db.ts";
import {
  CLIENT_CACHE_CAPACITY,
  CLIENT_CACHE_STALE_SECONDS,
  CLIENT_CACHE_TTL_SECONDS,
  ClientCache,
  ClientsUnavailableError,
} from "../../src/oidc/client-cache.ts";
import { createClient, updateClientRecord } from "../../src/oidc/clients.ts";
import { FakeClock } from "../support/clock.ts";
import { createTestClient } from "../support/factories.ts";
import { env } from "../support/op.ts";
import { resetStorage } from "../support/reset.ts";

const context = {
  issuer: "https://auth.example.com",
  actorHasAdmin: false,
  existingGroups: new Set<string>(),
};

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

describe("client service and repository", () => {
  beforeEach(resetStorage);

  it("[TIO-CLIENT-001] [TIO-CLIENT-003] creates a client with a generated id, returns a secret exactly once and stores only its hash", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const created = await createClient(
      db,
      {
        client_name: "Server App",
        redirect_uris: ["https://app.example.com/cb"],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "client_secret_basic",
        scopes_allowed: ["openid", "email"],
      },
      context,
      clock.now(),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    expect(created.client.client_id).toMatch(/^c_[a-z0-9]{22}$/);
    expect(created.secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = await getClient(db, created.client.client_id);
    expect(stored).toEqual(created.client);
    expect(stored?.client_secret_hash).toEqual(await sha256(created.secret as string));
    expect(JSON.stringify(stored)).not.toContain(created.secret as string);
    const publicClient = await createClient(
      db,
      {
        client_id: "spa",
        client_name: "SPA",
        redirect_uris: ["https://spa.example.com/cb"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scopes_allowed: ["openid"],
      },
      context,
      clock.now(),
    );
    expect(publicClient.ok && publicClient.secret).toBeNull();
    expect(publicClient.ok && publicClient.client.client_secret_hash).toBeNull();
    expect(await getClient(db, "missing")).toBeNull();
  });

  it("rejects invalid input, validation violations and duplicate ids without writing", async () => {
    const db = Db.from(env.DB);
    const now = new FakeClock().now();
    expect(await createClient(db, { client_name: "x" }, context, now)).toMatchObject({
      ok: false,
      error: "invalid_client",
      violations: expect.arrayContaining([expect.stringMatching(/^grant_types: /)]),
    });
    expect(await createClient(db, "not an object", context, now)).toMatchObject({
      ok: false,
      violations: ["$: Invalid input: expected object, received string"],
    });
    const badRedirect = await createClient(
      db,
      {
        client_name: "x",
        redirect_uris: ["http://localhost/cb"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scopes_allowed: ["openid"],
      },
      context,
      now,
    );
    expect(badRedirect).toEqual({
      ok: false,
      error: "invalid_client",
      violations: ['redirect_uris: "http://localhost/cb" is not registrable'],
    });
    await createTestClient(db, new FakeClock(), { client_id: "dup" });
    const duplicate = await createTestClient(db, new FakeClock(), { client_id: "dup" }).catch(
      (e: Error) => e.message,
    );
    expect(duplicate).toContain("client_exists");
    const rows = await db.prepare("SELECT COUNT(*) AS n FROM clients").first<{ n: number }>();
    expect(rows?.n).toBe(1);
  });

  it("round-trips every column, including JWKS, groups and TTL overrides, and treats a corrupt JSON column as absent", async () => {
    const db = Db.from(env.DB);
    const { client } = await createTestClient(
      db,
      new FakeClock(),
      {
        client_id: "full",
        client_uri: "https://app.example.com",
        logo_uri: "https://app.example.com/logo.png",
        post_logout_redirect_uris: ["https://app.example.com/bye"],
        backchannel_logout_uri: "https://app.example.com/bc",
        grant_types: ["authorization_code", "refresh_token", "client_credentials"],
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "EC", crv: "P-256", kid: "k1", x: "x", y: "y" }] },
        audiences: ["https://api.example.com"],
        allowed_groups: ["staff"],
        skip_consent: true,
        require_par: true,
        offline_access: true,
        access_token_ttl: 120,
        id_token_ttl: 300,
        refresh_token_ttl: 172_800,
        refresh_idle_ttl: 7_200,
      },
      { existingGroups: new Set(["staff"]) },
    );
    expect(await getClient(db, "full")).toEqual(client);
    expect(client.jwks?.keys[0]?.kid).toBe("k1");
    await db
      .prepare("UPDATE clients SET scopes_allowed = ? WHERE client_id = ?")
      .bind("{oops", "full")
      .run();
    expect(await getClient(db, "full")).toBeNull();
    for (const column of [
      "redirect_uris",
      "post_logout_redirect_uris",
      "grant_types",
      "audiences",
      "allowed_groups",
      "jwks",
    ]) {
      const raw = {
        client_id: "x",
        client_name: "x",
        client_uri: null,
        logo_uri: null,
        redirect_uris: "[]",
        post_logout_redirect_uris: "[]",
        backchannel_logout_uri: null,
        grant_types: '["authorization_code"]',
        token_endpoint_auth_method: "none" as const,
        client_secret_hash: null,
        jwks: null,
        jwks_uri: null,
        scopes_allowed: '["openid"]',
        audiences: "[]",
        allowed_groups: null,
        skip_consent: 0,
        require_par: 0,
        require_pkce: 1,
        offline_access: 0,
        access_token_ttl: null,
        id_token_ttl: null,
        refresh_token_ttl: null,
        refresh_idle_ttl: null,
        disabled_at: null,
        created_at: 0,
        updated_at: 0,
        [column]: "{corrupt",
      };
      expect(decodeClientRow(raw), column).toBeNull();
    }
  });

  it("[TIO-CLIENT-004] disable, enable, secret rotation and deletion update the row", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const { client } = await createTestClient(db, clock, {
      client_id: "web",
      token_endpoint_auth_method: "client_secret_basic",
    });
    expect(await setClientDisabled(db, "web", clock.now(), clock.now())).toBe(true);
    expect((await getClient(db, "web"))?.disabled_at).toBe(clock.now());
    expect(await setClientDisabled(db, "web", null, clock.now() + 1)).toBe(true);
    expect((await getClient(db, "web"))?.disabled_at).toBeNull();
    expect(await setClientDisabled(db, "nope", null, 0)).toBe(false);
    const newHash = await sha256("new-secret");
    expect(await updateClientSecretHash(db, "web", newHash, clock.now() + 2)).toBe(true);
    expect((await getClient(db, "web"))?.client_secret_hash).toEqual(newHash);
    expect((await getClient(db, "web"))?.client_secret_hash).not.toEqual(client.client_secret_hash);
    expect(await updateClientSecretHash(db, "nope", newHash, 0)).toBe(false);
    expect(await deleteClient(db, "web")).toBe(true);
    expect(await deleteClient(db, "web")).toBe(false);
    expect(await getClient(db, "web")).toBeNull();
    expect(await insertClient(db, client)).toBe("created");
    expect(await insertClient(db, client)).toBe("client_exists");
  });
});

describe("client cache", () => {
  beforeEach(resetStorage);

  it("[TIO-ARCH-011] caches hits and misses for 60 s, then refreshes so a disabled client is seen within the window", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const cache = new ClientCache(clock);
    expect(await cache.get(db, "web")).toBeNull();
    await createTestClient(db, clock, { client_id: "web" });
    expect(await cache.get(db, "web")).toBeNull();
    clock.advance(CLIENT_CACHE_TTL_SECONDS);
    expect((await cache.get(db, "web"))?.client_id).toBe("web");
    await setClientDisabled(db, "web", clock.now(), clock.now());
    expect((await cache.get(db, "web"))?.disabled_at).toBeNull();
    clock.advance(CLIENT_CACHE_TTL_SECONDS);
    expect((await cache.get(db, "web"))?.disabled_at).toBe(clock.now() - CLIENT_CACHE_TTL_SECONDS);
    // From three quarters of the TTL the entry refreshes in the background while still served.
    await setClientDisabled(db, "web", null, clock.now());
    clock.advance(CLIENT_CACHE_TTL_SECONDS * 0.75);
    expect((await cache.get(db, "web"))?.disabled_at).not.toBeNull();
    await cache.settled();
    expect((await cache.get(db, "web"))?.disabled_at).toBeNull();
    // The app hands the refresh to the runtime so it outlives the request.
    await setClientDisabled(db, "web", clock.now(), clock.now());
    clock.advance(CLIENT_CACHE_TTL_SECONDS * 0.75);
    const kept: Promise<unknown>[] = [];
    cache.keepAlive = (work) => kept.push(work);
    expect((await cache.get(db, "web"))?.disabled_at).toBeNull();
    expect(kept).toHaveLength(1);
    await cache.settled();
    expect((await cache.get(db, "web"))?.disabled_at).not.toBeNull();
    cache.invalidate("web");
    await setClientDisabled(db, "web", null, clock.now());
    expect((await cache.get(db, "web"))?.disabled_at).toBeNull();
    cache.invalidate();
    expect(cache.size).toBe(0);
  });

  it("[TIO-ARCH-012] serves stale records for an hour when D1 fails, then fails closed", async () => {
    const db = Db.from(env.DB);
    const clock = new FakeClock();
    const cache = new ClientCache(clock);
    await createTestClient(db, clock, { client_id: "web" });
    expect((await cache.get(db, "web"))?.client_id).toBe("web");
    const broken = Db.from(brokenD1());
    clock.advance(CLIENT_CACHE_TTL_SECONDS);
    expect((await cache.get(broken, "web"))?.client_id).toBe("web");
    clock.advance(CLIENT_CACHE_STALE_SECONDS);
    await expect(cache.get(broken, "web")).rejects.toBeInstanceOf(ClientsUnavailableError);
    await expect(cache.get(broken, "other")).rejects.toBeInstanceOf(ClientsUnavailableError);
  });

  it("evicts the least recently used entry beyond 1,000 entries", async () => {
    const db = Db.from(env.DB);
    const cache = new ClientCache(new FakeClock());
    for (let i = 0; i < CLIENT_CACHE_CAPACITY + 1; i++) await cache.get(db, `c${i}`);
    expect(cache.size).toBe(CLIENT_CACHE_CAPACITY);
    // c0 was evicted; c1 is refreshed by a touch and survives the next insertion.
    await cache.get(db, "c1");
    await cache.get(db, "extra");
    expect(cache.size).toBe(CLIENT_CACHE_CAPACITY);
  });
});

describe("updateClientRecord", () => {
  beforeEach(resetStorage);

  it("[TIO-CLIENT-002] refuses a patch that is not an object before anything else", async () => {
    const clock = new FakeClock();
    const db = Db.from(env.DB);
    const created = await createClient(
      db,
      {
        client_name: "Patched",
        redirect_uris: ["https://rp.example.com/cb"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
        scopes_allowed: ["openid"],
      },
      context,
      clock.now(),
    );
    if (!created.ok) throw new Error(created.error);
    for (const raw of [[1], null, "text", 5]) {
      expect(await updateClientRecord(db, created.client, raw, context, clock.now())).toEqual({
        ok: false,
        error: "invalid_client",
        violations: ["$: expected an object"],
      });
    }
  });
});
