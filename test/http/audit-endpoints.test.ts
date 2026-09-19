import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { type AuditEvent, Auditor } from "../../src/audit/events.ts";
import { archiveKey } from "../../src/audit/sink.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import { writeSettings } from "../../src/db/settings.ts";
import type { Env } from "../../src/env.ts";
import { createQueue } from "../../src/queue/consumer.ts";
import { admin, adminSettings, adminUser } from "../support/admin.ts";
import { harness } from "../support/http.ts";
import { env } from "../support/op.ts";
import { userWithPasskey } from "../support/passkeys.ts";
import { brokenD1, failingD1 } from "./faults.ts";

// The audit views (spec §9.4 Audit, §8, TIO-AUDIT-010): the hot table by
// filters and by user, keyset-paginated newest first and bounded by the hot
// retention window; the archive listed by day. The rows come through the
// real consumer.

const h = harness();
const { clock } = h;
const db = Db.from(env.DB);

interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

let token: string;
let alice: Awaited<ReturnType<typeof userWithPasskey>>;
/**
 * Ten days before the clock's start (2027-01-05 08:00 UTC): the seeded events sit in the
 * past, on another day than the live events the suite's own requests produce (which reach
 * the hot table through the queue consumer whenever it runs).
 */
const T0 = 1_800_000_000 - 10 * 86_400;
/** Bounds a listing to the seeded events. */
const SEEDED = `until=${T0 + 3_600}`;
const seeded: AuditEvent[] = [];

/** Events of a shape, stamped `at`, through the queue consumer into the hot table. */
async function ingest(events: AuditEvent[]): Promise<void> {
  const consume = createQueue({ clock, sink: () => undefined });
  const batch = {
    queue: "tiny-oidc-tasks",
    messages: [
      {
        id: "m",
        timestamp: clock.nowDate(),
        body: { kind: "audit", events },
        attempts: 1,
        ack: () => undefined,
        retry: () => {
          throw new Error("retry");
        },
      },
    ],
    ackAll: () => undefined,
    retryAll: () => undefined,
  } as unknown as MessageBatch<unknown>;
  await consume(batch, env, createExecutionContext());
}

function event(
  overrides: Partial<AuditEvent> & { ts: number; type: string },
  auditor = new Auditor(
    { request_id: "r", ip_hash: null, country: "BR", ua_family: "Chrome/128" },
    new UuidV7(clock),
    clock,
  ),
): AuditEvent {
  const base = auditor.emit({
    type: overrides.type,
    outcome: overrides.outcome ?? "success",
    actor: overrides.actor ?? { kind: "user", id: overrides.user_id ?? null },
    user_id: overrides.user_id ?? null,
    client_id: overrides.client_id ?? null,
    sid: overrides.sid ?? null,
    reason: overrides.reason ?? null,
    data: overrides.data ?? {},
  });
  return { ...base, ts: overrides.ts };
}

describe("admin audit listing", () => {
  it("[TIO-AUDIT-010] lists the hot table newest first with keyset cursors and every filter of §9.4; bad parameters and cursors are refused", async () => {
    await adminSettings(h);
    const operator = await adminUser(h);
    token = operator.access_token;
    alice = await userWithPasskey(clock, { email: "alice@example.com" });
    const bob = await userWithPasskey(clock, { email: "bob@example.com" });
    for (let i = 0; i < 12; i++) {
      seeded.push(
        event({
          ts: T0 + i * 60,
          type: i % 3 === 0 ? "session.revoked" : "token.issued",
          outcome: i % 4 === 0 ? "failure" : "success",
          user_id: i % 2 === 0 ? alice.profile.id : bob.profile.id,
          client_id: i < 6 ? "web" : "mobile",
          actor: {
            kind: i === 11 ? "admin" : "user",
            id: i === 11 ? operator.user.profile.id : null,
          },
          data:
            i % 3 === 0
              ? { clients: ["web"] }
              : { grant_type: "refresh_token", scopes: ["openid"] },
        }),
      );
    }
    await ingest(seeded);
    const list = async (query: string) => {
      const res = await admin(h, token, `audit${query}`);
      return {
        status: res.status,
        body: (await res.json()) as Page<AuditEvent> & { error?: string },
      };
    };
    const first = await list(`?limit=5&${SEEDED}`);
    expect(first.status).toBe(200);
    expect(first.body.items.map((e) => e.ts)).toEqual([
      T0 + 660,
      T0 + 600,
      T0 + 540,
      T0 + 480,
      T0 + 420,
    ]);
    expect(first.body.items[0]).toMatchObject({
      type: "token.issued",
      actor: { kind: "admin", id: operator.user.profile.id },
      country: "BR",
      ua_family: "Chrome/128",
      request_id: "r",
      data: { grant_type: "refresh_token", scopes: ["openid"] },
    });
    expect(first.body.next_cursor).not.toBeNull();
    const second = await list(`?limit=5&${SEEDED}&cursor=${first.body.next_cursor}`);
    expect(second.body.items.map((e) => e.ts)).toEqual([
      T0 + 360,
      T0 + 300,
      T0 + 240,
      T0 + 180,
      T0 + 120,
    ]);
    const third = await list(`?limit=5&${SEEDED}&cursor=${second.body.next_cursor}`);
    expect(third.body.items.map((e) => e.ts)).toEqual([T0 + 60, T0]);
    expect(third.body.next_cursor).toBeNull();
    // Filters.
    expect((await list(`?user_id=${alice.profile.id}&${SEEDED}`)).body.items).toHaveLength(6);
    expect((await list(`?type=session.revoked&${SEEDED}`)).body.items.map((e) => e.ts)).toEqual([
      T0 + 540,
      T0 + 360,
      T0 + 180,
      T0,
    ]);
    expect(
      (await list(`?client_id=mobile&outcome=failure&${SEEDED}`)).body.items.map((e) => e.ts),
    ).toEqual([T0 + 480]);
    expect((await list(`?actor_id=${operator.user.profile.id}&${SEEDED}`)).body.items).toHaveLength(
      1,
    );
    expect((await list(`?since=${T0 + 600}&${SEEDED}`)).body.items.map((e) => e.ts)).toEqual([
      T0 + 660,
      T0 + 600,
    ]);
    expect(
      (await list(`?since=${T0 + 120}&until=${T0 + 180}`)).body.items.map((e) => e.ts),
    ).toEqual([T0 + 180, T0 + 120]);
    // Refusals.
    for (const query of [
      "?limit=0",
      "?limit=abc",
      "?nope=1",
      "?outcome=maybe",
      "?since=x",
      "?until=1e3",
      "?cursor=forged",
      "?a=1&a=2",
    ]) {
      expect((await list(query)).status, query).toBe(400);
    }
    // A cursor of another listing does not open here.
    const users = (await (await admin(h, token, "users?limit=1")).json()) as Page<unknown>;
    expect(users.next_cursor).not.toBeNull();
    expect((await list(`?cursor=${users.next_cursor}`)).status).toBe(400);
    // Storage trouble.
    expect(
      (await admin(h, token, "audit", { env: { ...env, DB: failingD1(/FROM audit_hot/) } as Env }))
        .status,
    ).toBe(503);
    // A row whose data is not JSON any more still lists, with empty data.
    await db
      .prepare("UPDATE audit_hot SET data = 'not json' WHERE id = ?")
      .bind(seeded[0]?.id)
      .run();
    expect((await list(`?until=${T0}`)).body.items[0]?.data).toEqual({});
  });

  it("[TIO-AUDIT-010] lists the archive's keys for a range of days in UTC, at most 31 days, walking R2's own pages", async () => {
    const day = event({ ts: T0 + 3_661, type: "session.revoked" }); // 2027-01-05 09:01:01 UTC
    const nextDay = event({ ts: T0 + 90_061, type: "session.revoked" }); // 2027-01-06
    await ingest([day]);
    await ingest([nextDay]);
    const list = async (query: string) => {
      const res = await admin(h, token, `audit/archive${query}`);
      return {
        status: res.status,
        body: (await res.json()) as {
          items: { key: string; size: number; uploaded: number }[];
          from: string;
          to: string;
        },
      };
    };
    const seededKey = archiveKey(seeded[0] as AuditEvent);
    const one = await list("?from=2027-01-05");
    expect(one.status).toBe(200);
    expect(one.body).toMatchObject({ from: "2027-01-05", to: "2027-01-05" });
    expect(one.body.items.map((o) => o.key)).toEqual([seededKey, archiveKey(day)]);
    expect(one.body.items[0]?.size).toBeGreaterThan(20);
    const range = await list("?from=2027-01-05&to=2027-01-06");
    expect(range.body.items.map((o) => o.key)).toEqual([
      seededKey,
      archiveKey(day),
      archiveKey(nextDay),
    ]);
    expect((await list("?from=2027-01-07&to=2027-01-10")).body.items).toEqual([]);
    for (const query of [
      "",
      "?from=2027-1-5",
      "?from=2027-01-06&to=2027-01-05",
      "?from=2027-01-01&to=2027-02-15",
      "?from=2027-01-05&extra=1",
      "?from=2027-01-05&from=2027-01-06",
    ]) {
      expect((await list(query)).status, query).toBe(400);
    }
    // R2 pages: a bucket that hands the keys back one at a time.
    const paged = {
      ...env,
      AUDIT_BUCKET: {
        list: async (options: { prefix: string; cursor?: string }) => {
          const listed = await env.AUDIT_BUCKET.list({ prefix: options.prefix });
          const index = options.cursor === undefined ? 0 : Number(options.cursor);
          const object = listed.objects[index];
          return {
            objects: object === undefined ? [] : [object],
            truncated: index + 1 < listed.objects.length,
            cursor: String(index + 1),
          };
        },
      },
    } as unknown as Env;
    const walked = await admin(h, token, "audit/archive?from=2027-01-05&to=2027-01-06", {
      env: paged,
    });
    expect(((await walked.json()) as { items: { key: string }[] }).items.map((o) => o.key)).toEqual(
      [seededKey, archiveKey(day), archiveKey(nextDay)],
    );
    const down = {
      ...env,
      AUDIT_BUCKET: {
        list: async () => {
          throw new Error("bucket down");
        },
      },
    } as unknown as Env;
    expect((await admin(h, token, "audit/archive?from=2027-01-05", { env: down })).status).toBe(
      503,
    );
  });
});

describe("a person's events", () => {
  it("[TIO-AUDIT-010] the Admin and Self-service views show one user's events within the hot retention window, newest first, with only the §8 fields", async () => {
    const stale = event({
      ts: clock.now() - 31 * 86_400,
      type: "session.created",
      user_id: alice.profile.id,
    });
    const fresh = event({
      ts: clock.now() - 60,
      type: "session.created",
      user_id: alice.profile.id,
      client_id: "web",
    });
    await ingest([stale, fresh]);
    const viaAdmin = (await (
      await admin(h, token, `users/${alice.profile.id}/events`)
    ).json()) as Page<Record<string, unknown>>;
    // The seeded listing above holds six of alice's events too; the stale one is out of the window.
    expect(viaAdmin.items).toHaveLength(7);
    expect(viaAdmin.items[0]).toEqual({
      id: fresh.id,
      type: "session.created",
      ts: fresh.ts,
      outcome: "success",
      client_id: "web",
      country: "BR",
      ua_family: "Chrome/128",
    });
    expect(viaAdmin.items.some((e) => e["id"] === stale.id)).toBe(false);
    expect((await admin(h, token, `users/${alice.profile.id}/events?limit=x`)).status).toBe(400);
    expect((await admin(h, token, `users/${alice.profile.id}/events?type=x`)).status).toBe(400);
    expect((await admin(h, token, `users/${alice.profile.id}/events?limit=1&limit=2`)).status).toBe(
      400,
    );
    const page1 = (await (
      await admin(h, token, `users/${alice.profile.id}/events?limit=4`)
    ).json()) as Page<{ id: string }>;
    expect(page1.items).toHaveLength(4);
    const page2 = (await (
      await admin(h, token, `users/${alice.profile.id}/events?limit=4&cursor=${page1.next_cursor}`)
    ).json()) as Page<{ id: string }>;
    expect(page2.items).toHaveLength(3);
    expect(page2.next_cursor).toBeNull();
    // A wider window brings the stale event back.
    await writeSettings(db, { "audit.hot_retention_days": 60 }, "test", clock.now());
    clock.advance(61);
    const wider = (await (
      await admin(h, token, `users/${alice.profile.id}/events?limit=200`)
    ).json()) as Page<{ id: string }>;
    expect(wider.items.some((e) => e.id === stale.id)).toBe(true);
    await writeSettings(db, { "audit.hot_retention_days": null }, "test", clock.now());
    clock.advance(61);
    // Storage trouble on the events and on the settings.
    expect(
      (
        await admin(h, token, `users/${alice.profile.id}/events`, {
          env: { ...env, DB: failingD1(/FROM audit_hot/) } as Env,
        })
      ).status,
    ).toBe(503);
    const blind = harness(clock);
    const operator = await adminUser(blind);
    const noSettings = await blind.send(`/api/v1/admin/users/${alice.profile.id}/events`, {
      origin: null,
      headers: { authorization: `Bearer ${operator.access_token}` },
      env: { ...env, DB: brokenD1 } as Env,
    });
    // The guard needs keys first: a dead directory is 503 either way.
    expect(noSettings.status).toBe(503);
    // An app that has never read the settings, with the settings table failing.
    const settingsOnly = await harness(clock).send(
      `/api/v1/admin/users/${alice.profile.id}/events`,
      {
        origin: null,
        headers: { authorization: `Bearer ${operator.access_token}` },
        env: { ...env, DB: failingD1(/FROM settings/) } as Env,
      },
    );
    expect(settingsOnly.status).toBe(503);
    expect(await settingsOnly.json()).toMatchObject({ error_description: "settings unavailable" });
    // Self-service: the person's own token sees the same list.
    const own = await (async () => {
      const started = await h.start(operator.client, { scope: "openid account" });
      const { publicKey } = (await (await h.post(started, "passkey/options", {})).json()) as {
        publicKey: Parameters<typeof alice.authenticator.authenticate>[0];
      };
      expect(
        (
          await h.post(started, "passkey/verify", {
            response: await alice.authenticator.authenticate(
              publicKey,
              "https://login.example.com",
            ),
          })
        ).status,
      ).toBe(200);
      const complete = await h.send(`/interactions/${started.id}/complete`, {
        origin: null,
        cookie: started.cookie,
      });
      const code = new URL(complete.headers.get("location") as string).searchParams.get("code");
      const tokens = (await (
        await h.send("/token", {
          method: "POST",
          origin: null,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: operator.client.client_id,
            code: code as string,
            redirect_uri: "https://rp.example.com/cb",
            code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
          }).toString(),
        })
      ).json()) as { access_token: string };
      return tokens.access_token;
    })();
    const mine = (await (
      await h.send("/api/v1/me/events?limit=3", {
        origin: null,
        headers: { authorization: `Bearer ${own}` },
      })
    ).json()) as Page<Record<string, unknown>>;
    expect(mine.items).toHaveLength(3);
    expect(mine.items[0]).toEqual(viaAdmin.items[0]);
    expect(Object.keys(mine.items[0] as object).sort()).toEqual(
      ["client_id", "country", "id", "outcome", "ts", "type", "ua_family"].sort(),
    );
    expect(mine.next_cursor).not.toBeNull();
  });
});
