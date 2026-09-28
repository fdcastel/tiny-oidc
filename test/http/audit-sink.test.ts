import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { isHotType } from "../../src/audit/catalog.ts";
import { type AuditEvent, Auditor } from "../../src/audit/events.ts";
import {
  AUDIT_BATCH_SIZE,
  AUDIT_ROWS_PER_STATEMENT,
  archiveDayPrefix,
  shipAuditEvents,
} from "../../src/audit/sink.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Db } from "../../src/db/db.ts";
import type { Env } from "../../src/env.ts";
import { Logger, type LogLine } from "../../src/obs/log.ts";
import { createQueue } from "../../src/queue/consumer.ts";
import { FakeClock } from "../support/clock.ts";
import { harness } from "../support/http.ts";
import { env } from "../support/op.ts";
import { brokenD1, failingD1 } from "./faults.ts";

// The queue sink of audit events (spec §11.3): the producer ships each
// request's events after the response, the consumer writes
// the hot ones to `audit_hot` and all of them to the R2 archive and
// acknowledges only then, and a redelivered batch adds no row and
// overwrites no object (TIO-AUDIT-013, TIO-DATA-025).

const clock = new FakeClock(1_800_000_000);
const db = Db.from(env.DB);

interface Sent {
  body: unknown;
}

function recordingEnv(sent: Sent[], failing = false): Env {
  return {
    ...env,
    TASKS: {
      send: async (body: unknown) => {
        if (failing) throw new Error("queue down");
        sent.push({ body });
      },
    },
  } as unknown as Env;
}

function sink() {
  const lines: LogLine[] = [];
  return { lines, logger: new Logger((line) => lines.push(line), "debug") };
}

function synthetic(count: number, at = clock.now()): AuditEvent[] {
  const auditor = new Auditor(
    { request_id: "r", ip_hash: null, country: "BR", ua_family: "Chrome/128" },
    new UuidV7(clock),
    clock,
  );
  return Array.from({ length: count }, (_, i) =>
    auditor.emit({
      type: i % 2 === 0 ? "session.created" : "logout.rp_initiated",
      outcome: "success",
      actor: { kind: "user", id: `u${i}` },
      user_id: `u${i}`,
      client_id: "web",
      sid: `s${i}`,
      reason: null,
      data:
        i % 2 === 0 ? { amr: ["hwk"], acr: "a", upstream: null } : { registered_redirect: true },
    }),
  ).map((e) => ({ ...e, ts: at }));
}

function batchOf(bodies: unknown[]) {
  const calls: string[] = [];
  const batch = {
    queue: "tiny-oidc-tasks",
    messages: bodies.map((body, i) => ({
      id: `m${i}`,
      timestamp: clock.nowDate(),
      body,
      attempts: 1,
      ack: () => calls.push(`ack:m${i}`),
      retry: () => calls.push(`retry:m${i}`),
    })),
    ackAll: () => calls.push("ackAll"),
    retryAll: () => calls.push("retryAll"),
  } as unknown as MessageBatch<unknown>;
  return { batch, calls };
}

async function gunzip(bytes: ArrayBuffer): Promise<string> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}

describe("the producer", () => {
  it("[TIO-AUDIT-010] [TIO-AUDIT-012] ships a request's events to the queue after the response in batches of 50, and a queue that refuses them is logged while the request succeeds", async () => {
    const h = harness(clock);
    const sent: Sent[] = [];
    const res = await h.send("/api/v1/health", { origin: null, env: recordingEnv(sent) });
    expect(res.status).toBe(200);
    // A health check emits nothing; a rate-limited request does.
    expect(sent).toEqual([]);
    const { lines, logger } = sink();
    await shipAuditEvents(recordingEnv(sent), logger, synthetic(120));
    expect(sent.map((s) => (s.body as { events: unknown[] }).events.length)).toEqual([50, 50, 20]);
    expect(sent.every((s) => (s.body as { kind: string }).kind === "audit")).toBe(true);
    await shipAuditEvents(recordingEnv([], true), logger, synthetic(3));
    expect(lines.at(-1)).toMatchObject({
      level: "error",
      msg: "audit batch could not be queued",
      events: 3,
      reason: "Error: queue down",
    });
    // Through the app: the request answers before its events leave, and a dead queue changes nothing.
    const throttled = harness(clock);
    const ip = "203.0.113.150";
    const first = await throttled.send("/token", {
      method: "POST",
      origin: null,
      headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ip },
      body: "grant_type=client_credentials",
      env: recordingEnv([], true),
    });
    expect(first.status).toBe(401);
    expect(throttled.lines.find((l) => l["msg"] === "request")).toMatchObject({ status: 401 });
    expect(
      throttled.lines.find((l) => l["msg"] === "audit batch could not be queued"),
    ).toMatchObject({ events: 1 });
    expect(AUDIT_BATCH_SIZE).toBe(50);
    expect(AUDIT_ROWS_PER_STATEMENT).toBeLessThanOrEqual(9);
    expect(AUDIT_ROWS_PER_STATEMENT * 17).toBeLessThanOrEqual(100);
  });
});

describe("the consumer", () => {
  /** Every archived event under a prefix, deduplicated by id as the archive's readers do. */
  async function archived(prefix: string): Promise<{ keys: string[]; events: AuditEvent[] }> {
    const listed = await env.AUDIT_BUCKET.list({ prefix });
    const byId = new Map<string, AuditEvent>();
    for (const object of listed.objects) {
      const body = await env.AUDIT_BUCKET.get(object.key);
      const text = await gunzip(await (body as R2ObjectBody).arrayBuffer());
      for (const line of text.trimEnd().split("\n")) {
        const event = JSON.parse(line) as AuditEvent;
        byId.set(event.id, event);
      }
    }
    return { keys: listed.objects.map((o) => o.key), events: [...byId.values()] };
  }

  const mixed = (count: number, at: number) =>
    synthetic(count, at).map((e, i) =>
      i % 3 === 2
        ? { ...e, type: "token.refreshed", data: { scopes: ["openid"], kind: "offline" } }
        : e,
    );

  it("[TIO-AUDIT-011] [TIO-AUDIT-013] [TIO-DATA-025] writes a queue batch's hot events to audit_hot and all of its events to one R2 object under a Hive-style key unique to the write, acknowledges only then; a redelivery adds no row and lands under a new key", async () => {
    const { lines, logger } = sink();
    const consume = createQueue({ clock, sink: (line) => lines.push(line) });
    const at = 1_800_003_661;
    const first = mixed(23, at);
    const second = mixed(7, at);
    const { batch, calls } = batchOf([
      { kind: "audit", events: first },
      { kind: "audit", events: second },
    ]);
    await consume(batch, recordingEnv([]), createExecutionContext());
    expect(calls).toEqual(["ack:m0", "ack:m1"]);
    const all = [...first, ...second];
    const hot = all.filter((e) => isHotType(e.type));
    expect(hot.length).toBeLessThan(all.length);
    const rows = await db
      .prepare("SELECT id, type, user_id, sid, country, ua_family, data FROM audit_hot ORDER BY id")
      .all<Record<string, unknown>>();
    // Only the hot types reach the table (token.refreshed is archive-only).
    expect(rows.results.map((r) => r["id"]).sort()).toEqual(hot.map((e) => e.id).sort());
    expect(rows.results.some((r) => r["type"] === "token.refreshed")).toBe(false);
    expect(rows.results[0]).toMatchObject({
      id: first[0]?.id,
      type: "session.created",
      user_id: "u0",
      sid: "s0",
      country: "BR",
      ua_family: "Chrome/128",
      data: JSON.stringify({ amr: ["hwk"], acr: "a", upstream: null }),
    });
    const prefix = archiveDayPrefix("2027-01-15");
    expect(prefix).toBe("audit/year=2027/month=01/day=15/");
    const once = await archived(prefix);
    expect(once.keys).toHaveLength(1);
    expect(once.keys[0]).toMatch(
      new RegExp(
        `^audit/year=2027/month=01/day=15/hour=09/${first[0]?.id}-[0-9a-f-]{36}\\.ndjson\\.gz$`,
      ),
    );
    const object = await env.AUDIT_BUCKET.get(once.keys[0] as string);
    expect(object?.httpMetadata).toMatchObject({
      contentType: "application/x-ndjson",
      contentEncoding: "gzip",
    });
    expect(once.events).toEqual(all);
    expect(lines.find((l) => l["msg"] === "audit batch archived")).toMatchObject({
      messages: 2,
      events: all.length,
      hot: hot.length,
    });
    // Redelivered: no new row, a second object under a new key, the same events once deduplicated.
    const again = batchOf([{ kind: "audit", events: first }]);
    await consume(again.batch, recordingEnv([]), createExecutionContext());
    expect(again.calls).toEqual(["ack:m0"]);
    const count = await db.prepare("SELECT COUNT(*) AS n FROM audit_hot").first<{ n: number }>();
    expect(count?.n).toBe(hot.length);
    const twice = await archived(prefix);
    expect(twice.keys).toHaveLength(2);
    expect(twice.events).toHaveLength(all.length);
    expect(logger).toBeDefined();
  });

  it("[TIO-DATA-025] under a bucket that refuses to rewrite an object (a bucket lock, R2 error 10069), redeliveries and regrouped batches are all archived", async () => {
    const locked = {
      ...env,
      AUDIT_BUCKET: {
        put: async (key: string, value: Uint8Array, options: R2PutOptions) => {
          if ((await env.AUDIT_BUCKET.head(key)) !== null) {
            throw new Error("put: Object is protected by a bucket lock rule (10069)");
          }
          return env.AUDIT_BUCKET.put(key, value, options);
        },
      },
    } as unknown as Env;
    const consume = createQueue({ clock, sink: () => {} });
    const at = 1_800_090_000;
    const a = synthetic(4, at);
    const b = synthetic(3, at);
    const first = batchOf([{ kind: "audit", events: a }]);
    await consume(first.batch, locked, createExecutionContext());
    // The same first message regrouped with another: a new key, nothing refused.
    const regrouped = batchOf([
      { kind: "audit", events: a },
      { kind: "audit", events: b },
    ]);
    await consume(regrouped.batch, locked, createExecutionContext());
    expect([...first.calls, ...regrouped.calls]).toEqual(["ack:m0", "ack:m0", "ack:m1"]);
    const day = new Date(at * 1000).toISOString().slice(0, 10);
    const { keys, events } = await archived(archiveDayPrefix(day));
    expect(keys).toHaveLength(2);
    expect(events.map((e) => e.id).sort()).toEqual([...a, ...b].map((e) => e.id).sort());
  });

  it("[TIO-AUDIT-011] writes large batches in groups of bounded size, defers groups beyond the per-invocation statement budget, retries a group when D1 or R2 fails, and drops a batch nobody can read", async () => {
    const lines: LogLine[] = [];
    const small = createQueue({
      clock,
      sink: (line) => lines.push(line),
      archiveGroupEvents: 10,
      hotStatementsPerInvocation: 3,
    });
    const at = 1_800_120_000;
    const bodies = [0, 1, 2, 3].map(() => ({ kind: "audit", events: synthetic(6, at) }));
    const grouped = batchOf(bodies);
    await small(grouped.batch, recordingEnv([]), createExecutionContext());
    // 6 events a message, at most 10 a group: four groups of one message; each needs 2 hot
    // statements (3 hot rows of 6), so the budget of 3 admits one group and defers the rest.
    expect(grouped.calls).toEqual(["ack:m0", "retry:m1", "retry:m2", "retry:m3"]);
    expect(
      lines.filter((l) => l["msg"] === "audit group deferred to a later invocation"),
    ).toHaveLength(3);
    // A group of archive-only events needs no statement and no D1 batch.
    const quiet = batchOf([
      {
        kind: "audit",
        events: synthetic(2, at).map((e) => ({ ...e, type: "token.refreshed", data: {} })),
      },
    ]);
    await small(quiet.batch, { ...env, DB: brokenD1 } as Env, createExecutionContext());
    expect(quiet.calls).toEqual(["ack:m0"]);

    const consume = createQueue({ clock, sink: (line) => lines.push(line) });
    const events = synthetic(2, 1_800_150_000);
    const noD1 = batchOf([{ kind: "audit", events }]);
    await consume(noD1.batch, { ...env, DB: brokenD1 } as Env, createExecutionContext());
    expect(noD1.calls).toEqual(["retry:m0"]);
    const insertFails = batchOf([{ kind: "audit", events }]);
    await consume(
      insertFails.batch,
      { ...env, DB: failingD1(/INSERT OR IGNORE INTO audit_hot/, true) } as Env,
      createExecutionContext(),
    );
    expect(insertFails.calls).toEqual(["retry:m0"]);
    const noR2 = batchOf([{ kind: "audit", events }]);
    await consume(
      noR2.batch,
      {
        ...env,
        AUDIT_BUCKET: {
          put: async () => {
            throw new Error("bucket down");
          },
        },
      } as unknown as Env,
      createExecutionContext(),
    );
    expect(noR2.calls).toEqual(["retry:m0"]);
    expect(lines.filter((l) => l["msg"] === "audit batch retried")).toHaveLength(3);
    const malformed = batchOf([{ kind: "audit", events: [] }, { kind: "audit" }]);
    await consume(malformed.batch, env, createExecutionContext());
    expect(malformed.calls).toEqual(["ack:m0", "ack:m1"]);
    expect(lines.filter((l) => l["msg"] === "malformed audit batch dropped")).toHaveLength(2);
  });
});
