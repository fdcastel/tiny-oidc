import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { type AuditEvent, Auditor } from "../../src/audit/events.ts";
import {
  AUDIT_BATCH_SIZE,
  AUDIT_ROWS_PER_STATEMENT,
  archiveKey,
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
// request's events after the response, the consumer writes them to
// `audit_hot` and the R2 archive and acknowledges only then, and a
// redelivered batch changes nothing (TIO-DATA-025).

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
  it("[TIO-AUDIT-011] [TIO-DATA-025] writes a batch to audit_hot and to R2 as gzip NDJSON under a key derived from the first event, acknowledges only then, and a redelivery changes nothing", async () => {
    const { lines, logger } = sink();
    const consume = createQueue({ clock, sink: (line) => lines.push(line) });
    const events = synthetic(23, 1_800_003_661);
    const { batch, calls } = batchOf([{ kind: "audit", events }]);
    const shipped: Sent[] = [];
    await consume(batch, recordingEnv(shipped), createExecutionContext());
    expect(calls).toEqual(["ack:m0"]);
    const rows = await db
      .prepare("SELECT id, type, user_id, sid, country, ua_family, data FROM audit_hot ORDER BY id")
      .all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(23);
    expect(rows.results[0]).toMatchObject({
      id: events[0]?.id,
      type: "session.created",
      user_id: "u0",
      sid: "s0",
      country: "BR",
      ua_family: "Chrome/128",
      data: JSON.stringify({ amr: ["hwk"], acr: "a", upstream: null }),
    });
    const key = archiveKey(events[0] as AuditEvent);
    expect(key).toBe(`audit/2027/01/15/09/${events[0]?.id}.ndjson.gz`);
    const object = await env.AUDIT_BUCKET.get(key);
    expect(object).not.toBeNull();
    expect(object?.httpMetadata).toMatchObject({
      contentType: "application/x-ndjson",
      contentEncoding: "gzip",
    });
    const text = await gunzip(await (object as R2ObjectBody).arrayBuffer());
    const parsed = text
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
    expect(parsed).toEqual(events);
    // Redelivered: the same rows and the same object.
    const again = batchOf([{ kind: "audit", events }]);
    await consume(again.batch, recordingEnv(shipped), createExecutionContext());
    expect(again.calls).toEqual(["ack:m0"]);
    const count = await db.prepare("SELECT COUNT(*) AS n FROM audit_hot").first<{ n: number }>();
    expect(count?.n).toBe(23);
    expect(lines.filter((l) => l["msg"] === "audit batch archived")).toHaveLength(2);
    expect(logger).toBeDefined();
  });

  it("[TIO-AUDIT-011] a batch is retried when D1 or R2 fails, and a batch nobody can read is dropped", async () => {
    const lines: LogLine[] = [];
    const consume = createQueue({ clock, sink: (line) => lines.push(line) });
    const events = synthetic(2, 1_800_010_000);
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
    // The rows written before the R2 failure are harmless: the retry ignores duplicates.
    expect(await env.AUDIT_BUCKET.get(archiveKey(events[0] as AuditEvent))).toBeNull();
    const malformed = batchOf([{ kind: "audit", events: [] }, { kind: "audit" }]);
    await consume(malformed.batch, env, createExecutionContext());
    expect(malformed.calls).toEqual(["ack:m0", "ack:m1"]);
    expect(lines.filter((l) => l["msg"] === "malformed audit batch dropped")).toHaveLength(2);
  });
});
