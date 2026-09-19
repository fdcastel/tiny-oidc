import { createExecutionContext, createScheduledController } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import type { Env } from "../../src/env.ts";
import worker from "../../src/index.ts";
import { createScheduled } from "../../src/maintenance/scheduled.ts";
import type { LogLine } from "../../src/obs/log.ts";
import { FakeClock } from "../support/clock.ts";
import { env } from "../support/op.ts";
import { brokenD1 } from "./faults.ts";

// The cron trigger (spec §12.4, TIO-CFG-010): the maintenance body runs as
// the system actor and leaves one log line and one audit event; failures are
// logged, never thrown.

const clock = new FakeClock(1_800_000_000);
const lines: LogLine[] = [];
const scheduled = createScheduled({ clock, sink: (line) => lines.push(line) });

const run = (testEnv: Env = env) =>
  scheduled(
    createScheduledController({ cron: "*/5 * * * *", scheduledTime: clock.nowMs() }),
    testEnv,
    createExecutionContext(),
  );

describe("scheduled()", () => {
  it("[TIO-CFG-010] runs the maintenance body every trigger as the system actor, logging the report and a system.cron_run event", async () => {
    await run();
    const line = lines.find((l) => l["msg"] === "cron") as LogLine;
    expect(line).toMatchObject({
      level: "info",
      cron: "*/5 * * * *",
      scheduled_time: clock.nowMs(),
      audit_rows_purged: 0,
      skipped: [],
      keys: { created: null, retired: [], deleted: 0 },
    });
    const event = lines.find((l) => l["msg"] === "audit")?.["event"] as AuditEvent;
    expect(event).toMatchObject({
      type: "system.cron_run",
      outcome: "success",
      actor: { kind: "system", id: null },
      request_id: line["run_id"],
      ip_hash: null,
    });
    // The worker's default export carries the same handler.
    expect(typeof worker.scheduled).toBe("function");
    await worker.scheduled(createScheduledController(), env, createExecutionContext());
  });

  it("[TIO-CFG-010] logs and returns when the configuration is invalid or storage fails; the next trigger tries again", async () => {
    lines.length = 0;
    await run({ ...env, MASTER_KEYS: "not json" } as Env);
    expect(lines).toEqual([
      expect.objectContaining({ level: "error", msg: "cron skipped: invalid configuration" }),
    ]);
    lines.length = 0;
    await run({ ...env, DB: brokenD1 } as Env);
    expect(lines.map((l) => l["msg"])).toEqual(["cron failed"]);
    expect(lines[0]).toMatchObject({ level: "error", reason: expect.stringContaining("D1 down") });
    lines.length = 0;
    await run();
    expect(lines.map((l) => l["msg"])).toEqual(["cron", "audit"]);
  });
});
