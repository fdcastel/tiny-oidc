import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../../src/audit/events.ts";
import type { RequestLog } from "../../src/obs/log.ts";
import { metricPoints, writeMetrics } from "../../src/obs/metrics.ts";

// Analytics Engine points (TIO-OBS-002): events of one type and outcome fold
// into one point with the count, so a bulk import's thousands of events stay
// under the binding's per-invocation write limit.

const line: RequestLog = {
  request_id: "r",
  route: "/api/v1/admin/import/users",
  method: "POST",
  status: 200,
  duration_ms: 1234,
  do_calls: 0,
  d1_reads: 2,
  d1_writes: 10,
  content_length: 100,
};

const event = (type: string, outcome: "success" | "failure"): AuditEvent =>
  ({ type, outcome }) as unknown as AuditEvent;

describe("metric points", () => {
  it("emit the request, then one point per event type and outcome carrying the count, in first-seen order", () => {
    const events = [
      event("user.created", "success"),
      event("identity.linked", "success"),
      event("identity.linked", "success"),
      event("user.created", "success"),
      event("user.created", "failure"),
    ];
    expect(metricPoints(line, events)).toEqual([
      {
        blobs: ["/api/v1/admin/import/users", "200", ""],
        doubles: [1234],
        indexes: ["/api/v1/admin/import/users"],
      },
      { blobs: ["user.created", "success"], doubles: [2], indexes: ["user.created"] },
      { blobs: ["identity.linked", "success"], doubles: [2], indexes: ["identity.linked"] },
      { blobs: ["user.created", "failure"], doubles: [1], indexes: ["user.created"] },
    ]);
    expect(metricPoints({ ...line, error: "invalid_request" }, [])).toEqual([
      {
        blobs: ["/api/v1/admin/import/users", "200", "invalid_request"],
        doubles: [1234],
        indexes: ["/api/v1/admin/import/users"],
      },
    ]);
  });

  it("write every point and turn a refused write into one warning", () => {
    const written: unknown[] = [];
    const logged: unknown[] = [];
    const logger = {
      log: (level: string, msg: string, fields: unknown) => logged.push({ level, msg, fields }),
    };
    const points = metricPoints(line, [event("user.created", "success")]);
    writeMetrics(
      { writeDataPoint: (p: unknown) => written.push(p) } as unknown as AnalyticsEngineDataset,
      points,
      logger as never,
      "r",
    );
    expect(written).toEqual(points);
    writeMetrics(
      {
        writeDataPoint: () => {
          throw new Error("Analytics Engine write limit exceeded.");
        },
      } as unknown as AnalyticsEngineDataset,
      points,
      logger as never,
      "r",
    );
    expect(logged).toEqual([
      {
        level: "warn",
        msg: "metrics write failed",
        fields: { request_id: "r", reason: "Analytics Engine write limit exceeded." },
      },
    ]);
    writeMetrics(
      {
        writeDataPoint: () => {
          throw "not an error";
        },
      } as unknown as AnalyticsEngineDataset,
      points,
      logger as never,
      "r",
    );
    expect(logged[1]).toMatchObject({ fields: { reason: "not an error" } });
  });
});
