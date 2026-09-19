import type { AuditEvent } from "../audit/events.ts";
import type { Logger, RequestLog } from "./log.ts";

// Analytics Engine data points (TIO-OBS-002): one per request, and one per
// audit event type and outcome the request emitted, carrying the count. A
// bulk import emits thousands of events in one request and the binding
// refuses writes past its per-invocation limit, so events are aggregated and
// a refused write is logged, never surfaced.

export interface DataPoint {
  blobs: string[];
  doubles: number[];
  indexes: string[];
}

/** The points of one request: the request itself, then the event counts in first-seen order. */
export function metricPoints(line: RequestLog, events: readonly AuditEvent[]): DataPoint[] {
  const points: DataPoint[] = [
    {
      blobs: [line.route, String(line.status), line.error ?? ""],
      doubles: [line.duration_ms],
      indexes: [line.route],
    },
  ];
  const counts = new Map<string, { type: string; outcome: string; count: number }>();
  for (const event of events) {
    const key = `${event.type}\u0000${event.outcome}`;
    const entry = counts.get(key) ?? { type: event.type, outcome: event.outcome, count: 0 };
    entry.count++;
    counts.set(key, entry);
  }
  for (const { type, outcome, count } of counts.values()) {
    points.push({ blobs: [type, outcome], doubles: [count], indexes: [type] });
  }
  return points;
}

/** Writes the points; a refused write is a warning in the log and nothing else. */
export function writeMetrics(
  binding: AnalyticsEngineDataset,
  points: DataPoint[],
  logger: Logger,
  requestId: string,
): void {
  try {
    for (const point of points) binding.writeDataPoint(point);
  } catch (error) {
    logger.log("warn", "metrics write failed", {
      request_id: requestId,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}
