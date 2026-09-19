// Structured logging (TIO-OBS-001): one JSON line per request, written to
// console. The sink is injectable so tests capture lines instead of stdout.

export type LogLevel = "debug" | "info" | "warn" | "error";

const RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LogLine {
  level: LogLevel;
  msg: string;
  [key: string]: unknown;
}

export type LogSink = (line: LogLine) => void;

export const consoleSink: LogSink = (line) => {
  console.log(JSON.stringify(line));
};

export class Logger {
  private readonly sink: LogSink;
  private readonly minimum: number;

  constructor(sink: LogSink, minimum: LogLevel) {
    this.sink = sink;
    this.minimum = RANK[minimum];
  }

  log(level: LogLevel, msg: string, fields: Record<string, unknown>): void {
    if (RANK[level] < this.minimum) return;
    this.sink({ level, msg, ...fields });
  }
}

/** Fields of the per-request line. No query strings, bodies or headers other than content-length. */
export interface RequestLog {
  request_id: string;
  route: string;
  method: string;
  status: number;
  duration_ms: number;
  do_calls: number;
  d1_reads: number;
  d1_writes: number;
  content_length: number | null;
  /** Set by the token endpoint once the client is authenticated (Phase 2). */
  client_id?: string;
  error?: string;
}
