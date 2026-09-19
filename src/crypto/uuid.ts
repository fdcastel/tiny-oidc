import { UUID, V7Generator } from "uuidv7";
import type { Clock } from "../env.ts";

// UUID v7 identifiers (TIO-DATA-001, TIO-DATA-002): time-ordered, monotonic
// within an isolate, timestamped from the injected clock so tests control them.

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Monotonic UUID v7 generator bound to a clock. One per isolate in production, one per test when injected. */
export class UuidV7 {
  private readonly generator = new V7Generator();
  private readonly clock: Clock;

  constructor(clock: Clock) {
    this.clock = clock;
  }

  /** A new lowercase 36-character UUID v7 string. */
  next(): string {
    return this.generator.generateOrResetWithTs(this.clock.nowMs()).toString();
  }
}

/** The 16 raw bytes of a lowercase UUID string, or null when the string is not a UUID. */
export function uuidToBytes(uuid: string): Uint8Array | null {
  if (!UUID_PATTERN.test(uuid)) return null;
  return UUID.parse(uuid).bytes.slice();
}

export function bytesToUuid(bytes: Uint8Array): string {
  return UUID.ofInner(bytes).toString();
}

export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}
