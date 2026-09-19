import type { Clock } from "../../src/env.ts";

/** A clock tests advance explicitly (TIO-TEST-005). Starts at a fixed instant. */
export class FakeClock implements Clock {
  private ms: number;

  constructor(startSeconds = 1_790_000_000) {
    this.ms = startSeconds * 1000;
  }

  now(): number {
    return Math.floor(this.ms / 1000);
  }

  nowMs(): number {
    return this.ms;
  }

  /** Moves the clock forward by `seconds` (may be fractional). */
  advance(seconds: number): void {
    this.ms += Math.round(seconds * 1000);
  }

  set(seconds: number): void {
    this.ms = seconds * 1000;
  }
}
