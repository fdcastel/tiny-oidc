import type { Clock } from "../../src/env.ts";

/**
 * The instant the fake clock starts at: 2033-05-18T03:33:20Z, well ahead of
 * real time. The two must not cross: workerd fires a Durable Object alarm set
 * at a fake instant that real time has passed, and the Worker under test
 * reached through `op()` runs on the real clock, so a signing key it creates
 * activates at real time and is "not yet active" for a fake clock behind it.
 * The original base (1_790_000_000, 2026-09-21) broke five tests the morning
 * real time passed it.
 */
export const FAKE_EPOCH = 2_000_000_000;

/** A clock tests advance explicitly (TIO-TEST-005). Starts at a fixed instant. */
export class FakeClock implements Clock {
  private ms: number;

  constructor(startSeconds = FAKE_EPOCH) {
    this.ms = startSeconds * 1000;
  }

  now(): number {
    return Math.floor(this.ms / 1000);
  }

  nowMs(): number {
    return this.ms;
  }

  nowDate(): Date {
    return new Date(this.ms);
  }

  /** Moves the clock forward by `seconds` (may be fractional). */
  advance(seconds: number): void {
    this.ms += Math.round(seconds * 1000);
  }

  set(seconds: number): void {
    this.ms = seconds * 1000;
  }
}
