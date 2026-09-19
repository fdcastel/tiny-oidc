import { afterEach, describe, expect, it, vi } from "vitest";
import { systemClock } from "../../src/env.ts";

describe("systemClock", () => {
  afterEach(() => vi.useRealTimers());

  it("reports whole seconds and milliseconds from the system time", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_790_000_000_500));
    expect(systemClock.nowMs()).toBe(1_790_000_000_500);
    expect(systemClock.now()).toBe(1_790_000_000);
    expect(systemClock.nowDate().getTime()).toBe(1_790_000_000_500);
  });
});
