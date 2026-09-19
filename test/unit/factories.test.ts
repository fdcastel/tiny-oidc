import { describe, expect, it } from "vitest";
import { FakeClock } from "../support/clock.ts";
import { unique, userProfile } from "../support/factories.ts";

describe("factories", () => {
  it("produce unique names and normalized profiles with fresh UUID v7 ids", () => {
    expect(unique("a")).not.toBe(unique("a"));
    const clock = new FakeClock();
    const p = userProfile(clock, { email: "  Bob@Example.COM " });
    expect(p.email_norm).toBe("bob@example.com");
    expect(p.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(p.groups).toEqual([]);
    expect(p.email_verified).toBe(false);
    const q = userProfile(clock);
    expect(q.email).toMatch(/^user-[0-9a-z]+@example\.com$/);
    expect(q.id).not.toBe(p.id);
  });
});
