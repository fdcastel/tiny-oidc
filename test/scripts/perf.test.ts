import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  chunks,
  codeOf,
  cookieNamed,
  interactionOf,
  percentiles,
  pkce,
  pool,
  RateLimiter,
} from "../../perf/lib/flow.ts";
import {
  DEFAULT_POPULATION,
  emailOf,
  type Population,
  seedBatch,
  seedLine,
  subjectOf,
} from "../../perf/lib/lines.ts";

// The load harness (spec §13.10, TIO-TEST-050, TIO-ADMIN-021): the population
// generator and the pure helpers behind perf/seed.ts. The HTTP flows themselves
// run against staging in the nightly job.

describe("perf population", () => {
  const p: Population = {
    seed: "s",
    groups: ["staff"],
    identities: 2,
    issuer: "https://idp.example.com",
  };

  it("is deterministic: the same seed and number give the same email, subject and line, with the identities at issuer and issuer/1", () => {
    expect(emailOf(p, 7)).toBe("user-s-7@example.com");
    expect(subjectOf(p, 7)).toBe("sub-s-7");
    expect(JSON.parse(seedLine(p, 7))).toEqual({
      email: "user-s-7@example.com",
      email_verified: true,
      display_name: "User s-7",
      groups: ["staff"],
      identities: [
        { issuer: "https://idp.example.com", subject: "sub-s-7" },
        { issuer: "https://idp.example.com/1", subject: "sub-s-7" },
      ],
    });
    expect(seedLine(p, 7)).toBe(seedLine(p, 7));
    expect(seedLine(DEFAULT_POPULATION, 0)).toContain('"groups":[]');
  });

  it("writes a batch as NDJSON with a trailing newline, one line per user in order", () => {
    const batch = seedBatch(p, 10, 3);
    const lines = batch.split("\n");
    expect(lines).toHaveLength(4);
    expect(lines[3]).toBe("");
    expect(lines.slice(0, 3).map((l) => (JSON.parse(l) as { email: string }).email)).toEqual([
      "user-s-10@example.com",
      "user-s-11@example.com",
      "user-s-12@example.com",
    ]);
  });
});

describe("perf flow helpers", () => {
  it("makes S256 PKCE pairs", () => {
    const { verifier, challenge } = pkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
  });

  it("reads the OP's cookies and redirects", () => {
    const setCookies = [
      "__Host-tio_ix_abc=tio_ix_secret; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
      "__Host-tio_session=tio_ss_secret; Path=/; Secure; HttpOnly; SameSite=Lax",
    ];
    expect(cookieNamed(setCookies, "__Host-tio_ix_")).toBe("__Host-tio_ix_abc=tio_ix_secret");
    expect(cookieNamed(setCookies, "__Host-tio_session=")).toBe("__Host-tio_session=tio_ss_secret");
    expect(cookieNamed(setCookies, "other")).toBeNull();
    expect(interactionOf("https://login.example.com/?interaction=abc123")).toBe("abc123");
    expect(interactionOf("https://login.example.com/?error=x")).toBeNull();
    expect(interactionOf("not a url")).toBeNull();
    expect(interactionOf(null)).toBeNull();
    expect(codeOf("https://rp.example.com/cb?code=tio_ac_x&state=s")).toEqual({ code: "tio_ac_x" });
    expect(codeOf("https://rp.example.com/cb?error=access_denied&error_description=no")).toEqual({
      error: "access_denied",
      description: "no",
    });
    expect(codeOf("https://rp.example.com/cb")).toBeNull();
    expect(codeOf("::")).toBeNull();
    expect(codeOf(null)).toBeNull();
  });

  it("chunks a range, runs a bounded pool in input order and paces a rate limiter", async () => {
    expect(chunks(5, 7, 3)).toEqual([
      { from: 5, count: 3 },
      { from: 8, count: 3 },
      { from: 11, count: 1 },
    ]);
    expect(chunks(0, 0, 3)).toEqual([]);
    // Workers finish only when released, so the concurrency bound is observable.
    const release: (() => void)[] = [];
    const started: number[] = [];
    const running = pool([1, 2, 3, 4, 5], 2, (n) => {
      started.push(n);
      return new Promise<number>((resolve) => release.push(() => resolve(n * 10)));
    });
    await Promise.resolve();
    expect(started).toEqual([1, 2]);
    (release.shift() as () => void)();
    await Promise.resolve();
    await Promise.resolve();
    expect(started).toEqual([1, 2, 3]);
    while (release.length > 0) {
      (release.shift() as () => void)();
      await Promise.resolve();
      await Promise.resolve();
    }
    expect(await running).toEqual([10, 20, 30, 40, 50]);
    expect(await pool([], 4, async () => 1)).toEqual([]);
    // The pacer sleeps exactly the gap to the next slot, on the caller's clock.
    const slept: number[] = [];
    const limiter = new RateLimiter(10, async (ms) => {
      slept.push(ms);
    });
    expect(await limiter.acquire(1_000)).toBe(0);
    expect(await limiter.acquire(1_000)).toBe(100);
    expect(await limiter.acquire(1_000)).toBe(200);
    expect(await limiter.acquire(1_500)).toBe(0);
    expect(slept).toEqual([100, 200]);
    expect(await new RateLimiter(0).acquire()).toBe(0);
  });

  it("computes nearest-rank percentiles", () => {
    expect(percentiles([])).toEqual({ count: 0, p50: 0, p99: 0, max: 0 });
    const samples = Array.from({ length: 100 }, (_, i) => 100 - i);
    expect(percentiles(samples)).toEqual({ count: 100, p50: 50, p99: 99, max: 100 });
    expect(percentiles([7])).toEqual({ count: 1, p50: 7, p99: 7, max: 7 });
  });

  it("is what the nightly job runs: the seed CLI names every subcommand and the load job calls them", () => {
    const cli = readFileSync("perf/seed.ts", "utf8");
    for (const command of ["generate", "prepare", "import", "harvest"]) {
      expect(cli).toContain(`node perf/seed.ts ${command}`);
    }
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    expect(nightly).toContain("perf/seed.ts prepare");
    expect(nightly).toContain("perf/seed.ts import");
    expect(nightly).toContain("perf/seed.ts harvest");
  });
});
