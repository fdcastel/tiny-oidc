import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  type K6Summary,
  renderLoadMarkdown,
  type SeedReport,
  thresholdRows,
} from "../../scripts/lib/load-summary.ts";

// The load job's summary (spec §13.10): k6's handleSummary data and the seed
// reports rendered for the job page, failures named.

const summary: K6Summary = {
  metrics: {
    "server_ms{scenario:token_refresh}": {
      values: { "p(99)": 121.456, avg: 40 },
      thresholds: { "p(99)<=150": { ok: true } },
    },
    "http_req_failed{scenario:token_refresh}": {
      values: { rate: 0.002 },
      thresholds: { "rate<0.001": { ok: false } },
    },
    "d1_writes{scenario:token_refresh}": {
      values: { count: 0, rate: 0 },
      thresholds: { "rate<5": { ok: true } },
    },
    http_reqs: { values: { count: 100 } },
  },
};

describe("load summary", () => {
  it("lists every threshold with the measured aggregate the expression names", () => {
    expect(thresholdRows("token_refresh", summary)).toEqual([
      {
        scenario: "token_refresh",
        metric: "d1_writes{scenario:token_refresh}",
        expression: "rate<5",
        ok: true,
        value: 0,
      },
      {
        scenario: "token_refresh",
        metric: "http_req_failed{scenario:token_refresh}",
        expression: "rate<0.001",
        ok: false,
        value: 0,
      },
      {
        scenario: "token_refresh",
        metric: "server_ms{scenario:token_refresh}",
        expression: "p(99)<=150",
        ok: true,
        value: 121.46,
      },
    ]);
  });

  it("renders the seed reports and the threshold table, naming the failures", () => {
    const seeds: SeedReport[] = [
      {
        kind: "import_benchmark",
        users: 1000,
        duration_s: 12.3,
        users_per_s: 81,
        statuses: { created: 1000 },
        within_target: true,
        verification: { active_users: 1002, sampled: 100, mismatches: [] },
      },
      {
        kind: "seed_harvest",
        ok: 990,
        failed: 10,
        rate: 50,
        duration_s: 20,
        login_ms: { p50: 300, p99: 700 },
      },
    ];
    const text = renderLoadMarkdown(seeds, [{ scenario: "token_refresh", summary }]);
    expect(text).toContain(
      "**Import benchmark (TIO-ADMIN-021):** 1000 users in 12.3 s (81 users/s)",
    );
    expect(text).toContain("**Harvest (TIO-TEST-050):** 990 logins in 20 s at 50/s, 10 failed");
    expect(text).toContain(
      "| token_refresh | `http_req_failed{scenario:token_refresh}` rate<0.001 | 0 | **FAIL** |",
    );
    expect(text).toContain("**1 of 3 thresholds failed.**");
    expect(renderLoadMarkdown([], [])).toContain("No k6 summaries found.");
    expect(
      renderLoadMarkdown(
        [
          {
            kind: "import_benchmark",
            users: 5,
            duration_s: 4000,
            users_per_s: 0,
            statuses: {},
            within_target: false,
            verification: { active_users: null, sampled: 0, mismatches: ["x"] },
          },
        ],
        [],
      ),
    ).toContain("over the 60-minute target");
  });

  it("is what the nightly job runs", () => {
    expect(readFileSync("scripts/load-summary.ts", "utf8")).toContain("renderLoadMarkdown");
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    expect(nightly).toContain("scripts/load-summary.ts perf/data");
    // The harvested tokens are credentials: never an artifact.
    expect(nightly).toContain("!perf/data/tokens.ndjson");
  });
});
