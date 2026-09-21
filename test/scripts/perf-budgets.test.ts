import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  BUDGETS,
  MAX_D1_WRITE_RATE,
  MAX_FAILED_RATE,
  TAIL_FACTOR,
} from "../../perf/scenarios/budgets.js";

// The k6 thresholds are the specification's numbers (TIO-PERF-001,
// TIO-TEST-051): every scenario's p50 and p99 equal the §2.7 row it names,
// the failure and D1-write bounds are §13.10's, and every scenario named in
// trace.config.json exists as a script that uses its budget.

/** The §2.7 table: endpoint → { p50, p99 } in milliseconds. */
function specBudgets(): Map<string, { p50: number; p99: number }> {
  const spec = readFileSync("doc/TINY_OIDC_SPEC.md", "utf8");
  const start = spec.indexOf("### 2.7 Performance budgets");
  const end = spec.indexOf("**[TIO-PERF-001]**", start);
  const rows = new Map<string, { p50: number; p99: number }>();
  for (const m of spec.slice(start, end).matchAll(/^\| ([^|]+) \| (\d+) ms \| (\d+) ms \|/gm)) {
    rows.set((m[1] as string).replaceAll("`", "").trim(), { p50: Number(m[2]), p99: Number(m[3]) });
  }
  return rows;
}

/** The endpoint of §2.7 each scenario budget names, as the table spells it. */
const ROW_OF: Record<string, string> = {
  "GET /.well-known/*": "GET /.well-known/*, GET /.well-known/jwks.json",
  "GET /authorize (session hit)": "GET /authorize (session hit)",
  "GET /federation/callback": "GET /federation/callback",
  "POST /token code exchange": "POST /token code exchange",
  "POST /token refresh": "POST /token refresh",
  "GET /userinfo": "GET /userinfo",
  "Admin list endpoints": "Admin list endpoints",
};

describe("k6 budgets", () => {
  it("equal the §2.7 table, row by row", () => {
    const rows = specBudgets();
    expect(rows.size).toBeGreaterThanOrEqual(12);
    for (const [scenario, budget] of Object.entries(BUDGETS)) {
      const row = rows.get(ROW_OF[budget.endpoint] as string);
      expect(row, `${scenario}: ${budget.endpoint}`).toBeDefined();
      expect({ p50: budget.p50, p99: budget.p99 }, scenario).toEqual(row);
      expect(budget.d1w, `${scenario} allows no D1 write on the request path`).toBe(0);
    }
    expect(MAX_FAILED_RATE).toBe(0.001);
    expect(MAX_D1_WRITE_RATE).toBe(5);
    // The budget is on the requests that read no D1; the D1-touching ones are bounded at
    // four times it; the two rows that read D1 by design are budgeted over every request.
    expect(TAIL_FACTOR).toBe(4);
    const spec = readFileSync("doc/TINY_OIDC_SPEC.md", "utf8");
    expect(spec).toContain("bounded separately at four times the row's p99");
    expect(
      Object.entries(BUDGETS)
        .filter(([, b]) => b.d1)
        .map(([name]) => name)
        .sort(),
    ).toEqual(["admin_list", "login_federated"]);
  });

  it("cover every scenario trace.config.json maps a load requirement to, each with a script that enforces its thresholds", () => {
    const config = JSON.parse(readFileSync("scripts/trace.config.json", "utf8")) as {
      load_thresholds: Record<string, string[]>;
    };
    const named = new Set(Object.values(config.load_thresholds).flat());
    // The seed steps are perf/seed.ts subcommands, not k6 scenarios.
    for (const step of ["seed_import", "seed_harvest", "import_benchmark"]) named.delete(step);
    expect([...named].sort()).toEqual(Object.keys(BUDGETS).sort());
    for (const scenario of named) {
      const script = readFileSync(`perf/scenarios/${scenario}.js`, "utf8");
      expect(script, scenario).toContain(`thresholds("${scenario}")`);
      expect(script, scenario).toContain("record(");
      expect(script, scenario).toContain("summaryTrendStats: SUMMARY_TREND_STATS");
    }
    // k6 parses the scripts itself; a syntax error would surface only in the nightly.
    for (const file of ["lib.js", "budgets.js", ...[...named].map((s) => `${s}.js`)]) {
      expect(
        () => execFileSync(process.execPath, ["--check", `perf/scenarios/${file}`]),
        file,
      ).not.toThrow();
    }
  });
});
