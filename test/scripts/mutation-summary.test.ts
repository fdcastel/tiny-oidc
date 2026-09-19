import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  type MutantStatus,
  type MutationReport,
  renderMarkdown,
  summarize,
} from "../../scripts/lib/mutation-summary.ts";

// The nightly mutation job's summary (spec §13.1, P7-07): the metrics Stryker
// defines, computed from its JSON report, grouped by top-level directory.

const mutants = (...statuses: MutantStatus[]) => ({
  mutants: statuses.map((status) => ({ status })),
});

const report: MutationReport = {
  files: {
    "src/util/base64url.ts": mutants("Killed", "Killed", "Timeout", "Survived"),
    "src/util/json.ts": mutants("Killed", "NoCoverage", "NoCoverage"),
    "src\\crypto\\hash.ts": mutants("Killed", "CompileError", "RuntimeError", "Ignored"),
    "src/index.ts": mutants("NoCoverage"),
  },
};

describe("mutation summary", () => {
  it("computes Stryker's score (detected over valid) and covered score (NoCoverage left out) per group and overall", () => {
    const { all, groups } = summarize(report);
    expect(all).toEqual({
      killed: 4,
      timeout: 1,
      survived: 1,
      noCoverage: 3,
      errors: 2,
      ignored: 1,
      score: 55.56,
      coveredScore: 83.33,
    });
    expect([...groups.keys()]).toEqual(["src", "src/crypto", "src/util"]);
    expect(groups.get("src/util")).toMatchObject({ score: 57.14, coveredScore: 80, noCoverage: 2 });
    expect(groups.get("src/crypto")).toMatchObject({ score: 100, errors: 2, ignored: 1 });
    expect(groups.get("src")).toMatchObject({ score: 0, coveredScore: null, noCoverage: 1 });
  });

  it("renders a Markdown table with a dash where a score is undefined and an empty report without dividing by zero", () => {
    const text = renderMarkdown(report);
    expect(text).toContain("| all | 55.56% | 83.33% | 4 | 1 | 1 | 3 | 2 |");
    expect(text).toContain("| src | 0.00% | — | 0 | 0 | 0 | 1 | 0 |");
    expect(summarize({ files: {} }).all).toMatchObject({ score: null, coveredScore: null });
  });

  it("is what the nightly job runs: the script reads the report path and stryker.config.json keeps the run report-only", () => {
    expect(readFileSync("scripts/mutation-summary.ts", "utf8")).toContain("renderMarkdown");
    const config = JSON.parse(readFileSync("stryker.config.json", "utf8")) as {
      thresholds: { break: number | null };
      vitest: { configFile: string };
      jsonReporter: { fileName: string };
    };
    expect(config.thresholds.break).toBeNull();
    expect(config.vitest.configFile).toBe("vitest.unit.config.ts");
    expect(config.jsonReporter.fileName).toBe("reports/mutation/mutation.json");
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    expect(nightly).toContain("run: pnpm mutate");
    expect(nightly).toContain("scripts/mutation-summary.ts reports/mutation/mutation.json");
    expect(nightly).toMatch(/mutation:[\s\S]*continue-on-error: true/);
  });
});
