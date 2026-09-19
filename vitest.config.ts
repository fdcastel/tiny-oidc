import { defineConfig } from "vitest/config";

// Root config: one run, two projects, one coverage report.
// Coverage is the union of the unit (Node) and workers (workerd) suites and
// must stay at 100% on src/** (TIO-TEST-002); generated files are excluded.
export default defineConfig({
  test: {
    projects: ["./vitest.unit.config.ts", "./vitest.workers.config.ts"],
    coverage: {
      provider: "istanbul",
      include: ["src/**/*.ts"],
      exclude: ["src/generated/**"],
      reporter: ["text-summary", "html", "json-summary"],
      reportsDirectory: "./coverage",
      thresholds: { statements: 100, branches: 100, functions: 100, lines: 100 },
    },
  },
});
