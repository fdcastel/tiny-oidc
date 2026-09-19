// The load job's summary (spec §13.10): what k6 wrote through handleSummary
// (perf/scenarios/lib.js) and what perf/seed.ts reported, as one Markdown
// table per kind, so the nightly job's page says which threshold failed
// without opening the artifacts.

export interface K6Summary {
  metrics: Record<
    string,
    { values?: Record<string, number>; thresholds?: Record<string, { ok: boolean }> }
  >;
}

export interface ThresholdRow {
  scenario: string;
  metric: string;
  expression: string;
  ok: boolean;
  /** The measured value the expression is about, when the summary carries it. */
  value: number | null;
}

/** Every threshold of a k6 summary, one row each, in name order. */
export function thresholdRows(scenario: string, summary: K6Summary): ThresholdRow[] {
  const rows: ThresholdRow[] = [];
  for (const [metric, data] of Object.entries(summary.metrics).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    for (const [expression, result] of Object.entries(data.thresholds ?? {})) {
      const aggregate = /^([a-z0-9()._]+)\s*[<>=!]+/i.exec(expression)?.[1] ?? "";
      const value = data.values?.[aggregate];
      rows.push({
        scenario,
        metric,
        expression,
        ok: result.ok,
        value: typeof value === "number" ? Math.round(value * 100) / 100 : null,
      });
    }
  }
  return rows;
}

export interface SeedReport {
  kind: "import_benchmark" | "seed_harvest";
  duration_s: number;
  [key: string]: unknown;
}

/** A Markdown block for the seed reports and the k6 summaries of one run. */
export function renderLoadMarkdown(
  seeds: SeedReport[],
  summaries: { scenario: string; summary: K6Summary }[],
): string {
  const lines = ["## Load (staging)", ""];
  for (const report of seeds) {
    if (report.kind === "import_benchmark") {
      const v = report["verification"] as {
        active_users: number | null;
        sampled: number;
        mismatches: string[];
      };
      lines.push(
        `- **Import benchmark (TIO-ADMIN-021):** ${report["users"]} users in ${report.duration_s} s (${report["users_per_s"]} users/s), statuses ${JSON.stringify(report["statuses"])}, ${v.active_users ?? "?"} active users, ${v.mismatches.length} mismatches in ${v.sampled} sampled${report["within_target"] === false ? " — **over the 60-minute target**" : ""}`,
      );
    } else if (report.kind === "seed_harvest") {
      const ms = report["login_ms"] as { p50: number; p99: number };
      lines.push(
        `- **Harvest (TIO-TEST-050):** ${report["ok"]} logins in ${report.duration_s} s at ${report["rate"]}/s, ${report["failed"]} failed, login p50 ${ms.p50} ms, p99 ${ms.p99} ms`,
      );
    }
  }
  if (seeds.length > 0) lines.push("");
  const rows = summaries.flatMap((s) => thresholdRows(s.scenario, s.summary));
  if (rows.length > 0) {
    lines.push("| Scenario | Threshold | Measured | Result |", "|---|---|---|---|");
    for (const row of rows) {
      lines.push(
        `| ${row.scenario} | \`${row.metric}\` ${row.expression} | ${row.value === null ? "—" : row.value} | ${row.ok ? "pass" : "**FAIL**"} |`,
      );
    }
    const failed = rows.filter((r) => !r.ok).length;
    lines.push(
      "",
      failed === 0
        ? `All ${rows.length} thresholds passed.`
        : `**${failed} of ${rows.length} thresholds failed.**`,
    );
  } else {
    lines.push("No k6 summaries found.");
  }
  lines.push("");
  return lines.join("\n");
}
