// Mutation-report metrics (spec §13.1, P7-07): the numbers Stryker's
// reporters derive from a mutation-testing-report-schema document, computed
// here so the nightly job can print them without a browser.

export type MutantStatus =
  | "Killed"
  | "Survived"
  | "NoCoverage"
  | "Timeout"
  | "CompileError"
  | "RuntimeError"
  | "Ignored"
  | "Pending";

export interface MutationReport {
  files: Record<string, { mutants: { status: MutantStatus }[] }>;
}

export interface Metrics {
  killed: number;
  timeout: number;
  survived: number;
  noCoverage: number;
  errors: number;
  ignored: number;
  /** Detected over valid mutants, in percent; null when nothing was valid. */
  score: number | null;
  /** Detected over covered mutants (NoCoverage left out), in percent; null when nothing was covered. */
  coveredScore: number | null;
}

const EMPTY: Omit<Metrics, "score" | "coveredScore"> = {
  killed: 0,
  timeout: 0,
  survived: 0,
  noCoverage: 0,
  errors: 0,
  ignored: 0,
};

function tally(mutants: { status: MutantStatus }[]): Metrics {
  const m = { ...EMPTY };
  for (const { status } of mutants) {
    if (status === "Killed") m.killed++;
    else if (status === "Timeout") m.timeout++;
    else if (status === "Survived") m.survived++;
    else if (status === "NoCoverage") m.noCoverage++;
    else if (status === "Ignored") m.ignored++;
    else if (status === "CompileError" || status === "RuntimeError") m.errors++;
  }
  const detected = m.killed + m.timeout;
  const valid = detected + m.survived + m.noCoverage;
  const covered = detected + m.survived;
  const pct = (n: number, d: number) => (d === 0 ? null : Math.round((n / d) * 10000) / 100);
  return { ...m, score: pct(detected, valid), coveredScore: pct(detected, covered) };
}

/** Metrics for the whole report and for every top-level directory under `src/`. */
export function summarize(report: MutationReport): { all: Metrics; groups: Map<string, Metrics> } {
  const byGroup = new Map<string, { status: MutantStatus }[]>();
  const every: { status: MutantStatus }[] = [];
  for (const [file, { mutants }] of Object.entries(report.files)) {
    const parts = file.replaceAll("\\", "/").split("/");
    const group = parts[0] === "src" && parts.length > 2 ? `src/${parts[1]}` : "src";
    byGroup.set(group, [...(byGroup.get(group) ?? []), ...mutants]);
    every.push(...mutants);
  }
  const groups = new Map<string, Metrics>();
  for (const name of [...byGroup.keys()].sort()) {
    groups.set(name, tally(byGroup.get(name) as { status: MutantStatus }[]));
  }
  return { all: tally(every), groups };
}

const fmt = (n: number | null) => (n === null ? "—" : `${n.toFixed(2)}%`);

/** A Markdown table for the job summary. */
export function renderMarkdown(report: MutationReport): string {
  const { all, groups } = summarize(report);
  const row = (name: string, m: Metrics) =>
    `| ${name} | ${fmt(m.score)} | ${fmt(m.coveredScore)} | ${m.killed} | ${m.timeout} | ${m.survived} | ${m.noCoverage} | ${m.errors} |`;
  return [
    "## Mutation testing (unit project, report only)",
    "",
    "| Scope | Score | Covered score | Killed | Timeout | Survived | No coverage | Errors |",
    "|---|---|---|---|---|---|---|---|",
    row("all", all),
    ...[...groups].map(([name, m]) => row(name, m)),
    "",
  ].join("\n");
}
