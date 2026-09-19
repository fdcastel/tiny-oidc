// Prints the mutation score of a Stryker JSON report as Markdown (spec §13.1,
// P7-07): `node scripts/mutation-summary.ts reports/mutation/mutation.json`.
import { readFileSync } from "node:fs";
import { type MutationReport, renderMarkdown } from "./lib/mutation-summary.ts";

const path = process.argv[2] ?? "reports/mutation/mutation.json";
const report = JSON.parse(readFileSync(path, "utf8")) as MutationReport;
process.stdout.write(renderMarkdown(report));
