// Prints the load job's summary as Markdown (spec §13.10):
// `node scripts/load-summary.ts perf/data` reads every `*.summary.json` k6
// wrote and every seed report there.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { type K6Summary, renderLoadMarkdown, type SeedReport } from "./lib/load-summary.ts";

const dir = process.argv[2] ?? "perf/data";
const seeds: SeedReport[] = [];
const summaries: { scenario: string; summary: K6Summary }[] = [];
if (existsSync(dir)) {
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(dir, file), "utf8")) as Record<string, unknown>;
    if (file.endsWith(".summary.json")) {
      summaries.push({
        scenario: basename(file, ".summary.json"),
        summary: parsed as unknown as K6Summary,
      });
    } else if (parsed["kind"] === "import_benchmark" || parsed["kind"] === "seed_harvest") {
      seeds.push(parsed as unknown as SeedReport);
    }
  }
}
process.stdout.write(renderLoadMarkdown(seeds, summaries));
