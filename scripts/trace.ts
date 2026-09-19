// Traceability gate (TIO-TEST-006): every default-tag requirement in the
// specification needs a test whose title cites it, unless its phase has not
// started yet (scripts/trace.config.json). Writes doc/TRACEABILITY.md.
import { writeFileSync } from "node:fs";
import { readAll, readText } from "./lib/files.ts";
import {
  collectReferences,
  parseSpec,
  renderTraceability,
  type TraceConfig,
  trace,
} from "./lib/trace.ts";

const config = JSON.parse(readText("scripts/trace.config.json")) as TraceConfig;
const requirements = parseSpec(readText("doc/TINY_OIDC_SPEC.md"));
const tests = readAll("test", (p) => p.endsWith(".ts") && !p.endsWith(".d.ts"));
const references = collectReferences(tests);
const result = trace(requirements, references, config);

writeFileSync("doc/TRACEABILITY.md", renderTraceability(result.rows, config));

for (const warning of result.warnings) console.warn(`warning: ${warning}`);
for (const error of result.errors) console.error(`error: ${error}`);
const covered = result.rows.filter((r) => r.status === "covered").length;
const deferred = result.rows.filter((r) => r.status === "deferred").length;
console.log(
  `trace: ${requirements.length} requirements, ${covered} covered, ${deferred} deferred to later phases, ${result.errors.length} errors (phase ${config.phase})`,
);
if (result.errors.length > 0) process.exit(1);
