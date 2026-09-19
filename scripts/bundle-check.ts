// Bundle gate (TIO-PERF-002, TIO-GEN-002): builds the Worker with
// `wrangler deploy --dry-run` and checks size and content of the output.
import { rmSync } from "node:fs";
import { BUNDLE_LIMIT_BYTES, checkBundle } from "./lib/bundle-check.ts";
import { readAll } from "./lib/files.ts";
import { runWrangler } from "./lib/wrangler.ts";

const outdir = "dist/bundle-check";
rmSync(outdir, { recursive: true, force: true });
runWrangler(["deploy", "--dry-run", `--outdir=${outdir}`], { stdio: "inherit" });
const files = readAll(outdir, (p) => p.endsWith(".js") || p.endsWith(".mjs"));
const report = checkBundle(files);
for (const e of report.errors) console.error(`error: ${e}`);
console.log(
  `bundle-check: ${report.bytes} bytes (budget ${BUNDLE_LIMIT_BYTES}), ${Object.keys(files).length} module(s), ${report.errors.length} errors`,
);
if (report.errors.length > 0) process.exit(1);
