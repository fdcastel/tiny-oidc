// Public neutrality gate (TIO-DEPLOY-005) over every committed file.
import { execFileSync } from "node:child_process";
import { readText } from "./lib/files.ts";
import { checkNeutrality, isCheckedForNeutrality } from "./lib/neutrality.ts";

const tracked = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter((p) => p.length > 0 && isCheckedForNeutrality(p));
const files: Record<string, string> = {};
for (const path of tracked) files[path] = readText(path);
const findings = checkNeutrality(files);
for (const f of findings) console.error(`${f.path}:${f.line}: ${f.message}`);
console.log(`neutrality-check: ${tracked.length} files, ${findings.length} findings`);
if (findings.length > 0) process.exit(1);
