// Writes doc/CONFIG.md and .dev.vars.example from src/env.ts (TIO-CFG-005). CI
// regenerates both and fails on any diff.
import { writeFileSync } from "node:fs";
import { renderConfigMarkdown, renderDevVarsExample } from "./lib/config-docs.ts";

writeFileSync("doc/CONFIG.md", renderConfigMarkdown());
writeFileSync(".dev.vars.example", renderDevVarsExample());
console.log("gen-config-docs: wrote doc/CONFIG.md and .dev.vars.example");
