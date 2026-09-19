// Runs the requirement-encoding lint rules (TIO-TEST-060) over the repository.
import { readAll } from "./lib/files.ts";
import { RULES, runRules } from "./lib/lint-rules.ts";

const files = {
  ...readAll("src", (p) => p.endsWith(".ts")),
  ...readAll("test", (p) => p.endsWith(".ts")),
  ...readAll("scripts", (p) => p.endsWith(".ts")),
  ...readAll("examples", (p) => p.endsWith(".ts")),
  ...readAll(".", (p) => p === "wrangler.jsonc"),
};
const violations = runRules(files, RULES);
for (const v of violations) console.error(`${v.path}:${v.line}: [${v.rule}] ${v.message}`);
console.log(
  `lint-rules: ${RULES.length} rules, ${Object.keys(files).length} files, ${violations.length} violations`,
);
if (violations.length > 0) process.exit(1);
