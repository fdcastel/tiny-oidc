// Coverage exclusions (TIO-TEST-003): only `/* istanbul ignore next -- reason: … */`,
// at most 15 across src/, every occurrence printed.
import { readAll } from "./lib/files.ts";
import { findIstanbulIgnores, MAX_ISTANBUL_IGNORES } from "./lib/lint-rules.ts";

const occurrences = findIstanbulIgnores(readAll("src", (p) => p.endsWith(".ts")));
let failed = false;
for (const o of occurrences) {
  console.log(`${o.valid ? "ok " : "BAD"} ${o.path}:${o.line}: ${o.text}`);
  if (!o.valid) failed = true;
}
if (occurrences.length > MAX_ISTANBUL_IGNORES) {
  console.error(
    `error: ${occurrences.length} istanbul ignores exceed the limit of ${MAX_ISTANBUL_IGNORES}`,
  );
  failed = true;
}
console.log(
  `check-ignores: ${occurrences.length}/${MAX_ISTANBUL_IGNORES} istanbul ignores in src/`,
);
if (failed) process.exit(1);
