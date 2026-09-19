// `pnpm smoke <base-url>`: fails when discovery, JWKS or health do not answer.
import { smoke } from "./lib/smoke.ts";

const base = process.argv[2];
if (!base) {
  console.error("usage: pnpm smoke <base-url>");
  process.exit(2);
}
const failures = await smoke(base);
for (const f of failures) console.error(`smoke: ${f.path}: ${f.reason}`);
console.log(`smoke: ${base}: ${failures.length === 0 ? "ok" : `${failures.length} failure(s)`}`);
if (failures.length > 0) process.exit(1);
