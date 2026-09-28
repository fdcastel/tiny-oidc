// `node scripts/redact-artifacts.ts <dir>...`, run before the nightly uploads
// an artifact: every text file under the directories loses the registrable
// domains of the URLs in TIO_REDACT_URLS (whitespace-separated; the staging
// issuer, login app and fake upstream). Without any URL it does nothing.
import { existsSync } from "node:fs";
import { redactTree, registrableDomain } from "./lib/redact.ts";

const domains = (process.env["TIO_REDACT_URLS"] ?? "")
  .split(/\s+/)
  .map(registrableDomain)
  .filter((d): d is string => d !== null);
if (domains.length === 0) {
  console.log("redact-artifacts: no URL configured; nothing to redact");
  process.exit(0);
}
for (const dir of process.argv.slice(2)) {
  if (!existsSync(dir)) continue;
  const changed = redactTree(dir, domains);
  console.log(`redact-artifacts: ${dir}: ${changed.length} files redacted`);
}
