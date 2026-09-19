// Prints MASTER_KEYS, MASTER_KEY_ACTIVE and ADMIN_BOOTSTRAP_TOKEN for the README
// deploy steps. With --dev-vars, writes .dev.vars for `wrangler dev` unless it exists.
import { existsSync, writeFileSync } from "node:fs";
import { generateSecrets, renderDevVars } from "./lib/secrets.ts";

const secrets = generateSecrets();
if (process.argv.includes("--dev-vars")) {
  if (existsSync(".dev.vars")) {
    console.log("gen-secrets: .dev.vars already exists; leaving it untouched");
  } else {
    writeFileSync(".dev.vars", renderDevVars(secrets, "http://localhost:8787", "localhost"));
    console.log("gen-secrets: wrote .dev.vars for wrangler dev");
  }
} else {
  for (const [name, value] of Object.entries(secrets)) console.log(`${name}=${value}`);
}
