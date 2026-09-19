// Configuration gate: wrangler.jsonc bindings equal spec §2.2, runtime deps within
// spec §14.1, nodejs_compat absent, Deploy button prerequisites present.
import { parse } from "jsonc-parser";
import { checkPackageJson, checkReadme, checkWranglerConfig } from "./lib/config-check.ts";
import { readText } from "./lib/files.ts";

const errors = [
  ...checkWranglerConfig(parse(readText("wrangler.jsonc"))),
  ...checkPackageJson(JSON.parse(readText("package.json"))),
  ...checkReadme(readText("README.md")),
];
for (const e of errors) console.error(`error: ${e}`);
console.log(`config-check: ${errors.length} errors`);
if (errors.length > 0) process.exit(1);
