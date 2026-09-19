// `pnpm run deploy` for every profile (TIO-DEPLOY-007). Workers Builds runs
// this on every push to main (staging) and production (production); the
// Deploy-to-Cloudflare button runs it with TIO_ENV unset.
import { readFileSync, writeFileSync } from "node:fs";
import { deploy, GENERATED_CONFIG } from "./lib/deploy.ts";
import { smoke } from "./lib/smoke.ts";
import { runWrangler } from "./lib/wrangler.ts";

const result = await deploy(process.env, {
  wrangler: async (args) => runWrangler(args, { stdio: ["ignore", "pipe", "inherit"] }),
  readConfig: () => readFileSync("wrangler.jsonc", "utf8"),
  writeGeneratedConfig: (content) => {
    writeFileSync(GENERATED_CONFIG, content);
    return GENERATED_CONFIG;
  },
  smoke: async (baseUrl) => {
    const failures = await smoke(baseUrl);
    if (failures.length > 0) {
      throw new Error(
        `smoke test failed: ${failures.map((f) => `${f.path}: ${f.reason}`).join("; ")}`,
      );
    }
  },
  log: (message) => console.log(`deploy: ${message}`),
});
console.log(`deploy: ${result.profile} done (${result.commands.length} wrangler command(s))`);
