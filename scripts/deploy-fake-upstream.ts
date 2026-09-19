// `pnpm run deploy:fake-upstream`: the staging-only fake upstream Worker
// (TIO-TEST-031). Run from this workstation with TIO_ENV=staging and the
// TIO_FAKE_* values; refuses every other profile.
import { readFileSync } from "node:fs";
import { deployFakeUpstream, FAKE_UPSTREAM_CONFIG } from "./lib/deploy.ts";
import { runWrangler } from "./lib/wrangler.ts";

const result = await deployFakeUpstream(process.env, {
  wrangler: async (args) => runWrangler(args, { stdio: ["ignore", "pipe", "inherit"] }),
  readConfig: () => readFileSync(FAKE_UPSTREAM_CONFIG, "utf8"),
  log: (message) => console.log(`deploy-fake-upstream: ${message}`),
});
console.log(`deploy-fake-upstream: ${result.profile} done`);
