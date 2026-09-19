import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import testEnv from "./test/support/test-env.json" with { type: "json" };

// Workers suites: run inside workerd with real D1, Durable Objects, Queues and R2.
// Storage is isolated per test file (TIO-TEST-004); `test/support/setup.ts`
// applies the D1 migrations for each file before its tests run.
export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          // Test vars and secrets (issuer, RP id, master keys) shared with test/support/keys.ts.
          bindings: { ...testEnv, TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      name: "workers",
      include: [
        "test/component/**/*.test.ts",
        "test/http/**/*.test.ts",
        "test/security/**/*.test.ts",
        "test/concurrency/**/*.test.ts",
        "test/interop/**/*.test.ts",
      ],
      setupFiles: ["./test/support/setup.ts"],
      // Rate-limit tests exhaust a binding (2,000 calls) while other files run in parallel.
      testTimeout: 30_000,
    },
  };
});
