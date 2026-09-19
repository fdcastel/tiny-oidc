import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

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
          bindings: { TEST_MIGRATIONS: migrations },
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
    },
  };
});
