import { defineConfig, devices } from "@playwright/test";

// End-to-end suite: real browsers against `wrangler dev`, the reference login app
// served by the OP itself, and the example relying party on openid-client.
// CI runs Chromium on every push (TIO-TEST-001); Firefox and WebKit run locally and nightly.
const OP = process.env["TIO_E2E_BASE_URL"] ?? "http://localhost:8787";
const RP = "http://127.0.0.1:8788";

export default defineConfig({
  testDir: "./test/e2e",
  globalSetup: "./test/e2e/global-setup.ts",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: process.env["CI"] ? "github" : "list",
  use: {
    baseURL: OP,
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: "node scripts/e2e-server.ts",
      url: `${OP}/api/v1/health`,
      reuseExistingServer: !process.env["CI"],
      timeout: 120_000,
    },
    {
      command: "node examples/rp-node/server.ts",
      url: `${RP}/health`,
      reuseExistingServer: !process.env["CI"],
      timeout: 60_000,
      env: { TIO_ISSUER: OP, TIO_CLIENT_ID: "admin-cli", PORT: "8788" },
    },
  ],
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
