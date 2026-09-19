import { defineConfig, devices } from "@playwright/test";

// End-to-end suite: real browsers against `wrangler dev` and the reference login app.
// CI runs Chromium on every push (TIO-TEST-001); Firefox and WebKit run locally and nightly.
export default defineConfig({
  testDir: "./test/e2e",
  fullyParallel: false,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: process.env["CI"] ? "github" : "list",
  use: {
    baseURL: process.env["TIO_E2E_BASE_URL"] ?? "http://127.0.0.1:8787",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
