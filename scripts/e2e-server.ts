// Starts the OP for the end-to-end suite: local secrets, local D1 migrations,
// then `wrangler dev` on the port the Playwright config expects. Playwright
// runs this as its webServer and stops it when the suite ends.
import { spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { generateSecrets, renderDevVars } from "./lib/secrets.ts";
import { runWrangler, wranglerBin } from "./lib/wrangler.ts";

const port = process.env["TIO_E2E_PORT"] ?? "8787";
if (!existsSync(".dev.vars")) {
  writeFileSync(
    ".dev.vars",
    renderDevVars(generateSecrets(), `http://127.0.0.1:${port}`, "127.0.0.1"),
  );
  console.log("e2e-server: wrote .dev.vars");
}
runWrangler(["d1", "migrations", "apply", "DB", "--local"], { stdio: "inherit" });
const dev = spawn(process.execPath, [wranglerBin(), "dev", "--port", port, "--ip", "127.0.0.1"], {
  stdio: "inherit",
});
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => dev.kill());
dev.on("exit", (code) => process.exit(code ?? 0));
