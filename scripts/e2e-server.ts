// Starts the OP for the end-to-end suite: local secrets, a fresh local
// storage directory with the D1 migrations applied and the settings an
// operator would store, then `wrangler dev` on the host
// and port the Playwright config expects. Playwright runs this as its
// webServer and stops it when the suite ends. The issuer is
// http://localhost:<port> because browsers accept `localhost` as a WebAuthn
// RP ID and a secure context, but not an IP literal.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSecrets, renderDevVars } from "./lib/secrets.ts";
import { runWrangler, wranglerBin } from "./lib/wrangler.ts";

const port = process.env["TIO_E2E_PORT"] ?? "8787";
const issuer = `http://localhost:${port}`;
if (!existsSync(".dev.vars")) {
  writeFileSync(".dev.vars", renderDevVars(generateSecrets(), issuer, "localhost"));
  console.log("e2e-server: wrote .dev.vars");
}
// Every run starts from empty storage, so bootstrap happens exactly once per run.
const state = mkdtempSync(join(tmpdir(), "tiny-oidc-e2e-"));
const local = ["--local", "--persist-to", state];
runWrangler(["d1", "migrations", "apply", "DB", ...local], { stdio: "inherit" });
// Open registration; the relying party's settings page (http://localhost:8788) may run
// WebAuthn ceremonies; a five-second window to add a passkey without re-authenticating.
const seeded: [string, string][] = [
  ["registration.mode", '"open"'],
  ["webauthn_origins", `["${issuer}","http://localhost:8788"]`],
  ["me.passkey_add_max_auth_age", "5"],
];
runWrangler(
  [
    "d1",
    "execute",
    "DB",
    ...local,
    "--command",
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ${seeded
      .map(([key, value]) => `('${key}', '${value}', 0, 'e2e')`)
      .join(", ")}`,
  ],
  { stdio: "inherit" },
);
const dev = spawn(
  process.execPath,
  [
    wranglerBin(),
    "dev",
    "--port",
    port,
    "--ip",
    "127.0.0.1",
    "--persist-to",
    state,
    // The issuer and RP ID of the e2e run win over whatever .dev.vars holds.
    "--var",
    `ISSUER:${issuer}`,
    "--var",
    "RP_ID:localhost",
    "--var",
    "BUNDLED_LOGIN_APP:true",
  ],
  { stdio: "inherit" },
);
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => dev.kill());
dev.on("exit", (code) => process.exit(code ?? 0));
