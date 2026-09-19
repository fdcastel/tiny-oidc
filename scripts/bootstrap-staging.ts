// Bootstraps a hosted deployment end to end without a person at a browser
// (operator tooling for staging; the runbook §2 is the manual version):
//
//   TIO_ISSUER=… TIO_LOGIN_URL=… ADMIN_BOOTSTRAP_TOKEN=… TIO_OWNER_EMAIL=… node scripts/bootstrap-staging.ts
//
// 1. POST /api/v1/admin/bootstrap for a bot administrator.
// 2. Registers the bot's passkey through the real login app in Playwright's
//    Chromium with a CDP virtual authenticator (the same mechanism as the e2e
//    suite), on an `admin-cli` login whose loopback redirect a listener here
//    receives, and exchanges the code for a token with the admin scope.
// 3. Creates the `nightly-automation` client (client_credentials, admin scope)
//    the nightly jobs use, and a register invitation for the owner's own
//    administrator account with their real authenticator.
//
// Prints the automation client's secret and the owner's invitation URL once;
// stores nothing. The bot's virtual credential dies with the browser: the
// automation client is the durable identity, the owner's account the human one.
// The settings `login_url` and `login_origins` must already be stored (no
// administrator exists yet to set them through the API): with wrangler,
//   wrangler d1 execute <db> --remote --command "INSERT INTO settings (key, value, updated_at, updated_by)
//     VALUES ('login_url', '\"https://login.example.com/\"', 0, 'operator'),
//            ('login_origins', '[\"https://login.example.com\"]', 0, 'operator')"

import { createServer } from "node:http";
import { chromium } from "@playwright/test";
import { codeOf, pkce } from "../perf/lib/flow.ts";

const env = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
};
const issuer = env("TIO_ISSUER").replace(/\/$/, "");
const loginUrl = env("TIO_LOGIN_URL");
const bootstrapToken = env("ADMIN_BOOTSTRAP_TOKEN");
const ownerEmail = env("TIO_OWNER_EMAIL");
const botEmail = process.env["TIO_BOT_EMAIL"] ?? "bootstrap-bot@example.com";
const log = (message: string) => console.error(`bootstrap: ${message}`);

// 1. The bootstrap.
const bootstrapped = await fetch(`${issuer}/api/v1/admin/bootstrap`, {
  method: "POST",
  headers: { authorization: `Bearer ${bootstrapToken}`, "content-type": "application/json" },
  body: JSON.stringify({ email: botEmail, display_name: "Bootstrap bot" }),
});
if (bootstrapped.status !== 201) {
  throw new Error(`bootstrap: ${bootstrapped.status} ${await bootstrapped.text()}`);
}
const { invitation } = (await bootstrapped.json()) as { invitation: string };
log("bootstrapped; registering the bot's passkey through the login app");

// 2. The loopback listener the admin-cli login comes back to.
const listener = createServer();
const code = new Promise<string>((resolve, reject) => {
  listener.on("request", (req, res) => {
    const outcome = codeOf(`http://127.0.0.1${req.url ?? "/"}`);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("You can close this window.");
    if (outcome && "code" in outcome) resolve(outcome.code);
    else reject(new Error(`callback without a code: ${req.url}`));
  });
});
await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
const address = listener.address();
if (address === null || typeof address === "string") throw new Error("no loopback port");
const redirectUri = `http://127.0.0.1:${address.port}/callback`;
const { verifier, challenge } = pkce();
const authorize = new URL(`${issuer}/authorize`);
authorize.search = new URLSearchParams({
  response_type: "code",
  client_id: "admin-cli",
  redirect_uri: redirectUri,
  scope: "openid admin",
  state: "bootstrap",
  code_challenge: challenge,
  code_challenge_method: "S256",
}).toString();

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  await page.goto(authorize.href);
  if (!page.url().startsWith(loginUrl))
    throw new Error(`expected the login app, got ${page.url()}`);
  await page.locator("#register").click();
  await page.getByLabel("Invitation (if you have one)").fill(invitation);
  await page.getByLabel("Passkey name").fill("Bootstrap bot");
  await page.locator("#register-passkey").click();
  const received = await Promise.race([
    code,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("no callback in 60 s")), 60_000),
    ),
  ]);
  log("passkey registered, code received");
  const exchanged = await fetch(`${issuer}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "admin-cli",
      code: received,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  if (exchanged.status !== 200)
    throw new Error(`token: ${exchanged.status} ${await exchanged.text()}`);
  const { access_token: token } = (await exchanged.json()) as { access_token: string };

  // 3. The durable identities.
  const admin = async (method: string, path: string, body: unknown) => {
    const res = await fetch(`${issuer}/api/v1/admin/${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as Record<string, unknown>;
    if (res.status !== 201)
      throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(json)}`);
    return json;
  };
  const automation = await admin("POST", "clients", {
    client_id: "nightly-automation",
    client_name: "Nightly automation (conformance and load)",
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_basic",
    scopes_allowed: ["admin"],
  });
  const owner = await admin("POST", "invitations", {
    kind: "register",
    email: ownerEmail,
    email_verified: true,
    display_name: "Owner",
    groups: ["admins"],
    expires_in: 7 * 86_400,
  });
  console.log(
    JSON.stringify(
      {
        automation_client_id: automation["client_id"],
        automation_client_secret: automation["client_secret"],
        owner_invitation_url: owner["url"],
      },
      null,
      2,
    ),
  );
  log(
    "done: store the secret privately, hand the invitation URL to the owner, then delete ADMIN_BOOTSTRAP_TOKEN",
  );
} finally {
  await browser.close();
  listener.close();
}
