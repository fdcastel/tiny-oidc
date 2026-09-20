import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { INVITATION_FILE } from "./global-setup.ts";
import { OP, RP, type RpResult, rpJson, signUp } from "./support/flows.ts";
import { type PasskeyProvider, passkeyProvider } from "./support/passkeys.ts";

// Passkey sign-up and sign-in through the reference login app and the example
// relying party (TIO-TEST-033: everything here speaks HTTP to the OP). The RP
// on openid-client verifies the ID token against the live JWKS and shows the
// claims as JSON; the browser never sees a token.

test.describe.configure({ mode: "serial" });

/** The bootstrap outcome parked by the global setup; the first project to ask takes it. */
function takeInvitation(): { invitation: string; client: { client_id: string } } | null {
  if (!existsSync(INVITATION_FILE)) return null;
  const parsed = JSON.parse(readFileSync(INVITATION_FILE, "utf8")) as {
    invitation: string;
    client: { client_id: string };
  };
  unlinkSync(INVITATION_FILE);
  return parsed;
}

let provider: PasskeyProvider;
test.beforeAll(({ browserName }) => {
  provider = passkeyProvider(browserName);
});

test("the first administrator is bootstrapped and signs up with the invitation", async ({
  browser,
}) => {
  const bootstrapped = takeInvitation();
  test.skip(bootstrapped === null, "the invitation was consumed by an earlier project of this run");
  const { invitation, client } = bootstrapped as NonNullable<typeof bootstrapped>;
  expect(client.client_id).toBe("admin-cli");
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  await page.goto(`${RP}/login?scope=openid%20email%20profile%20admin`);
  await page.getByRole("button", { name: "Create an account" }).click();
  await page.getByLabel("Invitation (if you have one)").fill(invitation);
  await page.getByLabel("Passkey name").fill("Root's key");
  await page.getByRole("button", { name: "Create a passkey" }).click();
  const result = await rpJson(page);
  expect(result.claims).toMatchObject({
    iss: OP,
    aud: "admin-cli",
    email: "root@example.com",
    email_verified: true,
    name: "Root",
    acr: "urn:tinyoidc:acr:passkey",
  });
  expect(result.scope).toBe("openid email profile admin");
  await provider.remember(page);
  // The spent invitation is refused.
  const again = await context.newPage();
  await provider.attach(again);
  await again.goto(`${RP}/login?prompt=login`);
  await again.getByRole("button", { name: "Create an account" }).click();
  await again.getByLabel("Invitation (if you have one)").fill(invitation);
  await again.getByRole("button", { name: "Create a passkey" }).click();
  await expect(again.getByRole("alert")).toHaveText(/already used/);
  await context.close();
});

test("a visitor creates an account with a passkey and the relying party receives verified claims, userinfo and a refresh", async ({
  browser,
  browserName,
}) => {
  const email = `alice-${browserName}@example.com`;
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  const result = await signUp(page, provider, { email, name: "Alice", passkey: "Laptop" });
  expect(result.claims).toMatchObject({
    iss: OP,
    aud: "admin-cli",
    email,
    email_verified: false,
    name: "Alice",
    amr: [expect.stringMatching(/^(hwk|swk)$/), "user"],
  });
  expect(typeof result.claims["sid"]).toBe("string");
  expect(result.scope).toBe("openid email profile");
  await page.goto(`${RP}/userinfo`);
  expect(JSON.parse(await page.locator("body").innerText())).toMatchObject({
    sub: result.claims["sub"],
    email,
    name: "Alice",
  });
  await page.goto(`${RP}/refresh`);
  const refreshed = JSON.parse(await page.locator("body").innerText()) as RpResult;
  expect(refreshed.claims["sub"]).toBe(result.claims["sub"]);
  expect(refreshed.claims["auth_time"]).toBe(result.claims["auth_time"]);
  await context.close();
});

test("the same user signs in with the passkey from a fresh browser; the next visit is a session hit and prompt=login asks again", async ({
  browser,
  browserName,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  await page.goto(`${RP}/login`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  const first = await rpJson(page);
  expect(first.claims["email"]).toMatch(
    new RegExp(`-${browserName}@example.com$|^root@example.com$`),
  );
  const sid = first.claims["sid"];
  // Session hit: no login app at all.
  await page.goto(`${RP}/login?scope=openid%20email`);
  const second = await rpJson(page);
  expect(second.claims["sid"]).toBe(sid);
  expect(second.claims["sub"]).toBe(first.claims["sub"]);
  // prompt=login: the passkey is asked for again, the session is kept.
  await page.goto(`${RP}/login?prompt=login`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  const third = await rpJson(page);
  expect(third.claims["sid"]).toBe(sid);
  await context.close();
});

test("cancelling sends the browser back to the relying party with access_denied", async ({
  browser,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  await page.goto(`${RP}/login`);
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page).toHaveURL(new RegExp(`^${RP.replaceAll(".", "\\.")}/callback`));
  const body = JSON.parse(await page.locator("body").innerText()) as Record<string, string>;
  expect(body).toMatchObject({
    error: "callback_failed",
    oauth_error: "access_denied",
    oauth_error_description: "aborted by the user",
  });
  await context.close();
});

test("a browser without WebAuthn is told so on the sign-in screen instead of being offered a passkey button (federation, when registered, is still offered — the conformance suite's browser relies on it)", async ({
  browser,
}) => {
  const context = await browser.newContext();
  // The page-side script runs in the browser, which the Node tsconfig knows nothing about.
  await context.addInitScript("delete window.PublicKeyCredential;");
  const page = await context.newPage();
  await page.goto(`${RP}/login`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  // No upstream is registered in the e2e environment, so nothing can be offered at all.
  await expect(page.getByRole("heading", { name: "Unsupported browser" })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveText(/does not support passkeys/);
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toHaveCount(0);
  await context.close();
});
