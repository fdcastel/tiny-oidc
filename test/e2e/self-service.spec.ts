import { expect, type Page, test } from "@playwright/test";
import { RP, RP_SETTINGS, signUp } from "./support/flows.ts";
import { type PasskeyProvider, passkeyProvider } from "./support/passkeys.ts";

// The Self-service API from a first-party app (spec §8): the security
// settings page of the example relying party adds a passkey with a real
// WebAuthn ceremony, and re-authorizes with max_age=0 when the OP asks for
// a fresh authentication (TIO-ME-003). scripts/e2e-server.ts sets
// me.passkey_add_max_auth_age to 5 seconds for this run.

test.describe.configure({ mode: "serial" });

let provider: PasskeyProvider;
test.beforeAll(({ browserName }) => {
  provider = passkeyProvider(browserName);
});

async function passkeys(page: Page): Promise<{ items: { name: string | null }[] }> {
  await expect(page.getByLabel("Passkeys")).not.toBeEmpty();
  return JSON.parse(await page.getByLabel("Passkeys").innerText()) as {
    items: { name: string | null }[];
  };
}

test("a person adds a passkey from the settings page right after signing in, and again after re-authorizing with max_age=0 once the authentication is too old", async ({
  browser,
  browserName,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  const result = await signUp(page, provider, {
    email: `keys-${browserName}@example.com`,
    name: "Keys",
    passkey: "First key",
    scope: "openid email account",
  });
  expect(result.scope).toBe("openid email account");
  // Hand the RP session over to the settings origin (WebAuthn needs a registrable origin).
  await page.goto(`${RP}/handoff?to=%2Fme`);
  await expect(page).toHaveURL(`${RP_SETTINGS}/me`);
  expect((await passkeys(page)).items.map((p) => p.name)).toEqual(["First key"]);
  // A second device registers the second key (the first one is excluded).
  await provider.newDevice(page);
  await page.getByLabel("Passkey name").fill("Second key");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByLabel("Result")).toContainText('"status":201');
  await expect
    .poll(async () => (await passkeys(page)).items.map((p) => p.name).sort())
    .toEqual(["First key", "Second key"]);
  await provider.remember(page);
  // Past the maximum authentication age the OP refuses; the page re-authorizes with max_age=0.
  await page.waitForTimeout(6_000);
  await page.getByLabel("Passkey name").fill("Third key");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page).toHaveURL(`${RP_SETTINGS}/me`);
  await provider.newDevice(page);
  await page.getByLabel("Passkey name").fill("Third key");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByLabel("Result")).toContainText('"status":201');
  await expect
    .poll(async () => (await passkeys(page)).items.map((p) => p.name).sort())
    .toEqual(["First key", "Second key", "Third key"]);
  await context.close();
});
