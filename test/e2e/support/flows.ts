import { expect, type Page } from "@playwright/test";
import type { PasskeyProvider } from "./passkeys.ts";

// The browser's side of the flows every spec drives: the example relying
// party (examples/rp-node) starts logins, shows the verified claims as JSON,
// and hosts the security-settings page on its `localhost` origin.

export const OP = process.env["TIO_E2E_BASE_URL"] ?? "http://localhost:8787";
export const RP = "http://127.0.0.1:8788";
export const RP_SETTINGS = "http://localhost:8788";

export interface RpResult {
  claims: Record<string, unknown>;
  scope: string;
}

/** The JSON the RP renders at its callback. */
export async function rpJson(page: Page): Promise<RpResult> {
  await expect(page).toHaveURL(new RegExp(`^${RP.replaceAll(".", "\\.")}/`));
  return JSON.parse(await page.locator("body").innerText()) as RpResult;
}

/** Creates an account with a passkey through the login app and returns what the RP received. */
export async function signUp(
  page: Page,
  provider: PasskeyProvider,
  fields: { email?: string; name?: string; invitation?: string; passkey?: string; scope?: string },
): Promise<RpResult> {
  await page.goto(
    `${RP}/login?scope=${encodeURIComponent(fields.scope ?? "openid email profile")}`,
  );
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await page.getByRole("button", { name: "Create an account" }).click();
  if (fields.invitation)
    await page.getByLabel("Invitation (if you have one)").fill(fields.invitation);
  if (fields.email) await page.getByLabel("Email").fill(fields.email);
  if (fields.name) await page.getByLabel("Name", { exact: true }).fill(fields.name);
  if (fields.passkey) await page.getByLabel("Passkey name").fill(fields.passkey);
  await page.getByRole("button", { name: "Create a passkey" }).click();
  const result = await rpJson(page);
  await provider.remember(page);
  return result;
}
