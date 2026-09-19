import { expect, type Page, test } from "@playwright/test";
import { RP, rpJson, signUp } from "./support/flows.ts";
import { type PasskeyProvider, passkeyProvider } from "./support/passkeys.ts";

// RP-initiated logout through real browsers (spec §5.10.1, §7.6): with the ID
// token as the hint the session ends at once; without one the login app asks
// the person to confirm. Everything here speaks HTTP to the OP (TIO-TEST-033).

test.describe.configure({ mode: "serial" });

let provider: PasskeyProvider;
test.beforeAll(({ browserName }) => {
  provider = passkeyProvider(browserName);
});

/** The JSON the RP shows once the OP sent the browser back after a logout. */
async function loggedOut(page: Page): Promise<{ logged_out: boolean; state: string | null }> {
  await expect(page).toHaveURL(new RegExp(`^${RP.replaceAll(".", "\\.")}/loggedout\\?state=`));
  return JSON.parse(await page.locator("body").innerText()) as {
    logged_out: boolean;
    state: string | null;
  };
}

test("logout with an ID token hint ends the OP session and the relying party's, and the next visit asks for the passkey again", async ({
  browser,
  browserName,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  const first = await signUp(page, provider, {
    email: `bye-${browserName}@example.com`,
    name: "Bye",
    passkey: "Phone",
  });
  const sid = first.claims["sid"];
  expect(typeof sid).toBe("string");
  // A session hit proves the OP session exists.
  await page.goto(`${RP}/login?scope=openid%20email`);
  expect((await rpJson(page)).claims["sid"]).toBe(sid);
  await page.goto(`${RP}/logout`);
  const result = await loggedOut(page);
  expect(result).toEqual({ logged_out: true, state: expect.any(String) });
  await page.goto(`${RP}/session`);
  expect(JSON.parse(await page.locator("body").innerText())).toEqual({ error: "no_session" });
  // No session hit any more: the login app appears and the passkey is asked for.
  await page.goto(`${RP}/login?scope=openid%20email`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  const again = await rpJson(page);
  expect(again.claims["sub"]).toBe(first.claims["sub"]);
  expect(again.claims["sid"]).not.toBe(sid);
  await context.close();
});

test("logout without a hint asks for confirmation: staying keeps the session, signing out ends it", async ({
  browser,
  browserName,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await provider.attach(page);
  const first = await signUp(page, provider, {
    email: `stay-${browserName}@example.com`,
    name: "Stay",
    passkey: "Laptop",
  });
  const sid = first.claims["sid"];
  await page.goto(`${RP}/logout?nohint=1`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  await expect(page.getByRole("heading", { name: "Sign out?" })).toBeVisible();
  await page.getByRole("button", { name: "Stay signed in" }).click();
  expect((await loggedOut(page)).logged_out).toBe(true);
  // The OP session is intact: a session hit.
  await page.goto(`${RP}/login?scope=openid%20email`);
  expect((await rpJson(page)).claims["sid"]).toBe(sid);
  await page.goto(`${RP}/logout?nohint=1`);
  await expect(page.getByRole("heading", { name: "Sign out?" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  expect((await loggedOut(page)).logged_out).toBe(true);
  await page.goto(`${RP}/login?scope=openid%20email`);
  await expect(page).toHaveURL(/\/login\/\?interaction=/);
  // Without any session, logout lands straight away.
  await page.goto(`${RP}/logout?nohint=1`);
  expect((await loggedOut(page)).logged_out).toBe(true);
  await context.close();
});
