import { expect, test } from "@playwright/test";

// Phase 0 smoke: a real browser reaches the OP through wrangler dev (TIO-TEST-033:
// the suite only speaks HTTP). Passkey flows join this suite in Phase 2.
test("the OP answers the health endpoint from a browser", async ({ page, baseURL }) => {
  const response = await page.goto("/api/v1/health");
  expect(response?.status()).toBe(200);
  expect(response?.headers()["content-type"]).toMatch(/^application\/json/);
  expect(response?.headers()["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
  const body = JSON.parse(await page.locator("body").innerText()) as Record<string, unknown>;
  expect(body).toMatchObject({ status: "ok", d1: "ok" });
  expect(body["active_kid"]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(body["issuer_mismatch"]).toBeUndefined();
  expect(baseURL).toContain("127.0.0.1");
});

test("unknown paths are JSON 404s, never HTML", async ({ page }) => {
  const response = await page.goto("/login-page-that-does-not-exist");
  expect(response?.status()).toBe(404);
  expect(response?.headers()["content-type"]).toMatch(/^application\/json/);
  expect(await page.locator("body").innerText()).toContain('"error":"not_found"');
});

test("discovery and JWKS are served with public caching", async ({ page }) => {
  const discovery = await page.goto("/.well-known/openid-configuration");
  expect(discovery?.status()).toBe(200);
  expect(discovery?.headers()["cache-control"]).toBe("public, max-age=300");
  const doc = JSON.parse(await page.locator("body").innerText()) as Record<string, string>;
  expect(doc["jwks_uri"]).toMatch(/\/\.well-known\/jwks\.json$/);
  const jwks = await page.goto("/.well-known/jwks.json");
  expect(jwks?.status()).toBe(200);
  const body = await page.locator("body").innerText();
  expect(body).toContain('"kty":"EC"');
  expect(body).not.toContain('"d"');
});
