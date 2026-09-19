import { describe, expect, it } from "vitest";
import { fetchDiscovery, fetchJson, fetchJwks } from "../../src/federation/discovery.ts";

// Upstream discovery (spec §6.4.1, TIO-FED-001): the fetch is bounded and the
// document checked before anything is trusted.

const ISSUER = "https://idp.example.com";

const answering =
  (status: number, body: string): typeof fetch =>
  async () =>
    new Response(body, { status });

describe("fetchDiscovery", () => {
  it("[TIO-FED-001] accepts a document whose issuer matches exactly and whose endpoints are https; userinfo is optional", async () => {
    const document = {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/a`,
      token_endpoint: `${ISSUER}/t`,
      jwks_uri: `${ISSUER}/j`,
      extra: "ignored",
    };
    expect(
      await fetchDiscovery(ISSUER, { fetch: answering(200, JSON.stringify(document)) }),
    ).toEqual({
      ok: true,
      metadata: {
        authorization_endpoint: `${ISSUER}/a`,
        token_endpoint: `${ISSUER}/t`,
        jwks_uri: `${ISSUER}/j`,
        userinfo_endpoint: null,
      },
    });
    // A trailing slash on the configured issuer is not the document's issuer.
    expect(
      await fetchDiscovery(`${ISSUER}/`, { fetch: answering(200, JSON.stringify(document)) }),
    ).toMatchObject({ ok: false, reason: "issuer_mismatch" });
  });

  it("[TIO-FED-001] gives up after the timeout and reports a fetch that throws", async () => {
    const hanging: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    const timedOut = await fetchJson(`${ISSUER}/.well-known/openid-configuration`, {
      fetch: hanging,
      timeoutMs: 20,
    });
    expect(timedOut).toMatchObject({ ok: false, reason: "timeout" });
    const failing: typeof fetch = async () => {
      throw new Error("connection refused");
    };
    expect(await fetchDiscovery(ISSUER, { fetch: failing })).toMatchObject({
      ok: false,
      reason: "fetch_failed",
      detail: "Error: connection refused",
    });
    expect(
      await fetchJwks(`${ISSUER}/j`, { fetch: answering(200, '{"keys":[{"kty":"EC"}]}') }),
    ).toEqual({
      ok: true,
      keys: 1,
    });
  });
});
