import { describe, expect, it } from "vitest";
import type { FakeUpstream } from "../support/fake-upstream/index.ts";
import worker, { createProvider, type FakeUpstreamEnv } from "../support/fake-upstream/worker.ts";

// The standalone fake upstream Worker (TIO-TEST-031): every request reaches
// the one object that holds the provider, configured from the environment.

describe("fake upstream Worker", () => {
  it("[TIO-TEST-031] serves discovery, authorize and token from one object configured by the deploy environment", async () => {
    const issuer = "https://idp.staging.example";
    const env = {
      FAKE_ISSUER: issuer,
      FAKE_CLIENT_ID: "tiny-oidc",
      FAKE_CLIENT_SECRET: "s3cret",
      FAKE_REDIRECT_URIS: " https://auth.staging.example/federation/callback, ,",
    } as FakeUpstreamEnv;
    // The object as the Worker addresses it: one provider, built once from the environment.
    let created = 0;
    let provider: Promise<FakeUpstream> | null = null;
    const namespace = {
      idFromName: (name: string) => ({ name }),
      get: () => {
        created += 1;
        return {
          fetch: async (request: Request) => {
            provider ??= createProvider(env);
            return (await provider).handle(request);
          },
        };
      },
    } as unknown as FakeUpstreamEnv["FAKE_UPSTREAM"];
    const bound = { ...env, FAKE_UPSTREAM: namespace };
    const discovery = await worker.fetch(
      new Request(`${issuer}/.well-known/openid-configuration`),
      bound,
    );
    expect(discovery.status).toBe(200);
    expect(await discovery.json()).toMatchObject({ issuer, token_endpoint: `${issuer}/token` });
    const authorize = await worker.fetch(
      new Request(
        `${issuer}/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: "tiny-oidc",
          redirect_uri: "https://auth.staging.example/federation/callback",
          state: "s",
          nonce: "n",
          x_sub: "alice",
        })}`,
      ),
      bound,
    );
    expect(authorize.status).toBe(302);
    const code = new URL(authorize.headers.get("location") as string).searchParams.get("code");
    expect(code).not.toBeNull();
    const token = await worker.fetch(
      new Request(`${issuer}/token`, {
        method: "POST",
        headers: {
          authorization: `Basic ${btoa("tiny-oidc:s3cret")}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code as string,
          redirect_uri: "https://auth.staging.example/federation/callback",
        }).toString(),
      }),
      bound,
    );
    expect(token.status).toBe(200);
    expect(await token.json()).toMatchObject({ token_type: "Bearer" });
    // Every request went through the same object; a foreign redirect URI is refused.
    expect(created).toBe(3);
    const foreign = await worker.fetch(
      new Request(
        `${issuer}/authorize?response_type=code&client_id=tiny-oidc&redirect_uri=https://elsewhere.example/cb`,
      ),
      bound,
    );
    expect(foreign.status).toBe(400);
  });
});
