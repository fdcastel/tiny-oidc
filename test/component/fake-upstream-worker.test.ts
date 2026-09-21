import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import type { FakeUpstream, StoredKey } from "../support/fake-upstream/index.ts";
import worker, {
  createProvider,
  type FakeUpstreamEnv,
  storageKeyStore,
} from "../support/fake-upstream/worker.ts";

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

  it("[TIO-TEST-031] a restarted object serves the keys of its first incarnation from its storage, so an OP that cached the JWKS still verifies its ID tokens", async () => {
    const env = {
      FAKE_ISSUER: "https://idp.staging.example",
      FAKE_CLIENT_ID: "tiny-oidc",
      FAKE_CLIENT_SECRET: "s3cret",
      FAKE_REDIRECT_URIS: "https://auth.staging.example/federation/callback",
    } as FakeUpstreamEnv;
    // The storage a Durable Object keeps across restarts, reduced to what the store uses.
    const rows = new Map<string, unknown>();
    const storage = {
      get: async (key: string) => rows.get(key),
      put: async (key: string, value: unknown) => {
        rows.set(key, value);
      },
    } as unknown as DurableObjectStorage;
    const first = await createProvider(env, storageKeyStore(storage));
    const jwks = (await (await first.handle(new Request(`${env.FAKE_ISSUER}/jwks`))).json()) as {
      keys: { kid: string; x: string }[];
    };
    // Two keys, each named by its thumbprint: new material can never carry an old kid.
    const storedKids = (rows.get("keys") as StoredKey[]).map((k) => k.kid);
    expect(new Set(storedKids).size).toBe(2);
    // The JWKS publishes the signing key only.
    expect(jwks.keys.map((k) => k.kid)).toEqual([storedKids[0]]);
    expect(storedKids[0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The second incarnation: same kids, same material, and a fresh incarnation without a store differs.
    const second = await createProvider(env, storageKeyStore(storage));
    const again = (await (await second.handle(new Request(`${env.FAKE_ISSUER}/jwks`))).json()) as {
      keys: { kid: string; x: string }[];
    };
    expect(again).toEqual(jwks);
    const fresh = await createProvider(env);
    const other = (await (await fresh.handle(new Request(`${env.FAKE_ISSUER}/jwks`))).json()) as {
      keys: { kid: string; x: string }[];
    };
    expect(other.keys.map((k) => k.x)).not.toEqual(jwks.keys.map((k) => k.x));
    // A token the second incarnation signs verifies against the first one's JWKS.
    const authorize = await second.handle(
      new Request(
        `${env.FAKE_ISSUER}/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: "tiny-oidc",
          redirect_uri: "https://auth.staging.example/federation/callback",
          state: "s",
          nonce: "n",
        })}`,
      ),
    );
    const code = new URL(authorize.headers.get("location") as string).searchParams.get("code");
    const token = await second.handle(
      new Request(`${env.FAKE_ISSUER}/token`, {
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
    );
    const { id_token: idToken } = (await token.json()) as { id_token: string };
    const verified = await jwtVerify(idToken, createLocalJWKSet(jwks), { issuer: env.FAKE_ISSUER });
    expect(verified.payload["nonce"]).toBe("n");
  });
});
