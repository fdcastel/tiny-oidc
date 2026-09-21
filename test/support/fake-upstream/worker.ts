import { DurableObject } from "cloudflare:workers";
import { FakeUpstream, type KeyStore, type StoredKey } from "./index.ts";

// The fake upstream as a standalone Worker for staging (TIO-TEST-031,
// TIO-DEPLOY-001): one Durable Object holds the provider so codes issued by
// `/authorize` are found by `/token` whichever isolate serves the request.
// The signing keys are generated once and kept in the object's storage, so
// a restart of the object (eviction, deploy) serves the same JWKS: new
// material under the same kids would fail every signature at an OP isolate
// that had cached the previous set, and a known kid never triggers a refetch.
//
// Configuration comes from the deploy environment (scripts/deploy-fake-upstream.ts),
// never from this repository: the issuer, the relying party's client id and
// secret, and the redirect URIs it accepts. It is deployable to staging only.

export interface FakeUpstreamEnv {
  FAKE_ISSUER: string;
  FAKE_CLIENT_ID: string;
  FAKE_CLIENT_SECRET: string;
  /** Comma-separated. */
  FAKE_REDIRECT_URIS: string;
  FAKE_UPSTREAM: DurableObjectNamespace<FakeUpstreamObject>;
}

/** The provider as the environment describes it, its keys from the store when one is given. */
export function createProvider(
  env: Omit<FakeUpstreamEnv, "FAKE_UPSTREAM">,
  store?: KeyStore,
): Promise<FakeUpstream> {
  return FakeUpstream.create(
    {
      issuer: env.FAKE_ISSUER,
      client_id: env.FAKE_CLIENT_ID,
      client_secret: env.FAKE_CLIENT_SECRET,
      redirect_uris: env.FAKE_REDIRECT_URIS.split(",")
        .map((u) => u.trim())
        .filter((u) => u.length > 0),
    },
    store,
  );
}

const KEYS = "keys";

/** The object's storage as the provider's key store. */
export function storageKeyStore(storage: DurableObjectStorage): KeyStore {
  return {
    load: () => storage.get<StoredKey[]>(KEYS),
    save: (keys) => storage.put(KEYS, keys),
  };
}

export class FakeUpstreamObject extends DurableObject<FakeUpstreamEnv> {
  private provider: Promise<FakeUpstream> | null = null;

  override async fetch(request: Request): Promise<Response> {
    this.provider ??= createProvider(this.env, storageKeyStore(this.ctx.storage));
    return (await this.provider).handle(request);
  }
}

export default {
  fetch(request: Request, env: FakeUpstreamEnv): Promise<Response> {
    return env.FAKE_UPSTREAM.get(env.FAKE_UPSTREAM.idFromName("provider")).fetch(request);
  },
};
