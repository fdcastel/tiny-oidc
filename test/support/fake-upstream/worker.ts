import { DurableObject } from "cloudflare:workers";
import { FakeUpstream } from "./index.ts";

// The fake upstream as a standalone Worker for staging (TIO-TEST-031,
// TIO-DEPLOY-001): one Durable Object holds the provider so codes issued by
// `/authorize` are found by `/token` whichever isolate serves the request.
// The signing keys live in memory: after the object restarts the JWKS
// publishes new ones and the OP refetches on the unknown `kid`.
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

/** The provider as the environment describes it. */
export function createProvider(env: Omit<FakeUpstreamEnv, "FAKE_UPSTREAM">): Promise<FakeUpstream> {
  return FakeUpstream.create({
    issuer: env.FAKE_ISSUER,
    client_id: env.FAKE_CLIENT_ID,
    client_secret: env.FAKE_CLIENT_SECRET,
    redirect_uris: env.FAKE_REDIRECT_URIS.split(",")
      .map((u) => u.trim())
      .filter((u) => u.length > 0),
  });
}

export class FakeUpstreamObject extends DurableObject<FakeUpstreamEnv> {
  private provider: Promise<FakeUpstream> | null = null;

  override async fetch(request: Request): Promise<Response> {
    this.provider ??= createProvider(this.env);
    return (await this.provider).handle(request);
  }
}

export default {
  fetch(request: Request, env: FakeUpstreamEnv): Promise<Response> {
    return env.FAKE_UPSTREAM.get(env.FAKE_UPSTREAM.idFromName("provider")).fetch(request);
  },
};
