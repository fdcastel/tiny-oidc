import { sealSecret } from "../../src/crypto/secretbox.ts";
import { Db } from "../../src/db/db.ts";
import { insertUpstream } from "../../src/db/upstreams.ts";
import type { Upstream } from "../../src/federation/upstreams.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { interactionStub } from "../../src/oidc/interactions.ts";
import { utf8 } from "../../src/util/base64url.ts";
import type { FakeUpstream, Fault } from "./fake-upstream/index.ts";
import { mountOrigin } from "./fetch-allowlist.ts";
import type { CallOptions, Harness, Started } from "./http.ts";
import { testKeys } from "./keys.ts";
import { env } from "./op.ts";

// Federated logins in tests: an upstream row sealed like the Admin API seals
// it, the fake provider mounted on the outbound interceptor, and a driver that
// walks the browser's part of the flow (interaction → provider → callback).

export const IDP = "https://idp.example.com";
export const IDP_CLIENT_ID = "tiny-oidc-at-idp";
export const IDP_CLIENT_SECRET = "idp-shared-secret";

export interface UpstreamOverrides
  extends Partial<Omit<Upstream, "client_secret_enc" | "client_jwk_enc">> {
  client_secret?: string | null;
  client_jwk?: Record<string, unknown> | null;
}

/** Registers an upstream row the way `POST /admin/upstreams` would (secrets sealed). */
export async function registerUpstream(
  clock: { now(): number },
  overrides: UpstreamOverrides = {},
): Promise<Upstream> {
  const keys = testKeys();
  const { client_secret: secret, client_jwk: jwk, ...rest } = overrides;
  const upstream: Upstream = {
    alias: "idp",
    issuer: IDP,
    display_name: "Example IdP",
    client_id: IDP_CLIENT_ID,
    token_endpoint_auth_method: "client_secret_basic",
    client_secret_enc:
      secret === null ? null : await sealSecret(keys, utf8(secret ?? IDP_CLIENT_SECRET)),
    client_jwk_enc:
      jwk === undefined || jwk === null ? null : await sealSecret(keys, utf8(JSON.stringify(jwk))),
    scopes: "openid email profile",
    discovery: { mode: "auto" },
    use_userinfo: false,
    trust_email_verified: true,
    claims_map: {},
    required_claims: {},
    extra_authorize_params: {},
    forward_login_hint: false,
    enabled: true,
    created_at: clock.now(),
    updated_at: clock.now(),
    ...rest,
  };
  const inserted = await insertUpstream(Db.from(env.DB), upstream);
  if (inserted !== "created") throw new Error(inserted);
  return upstream;
}

/** Routes the fake provider's origin to its handler for the rest of the file. */
export function mountFakeUpstream(fake: FakeUpstream, origin = IDP): void {
  mountOrigin(origin, (request) => fake.handle(request));
}

export interface FederatedStep {
  started: Started;
  /** The provider's authorization URL the OP asked the browser to visit. */
  authorizeUrl: URL;
  /** Where the provider sent the browser (the OP's callback), or null on an upstream refusal. */
  callbackUrl: URL | null;
  /** The OP's answer to the callback. */
  callback: Response;
  /** Where the OP sent the browser afterwards. */
  next: URL;
}

export interface DriveOptions {
  alias?: string;
  scope?: string;
  /** Which person the provider acts as (`x_sub`). */
  sub?: string;
  faults?: Fault[];
  invitation?: string;
  /** Extra authorize overrides the harness sends with /authorize. */
  authorize?: Record<string, string>;
  /** Present the callback with another cookie (null: none). */
  cookie?: string | null;
  /** Send the callback as a POST form instead of a GET. */
  post?: boolean;
  sessionCookie?: string;
  /** Runs between the provider's redirect and the callback (to move state under its feet). */
  beforeCallback?: (started: Started) => Promise<void> | void;
  /** The environment the callback runs against (fault injection). */
  env?: CallOptions["env"];
}

/** Walks one federated login up to the OP's redirect after the callback. */
export async function driveFederation(
  h: Harness,
  fake: FakeUpstream,
  client: Client,
  options: DriveOptions = {},
): Promise<FederatedStep> {
  const started = await h.start(
    client,
    { scope: options.scope ?? "openid email profile", ...options.authorize },
    options.sessionCookie,
  );
  const begun = await h.post(
    started,
    `upstream/${options.alias ?? "idp"}`,
    options.invitation === undefined ? {} : { invitation: options.invitation },
  );
  if (begun.status !== 200) throw new Error(`upstream: ${begun.status} ${await begun.text()}`);
  const { redirect_to } = (await begun.json()) as { redirect_to: string };
  const authorizeUrl = new URL(redirect_to);
  if (options.sub !== undefined) authorizeUrl.searchParams.set("x_sub", options.sub);
  for (const fault of options.faults ?? []) authorizeUrl.searchParams.append("fault", fault);
  const atProvider = await fake.handle(new Request(authorizeUrl.href));
  const location = atProvider.headers.get("location");
  if (atProvider.status !== 302 || location === null) {
    throw new Error(`provider answered ${atProvider.status}`);
  }
  const callbackUrl = new URL(location);
  const cookie = options.cookie === undefined ? started.cookie : options.cookie;
  await options.beforeCallback?.(started);
  const env = options.env === undefined ? {} : { env: options.env };
  const callback = options.post
    ? await h.send(callbackUrl.pathname, {
        method: "POST",
        origin: null,
        cookie,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: callbackUrl.searchParams.toString(),
        ...env,
      })
    : await h.send(`${callbackUrl.pathname}${callbackUrl.search}`, {
        origin: null,
        cookie,
        ...env,
      });
  const next = new URL(
    callback.headers.get("location") ?? "https://none.invalid/",
    "https://none.invalid/",
  );
  return { started, authorizeUrl, callbackUrl, callback, next };
}

/** The interaction document behind a step. */
export async function docOf(step: FederatedStep, now: number) {
  const got = await interactionStub(env, step.started.id).get(now);
  if (!got.ok) throw new Error(got.error);
  return got.doc;
}
