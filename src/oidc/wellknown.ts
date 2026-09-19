import type { Handler } from "hono";
import type { Config } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { CAPABILITIES } from "./capabilities.ts";

// Discovery (§5.2), JWKS (§5.3) and WebAuthn related origins (§6.1.1):
// public, cacheable documents served through the Worker cache with
// `Cache-Control: public, max-age=300` (TIO-DISC-001, TIO-KEYS-002).

export const PUBLIC_CACHE_CONTROL = "public, max-age=300";
export const SERVICE_DOCUMENTATION =
  "https://github.com/fdcastel/tiny-oidc/blob/main/doc/TINY_OIDC_SPEC.md";

/** The OIDC discovery document (also served as RFC 8414 metadata), built from the issuer and the capabilities constant. */
export function discoveryDocument(config: Config): Record<string, unknown> {
  const base = config.issuerUrl;
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    pushed_authorization_request_endpoint: `${base}/par`,
    require_pushed_authorization_requests: false,
    token_endpoint: `${base}/token`,
    userinfo_endpoint: `${base}/userinfo`,
    revocation_endpoint: `${base}/revoke`,
    end_session_endpoint: `${base}/logout`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    scopes_supported: CAPABILITIES.scopes_supported,
    response_types_supported: CAPABILITIES.response_types_supported,
    response_modes_supported: CAPABILITIES.response_modes_supported,
    grant_types_supported: CAPABILITIES.grant_types_supported,
    subject_types_supported: CAPABILITIES.subject_types_supported,
    id_token_signing_alg_values_supported: CAPABILITIES.id_token_signing_alg_values_supported,
    token_endpoint_auth_methods_supported: CAPABILITIES.token_endpoint_auth_methods_supported,
    token_endpoint_auth_signing_alg_values_supported:
      CAPABILITIES.token_endpoint_auth_signing_alg_values_supported,
    revocation_endpoint_auth_methods_supported:
      CAPABILITIES.revocation_endpoint_auth_methods_supported,
    code_challenge_methods_supported: CAPABILITIES.code_challenge_methods_supported,
    claims_supported: CAPABILITIES.claims_supported,
    claims_parameter_supported: false,
    request_parameter_supported: false,
    // PAR-issued request_uri values are accepted regardless (RFC 9126 §5); JAR ones are not (TIO-DISC-003).
    request_uri_parameter_supported: false,
    authorization_response_iss_parameter_supported: true,
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
    frontchannel_logout_supported: false,
    acr_values_supported: CAPABILITIES.acr_values_supported,
    ui_locales_supported: [],
    service_documentation: SERVICE_DOCUMENTATION,
    // Not part of the reference document; informational for login apps.
    prompt_values_supported: CAPABILITIES.prompt_values_supported,
  };
}

/** Serves a public document through the Worker cache (`caches.default`) keyed by URL. */
function cached(build: (c: Parameters<Handler<AppEnv>>[0]) => Promise<unknown>): Handler<AppEnv> {
  return async (c) => {
    const cache = caches.default;
    const key = new Request(c.req.url, { method: "GET" });
    const hit = await cache.match(key);
    // A cached Response has immutable headers; copy it so the header middleware can decorate it.
    if (hit) return new Response(hit.body, hit);
    const body = await build(c);
    const response = c.json(body as never, 200, { "Cache-Control": PUBLIC_CACHE_CONTROL });
    c.executionCtx.waitUntil(cache.put(key, response.clone()));
    return response;
  };
}

export const discoveryHandler: Handler<AppEnv> = cached(async (c) =>
  discoveryDocument(c.get("config")),
);

/** Every unretired key's public JWK, never a private parameter (TIO-KEYS-001). */
export const jwksHandler: Handler<AppEnv> = cached(async (c) => {
  const keys = await c.get("keyStore").get(c.get("db"), c.get("config").keys);
  return keys.jwks;
});

/** WebAuthn Related Origin Requests document (TIO-PK-001). */
export const webauthnHandler: Handler<AppEnv> = cached(async (c) => {
  const settings = await c.get("settingsLoader").get(c.get("db"), c.get("config"));
  return { origins: settings.webauthn_origins };
});
