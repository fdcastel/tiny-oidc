import { z } from "zod";
import { CAPABILITIES } from "../oidc/capabilities.ts";

// Upstream OIDC providers (spec §6.4.1, §4.1 `upstreams`): the record, its
// validation and the shape the Admin API shows (TIO-ADMIN-003: never a
// secret, never a private key).

export const ALIAS_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/** The upstream client authenticates with a secret or a key; `none` is not an option (§4.1). */
export const UPSTREAM_AUTH_METHODS = CAPABILITIES.token_endpoint_auth_methods_supported.filter(
  (method) => method !== "none",
);

const httpsUrl = z.url({ protocol: /^https$/ }).max(2_048);

/** A private JWK for private_key_jwt; stored encrypted, never returned. */
const PrivateJwkSchema = z.looseObject({
  kty: z.enum(["EC", "RSA", "OKP"]),
  kid: z.string().min(1).max(128),
  d: z.string().min(1),
});

export const DiscoverySchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("auto") }).strict(),
  z
    .object({
      mode: z.literal("manual"),
      authorization_endpoint: httpsUrl,
      token_endpoint: httpsUrl,
      jwks_uri: httpsUrl,
      userinfo_endpoint: httpsUrl.optional(),
    })
    .strict(),
]);

export type Discovery = z.infer<typeof DiscoverySchema>;

const ClaimsMapSchema = z
  .object({
    email: z.string().min(1).max(64).optional(),
    email_verified: z.string().min(1).max(64).optional(),
    name: z.string().min(1).max(64).optional(),
  })
  .strict();

const scalar = z.union([z.string().max(256), z.number(), z.boolean()]);

/** The create body of `POST /admin/upstreams` (§9.4); `client_secret` and `client_jwk` are write-only. */
export const UpstreamInputSchema = z
  .object({
    alias: z.string().regex(ALIAS_PATTERN),
    issuer: httpsUrl,
    display_name: z.string().trim().min(1).max(128),
    client_id: z.string().min(1).max(512),
    token_endpoint_auth_method: z.enum(UPSTREAM_AUTH_METHODS),
    client_secret: z.string().min(1).max(1_024).optional(),
    client_jwk: PrivateJwkSchema.optional(),
    scopes: z.string().trim().min(1).max(512).default("openid email profile"),
    discovery: DiscoverySchema.default({ mode: "auto" }),
    use_userinfo: z.boolean().default(false),
    trust_email_verified: z.boolean().default(false),
    claims_map: ClaimsMapSchema.default({}),
    required_claims: z.record(z.string().max(64), scalar).default({}),
    extra_authorize_params: z.record(z.string().max(64), z.string().max(512)).default({}),
    enabled: z.boolean().default(true),
  })
  .strict();

export type UpstreamInput = z.infer<typeof UpstreamInputSchema>;

/** The stored record (§4.1 `upstreams`) with JSON columns decoded. */
export interface Upstream {
  alias: string;
  issuer: string;
  display_name: string;
  client_id: string;
  token_endpoint_auth_method: UpstreamInput["token_endpoint_auth_method"];
  client_secret_enc: Uint8Array | null;
  client_jwk_enc: Uint8Array | null;
  scopes: string;
  discovery: Discovery;
  use_userinfo: boolean;
  trust_email_verified: boolean;
  claims_map: z.infer<typeof ClaimsMapSchema>;
  required_claims: Record<string, string | number | boolean>;
  extra_authorize_params: Record<string, string>;
  enabled: boolean;
  created_at: number;
  updated_at: number;
}

/** The cross-field rules; each violation names its field. */
export function validateUpstreamInput(
  input: UpstreamInput,
  hasSecret: boolean,
  hasJwk: boolean,
): string[] {
  const violations: string[] = [];
  const scopes = input.scopes.split(/\s+/).filter((s) => s.length > 0);
  if (!scopes.includes("openid")) violations.push("scopes: must contain openid");
  if (new Set(scopes).size !== scopes.length) violations.push("scopes: duplicate values");
  if (input.issuer.includes("#") || input.issuer.includes("?")) {
    violations.push("issuer: must not carry a query or fragment");
  }
  const secretMethod = input.token_endpoint_auth_method !== "private_key_jwt";
  if (secretMethod && !hasSecret) violations.push("client_secret: required for this method");
  if (!secretMethod && !hasJwk) violations.push("client_jwk: required for private_key_jwt");
  if (secretMethod && input.client_jwk !== undefined) {
    violations.push("client_jwk: only for private_key_jwt");
  }
  if (!secretMethod && input.client_secret !== undefined) {
    violations.push("client_secret: only for secret methods");
  }
  if (
    input.use_userinfo &&
    input.discovery.mode === "manual" &&
    !input.discovery.userinfo_endpoint
  ) {
    violations.push("discovery.userinfo_endpoint: required when use_userinfo is set");
  }
  return violations;
}

/** The record as the Admin API shows it: no secret material, plus what operators register (TIO-FED-002). */
export function publicUpstream(upstream: Upstream, issuerUrl: string) {
  const { client_secret_enc: secret, client_jwk_enc: jwk, ...rest } = upstream;
  return {
    ...rest,
    has_client_secret: secret !== null,
    has_client_jwk: jwk !== null,
    redirect_uri: `${issuerUrl}/federation/callback`,
  };
}
