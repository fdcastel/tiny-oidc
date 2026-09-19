// The single source of every advertised capability (TIO-DISC-002, TIO-DISC-004).
// Discovery is generated from this constant and the validators of §5.4 and
// §5.6 import it; a lint rule forbids literal capability lists anywhere else.

export const CAPABILITIES = {
  scopes_supported: ["openid", "profile", "email", "groups", "offline_access", "account", "admin"],
  response_types_supported: ["code"],
  response_modes_supported: ["query"],
  grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["ES256"],
  token_endpoint_auth_methods_supported: [
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
  ],
  token_endpoint_auth_signing_alg_values_supported: ["ES256", "ES384", "EdDSA", "PS256", "RS256"],
  revocation_endpoint_auth_methods_supported: [
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
  ],
  code_challenge_methods_supported: ["S256"],
  claims_supported: [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "at_hash",
    "name",
    "updated_at",
    "email",
    "email_verified",
    "groups",
  ],
  acr_values_supported: ["urn:tinyoidc:acr:passkey", "urn:tinyoidc:acr:federated"],
  /** Accepted `prompt` values (TIO-AUTHZ-011); `select_account` is treated as `login`. */
  prompt_values_supported: ["none", "login", "consent", "select_account"],
} as const;

export type Scope = (typeof CAPABILITIES.scopes_supported)[number];
export type AcrValue = (typeof CAPABILITIES.acr_values_supported)[number];

export const ACR = {
  passkey: CAPABILITIES.acr_values_supported[0],
  federated: CAPABILITIES.acr_values_supported[1],
} as const;

/** Signing algorithm of every token the OP issues (§10.1). */
export const SIGNING_ALG = CAPABILITIES.id_token_signing_alg_values_supported[0];

export function isScope(value: string): value is Scope {
  return (CAPABILITIES.scopes_supported as readonly string[]).includes(value);
}
