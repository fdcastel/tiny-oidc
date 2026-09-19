import { z } from "zod";
import { sha256 } from "../crypto/hash.ts";
import { newSecret, randomBytes } from "../crypto/random.ts";
import { insertClient } from "../db/clients.ts";
import type { Db } from "../db/db.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { CAPABILITIES, type Scope, type TokenEndpointAuthMethod } from "./capabilities.ts";
import { isRegistrableRedirectUri } from "./redirect-uri.ts";

// Client model and validation (spec §5.11). Clients are created and updated
// only through the Admin API (TIO-CLIENT-001); every rule of TIO-CLIENT-002 is
// a named check below.

export const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;

/** TTL bounds of §5.7.4 for per-client overrides. */
export const TTL_BOUNDS = {
  access_token_ttl: [60, 3_600],
  id_token_ttl: [60, 3_600],
  refresh_token_ttl: [86_400, 7_776_000],
  refresh_idle_ttl: [3_600, 2_592_000],
} as const;

const PublicJwkSchema = z
  .object({
    kty: z.enum(["EC", "RSA", "OKP"]),
    kid: z.string().min(1).max(128),
    alg: z.string().optional(),
    use: z.string().optional(),
    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),
    n: z.string().optional(),
    e: z.string().optional(),
  })
  .strict()
  .refine((k) => !("d" in k) && !("p" in k), "only public keys are accepted");

export const JwksSchema = z.object({ keys: z.array(PublicJwkSchema).min(1).max(8) }).strict();

const grantType = z.enum(CAPABILITIES.grant_types_supported);
const authMethod = z.enum(CAPABILITIES.token_endpoint_auth_methods_supported);
const scope = z.enum(CAPABILITIES.scopes_supported);
const httpsUrl = z.url({ protocol: /^https$/ });
const ttl = (key: keyof typeof TTL_BOUNDS) =>
  z.int().min(TTL_BOUNDS[key][0]).max(TTL_BOUNDS[key][1]).nullable().default(null);

/** The Admin API create/update body (§9.4 Clients). */
export const ClientInputSchema = z
  .object({
    client_id: z.string().regex(CLIENT_ID_PATTERN).optional(),
    client_name: z.string().trim().min(1).max(128),
    client_uri: httpsUrl.nullable().default(null),
    logo_uri: httpsUrl.nullable().default(null),
    redirect_uris: z.array(z.string().max(2_048)).max(32).default([]),
    post_logout_redirect_uris: z.array(z.string().max(2_048)).max(32).default([]),
    backchannel_logout_uri: z.string().max(2_048).nullable().default(null),
    grant_types: z.array(grantType).min(1),
    token_endpoint_auth_method: authMethod,
    jwks: JwksSchema.nullable().default(null),
    jwks_uri: httpsUrl.nullable().default(null),
    scopes_allowed: z.array(scope).min(1),
    audiences: z.array(z.string().max(512)).max(16).default([]),
    allowed_groups: z.array(z.string()).nullable().default(null),
    skip_consent: z.boolean().default(false),
    require_par: z.boolean().default(false),
    offline_access: z.boolean().default(false),
    access_token_ttl: ttl("access_token_ttl"),
    id_token_ttl: ttl("id_token_ttl"),
    refresh_token_ttl: ttl("refresh_token_ttl"),
    refresh_idle_ttl: ttl("refresh_idle_ttl"),
  })
  .strict();

export type ClientInput = z.infer<typeof ClientInputSchema>;

/** A client record as stored (§4.1 `clients`), with JSON columns decoded. */
export interface Client {
  client_id: string;
  client_name: string;
  client_uri: string | null;
  logo_uri: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  backchannel_logout_uri: string | null;
  grant_types: (typeof CAPABILITIES.grant_types_supported)[number][];
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  client_secret_hash: Uint8Array | null;
  jwks: z.infer<typeof JwksSchema> | null;
  jwks_uri: string | null;
  scopes_allowed: Scope[];
  audiences: string[];
  allowed_groups: string[] | null;
  skip_consent: boolean;
  require_par: boolean;
  offline_access: boolean;
  access_token_ttl: number | null;
  id_token_ttl: number | null;
  refresh_token_ttl: number | null;
  refresh_idle_ttl: number | null;
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface ValidationContext {
  issuer: string;
  /** Whether the acting principal holds `admin` (only such actors may grant the `admin` scope). */
  actorHasAdmin: boolean;
  /** Names of the groups that exist, for `allowed_groups`. */
  existingGroups: ReadonlySet<string>;
}

function isAudience(value: string): boolean {
  if (value.includes("#")) return false;
  if (/^urn:[a-z0-9][a-z0-9-]{0,31}:\S+$/i.test(value)) return true;
  try {
    const url = new URL(value);
    const canonical = url.href === value || url.href === `${value}/`;
    return url.protocol === "https:" && url.hostname !== "" && canonical;
  } catch {
    return false;
  }
}

function hasDuplicates(values: readonly string[]): boolean {
  return new Set(values).size !== values.length;
}

/** The cross-field rules of TIO-CLIENT-002; each violation names its field. */
export function validateClientInput(input: ClientInput, context: ValidationContext): string[] {
  const violations: string[] = [];
  const grants = new Set(input.grant_types);
  const code = grants.has("authorization_code");
  if (hasDuplicates(input.grant_types)) violations.push("grant_types: duplicates");
  if (grants.has("refresh_token") && !code) {
    violations.push("grant_types: refresh_token requires authorization_code");
  }
  if (code && input.redirect_uris.length === 0) {
    violations.push("redirect_uris: required for authorization_code");
  }
  if (!code && input.redirect_uris.length > 0) {
    violations.push("redirect_uris: must be empty without authorization_code");
  }
  if (hasDuplicates(input.redirect_uris)) violations.push("redirect_uris: duplicates");
  for (const uri of input.redirect_uris) {
    if (!isRegistrableRedirectUri(uri))
      violations.push(`redirect_uris: "${uri}" is not registrable`);
  }
  if (hasDuplicates(input.post_logout_redirect_uris)) {
    violations.push("post_logout_redirect_uris: duplicates");
  }
  for (const uri of input.post_logout_redirect_uris) {
    if (!isRegistrableRedirectUri(uri)) {
      violations.push(`post_logout_redirect_uris: "${uri}" is not registrable`);
    }
  }
  if (input.backchannel_logout_uri !== null) {
    const uri = input.backchannel_logout_uri;
    const ok = httpsUrl.safeParse(uri).success && !uri.includes("#");
    if (!ok) violations.push("backchannel_logout_uri: must be an https URL without a fragment");
  }
  const method = input.token_endpoint_auth_method;
  if (method === "none") {
    const allowed = [...grants].every((g) => g === "authorization_code" || g === "refresh_token");
    if (!code || !allowed) {
      violations.push(
        "token_endpoint_auth_method: none requires grant_types of authorization_code with optional refresh_token",
      );
    }
  }
  if (grants.has("client_credentials") && method === "none") {
    violations.push(
      "grant_types: client_credentials requires a confidential authentication method",
    );
  }
  if (method === "private_key_jwt") {
    if ((input.jwks === null) === (input.jwks_uri === null)) {
      violations.push("jwks: private_key_jwt requires exactly one of jwks or jwks_uri");
    }
  } else if (input.jwks !== null || input.jwks_uri !== null) {
    violations.push("jwks: only private_key_jwt clients register keys");
  }
  if (hasDuplicates(input.scopes_allowed)) violations.push("scopes_allowed: duplicates");
  if (input.scopes_allowed.includes("admin") && !context.actorHasAdmin) {
    violations.push("scopes_allowed: admin may only be granted by an administrator");
  }
  if (hasDuplicates(input.audiences)) violations.push("audiences: duplicates");
  for (const audience of input.audiences) {
    if (!isAudience(audience))
      violations.push(`audiences: "${audience}" is not an https URI or URN`);
    else if (audience === context.issuer) {
      violations.push("audiences: the issuer is added by scope, never configured");
    }
  }
  if (input.allowed_groups !== null) {
    if (hasDuplicates(input.allowed_groups)) violations.push("allowed_groups: duplicates");
    for (const group of input.allowed_groups) {
      if (!context.existingGroups.has(group)) {
        violations.push(`allowed_groups: group "${group}" does not exist`);
      }
    }
  }
  return violations;
}

const CLIENT_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

/** `c_` followed by 22 characters of [a-z0-9] (~114 bits), so that generated ids satisfy the client id pattern (TIO-DATA-003). */
export function generateClientId(): string {
  const bytes = randomBytes(22);
  let id = "c_";
  for (const byte of bytes) id += CLIENT_ID_ALPHABET[byte % CLIENT_ID_ALPHABET.length];
  return id;
}

export interface GeneratedSecret {
  /** Returned exactly once (TIO-CLIENT-003). */
  secret: string;
  hash: Uint8Array;
}

/** 32 random bytes, base64url; only its SHA-256 is stored (TIO-CLIENT-003, TIO-CRYPTO-004). */
export async function generateClientSecret(): Promise<GeneratedSecret> {
  const secret = encodeBase64Url(newSecret());
  return { secret, hash: await sha256(secret) };
}

/** Whether the method uses a shared secret. */
export function usesSecret(method: TokenEndpointAuthMethod): boolean {
  return method === "client_secret_basic" || method === "client_secret_post";
}

/** The record to store for a validated input (secret hash set by the caller when the method uses one). */
export function clientFromInput(
  input: ClientInput,
  clientId: string,
  secretHash: Uint8Array | null,
  now: number,
): Client {
  return {
    client_id: clientId,
    client_name: input.client_name,
    client_uri: input.client_uri,
    logo_uri: input.logo_uri,
    redirect_uris: input.redirect_uris,
    post_logout_redirect_uris: input.post_logout_redirect_uris,
    backchannel_logout_uri: input.backchannel_logout_uri,
    grant_types: input.grant_types,
    token_endpoint_auth_method: input.token_endpoint_auth_method,
    client_secret_hash: secretHash,
    jwks: input.jwks,
    jwks_uri: input.jwks_uri,
    scopes_allowed: input.scopes_allowed,
    audiences: input.audiences,
    allowed_groups: input.allowed_groups,
    skip_consent: input.skip_consent,
    require_par: input.require_par,
    offline_access: input.offline_access,
    access_token_ttl: input.access_token_ttl,
    id_token_ttl: input.id_token_ttl,
    refresh_token_ttl: input.refresh_token_ttl,
    refresh_idle_ttl: input.refresh_idle_ttl,
    disabled_at: null,
    created_at: now,
    updated_at: now,
  };
}

export type CreateClientResult =
  | { ok: true; client: Client; secret: string | null }
  | { ok: false; error: "invalid_client"; violations: string[] }
  | { ok: false; error: "client_exists" };

/**
 * Creates a client: schema and cross-field validation, id and secret
 * generation, one insert. The secret is returned exactly once (TIO-CLIENT-003).
 * Used by the Admin API and by test factories.
 */
export async function createClient(
  db: Db,
  raw: unknown,
  context: ValidationContext,
  now: number,
): Promise<CreateClientResult> {
  const parsed = ClientInputSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: "invalid_client",
      violations: parsed.error.issues.map((i) => `${i.path.join(".") || "$"}: ${i.message}`),
    };
  }
  const violations = validateClientInput(parsed.data, context);
  if (violations.length > 0) return { ok: false, error: "invalid_client", violations };
  const clientId = parsed.data.client_id ?? generateClientId();
  const generated = usesSecret(parsed.data.token_endpoint_auth_method)
    ? await generateClientSecret()
    : null;
  const client = clientFromInput(parsed.data, clientId, generated?.hash ?? null, now);
  const inserted = await insertClient(db, client);
  if (inserted === "client_exists") return { ok: false, error: "client_exists" };
  return { ok: true, client, secret: generated?.secret ?? null };
}
