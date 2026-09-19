import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  type JSONWebKeySet,
  jwtVerify,
} from "jose";
import { secretsEqual, sha256 } from "../crypto/hash.ts";
import type { Clock } from "../env.ts";
import { utf8 } from "../util/base64url.ts";
import { CAPABILITIES } from "./capabilities.ts";
import { ClientsUnavailableError } from "./client-cache.ts";
import type { Client } from "./clients.ts";
import type { RemoteJwksCache } from "./jwks-cache.ts";

// Client authentication for /token, /par and /revoke (spec §5.6.1). The
// registered `token_endpoint_auth_method` is enforced strictly: credentials
// of any other method, or of two methods at once, are `invalid_client`
// (TIO-TOKEN-002). `private_key_jwt` assertions are verified against the
// client's `jwks` or `jwks_uri` within a 60-second window (TIO-TOKEN-003).

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const ASSERTION_ALGORITHMS = CAPABILITIES.token_endpoint_auth_signing_alg_values_supported;
export const ASSERTION_WINDOW_SECONDS = 60;
export const ASSERTION_JTI_MAX_LENGTH = 255;
export const BASIC_CHALLENGE = 'Basic realm="tiny-oidc"';

/** What the request carried; the form's duplicates have already been rejected. */
export interface PresentedCredentials {
  params: ReadonlyMap<string, string>;
  /** The `Authorization` header, if any. */
  authorization: string | null;
}

export interface ClientAuthContext {
  /** The client record by id, or null when unknown; throws ClientsUnavailableError when D1 is down and the cache is stale. */
  lookup: (clientId: string) => Promise<Client | null>;
  issuer: string;
  /** The token endpoint URL, the alternative `aud` of an assertion. */
  tokenEndpoint: string;
  clock: Clock;
  jwks: RemoteJwksCache;
}

export type ClientAuthResult =
  | { ok: true; client: Client }
  | {
      ok: false;
      error: "invalid_client";
      /** For the log line only; never contains a credential (TIO-TOKEN-004). */
      reason: string;
      /** The client id the request named, for the failed-authentication rate limit (TIO-TOKEN-004). */
      client_id: string | null;
      /** Whether the 401 carries `WWW-Authenticate: Basic` (the request or the client used Basic). */
      basic_challenge: boolean;
    }
  | { ok: false; error: "temporarily_unavailable"; reason: string };

interface BasicCredentials {
  id: string;
  secret: string;
}

/** RFC 6749 §2.3.1: `Basic BASE64(urlencode(id) ":" urlencode(secret))`. */
function parseBasic(header: string): BasicCredentials | null {
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
  if (!match) return null;
  let decoded: string;
  try {
    decoded = atob(match[1] as string);
  } catch {
    return null;
  }
  const colon = decoded.indexOf(":");
  if (colon < 0) return null;
  try {
    return {
      id: decodeURIComponent(decoded.slice(0, colon)),
      secret: decodeURIComponent(decoded.slice(colon + 1)),
    };
  } catch {
    return null;
  }
}

/** Constant-time comparison of a presented secret with the stored SHA-256 (TIO-TOKEN-002). */
export async function secretMatches(client: Client, secret: string): Promise<boolean> {
  if (!client.client_secret_hash) return false;
  return secretsEqual(await sha256(utf8(secret)), client.client_secret_hash);
}

/**
 * Authenticates the client of a token-style request. Unknown and disabled
 * clients, wrong credentials and mixed methods all answer the same
 * `invalid_client` (TIO-ERR-002); the reason is for the log line.
 */
export async function authenticateClient(
  presented: PresentedCredentials,
  context: ClientAuthContext,
): Promise<ClientAuthResult> {
  const { params } = presented;
  const bodyId = params.get("client_id") ?? null;
  const bodySecret = params.get("client_secret") ?? null;
  const assertionType = params.get("client_assertion_type") ?? null;
  const assertion = params.get("client_assertion") ?? null;
  const usedBasic = presented.authorization !== null;
  const rejected = (
    reason: string,
    clientId: string | null,
    basic = usedBasic,
  ): ClientAuthResult => ({
    ok: false,
    error: "invalid_client",
    reason,
    client_id: clientId,
    basic_challenge: basic,
  });

  // 1. Who does the request claim to be?
  let basic: BasicCredentials | null = null;
  if (presented.authorization !== null) {
    basic = parseBasic(presented.authorization);
    if (!basic) return rejected("malformed Authorization header", bodyId);
    if (bodyId !== null && bodyId !== basic.id) {
      return rejected("client_id differs between header and body", bodyId);
    }
  }
  let assertionIssuer: string | null = null;
  if (assertion !== null) {
    assertionIssuer = issuerOf(assertion);
    if (assertionIssuer === null) return rejected("malformed client_assertion", bodyId);
    if (bodyId !== null && bodyId !== assertionIssuer) {
      return rejected("client_id differs between assertion and body", bodyId);
    }
  }
  const clientId = basic?.id ?? assertionIssuer ?? bodyId;
  if (clientId === null) return rejected("no client identification", null);

  // 2. The registered client, failing closed when the directory is unreachable (TIO-ARCH-014).
  let client: Client | null;
  try {
    client = await context.lookup(clientId);
  } catch (error) {
    if (error instanceof ClientsUnavailableError) {
      return { ok: false, error: "temporarily_unavailable", reason: "clients unavailable" };
    }
    throw error;
  }
  if (!client) return rejected("unknown client", clientId);
  if (client.disabled_at !== null) return rejected("client disabled", clientId);

  // 3. Exactly the registered method, nothing else (TIO-TOKEN-002).
  const method = client.token_endpoint_auth_method;
  const wantsBasic = usedBasic || method === "client_secret_basic";
  const extra: string[] = [];
  if (basic && method !== "client_secret_basic") extra.push("Authorization header");
  if (bodySecret !== null && method !== "client_secret_post") extra.push("client_secret");
  if ((assertion !== null || assertionType !== null) && method !== "private_key_jwt") {
    extra.push("client_assertion");
  }
  if (extra.length > 0) {
    return rejected(`${method} client presented ${extra.join(", ")}`, clientId, wantsBasic);
  }
  switch (method) {
    case "none":
      // Nothing else was presented, so the id came from the body.
      return { ok: true, client };
    case "client_secret_basic": {
      if (!basic) return rejected("missing Authorization header", clientId, true);
      if (!(await secretMatches(client, basic.secret))) {
        return rejected("wrong client secret", clientId, true);
      }
      return { ok: true, client };
    }
    case "client_secret_post": {
      if (bodyId === null || bodySecret === null) {
        return rejected("missing client_id or client_secret in the body", clientId);
      }
      if (!(await secretMatches(client, bodySecret)))
        return rejected("wrong client secret", clientId);
      return { ok: true, client };
    }
    case "private_key_jwt": {
      if (assertionType !== CLIENT_ASSERTION_TYPE) {
        return rejected("missing or unsupported client_assertion_type", clientId);
      }
      if (assertion === null) return rejected("missing client_assertion", clientId);
      const failure = await verifyAssertion(assertion, client, context);
      if (failure !== null) return rejected(failure, clientId);
      return { ok: true, client };
    }
  }
}

/** The `iss` of an unverified assertion, for routing only. */
function issuerOf(assertion: string): string | null {
  try {
    const { iss } = decodeJwt(assertion);
    return typeof iss === "string" && iss.length > 0 ? iss : null;
  } catch {
    return null;
  }
}

/**
 * The `private_key_jwt` checks of TIO-TOKEN-003. Returns the failing
 * condition, or null when the assertion is acceptable.
 */
async function verifyAssertion(
  assertion: string,
  client: Client,
  context: ClientAuthContext,
): Promise<string | null> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(assertion);
  } catch {
    return "malformed client_assertion";
  }
  if (!(ASSERTION_ALGORITHMS as readonly string[]).includes(header.alg ?? "")) {
    return "unsupported assertion alg";
  }
  const now = context.clock.now();
  try {
    let keys: ReturnType<typeof createLocalJWKSet> | ReturnType<RemoteJwksCache["get"]>;
    if (client.jwks !== null) keys = createLocalJWKSet(client.jwks as JSONWebKeySet);
    else if (client.jwks_uri !== null) keys = context.jwks.get(client.jwks_uri);
    else return "client has no keys";
    const { payload } = await jwtVerify(assertion, keys, {
      algorithms: [...ASSERTION_ALGORITHMS],
      issuer: client.client_id,
      subject: client.client_id,
      audience: [context.issuer, context.tokenEndpoint],
      requiredClaims: ["iat", "exp", "jti"],
      clockTolerance: 0,
      currentDate: context.clock.nowDate(),
    });
    // jose has checked signature, iss, sub, aud, the presence of iat/exp/jti and exp > now.
    const iat = payload.iat as number;
    const exp = payload.exp as number;
    if (iat < now - ASSERTION_WINDOW_SECONDS) return "assertion iat too old";
    if (iat > now + ASSERTION_WINDOW_SECONDS) return "assertion iat in the future";
    if (exp > now + ASSERTION_WINDOW_SECONDS) return "assertion exp too far ahead";
    const jti = payload.jti;
    if (typeof jti !== "string" || jti.length === 0 || jti.length > ASSERTION_JTI_MAX_LENGTH) {
      return "assertion jti missing or too long";
    }
    return null;
  } catch (error) {
    // jose's messages name the failing claim, never its value.
    return `assertion rejected: ${String(error)}`;
  }
}
