import { importJWK, SignJWT } from "jose";
import { z } from "zod";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import { openSecret } from "../crypto/secretbox.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import type { Clock } from "../env.ts";
import { parseJson } from "../util/json.ts";
import type { UpstreamMetadata } from "./discovery.ts";
import type { Upstream } from "./upstreams.ts";

// The code exchange with the upstream (spec §6.4.3, TIO-FED-022) and the
// optional userinfo call (TIO-FED-031), both bounded in time and both
// answering "upstream_error" for anything that is not the expected JSON.

export const TOKEN_TIMEOUT_MS = 10_000;
export const USERINFO_TIMEOUT_MS = 5_000;
export const ASSERTION_TTL_SECONDS = 60;

const TokenResponse = z.looseObject({
  access_token: z.string().min(1),
  id_token: z.string().min(1),
  token_type: z.string().optional(),
});

const Claims = z.record(z.string(), z.unknown());

export type ExchangeResult =
  | { ok: true; access_token: string; id_token: string }
  | { ok: false; reason: string };

export interface ExchangeInput {
  upstream: Upstream;
  metadata: UpstreamMetadata;
  code: string;
  redirect_uri: string;
  code_verifier: string;
  keys: DerivedKeys;
  clock: Clock;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

type PrivateJwk = Record<string, unknown> & { kid?: string; alg?: string; kty: string };

/** A client assertion for private_key_jwt: signed with the upstream's private JWK, 60 s, fresh jti. */
async function clientAssertion(
  upstream: Upstream,
  tokenEndpoint: string,
  keys: DerivedKeys,
  clock: Clock,
): Promise<string | null> {
  if (upstream.client_jwk_enc === null) return null;
  const opened = await openSecret(keys, upstream.client_jwk_enc);
  if (opened === null) return null;
  const parsed = parseJson(z.looseObject({ kty: z.string() }), new TextDecoder().decode(opened));
  if (!parsed.ok) return null;
  const jwk = parsed.value as PrivateJwk;
  const alg = typeof jwk.alg === "string" ? jwk.alg : jwk.kty === "RSA" ? "RS256" : "ES256";
  const now = clock.now();
  try {
    const key = await importJWK(jwk, alg);
    return await new SignJWT({})
      .setProtectedHeader({ alg, ...(typeof jwk.kid === "string" ? { kid: jwk.kid } : {}) })
      .setIssuer(upstream.client_id)
      .setSubject(upstream.client_id)
      .setAudience(tokenEndpoint)
      .setIssuedAt(now)
      .setExpirationTime(now + ASSERTION_TTL_SECONDS)
      .setJti(new UuidV7(clock).next())
      .sign(key);
  } catch {
    return null;
  }
}

/** POSTs the code to the token endpoint with the configured client authentication. */
export async function exchangeCode(input: ExchangeInput): Promise<ExchangeResult> {
  const { upstream, metadata, keys, clock } = input;
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirect_uri,
    code_verifier: input.code_verifier,
  });
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  if (upstream.token_endpoint_auth_method === "private_key_jwt") {
    const assertion = await clientAssertion(upstream, metadata.token_endpoint, keys, clock);
    if (assertion === null) return { ok: false, reason: "client_key_unavailable" };
    form.set("client_id", upstream.client_id);
    form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    form.set("client_assertion", assertion);
  } else {
    const opened =
      upstream.client_secret_enc === null
        ? null
        : await openSecret(keys, upstream.client_secret_enc);
    if (opened === null) return { ok: false, reason: "client_secret_unavailable" };
    const secret = new TextDecoder().decode(opened);
    if (upstream.token_endpoint_auth_method === "client_secret_basic") {
      headers["authorization"] = `Basic ${btoa(
        `${encodeURIComponent(upstream.client_id)}:${encodeURIComponent(secret)}`,
      )}`;
    } else {
      form.set("client_id", upstream.client_id);
      form.set("client_secret", secret);
    }
  }
  const doFetch = input.fetch ?? fetch;
  let response: Response;
  try {
    response = await doFetch(metadata.token_endpoint, {
      method: "POST",
      headers,
      body: form.toString(),
      signal: AbortSignal.timeout(input.timeoutMs ?? TOKEN_TIMEOUT_MS),
    });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return { ok: false, reason: timedOut ? "token_timeout" : "token_unreachable" };
  }
  if (!response.ok) return { ok: false, reason: `token_status_${response.status}` };
  const parsed = parseJson(TokenResponse, await response.text());
  if (!parsed.ok) return { ok: false, reason: "token_malformed" };
  return { ok: true, access_token: parsed.value.access_token, id_token: parsed.value.id_token };
}

export type UserinfoResult =
  | { ok: true; claims: Record<string, unknown> }
  | { ok: false; reason: string };

/** GETs userinfo with the upstream access token; the caller checks `sub` (TIO-FED-031). */
export async function fetchUserinfo(
  endpoint: string,
  accessToken: string,
  options: { fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<UserinfoResult> {
  const doFetch = options.fetch ?? fetch;
  let response: Response;
  try {
    response = await doFetch(endpoint, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      signal: AbortSignal.timeout(options.timeoutMs ?? USERINFO_TIMEOUT_MS),
    });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return { ok: false, reason: timedOut ? "userinfo_timeout" : "userinfo_unreachable" };
  }
  if (!response.ok) return { ok: false, reason: `userinfo_status_${response.status}` };
  const parsed = parseJson(Claims, await response.text());
  if (!parsed.ok) return { ok: false, reason: "userinfo_malformed" };
  return { ok: true, claims: parsed.value };
}
