import { z } from "zod";
import { parseJson } from "../util/json.ts";

// Upstream discovery (spec §6.4.1, TIO-FED-001): the provider's metadata
// document, fetched with a bounded timeout and checked against what the
// operator configured before it is trusted.

export const DISCOVERY_TIMEOUT_MS = 5_000;

const httpsUrl = z.url({ protocol: /^https$/ });

const DiscoveryDocument = z.looseObject({
  issuer: z.string(),
  authorization_endpoint: httpsUrl,
  token_endpoint: httpsUrl,
  jwks_uri: httpsUrl,
  userinfo_endpoint: httpsUrl.optional(),
});

export interface UpstreamMetadata {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint: string | null;
}

export type DiscoveryResult =
  | { ok: true; metadata: UpstreamMetadata }
  | {
      ok: false;
      reason:
        | "fetch_failed"
        | "timeout"
        | "http_error"
        | "not_json"
        | "invalid_document"
        | "issuer_mismatch";
      detail: string;
    };

export interface FetchOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** GETs a JSON document with a timeout; the reasons are the same for discovery and JWKS. */
export async function fetchJson(
  url: string,
  options: FetchOptions,
): Promise<{ ok: true; body: string } | Extract<DiscoveryResult, { ok: false }>> {
  const doFetch = options.fetch ?? fetch;
  let response: Response;
  try {
    response = await doFetch(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(options.timeoutMs ?? DISCOVERY_TIMEOUT_MS),
    });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return { ok: false, reason: timedOut ? "timeout" : "fetch_failed", detail: String(error) };
  }
  if (!response.ok) {
    return { ok: false, reason: "http_error", detail: `status ${response.status}` };
  }
  return { ok: true, body: await response.text() };
}

/**
 * The metadata of `issuer` from its well-known document: the document's
 * `issuer` must equal the configured one exactly, and the three endpoints
 * must be https URLs.
 */
export async function fetchDiscovery(
  issuer: string,
  options: FetchOptions = {},
): Promise<DiscoveryResult> {
  const fetched = await fetchJson(
    `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    options,
  );
  if (!fetched.ok) return fetched;
  const parsed = parseJson(DiscoveryDocument, fetched.body);
  if (!parsed.ok) {
    const reason = parsed.error === "malformed_json" ? "not_json" : "invalid_document";
    return { ok: false, reason, detail: parsed.error };
  }
  if (parsed.value.issuer !== issuer) {
    return { ok: false, reason: "issuer_mismatch", detail: "the document names another issuer" };
  }
  return {
    ok: true,
    metadata: {
      authorization_endpoint: parsed.value.authorization_endpoint,
      token_endpoint: parsed.value.token_endpoint,
      jwks_uri: parsed.value.jwks_uri,
      userinfo_endpoint: parsed.value.userinfo_endpoint ?? null,
    },
  };
}

const JwksDocument = z.looseObject({
  keys: z.array(z.looseObject({ kty: z.string() })),
});

export type JwksResult = { ok: true; keys: number } | Extract<DiscoveryResult, { ok: false }>;

/** Fetches a JWKS and reports how many keys it carries (the `test` endpoint). */
export async function fetchJwks(url: string, options: FetchOptions = {}): Promise<JwksResult> {
  const fetched = await fetchJson(url, options);
  if (!fetched.ok) return fetched;
  const parsed = parseJson(JwksDocument, fetched.body);
  if (!parsed.ok) {
    const reason = parsed.error === "malformed_json" ? "not_json" : "invalid_document";
    return { ok: false, reason, detail: parsed.error };
  }
  return { ok: true, keys: parsed.value.keys.length };
}
