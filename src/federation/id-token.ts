import { decodeProtectedHeader, type JWTPayload, jwtVerify } from "jose";
import type { Clock } from "../env.ts";
import { UPSTREAM_ID_TOKEN_ALGORITHMS } from "../oidc/capabilities.ts";
import type { RemoteJwks } from "../oidc/jwks-cache.ts";
import type { Upstream } from "./upstreams.ts";

// Validation of the upstream ID token (spec §6.4.4, TIO-FED-030) and
// extraction of the claims the OP keeps (TIO-FED-032, TIO-FED-033).

export const EXP_LEEWAY_SECONDS = 60;
export const IAT_MAX_AGE_SECONDS = 600;
export const IAT_FUTURE_LEEWAY_SECONDS = 60;

export type IdTokenFailure =
  | "malformed"
  | "alg"
  | "signature"
  | "iss"
  | "aud"
  | "azp"
  | "exp"
  | "iat"
  | "nonce"
  | "sub";

export type IdTokenResult =
  | { ok: true; claims: JWTPayload & { sub: string } }
  | { ok: false; reason: IdTokenFailure };

export interface IdTokenExpectations {
  issuer: string;
  clientId: string;
  nonce: string;
  jwks: RemoteJwks;
  clock: Clock;
}

/** Every rule of TIO-FED-030, each with its own reason, so each one has its own negative test. */
export async function verifyUpstreamIdToken(
  token: string,
  expected: IdTokenExpectations,
): Promise<IdTokenResult> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!(UPSTREAM_ID_TOKEN_ALGORITHMS as readonly string[]).includes(header.alg ?? "")) {
    return { ok: false, reason: "alg" };
  }
  const now = expected.clock.now();
  let payload: JWTPayload;
  try {
    // jose checks the signature, iss, aud and exp (with leeway); the rest is checked below.
    ({ payload } = await jwtVerify(token, expected.jwks, {
      algorithms: [...UPSTREAM_ID_TOKEN_ALGORITHMS],
      issuer: expected.issuer,
      audience: expected.clientId,
      clockTolerance: EXP_LEEWAY_SECONDS,
      currentDate: expected.clock.nowDate(),
    }));
  } catch (error) {
    return { ok: false, reason: joseReason(error) };
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (aud.length > 1 && payload["azp"] !== expected.clientId) return { ok: false, reason: "azp" };
  const iat = payload.iat;
  if (
    typeof iat !== "number" ||
    iat < now - IAT_MAX_AGE_SECONDS ||
    iat > now + IAT_FUTURE_LEEWAY_SECONDS
  ) {
    return { ok: false, reason: "iat" };
  }
  if (payload["nonce"] !== expected.nonce) return { ok: false, reason: "nonce" };
  const sub = payload.sub;
  if (typeof sub !== "string" || sub.length < 1 || sub.length > 255) {
    return { ok: false, reason: "sub" };
  }
  return { ok: true, claims: { ...payload, sub } };
}

/** Maps jose's errors to the rule that failed. */
function joseReason(error: unknown): IdTokenFailure {
  const code = (error as { code?: string }).code ?? "";
  const claim = (error as { claim?: string }).claim ?? "";
  if (code === "ERR_JWT_EXPIRED") return "exp";
  if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    if (claim === "iss") return "iss";
    if (claim === "aud") return "aud";
    return "exp";
  }
  if (code === "ERR_JWS_INVALID" || code === "ERR_JWT_INVALID") return "malformed";
  return "signature";
}

export interface UpstreamClaims {
  sub: string;
  email: string | null;
  /** True only with `trust_email_verified` and a boolean `true` claim (TIO-FED-033). */
  email_verified: boolean;
  name: string | null;
}

/** The claims the OP keeps, read through `claims_map` from the merged ID-token and userinfo claims. */
export function extractClaims(
  upstream: Pick<Upstream, "claims_map" | "trust_email_verified">,
  merged: Record<string, unknown>,
  sub: string,
): UpstreamClaims {
  const map = upstream.claims_map;
  const email = merged[map.email ?? "email"];
  const verified = merged[map.email_verified ?? "email_verified"];
  const name = merged[map.name ?? "name"];
  return {
    sub,
    email: typeof email === "string" && email.length > 0 ? email : null,
    email_verified: upstream.trust_email_verified && verified === true,
    name: typeof name === "string" && name.length > 0 ? name : null,
  };
}

/** Strict equality of every required claim (TIO-FED-032); returns the first that differs. */
export function missingRequiredClaim(
  required: Record<string, string | number | boolean>,
  merged: Record<string, unknown>,
): string | null {
  for (const [key, value] of Object.entries(required)) {
    if (merged[key] !== value) return key;
  }
  return null;
}
