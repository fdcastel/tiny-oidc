import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";
import type { Clock } from "../env.ts";
import { SIGNING_ALG } from "../oidc/capabilities.ts";
import type { LoadedKeys } from "./keystore.ts";

// JWT signing and verification of the OP's own tokens over jose (spec §10.1,
// TIO-KEYS-013, TIO-KEYS-015, TIO-TOKEN-034).

export type TokenTyp = "JWT" | "at+jwt" | "logout+jwt";

/** Upper bound of the encoded JOSE header (TIO-KEYS-015). */
export const MAX_HEADER_BYTES = 512;

export class HeaderTooLargeError extends Error {
  constructor(bytes: number) {
    super(`JOSE header is ${bytes} bytes, over ${MAX_HEADER_BYTES}`);
    this.name = "HeaderTooLargeError";
  }
}

/** Signs `claims` with the signing key; the header carries exactly alg, typ and kid. */
export async function signJwt(
  keys: LoadedKeys,
  typ: TokenTyp,
  claims: JWTPayload,
): Promise<string> {
  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg: SIGNING_ALG, typ, kid: keys.signing.kid })
    .sign(keys.signing.privateKey);
  const header = jwt.slice(0, jwt.indexOf("."));
  if (header.length > MAX_HEADER_BYTES) throw new HeaderTooLargeError(header.length);
  return jwt;
}

export interface VerifyOptions {
  issuer: string;
  typ: TokenTyp;
  /** Required audience; the token's `aud` must contain it. */
  audience?: string;
  /** For the logout `id_token_hint`: signature, `iss` and `typ` are checked, expiry is ignored (TIO-LOGOUT-001). */
  ignoreExpiry?: boolean;
}

/**
 * Verifies one of the OP's own tokens against every unretired key (TIO-KEYS-013)
 * with `iss`, `typ`, optional `aud`, `exp` with 0 s leeway from the injected
 * clock (TIO-TOKEN-034). A token signed by a retired or unknown `kid`, or with
 * another algorithm, is rejected. Returns the payload or null.
 */
export async function verifyOwnJwt(
  keys: LoadedKeys,
  token: string,
  options: VerifyOptions,
  clock: Clock,
): Promise<JWTPayload | null> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return null;
  }
  if (header.alg !== SIGNING_ALG || header.typ !== options.typ || typeof header.kid !== "string") {
    return null;
  }
  try {
    const verifyOptions: Parameters<typeof jwtVerify>[2] = {
      issuer: options.issuer,
      typ: options.typ,
      algorithms: [SIGNING_ALG],
      clockTolerance: 0,
      currentDate: clock.nowDate(),
      requiredClaims: ["iat", "exp", "sub"],
    };
    if (options.audience !== undefined) verifyOptions.audience = options.audience;
    const { payload } = await jwtVerify(token, createLocalJWKSet(keys.jwks), verifyOptions);
    return payload;
  } catch (error) {
    if (!options.ignoreExpiry || !(error instanceof Error) || error.name !== "JWTExpired")
      return null;
    // Expired hint: re-run every other check with the clock set to the token's own iat,
    // which jose has already required to be present.
    const iat = decodeJwt(token).iat as number;
    const atIssue = clock.nowDate();
    atIssue.setTime(iat * 1000);
    return verifyOwnJwt(
      keys,
      token,
      { ...options, ignoreExpiry: false },
      { ...clock, nowDate: () => atIssue },
    );
  }
}
