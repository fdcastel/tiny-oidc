import {
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
  type AttestationObject,
  cose,
  decodeAttestationObject,
  decodeCredentialPublicKey,
  isoCBOR,
} from "@simplewebauthn/server/helpers";
import { z } from "zod";
import { randomBytes } from "../crypto/random.ts";
import type { NewPasskey } from "../do/UserDO.ts";
import { decodeBase64Url, encodeBase64Url } from "../util/base64url.ts";

// Passkey ceremonies (spec §6.1). Options are built exactly as §6.1.2 and
// §6.1.4 prescribe; verification is @simplewebauthn/server (TIO-CRYPTO-001)
// with the OP's expectations (TIO-PK-002) applied on top.

/** COSE algorithms in preference order (TIO-PK-010). */
export const SUPPORTED_ALGORITHMS = [-8, -7, -257] as const;
/** Ceremony timeout in milliseconds and challenge lifetime in seconds (§5.7.4). */
export const CEREMONY_TIMEOUT_MS = 300_000;
export const CHALLENGE_TTL_SECONDS = 300;
export const CREDENTIAL_ID_MIN_BYTES = 16;
export const CREDENTIAL_ID_MAX_BYTES = 1_023;

/** A 32-byte random challenge, base64url (TIO-PK-010, TIO-PK-020). */
export function newChallenge(): string {
  return encodeBase64Url(randomBytes(32));
}

export interface RegistrationOptionsInput {
  rpId: string;
  rpName: string;
  /** The 16 raw bytes of the user's UUID. */
  userId: Uint8Array;
  userName: string;
  displayName: string;
  challenge: string;
  excludeCredentialIds: string[];
}

/** Registration options per TIO-PK-010. */
export function registrationOptions(
  input: RegistrationOptionsInput,
): PublicKeyCredentialCreationOptionsJSON {
  return {
    rp: { id: input.rpId, name: input.rpName },
    user: {
      id: encodeBase64Url(input.userId),
      name: input.userName,
      displayName: input.displayName,
    },
    challenge: input.challenge,
    pubKeyCredParams: SUPPORTED_ALGORITHMS.map((alg) => ({ type: "public-key", alg })),
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    excludeCredentials: input.excludeCredentialIds.map((id) => ({ id, type: "public-key" })),
    extensions: { credProps: true },
  };
}

/** Authentication options per TIO-PK-020: discoverable credentials only. */
export function authenticationOptions(
  rpId: string,
  challenge: string,
): PublicKeyCredentialRequestOptionsJSON {
  return {
    challenge,
    rpId,
    timeout: CEREMONY_TIMEOUT_MS,
    userVerification: "required",
    allowCredentials: [],
  };
}

/** The user name shown by authenticators: the email, or `user-` plus the first 8 hex digits of the id (TIO-PK-010). */
export function authenticatorUserName(email: string | null, userId: string): string {
  return email ?? `user-${userId.replaceAll("-", "").slice(0, 8)}`;
}

export type RegistrationFailure = "passkey_verification_failed" | "passkey_not_discoverable";
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

export interface RegistrationExpectations {
  challenge: string;
  origins: string[];
  rpId: string;
}

export type VerifiedRegistration =
  | { ok: true; passkey: Omit<NewPasskey, "id" | "name" | "created_via"> }
  /** `reason` is for logs only; the error code is what the client sees (§7.8). */
  | { ok: false; error: RegistrationFailure; reason: string };

const RegistrationShape = z.object({
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal("public-key"),
  response: z.object({
    clientDataJSON: z.string().min(1),
    attestationObject: z.string().min(1),
    transports: z.array(z.string()).optional(),
  }),
  clientExtensionResults: z
    .object({ credProps: z.object({ rk: z.boolean().optional() }).optional() })
    .passthrough()
    .optional(),
});

/**
 * Registration verification (TIO-PK-012, TIO-PK-013, TIO-PK-014): type,
 * challenge, origin, RP ID, UP and UV flags, algorithm, credential id length
 * and discoverability. Attestation is not evaluated (`attestation_policy = ignore`):
 * a statement in any other format is replaced by `none` before verification.
 */
export async function verifyRegistration(
  raw: unknown,
  expected: RegistrationExpectations,
): Promise<VerifiedRegistration> {
  const parsed = RegistrationShape.safeParse(raw);
  if (!parsed.success) return rejected("malformed registration response");
  const response = parsed.data as RegistrationResponseJSON;
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: withoutAttestation(response),
      expectedChallenge: expected.challenge,
      expectedOrigin: expected.origins,
      expectedRPID: expected.rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: [...SUPPORTED_ALGORITHMS],
    });
  } catch (error) {
    // The library throws Errors; String() keeps the message and adds the name.
    return rejected(String(error));
  }
  // With format `none` the library either throws or verifies, so the info is always present.
  const info = verification.registrationInfo as NonNullable<typeof verification.registrationInfo>;
  // TIO-PK-013: an explicit rk: false means the credential is not discoverable.
  if (parsed.data.clientExtensionResults?.credProps?.rk === false) {
    return { ok: false, error: "passkey_not_discoverable", reason: "credProps.rk is false" };
  }
  const idLength = (decodeBase64Url(info.credential.id) as Uint8Array).length;
  if (idLength < CREDENTIAL_ID_MIN_BYTES || idLength > CREDENTIAL_ID_MAX_BYTES) {
    return rejected(`credential id of ${idLength} bytes`);
  }
  return {
    ok: true,
    passkey: {
      credential_id: info.credential.id,
      public_key: info.credential.publicKey,
      // The library has already rejected any algorithm outside SUPPORTED_ALGORITHMS.
      alg: decodeCredentialPublicKey(info.credential.publicKey).get(
        cose.COSEKEYS.alg,
      ) as number as SupportedAlgorithm,
      counter: info.credential.counter,
      transports: info.credential.transports ?? [],
      aaguid: info.aaguid,
      backup_eligible: info.credentialDeviceType === "multiDevice",
      backed_up: info.credentialBackedUp,
    },
  };
}

function rejected(reason: string): VerifiedRegistration {
  return { ok: false, error: "passkey_verification_failed", reason };
}

/**
 * The response with any attestation statement other than `none` dropped
 * (TIO-PK-012, `attestation_policy = ignore`). Input that is not base64url
 * is passed through for the library to reject; undecodable CBOR throws to
 * the caller's catch.
 */
function withoutAttestation(response: RegistrationResponseJSON): RegistrationResponseJSON {
  const bytes = decodeBase64Url(response.response.attestationObject);
  if (!bytes) return response;
  const attestation: AttestationObject = decodeAttestationObject(new Uint8Array(bytes));
  if (attestation.get("fmt") === "none") return response;
  const stripped = new Map<string, string | Map<string, never> | Uint8Array>();
  stripped.set("fmt", "none");
  stripped.set("attStmt", new Map<string, never>());
  stripped.set("authData", attestation.get("authData"));
  return {
    ...response,
    response: {
      ...response.response,
      attestationObject: encodeBase64Url(isoCBOR.encode(stripped)),
    },
  };
}

export interface AssertionExpectations {
  challenge: string;
  origins: string[];
  rpId: string;
}

const AuthenticationShape = z.object({
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal("public-key"),
  response: z.object({
    clientDataJSON: z.string().min(1),
    authenticatorData: z.string().min(1),
    signature: z.string().min(1),
    userHandle: z.string().optional(),
  }),
  clientExtensionResults: z.object({}).passthrough().optional(),
});

/** The credential id and user handle of an assertion, without verifying it (routing, TIO-PK-021). */
export function assertionIdentity(
  raw: unknown,
): { credentialId: string; userHandle: string | null } | null {
  const parsed = AuthenticationShape.safeParse(raw);
  if (!parsed.success) return null;
  return { credentialId: parsed.data.id, userHandle: parsed.data.response.userHandle ?? null };
}

export interface StoredCredential {
  credential_id: string;
  public_key: Uint8Array;
}

export type VerifiedAssertion =
  | { ok: true; newCounter: number }
  | { ok: false; error: "passkey_verification_failed" };

/**
 * Signature and client-data verification of an assertion (TIO-PK-022):
 * `webauthn.get`, challenge, origin, RP ID hash, UP and UV flags, and the
 * signature over `authenticatorData || SHA-256(clientDataJSON)`. The counter
 * policy is applied by the caller with the stored counter (TIO-PK-030).
 */
export async function verifyAssertionSignature(
  raw: unknown,
  credential: StoredCredential,
  expected: AssertionExpectations,
): Promise<VerifiedAssertion> {
  const parsed = AuthenticationShape.safeParse(raw);
  if (!parsed.success) return { ok: false, error: "passkey_verification_failed" };
  try {
    const verification = await verifyAuthenticationResponse({
      response: parsed.data as AuthenticationResponseJSON,
      expectedChallenge: expected.challenge,
      expectedOrigin: expected.origins,
      expectedRPID: expected.rpId,
      requireUserVerification: true,
      credential: {
        id: credential.credential_id,
        publicKey: new Uint8Array(credential.public_key),
        // The library's own counter check is disabled (counter 0 skips it); the OP applies §6.1.5 itself.
        counter: 0,
      },
    });
    if (!verification.verified) return { ok: false, error: "passkey_verification_failed" };
    return { ok: true, newCounter: verification.authenticationInfo.newCounter };
  } catch {
    return { ok: false, error: "passkey_verification_failed" };
  }
}

/** Signature-counter policy (TIO-PK-030). */
export function counterPolicy(stored: number, observed: number): "accept" | "regression" {
  if (stored === 0 && observed === 0) return "accept";
  return observed > stored ? "accept" : "regression";
}
