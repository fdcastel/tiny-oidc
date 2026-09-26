import { maskEmail } from "../users/email.ts";

// Redaction of audit payloads (spec §11, TIO-AUDIT-002): whatever an emitter
// puts into `data` or `reason`, nothing that looks like a token, a code, a
// handle, a secret, a hash, a challenge, a WebAuthn response, an address, a
// user agent or an unmasked email reaches a sink — not even the subject's own
// in an admin diff, which the Admin API already records as changed only
// (ADR 0020). The allow-lists of the catalog drop unknown keys first; this is
// the second net.

export const REDACTED = "[redacted]";

/** Keys whose values are secrets by name, wherever they appear. */
const SECRET_KEYS = new Set([
  "token",
  "tokens",
  "access_token",
  "refresh_token",
  "id_token",
  "logout_token",
  "code",
  "secret",
  "client_secret",
  "secret_hash",
  "hash",
  "challenge",
  "password",
  "response",
  "assertion",
  "client_assertion",
  "private_jwk",
  "private_key",
  "cookie",
  "authorization",
  "state",
  "nonce",
  "code_verifier",
  "user_agent",
  "ip",
  "error_description",
]);

const HANDLE = /tio_[a-z]{2}_/;
const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OPAQUE = /^[A-Za-z0-9_-]{32,}$/;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^(?=.*[0-9a-f])[0-9a-f]*(?::[0-9a-f]*){2,7}$/i;
const USER_AGENT = /Mozilla\/|AppleWebKit|Chrome\/|Safari\/|Firefox\//;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function scrubString(value: string): string {
  if (HANDLE.test(value) || JWT.test(value) || USER_AGENT.test(value)) return REDACTED;
  // A bare opaque string is a secret whatever its key; key thumbprints travel as `kid:<thumbprint>`.
  if (!UUID.test(value) && OPAQUE.test(value)) return REDACTED;
  if (IPV4.test(value) || IPV6.test(value)) return REDACTED;
  // Addresses are masked wherever they appear (TIO-IX-021, TIO-PRIV-002).
  if (EMAIL.test(value)) return maskEmail(value) as string;
  return value;
}

function scrub(value: unknown): unknown {
  if (typeof value === "string") return scrubString(value);
  if (Array.isArray(value)) return value.map((item) => scrub(item));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS.has(k)) {
        out[k] = REDACTED;
        continue;
      }
      out[k] = scrub(v);
    }
    return out;
  }
  return value;
}

/** The `data` of an event with every suspicious value replaced. */
export function redactData(data: Record<string, unknown>): Record<string, unknown> {
  return scrub(data) as Record<string, unknown>;
}

/** A `reason` is a machine-readable word; anything that looks like more is replaced. */
export function redactReason(reason: string | null): string | null {
  if (reason === null) return null;
  return scrubString(reason);
}
