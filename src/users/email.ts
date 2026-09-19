// Email semantics (spec §3.3): an attribute, never an identifier. Stored as
// given, compared after trimming, NFC normalization and lower-casing
// (TIO-DATA-005).

export const EMAIL_MAX_LENGTH = 254;

/** The WHATWG HTML `input[type=email]` grammar. */
const EMAIL_PATTERN =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

/** The comparison form of an email. */
export function normalizeEmail(email: string): string {
  return email.trim().normalize("NFC").toLowerCase();
}

/** Syntactic validity after trimming, within 254 characters. */
export function isValidEmail(email: string): boolean {
  const trimmed = email.trim();
  return trimmed.length > 0 && trimmed.length <= EMAIL_MAX_LENGTH && EMAIL_PATTERN.test(trimmed);
}
