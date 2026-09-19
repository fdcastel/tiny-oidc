// base64url without padding (RFC 4648 §5), strict on decode: only the alphabet,
// no padding, and canonical (re-encoding must reproduce the input) so that a
// flipped trailing bit is rejected rather than silently ignored.

const ALPHABET = /^[A-Za-z0-9_-]*$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Returns the decoded bytes, or null when the input is not canonical base64url. */
export function decodeBase64Url(text: string): Uint8Array | null {
  if (!ALPHABET.test(text) || text.length % 4 === 1) return null;
  const padded =
    text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return encodeBase64Url(bytes) === text ? bytes : null;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
