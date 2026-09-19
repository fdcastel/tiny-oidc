// The OP's two cookies (TIO-SESS-001, TIO-AUTHZ-020): the session cookie and
// per-interaction binding cookies, all `__Host-` prefixed, `Secure`,
// `HttpOnly`, `SameSite=Lax`, `Path=/` and without a `Domain`.

export const SESSION_COOKIE = "__Host-tio_session";
export const BINDING_COOKIE_PREFIX = "__Host-tio_ix_";
/** Characters of the interaction id that name its binding cookie. */
export const BINDING_COOKIE_ID_LENGTH = 16;

/** The request's cookies by name; malformed pairs are skipped and the first occurrence wins. */
export function parseCookies(header: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  if (header === null) return cookies;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name.length > 0 && !cookies.has(name)) cookies.set(name, value);
  }
  return cookies;
}

export function bindingCookieName(interactionId: string): string {
  return `${BINDING_COOKIE_PREFIX}${interactionId.slice(0, BINDING_COOKIE_ID_LENGTH)}`;
}

/** A `Set-Cookie` value that stores `value` for `maxAge` seconds. */
export function setCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

/** A `Set-Cookie` value that removes the cookie. */
export function clearCookie(name: string): string {
  return setCookie(name, "", 0);
}
