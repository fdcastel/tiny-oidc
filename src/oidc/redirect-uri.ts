// Redirect URI registration and matching rules (spec §5.11.3, RFC 8252).

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]"]);

function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith("[");
}

/**
 * Whether a URI may be registered (TIO-CLIENT-010): absolute, no fragment, and
 * (a) https with a non-empty, non-IP host; (b) http on the loopback interface
 * (127.0.0.1 or [::1], any port); or (c) a private-use scheme containing a dot.
 * `http://localhost` and wildcards are rejected.
 */
export function isRegistrableRedirectUri(value: string): boolean {
  if (value.includes("*") || value.includes("#") || /\s/.test(value)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  // The registered form must be canonical: what the parser would print, except
  // that an origin-only URI may omit the trailing slash.
  if (url.href !== value && url.href !== `${value}/`) return false;
  if (url.username !== "" || url.password !== "") return false;
  switch (url.protocol) {
    case "https:":
      return url.hostname !== "" && !isIpLiteral(url.hostname);
    case "http:":
      return LOOPBACK_HOSTS.has(url.hostname);
    default: {
      // Private-use scheme, reverse-DNS: at least one dot in the scheme (RFC 8252 §7.1).
      const scheme = url.protocol.slice(0, -1);
      return scheme.includes(".") && /^[a-z][a-z0-9+.-]*$/i.test(scheme);
    }
  }
}

/** Whether a registered URI is a loopback URI whose port may vary at authorization time (RFC 8252 §7.3). */
export function isLoopbackRedirectUri(registered: string): boolean {
  try {
    const url = new URL(registered);
    return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Exact, byte-for-byte matching against the registered strings (TIO-CLIENT-011),
 * with the single loopback exception: the port of a registered `http://127.0.0.1`
 * or `http://[::1]` URI may differ. Returns the registered entry that matched.
 */
export function matchRedirectUri(registered: readonly string[], requested: string): string | null {
  for (const candidate of registered) {
    if (candidate === requested) return candidate;
    if (isLoopbackRedirectUri(candidate) && sameExceptPort(candidate, requested)) return candidate;
  }
  return null;
}

function sameExceptPort(registered: string, requested: string): boolean {
  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(requested);
  } catch {
    return false;
  }
  if (b.href !== requested) return false;
  if (a.protocol !== b.protocol || a.hostname !== b.hostname) return false;
  if (a.username !== b.username || a.password !== b.password) return false;
  return a.pathname === b.pathname && a.search === b.search && a.hash === b.hash;
}
