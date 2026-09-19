// Registrable-domain approximation used for the same-site rules of §6.1.1 and
// the 5-label limit of Related Origin Requests (TIO-PK-001). The OP embeds no
// public-suffix list; the last two labels are the registrable domain except
// under a short list of well-known second-level public suffixes (co.uk, com.br…),
// where the last three labels are. Loopback hosts are their own site.

const SECOND_LEVEL_SUFFIXES = new Set([
  "co",
  "com",
  "org",
  "net",
  "gov",
  "edu",
  "ac",
  "or",
  "ne",
  "gob",
  "mil",
]);

export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || /^[\d.]+$/.test(host) || host.startsWith("[")) return host;
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const secondLevel = labels[labels.length - 2] as string;
  const tld = labels[labels.length - 1] as string;
  const take =
    SECOND_LEVEL_SUFFIXES.has(secondLevel) && tld.length === 2 && labels.length >= 3 ? 3 : 2;
  return labels.slice(-take).join(".");
}

/** Same-site: equal registrable domains (scheme is checked by the caller). */
export function sameSite(hostA: string, hostB: string): boolean {
  return registrableDomain(hostA) === registrableDomain(hostB);
}
