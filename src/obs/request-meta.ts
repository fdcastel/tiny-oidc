import { hmacSha256 } from "../crypto/hash.ts";
import type { DerivedKeys } from "../crypto/master-keys.ts";
import type { SessionMetadata } from "../do/UserDO.ts";
import { encodeBase64Url, utf8 } from "../util/base64url.ts";

// What a session or audit record keeps about the request (TIO-SESS-005,
// §11.5): a pseudonymized IP, the browser family with its major version, and
// the country Cloudflare attaches. Never the address or the full user agent.

/** HMAC-SHA256 of the address under `tio/v1/iphash`, truncated to 16 bytes, base64url. */
export async function ipHash(keys: DerivedKeys, ip: string | null): Promise<string | null> {
  if (ip === null) return null;
  const key = await (keys.hmacKey("iphash") as Promise<CryptoKey>);
  return encodeBase64Url((await hmacSha256(key, utf8(ip))).slice(0, 16));
}

const FAMILIES: [RegExp, string][] = [
  [/\bEdg(?:e|A|iOS)?\/(\d+)/, "Edge"],
  [/\bOPR\/(\d+)/, "Opera"],
  [/\bFirefox\/(\d+)/, "Firefox"],
  [/\bFxiOS\/(\d+)/, "Firefox"],
  [/\bCriOS\/(\d+)/, "Chrome"],
  [/\bChrome\/(\d+)/, "Chrome"],
  [/\bVersion\/(\d+)[.\d]* .*\bSafari\//, "Safari"],
];

/** `Family/major` (for example `Chrome/128`), `Other` for anything else, null without a header. */
export function uaFamily(userAgent: string | null): string | null {
  if (userAgent === null) return null;
  for (const [pattern, family] of FAMILIES) {
    const match = pattern.exec(userAgent);
    if (match) return `${family}/${match[1]}`;
  }
  return "Other";
}

/** The metadata of a request, for a new session. */
export async function sessionMetadata(
  keys: DerivedKeys,
  request: Request,
): Promise<SessionMetadata> {
  const cf = (request as Request & { cf?: { country?: string } }).cf;
  return {
    ip_hash: await ipHash(keys, request.headers.get("cf-connecting-ip")),
    ua_family: uaFamily(request.headers.get("user-agent")),
    country: typeof cf?.country === "string" ? cf.country : null,
  };
}
