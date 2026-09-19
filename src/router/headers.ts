import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "./context.ts";
import { matchRoute, type Route } from "./routes.ts";

// Security headers (TIO-HTTP-002) and the CORS matrix (TIO-HTTP-003), both
// derived from the route table. The `interactions` class reflects the request
// Origin only when it is one of the effective `login_origins`, with credentials.

const ALLOWED_HEADERS = "Authorization, Content-Type";
const MAX_AGE = "600";

/** Headers every response carries. Cache-Control is set only when a cacheable route already set one. */
export function applySecurityHeaders(headers: Headers, route: Route | undefined): void {
  if (!headers.has("Cache-Control") || !route?.cacheable) headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set(
    "Content-Security-Policy",
    route?.assets
      ? "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
      : "default-src 'none'; frame-ancestors 'none'",
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  if (route?.navigation) {
    headers.set(
      "Permissions-Policy",
      "publickey-credentials-get=(), publickey-credentials-create=()",
    );
  }
}

/** Sets the security headers on every response, including errors and 404s. */
export const securityHeaders: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  const { route } = matchRoute(c.req.method, c.req.path);
  applySecurityHeaders(c.res.headers, route);
};

function publicCorsHeaders(methods: string[]): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": methods.join(", "),
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    "Access-Control-Max-Age": MAX_AGE,
  };
}

function loginOriginCorsHeaders(origin: string, methods: string[]): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": methods.join(", "),
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    "Access-Control-Max-Age": MAX_AGE,
    Vary: "Origin",
  };
}

/** Whether the request Origin is an effective login origin; unknown when settings cannot be read. */
async function isLoginOrigin(
  c: Parameters<MiddlewareHandler<AppEnv>>[0],
  origin: string,
): Promise<boolean> {
  try {
    const settings = await c.get("settingsLoader").get(c.get("db"), c.get("config"));
    return settings.login_origins?.includes(origin) ?? false;
  } catch {
    return false;
  }
}

/**
 * CORS per route class: preflights are answered here; actual responses get
 * the allow-origin header after the handler runs. Navigation endpoints and
 * unknown paths get nothing.
 */
export const cors: MiddlewareHandler<AppEnv> = async (c, next) => {
  const path = c.req.path;
  const origin = c.req.header("Origin") ?? null;
  if (c.req.method === "OPTIONS") {
    const requested = c.req.header("Access-Control-Request-Method") ?? "GET";
    const { route, methods } = matchRoute(requested, path);
    if (route?.cors === "public") return c.body(null, 204, publicCorsHeaders(methods));
    if (route?.cors === "interactions" && origin !== null && (await isLoginOrigin(c, origin))) {
      return c.body(null, 204, loginOriginCorsHeaders(origin, methods));
    }
    return c.body(null, 204);
  }
  await next();
  const { route } = matchRoute(c.req.method, path);
  if (route?.cors === "public") {
    c.res.headers.set("Access-Control-Allow-Origin", "*");
    c.res.headers.set("Access-Control-Expose-Headers", "X-Request-Id");
  } else if (
    route?.cors === "interactions" &&
    origin !== null &&
    (await isLoginOrigin(c, origin))
  ) {
    c.res.headers.set("Access-Control-Allow-Origin", origin);
    c.res.headers.set("Access-Control-Allow-Credentials", "true");
    c.res.headers.set("Access-Control-Expose-Headers", "X-Request-Id");
    c.res.headers.set("Vary", "Origin");
  }
};
