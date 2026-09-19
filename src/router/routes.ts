// The route table (spec §5.1). One entry per endpoint; the router derives
// CORS behaviour (TIO-HTTP-003), 405 `Allow` headers (TIO-HTTP-001), body
// limits (TIO-HTTP-004), the Permissions-Policy header (TIO-HTTP-002) and the
// log `route` template (TIO-OBS-001) from it. Tests compare it with the
// discovery document and assert every route is exercised (TIO-TEST-008).

export type Cors =
  /** `Access-Control-Allow-Origin: *`, no credentials. */
  | "public"
  /** Reflects the request Origin when it is in `login_origins`, with credentials. */
  | "interactions"
  /** Browser-navigation endpoints: no CORS headers at all. */
  | "none";

export type BodyClass = "protocol" | "api" | "import";

export interface Route {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Hono path pattern, e.g. `/interactions/:id/complete`. */
  path: string;
  cors: Cors;
  /** Top-level navigation endpoint: gets the Permissions-Policy header, never CORS. */
  navigation: boolean;
  /** Public, cacheable response (discovery, JWKS, related origins, OpenAPI). */
  cacheable: boolean;
}

export const BODY_LIMITS: Record<BodyClass, number> = {
  protocol: 16 * 1024,
  api: 64 * 1024,
  import: 8 * 1024 * 1024,
};

export const ROUTES: readonly Route[] = [
  {
    method: "GET",
    path: "/.well-known/openid-configuration",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  {
    method: "GET",
    path: "/.well-known/oauth-authorization-server",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  {
    method: "GET",
    path: "/.well-known/jwks.json",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  {
    method: "GET",
    path: "/.well-known/webauthn",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  { method: "GET", path: "/authorize", cors: "none", navigation: true, cacheable: false },
  { method: "POST", path: "/par", cors: "public", navigation: false, cacheable: false },
  { method: "POST", path: "/token", cors: "public", navigation: false, cacheable: false },
  { method: "GET", path: "/userinfo", cors: "public", navigation: false, cacheable: false },
  { method: "POST", path: "/userinfo", cors: "public", navigation: false, cacheable: false },
  { method: "POST", path: "/revoke", cors: "public", navigation: false, cacheable: false },
  { method: "GET", path: "/logout", cors: "none", navigation: true, cacheable: false },
  { method: "POST", path: "/logout", cors: "none", navigation: true, cacheable: false },
  { method: "GET", path: "/federation/callback", cors: "none", navigation: true, cacheable: false },
  {
    method: "POST",
    path: "/federation/callback",
    cors: "none",
    navigation: true,
    cacheable: false,
  },
  {
    method: "GET",
    path: "/interactions/:id/complete",
    cors: "none",
    navigation: true,
    cacheable: false,
  },
  {
    method: "GET",
    path: "/api/v1/openapi.json",
    cors: "public",
    navigation: false,
    cacheable: true,
  },
  { method: "GET", path: "/api/v1/health", cors: "public", navigation: false, cacheable: false },
  ...interactionRoutes(),
];

/** The Interaction API (§7): one GET and the POST operations, all in the `interactions` CORS class. */
function interactionRoutes(): Route[] {
  const base = "/api/v1/interactions/:id";
  const operations = [
    "passkey/options",
    "passkey/verify",
    "register/options",
    "register/verify",
    "upstream/:alias",
    "consent",
    "abort",
    "logout",
  ];
  return [
    { method: "GET", path: base, cors: "interactions", navigation: false, cacheable: false },
    ...operations.map(
      (op): Route => ({
        method: "POST",
        path: `${base}/${op}`,
        cors: "interactions",
        navigation: false,
        cacheable: false,
      }),
    ),
  ];
}

/** Body limit class of a path (TIO-HTTP-004): 8 MB for import, 64 KB for the JSON APIs, 16 KB elsewhere. */
export function bodyClass(path: string): BodyClass {
  if (path.startsWith("/api/v1/admin/import/")) return "import";
  if (path.startsWith("/api/v1/")) return "api";
  return "protocol";
}

function toRegExp(pattern: string): RegExp {
  const source = pattern
    .split("/")
    .map((segment) =>
      segment.startsWith(":") ? "[^/]+" : segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    )
    .join("/");
  return new RegExp(`^${source}$`);
}

export interface RouteMatch {
  /** The route for the request method, when one exists. */
  route: Route | undefined;
  /** Every method registered on the path (for `Allow`). Empty when the path is unknown. */
  methods: string[];
  /** The path template of the matched path, for logs. */
  template: string | undefined;
}

export type RouteMatcher = (method: string, path: string) => RouteMatch;

/** Compiles a route table into a matcher; exported so tests can exercise patterns not yet in the table. */
export function createMatcher(routes: readonly Route[]): RouteMatcher {
  const compiled = routes.map((route) => ({ route, pattern: toRegExp(route.path) }));
  return (method, path) => {
    const onPath = compiled.filter((c) => c.pattern.test(path)).map((c) => c.route);
    const methods = [...new Set(onPath.map((r) => r.method))];
    const route = onPath.find((r) => r.method === method);
    return { route, methods, template: onPath[0]?.path };
  };
}

export const matchRoute: RouteMatcher = createMatcher(ROUTES);
