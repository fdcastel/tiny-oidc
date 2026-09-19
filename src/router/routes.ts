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
  /** Static files of the bundled login app: the CSP admits same-origin scripts and styles (TIO-IX-081). */
  assets?: boolean;
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
  {
    method: "POST",
    path: "/api/v1/admin/bootstrap",
    cors: "public",
    navigation: false,
    cacheable: false,
  },
  ...interactionRoutes(),
  ...adminRoutes(),
  {
    method: "GET",
    path: "/login/*",
    cors: "none",
    navigation: false,
    cacheable: true,
    assets: true,
  },
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

/** The Admin API (§9.4): JSON under /api/v1/admin, bearer-protected, public CORS (TIO-HTTP-003). */
function adminRoutes(): Route[] {
  const operations: [Route["method"], string][] = [
    ["GET", "users"],
    ["POST", "users"],
    ["GET", "users/:id"],
    ["PATCH", "users/:id"],
    ["DELETE", "users/:id"],
    ["POST", "users/:id/disable"],
    ["POST", "users/:id/enable"],
    ["GET", "users/:id/passkeys"],
    ["DELETE", "users/:id/passkeys/:pid"],
    ["GET", "users/:id/identities"],
    ["DELETE", "users/:id/identities/:iid"],
    ["GET", "users/:id/sessions"],
    ["DELETE", "users/:id/sessions/:sid"],
    ["DELETE", "users/:id/sessions"],
    ["GET", "users/:id/refresh-families"],
    ["DELETE", "users/:id/refresh-families/:fid"],
    ["DELETE", "users/:id/refresh-families"],
    ["GET", "users/:id/grants"],
    ["DELETE", "users/:id/grants/:client_id"],
    ["GET", "users/:id/events"],
    ["POST", "users/:id/invitations"],
    ["POST", "users/:id/reindex"],
    ["GET", "users/:id/export"],
    ["POST", "users/:id/restore"],
    ["GET", "groups"],
    ["POST", "groups"],
    ["GET", "groups/:id"],
    ["PATCH", "groups/:id"],
    ["DELETE", "groups/:id"],
    ["GET", "groups/:id/members"],
    ["PUT", "groups/:id/members/:user_id"],
    ["DELETE", "groups/:id/members/:user_id"],
    ["GET", "clients"],
    ["POST", "clients"],
    ["GET", "clients/:id"],
    ["PATCH", "clients/:id"],
    ["DELETE", "clients/:id"],
    ["POST", "clients/:id/rotate-secret"],
    ["POST", "clients/:id/disable"],
    ["POST", "clients/:id/enable"],
    ["GET", "upstreams"],
    ["POST", "upstreams"],
    ["GET", "upstreams/:alias"],
    ["PATCH", "upstreams/:alias"],
    ["DELETE", "upstreams/:alias"],
    ["POST", "upstreams/:alias/test"],
  ];
  return operations.map(
    ([method, path]): Route => ({
      method,
      path: `/api/v1/admin/${path}`,
      cors: "public",
      navigation: false,
      cacheable: false,
    }),
  );
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
    .map((segment) => {
      if (segment.startsWith(":")) return "[^/]+";
      if (segment === "*") return ".*";
      return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
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
