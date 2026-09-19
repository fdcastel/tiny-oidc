import { OpenAPIHono } from "@hono/zod-openapi";
import { bodyLimit } from "hono/body-limit";
import { listArchiveHandler, listAuditHandler, userEventsHandler } from "../admin/audit-log.ts";
import { requireAdmin } from "../admin/auth.ts";
import { bootstrapHandler } from "../admin/bootstrap.ts";
import {
  createClientHandler,
  deleteClientHandler,
  getClientHandler,
  listClientsHandler,
  patchClientHandler,
  rotateSecretHandler,
  setClientDisabledHandler,
} from "../admin/clients.ts";
import {
  createGroupHandler,
  deleteGroupHandler,
  getGroupHandler,
  listGroupsHandler,
  listMembersHandler,
  membershipHandler,
  patchGroupHandler,
} from "../admin/groups.ts";
import { importUsersHandler } from "../admin/import.ts";
import {
  createInvitationHandler,
  deleteInvitationHandler,
  getInvitationHandler,
  listInvitationsHandler,
} from "../admin/invitations.ts";
import {
  getSettingsHandler,
  listKeysHandler,
  patchSettingsHandler,
  purgeHandler,
  reindexAllHandler,
  rekeyHandler,
  retireKeyHandler,
  rotateKeyHandler,
  statsHandler,
} from "../admin/system.ts";
import {
  createUpstreamHandler,
  deleteUpstreamHandler,
  getUpstreamHandler,
  listUpstreamsHandler,
  patchUpstreamHandler,
  testUpstreamHandler,
} from "../admin/upstreams.ts";
import {
  createRecoverInvitationHandler,
  createUserHandler,
  deleteFamiliesOfClientHandler,
  deleteFamilyHandler,
  deleteGrantHandler,
  deleteIdentityHandler,
  deletePasskeyHandler,
  deleteSessionHandler,
  deleteSessionsHandler,
  deleteUserHandler,
  exportUserHandler,
  getUserHandler,
  listFamiliesHandler,
  listGrantsHandler,
  listIdentitiesHandler,
  listPasskeysHandler,
  listSessionsHandler,
  listUsersHandler,
  patchUserHandler,
  reindexUserHandler,
  restoreUserHandler,
  setDisabledHandler,
} from "../admin/users.ts";
import { API_INFO, OPENAPI_PATH, registerApi } from "../api/definitions.ts";
import { Auditor } from "../audit/events.ts";
import { shipAuditEvents } from "../audit/sink.ts";
import { KeyStore } from "../crypto/keystore.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import { Db } from "../db/db.ts";
import { buildConfig, type Clock, type ConfigResult, type Env, SettingsLoader } from "../env.ts";
import { federationCallbackHandler } from "../federation/callback.ts";
import { UPSTREAM_JWKS_COOLDOWN_MS, UpstreamMetadataCache } from "../federation/metadata.ts";
import { upstreamHandler } from "../federation/outbound.ts";
import { abortHandler, consentHandler, getInteractionHandler } from "../interaction/api.ts";
import { completeHandler } from "../interaction/complete.ts";
import { logoutDecisionHandler } from "../interaction/logout.ts";
import { passkeyOptionsHandler, passkeyVerifyHandler } from "../interaction/passkey.ts";
import { registerOptionsHandler, registerVerifyHandler } from "../interaction/register.ts";
import { logoutHandler } from "../logout/rp-logout.ts";
import { requireAccount } from "../me/auth.ts";
import * as me from "../me/handlers.ts";
import { healthHandler } from "../obs/health.ts";
import {
  consoleSink,
  Logger,
  type LogLevel,
  type LogSink,
  type RequestLog,
  serverTiming,
} from "../obs/log.ts";
import { sessionMetadata } from "../obs/request-meta.ts";
import { authorizeHandler } from "../oidc/authorize-endpoint.ts";
import { ClientCache } from "../oidc/client-cache.ts";
import { RemoteJwksCache } from "../oidc/jwks-cache.ts";
import { parHandler } from "../oidc/par-endpoint.ts";
import { revokeHandler } from "../oidc/revoke-endpoint.ts";
import { tokenHandler } from "../oidc/token-endpoint.ts";
import { userinfoHandler } from "../oidc/userinfo-endpoint.ts";
import { discoveryHandler, jwksHandler, webauthnHandler } from "../oidc/wellknown.ts";
import type { AppEnv } from "./context.ts";
import { errorBody, errorResponse } from "./errors.ts";
import { cors, securityHeaders } from "./headers.ts";
import { loginAppHandler } from "./login-app.ts";
import { BODY_LIMITS, bodyClass, matchRoute } from "./routes.ts";

export interface AppDeps {
  clock: Clock;
  /** Where log lines go; console in production, a collector in tests. */
  sink?: LogSink;
}

const MAX_QUERY_BYTES = 8 * 1024;
const HEALTH_PATH = "/api/v1/health";
const BOOTSTRAP_PATH = "/api/v1/admin/bootstrap";

/**
 * Builds the Worker's Hono application (spec §2.1, §5.14). One instance lives
 * per isolate; its caches (startup config, settings) are isolate caches.
 */
export function createApp(deps: AppDeps) {
  const sink = deps.sink ?? consoleSink;
  const uuids = new UuidV7(deps.clock);
  const settingsLoader = new SettingsLoader(deps.clock);
  const keyStore = new KeyStore(deps.clock);
  const clients = new ClientCache(deps.clock);
  const jwks = new RemoteJwksCache();
  const upstreamMetadata = new UpstreamMetadataCache(deps.clock);
  const upstreamJwks = new RemoteJwksCache({ cooldownMs: UPSTREAM_JWKS_COOLDOWN_MS });
  // Startup validation happens at the first request and is remembered for the
  // isolate's lifetime (TIO-CRYPTO-010, TIO-CFG-002).
  let startup: { fingerprint: string; result: ConfigResult } | undefined;
  const configFor = (env: Env): ConfigResult => {
    const fingerprint = JSON.stringify([
      env.ISSUER,
      env.RP_ID,
      env.RP_NAME,
      env.BUNDLED_LOGIN_APP,
      env.LOG_LEVEL,
      env.MASTER_KEYS,
      env.MASTER_KEY_ACTIVE,
      env.ADMIN_BOOTSTRAP_TOKEN,
      env.VERSION,
    ]);
    if (!startup || startup.fingerprint !== fingerprint)
      startup = { fingerprint, result: buildConfig(env) };
    return startup.result;
  };
  const limits = Object.fromEntries(
    Object.entries(BODY_LIMITS).map(([cls, maxSize]) => [
      cls,
      bodyLimit({
        maxSize,
        onError: (c) => errorResponse(c, 413, "payload_too_large", `body exceeds ${maxSize} bytes`),
      }),
    ]),
  ) as Record<ReturnType<typeof bodyClass>, ReturnType<typeof bodyLimit>>;

  const app = new OpenAPIHono<AppEnv>();

  // Outermost so that every response, including startup failures, carries the headers.
  app.use("*", securityHeaders);

  // 1. Request id (TIO-HTTP-005), startup config, per-request context, log line (TIO-OBS-001).
  app.use("*", async (c, next) => {
    const started = deps.clock.nowMs();
    const requestId = uuids.next();
    c.set("requestId", requestId);
    c.header("X-Request-Id", requestId);
    const config = configFor(c.env);
    const level: LogLevel = config.ok ? config.config.logLevel : "info";
    const logger = new Logger(sink, level);
    c.set("logger", logger);
    const metrics = { doCalls: 0 };
    c.set("metrics", metrics);
    const db = Db.from(c.env.DB);
    c.set("db", db);
    c.set("settingsLoader", settingsLoader);
    c.set("keyStore", keyStore);
    c.set("clients", clients);
    c.set("jwks", jwks);
    c.set("upstreamMetadata", upstreamMetadata);
    c.set("upstreamJwks", upstreamJwks);
    if (!config.ok) {
      // Fail every request closed until the configuration is fixed (TIO-ARCH-014).
      logger.log("error", "fatal: invalid configuration", {
        request_id: requestId,
        reason: config.error,
      });
      c.res = c.json(errorBody(requestId, "server_error", "server misconfigured"), 500);
    } else {
      c.set("config", config.config);
      const auditor = new Auditor(
        { request_id: requestId, ...(await sessionMetadata(config.config.keys, c.req.raw)) },
        uuids,
        deps.clock,
      );
      c.set("audit", auditor);
      await next();
      auditor.flush(logger);
      // Sink 1 of TIO-AUDIT-010: the queue, after the response.
      if (auditor.events.length > 0) {
        c.executionCtx.waitUntil(shipAuditEvents(c.env, logger, auditor.events));
      }
    }
    const { template } = matchRoute(c.req.method, c.req.path);
    const contentLength = c.req.header("content-length");
    const line: RequestLog = {
      request_id: requestId,
      route: template ?? "unmatched",
      method: c.req.method,
      status: c.res.status,
      duration_ms: deps.clock.nowMs() - started,
      do_calls: metrics.doCalls,
      d1_reads: db.counters.reads,
      d1_writes: db.counters.writes,
      content_length: contentLength === undefined ? null : Number(contentLength),
    };
    const error = c.get("error");
    if (error !== undefined) line.error = error;
    logger.log("info", "request", { ...line });
    // One data point per request and one per audit event when metrics are bound (TIO-OBS-002).
    c.env.METRICS?.writeDataPoint({
      blobs: [line.route, String(line.status), line.error ?? ""],
      doubles: [line.duration_ms],
      indexes: [line.route],
    });
    for (const event of c.get("audit")?.events ?? []) {
      c.env.METRICS?.writeDataPoint({
        blobs: [event.type, event.outcome],
        doubles: [1],
        indexes: [event.type],
      });
    }
    c.res.headers.set("X-Request-Id", requestId);
    c.res.headers.set("Server-Timing", serverTiming(line));
  });

  app.use("*", cors);

  // 2. Host check (TIO-HTTP-006): the OP never builds URLs from the request Host; a
  //    mismatch is 421, except for the health endpoint which reports it instead.
  app.use("*", async (c, next) => {
    const expected = c.get("config").issuer.host;
    // In Workers the request URL is built from the Host header; the header itself is not exposed.
    const host = new URL(c.req.url).host;
    if (host !== expected && !(c.req.method === "GET" && c.req.path === HEALTH_PATH)) {
      return errorResponse(c, 421, "invalid_host", "request host does not match the issuer");
    }
    await next();
  });

  // 3. Query and body limits (TIO-AUTHZ-001, TIO-HTTP-004).
  app.use("*", async (c, next) => {
    const query = new URL(c.req.url).search;
    if (query.length > MAX_QUERY_BYTES) {
      return errorResponse(c, 414, "invalid_request", "query string exceeds 8 KB");
    }
    return limits[bodyClass(c.req.path)](c, next);
  });

  // Routes
  app.get("/.well-known/openid-configuration", discoveryHandler);
  app.get("/.well-known/oauth-authorization-server", discoveryHandler);
  app.get("/.well-known/jwks.json", jwksHandler);
  app.get("/.well-known/webauthn", webauthnHandler);
  app.get("/api/v1/health", healthHandler(deps.clock));
  app.get("/authorize", authorizeHandler(deps.clock));
  app.post("/par", parHandler(deps.clock));
  app.post("/token", tokenHandler(deps.clock));
  app.on(["GET", "POST"], "/userinfo", userinfoHandler(deps.clock));
  app.post("/revoke", revokeHandler(deps.clock));
  app.on(["GET", "POST"], "/logout", logoutHandler(deps.clock));
  app.on(["GET", "POST"], "/federation/callback", federationCallbackHandler(deps.clock));
  app.get("/interactions/:id/complete", completeHandler(deps.clock));
  // Interaction API (§7); the JSON APIs are documented from their route definitions.
  app.get("/api/v1/interactions/:id", getInteractionHandler(deps.clock));
  app.post("/api/v1/interactions/:id/consent", consentHandler(deps.clock));
  app.post("/api/v1/interactions/:id/abort", abortHandler(deps.clock));
  app.post("/api/v1/interactions/:id/passkey/options", passkeyOptionsHandler(deps.clock));
  app.post("/api/v1/interactions/:id/passkey/verify", passkeyVerifyHandler(deps.clock));
  app.post("/api/v1/interactions/:id/register/options", registerOptionsHandler(deps.clock));
  app.post("/api/v1/interactions/:id/register/verify", registerVerifyHandler(deps.clock));
  app.post("/api/v1/interactions/:id/upstream/:alias", upstreamHandler(deps.clock));
  app.post("/api/v1/interactions/:id/logout", logoutDecisionHandler(deps.clock));
  // Self-service API (§8): every path needs the person's own token.
  app.use("/api/v1/me/*", requireAccount(deps.clock));
  app.get("/api/v1/me", me.getProfileHandler);
  app.patch("/api/v1/me", me.patchProfileHandler(deps.clock));
  app.get("/api/v1/me/passkeys", me.listPasskeysHandler);
  app.post("/api/v1/me/passkeys/options", me.passkeyOptionsHandler(deps.clock));
  app.post("/api/v1/me/passkeys", me.registerPasskeyHandler(deps.clock));
  app.patch("/api/v1/me/passkeys/:id", me.renamePasskeyHandler());
  app.delete("/api/v1/me/passkeys/:id", me.deletePasskeyHandler());
  app.get("/api/v1/me/sessions", me.listSessionsHandler(deps.clock));
  app.delete("/api/v1/me/sessions/:sid", me.deleteSessionHandler(deps.clock));
  app.delete("/api/v1/me/sessions", me.deleteSessionsHandler(deps.clock));
  app.get("/api/v1/me/identities", me.listIdentitiesHandler);
  app.delete("/api/v1/me/identities/:id", me.deleteIdentityHandler);
  app.get("/api/v1/me/grants", me.listGrantsHandler);
  app.delete("/api/v1/me/grants/:client_id", me.deleteGrantHandler(deps.clock));
  app.get("/api/v1/me/events", me.eventsHandler(deps.clock));
  app.post("/api/v1/admin/bootstrap", bootstrapHandler(deps.clock));
  // Admin API (§9): every other path under the prefix needs an administrator's token.
  app.use("/api/v1/admin/*", async (c, next) => {
    if (c.req.path === BOOTSTRAP_PATH) return next();
    return requireAdmin(deps.clock)(c, next);
  });
  const users = "/api/v1/admin/users";
  app.get(users, listUsersHandler(deps.clock));
  app.post(users, createUserHandler(deps.clock));
  app.get(`${users}/:id`, getUserHandler(deps.clock));
  app.patch(`${users}/:id`, patchUserHandler(deps.clock));
  app.delete(`${users}/:id`, deleteUserHandler(deps.clock));
  app.post(`${users}/:id/disable`, setDisabledHandler(deps.clock, true));
  app.post(`${users}/:id/enable`, setDisabledHandler(deps.clock, false));
  app.get(`${users}/:id/passkeys`, listPasskeysHandler(deps.clock));
  app.delete(`${users}/:id/passkeys/:pid`, deletePasskeyHandler(deps.clock));
  app.get(`${users}/:id/identities`, listIdentitiesHandler(deps.clock));
  app.delete(`${users}/:id/identities/:iid`, deleteIdentityHandler(deps.clock));
  app.get(`${users}/:id/sessions`, listSessionsHandler(deps.clock));
  app.delete(`${users}/:id/sessions/:sid`, deleteSessionHandler(deps.clock));
  app.delete(`${users}/:id/sessions`, deleteSessionsHandler(deps.clock));
  app.get(`${users}/:id/refresh-families`, listFamiliesHandler(deps.clock));
  app.delete(`${users}/:id/refresh-families/:fid`, deleteFamilyHandler(deps.clock));
  app.delete(`${users}/:id/refresh-families`, deleteFamiliesOfClientHandler(deps.clock));
  app.get(`${users}/:id/grants`, listGrantsHandler());
  app.delete(`${users}/:id/grants/:client_id`, deleteGrantHandler(deps.clock));
  app.get(`${users}/:id/events`, userEventsHandler(deps.clock));
  app.post(`${users}/:id/invitations`, createRecoverInvitationHandler(deps.clock));
  app.post(`${users}/:id/reindex`, reindexUserHandler(deps.clock));
  app.get(`${users}/:id/export`, exportUserHandler(deps.clock));
  app.post(`${users}/:id/restore`, restoreUserHandler(deps.clock));
  const groups = "/api/v1/admin/groups";
  app.get(groups, listGroupsHandler(deps.clock));
  app.post(groups, createGroupHandler(deps.clock));
  app.get(`${groups}/:id`, getGroupHandler);
  app.patch(`${groups}/:id`, patchGroupHandler(deps.clock));
  app.delete(`${groups}/:id`, deleteGroupHandler(deps.clock));
  app.get(`${groups}/:id/members`, listMembersHandler(deps.clock));
  app.put(`${groups}/:id/members/:user_id`, membershipHandler(deps.clock, true));
  app.delete(`${groups}/:id/members/:user_id`, membershipHandler(deps.clock, false));
  const clientsPath = "/api/v1/admin/clients";
  app.get(clientsPath, listClientsHandler(deps.clock));
  app.post(clientsPath, createClientHandler(deps.clock));
  app.get(`${clientsPath}/:id`, getClientHandler);
  app.patch(`${clientsPath}/:id`, patchClientHandler(deps.clock));
  app.delete(`${clientsPath}/:id`, deleteClientHandler);
  app.post(`${clientsPath}/:id/rotate-secret`, rotateSecretHandler(deps.clock));
  app.post(`${clientsPath}/:id/disable`, setClientDisabledHandler(deps.clock, true));
  app.post(`${clientsPath}/:id/enable`, setClientDisabledHandler(deps.clock, false));
  const upstreams = "/api/v1/admin/upstreams";
  app.get(upstreams, listUpstreamsHandler(deps.clock));
  app.post(upstreams, createUpstreamHandler(deps.clock));
  app.get(`${upstreams}/:alias`, getUpstreamHandler);
  app.patch(`${upstreams}/:alias`, patchUpstreamHandler(deps.clock));
  app.delete(`${upstreams}/:alias`, deleteUpstreamHandler);
  app.post(`${upstreams}/:alias/test`, testUpstreamHandler);
  const invitations = "/api/v1/admin/invitations";
  app.get(invitations, listInvitationsHandler(deps.clock));
  app.post(invitations, createInvitationHandler(deps.clock));
  app.get(`${invitations}/:id`, getInvitationHandler);
  app.delete(`${invitations}/:id`, deleteInvitationHandler);
  app.get("/api/v1/admin/keys", listKeysHandler(deps.clock));
  app.post("/api/v1/admin/keys/rotate", rotateKeyHandler(deps.clock));
  app.delete("/api/v1/admin/keys/:kid", retireKeyHandler(deps.clock));
  app.get("/api/v1/admin/settings", getSettingsHandler);
  app.patch("/api/v1/admin/settings", patchSettingsHandler(deps.clock));
  app.get("/api/v1/admin/stats", statsHandler(deps.clock));
  app.post("/api/v1/admin/maintenance/purge", purgeHandler(deps.clock));
  app.post("/api/v1/admin/maintenance/rekey", rekeyHandler);
  app.post("/api/v1/admin/maintenance/reindex", reindexAllHandler(deps.clock));
  app.post("/api/v1/admin/import/users", importUsersHandler(deps.clock));
  app.get("/api/v1/admin/audit", listAuditHandler(deps.clock));
  app.get("/api/v1/admin/audit/archive", listArchiveHandler());
  app.get("/login/*", loginAppHandler);
  registerApi(app);

  app.use(OPENAPI_PATH, async (c, next) => {
    await next();
    c.res.headers.set("Cache-Control", "public, max-age=300");
  });
  app.doc31(OPENAPI_PATH, API_INFO);

  // 4. Unknown paths are 404; known paths with an unlisted method are 405 with Allow (TIO-HTTP-001).
  app.notFound((c) => {
    const { methods } = matchRoute(c.req.method, c.req.path);
    if (methods.length > 0) {
      return errorResponse(c, 405, "method_not_allowed", "method not allowed", {
        Allow: methods.join(", "),
      });
    }
    return errorResponse(c, 404, "not_found", "no such endpoint");
  });

  // 5. Uncaught errors: generic body, details only in the log (TIO-ERR-001, TIO-ARCH-014).
  app.onError((error, c) => {
    c.get("logger").log("error", "unhandled error", {
      request_id: c.get("requestId"),
      name: error.name,
      message: error.message,
    });
    return errorResponse(c, 500, "server_error", "internal error");
  });

  return app;
}
