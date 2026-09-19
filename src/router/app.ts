import { OpenAPIHono } from "@hono/zod-openapi";
import { bodyLimit } from "hono/body-limit";
import { UuidV7 } from "../crypto/uuid.ts";
import { Db } from "../db/db.ts";
import { buildConfig, type Clock, type ConfigResult, type Env, SettingsLoader } from "../env.ts";
import { healthHandler, healthRoute } from "../obs/health.ts";
import { consoleSink, Logger, type LogLevel, type LogSink, type RequestLog } from "../obs/log.ts";
import type { AppEnv } from "./context.ts";
import { errorBody, errorResponse } from "./errors.ts";
import { cors, securityHeaders } from "./headers.ts";
import { BODY_LIMITS, bodyClass, matchRoute } from "./routes.ts";

export interface AppDeps {
  clock: Clock;
  /** Where log lines go; console in production, a collector in tests. */
  sink?: LogSink;
}

const MAX_QUERY_BYTES = 8 * 1024;
const OPENAPI_PATH = "/api/v1/openapi.json";
const HEALTH_PATH = "/api/v1/health";

/**
 * Builds the Worker's Hono application (spec §2.1, §5.14). One instance lives
 * per isolate; its caches (startup config, settings) are isolate caches.
 */
export function createApp(deps: AppDeps) {
  const sink = deps.sink ?? consoleSink;
  const uuids = new UuidV7(deps.clock);
  const settingsLoader = new SettingsLoader(deps.clock);
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
    if (!config.ok) {
      // Fail every request closed until the configuration is fixed (TIO-ARCH-014).
      logger.log("error", "fatal: invalid configuration", {
        request_id: requestId,
        reason: config.error,
      });
      c.res = c.json(errorBody(requestId, "server_error", "server misconfigured"), 500);
    } else {
      c.set("config", config.config);
      await next();
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
    // One data point per request when metrics are bound (TIO-OBS-002).
    c.env.METRICS?.writeDataPoint({
      blobs: [line.route, String(line.status), line.error ?? ""],
      doubles: [line.duration_ms],
      indexes: [line.route],
    });
    c.res.headers.set("X-Request-Id", requestId);
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
  app.openapi(healthRoute, healthHandler(deps.clock));

  app.use(OPENAPI_PATH, async (c, next) => {
    await next();
    c.res.headers.set("Cache-Control", "public, max-age=300");
  });
  app.doc31(OPENAPI_PATH, {
    openapi: "3.1.0",
    info: {
      title: "Tiny OIDC JSON APIs",
      version: "1.0.0",
      description:
        "Interaction, Self-service and Admin APIs of Tiny OIDC. The OIDC protocol endpoints are described by the discovery document.",
    },
  });

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
