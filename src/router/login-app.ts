import type { Handler } from "hono";
import type { AppEnv } from "./context.ts";
import { errorResponse } from "./errors.ts";

// The bundled reference login app (spec §7.9, TIO-IX-081): the files of
// examples/login-app/ served from the ASSETS binding under /login/ when
// BUNDLED_LOGIN_APP is true, and nothing at all otherwise. The OP never
// produces HTML itself (TIO-GEN-001); the binding does.

export const LOGIN_APP_PREFIX = "/login";
const ASSET_CACHE_CONTROL = "public, max-age=300";

export const loginAppHandler: Handler<AppEnv> = async (c) => {
  if (!c.get("config").bundledLoginApp) {
    return errorResponse(c, 404, "not_found", "no such endpoint");
  }
  const url = new URL(c.req.url);
  // The assets directory is the app's root: /login/app.js is /app.js in the binding.
  const asset = new URL(url.pathname.slice(LOGIN_APP_PREFIX.length), url.origin);
  const served = await c.env.ASSETS.fetch(new Request(asset, { headers: c.req.raw.headers }));
  if (served.status === 404) return errorResponse(c, 404, "not_found", "no such file");
  const headers = new Headers(served.headers);
  headers.set("Cache-Control", ASSET_CACHE_CONTROL);
  return new Response(served.body, { status: served.status, headers });
};
