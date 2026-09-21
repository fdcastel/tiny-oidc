import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import type { Env } from "../../src/env.ts";
import type { LogLine } from "../../src/obs/log.ts";
import type { Client } from "../../src/oidc/clients.ts";
import { createApp } from "../../src/router/app.ts";
import { FakeClock } from "./clock.ts";
import { env, url } from "./op.ts";
import { dropCachesOnReset } from "./reset.ts";

// An app instance driven directly with a fake clock and a log collector, for
// HTTP suites that need to move time or inspect log lines. Redirects are never
// followed; the caller reads `Location` and `Set-Cookie`.

export const RP_REDIRECT = "https://rp.example.com/cb";
export const LOGIN_ORIGIN = "https://login.example.com";

export interface Started {
  id: string;
  /** The binding cookie as a `Cookie` header value. */
  cookie: string;
}

export interface CallOptions {
  method?: string;
  /** The `Origin` header; null sends none, undefined sends the login origin. */
  origin?: string | null;
  cookie?: string | null;
  headers?: Record<string, string>;
  /** JSON body (objects are serialized; strings are sent as-is). */
  body?: unknown;
  env?: Env;
}

export interface Harness {
  clock: FakeClock;
  lines: LogLine[];
  /** A request to the app under the test issuer. */
  send(path: string, options?: CallOptions): Promise<Response>;
  /** Starts an authorize interaction through /authorize and returns its id and binding cookie (an `undefined` override removes the parameter). */
  start(
    client: Client,
    overrides?: Record<string, string | undefined>,
    sessionCookie?: string,
  ): Promise<Started>;
  /** GET the interaction document. */
  get(started: Started, options?: CallOptions): Promise<Response>;
  /** POST an Interaction API operation. */
  post(started: Started, op: string, body?: unknown, options?: CallOptions): Promise<Response>;
  /** Drops the app's isolate caches (a record changed under them in this test). */
  invalidate(): void;
  /** The app's isolate caches, for a test that drops one of them. */
  caches: ReturnType<typeof createApp>["caches"];
}

export function harness(clock = new FakeClock(1_800_000_000)): Harness {
  const lines: LogLine[] = [];
  const app = createApp({ clock, sink: (line) => lines.push(line) });
  dropCachesOnReset(() => app.caches.invalidate());
  const send = async (path: string, options: CallOptions = {}): Promise<Response> => {
    const headers: Record<string, string> = { ...options.headers };
    if (options.origin !== null) headers["origin"] = options.origin ?? LOGIN_ORIGIN;
    if (options.cookie !== null && options.cookie !== undefined) headers["cookie"] = options.cookie;
    const init: RequestInit = { method: options.method ?? "GET", headers };
    if (options.body !== undefined) {
      headers["content-type"] ??= "application/json";
      init.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
    }
    const ctx = createExecutionContext();
    const res = await app.fetch(new Request(url(path), init), options.env ?? env, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  const start = async (
    client: Client,
    overrides: Record<string, string | undefined> = {},
    sessionCookie?: string,
  ): Promise<Started> => {
    const params = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri: RP_REDIRECT,
      response_type: "code",
      scope: "openid email profile",
      state: "st-1",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      nonce: "n-1",
    });
    for (const [name, value] of Object.entries(overrides)) {
      if (value === undefined) params.delete(name);
      else params.set(name, value);
    }
    const res = await send(`/authorize?${params}`, { origin: null, cookie: sessionCookie ?? null });
    if (res.status !== 303) throw new Error(`authorize answered ${res.status}`);
    const location = new URL(res.headers.get("location") as string);
    const id = location.searchParams.get("interaction");
    if (id === null) throw new Error(`no interaction: ${location.href}`);
    const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-tio_ix_"));
    if (setCookie === undefined) throw new Error("no binding cookie");
    return { id, cookie: setCookie.slice(0, setCookie.indexOf(";")) };
  };
  const api = (id: string) => `/api/v1/interactions/${id}`;
  return {
    clock,
    lines,
    send,
    start,
    invalidate: () => app.caches.invalidate(),
    caches: app.caches,
    get: (started, options = {}) => send(api(started.id), { cookie: started.cookie, ...options }),
    post: (started, op, body, options = {}) =>
      send(`${api(started.id)}/${op}`, {
        method: "POST",
        cookie: started.cookie,
        body,
        ...options,
      }),
  };
}
