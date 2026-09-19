import { exports, env as workerEnv } from "cloudflare:workers";
import type { Env } from "../../src/env.ts";
import { TEST_ENV } from "./keys.ts";

// The Worker under test, reached the way a client reaches it: through its
// fetch handler with the real bindings. Test files never import src/index.ts.

/** The Worker's bindings as configured for tests (vitest.workers.config.ts). */
export const env = workerEnv as unknown as Env;

/** Absolute URL under the test issuer. */
export function url(path: string): string {
  return `${TEST_ENV.ISSUER}${path}`;
}

/** Sends a request to the Worker under test. `input` may be a path under the issuer or an absolute URL. */
export function op(input: string, init?: RequestInit): Promise<Response> {
  const target = input.startsWith("/") ? url(input) : input;
  return exports.default.fetch(new Request(target, init));
}
