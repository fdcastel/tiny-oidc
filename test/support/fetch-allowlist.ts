import { setupNetwork } from "@msw/cloudflare";
import { http } from "msw";

// Outbound guard (TIO-ARCH-016): the Worker under test runs with outbound
// requests intercepted; only origins mounted here answer, through a pure
// `handle(Request)` module, and every other outbound request fails. The
// interception is per test file, like storage.

export type FetchHandler = (request: Request) => Promise<Response> | Response;

export const network = setupNetwork();
network.configure({ onUnhandledFrame: "error" });

/** Rejects every outbound request that no mounted origin handles. Idempotent. */
export function disableNetwork(): void {
  if (network.readyState !== 1) network.enable();
}

/**
 * Routes every request to `origin` (for example `https://accounts.google.com`)
 * to `handler` for the rest of the file. Handlers see a real Request and
 * return a real Response, so fixtures such as the fake upstream stay pure.
 */
export function mountOrigin(origin: string, handler: FetchHandler): void {
  disableNetwork();
  network.use(http.all(`${origin}/*`, ({ request }) => handler(request as unknown as Request)));
}
