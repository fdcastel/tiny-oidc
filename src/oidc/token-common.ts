import type { Context } from "hono";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { readForm } from "../router/form.ts";
import { limited, rateLimited } from "../router/rate-limit.ts";
import { authenticateClient, BASIC_CHALLENGE } from "./client-auth.ts";
import type { Client } from "./clients.ts";

// What `/par`, `/token` and `/revoke` share (spec §5.6.1): the form body and
// the client authentication with its failure responses.

export type AppContext = Context<AppEnv>;

/** The form body, or the 400 that refuses it (TIO-TOKEN-001). */
export async function protocolForm(
  c: AppContext,
): Promise<{ ok: true; params: Map<string, string> } | { ok: false; response: Response }> {
  const form = await readForm(c.req.raw);
  if (form.ok) return form;
  return { ok: false, response: errorResponse(c, 400, "invalid_request", form.reason) };
}

/**
 * Authenticates the client of a form request (TIO-TOKEN-002..004). Failures
 * are 401 `invalid_client` (with the Basic challenge when applicable), counted
 * against the failed-authentication limit of the named client, or 503 when
 * the client directory is unreachable.
 */
export async function authenticateFormClient(
  c: AppContext,
  params: ReadonlyMap<string, string>,
  clock: Clock,
): Promise<
  | { ok: true; client: Client }
  | { ok: false; response: Response; disabled_client_id: string | null }
> {
  const config = c.get("config");
  const result = await authenticateClient(
    { params, authorization: c.req.header("authorization") ?? null },
    {
      lookup: (id) => c.get("clients").get(c.get("db"), id),
      issuer: config.issuerUrl,
      tokenEndpoint: `${config.issuerUrl}/token`,
      clock,
      jwks: c.get("jwks"),
    },
  );
  if (result.ok) return result;
  if (result.error === "temporarily_unavailable") {
    return {
      ok: false,
      response: errorResponse(c, 503, "temporarily_unavailable", "client directory unavailable"),
      disabled_client_id: null,
    };
  }
  // A disabled client is refused before its credentials are looked at (TIO-CLIENT-004); the
  // caller may still act on the handle it presented (the refresh grant revokes the family).
  const disabledClientId = result.reason === "client disabled" ? result.client_id : null;
  c.get("logger").log("warn", "client authentication failed", {
    request_id: c.get("requestId"),
    client_id: result.client_id,
    reason: result.reason,
  });
  if (result.client_id !== null && (await limited(c.env, "client_auth_failed", result.client_id))) {
    return { ok: false, response: rateLimited(c), disabled_client_id: disabledClientId };
  }
  const headers: Record<string, string> = {};
  if (result.basic_challenge) headers["WWW-Authenticate"] = BASIC_CHALLENGE;
  return {
    ok: false,
    response: errorResponse(c, 401, "invalid_client", "client authentication failed", headers),
    disabled_client_id: disabledClientId,
  };
}
