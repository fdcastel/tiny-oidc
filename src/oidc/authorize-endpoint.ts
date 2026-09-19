import type { Handler } from "hono";
import { sha256 } from "../crypto/hash.ts";
import { newInteractionId, newSecret } from "../crypto/random.ts";
import type { InteractionDO } from "../do/InteractionDO.ts";
import type { AuthorizeOutcome, ClientRef } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { clearCookie, parseCookies, SESSION_COOKIE } from "../router/cookies.ts";
import { errorResponse, sanitizeDescription } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import {
  type AuthorizeErrorCode,
  type AuthorizeRequest,
  validateAuthorizeRequest,
} from "./authorize.ts";
import type { Client } from "./clients.ts";
import { openSessionHandle, type SessionRef, sealCodeHandle } from "./handles.ts";
import {
  INTERACTION_ID_PATTERN,
  interactionStub,
  newBinding,
  startInteraction,
  withQuery,
} from "./interactions.ts";

// GET /authorize (spec §5.4): the validation pipeline in spec order, then the
// session evaluation of step 14. Errors before the redirect URI is trusted go
// to the login app (TIO-AUTHZ-018); later ones go back to the client with
// `state` and `iss` (TIO-AUTHZ-019); everything else starts an interaction.

export const REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

type RedirectError = AuthorizeErrorCode | "login_required" | "consent_required" | "access_denied";

interface Evaluation {
  /** What the session cookie amounted to. */
  outcome: "none" | "authorized" | "login_required" | "consent_required" | "not_allowed";
  existing_session: { uid: string; sid: string; auth_time: number } | null;
  code: string | null;
  /** The cookie was present but unusable and is cleared (TIO-SESS-004). */
  clear: boolean;
}

/** The interaction id inside a `request_uri`, or null. */
export function parseRequestUri(value: string): string | null {
  if (!value.startsWith(REQUEST_URI_PREFIX)) return null;
  const id = value.slice(REQUEST_URI_PREFIX.length);
  return INTERACTION_ID_PATTERN.test(id) ? id : null;
}

export function authorizeHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const config = c.get("config");
    const db = c.get("db");
    const metrics = c.get("metrics");
    const now = clock.now();

    // The login app is where every non-redirectable outcome is rendered (TIO-CFG-004).
    let settings: Settings;
    try {
      settings = await c.get("settingsLoader").get(db, config);
    } catch {
      // The loader wraps every failure (TIO-ARCH-012); with no login_url known, JSON it is.
      return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
    }
    const loginUrl = settings.login_url;
    if (loginUrl === null || settings.login_origins === null) {
      return errorResponse(c, 503, "not_configured", "login_url and login_origins are not set");
    }
    const toLoginApp = (error: string, description: string): Response => {
      c.set("error", error);
      return c.redirect(
        withQuery(loginUrl, { error, error_description: sanitizeDescription(description) }),
        303,
      );
    };

    // 1. Duplicates (TIO-AUTHZ-001); the method, query size and body are the router's.
    const parsed = uniqueParams(new URL(c.req.url).searchParams);
    if (!parsed.ok) return toLoginApp("invalid_request", "duplicate parameter");
    const params = parsed.params;

    // 2. The client (TIO-AUTHZ-002).
    const clientId = params.get("client_id");
    if (clientId === undefined) return toLoginApp("invalid_request", "client_id is required");
    let client: Client | null;
    try {
      client = await c.get("clients").get(db, clientId);
    } catch {
      // ClientsUnavailableError: D1 down beyond the stale window (TIO-ARCH-012, TIO-RL-001 style).
      return toLoginApp("temporarily_unavailable", "client directory unavailable");
    }
    if (!client || client.disabled_at !== null) {
      return toLoginApp("invalid_request", "unknown client");
    }
    if (!client.grant_types.includes("authorization_code")) {
      return toLoginApp("unauthorized_client", "client cannot use the authorization code grant");
    }

    // 3. A pushed request replaces the query (TIO-AUTHZ-003); 4. require_par (TIO-AUTHZ-004).
    let request: AuthorizeRequest;
    let pushed: { id: string; stub: DurableObjectStub<InteractionDO>; cookie: string } | null =
      null;
    const requestUri = params.get("request_uri");
    if (requestUri !== undefined) {
      if ([...params.keys()].some((k) => k !== "client_id" && k !== "request_uri")) {
        return toLoginApp(
          "invalid_request",
          "request_uri allows no other parameter than client_id",
        );
      }
      const id = parseRequestUri(requestUri);
      if (id === null) return toLoginApp("invalid_request", "request_uri is malformed");
      const stub = interactionStub(c.env, id);
      const binding = await newBinding(config.keys, id, settings.interaction_ttl);
      metrics.doCalls += 1;
      const claimed = await stub.claimPushed(
        client.client_id,
        binding.hash,
        now,
        settings.interaction_ttl,
      );
      if (!claimed.ok) {
        return toLoginApp("invalid_request", "request_uri is unknown, expired or already used");
      }
      request = claimed.doc.request as AuthorizeRequest;
      pushed = { id, stub, cookie: binding.cookie };
    } else {
      if (client.require_par) {
        return toLoginApp("invalid_request", "this client must use pushed authorization requests");
      }
      const validated = validateAuthorizeRequest(params, client);
      if (!validated.ok) {
        if (!validated.redirectable) return toLoginApp(validated.error, validated.description);
        return redirectError(
          c,
          validated.redirect_uri,
          validated.error,
          validated.description,
          validated.state,
        );
      }
      request = validated.request;
    }
    const clientRef: ClientRef = {
      client_id: client.client_id,
      created_at: client.created_at,
      skip_consent: client.skip_consent,
      allowed_groups: client.allowed_groups,
    };
    const fail = async (error: RedirectError, description: string): Promise<Response> => {
      if (pushed) {
        metrics.doCalls += 1;
        await pushed.stub.apply(
          "fail",
          "failed",
          { error: { error, error_description: description } },
          now,
        );
      }
      return redirectError(c, request.redirect_uri, error, description, request.state);
    };

    // 14. Session evaluation (TIO-AUTHZ-014..017).
    const evaluation = await evaluateSession(c, clientRef, request, settings, now);
    if (evaluation.clear) c.header("Set-Cookie", clearCookie(SESSION_COOKIE), { append: true });
    if (evaluation.outcome === "authorized") {
      if (pushed) {
        metrics.doCalls += 1;
        await pushed.stub.apply("consume_par", "completed", {}, now);
      }
      return c.redirect(
        withQuery(request.redirect_uri, {
          code: evaluation.code as string,
          state: request.state,
          iss: config.issuerUrl,
        }),
        303,
      );
    }
    if (evaluation.outcome === "not_allowed") return fail("access_denied", "user_not_allowed");
    const status =
      evaluation.outcome === "consent_required" ? "consent_required" : "login_required";
    if (request.prompt.includes("none")) {
      return fail(status, `prompt=none and ${status.replace("_", " ")}`);
    }
    const existing_session = evaluation.existing_session;
    let id: string;
    let cookie: string;
    if (pushed) {
      metrics.doCalls += 1;
      // Claimed moments ago with a fresh TTL, so the transition cannot fail.
      await pushed.stub.apply("consume_par", status, { existing_session }, now);
      id = pushed.id;
      cookie = pushed.cookie;
    } else {
      metrics.doCalls += 1;
      const started = await startInteraction(
        c.env,
        config.keys,
        newInteractionId(),
        {
          kind: "authorize",
          status,
          client_id: client.client_id,
          request,
          existing_session,
        },
        now,
        settings.interaction_ttl,
      );
      id = started.id;
      cookie = started.cookie;
    }
    // TIO-AUTHZ-020: 303 to login_url with the interaction id and the binding cookie.
    c.header("Set-Cookie", cookie, { append: true });
    return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
  };
}

/** A redirectable error (TIO-AUTHZ-019): `error`, `error_description`, `state` when known, and `iss`. */
function redirectError(
  c: Parameters<Handler<AppEnv>>[0],
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): Response {
  c.set("error", error);
  const params: Record<string, string> = {
    error,
    error_description: sanitizeDescription(description),
  };
  if (state !== null) params["state"] = state;
  params["iss"] = c.get("config").issuerUrl;
  return c.redirect(withQuery(redirectUri, params), 303);
}

/**
 * Step 14: the session cookie, if any, against `UserDO.authorizeWithSession`,
 * which issues the code when the session and consent are satisfied and
 * touches nothing otherwise (TIO-AUTHZ-015).
 */
async function evaluateSession(
  c: Parameters<Handler<AppEnv>>[0],
  client: ClientRef,
  request: AuthorizeRequest,
  settings: Settings,
  now: number,
): Promise<Evaluation> {
  const none: Evaluation = { outcome: "none", existing_session: null, code: null, clear: false };
  const cookie = parseCookies(c.req.header("cookie") ?? null).get(SESSION_COOKIE);
  if (cookie === undefined) return none;
  const config = c.get("config");
  const ref: SessionRef | null = await openSessionHandle(config.keys, cookie);
  if (ref === null) return { ...none, clear: true };
  const secret = newSecret();
  const stub = c.env.USER_DO.get(c.env.USER_DO.idFromName(ref.uid));
  c.get("metrics").doCalls += 1;
  const result: AuthorizeOutcome = await stub.authorizeWithSession({
    sid: ref.sid,
    secret_hash: ref.secret_hash,
    now,
    client,
    scope: request.scope,
    prompt_login: request.prompt.includes("login"),
    prompt_consent: request.prompt.includes("consent"),
    max_age: request.max_age,
    code: {
      secret_hash: await sha256(secret),
      client_id: client.client_id,
      redirect_uri: request.redirect_uri,
      scope: request.scope,
      nonce: request.nonce,
      code_challenge: request.code_challenge,
    },
    session_idle_ttl: settings["session.idle_ttl"],
  });
  if (!result.ok) {
    if (result.error === "user_not_allowed") return { ...none, outcome: "not_allowed" };
    // Unknown, revoked or expired session, or a disabled user: as if absent (TIO-SESS-004).
    return { ...none, clear: true };
  }
  return {
    outcome: result.outcome,
    existing_session: {
      uid: ref.uid,
      sid: result.session.sid,
      auth_time: result.session.auth_time,
    },
    code:
      result.outcome === "authorized" ? await sealCodeHandle(config.keys, ref.uid, secret) : null,
    clear: false,
  };
}
