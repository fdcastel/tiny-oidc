import type { Handler } from "hono";
import type { JWTPayload } from "jose";
import { verifyOwnJwt } from "../crypto/jwt.ts";
import type { LoadedKeys } from "../crypto/keystore.ts";
import { newInteractionId } from "../crypto/random.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppContext } from "../interaction/api.ts";
import type { Client } from "../oidc/clients.ts";
import { openSessionHandle, type SessionRef } from "../oidc/handles.ts";
import { startInteraction, withQuery } from "../oidc/interactions.ts";
import { matchRedirectUri } from "../oidc/redirect-uri.ts";
import type { AppEnv } from "../router/context.ts";
import { clearCookie, parseCookies, SESSION_COOKIE } from "../router/cookies.ts";
import { errorResponse } from "../router/errors.ts";
import { readForm, uniqueParams } from "../router/form.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { userStub } from "../users/create.ts";
import { type EndedSession, notifyClients } from "./backchannel.ts";

// RP-initiated logout (spec §5.10.1): `GET|POST /logout` with an optional
// `id_token_hint`. A valid hint ends the hinted session at once
// (TIO-LOGOUT-003); without one the browser is asked to confirm through a
// `logout` interaction (TIO-LOGOUT-004). The post-logout destination is the
// client's registered URI when it matches exactly, else the landing URL
// (TIO-LOGOUT-002).

/** Where the browser goes after logout: the client's registered URI with `state`, or the landing URL. */
export function postLogoutDestination(
  settings: Settings,
  registered: string | null,
  state: string | null,
): string {
  if (registered === null) return settings.logout_landing_url as string;
  return state === null ? registered : withQuery(registered, { state });
}

/**
 * Back-channel logout for sessions that just ended, from any path
 * (TIO-LOGOUT-013). Nothing here fails the request: without a signing key
 * the sessions stay ended and the clients go unnotified, logged.
 */
export async function notifyEndedSessions(
  c: AppContext,
  clock: Clock,
  ended: EndedSession[],
): Promise<void> {
  if (ended.length === 0) return;
  const config = c.get("config");
  const db = c.get("db");
  let keys: LoadedKeys;
  try {
    keys = await c.get("keyStore").get(db, config.keys);
  } catch (error) {
    c.get("logger").log("error", "backchannel logout skipped: keys unavailable", {
      request_id: c.get("requestId"),
      reason: String(error),
    });
    return;
  }
  const deps = {
    env: c.env,
    db,
    keys,
    issuer: config.issuerUrl,
    clients: c.get("clients"),
    clock,
    audit: c.get("audit"),
    logger: c.get("logger"),
    waitUntil: (promise: Promise<unknown>) => c.executionCtx.waitUntil(promise),
  };
  for (const session of ended) await notifyClients(deps, session);
}

/**
 * Ends a session on its user's object and notifies the session's clients
 * (TIO-LOGOUT-005). Idempotent: an already ended session notifies nobody.
 */
export async function endSession(
  c: AppContext,
  clock: Clock,
  uid: string,
  sid: string,
  reason: string,
): Promise<EndedSession | null> {
  c.get("metrics").doCalls += 1;
  const revoked = await userStub(c.env, uid).revokeSession(sid, clock.now(), reason);
  if (!revoked.ok || revoked.revoked === null) return null;
  const ended: EndedSession = { uid, sid, clients: revoked.revoked.clients };
  c.get("audit").emit({
    type: "session.revoked",
    outcome: "success",
    actor: { kind: "user", id: uid },
    user_id: uid,
    sid,
    reason,
    data: { clients: ended.clients },
  });
  await notifyEndedSessions(c, clock, [ended]);
  return ended;
}

interface Hint {
  sub: string;
  sid: string | null;
  client: Client;
}

export function logoutHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    if (await limited(c.env, "ip_navigation", ipKey(c.req.raw)))
      return rateLimited(c, "ip_navigation");
    const config = c.get("config");
    const db = c.get("db");
    let settings: Settings;
    try {
      settings = await c.get("settingsLoader").get(db, config);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
    }
    const loginUrl = settings.login_url;
    if (loginUrl === null) {
      return errorResponse(c, 503, "not_configured", "login_url and login_origins are not set");
    }
    const toLoginApp = (error: string): Response => {
      c.set("error", error);
      return c.redirect(withQuery(loginUrl, { error }), 303);
    };
    let params: Map<string, string>;
    if (c.req.method === "POST") {
      const form = await readForm(c.req.raw);
      if (!form.ok) return toLoginApp("invalid_request");
      params = form.params;
    } else {
      const query = uniqueParams(new URL(c.req.url).searchParams);
      if (!query.ok) return toLoginApp("invalid_request");
      params = query.params;
    }
    const lookupClient = async (clientId: string): Promise<Client | null> => {
      try {
        return await c.get("clients").get(db, clientId);
      } catch {
        return null;
      }
    };
    // The hint: our own ID token, expiry ignored, `aud` naming a known client (TIO-LOGOUT-001).
    const hintParam = params.get("id_token_hint");
    const clientIdParam = params.get("client_id") ?? null;
    let hint: Hint | null = null;
    let client: Client | null = null;
    if (hintParam !== undefined) {
      let keys: LoadedKeys;
      try {
        keys = await c.get("keyStore").get(db, config.keys);
      } catch {
        return errorResponse(c, 503, "temporarily_unavailable", "keys unavailable");
      }
      const payload = await verifyOwnJwt(
        keys,
        hintParam,
        { issuer: config.issuerUrl, typ: "JWT", ignoreExpiry: true },
        clock,
      );
      const audience = payload === null ? null : hintAudience(payload, clientIdParam);
      client = audience === null ? null : await lookupClient(audience);
      if (payload === null || client === null) return toLoginApp("invalid_request");
      hint = {
        sub: payload.sub as string,
        sid: typeof payload["sid"] === "string" ? payload["sid"] : null,
        client,
      };
    } else if (clientIdParam !== null) {
      client = await lookupClient(clientIdParam);
    }
    // The destination (TIO-LOGOUT-002): an exact match on the client's registered URIs (with
    // the loopback port tolerance of TIO-CLIENT-011, as at /authorize), or the landing URL.
    const requested = params.get("post_logout_redirect_uri") ?? null;
    const registered =
      requested !== null &&
      client !== null &&
      matchRedirectUri(client.post_logout_redirect_uris, requested) !== null
        ? requested
        : null;
    const state = params.get("state") ?? null;
    const destination = postLogoutDestination(settings, registered, state);
    // The browser's session, if any.
    const cookie = parseCookies(c.req.header("cookie") ?? null).get(SESSION_COOKIE);
    const ref: SessionRef | null =
      cookie === undefined ? null : await openSessionHandle(config.keys, cookie);
    const clearSession = () =>
      c.header("Set-Cookie", clearCookie(SESSION_COOKIE), { append: true });

    if (hint !== null) {
      // TIO-LOGOUT-003: the hinted session ends wherever it lives; the cookie goes only when it was that session.
      c.get("audit").emit({
        type: "logout.rp_initiated",
        outcome: "success",
        actor: { kind: "client", id: hint.client.client_id },
        user_id: hint.sub,
        client_id: hint.client.client_id,
        sid: hint.sid,
        data: { registered_redirect: registered !== null },
      });
      if (hint.sid !== null) {
        const own = ref !== null && ref.sid === hint.sid;
        await endSession(c, clock, own ? ref.uid : hint.sub, hint.sid, "rp_logout");
        if (own) clearSession();
      }
      return c.redirect(destination, 303);
    }

    // TIO-LOGOUT-004: no hint. No live session: straight to the destination; a session: ask first.
    if (ref === null) {
      if (cookie !== undefined) clearSession();
      return c.redirect(destination, 303);
    }
    c.get("metrics").doCalls += 1;
    const session = await userStub(c.env, ref.uid).getSession(
      ref.sid,
      ref.secret_hash,
      clock.now(),
    );
    if (!session.ok) {
      clearSession();
      return c.redirect(destination, 303);
    }
    const now = clock.now();
    c.get("metrics").doCalls += 1;
    const started = await startInteraction(
      c.env,
      config.keys,
      newInteractionId(),
      {
        kind: "logout",
        status: "login_required",
        client_id: client?.client_id ?? null,
        logout: {
          sid: ref.sid,
          uid: ref.uid,
          post_logout_redirect_uri: registered,
          state,
          decision: null,
        },
      },
      now,
      settings.interaction_ttl,
    );
    c.get("audit").emit({
      type: "interaction.created",
      outcome: "success",
      actor: { kind: "user", id: ref.uid },
      user_id: ref.uid,
      client_id: client?.client_id ?? null,
      sid: ref.sid,
      interaction_id: started.id,
      data: { kind: "logout", status: "login_required" },
    });
    c.header("Set-Cookie", started.cookie, { append: true });
    return c.redirect(withQuery(loginUrl, { interaction: started.id }), 303);
  };
}

/** The client an ID token was issued to; with `client_id` given too, both must agree. */
function hintAudience(payload: JWTPayload, clientId: string | null): string | null {
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const single = aud.length === 1 && typeof aud[0] === "string" ? aud[0] : null;
  if (single === null) return null;
  return clientId === null || clientId === single ? single : null;
}
