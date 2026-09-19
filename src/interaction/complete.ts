import type { Handler } from "hono";
import { sha256 } from "../crypto/hash.ts";
import { newSecret } from "../crypto/random.ts";
import { UuidV7 } from "../crypto/uuid.ts";
import type { ExistingSession } from "../do/InteractionDO.ts";
import type { AuthContext, CodeInput } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import { sessionMetadata } from "../obs/request-meta.ts";
import type { AuthorizeRequest } from "../oidc/authorize.ts";
import {
  openBindingHandle,
  openSessionHandle,
  sealCodeHandle,
  sealSessionHandle,
} from "../oidc/handles.ts";
import { INTERACTION_ID_PATTERN, interactionStub, withQuery } from "../oidc/interactions.ts";
import type { AppEnv } from "../router/context.ts";
import {
  bindingCookieName,
  clearCookie,
  parseCookies,
  SESSION_COOKIE,
  setCookie,
} from "../router/cookies.ts";
import { errorResponse, sanitizeDescription } from "../router/errors.ts";
import { userStub } from "../users/create.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { clientRef, interactionClient } from "./api.ts";

// GET /interactions/{id}/complete (spec §7.7): the top-level navigation that
// turns a ready interaction into a session and a code, or a failed one into
// the error redirect. The binding cookie is the only credential it needs.

/** What the RP is told when the user cannot be signed in (never the account's status). */
function accessDeniedDescription(error: string): string {
  return error === "user_not_allowed" ? "user_not_allowed" : "the user cannot sign in";
}

export function completeHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const config = c.get("config");
    const id = c.req.param("id") as string;
    let settings: Settings;
    try {
      settings = await c.get("settingsLoader").get(c.get("db"), config);
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
    if (!INTERACTION_ID_PATTERN.test(id)) return toLoginApp("interaction_not_found");
    // The binding cookie (TIO-IX-060).
    const cookies = parseCookies(c.req.header("cookie") ?? null);
    const cookie = cookies.get(bindingCookieName(id));
    const binding = cookie === undefined ? null : await openBindingHandle(config.keys, cookie);
    if (binding === null || binding.interaction_id !== id) {
      return toLoginApp("interaction_binding_failed");
    }
    const now = clock.now();
    const stub = interactionStub(c.env, id);
    c.get("metrics").doCalls += 1;
    const got = await stub.get(now);
    if (!got.ok || got.doc.status === "pushed") return toLoginApp("interaction_not_found");
    const doc = got.doc;
    if (doc.binding_hash !== encodeBase64Url(binding.secret_hash)) {
      return toLoginApp("interaction_binding_failed");
    }
    // TIO-IX-061: not there yet, or already done.
    if (doc.status === "completed") return toLoginApp("interaction_already_completed");
    if (doc.status !== "ready" && doc.status !== "failed") {
      return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
    }
    const request = doc.request as AuthorizeRequest;
    const finish = async (params: Record<string, string>, sessionCookie?: string) => {
      c.get("metrics").doCalls += 1;
      await stub.apply("complete", "completed", {}, now);
      c.header("Set-Cookie", clearCookie(bindingCookieName(id)), { append: true });
      if (sessionCookie !== undefined) c.header("Set-Cookie", sessionCookie, { append: true });
      return c.redirect(
        withQuery(request.redirect_uri, { ...params, state: request.state, iss: config.issuerUrl }),
        303,
      );
    };
    const failWith = (error: string, description: string) => {
      c.set("error", error);
      return finish({ error, error_description: sanitizeDescription(description) });
    };
    if (doc.status === "failed") {
      const error = doc.error ?? { error: "server_error", error_description: "interaction failed" };
      return failWith(error.error, error.error_description);
    }

    // ready: the code, on a session that is created, rotated or reused (TIO-SESS-002, TIO-AUTHZ-022).
    const client = await interactionClient(c, doc);
    if (client === null) return failWith("server_error", "client unavailable");
    const uid = doc.auth?.uid ?? doc.existing_session?.uid ?? null;
    if (uid === null) return failWith("server_error", "no user");
    const user = userStub(c.env, uid);
    const ref = clientRef(client);
    const codeSecret = newSecret();
    const code: CodeInput = {
      secret_hash: await sha256(codeSecret),
      client_id: client.client_id,
      redirect_uri: request.redirect_uri,
      scope: doc.consent?.scopes ?? request.scope,
      nonce: request.nonce,
      code_challenge: request.code_challenge,
    };
    const idleTtl = settings["session.idle_ttl"];
    const absoluteTtl = settings["session.absolute_ttl"];
    const existing = doc.existing_session;

    if (doc.auth === null) {
      // Consent given on the session that started the interaction (the user id came from
      // it): the browser still presents that session's cookie, and the code is issued on it.
      const session = existing as ExistingSession;
      const sessionCookie = cookies.get(SESSION_COOKIE);
      const opened =
        sessionCookie === undefined ? null : await openSessionHandle(config.keys, sessionCookie);
      const presented =
        opened !== null && opened.sid === session.sid ? opened.secret_hash : new Uint8Array(32);
      c.get("metrics").doCalls += 1;
      const authorized = await user.authorizeWithSession({
        sid: session.sid,
        secret_hash: presented,
        now,
        client: ref,
        scope: code.scope,
        prompt_login: false,
        prompt_consent: false,
        max_age: null,
        code,
        session_idle_ttl: idleTtl,
      });
      if (!authorized.ok || authorized.outcome !== "authorized") {
        // TIO-IX-062: the session is gone; the login app starts over from login_required.
        c.get("metrics").doCalls += 1;
        await stub.apply(
          "restart",
          "login_required",
          { existing_session: null, consent: null },
          now,
        );
        c.header("Set-Cookie", clearCookie(SESSION_COOKIE), { append: true });
        return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
      }
      return finish({ code: await sealCodeHandle(config.keys, uid, codeSecret) });
    }

    const auth: AuthContext = {
      auth_time: doc.auth.auth_time,
      amr: doc.auth.amr,
      acr: doc.auth.acr,
      upstream: doc.auth.upstream,
    };
    const sessionSecret = newSecret();
    const secretHash = await sha256(sessionSecret);
    let sid: string | null = null;
    if (!doc.auth.new_session && existing !== null) {
      // The same user again: rotate the secret and the authentication context (TIO-SESS-002).
      c.get("metrics").doCalls += 1;
      const rotated = await user.finalizeLogin({
        now,
        session: { rotate: { sid: existing.sid, secret_hash: secretHash, auth } },
        code,
        client: ref,
        session_idle_ttl: idleTtl,
      });
      if (rotated.ok) sid = existing.sid;
      else if (rotated.error !== "session_invalid") {
        return failWith("access_denied", accessDeniedDescription(rotated.error));
      }
      // A session that vanished since the user authenticated is replaced by a new one.
    }
    if (sid === null) {
      if (existing !== null && existing.uid !== uid) {
        // Another user's session ends before the new one starts (TIO-SESS-002).
        c.get("metrics").doCalls += 1;
        await userStub(c.env, existing.uid).revokeSession(existing.sid, now, "reauth");
      }
      sid = new UuidV7(clock).next();
      c.get("metrics").doCalls += 1;
      const created = await user.finalizeLogin({
        now,
        session: {
          create: {
            sid,
            secret_hash: secretHash,
            auth,
            metadata: await sessionMetadata(config.keys, c.req.raw),
            idle_ttl: idleTtl,
            absolute_ttl: absoluteTtl,
          },
        },
        code,
        client: ref,
        session_idle_ttl: idleTtl,
      });
      if (!created.ok) return failWith("access_denied", accessDeniedDescription(created.error));
    }
    const handle = await sealSessionHandle(config.keys, uid, sid, sessionSecret);
    return finish(
      { code: await sealCodeHandle(config.keys, uid, codeSecret) },
      setCookie(SESSION_COOKIE, handle, absoluteTtl),
    );
  };
}
