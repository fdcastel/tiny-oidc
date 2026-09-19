import type { Context, Handler } from "hono";
import type { z } from "zod";
import {
  ConsentDecisionSchema,
  type InteractionDocumentBody,
  type InteractionStep,
} from "../api/definitions.ts";
import { listEnabledUpstreams } from "../db/upstreams.ts";
import type { InteractionDO, InteractionDocument, LinkCandidate } from "../do/InteractionDO.ts";
import type { ClientRef } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import type { Client } from "../oidc/clients.ts";
import { openBindingHandle } from "../oidc/handles.ts";
import { INTERACTION_ID_PATTERN, interactionStub } from "../oidc/interactions.ts";
import type { AppEnv } from "../router/context.ts";
import { bindingCookieName, parseCookies } from "../router/cookies.ts";
import { errorResponse } from "../router/errors.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { userStub } from "../users/create.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import { readJsonBody } from "../util/json.ts";
import { isTerminal } from "./state-machine.ts";

// The Interaction API (spec §7): what the login app reads and drives. Every
// request passes the origin and binding-cookie guard of TIO-IX-001 and the id
// rule of TIO-IX-002 before any Durable Object is touched.

/** Passkey and registration attempts per interaction (§6.7). */
export const ATTEMPT_LIMIT = 10;

/** Fixed English scope descriptions for the consent screen (TIO-CONSENT-002); the login app localizes. */
export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: "Sign you in and know who you are",
  profile: "Your name",
  email: "Your email address and whether it is verified",
  groups: "The groups you belong to",
  offline_access: "Stay signed in to this application when you are away",
  account: "Manage your own account: sessions, passkeys and linked identities",
  admin: "Administer this identity provider",
};

export type AppContext = Context<AppEnv>;

export interface Guarded {
  id: string;
  stub: DurableObjectStub<InteractionDO>;
  doc: InteractionDocument;
  settings: Settings;
  now: number;
}

/** TIO-IX-021: the first character of the local part, `***`, and the full domain. */
export function maskEmail(email: string | null): string | null {
  if (email === null) return null;
  const at = email.lastIndexOf("@");
  if (at <= 0) return "***";
  return `${email[0]}***${email.slice(at)}`;
}

/** TIO-IX-033: where the browser finishes the interaction. */
export function redirectTo(c: AppContext, id: string): string {
  return `${c.get("config").issuerUrl}/interactions/${id}/complete`;
}

const SAME_SITE = new Set(["same-origin", "same-site"]);

/**
 * The guard of TIO-IX-001..003: id shape, origin, binding cookie, then the
 * document. Terminal documents are served to GET only (TIO-IX-003); pushed
 * requests are not interactions yet. Returns the response to send instead when
 * the request is refused.
 */
export async function guard(c: AppContext, clock: Clock): Promise<Guarded | Response> {
  if (await limited(c.env, "ip_interactions", ipKey(c.req.raw))) return rateLimited(c);
  const id = c.req.param("id") as string;
  if (!INTERACTION_ID_PATTERN.test(id)) {
    return errorResponse(c, 404, "interaction_not_found", "no such interaction");
  }
  let settings: Settings;
  try {
    settings = await c.get("settingsLoader").get(c.get("db"), c.get("config"));
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
  }
  // (a) The origin: a login origin, or a same-site GET without one.
  const origin = c.req.header("origin") ?? null;
  const allowed =
    origin !== null
      ? (settings.login_origins?.includes(origin) ?? false)
      : c.req.method === "GET" && SAME_SITE.has(c.req.header("sec-fetch-site") ?? "");
  if (!allowed) return errorResponse(c, 403, "origin_not_allowed", "origin not allowed");
  // (b) The binding cookie, before any Durable Object access.
  const bindingFailed = () =>
    errorResponse(c, 403, "interaction_binding_failed", "interaction binding failed");
  const cookie = parseCookies(c.req.header("cookie") ?? null).get(bindingCookieName(id));
  if (cookie === undefined) return bindingFailed();
  const binding = await openBindingHandle(c.get("config").keys, cookie);
  if (binding === null || binding.interaction_id !== id) return bindingFailed();
  const now = clock.now();
  const stub = interactionStub(c.env, id);
  c.get("metrics").doCalls += 1;
  const got = await stub.get(now);
  if (!got.ok || got.doc.status === "pushed") {
    return errorResponse(c, 404, "interaction_not_found", "no such interaction");
  }
  if (got.doc.binding_hash !== encodeBase64Url(binding.secret_hash)) return bindingFailed();
  if (c.req.method !== "GET" && isTerminal(got.doc.status)) {
    return errorResponse(c, 404, "interaction_not_found", "no such interaction");
  }
  return { id, stub, doc: got.doc, settings, now };
}

/** The client record of an interaction, or null when it has none or it is gone. */
export async function interactionClient(
  c: AppContext,
  doc: InteractionDocument,
): Promise<Client | null> {
  if (doc.client_id === null) return null;
  try {
    return await c.get("clients").get(c.get("db"), doc.client_id);
  } catch {
    return null;
  }
}

export function clientRef(client: Client): ClientRef {
  return {
    client_id: client.client_id,
    created_at: client.created_at,
    skip_consent: client.skip_consent,
    allowed_groups: client.allowed_groups,
  };
}

/** The scopes of the first grant in a listGrants result; none when the user is gone. */
export function grantedScopes(
  result: { ok: true; grants: { scopes: string[] }[] } | { ok: false },
): string[] {
  return result.ok ? (result.grants[0]?.scopes ?? []) : [];
}

/** The user an interaction is about: authenticated in it, or holding the session it started from. */
export function interactionUid(doc: InteractionDocument): string | null {
  return doc.auth?.uid ?? doc.existing_session?.uid ?? null;
}

/** GET /api/v1/interactions/{id} (§7.3, TIO-IX-020). */
/** The enabled upstreams the login app may offer (§7.3); none when the directory is unreachable. */
async function upstreamMethods(c: AppContext): Promise<{ alias: string; display_name: string }[]> {
  try {
    return (await listEnabledUpstreams(c.get("db"))).map((u) => ({
      alias: u.alias,
      display_name: u.display_name,
    }));
  } catch {
    return [];
  }
}

/** The `link` section (§7.3): the candidate is shown a masked email, never the account (TIO-IX-021). */
function linkSection(link: LinkCandidate) {
  return {
    upstream: link.alias,
    email_masked: maskEmail(link.claims.email) as string,
    display_name_hint: link.claims.name,
  };
}

export function getInteractionHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, settings } = guarded;
    const client = await interactionClient(c, doc);
    const request = doc.request;
    const body: InteractionDocumentBody = {
      id: doc.id,
      // The guard never lets a pushed request through, and a claimed one is an authorize kind.
      kind: doc.kind as InteractionDocumentBody["kind"],
      status: doc.status as InteractionDocumentBody["status"],
      expires_at: doc.expires_at,
      client: client
        ? {
            client_id: client.client_id,
            client_name: client.client_name,
            client_uri: client.client_uri,
            logo_uri: client.logo_uri,
          }
        : null,
      request: request
        ? {
            scopes: request.scope,
            prompt: request.prompt,
            max_age: request.max_age,
            login_hint: request.login_hint,
            ui_locales: request.ui_locales,
            acr_values: request.acr_values,
          }
        : null,
      methods: {
        passkey: true,
        registration: settings["registration.mode"],
        upstreams: await upstreamMethods(c),
      },
      session_user: null,
      consent: null,
      link: doc.link === null ? null : linkSection(doc.link),
      logout: null,
      error: doc.error,
      attempts_remaining: Math.max(0, ATTEMPT_LIMIT - doc.attempts),
    };
    if (doc.kind === "logout" && doc.logout !== null) {
      // §7.6: who asked, and whether the browser will land at the client afterwards.
      body.logout = {
        client: body.client,
        post_logout_redirect_uri_registered: doc.logout.post_logout_redirect_uri !== null,
      };
    }
    const uid = interactionUid(doc);
    if (doc.status === "consent_required" && client && request && uid !== null) {
      const stub = userStub(c.env, uid);
      c.get("metrics").doCalls += 1;
      const granted = grantedScopes(await stub.listGrants([clientRef(client)]));
      body.consent = {
        scopes: request.scope.map((name) => ({
          name,
          description: SCOPE_DESCRIPTIONS[name] as string,
          granted: granted.includes(name),
        })),
      };
      if (doc.existing_session) {
        const profile = await stub.getProfile();
        if (profile.ok) {
          body.session_user = {
            display_name: profile.profile.display_name,
            email_masked: maskEmail(profile.profile.email),
          };
        }
      }
    }
    return c.json(body, 200);
  };
}

/** POST …/abort (TIO-IX-041): failed with access_denied, from any non-terminal status. */
export function abortHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    // Every non-terminal status permits abort, and the guard has excluded the terminal ones.
    c.get("metrics").doCalls += 1;
    await guarded.stub.apply(
      "abort",
      "failed",
      { error: { error: "access_denied", error_description: "aborted by the user" } },
      guarded.now,
    );
    const step: InteractionStep = { status: "failed", redirect_to: redirectTo(c, guarded.id) };
    return c.json(step, 200);
  };
}

/** POST …/consent (TIO-CONSENT-003): grant a subset of the request or deny. */
export function consentHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, id, stub, now } = guarded;
    if (doc.status !== "consent_required" || doc.request === null || doc.client_id === null) {
      return invalidState(c);
    }
    const body = await readJsonBody(c.req.raw, ConsentDecisionSchema, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const decision: z.infer<typeof ConsentDecisionSchema> = body.value;
    if (decision.decision === "deny") {
      c.get("metrics").doCalls += 1;
      await stub.apply(
        "consent",
        "failed",
        { error: { error: "access_denied", error_description: "consent denied" } },
        now,
      );
      const step: InteractionStep = { status: "failed", redirect_to: redirectTo(c, id) };
      return c.json(step, 200);
    }
    const requested = doc.request.scope;
    if (!decision.scopes.every((s) => (requested as string[]).includes(s))) {
      return errorResponse(c, 400, "invalid_request", "scopes must be a subset of the request");
    }
    const scopes = [...new Set(["openid", ...decision.scopes])];
    const client = await interactionClient(c, doc);
    if (!client) return errorResponse(c, 503, "temporarily_unavailable", "client unavailable");
    const uid = interactionUid(doc) as string;
    const user = userStub(c.env, uid);
    c.get("metrics").doCalls += 1;
    const granted = await user.grantConsent(clientRef(client), scopes, now);
    if (!granted.ok) return errorResponse(c, 403, "access_denied", granted.error);
    c.get("metrics").doCalls += 1;
    await stub.apply("consent", "ready", { consent: { scopes } }, now);
    const step: InteractionStep = { status: "ready", redirect_to: redirectTo(c, id) };
    return c.json(step, 200);
  };
}

function invalidState(c: AppContext): Response {
  return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
}
