import type { Handler } from "hono";
import type { JWTPayload } from "jose";
import { UuidV7 } from "../crypto/uuid.ts";
import type { Db } from "../db/db.ts";
import { lookupIdentity, releaseIdentity } from "../db/identities.ts";
import { consumeInvitation, getInvitation } from "../db/invitations.ts";
import { getUpstream } from "../db/upstreams.ts";
import { findVerifiedUser } from "../db/users.ts";
import type { FederationLeg, InteractionDO } from "../do/InteractionDO.ts";
import type { UserProfile } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import {
  type AppContext,
  type Guarded,
  interactionClient,
  interactionFailed,
  redirectTo,
} from "../interaction/api.ts";
import { authenticateInteraction } from "../interaction/passkey.ts";
import { ACR } from "../oidc/capabilities.ts";
import { openBindingHandle, openFederationHandle } from "../oidc/handles.ts";
import { interactionStub, withQuery } from "../oidc/interactions.ts";
import type { AppEnv } from "../router/context.ts";
import { bindingCookieName, parseCookies } from "../router/cookies.ts";
import { errorResponse } from "../router/errors.ts";
import { readForm, uniqueParams } from "../router/form.ts";
import { ipKey, limited, rateLimited } from "../router/rate-limit.ts";
import { createUser, userStub } from "../users/create.ts";
import { normalizeEmail } from "../users/email.ts";
import { encodeBase64Url } from "../util/base64url.ts";
import type { UpstreamMetadata } from "./discovery.ts";
import { extractClaims, missingRequiredClaim, verifyUpstreamIdToken } from "./id-token.ts";
import { UpstreamUnavailableError } from "./metadata.ts";
import { federationCallbackUrl } from "./outbound.ts";
import { exchangeCode, fetchUserinfo } from "./token.ts";
import type { Upstream } from "./upstreams.ts";

// `/federation/callback` (spec §6.4.3–§6.4.5): the browser comes back from the
// upstream with a code and the `tio_fs` state. The leg is consumed exactly
// once (TIO-FED-020), the code exchanged (TIO-FED-022), the ID token validated
// (TIO-FED-030), the claims read (TIO-FED-031..033) and the account resolved
// (TIO-FED-040..043). A ready interaction goes straight to /complete; every
// other outcome goes back to the login app with the interaction id.

/** The upstream error codes forwarded to the login app; anything else is `upstream_error` (TIO-FED-021). */
const UPSTREAM_ERROR_CODES = new Set([
  "access_denied",
  "login_required",
  "interaction_required",
  "consent_required",
  "invalid_request",
  "unauthorized_client",
  "unsupported_response_type",
  "invalid_scope",
  "server_error",
  "temporarily_unavailable",
]);

/** Fails the interaction with a §7.8 code and sends the browser to the login app. */
async function failInteraction(
  c: AppContext,
  stub: DurableObjectStub<InteractionDO>,
  id: string,
  loginUrl: string,
  now: number,
  error: string,
  description: string,
  audit: { alias: string; reason: string },
): Promise<Response> {
  c.get("metrics").doCalls += 1;
  const applied = await stub.apply(
    "fail",
    "failed",
    { error: { error, error_description: description } },
    now,
  );
  c.get("audit").emit({
    type: "identity.login_failed",
    outcome: "failure",
    actor: { kind: "anonymous", id: null },
    upstream: audit.alias,
    interaction_id: id,
    reason: audit.reason,
  });
  if (applied.ok) interactionFailed(c, applied.doc, error, audit.reason);
  c.set("error", error);
  return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
}

/** Who the upstream says the person is, as the OP keeps it. */
interface Resolved {
  sub: string;
  email: string | null;
  email_verified: boolean;
  name: string | null;
}

type Resolution =
  | { kind: "user"; profile: UserProfile; linked: boolean }
  | { kind: "link"; candidate_uid: string }
  | { kind: "fail"; error: string; description: string; reason: string };

/** The account behind an upstream identity, in the order of TIO-FED-040. */
async function resolveAccount(
  c: AppContext,
  db: Db,
  upstream: Upstream,
  leg: FederationLeg,
  claims: Resolved,
  settings: Settings,
  clock: Clock,
): Promise<Resolution> {
  const now = clock.now();
  const identity = { issuer: upstream.issuer, subject: claims.sub };
  // 1. A linked identity whose object confirms it.
  const holder = await lookupIdentity(db, identity.issuer, identity.subject);
  if (holder !== null) {
    // A `creating` holder is a creation in flight that claimed the pair (§4.6 step 1) and has
    // not yet reached the object: the pair is taken, not stale (TIO-TEST-010). An abandoned
    // creation is repaired or dropped by the cron (§3.4), which also frees the pair.
    if (holder.status === "creating") {
      return {
        kind: "fail",
        error: "identity_already_linked",
        description: "the account could not be created",
        reason: "identity_already_linked",
      };
    }
    c.get("metrics").doCalls += 1;
    const stub = userStub(c.env, holder.user_id);
    const touched = await stub.touchIdentity(identity.issuer, identity.subject, claims, now);
    if (touched.ok && touched.found) {
      const profile = await stub.getProfile();
      if (profile.ok) return { kind: "user", profile: profile.profile, linked: false };
    }
    // The index names a user whose object does not hold the identity (TIO-DATA-026).
    await releaseIdentity(db, identity.issuer, identity.subject);
  }
  // 2. A verified email that belongs to an existing user.
  if (claims.email_verified && claims.email !== null) {
    const owner = await findVerifiedUser(db, normalizeEmail(claims.email));
    if (owner !== null) {
      if (settings["federation.link_by_verified_email"] === "never") {
        return {
          kind: "fail",
          error: "account_exists",
          description: "an account with this email exists",
          reason: "account_exists",
        };
      }
      return { kind: "link", candidate_uid: owner.id };
    }
  }
  // 3. Creation: the policy or an invitation allows it, registration is not closed.
  let invitation = null;
  if (leg.invitation_id !== null) {
    invitation = await getInvitation(db, leg.invitation_id);
    if (invitation === null || invitation.used_at !== null || invitation.expires_at <= now) {
      return {
        kind: "fail",
        error: "invitation_invalid",
        description: "invitation not accepted",
        reason: "invitation_invalid",
      };
    }
  }
  const allowed = settings["federation.auto_create"] || invitation !== null;
  if (!allowed || settings["registration.mode"] === "closed") {
    return {
      kind: "fail",
      error: "registration_closed",
      description: "registration is closed",
      reason: "registration_closed",
    };
  }
  const uuids = new UuidV7(clock);
  const id = uuids.next();
  if (invitation !== null) {
    if (!(await consumeInvitation(db, invitation.id, id, now))) {
      return {
        kind: "fail",
        error: "invitation_used",
        description: "invitation not accepted",
        reason: "invitation_used",
      };
    }
    c.get("audit").emit({
      type: "invitation.used",
      outcome: "success",
      actor: { kind: "user", id },
      user_id: id,
      upstream: upstream.alias,
      data: { kind: invitation.kind, via: "federation" },
    });
  }
  // An invitation that names an email decides the email and its verification (TIO-DATA-008 b).
  const named = invitation !== null && invitation.email !== null ? invitation : null;
  const created = await createUser(
    c.env,
    db,
    {
      id,
      email: named === null ? claims.email : named.email,
      email_verified: named === null ? claims.email_verified : named.email_verified,
      display_name: invitation?.display_name ?? claims.name,
      groups: invitation?.groups ?? [],
      identities: [
        {
          id: uuids.next(),
          issuer: identity.issuer,
          subject: identity.subject,
          email: claims.email,
          email_verified: claims.email_verified,
          name: claims.name,
        },
      ],
    },
    now,
  );
  if (!created.ok) {
    return {
      kind: "fail",
      error: created.error,
      description: "the account could not be created",
      reason: created.error,
    };
  }
  c.get("audit").emit({
    type: "user.created",
    outcome: "success",
    actor: { kind: "user", id: id },
    user_id: id,
    upstream: upstream.alias,
    data: { via: "federation", invitation: invitation !== null },
  });
  c.get("audit").emit({
    type: "identity.linked",
    outcome: "success",
    actor: { kind: "user", id: id },
    user_id: id,
    upstream: upstream.alias,
    data: { issuer: identity.issuer },
  });
  return { kind: "user", profile: created.profile, linked: true };
}

export function federationCallbackHandler(clock: Clock): Handler<AppEnv> {
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
    // GET query or POST form (TIO-FED-020).
    let params: Map<string, string>;
    if (c.req.method === "POST") {
      const form = await readForm(c.req.raw);
      if (!form.ok) return errorResponse(c, 400, "invalid_request", form.reason);
      params = form.params;
    } else {
      const query = uniqueParams(new URL(c.req.url).searchParams);
      if (!query.ok) return errorResponse(c, 400, "invalid_request", query.reason);
      params = query.params;
    }
    const state = params.get("state");
    const opened = state === undefined ? null : await openFederationHandle(config.keys, state);
    if (opened === null) return toLoginApp("invalid_state");
    const id = opened.interaction_id;
    // The binding cookie ties the browser to the interaction (TIO-IX-060).
    const cookies = parseCookies(c.req.header("cookie") ?? null);
    const cookie = cookies.get(bindingCookieName(id));
    const binding = cookie === undefined ? null : await openBindingHandle(config.keys, cookie);
    if (binding === null || binding.interaction_id !== id) {
      return toLoginApp("interaction_binding_failed");
    }
    const now = clock.now();
    const stub = interactionStub(c.env, id);
    c.get("metrics").doCalls += 1;
    const consumed = await stub.consumeFederation(encodeBase64Url(opened.secret_hash), now);
    if (!consumed.ok) return toLoginApp("invalid_state");
    const { doc, leg } = consumed;
    if (doc.binding_hash !== encodeBase64Url(binding.secret_hash)) {
      return toLoginApp("interaction_binding_failed");
    }
    const fail = (error: string, description: string, reason: string) =>
      failInteraction(c, stub, id, loginUrl, now, error, description, { alias: leg.alias, reason });
    // An error from the upstream: only its code travels on (TIO-FED-021).
    const upstreamError = params.get("error");
    if (upstreamError !== undefined) {
      const code = UPSTREAM_ERROR_CODES.has(upstreamError) ? upstreamError : "upstream_error";
      return fail("upstream_error", code, `upstream:${code}`);
    }
    const code = params.get("code");
    if (code === undefined || code.length === 0) {
      return fail("upstream_error", "invalid_request", "no_code");
    }
    let upstream: Upstream | null;
    let metadata: UpstreamMetadata;
    try {
      upstream = await getUpstream(db, leg.alias);
      if (upstream === null || !upstream.enabled) {
        return fail("upstream_error", "upstream_not_found", "upstream_not_found");
      }
      metadata = await c.get("upstreamMetadata").get(upstream);
    } catch (error) {
      const reason = error instanceof UpstreamUnavailableError ? error.reason : "storage";
      return fail("upstream_error", "temporarily_unavailable", reason);
    }
    const exchanged = await exchangeCode({
      upstream,
      metadata,
      code,
      redirect_uri: federationCallbackUrl(config.issuerUrl),
      code_verifier: leg.code_verifier,
      keys: config.keys,
      clock,
    });
    if (!exchanged.ok) return fail("upstream_error", "server_error", exchanged.reason);
    const verified = await verifyUpstreamIdToken(exchanged.id_token, {
      issuer: upstream.issuer,
      clientId: upstream.client_id,
      nonce: leg.nonce,
      jwks: c.get("upstreamJwks").get(metadata.jwks_uri),
      clock,
    });
    if (!verified.ok)
      return fail("upstream_error", "invalid_id_token", `id_token:${verified.reason}`);
    let merged: Record<string, unknown> = { ...(verified.claims as JWTPayload) };
    if (upstream.use_userinfo) {
      if (metadata.userinfo_endpoint === null) {
        return fail("upstream_error", "server_error", "userinfo_endpoint_missing");
      }
      const info = await fetchUserinfo(metadata.userinfo_endpoint, exchanged.access_token);
      if (!info.ok) return fail("upstream_error", "server_error", info.reason);
      if (info.claims["sub"] !== verified.claims.sub) {
        return fail("upstream_error", "invalid_userinfo", "userinfo_sub_mismatch");
      }
      merged = { ...merged, ...info.claims };
    }
    const missing = missingRequiredClaim(upstream.required_claims, merged);
    if (missing !== null) {
      return fail("upstream_claims_rejected", `claim ${missing} not accepted`, "required_claims");
    }
    const claims = extractClaims(upstream, merged, verified.claims.sub);
    const client = await interactionClient(c, doc);
    if (client === null) return fail("temporarily_unavailable", "client unavailable", "client");
    const resolution = await resolveAccount(c, db, upstream, leg, claims, settings, clock);
    if (resolution.kind === "fail") {
      return fail(resolution.error, resolution.description, resolution.reason);
    }
    if (resolution.kind === "link") {
      c.get("metrics").doCalls += 1;
      const linked = await stub.apply(
        "authenticate",
        "link_required",
        {
          link: {
            candidate_uid: resolution.candidate_uid,
            alias: upstream.alias,
            subject: claims.sub,
            claims: {
              email: claims.email as string,
              name: claims.name,
              email_verified: claims.email_verified,
            },
          },
        },
        now,
      );
      if (!linked.ok) return toLoginApp("interaction_invalid_state");
      return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
    }
    // A disabled user fails with no upstream detail (TIO-FED-043); the rest is the shared step.
    const guarded: Guarded = { id, stub, doc, settings, now };
    const step = await authenticateInteraction(c, guarded, client, resolution.profile, {
      amr: ["fed"],
      acr: ACR.federated,
      upstream: upstream.alias,
    });
    c.get("audit").emit({
      type: step.status === "failed" ? "identity.login_failed" : "identity.login_succeeded",
      outcome: step.status === "failed" ? "failure" : "success",
      actor: { kind: "user", id: resolution.profile.id },
      user_id: resolution.profile.id,
      upstream: upstream.alias,
      interaction_id: id,
      reason: step.status === "failed" ? "access_denied" : null,
    });
    if (step.status === "ready") return c.redirect(redirectTo(c, id), 303);
    return c.redirect(withQuery(loginUrl, { interaction: id }), 303);
  };
}
