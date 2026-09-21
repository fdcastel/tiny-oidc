import type { Handler } from "hono";
import { z } from "zod";
import type { InteractionStep } from "../api/definitions.ts";
import {
  assertionIdentity,
  authenticationOptions,
  CHALLENGE_TTL_SECONDS,
  newChallenge,
} from "../auth/passkey.ts";
import { bytesToUuid, UuidV7 } from "../crypto/uuid.ts";
import { insertIdentityStatement, releaseIdentity } from "../db/identities.ts";
import { lookupCredential, releaseCredential } from "../db/users.ts";
import type { InteractionAuth, InteractionDocument, LinkCandidate } from "../do/InteractionDO.ts";
import type { PasskeyRecord, UserProfile } from "../do/UserDO.ts";
import type { Clock } from "../env.ts";
import { ACR } from "../oidc/capabilities.ts";
import type { Client } from "../oidc/clients.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { userStub } from "../users/create.ts";
import { decodeBase64Url } from "../util/base64url.ts";
import { readJsonBody } from "../util/json.ts";
import {
  type AppContext,
  ATTEMPT_LIMIT,
  clientRef,
  type Guarded,
  grantedScopes,
  guard,
  interactionClient,
  interactionFailed,
  redirectTo,
} from "./api.ts";

// The passkey endpoints of the Interaction API (§7.4): options replace the
// interaction's challenge, verify consumes it before verification, and both
// count as attempts (TIO-IX-030). Verification itself is UserDO.verifyAssertion.

// In `link_required` the assertion must come from the candidate user, whose
// upstream identity is then linked (TIO-IX-031).
const PASSKEY_STATUSES = new Set(["login_required", "link_required"]);

const VerifyBody = z.object({ response: z.looseObject({}) });

/** One attempt against the interaction, or the response refusing it. */
async function countAttempt(c: AppContext, guarded: Guarded): Promise<Response | null> {
  c.get("metrics").doCalls += 1;
  const counted = await guarded.stub.attempt(guarded.now, ATTEMPT_LIMIT);
  if (counted.ok) return null;
  if (counted.error === "too_many_attempts") {
    interactionFailed(c, guarded.doc, "too_many_attempts", "attempt_limit");
  }
  return errorResponse(c, 403, "too_many_attempts", "too many attempts");
}

function invalidState(c: AppContext): Response {
  return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
}

/** POST …/passkey/options (TIO-PK-020, TIO-IX-030). */
export function passkeyOptionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    if (guarded.doc.kind !== "authorize" || !PASSKEY_STATUSES.has(guarded.doc.status)) {
      return invalidState(c);
    }
    const refused = await countAttempt(c, guarded);
    if (refused) return refused;
    const challenge = newChallenge();
    c.get("metrics").doCalls += 1;
    await guarded.stub.patch(
      {
        passkey_challenge: {
          value: challenge,
          expires_at: guarded.now + CHALLENGE_TTL_SECONDS,
          pending_uid: null,
          invitation_id: null,
        },
      },
      guarded.now,
    );
    return c.json({ publicKey: authenticationOptions(c.get("config").rpId, challenge) }, 200);
  };
}

/** The user id inside a `userHandle`: the 16 raw bytes of the UUID (TIO-PK-010). */
function uidFromUserHandle(userHandle: string | null): string | null {
  if (userHandle === null) return null;
  const bytes = decodeBase64Url(userHandle);
  return bytes !== null && bytes.length === 16 ? bytesToUuid(bytes) : null;
}

/** POST …/passkey/verify (TIO-PK-021..023, TIO-IX-030, TIO-IX-070). */
export function passkeyVerifyHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, stub, now, settings } = guarded;
    if (doc.kind !== "authorize" || !PASSKEY_STATUSES.has(doc.status)) return invalidState(c);
    const refused = await countAttempt(c, guarded);
    if (refused) return refused;
    const body = await readJsonBody(c.req.raw, VerifyBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    // Both failures answer the same body (TIO-IX-070); the reason goes to the log and the audit only.
    const failed = (reason: string, uid: string | null = null): Response => {
      c.get("logger").log("info", "passkey verification failed", {
        request_id: c.get("requestId"),
        reason,
      });
      c.get("audit").emit({
        type: "passkey.auth_failed",
        outcome: "failure",
        actor: uid === null ? { kind: "anonymous", id: null } : { kind: "user", id: uid },
        user_id: uid,
        client_id: doc.client_id,
        interaction_id: guarded.id,
        reason,
        data: { step: reason },
      });
      return errorResponse(c, 401, "passkey_verification_failed", "passkey verification failed");
    };
    // The challenge is consumed before anything is verified (TIO-IX-030, TIO-PK-022).
    const challenge = doc.passkey_challenge;
    c.get("metrics").doCalls += 1;
    await stub.patch({ passkey_challenge: null }, now);
    if (challenge === null || challenge.expires_at <= now) return failed("no live challenge");
    const identity = assertionIdentity(body.value.response);
    if (identity === null) return failed("malformed assertion");
    // Routing (TIO-PK-021): userHandle, else the index.
    const db = c.get("db");
    let uid = uidFromUserHandle(identity.userHandle);
    let fromIndex = false;
    if (uid === null) {
      uid = await lookupCredential(db, identity.credentialId);
      fromIndex = true;
    }
    if (uid === null) return failed("passkey_unknown");
    const user = userStub(c.env, uid);
    c.get("metrics").doCalls += 1;
    const verified = await user.verifyAssertion({
      response: body.value.response,
      credential_id: identity.credentialId,
      expected: {
        challenge: challenge.value,
        origins: settings.webauthn_origins,
        rpId: c.get("config").rpId,
      },
      now,
    });
    if (!verified.ok) {
      if ("regression" in verified) {
        // TIO-PK-023: a counter that went backwards means a cloned credential.
        c.get("audit").emit({
          type: "passkey.clone_suspected",
          outcome: "failure",
          actor: { kind: "user", id: uid },
          user_id: uid,
          client_id: doc.client_id,
          interaction_id: guarded.id,
          reason: "counter_regression",
          data: { ...verified.regression },
        });
        failed("passkey_counter_regression", uid);
        return errorResponse(c, 401, "passkey_counter_regression", "passkey counter regression");
      }
      if (verified.error === "user_not_initialized" || verified.error === "user_destroyed") {
        // An index row without a user behind it is deleted on discovery (TIO-DATA-026).
        if (fromIndex) await releaseCredential(db, identity.credentialId);
        return failed("passkey_unknown");
      }
      return failed(verified.error, uid);
    }
    c.get("audit").emit({
      type: "passkey.auth_succeeded",
      outcome: "success",
      actor: { kind: "user", id: uid },
      user_id: uid,
      client_id: doc.client_id,
      interaction_id: guarded.id,
      data: { passkey_id: verified.passkey.id },
    });
    const client = await interactionClient(c, doc);
    if (!client) return errorResponse(c, 503, "temporarily_unavailable", "client unavailable");
    if (doc.status === "link_required") {
      const link = doc.link as LinkCandidate;
      if (verified.profile.id !== link.candidate_uid) {
        return errorResponse(c, 403, "link_wrong_user", "the assertion is not the candidate's");
      }
      const linked = await linkIdentity(c, verified.profile.id, link, clock);
      if (!linked) return errorResponse(c, 503, "temporarily_unavailable", "linking failed");
    }
    return c.json(
      await authenticateInteraction(
        c,
        guarded,
        client,
        verified.profile,
        passkeyAuthMethod(verified.passkey),
        doc.status === "link_required" ? "link" : "authenticate",
      ),
      200,
    );
  };
}

/** Links the upstream identity to the candidate: the D1 claim first, then the object (TIO-FED-041). */
async function linkIdentity(
  c: AppContext,
  uid: string,
  link: LinkCandidate,
  clock: Clock,
): Promise<boolean> {
  const db = c.get("db");
  const now = clock.now();
  const upstream = await c.get("upstreams").get(db, link.alias);
  if (upstream === null) return false;
  try {
    await insertIdentityStatement(db, upstream.issuer, link.subject, uid, now).run();
  } catch (error) {
    if (!String(error).includes("UNIQUE")) throw error;
    return false;
  }
  c.get("metrics").doCalls += 1;
  const added = await userStub(c.env, uid).addIdentity(
    {
      id: new UuidV7(clock).next(),
      issuer: upstream.issuer,
      subject: link.subject,
      email: link.claims.email,
      email_verified: link.claims.email_verified,
      name: link.claims.name,
    },
    now,
  );
  if (!added.ok) {
    await releaseIdentity(db, upstream.issuer, link.subject);
    return false;
  }
  c.get("audit").emit({
    type: "identity.linked",
    outcome: "success",
    actor: { kind: "user", id: uid },
    user_id: uid,
    upstream: link.alias,
    data: { issuer: upstream.issuer, via: "reauth" },
  });
  return true;
}

/**
 * What follows a successful authentication (§7.2): a disabled user or one
 * outside `allowed_groups` fails the interaction with access_denied
 * (TIO-PK-023, TIO-AUTHZ-017); otherwise consent is evaluated
 * (TIO-CONSENT-001) and the interaction becomes ready or consent_required.
 */
/** How a passkey assertion is described in the session (TIO-PK-030): hardware- or software-bound key plus user presence. */
export function passkeyAuthMethod(passkey: Pick<PasskeyRecord, "backup_eligible">): AuthMethod {
  return {
    amr: passkey.backup_eligible ? ["swk", "user"] : ["hwk", "user"],
    acr: ACR.passkey,
    upstream: null,
  };
}

/** The authentication a login step establishes: its factors, class and (for federation) the upstream. */
export interface AuthMethod {
  amr: string[];
  acr: string;
  upstream: string | null;
}

export async function authenticateInteraction(
  c: AppContext,
  guarded: Guarded,
  client: Client,
  profile: UserProfile,
  method: AuthMethod,
  operation: "authenticate" | "link" = "authenticate",
): Promise<InteractionStep> {
  const { doc, stub, now, id } = guarded;
  const fail = async (description: string): Promise<InteractionStep> => {
    c.get("metrics").doCalls += 1;
    await stub.apply(
      operation,
      "failed",
      { error: { error: "access_denied", error_description: description } },
      now,
    );
    interactionFailed(
      c,
      doc,
      "access_denied",
      description === "user_not_allowed" ? "user_not_allowed" : "user_disabled",
    );
    return { status: "failed", redirect_to: redirectTo(c, id) };
  };
  if (profile.disabled_at !== null) return fail("the user cannot sign in");
  const ref = clientRef(client);
  if (ref.allowed_groups !== null && !ref.allowed_groups.some((g) => profile.groups.includes(g))) {
    return fail("user_not_allowed");
  }
  // TIO-SCOPE-002: the admin scope needs membership of `admins` at authentication time.
  if (doc.request?.scope.includes("admin") && !profile.groups.includes("admins")) {
    return fail("user_not_allowed");
  }
  const auth: InteractionAuth = {
    uid: profile.id,
    method: method.upstream === null ? "passkey" : "federated",
    amr: method.amr,
    acr: method.acr,
    upstream: method.upstream,
    auth_time: now,
    // The same user re-authenticating keeps the session; anyone else gets a new one (TIO-SESS-002).
    new_session: doc.existing_session?.uid !== profile.id,
  };
  const status = (await consentNeeded(c, doc, client, profile.id)) ? "consent_required" : "ready";
  c.get("metrics").doCalls += 1;
  const applied = await stub.apply(operation, status, { auth }, now);
  // A concurrent request may have failed the interaction meanwhile (attempt limit).
  if (!applied.ok) return { status: "failed", redirect_to: redirectTo(c, id) };
  return { status, redirect_to: status === "ready" ? redirectTo(c, id) : null };
}

/** TIO-CONSENT-001: skip_consent, or a grant covering every requested scope and no prompt=consent. */
async function consentNeeded(
  c: AppContext,
  doc: InteractionDocument,
  client: Client,
  uid: string,
): Promise<boolean> {
  const request = doc.request;
  if (client.skip_consent || request === null) return false;
  if (request.prompt.includes("consent")) return true;
  c.get("metrics").doCalls += 1;
  const granted = grantedScopes(await userStub(c.env, uid).listGrants([clientRef(client)]));
  return !request.scope.every((s) => granted.includes(s));
}
