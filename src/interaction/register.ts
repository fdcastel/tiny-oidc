import type { Handler } from "hono";
import { z } from "zod";
import {
  authenticatorUserName,
  CHALLENGE_TTL_SECONDS,
  newChallenge,
  registrationOptions,
  verifyRegistration,
} from "../auth/passkey.ts";
import { UuidV7, uuidToBytes } from "../crypto/uuid.ts";
import { consumeInvitation, getInvitation, type InvitationRow } from "../db/invitations.ts";
import { findVerifiedUser, getUser, lookupCredential } from "../db/users.ts";
import type { RegistrationDraft } from "../do/InteractionDO.ts";
import type { UserProfile } from "../do/UserDO.ts";
import type { Clock } from "../env.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { createUser, userStub } from "../users/create.ts";
import { isValidEmail, normalizeEmail } from "../users/email.ts";
import { openInvitation } from "../users/invitations.ts";
import { registerPasskey } from "../users/passkeys.ts";
import { readJsonBody } from "../util/json.ts";
import { type AppContext, ATTEMPT_LIMIT, type Guarded, guard, interactionClient } from "./api.ts";
import { authenticateInteraction, passkeyAuthMethod } from "./passkey.ts";

// The registration endpoints of the Interaction API (§7.4, §6.3): options
// allocate a pending user and a challenge under the registration policy;
// verify creates the user (or recovers one) only after the WebAuthn ceremony
// succeeds, consuming the invitation first (TIO-IX-032).

export const PASSKEY_NAME_MAX_LENGTH = 64;

const OptionsBody = z.object({
  invitation: z.string().min(1).max(512).optional(),
  email: z.string().min(1).max(254).optional(),
  display_name: z.string().min(1).max(128).optional(),
});

const VerifyBody = z.object({
  response: z.looseObject({}),
  name: z.string().max(256).optional(),
});

function invalidState(c: AppContext): Response {
  return errorResponse(c, 409, "interaction_invalid_state", "not allowed in this state");
}

/** One attempt against the interaction, or the response refusing it. */
async function countAttempt(c: AppContext, guarded: Guarded): Promise<Response | null> {
  c.get("metrics").doCalls += 1;
  const counted = await guarded.stub.attempt(guarded.now, ATTEMPT_LIMIT);
  if (counted.ok) return null;
  return errorResponse(c, 403, "too_many_attempts", "too many attempts");
}

/** POST …/register/options (TIO-REG-001, TIO-REG-003, TIO-REG-005, TIO-IX-032). */
export function registerOptionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, stub, now, settings } = guarded;
    if (doc.kind !== "authorize" || doc.status !== "login_required") return invalidState(c);
    const refused = await countAttempt(c, guarded);
    if (refused) return refused;
    const body = await readJsonBody(c.req.raw, OptionsBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const db = c.get("db");
    const config = c.get("config");
    // The policy (TIO-REG-001): an invitation, or open registration.
    let invitation: InvitationRow | null = null;
    if (body.value.invitation !== undefined) {
      const opened = await openInvitation(db, config.keys, body.value.invitation, now);
      if (!opened.ok) return errorResponse(c, 400, opened.error, "invitation not accepted");
      invitation = opened.invitation;
    } else if (settings["registration.mode"] !== "open") {
      return errorResponse(c, 403, "registration_closed", "registration is closed");
    }
    let pendingUid: string;
    let draft: RegistrationDraft;
    let excludeCredentialIds: string[] = [];
    if (invitation?.kind === "recover") {
      // TIO-REG-004: bound to an existing user; the new passkey joins the others.
      // createInvitation guarantees a user id on recover invitations; the row must still be active.
      const target = await getUser(db, invitation.user_id as string);
      if (target?.status !== "active") {
        return errorResponse(c, 400, "invitation_invalid", "invitation not accepted");
      }
      pendingUid = target.id;
      draft = {
        kind: "recover",
        email: target.email,
        email_verified: target.email_verified,
        display_name: target.display_name,
        groups: [],
      };
      c.get("metrics").doCalls += 1;
      const passkeys = await userStub(c.env, target.id).listPasskeys();
      excludeCredentialIds = passkeys.ok ? passkeys.passkeys.map((p) => p.credential_id) : [];
    } else {
      // TIO-REG-003: the invitation's fields win; the login app may add an email only when it has none.
      const email = invitation?.email ?? body.value.email ?? null;
      if (email !== null && !isValidEmail(email)) {
        return errorResponse(c, 400, "email_invalid", "email is not valid");
      }
      const emailVerified =
        invitation !== null && invitation.email !== null && invitation.email_verified;
      if (email !== null && emailVerified && (await findVerifiedUser(db, normalizeEmail(email)))) {
        return errorResponse(c, 409, "account_exists", "an account with this email exists");
      }
      pendingUid = new UuidV7(clock).next();
      draft = {
        kind: "register",
        email: email === null ? null : email.trim(),
        email_verified: emailVerified,
        display_name: body.value.display_name ?? invitation?.display_name ?? null,
        groups: invitation?.groups ?? [],
      };
    }
    // TIO-REG-005: a verified holder of the same email exists; the login app may suggest signing in.
    const emailInUse =
      draft.kind === "register" &&
      draft.email !== null &&
      !draft.email_verified &&
      (await findVerifiedUser(db, normalizeEmail(draft.email))) !== null;
    const challenge = newChallenge();
    c.get("metrics").doCalls += 1;
    await stub.patch(
      {
        passkey_challenge: {
          value: challenge,
          expires_at: now + CHALLENGE_TTL_SECONDS,
          pending_uid: pendingUid,
          invitation_id: invitation?.id ?? null,
        },
        registration: draft,
      },
      now,
    );
    const userName = authenticatorUserName(draft.email, pendingUid);
    return c.json(
      {
        publicKey: registrationOptions({
          rpId: config.rpId,
          rpName: config.rpName,
          userId: uuidToBytes(pendingUid) as Uint8Array,
          userName,
          displayName: draft.display_name ?? userName,
          challenge,
          excludeCredentialIds,
        }),
        email_in_use: emailInUse,
      },
      200,
    );
  };
}

/** TIO-PK-041: 1–64 characters after trimming, stored as given. */
export function passkeyName(raw: string | undefined): string | null | undefined {
  if (raw === undefined) return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || [...trimmed].length > PASSKEY_NAME_MAX_LENGTH) return undefined;
  return trimmed;
}

/** POST …/register/verify (TIO-REG-002..004, TIO-IX-032, TIO-PK-041). */
export function registerVerifyHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const guarded = await guard(c, clock);
    if (guarded instanceof Response) return guarded;
    const { doc, stub, now, settings } = guarded;
    if (doc.kind !== "authorize" || doc.status !== "login_required") return invalidState(c);
    const refused = await countAttempt(c, guarded);
    if (refused) return refused;
    const body = await readJsonBody(c.req.raw, VerifyBody, BODY_LIMITS.api);
    if (!body.ok) return errorResponse(c, 400, "invalid_request", body.error);
    const name = passkeyName(body.value.name);
    if (name === undefined) {
      return errorResponse(c, 400, "invalid_request", "name must be 1-64 characters");
    }
    // The challenge is consumed before anything is verified (TIO-IX-030).
    const challenge = doc.passkey_challenge;
    const draft = doc.registration;
    c.get("metrics").doCalls += 1;
    await stub.patch({ passkey_challenge: null, registration: null }, now);
    if (
      challenge === null ||
      challenge.expires_at <= now ||
      challenge.pending_uid === null ||
      draft === null
    ) {
      return errorResponse(c, 401, "passkey_verification_failed", "passkey verification failed");
    }
    const config = c.get("config");
    const verified = await verifyRegistration(body.value.response, {
      challenge: challenge.value,
      origins: settings.webauthn_origins,
      rpId: config.rpId,
    });
    if (!verified.ok) {
      c.get("logger").log("info", "passkey registration failed", {
        request_id: c.get("requestId"),
        reason: verified.reason,
      });
      const status = verified.error === "passkey_not_discoverable" ? 400 : 401;
      return errorResponse(c, status, verified.error, "passkey registration failed");
    }
    const db = c.get("db");
    const uid = challenge.pending_uid;
    // A credential registered anywhere is refused before anything is created (TIO-PK-012).
    if ((await lookupCredential(db, verified.passkey.credential_id)) !== null) {
      return errorResponse(c, 401, "passkey_verification_failed", "passkey registration failed");
    }
    // The invitation goes first, exactly once (TIO-REG-002, TIO-IX-032).
    if (challenge.invitation_id !== null) {
      const consumed = await consumeInvitation(db, challenge.invitation_id, uid, now);
      if (!consumed) {
        const row = await getInvitation(db, challenge.invitation_id);
        const error =
          row === null
            ? "invitation_invalid"
            : row.used_at !== null
              ? "invitation_used"
              : "invitation_expired";
        return errorResponse(c, 400, error, "invitation not accepted");
      }
    }
    let profile: UserProfile;
    if (draft.kind === "register") {
      const created = await createUser(
        c.env,
        db,
        {
          id: uid,
          email: draft.email,
          email_verified: draft.email_verified,
          display_name: draft.display_name,
          groups: draft.groups,
        },
        now,
      );
      if (!created.ok) {
        if (created.error === "account_exists") {
          return errorResponse(c, 409, "account_exists", "an account with this email exists");
        }
        return errorResponse(c, 503, "temporarily_unavailable", created.error);
      }
      profile = created.profile;
    } else {
      // TIO-REG-004: recovery ends every session and family before the new passkey is added.
      const user = userStub(c.env, uid);
      c.get("metrics").doCalls += 1;
      const current = await user.getProfile();
      if (!current.ok)
        return errorResponse(c, 400, "invitation_invalid", "invitation not accepted");
      await user.revokeAll(now, "recover");
      profile = current.profile;
    }
    const registered = await registerPasskey(
      c.env,
      db,
      uid,
      {
        ...verified.passkey,
        id: new UuidV7(clock).next(),
        name,
        created_via: draft.kind === "recover" ? "recovery" : "interaction",
      },
      now,
      settings["passkeys.max_per_user"],
    );
    if (!registered.ok) {
      if (registered.error === "passkey_limit_reached") {
        return errorResponse(c, 403, "passkey_limit_reached", "too many passkeys");
      }
      // A credential claimed by someone else since the check above, or storage trouble.
      return errorResponse(c, 503, "temporarily_unavailable", registered.error);
    }
    const client = await interactionClient(c, doc);
    if (!client) return errorResponse(c, 503, "temporarily_unavailable", "client unavailable");
    return c.json(
      await authenticateInteraction(
        c,
        guarded,
        client,
        profile,
        passkeyAuthMethod(registered.passkey),
      ),
      200,
    );
  };
}
