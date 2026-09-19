import type { Handler } from "hono";
import { z } from "zod";
import { userEvents } from "../admin/audit-log.ts";
import type { AuditEvent, AuditInput } from "../audit/events.ts";
import {
  authenticatorUserName,
  CHALLENGE_TTL_SECONDS,
  newChallenge,
  registrationOptions,
  verifyRegistration,
} from "../auth/passkey.ts";
import { UuidV7, uuidToBytes } from "../crypto/uuid.ts";
import { getClient } from "../db/clients.ts";
import { releaseIdentity } from "../db/identities.ts";
import { listUpstreamAliases } from "../db/upstreams.ts";
import { lookupCredential } from "../db/users.ts";
import {
  type ClientRef,
  PASSKEY_ATTEMPT_WINDOW_SECONDS,
  type RevokedSession,
  type UserProfile,
} from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppContext } from "../interaction/api.ts";
import { passkeyName } from "../interaction/register.ts";
import { endSession, notifyEndedSessions } from "../logout/rp-logout.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import { updateUserProfile } from "../users/admin.ts";
import { userStub } from "../users/create.ts";
import { registerPasskey, unregisterOwnPasskey } from "../users/passkeys.ts";
import { readJsonBody } from "../util/json.ts";
import type { Account } from "./auth.ts";

// The Self-service API (spec §8): a person's own profile, passkeys, sessions,
// linked identities and consent grants, under a token with scope `account`.
// Every mutation is audited as the person, with the token's client
// (TIO-ME-002). Storage trouble is 503 `temporarily_unavailable`.

const ProfilePatchSchema = z
  .object({
    display_name: z.string().trim().min(1).max(128).optional(),
    email: z.string().trim().min(3).max(254).optional(),
  })
  .strict();

const PasskeyRegisterSchema = z
  .object({
    response: z.record(z.string(), z.unknown()),
    name: z.string().max(256).optional(),
  })
  .strict();

const PasskeyRenameSchema = z.object({ name: z.string().max(256) }).strict();

/** The public profile (§8 GET /me). */
function publicProfile(profile: UserProfile) {
  return {
    id: profile.id,
    email: profile.email,
    email_verified: profile.email_verified,
    display_name: profile.display_name,
    groups: profile.groups,
    created_at: profile.created_at,
    updated_at: profile.updated_at,
  };
}

/** One audit event as the person, from the token's client (TIO-ME-002). */
function auditMe(
  c: AppContext,
  input: Omit<AuditInput, "actor" | "outcome" | "user_id" | "client_id"> & {
    outcome?: AuditEvent["outcome"];
  },
): void {
  const me = c.get("me") as Account;
  c.get("audit").emit({
    ...input,
    outcome: input.outcome ?? "success",
    actor: { kind: "user", id: me.profile.id },
    user_id: me.profile.id,
    client_id: me.token.client_id,
  });
}

const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");

async function readBody<T>(c: AppContext, schema: z.ZodType<T>) {
  const body = await readJsonBody(c.req.raw, schema, BODY_LIMITS.api);
  return body.ok
    ? body
    : { ok: false as const, response: errorResponse(c, 400, "invalid_request", body.error) };
}

async function loadSettings(c: AppContext): Promise<Settings | Response> {
  try {
    return await c.get("settingsLoader").get(c.get("db"), c.get("config"));
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
  }
}

export const getProfileHandler: Handler<AppEnv> = (c) =>
  c.json(publicProfile((c.get("me") as Account).profile));

/** PATCH /me: `display_name`; `email` only under `me.allow_email_change`, and then unverified. */
export function patchProfileHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const body = await readBody(c, ProfilePatchSchema);
    if (!body.ok) return body.response;
    const patch = body.value;
    if (Object.keys(patch).length === 0) {
      return errorResponse(c, 400, "invalid_request", "nothing to update");
    }
    const settings = await loadSettings(c);
    if (settings instanceof Response) return settings;
    if (patch.email !== undefined && !settings["me.allow_email_change"]) {
      return errorResponse(c, 403, "email_change_not_allowed", "email changes are not allowed");
    }
    try {
      const updated = await updateUserProfile(
        c.env,
        c.get("db"),
        me.profile.id,
        {
          ...(patch.display_name === undefined ? {} : { display_name: patch.display_name }),
          ...(patch.email === undefined ? {} : { email: patch.email, email_verified: false }),
        },
        clock.now(),
      );
      if (!updated.ok && updated.error !== "partial_failure") {
        // A changed email is unverified, so it can never collide with a verified holder.
        return updated.error === "email_invalid"
          ? errorResponse(c, 400, "email_invalid", "email is not valid")
          : unavailable(c);
      }
      // A partial failure changed the object and not the D1 mirror (the cron repairs it, TIO-DATA-027).
      const profile = updated.profile;
      auditMe(c, {
        type: "user.updated",
        outcome: updated.ok ? "success" : "failure",
        reason: updated.ok ? null : "partial_failure",
        data: { fields: Object.keys(patch) },
      });
      return c.json(publicProfile(profile));
    } catch {
      return unavailable(c);
    }
  };
}

export const listPasskeysHandler: Handler<AppEnv> = async (c) => {
  const me = c.get("me") as Account;
  c.get("metrics").doCalls += 1;
  try {
    const listed = await userStub(c.env, me.profile.id).listPasskeys();
    if (!listed.ok) return unavailable(c);
    return c.json({
      items: listed.passkeys.map(({ public_key: _key, ...passkey }) => passkey),
    });
  } catch {
    return unavailable(c);
  }
};

/** §6.7: ten registration attempts per ten minutes per user, whatever the token. */
async function passkeyAttempt(c: AppContext, clock: Clock): Promise<Response | null> {
  const me = c.get("me") as Account;
  c.get("metrics").doCalls += 1;
  const counted = await userStub(c.env, me.profile.id).countPasskeyAttempt(clock.now());
  if (counted.ok) return null;
  if (counted.error !== "too_many_attempts") return unavailable(c);
  c.get("audit").emit({
    type: "ratelimit.exceeded",
    outcome: "failure",
    actor: { kind: "user", id: me.profile.id },
    user_id: me.profile.id,
    client_id: me.token.client_id,
    reason: "me_passkey_attempts",
    data: { class: "me_passkey_attempts" },
  });
  return errorResponse(c, 429, "rate_limited", "too many passkey registration attempts", {
    "Retry-After": String(PASSKEY_ATTEMPT_WINDOW_SECONDS),
  });
}

/** TIO-ME-003: the token's session must have authenticated recently enough to add a passkey. */
function reauthenticationRequired(
  c: AppContext,
  settings: Settings,
  clock: Clock,
): Response | null {
  const me = c.get("me") as Account;
  const maxAge = settings["me.passkey_add_max_auth_age"];
  if (me.token.auth_time !== null && me.token.auth_time + maxAge > clock.now()) return null;
  return errorResponse(
    c,
    403,
    "reauthentication_required",
    `the session must have authenticated within ${maxAge} seconds`,
  );
}

/** POST /me/passkeys/options: registration options with a challenge kept on the user's object. */
export function passkeyOptionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const settings = await loadSettings(c);
    if (settings instanceof Response) return settings;
    const refused = reauthenticationRequired(c, settings, clock);
    if (refused) return refused;
    const config = c.get("config");
    const stub = userStub(c.env, me.profile.id);
    const challenge = newChallenge();
    try {
      const throttled = await passkeyAttempt(c, clock);
      if (throttled) return throttled;
      c.get("metrics").doCalls += 2;
      const passkeys = await stub.listPasskeys();
      const stored = await stub.putChallenge(
        me.challengeKey,
        challenge,
        clock.now() + CHALLENGE_TTL_SECONDS,
      );
      if (!passkeys.ok || !stored.ok) return unavailable(c);
      const userName = authenticatorUserName(me.profile.email, me.profile.id);
      return c.json({
        publicKey: registrationOptions({
          rpId: config.rpId,
          rpName: config.rpName,
          userId: uuidToBytes(me.profile.id) as Uint8Array,
          userName,
          displayName: me.profile.display_name ?? userName,
          challenge,
          excludeCredentialIds: passkeys.passkeys.map((p) => p.credential_id),
        }),
      });
    } catch {
      return unavailable(c);
    }
  };
}

/** POST /me/passkeys: verifies the ceremony against the stored challenge and registers the passkey. */
export function registerPasskeyHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const settings = await loadSettings(c);
    if (settings instanceof Response) return settings;
    const refused = reauthenticationRequired(c, settings, clock);
    if (refused) return refused;
    const body = await readBody(c, PasskeyRegisterSchema);
    if (!body.ok) return body.response;
    const name = passkeyName(body.value.name);
    if (name === undefined) {
      return errorResponse(c, 400, "invalid_request", "name must be 1-64 characters");
    }
    const now = clock.now();
    const stub = userStub(c.env, me.profile.id);
    const failed = () =>
      errorResponse(c, 401, "passkey_verification_failed", "passkey registration failed");
    try {
      const throttled = await passkeyAttempt(c, clock);
      if (throttled) return throttled;
      c.get("metrics").doCalls += 1;
      const taken = await stub.takeChallenge(me.challengeKey, now);
      if (!taken.ok) return unavailable(c);
      if (taken.value === null) return failed();
      const verified = await verifyRegistration(body.value.response, {
        challenge: taken.value,
        origins: settings.webauthn_origins,
        rpId: c.get("config").rpId,
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
      // A credential registered anywhere is refused (TIO-PK-012).
      if ((await lookupCredential(db, verified.passkey.credential_id)) !== null) return failed();
      const registered = await registerPasskey(
        c.env,
        db,
        me.profile.id,
        { ...verified.passkey, id: new UuidV7(clock).next(), name, created_via: "me" },
        now,
        settings["passkeys.max_per_user"],
      );
      if (!registered.ok) {
        if (registered.error === "passkey_limit_reached") {
          return errorResponse(c, 403, "passkey_limit_reached", "too many passkeys");
        }
        if (registered.error === "passkey_exists") return failed();
        return unavailable(c);
      }
      auditMe(c, { type: "passkey.registered", data: { passkey_id: registered.passkey.id } });
      const { public_key: _key, ...passkey } = registered.passkey;
      return c.json(passkey, 201);
    } catch {
      return unavailable(c);
    }
  };
}

export function renamePasskeyHandler(): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const body = await readBody(c, PasskeyRenameSchema);
    if (!body.ok) return body.response;
    const name = passkeyName(body.value.name);
    if (name === undefined || name === null) {
      return errorResponse(c, 400, "invalid_request", "name must be 1-64 characters");
    }
    const id = c.req.param("id") as string;
    try {
      c.get("metrics").doCalls += 1;
      const renamed = await userStub(c.env, me.profile.id).renamePasskey(id, name);
      if (!renamed.ok) return unavailable(c);
      if (!renamed.renamed) return errorResponse(c, 404, "not_found", "no such passkey");
      auditMe(c, { type: "passkey.renamed", data: { passkey_id: id } });
      return c.body(null, 204);
    } catch {
      return unavailable(c);
    }
  };
}

/** DELETE /me/passkeys/{id}: the last-method rule (TIO-PK-040) answers 409 `last_login_method`. */
export function deletePasskeyHandler(): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const id = c.req.param("id") as string;
    const stub = userStub(c.env, me.profile.id);
    try {
      c.get("metrics").doCalls += 2;
      const listed = await stub.listPasskeys();
      if (!listed.ok) return unavailable(c);
      const passkey = listed.passkeys.find((p) => p.id === id);
      if (passkey === undefined) return errorResponse(c, 404, "not_found", "no such passkey");
      const result = await unregisterOwnPasskey(c.env, c.get("db"), me.profile.id, passkey);
      switch (result) {
        case "removed":
          auditMe(c, { type: "passkey.deleted", data: { passkey_id: id } });
          return c.body(null, 204);
        case "last_login_method":
          return errorResponse(
            c,
            409,
            "last_login_method",
            "the last passkey stays unless an identity is linked",
          );
        case "missing":
          return errorResponse(c, 404, "not_found", "no such passkey");
        default:
          return unavailable(c);
      }
    } catch {
      return unavailable(c);
    }
  };
}

/** GET /me/sessions: every live session, the token's own flagged `current`. */
export function listSessionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    try {
      c.get("metrics").doCalls += 1;
      const listed = await userStub(c.env, me.profile.id).listSessions(clock.now());
      if (!listed.ok) return unavailable(c);
      return c.json({
        items: listed.sessions.map((s) => ({
          sid: s.sid,
          created_at: s.created_at,
          last_seen_at: s.last_seen_at,
          auth_time: s.auth_time,
          amr: s.amr,
          upstream: s.upstream,
          country: s.country,
          ua_family: s.ua_family,
          current: s.sid === me.token.sid,
          clients: s.clients,
        })),
      });
    } catch {
      return unavailable(c);
    }
  };
}

export function deleteSessionHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const sid = c.req.param("sid") as string;
    try {
      const ended = await endSession(c, clock, me.profile.id, sid, "self");
      if (ended === null) return errorResponse(c, 404, "not_found", "no such session");
      auditMe(c, {
        type: "session.revoked",
        sid,
        reason: "self",
        data: { clients: ended.clients },
      });
      return c.body(null, 204);
    } catch {
      return unavailable(c);
    }
  };
}

/** DELETE /me/sessions: every other session; `?include_current=true` ends this one too. */
export function deleteSessionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const includeCurrent = c.req.query("include_current") === "true";
    const except = includeCurrent ? null : me.token.sid;
    try {
      c.get("metrics").doCalls += 1;
      const revoked = await userStub(c.env, me.profile.id).revokeSessions(
        except,
        clock.now(),
        "self",
      );
      if (!revoked.ok) return unavailable(c);
      for (const session of revoked.revoked) {
        auditMe(c, {
          type: "session.revoked",
          sid: session.sid,
          reason: "self",
          data: { clients: session.clients },
        });
      }
      await notifyEndedSessions(
        c,
        clock,
        revoked.revoked.map((s: RevokedSession) => ({ uid: me.profile.id, ...s })),
      );
      return c.json({ revoked: revoked.revoked.length });
    } catch {
      return unavailable(c);
    }
  };
}

/** GET /me/identities: never the upstream subject (§8). */
export const listIdentitiesHandler: Handler<AppEnv> = async (c) => {
  const me = c.get("me") as Account;
  try {
    c.get("metrics").doCalls += 1;
    const listed = await userStub(c.env, me.profile.id).listIdentities();
    if (!listed.ok) return unavailable(c);
    const aliases = new Map(
      (await listUpstreamAliases(c.get("db"))).map((u) => [u.issuer, u.alias]),
    );
    return c.json({
      items: listed.identities.map((i) => ({
        id: i.id,
        upstream: aliases.get(i.issuer) ?? null,
        issuer: i.issuer,
        email: i.email,
        name: i.name,
        created_at: i.created_at,
        last_login_at: i.last_login_at,
      })),
    });
  } catch {
    return unavailable(c);
  }
};

/** DELETE /me/identities/{id}: the last-method rule (TIO-FED-051) answers 409 `last_login_method`. */
export const deleteIdentityHandler: Handler<AppEnv> = async (c) => {
  const me = c.get("me") as Account;
  const id = c.req.param("id") as string;
  const stub = userStub(c.env, me.profile.id);
  try {
    c.get("metrics").doCalls += 2;
    const listed = await stub.listIdentities();
    if (!listed.ok) return unavailable(c);
    const identity = listed.identities.find((i) => i.id === id);
    if (identity === undefined) return errorResponse(c, 404, "not_found", "no such identity");
    const removed = await stub.removeIdentity(id, "self");
    if (!removed.ok) {
      if (removed.error === "last_login_method") {
        return errorResponse(
          c,
          409,
          "last_login_method",
          "the last identity stays unless a passkey is registered",
        );
      }
      return unavailable(c);
    }
    if (!removed.removed) return errorResponse(c, 404, "not_found", "no such identity");
    await releaseIdentity(c.get("db"), identity.issuer, identity.subject);
    auditMe(c, {
      type: "identity.unlinked",
      upstream: identity.issuer,
      data: { identity_id: id, issuer: identity.issuer },
    });
    return c.body(null, 204);
  } catch {
    return unavailable(c);
  }
};

/** GET /me/grants: against the current client records, so stale grants are dropped (TIO-CLIENT-005). */
export const listGrantsHandler: Handler<AppEnv> = async (c) => {
  const me = c.get("me") as Account;
  const stub = userStub(c.env, me.profile.id);
  try {
    c.get("metrics").doCalls += 2;
    const ids = await stub.grantClientIds();
    if (!ids.ok) return unavailable(c);
    const refs: ClientRef[] = [];
    for (const clientId of ids.client_ids) {
      const client = await getClient(c.get("db"), clientId);
      if (client === null) continue;
      refs.push({
        client_id: client.client_id,
        created_at: client.created_at,
        skip_consent: client.skip_consent,
        allowed_groups: client.allowed_groups,
      });
    }
    const listed = await stub.listGrants(refs);
    if (!listed.ok) return unavailable(c);
    return c.json({
      items: listed.grants.map((g) => ({
        client_id: g.client_id,
        scopes: g.scopes,
        granted_at: g.granted_at,
        updated_at: g.updated_at,
      })),
    });
  } catch {
    return unavailable(c);
  }
};

/** DELETE /me/grants/{client_id}: the grant and every refresh family of that client (TIO-CONSENT-004). */
export function deleteGrantHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const me = c.get("me") as Account;
    const clientId = c.req.param("client_id") as string;
    try {
      c.get("metrics").doCalls += 1;
      const revoked = await userStub(c.env, me.profile.id).revokeGrant(clientId, clock.now());
      if (!revoked.ok) return unavailable(c);
      if (!revoked.revoked) return errorResponse(c, 404, "not_found", "no such grant");
      auditMe(c, { type: "consent.revoked", data: { grant_client_id: clientId } });
      return c.body(null, 204);
    } catch {
      return unavailable(c);
    }
  };
}

/** GET /me/events: the person's own events within the hot window (§8). */
export function eventsHandler(clock: Clock): Handler<AppEnv> {
  return (c) =>
    userEvents(c, clock, (c.get("me") as Account).profile.id, new URL(c.req.url).searchParams);
}
