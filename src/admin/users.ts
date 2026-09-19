import type { Handler } from "hono";
import type { z } from "zod";
import {
  AdminUserCreateSchema,
  AdminUserListQuerySchema,
  AdminUserPatchSchema,
  RecoverInvitationBodySchema,
  RestoreBodySchema,
} from "../api/definitions.ts";
import { isUuid, UuidV7 } from "../crypto/uuid.ts";
import { getGroupByName } from "../db/groups.ts";
import { releaseIdentity } from "../db/identities.ts";
import { getUser, listUsers, type UserFilters, type UserRow } from "../db/users.ts";
import type { ClientRef, PasskeyRecord, UserCounts, UserDO, UserProfile } from "../do/UserDO.ts";
import type { Clock, Settings } from "../env.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import {
  deleteUser,
  type ProfileUpdate,
  reindexUser,
  setUserDisabled,
  updateUserProfile,
} from "../users/admin.ts";
import { createUser, userStub } from "../users/create.ts";
import { normalizeEmail } from "../users/email.ts";
import { setUserGroups } from "../users/groups.ts";
import { createInvitation } from "../users/invitations.ts";
import { unregisterPasskey } from "../users/passkeys.ts";
import { readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import type { AdminActor } from "./auth.ts";
import { invitationUrl, publicInvitation } from "./invitations.ts";
import { openCursor, page, parseLimit, sealCursor } from "./pagination.ts";

// Admin users endpoints (spec §9.4). The list reads the D1 mirror with
// keyset paging (TIO-ADMIN-004); everything about one user comes from its
// Durable Object, and every mutation writes the object first (§4.6) and
// leaves an audit record (TIO-ADMIN-002).

const LISTING = "users";

/** The registry row as the API shows it (no normalized email). */
export function publicUser(row: UserRow): Omit<UserRow, "email_norm"> {
  const { email_norm: _norm, ...rest } = row;
  return rest;
}

/** A passkey as the Admin API shows it: metadata, never the public key (TIO-ADMIN-003). */
export function publicPasskey(passkey: PasskeyRecord): Omit<PasskeyRecord, "public_key"> {
  const { public_key: _key, ...rest } = passkey;
  return rest;
}

const TIMESTAMP = /^\d{1,12}$/;

export function listUsersHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const params = uniqueParams(new URL(c.req.url).searchParams);
    if (!params.ok) return errorResponse(c, 400, "invalid_request", params.reason);
    const query = AdminUserListQuerySchema.safeParse(Object.fromEntries(params.params));
    if (!query.success)
      return errorResponse(c, 400, "invalid_request", "unknown or malformed query parameter");
    const limit = parseLimit(query.data.limit);
    if (limit === null) return errorResponse(c, 400, "invalid_request", "limit must be 1..200");
    const now = clock.now();
    const config = c.get("config");
    let after = null;
    if (query.data.cursor !== undefined) {
      after = await openCursor(config.keys, LISTING, query.data.cursor, now);
      if (after === null) return errorResponse(c, 400, "invalid_request", "cursor is not valid");
    }
    const filters: UserFilters = {};
    if (query.data.email !== undefined) filters.email_norm = normalizeEmail(query.data.email);
    if (query.data.status !== undefined) filters.status = query.data.status;
    for (const bound of ["created_after", "created_before"] as const) {
      const raw = query.data[bound];
      if (raw === undefined) continue;
      if (!TIMESTAMP.test(raw))
        return errorResponse(c, 400, "invalid_request", `${bound} must be a timestamp`);
      filters[bound] = Number(raw);
    }
    const db = c.get("db");
    try {
      if (query.data.group !== undefined) {
        const group = await getGroupByName(db, query.data.group);
        // An unknown group has no members.
        if (group === null) return c.json({ items: [], next_cursor: null });
        filters.group_id = group.id;
      }
      const rows = await listUsers(db, filters, after, limit + 1);
      const result = await page(
        rows.map(publicUser),
        limit,
        (row) => ({ created_at: row.created_at, id: row.id }),
        (keyset) => sealCursor(config.keys, LISTING, keyset, now),
      );
      return c.json(result);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "user directory unavailable");
    }
  };
}

// --- one user ------------------------------------------------------------------

type Stub = ReturnType<typeof userStub>;

const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "user storage unavailable");
const notFound = (c: AppContext) => errorResponse(c, 404, "user_not_found", "user not found");

/**
 * The registry row of the user named by the path, or the 404. Rows still
 * `creating` are invisible (§3.4).
 */
async function loadUser(c: AppContext): Promise<{ row: UserRow; stub: Stub } | Response> {
  const id = c.req.param("id") as string;
  if (!isUuid(id)) return notFound(c);
  let row: UserRow | null;
  try {
    row = await getUser(c.get("db"), id);
  } catch {
    return errorResponse(c, 503, "temporarily_unavailable", "user directory unavailable");
  }
  if (row === null || row.status === "creating") return notFound(c);
  c.get("metrics").doCalls += 1;
  return { row, stub: userStub(c.env, id) };
}

/** What the API shows about one user (§9.4): the object's profile, the row's status, the counts. */
export interface UserDetail {
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  groups: string[];
  status: UserRow["status"];
  disabled_at: number | null;
  created_at: number;
  updated_at: number;
  counts: UserCounts;
}

function detail(row: UserRow, profile: UserProfile, counts: UserCounts): UserDetail {
  return {
    id: profile.id,
    email: profile.email,
    email_verified: profile.email_verified,
    display_name: profile.display_name,
    groups: profile.groups,
    status: row.status,
    disabled_at: profile.disabled_at,
    created_at: profile.created_at,
    updated_at: profile.updated_at,
    counts,
  };
}

/** The detail from a live object, or null when the object refuses (not initialized, destroyed). */
async function detailOf(stub: Stub, row: UserRow, now: number): Promise<UserDetail | null> {
  const [profile, counts] = await Promise.all([stub.getProfile(), stub.counts(now)]);
  if (!profile.ok || !counts.ok) return null;
  return detail(row, profile.profile, counts.counts);
}

/** The fields of a profile an audit diff compares (TIO-ADMIN-002). */
function auditable(profile: UserProfile): Record<string, unknown> {
  return {
    email: profile.email,
    email_verified: profile.email_verified,
    display_name: profile.display_name,
    groups: profile.groups,
    disabled_at: profile.disabled_at,
  };
}

async function readBody<T>(c: AppContext, schema: z.ZodType<T>) {
  const body = await readJsonBody(c.req.raw, schema, BODY_LIMITS.api);
  return body.ok
    ? body
    : { ok: false as const, response: errorResponse(c, 400, "invalid_request", body.error) };
}

export function createUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readBody(c, AdminUserCreateSchema);
    if (!body.ok) return body.response;
    const input = body.value;
    const uuids = new UuidV7(clock);
    const now = clock.now();
    const identities = (input.identities ?? []).map((identity) => ({
      id: uuids.next(),
      issuer: identity.issuer,
      subject: identity.subject,
      email: identity.email ?? null,
      email_verified: identity.email_verified ?? null,
      name: identity.name ?? null,
    }));
    let created: Awaited<ReturnType<typeof createUser>>;
    try {
      created = await createUser(
        c.env,
        c.get("db"),
        {
          id: uuids.next(),
          email: input.email ?? null,
          email_verified: input.email_verified ?? false,
          display_name: input.display_name ?? null,
          groups: [...new Set(input.groups ?? [])],
          identities,
        },
        now,
      );
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "user directory unavailable");
    }
    if (!created.ok) {
      switch (created.error) {
        case "email_invalid":
          return errorResponse(c, 400, "email_invalid", "email is not valid");
        case "group_unknown":
          return errorResponse(c, 400, "group_unknown", "a group does not exist");
        case "account_exists":
          return errorResponse(c, 409, "email_taken", "a user already holds this verified email");
        case "identity_already_linked":
          return errorResponse(c, 409, "identity_already_linked", "an identity is already linked");
        default:
          return unavailable(c);
      }
    }
    const profile = created.profile;
    auditAdmin(c, {
      type: "user.created",
      target: profile.id,
      user_id: profile.id,
      after: auditable(profile),
      data: { identities: identities.length },
    });
    for (const identity of identities) {
      auditAdmin(c, {
        type: "identity.linked",
        target: identity.id,
        user_id: profile.id,
        upstream: identity.issuer,
        data: { issuer: identity.issuer },
      });
    }
    const counts: UserCounts = {
      passkeys: 0,
      identities: identities.length,
      sessions: 0,
      refresh_families: 0,
      grants: 0,
    };
    const row: UserRow = {
      id: profile.id,
      email: profile.email,
      email_norm: profile.email_norm,
      email_verified: profile.email_verified,
      display_name: profile.display_name,
      status: "active",
      created_at: profile.created_at,
      updated_at: profile.updated_at,
    };
    return c.json(detail(row, profile, counts), 201);
  };
}

export function getUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const shown = await detailOf(user.stub, user.row, clock.now());
      return shown === null ? notFound(c) : c.json(shown);
    } catch {
      return unavailable(c);
    }
  };
}

export function patchUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const body = await readBody(c, AdminUserPatchSchema);
    if (!body.ok) return body.response;
    const patch = body.value;
    if (Object.keys(patch).length === 0) {
      return errorResponse(c, 400, "invalid_request", "nothing to update");
    }
    const now = clock.now();
    const db = c.get("db");
    let partialFailure = false;
    try {
      const before = await user.stub.getProfile();
      if (!before.ok) return notFound(c);
      let profile = before.profile;
      if (patch.groups !== undefined) {
        const groups = [...new Set(patch.groups)].sort();
        const set = await setUserGroups(c.env, db, user.row.id, groups, now);
        if (!set.ok && set.error !== "partial_failure") {
          return set.error === "group_unknown"
            ? errorResponse(c, 400, "group_unknown", "a group does not exist")
            : notFound(c);
        }
        if (!set.ok) partialFailure = true;
        profile = set.profile;
        for (const name of groups.filter((g) => !before.profile.groups.includes(g))) {
          auditAdmin(c, {
            type: "user.group_added",
            target: user.row.id,
            user_id: user.row.id,
            data: { group: name },
          });
        }
        for (const name of before.profile.groups.filter((g) => !groups.includes(g))) {
          auditAdmin(c, {
            type: "user.group_removed",
            target: user.row.id,
            user_id: user.row.id,
            data: { group: name },
          });
        }
      }
      const { groups: _groups, ...fields } = patch;
      if (Object.keys(fields).length > 0) {
        const update: ProfileUpdate = {};
        if (fields.email !== undefined) update.email = fields.email;
        if (fields.email_verified !== undefined) update.email_verified = fields.email_verified;
        if (fields.display_name !== undefined) update.display_name = fields.display_name;
        const updated = await updateUserProfile(c.env, db, user.row.id, update, now);
        if (!updated.ok) {
          switch (updated.error) {
            case "email_invalid":
              return errorResponse(c, 400, "email_invalid", "email is not valid");
            case "email_taken":
              return errorResponse(
                c,
                409,
                "email_taken",
                "a user already holds this verified email",
              );
            case "user_not_available":
              return notFound(c);
            default:
              partialFailure = true;
              profile = updated.profile;
          }
        } else {
          profile = updated.profile;
        }
      }
      auditAdmin(c, {
        type: "user.updated",
        outcome: partialFailure ? "failure" : "success",
        reason: partialFailure ? "partial_failure" : null,
        target: user.row.id,
        user_id: user.row.id,
        before: auditable(before.profile),
        after: auditable(profile),
      });
      const counts = await user.stub.counts(now);
      if (!counts.ok) return notFound(c);
      return c.json({
        ...detail(user.row, profile, counts.counts),
        partial_failure: partialFailure,
      });
    } catch {
      return unavailable(c);
    }
  };
}

export function setDisabledHandler(clock: Clock, disabled: boolean): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const now = clock.now();
    try {
      const before = await user.stub.getProfile();
      if (!before.ok) return notFound(c);
      const result = await setUserDisabled(c.env, c.get("db"), user.row.id, disabled, now);
      if (!result.ok && result.error === "user_not_available") return notFound(c);
      const partialFailure = !result.ok;
      auditAdmin(c, {
        type: disabled ? "user.disabled" : "user.enabled",
        outcome: partialFailure ? "failure" : "success",
        reason: partialFailure ? "partial_failure" : null,
        target: user.row.id,
        user_id: user.row.id,
        before: auditable(before.profile),
        after: auditable(result.profile),
        data: { sessions_revoked: result.revoked.length },
      });
      const counts = await user.stub.counts(now);
      if (!counts.ok) return notFound(c);
      const row: UserRow = {
        ...user.row,
        status: partialFailure ? user.row.status : disabled ? "disabled" : "active",
      };
      return c.json({
        ...detail(row, result.profile, counts.counts),
        partial_failure: partialFailure,
      });
    } catch {
      return unavailable(c);
    }
  };
}

export function deleteUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const result = await deleteUser(c.env, c.get("db"), user.row.id, clock.now());
      auditAdmin(c, {
        type: "user.deleted",
        target: user.row.id,
        user_id: user.row.id,
        data: { sessions_revoked: result.revoked.length },
      });
      return c.body(null, 204);
    } catch {
      return unavailable(c);
    }
  };
}

// --- sub-resources ------------------------------------------------------------

type Listing<T> = (stub: Stub, now: number) => Promise<{ ok: true; items: T[] } | { ok: false }>;

function listHandler<T>(clock: Clock, listing: Listing<T>): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const listed = await listing(user.stub, clock.now());
      return listed.ok ? c.json({ items: listed.items }) : notFound(c);
    } catch {
      return unavailable(c);
    }
  };
}

export const listPasskeysHandler = (clock: Clock) =>
  listHandler(clock, async (stub) => {
    const listed = await stub.listPasskeys();
    return listed.ok ? { ok: true, items: listed.passkeys.map(publicPasskey) } : { ok: false };
  });

export const listIdentitiesHandler = (clock: Clock) =>
  listHandler(clock, async (stub) => {
    const listed = await stub.listIdentities();
    return listed.ok ? { ok: true, items: listed.identities } : { ok: false };
  });

export const listSessionsHandler = (clock: Clock) =>
  listHandler(clock, async (stub, now) => {
    const listed = await stub.listSessions(now);
    return listed.ok ? { ok: true, items: listed.sessions } : { ok: false };
  });

export const listFamiliesHandler = (clock: Clock) =>
  listHandler(clock, async (stub, now) => {
    const listed = await stub.listFamilies(now);
    return listed.ok ? { ok: true, items: listed.families } : { ok: false };
  });

/** Grants are listed against the current client records so stale ones are dropped (TIO-CLIENT-005). */
export function listGrantsHandler(): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const ids = await user.stub.grantClientIds();
      if (!ids.ok) return notFound(c);
      const refs: ClientRef[] = [];
      for (const clientId of ids.client_ids) {
        const client = await c.get("clients").get(c.get("db"), clientId);
        if (client === null) continue;
        refs.push({
          client_id: client.client_id,
          created_at: client.created_at,
          skip_consent: client.skip_consent,
          allowed_groups: client.allowed_groups,
        });
      }
      c.get("metrics").doCalls += 1;
      const listed = await user.stub.listGrants(refs);
      if (!listed.ok) return notFound(c);
      return c.json({
        items: listed.grants.map(({ client_created_at: _at, ...grant }) => grant),
      });
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");
    }
  };
}

type Removal = (
  c: AppContext,
  stub: Stub,
  userId: string,
  target: string,
  now: number,
) => Promise<{ ok: true; removed: boolean } | { ok: false }>;

function removeHandler(clock: Clock, param: string, removal: Removal): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const target = c.req.param(param) as string;
    try {
      const result = await removal(c, user.stub, user.row.id, target, clock.now());
      if (!result.ok) return notFound(c);
      return c.json({ revoked: result.removed });
    } catch {
      return unavailable(c);
    }
  };
}

export const deletePasskeyHandler = (clock: Clock) =>
  removeHandler(clock, "pid", async (c, stub, userId, pid) => {
    const listed = await stub.listPasskeys();
    if (!listed.ok) return { ok: false };
    const passkey = listed.passkeys.find((p) => p.id === pid);
    const removed =
      passkey === undefined ? false : await unregisterPasskey(c.env, c.get("db"), userId, passkey);
    if (removed) {
      auditAdmin(c, { type: "passkey.deleted", target: pid, user_id: userId });
    }
    return { ok: true, removed };
  });

export const deleteIdentityHandler = (clock: Clock) =>
  removeHandler(clock, "iid", async (c, stub, userId, iid) => {
    const listed = await stub.listIdentities();
    if (!listed.ok) return { ok: false };
    const identity = listed.identities.find((i) => i.id === iid);
    if (identity === undefined) return { ok: true, removed: false };
    const removed = await stub.removeIdentity(iid);
    if (!removed.ok) return { ok: false };
    // The index row goes whether or not the object still had the record (TIO-DATA-026).
    await releaseIdentity(c.get("db"), identity.issuer, identity.subject);
    auditAdmin(c, {
      type: "identity.unlinked",
      target: iid,
      user_id: userId,
      upstream: identity.issuer,
      data: { issuer: identity.issuer },
    });
    return { ok: true, removed: true };
  });

export const deleteSessionHandler = (clock: Clock) =>
  removeHandler(clock, "sid", async (c, stub, userId, sid, now) => {
    const revoked = await stub.revokeSession(sid, now, "admin");
    if (!revoked.ok) return { ok: false };
    if (revoked.revoked !== null) {
      auditAdmin(c, {
        type: "session.revoked",
        target: sid,
        user_id: userId,
        sid,
        data: { clients: revoked.revoked.clients },
      });
    }
    return { ok: true, removed: revoked.revoked !== null };
  });

export function deleteSessionsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const revoked = await user.stub.revokeAll(clock.now(), "admin");
      if (!revoked.ok) return notFound(c);
      for (const session of revoked.revoked) {
        auditAdmin(c, {
          type: "session.revoked",
          target: session.sid,
          user_id: user.row.id,
          sid: session.sid,
          data: { clients: session.clients },
        });
      }
      return c.json({ revoked: revoked.revoked.length });
    } catch {
      return unavailable(c);
    }
  };
}

export const deleteFamilyHandler = (clock: Clock) =>
  removeHandler(clock, "fid", async (c, stub, userId, fid, now) => {
    const revoked = await stub.revokeFamilyById(fid, now, "admin", null);
    if (!revoked.ok) return { ok: false };
    if (revoked.revoked) {
      auditAdmin(c, { type: "token.revoked", target: fid, user_id: userId, data: { family: fid } });
    }
    return { ok: true, removed: revoked.revoked };
  });

export function deleteFamiliesOfClientHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const clientId = new URL(c.req.url).searchParams.get("client_id");
    if (clientId === null || clientId.length === 0) {
      return errorResponse(c, 400, "invalid_request", "client_id is required");
    }
    try {
      const revoked = await user.stub.revokeFamiliesOfClient(clientId, clock.now(), "admin");
      if (!revoked.ok) return notFound(c);
      if (revoked.revoked > 0) {
        auditAdmin(c, {
          type: "token.revoked",
          target: clientId,
          user_id: user.row.id,
          client_id: clientId,
          data: { families: revoked.revoked },
        });
      }
      return c.json({ revoked: revoked.revoked });
    } catch {
      return unavailable(c);
    }
  };
}

export const deleteGrantHandler = (clock: Clock) =>
  removeHandler(clock, "client_id", async (c, stub, userId, clientId, now) => {
    const revoked = await stub.revokeGrant(clientId, now);
    if (!revoked.ok) return { ok: false };
    if (revoked.revoked) {
      auditAdmin(c, {
        type: "consent.revoked",
        target: clientId,
        user_id: userId,
        client_id: clientId,
      });
    }
    return { ok: true, removed: revoked.revoked };
  });

export const eventsNotImplemented: Handler<AppEnv> = (c) =>
  errorResponse(c, 501, "not_implemented", "user events arrive with the audit endpoints");

export function createRecoverInvitationHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const body = await readBody(c, RecoverInvitationBodySchema);
    if (!body.ok) return body.response;
    if (user.row.status !== "active") {
      return errorResponse(c, 409, "user_not_active", "only an active user can be recovered");
    }
    const actor = c.get("admin") as AdminActor;
    const db = c.get("db");
    const config = c.get("config");
    let settings: Settings;
    try {
      settings = await c.get("settingsLoader").get(db, config);
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "settings unavailable");
    }
    try {
      const created = await createInvitation(
        db,
        config.keys,
        {
          kind: "recover",
          user_id: user.row.id,
          email: null,
          email_verified: false,
          display_name: null,
          groups: [],
          expires_in: body.value.expires_in ?? null,
          created_by: actor.id,
        },
        clock,
      );
      if (!created.ok) {
        return errorResponse(c, 400, "expires_in_out_of_bounds", "expires_in is out of bounds");
      }
      auditAdmin(c, {
        type: "invitation.created",
        target: created.invitation.id,
        user_id: user.row.id,
        data: { kind: "recover", expires_at: created.invitation.expires_at },
      });
      return c.json(
        {
          ...publicInvitation(created.invitation),
          token: created.token,
          url: invitationUrl(settings, created.token),
        },
        201,
      );
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "invitation storage unavailable");
    }
  };
}

export function reindexUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const result = await reindexUser(c.env, c.get("db"), user.row.id, clock.now());
      if (!result.ok) return notFound(c);
      auditAdmin(c, {
        type: "user.reindexed",
        target: user.row.id,
        user_id: user.row.id,
        data: { ...result.report },
      });
      return c.json(result.report);
    } catch {
      return unavailable(c);
    }
  };
}

export function exportUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    try {
      const exported = await user.stub.exportState(clock.now());
      if (!exported.ok) return notFound(c);
      return c.json({ ...exported.export, status: user.row.status });
    } catch {
      return unavailable(c);
    }
  };
}

export function restoreUserHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const user = await loadUser(c);
    if (user instanceof Response) return user;
    const body = await readBody(c, RestoreBodySchema);
    if (!body.ok) return body.response;
    if (body.value.bookmark_time >= clock.now()) {
      return errorResponse(c, 400, "invalid_request", "bookmark_time must be in the past");
    }
    let restored: Awaited<ReturnType<UserDO["restore"]>>;
    try {
      restored = await user.stub.restore(body.value.bookmark_time);
    } catch {
      return unavailable(c);
    }
    /* istanbul ignore next -- reason: the local Durable Object backend implements no point-in-time recovery, so a successful restore never happens in tests */
    if (restored.ok) {
      auditAdmin(c, {
        type: "user.updated",
        target: user.row.id,
        user_id: user.row.id,
        reason: "restored",
        data: { bookmark_time: body.value.bookmark_time },
      });
      return c.json({ bookmark: restored.bookmark }, 202);
    }
    return errorResponse(c, 503, "restore_unavailable", "point-in-time recovery is not available");
  };
}
