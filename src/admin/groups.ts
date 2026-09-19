import type { Handler } from "hono";
import type { z } from "zod";
import {
  AdminGroupCreateSchema,
  AdminGroupPatchSchema,
  AdminListQuerySchema,
} from "../api/definitions.ts";
import { isUuid, UuidV7 } from "../crypto/uuid.ts";
import {
  countMembers,
  deleteGroup,
  type GroupPatch,
  type GroupRow,
  getGroupById,
  getGroupByName,
  insertGroup,
  listGroupsPage,
  updateGroup,
} from "../db/groups.ts";
import { getUser, listUsers } from "../db/users.ts";
import type { Clock } from "../env.ts";
import type { AppContext } from "../oidc/token-common.ts";
import type { AppEnv } from "../router/context.ts";
import { errorResponse } from "../router/errors.ts";
import { uniqueParams } from "../router/form.ts";
import { BODY_LIMITS } from "../router/routes.ts";
import {
  addMembership,
  type MembershipResult,
  type Propagation,
  propagateToMembers,
  removeMembership,
} from "../users/groups.ts";
import { readJsonBody } from "../util/json.ts";
import { auditAdmin } from "./audit.ts";
import { type Keyset, openCursor, page, parseLimit, sealCursor } from "./pagination.ts";
import { publicUser } from "./users.ts";

// Admin groups endpoints (spec §9.4 Groups, §3.5): flat groups in D1, with
// `admins` system-defined (TIO-DATA-012). A member's list lives in its
// Durable Object and is mirrored in `group_members`; every membership change
// and every rename or deletion writes the objects first (TIO-DATA-013) and
// reports what the mirror or a member's object refused.

const notFound = (c: AppContext) => errorResponse(c, 404, "group_not_found", "group not found");
const unavailable = (c: AppContext) =>
  errorResponse(c, 503, "temporarily_unavailable", "group directory unavailable");

async function readBody<T>(c: AppContext, schema: z.ZodType<T>) {
  const body = await readJsonBody(c.req.raw, schema, BODY_LIMITS.api);
  return body.ok
    ? body
    : { ok: false as const, response: errorResponse(c, 400, "invalid_request", body.error) };
}

/** The list query of a group listing: limit and cursor, both validated. */
async function listQuery(
  c: AppContext,
  listing: string,
  now: number,
): Promise<{ ok: true; limit: number; after: Keyset | null } | { ok: false; response: Response }> {
  const bad = (description: string) => ({
    ok: false as const,
    response: errorResponse(c, 400, "invalid_request", description),
  });
  const params = uniqueParams(new URL(c.req.url).searchParams);
  if (!params.ok) return bad(params.reason);
  const query = AdminListQuerySchema.safeParse(Object.fromEntries(params.params));
  if (!query.success) return bad("unknown or malformed query parameter");
  const limit = parseLimit(query.data.limit);
  if (limit === null) return bad("limit must be 1..200");
  let after: Keyset | null = null;
  if (query.data.cursor !== undefined) {
    after = await openCursor(c.get("config").keys, listing, query.data.cursor, now);
    if (after === null) return bad("cursor is not valid");
  }
  return { ok: true, limit, after };
}

async function loadGroup(c: AppContext): Promise<GroupRow | Response> {
  const id = c.req.param("id") as string;
  if (!isUuid(id)) return notFound(c);
  let group: GroupRow | null;
  try {
    group = await getGroupById(c.get("db"), id);
  } catch {
    return unavailable(c);
  }
  return group ?? notFound(c);
}

async function detail(c: AppContext, group: GroupRow) {
  return { ...group, members: await countMembers(c.get("db"), group.id) };
}

export function listGroupsHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const now = clock.now();
    const query = await listQuery(c, "groups", now);
    if (!query.ok) return query.response;
    try {
      const rows = await listGroupsPage(c.get("db"), query.after, query.limit + 1);
      return c.json(
        await page(
          rows,
          query.limit,
          (row) => ({ created_at: row.created_at, id: row.id }),
          (keyset) => sealCursor(c.get("config").keys, "groups", keyset, now),
        ),
      );
    } catch {
      return unavailable(c);
    }
  };
}

export function createGroupHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const body = await readBody(c, AdminGroupCreateSchema);
    if (!body.ok) return body.response;
    const db = c.get("db");
    const group: GroupRow = {
      id: new UuidV7(clock).next(),
      name: body.value.name,
      description: body.value.description ?? null,
      system: false,
      created_at: clock.now(),
      updated_at: clock.now(),
    };
    try {
      const inserted = await insertGroup(db, group, clock.now());
      if (inserted === "group_exists") {
        return errorResponse(c, 409, "group_exists", "a group with this name exists");
      }
    } catch {
      return unavailable(c);
    }
    auditAdmin(c, { type: "group.created", target: group.id, after: { ...group } });
    return c.json({ ...group, members: 0 }, 201);
  };
}

export const getGroupHandler: Handler<AppEnv> = async (c) => {
  const group = await loadGroup(c);
  if (group instanceof Response) return group;
  try {
    return c.json(await detail(c, group));
  } catch {
    return unavailable(c);
  }
};

export function patchGroupHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const group = await loadGroup(c);
    if (group instanceof Response) return group;
    const body = await readBody(c, AdminGroupPatchSchema);
    if (!body.ok) return body.response;
    const patch: GroupPatch = {};
    if (body.value.name !== undefined) patch.name = body.value.name;
    if (body.value.description !== undefined) patch.description = body.value.description;
    if (Object.keys(patch).length === 0) {
      return errorResponse(c, 400, "invalid_request", "nothing to update");
    }
    const now = clock.now();
    const db = c.get("db");
    const renaming = patch.name !== undefined && patch.name !== group.name;
    if (renaming && group.system) {
      return errorResponse(c, 409, "system_group", "a system group keeps its name");
    }
    const taken = () => errorResponse(c, 409, "group_exists", "a group with this name exists");
    try {
      // A rename reaches every member's object before the directory changes, so a
      // member's claims never name a group that no longer exists.
      let propagation: Propagation | null = null;
      if (renaming) {
        const oldName = group.name;
        const newName = patch.name as string;
        if ((await getGroupByName(db, newName)) !== null) return taken();
        const rename = (from: string, to: string) => (groups: string[]) =>
          groups.map((name) => (name === from ? to : name));
        const propagated = await propagateToMembers(
          c.env,
          db,
          group.id,
          rename(oldName, newName),
          now,
        );
        if (!propagated.ok) {
          return errorResponse(c, 409, "group_too_large", "rename groups of at most 1,000 members");
        }
        propagation = propagated.propagation;
        const updated = await updateGroup(db, group.id, patch, now);
        if (updated === "group_exists") {
          // Taken between the check and the write: the members get the old name back.
          await propagateToMembers(c.env, db, group.id, rename(newName, oldName), now);
          return taken();
        }
      } else {
        await updateGroup(db, group.id, patch, now);
      }
      const after = (await getGroupById(db, group.id)) as GroupRow;
      auditAdmin(c, {
        type: "group.updated",
        outcome: propagation !== null && propagation.failed.length > 0 ? "failure" : "success",
        reason: propagation !== null && propagation.failed.length > 0 ? "partial_failure" : null,
        target: group.id,
        before: { ...group },
        after: { ...after },
        ...(propagation === null ? {} : { data: { propagation } }),
      });
      return c.json({ ...(await detail(c, after)), propagation });
    } catch {
      return unavailable(c);
    }
  };
}

export function deleteGroupHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const group = await loadGroup(c);
    if (group instanceof Response) return group;
    if (group.system) {
      return errorResponse(c, 409, "system_group", "a system group cannot be deleted");
    }
    const now = clock.now();
    const db = c.get("db");
    try {
      const propagated = await propagateToMembers(
        c.env,
        db,
        group.id,
        (groups) => groups.filter((name) => name !== group.name),
        now,
      );
      if (!propagated.ok) {
        return errorResponse(c, 409, "group_too_large", "delete groups of at most 1,000 members");
      }
      await deleteGroup(db, group.id);
      const failed = propagated.propagation.failed.length > 0;
      auditAdmin(c, {
        type: "group.deleted",
        outcome: failed ? "failure" : "success",
        reason: failed ? "partial_failure" : null,
        target: group.id,
        before: { ...group },
        data: { propagation: propagated.propagation },
      });
      return c.json({ propagation: propagated.propagation });
    } catch {
      return unavailable(c);
    }
  };
}

export function listMembersHandler(clock: Clock): Handler<AppEnv> {
  return async (c) => {
    const group = await loadGroup(c);
    if (group instanceof Response) return group;
    const now = clock.now();
    const query = await listQuery(c, "members", now);
    if (!query.ok) return query.response;
    try {
      const rows = await listUsers(
        c.get("db"),
        { group_id: group.id },
        query.after,
        query.limit + 1,
      );
      return c.json(
        await page(
          rows.map(publicUser),
          query.limit,
          (row) => ({ created_at: row.created_at, id: row.id }),
          (keyset) => sealCursor(c.get("config").keys, "members", keyset, now),
        ),
      );
    } catch {
      return unavailable(c);
    }
  };
}

export function membershipHandler(clock: Clock, add: boolean): Handler<AppEnv> {
  return async (c) => {
    const group = await loadGroup(c);
    if (group instanceof Response) return group;
    const userId = c.req.param("user_id") as string;
    const userNotFound = () => errorResponse(c, 404, "user_not_found", "user not found");
    if (!isUuid(userId)) return userNotFound();
    const db = c.get("db");
    try {
      const row = await getUser(db, userId);
      if (row === null || row.status === "creating") return userNotFound();
      c.get("metrics").doCalls += 1;
      const now = clock.now();
      const result: MembershipResult = add
        ? await addMembership(c.env, db, userId, group, now)
        : await removeMembership(c.env, db, userId, group, now);
      if (!result.ok && result.error === "user_not_available") return userNotFound();
      const partialFailure = !result.ok;
      const changed = result.ok ? result.changed : true;
      if (changed) {
        auditAdmin(c, {
          type: add ? "user.group_added" : "user.group_removed",
          outcome: partialFailure ? "failure" : "success",
          reason: partialFailure ? "partial_failure" : null,
          target: userId,
          user_id: userId,
          data: { group: group.name },
        });
      }
      return c.json({
        user_id: userId,
        groups: result.profile.groups,
        changed,
        partial_failure: partialFailure,
      });
    } catch {
      return errorResponse(c, 503, "temporarily_unavailable", "storage unavailable");
    }
  };
}
