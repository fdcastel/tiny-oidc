import { UuidV7 } from "../crypto/uuid.ts";
import type { Db } from "../db/db.ts";
import {
  deleteMembership,
  type GroupRow,
  getGroupByName,
  insertGroup,
  insertMembershipStatement,
  memberUserIds,
  replaceMembershipStatements,
} from "../db/groups.ts";
import { groupIdsByName } from "../db/users.ts";
import type { UserProfile } from "../do/UserDO.ts";
import type { Clock, Env } from "../env.ts";
import { userStub } from "./create.ts";

// Groups (spec §3.5): flat, with `admins` system-defined (TIO-DATA-012). A
// user's list lives in the UserDO and is mirrored in D1 `group_members`;
// a membership change writes both and reports a failed mirror write as
// `partial_failure` for the reindex endpoint to repair (TIO-DATA-013).

export const ADMINS_GROUP = "admins";

/** Makes sure the `admins` system group exists; returns it. */
export async function ensureAdminsGroup(db: Db, clock: Clock): Promise<GroupRow> {
  const existing = await getGroupByName(db, ADMINS_GROUP);
  if (existing !== null) return existing;
  await insertGroup(
    db,
    {
      id: new UuidV7(clock).next(),
      name: ADMINS_GROUP,
      description: "Administrators",
      system: true,
    },
    clock.now(),
  );
  return (await getGroupByName(db, ADMINS_GROUP)) as GroupRow;
}

export type SetGroupsResult =
  | { ok: true; profile: UserProfile }
  | { ok: false; error: "group_unknown" | "user_not_available" }
  | { ok: false; error: "partial_failure"; profile: UserProfile };

/** Replaces a user's groups: the UserDO first (authoritative for claims), then the D1 mirror. */
export async function setUserGroups(
  env: Env,
  db: Db,
  userId: string,
  groups: string[],
  now: number,
): Promise<SetGroupsResult> {
  const ids = await groupIdsByName(db);
  const groupIds: string[] = [];
  for (const name of new Set(groups)) {
    const id = ids.get(name);
    if (id === undefined) return { ok: false, error: "group_unknown" };
    groupIds.push(id);
  }
  const updated = await userStub(env, userId).setGroups(groups, now);
  if (!updated.ok) return { ok: false, error: "user_not_available" };
  try {
    await db.batch(replaceMembershipStatements(db, userId, groupIds, now));
  } catch {
    return { ok: false, error: "partial_failure", profile: updated.profile };
  }
  return { ok: true, profile: updated.profile };
}

// --- membership of one user (§4.6 "Update groups") -----------------------------

export type MembershipResult =
  | { ok: true; profile: UserProfile; changed: boolean }
  | { ok: false; error: "user_not_available" }
  | { ok: false; error: "partial_failure"; profile: UserProfile };

/** Adds the user to the group: the object's list first, then the mirror row (TIO-DATA-013). */
export async function addMembership(
  env: Env,
  db: Db,
  userId: string,
  group: GroupRow,
  now: number,
): Promise<MembershipResult> {
  const stub = userStub(env, userId);
  const current = await stub.getProfile();
  if (!current.ok) return { ok: false, error: "user_not_available" };
  const changed = !current.profile.groups.includes(group.name);
  let profile = current.profile;
  if (changed) {
    const updated = await stub.setGroups([...current.profile.groups, group.name], now);
    if (!updated.ok) return { ok: false, error: "user_not_available" };
    profile = updated.profile;
  }
  try {
    await insertMembershipStatement(db, group.id, userId, now).run();
  } catch {
    return { ok: false, error: "partial_failure", profile };
  }
  return { ok: true, profile, changed };
}

/** Removes the user from the group: the object first, then the mirror row. */
export async function removeMembership(
  env: Env,
  db: Db,
  userId: string,
  group: GroupRow,
  now: number,
): Promise<MembershipResult> {
  const stub = userStub(env, userId);
  const current = await stub.getProfile();
  if (!current.ok) return { ok: false, error: "user_not_available" };
  const changed = current.profile.groups.includes(group.name);
  let profile = current.profile;
  if (changed) {
    const updated = await stub.setGroups(
      current.profile.groups.filter((name) => name !== group.name),
      now,
    );
    if (!updated.ok) return { ok: false, error: "user_not_available" };
    profile = updated.profile;
  }
  try {
    await deleteMembership(db, group.id, userId);
  } catch {
    return { ok: false, error: "partial_failure", profile };
  }
  return { ok: true, profile, changed };
}

// --- propagation of a rename or deletion to the members' objects ---------------

/** Renames and deletions walk at most this many members in one request. */
export const PROPAGATION_LIMIT = 1000;
const PROPAGATION_CONCURRENCY = 20;

export interface Propagation {
  members: number;
  /** Members whose object could not be written; the operator retries the call. */
  failed: string[];
}

export type PropagationResult =
  | { ok: true; propagation: Propagation }
  | { ok: false; error: "group_too_large" };

/**
 * Applies `rewrite` to the group list held by every member's object, `rewrite`
 * mapping the old list to the new one. The mirror is the caller's; a member
 * whose object fails is reported, never skipped silently.
 */
export async function propagateToMembers(
  env: Env,
  db: Db,
  groupId: string,
  rewrite: (groups: string[]) => string[],
  now: number,
): Promise<PropagationResult> {
  const members = await memberUserIds(db, groupId, PROPAGATION_LIMIT + 1);
  if (members.length > PROPAGATION_LIMIT) return { ok: false, error: "group_too_large" };
  const failed: string[] = [];
  for (let i = 0; i < members.length; i += PROPAGATION_CONCURRENCY) {
    await Promise.all(
      members.slice(i, i + PROPAGATION_CONCURRENCY).map(async (userId) => {
        try {
          const stub = userStub(env, userId);
          const current = await stub.getProfile();
          if (!current.ok) return;
          const next = rewrite(current.profile.groups);
          if (next.join("\n") === current.profile.groups.join("\n")) return;
          const updated = await stub.setGroups(next, now);
          if (!updated.ok) failed.push(userId);
        } catch {
          failed.push(userId);
        }
      }),
    );
  }
  return { ok: true, propagation: { members: members.length, failed: failed.sort() } };
}
