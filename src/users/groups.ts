import { UuidV7 } from "../crypto/uuid.ts";
import type { Db } from "../db/db.ts";
import {
  type GroupRow,
  getGroupByName,
  insertGroup,
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
