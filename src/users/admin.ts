import type { Db } from "../db/db.ts";
import { replaceMembershipStatements } from "../db/groups.ts";
import {
  deleteUserRow,
  findVerifiedUser,
  groupIdsByName,
  replaceIdentityIndexStatements,
  replacePasskeyIndexStatements,
  setUserStatus,
  updateUserMirrorStatement,
} from "../db/users.ts";
import type { RevokedSession, UserProfile } from "../do/UserDO.ts";
import type { Env } from "../env.ts";
import { userStub } from "./create.ts";
import { isValidEmail, normalizeEmail } from "./email.ts";

// Administrative operations on one user in the order of §4.6: the Durable
// Object first (authoritative), then the D1 mirror, with a failed second
// write reported as `partial_failure` for the reindex endpoint to repair.

export interface ProfileUpdate {
  email?: string | null;
  email_verified?: boolean;
  display_name?: string | null;
}

export type UpdateProfileResult =
  | { ok: true; profile: UserProfile }
  | { ok: false; error: "email_invalid" | "email_taken" | "user_not_available" }
  | { ok: false; error: "partial_failure"; profile: UserProfile };

/** Updates the profile attributes (TIO-DATA-008): a verified email must be unique (TIO-DATA-006). */
export async function updateUserProfile(
  env: Env,
  db: Db,
  userId: string,
  update: ProfileUpdate,
  now: number,
): Promise<UpdateProfileResult> {
  const stub = userStub(env, userId);
  const current = await stub.getProfile();
  if (!current.ok) return { ok: false, error: "user_not_available" };
  const email = update.email === undefined ? current.profile.email : (update.email?.trim() ?? null);
  if (email !== null && !isValidEmail(email)) return { ok: false, error: "email_invalid" };
  const emailNorm = email === null ? null : normalizeEmail(email);
  const verified =
    update.email_verified ??
    (email === current.profile.email ? current.profile.email_verified : false);
  if (verified && emailNorm !== null) {
    const holder = await findVerifiedUser(db, emailNorm);
    if (holder !== null && holder.id !== userId) return { ok: false, error: "email_taken" };
  }
  const updated = await stub.updateProfile(
    {
      email,
      email_norm: emailNorm,
      email_verified: verified,
      ...(update.display_name === undefined ? {} : { display_name: update.display_name }),
    },
    now,
  );
  if (!updated.ok) return { ok: false, error: "user_not_available" };
  const mirror = {
    email,
    email_norm: emailNorm,
    email_verified: verified,
    display_name: updated.profile.display_name,
  };
  try {
    await updateUserMirrorStatement(db, userId, mirror, now).run();
  } catch {
    return { ok: false, error: "partial_failure", profile: updated.profile };
  }
  return { ok: true, profile: updated.profile };
}

export type SetDisabledResult =
  | { ok: true; profile: UserProfile; revoked: RevokedSession[] }
  | { ok: false; error: "user_not_available" }
  | { ok: false; error: "partial_failure"; profile: UserProfile; revoked: RevokedSession[] };

/** Disables (revoking every session and family, TIO-DATA-009) or enables a user. */
export async function setUserDisabled(
  env: Env,
  db: Db,
  userId: string,
  disabled: boolean,
  now: number,
): Promise<SetDisabledResult> {
  const result = await userStub(env, userId).setDisabled(disabled ? now : null, now);
  if (!result.ok) return { ok: false, error: "user_not_available" };
  try {
    await setUserStatus(db, userId, disabled ? "disabled" : "active", now);
  } catch {
    return {
      ok: false,
      error: "partial_failure",
      profile: result.profile,
      revoked: result.revoked,
    };
  }
  return { ok: true, profile: result.profile, revoked: result.revoked };
}

/**
 * Deletes a user (TIO-DATA-010): the row goes to `deleting`, the object is
 * revoked and destroyed, then the row and everything referencing it go. A
 * failure after the first step leaves `deleting` for the cron to finish;
 * an object that is already gone has nothing to revoke.
 */
export async function deleteUser(
  env: Env,
  db: Db,
  userId: string,
  now: number,
): Promise<{ revoked: RevokedSession[] }> {
  await setUserStatus(db, userId, "deleting", now);
  const stub = userStub(env, userId);
  const revoked = await stub.setDisabled(now, now);
  await stub.destroy();
  await deleteUserRow(db, userId);
  return { revoked: revoked.ok ? revoked.revoked : [] };
}

export interface ReindexReport {
  passkeys: number;
  identities: number;
  groups: number;
  /** Group names held by the object that no longer exist in D1 (left out of the mirror). */
  unknown_groups: string[];
}

export type ReindexResult =
  | { ok: true; report: ReindexReport }
  | { ok: false; error: "user_not_available" };

/** Rebuilds the user's mirror row and index rows from the object (TIO-DATA-027). */
export async function reindexUser(
  env: Env,
  db: Db,
  userId: string,
  now: number,
): Promise<ReindexResult> {
  const stub = userStub(env, userId);
  const [profile, passkeys, identities] = await Promise.all([
    stub.getProfile(),
    stub.listPasskeys(),
    stub.listIdentities(),
  ]);
  if (!profile.ok || !passkeys.ok || !identities.ok) {
    return { ok: false, error: "user_not_available" };
  }
  const groupIds = await groupIdsByName(db);
  const known: string[] = [];
  const unknown: string[] = [];
  for (const name of profile.profile.groups) {
    const id = groupIds.get(name);
    if (id === undefined) unknown.push(name);
    else known.push(id);
  }
  await db.batch([
    updateUserMirrorStatement(db, userId, profile.profile, now),
    ...replacePasskeyIndexStatements(
      db,
      userId,
      passkeys.passkeys.map((p) => p.credential_id),
      now,
    ),
    ...replaceIdentityIndexStatements(db, userId, identities.identities, now),
    ...replaceMembershipStatements(db, userId, known, now),
  ]);
  return {
    ok: true,
    report: {
      passkeys: passkeys.passkeys.length,
      identities: identities.identities.length,
      groups: known.length,
      unknown_groups: unknown,
    },
  };
}
