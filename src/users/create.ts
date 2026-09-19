import type { Db } from "../db/db.ts";
import { insertIdentityStatement } from "../db/identities.ts";
import {
  groupIdsByName,
  insertMembershipStatements,
  insertUserStatement,
  setUserStatus,
} from "../db/users.ts";
import type { NewIdentity, UserDO, UserProfile } from "../do/UserDO.ts";
import type { Env } from "../env.ts";
import { isValidEmail, normalizeEmail } from "./email.ts";

// User creation in the order of §4.6: claim the D1 row (`creating`) and the
// group memberships in one batch, initialize the UserDO, then activate the
// row. A failure after step 1 leaves an invisible `creating` row that the
// cron repairs or removes (§3.4).

export interface NewUser {
  /** A fresh UUID v7 from the caller's clock (TIO-DATA-001). */
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  /** Group names; every one must exist. */
  groups: string[];
  /** Upstream identities to link at creation (admin, import); ids are the caller's UUID v7s. */
  identities?: NewIdentity[];
}

export type CreateUserResult =
  | { ok: true; profile: UserProfile }
  | {
      ok: false;
      error:
        | "email_invalid"
        | "account_exists"
        | "identity_already_linked"
        | "group_unknown"
        | "temporarily_unavailable";
    };

export function userStub(env: Env, id: string): DurableObjectStub<UserDO> {
  return env.USER_DO.get(env.USER_DO.idFromName(id));
}

export async function createUser(
  env: Env,
  db: Db,
  input: NewUser,
  now: number,
): Promise<CreateUserResult> {
  const email = input.email === null ? null : input.email.trim();
  if (email !== null && !isValidEmail(email)) return { ok: false, error: "email_invalid" };
  const emailNorm = email === null ? null : normalizeEmail(email);
  const groupIds = await groupIdsByName(db);
  const ids: string[] = [];
  for (const name of input.groups) {
    const id = groupIds.get(name);
    if (id === undefined) return { ok: false, error: "group_unknown" };
    ids.push(id);
  }
  const row = {
    id: input.id,
    email,
    email_norm: emailNorm,
    email_verified: input.email_verified,
    display_name: input.display_name,
  };
  const identities = input.identities ?? [];
  // 1. Claim the row, the memberships and the identity pairs; the partial unique index
  //    refuses a second verified email, the index primary key a second holder of a pair.
  try {
    await db.batch([
      insertUserStatement(db, row, now),
      ...insertMembershipStatements(db, input.id, ids, now),
      ...identities.map((identity) =>
        insertIdentityStatement(db, identity.issuer, identity.subject, input.id, now),
      ),
    ]);
  } catch (error) {
    const message = String(error);
    if (message.includes("UNIQUE")) {
      return {
        ok: false,
        error: message.includes("identity_index") ? "identity_already_linked" : "account_exists",
      };
    }
    throw error;
  }
  // 2. The Durable Object.
  let profile: UserProfile;
  try {
    const initialized = await userStub(env, input.id).init(
      {
        id: input.id,
        email,
        email_norm: emailNorm,
        email_verified: input.email_verified,
        display_name: input.display_name,
        groups: [...input.groups].sort(),
      },
      now,
    );
    if (!initialized.ok) return { ok: false, error: "temporarily_unavailable" };
    profile = initialized.profile;
    for (const identity of identities) {
      const linked = await userStub(env, input.id).addIdentity(identity, now);
      if (!linked.ok) return { ok: false, error: "temporarily_unavailable" };
    }
  } catch {
    return { ok: false, error: "temporarily_unavailable" };
  }
  // 3. Visible.
  await setUserStatus(db, input.id, "active", now);
  return { ok: true, profile };
}
